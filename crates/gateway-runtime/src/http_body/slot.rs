//! Single-producer/single-consumer adapter with one fixed verified queue slot.
//! Mutex ordering, waker behavior, and destruction remain trusted Rust.
use gateway_core::fixed_queue::FixedQueue;
use std::{sync::{Arc, Mutex}, task::{Context, Poll, Waker}};

struct State<T> {
    queue: FixedQueue<T>,
    sender_open: bool,
    receiver_open: bool,
    reader: Option<Waker>,
    writer: Option<Waker>,
}
pub(super) struct Sender<T> { state: Arc<Mutex<State<T>>> }
pub(super) struct Receiver<T> { state: Arc<Mutex<State<T>>> }

pub(super) fn channel<T>() -> (Sender<T>, Receiver<T>) {
    let state = Arc::new(Mutex::new(State { queue: FixedQueue::new(1),
        sender_open: true, receiver_open: true, reader: None, writer: None }));
    (Sender { state: state.clone() }, Receiver { state })
}
fn register(slot: &mut Option<Waker>, waker: &Waker) {
    if slot.as_ref().is_none_or(|old| !old.will_wake(waker)) { *slot = Some(waker.clone()); }
}
fn wake(waker: Option<Waker>) { if let Some(waker) = waker { waker.wake(); } }
struct WakeOnDrop(Option<Waker>);
impl Drop for WakeOnDrop { fn drop(&mut self) { wake(self.0.take()); } }
impl<T> Sender<T> {
    pub(super) fn poll_send_with(&mut self, cx: &mut Context<'_>, make: impl FnOnce() -> T) -> Poll<Result<(), ()>> {
        // Declared before the guard so an encoding panic wakes the receiver
        // after the mutex has been poisoned and unlocked.
        let mut notify = WakeOnDrop(None);
        let mut state = match self.state.lock() { Ok(state) => state, Err(_) => return Poll::Ready(Err(())) };
        if !state.receiver_open { return Poll::Ready(Err(())); }
        if state.queue.is_full() {
            register(&mut state.writer, cx.waker());
            return Poll::Pending;
        }
        // Capacity and receiver liveness stay locked through construction. No
        // permit can escape and publish a late payload after receiver drop.
        notify.0 = state.reader.take();
        let result = state.queue.push(make()).map_err(|_| ());
        state.writer = None;
        drop(state);
        drop(notify);
        Poll::Ready(result)
    }
}
impl<T> Receiver<T> {
    pub(super) fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<T>> {
        let mut state = match self.state.lock() { Ok(state) => state, Err(_) => return Poll::Ready(None) };
        if let Some(value) = state.queue.pop() {
            state.reader = None;
            let writer = state.writer.take();
            drop(state);
            wake(writer);
            return Poll::Ready(Some(value));
        }
        if !state.sender_open { return Poll::Ready(None); }
        register(&mut state.reader, cx.waker());
        Poll::Pending
    }
}
impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        let reader = if let Ok(mut state) = self.state.lock() {
            state.sender_open = false;
            state.queue.close();
            state.writer = None;
            state.reader.take()
        } else { None };
        wake(reader);
    }
}
impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        let (writer, pending) = if let Ok(mut state) = self.state.lock() {
            state.receiver_open = false;
            state.queue.close();
            state.reader = None;
            (state.writer.take(), state.queue.pop())
        } else { (None, None) };
        // Drop the payload and invoke wake outside the state lock.
        drop(pending);
        wake(writer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::atomic::{AtomicUsize, Ordering}, task::Wake, time::{Duration, Instant}};
    struct Count(AtomicUsize);
    impl Wake for Count { fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); } }
    fn counter() -> (Arc<Count>, Waker) {
        let count = Arc::new(Count(AtomicUsize::new(0)));
        (count.clone(), Waker::from(count))
    }
    #[test]
    fn one_slot_replaces_waiters_and_rejects_without_constructing() {
        let (mut sender, mut receiver) = channel();
        let (old, old_waker) = counter(); let (new, new_waker) = counter();
        let mut first = Context::from_waker(&old_waker); let mut latest = Context::from_waker(&new_waker);
        assert!(receiver.poll_recv(&mut first).is_pending());
        assert!(receiver.poll_recv(&mut latest).is_pending());
        assert_eq!(sender.poll_send_with(&mut first, || 1), Poll::Ready(Ok(())));
        assert_eq!(old.0.load(Ordering::SeqCst), 0); assert_eq!(new.0.load(Ordering::SeqCst), 1);
        assert!(sender.poll_send_with(&mut first, || panic!("full allocation")).is_pending());
        assert!(sender.poll_send_with(&mut latest, || panic!("full allocation")).is_pending());
        assert_eq!(receiver.poll_recv(&mut first), Poll::Ready(Some(1)));
        assert_eq!(old.0.load(Ordering::SeqCst), 0); assert_eq!(new.0.load(Ordering::SeqCst), 2);
        drop(receiver);
        assert_eq!(sender.poll_send_with(&mut first, || panic!("closed allocation")), Poll::Ready(Err(())));
    }
    #[test]
    fn construction_panic_wakes_reader_and_poison_refuses_resumption() {
        let (mut sender, mut receiver) = channel::<usize>();
        let (count, waker) = counter(); let mut cx = Context::from_waker(&waker);
        assert!(receiver.poll_recv(&mut cx).is_pending());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            sender.poll_send_with(&mut cx, || panic!("injected allocation panic"))
        })).is_err());
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert_eq!(receiver.poll_recv(&mut cx), Poll::Ready(None));
        assert_eq!(sender.poll_send_with(&mut cx, || panic!("poison recovery")), Poll::Ready(Err(())));
    }
    #[test]
    fn receiver_drop_waits_for_construction_then_discards_its_payload() {
        use std::sync::mpsc;
        struct Payload(Arc<AtomicUsize>);
        impl Drop for Payload { fn drop(&mut self) { self.0.fetch_add(1, Ordering::SeqCst); } }
        let (mut sender, receiver) = channel();
        let dropped = Arc::new(AtomicUsize::new(0)); let observed = dropped.clone();
        let (entered, inside) = mpsc::channel(); let (release, resume) = mpsc::channel();
        let producer = std::thread::spawn(move || {
            let mut cx = Context::from_waker(Waker::noop());
            assert!(matches!(sender.poll_send_with(&mut cx, || {
                entered.send(()).unwrap(); resume.recv_timeout(Duration::from_secs(5)).unwrap();
                Payload(observed)
            }), Poll::Ready(Ok(()))));
            sender
        });
        inside.recv_timeout(Duration::from_secs(5)).unwrap();
        let (closing, started) = mpsc::channel(); let (closed, complete) = mpsc::channel();
        let consumer = std::thread::spawn(move || {
            closing.send(()).unwrap(); drop(receiver); closed.send(()).unwrap();
        });
        started.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(matches!(complete.try_recv(), Err(mpsc::TryRecvError::Empty)));
        release.send(()).unwrap();
        let mut sender = producer.join().unwrap();
        complete.recv_timeout(Duration::from_secs(5)).unwrap(); consumer.join().unwrap();
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(sender.poll_send_with(&mut cx, || panic!("late construction")), Poll::Ready(Err(()))));
    }
    struct Unpark(std::thread::Thread);
    impl Wake for Unpark { fn wake(self: Arc<Self>) { self.0.unpark(); } }
    #[test]
    fn two_threads_preserve_fifo_and_wake_through_repeated_handoffs() {
        const COUNT: usize = 10000;
        let (mut sender, mut receiver) = channel();
        let deadline = Instant::now() + Duration::from_secs(15);
        let producer = std::thread::spawn(move || {
            let waker = Waker::from(Arc::new(Unpark(std::thread::current())));
            let mut cx = Context::from_waker(&waker);
            for i in 0..COUNT {
                loop {
                    match sender.poll_send_with(&mut cx, || i) {
                        Poll::Ready(Ok(())) => break,
                        Poll::Ready(Err(())) => panic!("unexpected receiver loss"),
                        Poll::Pending => { assert!(Instant::now() < deadline); std::thread::park_timeout(Duration::from_millis(100)); }
                    }
                }
            }
        });
        let waker = Waker::from(Arc::new(Unpark(std::thread::current())));
        let mut cx = Context::from_waker(&waker);
        for expected in 0..=COUNT {
            loop {
                match receiver.poll_recv(&mut cx) {
                    Poll::Ready(value) => { assert_eq!(value, if expected == COUNT { None } else { Some(expected) }); break; }
                    Poll::Pending => { assert!(Instant::now() < deadline); std::thread::park_timeout(Duration::from_millis(100)); }
                }
            }
        }
        producer.join().unwrap();
    }
}
