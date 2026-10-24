//! Single-producer/single-consumer adapter with one inline verified mailbox.
//! Mutex ordering, waker behavior, and destruction remain trusted Rust.
use gateway_core::mailbox::Mailbox;
use std::{sync::{Arc, Mutex}, task::{Context, Poll, Waker}};

struct State<T> {
    queue: Mailbox<T>,
    reader: Option<Waker>,
    writer: Option<Waker>,
}
pub(super) struct Sender<T> { state: Arc<Mutex<State<T>>> }
pub(super) struct Receiver<T> { state: Arc<Mutex<State<T>>> }

pub(super) fn channel<T>() -> (Sender<T>, Receiver<T>) {
    let state = Arc::new(Mutex::new(State { queue: Mailbox::new(), reader: None, writer: None }));
    (Sender { state: state.clone() }, Receiver { state })
}
// Only pointer/vtable comparison and moves occur while locked. Cloning and
// dropping wakers can invoke user code and must happen outside the state mutex.
fn register(slot: &mut Option<Waker>, incoming: &mut Option<Waker>) -> Option<Waker> {
    let waker = incoming.as_ref().expect("candidate waker");
    if slot.as_ref().is_some_and(|old| old.will_wake(waker)) { None }
    else { std::mem::replace(slot, incoming.take()) }
}
fn wake(waker: Option<Waker>) { if let Some(waker) = waker { waker.wake(); } }
struct WakeOnDrop(Option<Waker>);
impl Drop for WakeOnDrop { fn drop(&mut self) { wake(self.0.take()); } }
impl<T> Sender<T> {
    pub(super) fn poll_send_with(&mut self, cx: &mut Context<'_>, make: impl FnOnce() -> T) -> Poll<Result<(), ()>> {
        // Declared before the guard so an encoding panic wakes the receiver
        // after the mutex has been poisoned and unlocked.
        let mut notify = WakeOnDrop(None);
        let mut incoming = Some(cx.waker().clone());
        let mut state = match self.state.lock() { Ok(state) => state, Err(_) => return Poll::Ready(Err(())) };
        if state.queue.is_closed() { return Poll::Ready(Err(())); }
        if state.queue.is_full() {
            let retired = register(&mut state.writer, &mut incoming);
            drop(state);
            drop(retired);
            return Poll::Pending;
        }
        // Capacity and receiver liveness stay locked through construction. No
        // permit can escape and publish a late payload after receiver drop.
        notify.0 = state.reader.take();
        let result = state.queue.push(make()).map_err(|_| ());
        let retired = state.writer.take();
        drop(state);
        drop(retired);
        drop(notify);
        Poll::Ready(result)
    }
}
impl<T> Receiver<T> {
    pub(super) fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<T>> {
        let mut notify = WakeOnDrop(None);
        let mut incoming = Some(cx.waker().clone());
        let mut state = match self.state.lock() { Ok(state) => state, Err(_) => return Poll::Ready(None) };
        if let Some(value) = state.queue.pop() {
            let retired = state.reader.take();
            notify.0 = state.writer.take();
            drop(state);
            drop(retired);
            drop(notify);
            return Poll::Ready(Some(value));
        }
        if state.queue.is_closed() { return Poll::Ready(None); }
        let retired = register(&mut state.reader, &mut incoming);
        drop(state);
        drop(retired);
        Poll::Pending
    }
}
impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        let (reader, retired) = if let Ok(mut state) = self.state.lock() {
            state.queue.close_sender();
            (state.reader.take(), state.writer.take())
        } else { (None, None) };
        let notify = WakeOnDrop(reader);
        drop(retired);
        drop(notify);
    }
}
impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        let (writer, retired, pending) = if let Ok(mut state) = self.state.lock() {
            let pending = state.queue.close_receiver_charged();
            (state.writer.take(), state.reader.take(), Some(pending))
        } else { (None, None, None) };
        // Drop callbacks and wake outside the lock. Even if a payload/drop
        // callback panics, the waiting writer must observe receiver closure.
        let notify = WakeOnDrop(writer);
        if let Some(mut cleanup) = pending {
            let payload = cleanup.begin();
            drop(payload);
            assert!(cleanup.finish());
        }
        drop(retired);
        drop(notify);
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
    #[test]
    fn waker_callbacks_never_run_under_slot_mutex() {
        struct Probe {
            state: std::sync::Weak<Mutex<State<usize>>>,
            locked: Arc<AtomicUsize>,
            drops: Arc<AtomicUsize>,
        }
        impl Probe {
            fn check(&self) {
                if let Some(state) = self.state.upgrade() {
                    if state.try_lock().is_err() { self.locked.fetch_add(1, Ordering::SeqCst); }
                }
            }
        }
        impl Wake for Probe { fn wake(self: Arc<Self>) { self.check(); } }
        impl Drop for Probe { fn drop(&mut self) { self.check(); self.drops.fetch_add(1, Ordering::SeqCst); } }
        let locked = Arc::new(AtomicUsize::new(0)); let drops = Arc::new(AtomicUsize::new(0));
        let probe = |state: &Arc<Mutex<State<usize>>>| Waker::from(Arc::new(Probe {
            state: Arc::downgrade(state), locked: locked.clone(), drops: drops.clone(),
        }));
        let mut noop = Context::from_waker(Waker::noop());
        // Replacing the reader's last waker must retire it after unlocking.
        let (mut sender, mut receiver) = channel();
        let waker = probe(&sender.state);
        assert!(receiver.poll_recv(&mut Context::from_waker(&waker)).is_pending()); drop(waker);
        assert!(receiver.poll_recv(&mut noop).is_pending());
        assert_eq!(sender.poll_send_with(&mut noop, || 1), Poll::Ready(Ok(())));
        // Dequeue wakes a blocked sender after unlocking.
        let waker = probe(&sender.state);
        assert!(sender.poll_send_with(&mut Context::from_waker(&waker), || 2).is_pending()); drop(waker);
        assert_eq!(receiver.poll_recv(&mut noop), Poll::Ready(Some(1)));
        // Sender destruction clears its pending waker after unlocking.
        assert_eq!(sender.poll_send_with(&mut noop, || 3), Poll::Ready(Ok(())));
        let waker = probe(&sender.state);
        assert!(sender.poll_send_with(&mut Context::from_waker(&waker), || 4).is_pending()); drop(waker);
        drop(sender); drop(receiver);
        // Receiver destruction does the same for its pending waker.
        let (sender, mut receiver) = channel();
        let waker = probe(&sender.state);
        assert!(receiver.poll_recv(&mut Context::from_waker(&waker)).is_pending()); drop(waker);
        drop(receiver); drop(sender);
        assert_eq!(drops.load(Ordering::SeqCst), 4);
        assert_eq!(locked.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn receiver_drop_wakes_writer_even_when_payload_drop_panics() {
        struct Panics;
        impl Drop for Panics { fn drop(&mut self) { panic!("injected payload drop panic"); } }
        let (mut sender, receiver) = channel();
        let (count, waker) = counter(); let mut cx = Context::from_waker(&waker);
        assert!(matches!(sender.poll_send_with(&mut cx, || Panics), Poll::Ready(Ok(()))));
        assert!(sender.poll_send_with(&mut cx, || panic!("full construction")).is_pending());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(receiver))).is_err());
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert!(matches!(sender.poll_send_with(&mut cx, || panic!("closed construction")), Poll::Ready(Err(()))));
        assert!(!sender.state.is_poisoned());
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
