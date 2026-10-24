use super::*;
use tokio::io::AsyncReadExt;
use crate::admission::Admission;
use gateway_core::policy::{Identity, Policy, Route};
use std::{pin::Pin, sync::{Arc, Mutex}, task::{Context, Poll}, time::Duration};

fn admission(strict: bool) -> Admission {
    let route = || Route { tenant: 1, selector: 7, origin: 0, credential: 0 };
    Admission::new(Policy::validate(vec![Identity { tenant: 1, digest: vec![11; 32] }],
        vec![route()], vec![route()], 1, vec![1]).unwrap(), 1, 3, strict)
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Event { Log(u64, Direction, Vec<u8>), Write(Vec<u8>) }
type Events = Arc<Mutex<Vec<Event>>>;
struct Log { events: Events, fail: bool, pending: bool }
impl AuditLog for Log {
    fn session_id(&self) -> u128 { 0 }
    async fn append(&mut self, record: LogRecord<'_>) -> io::Result<crate::transfer::DurableFrame> {
        assert_eq!(record.tenant, 1);
        assert!(record.request != 0);
        if self.pending { std::future::pending::<()>().await; }
        self.events.lock().unwrap().push(Event::Log(record.chunk, record.direction, record.bytes.to_vec()));
        if self.fail { Err(io::ErrorKind::Other.into()) } else { Ok(receipt_for_test(record)) }
    }
}
struct Writer { events: Events, max: usize, fail: bool, flush_fail: bool, pending: bool }
impl AsyncWrite for Writer {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        if self.pending { return Poll::Pending; }
        if self.fail { return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())); }
        let n = self.max.min(bytes.len());
        self.events.lock().unwrap().push(Event::Write(bytes[..n].to_vec()));
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(if self.flush_fail { Err(io::ErrorKind::BrokenPipe.into()) } else { Ok(()) })
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
}
fn io_pair() -> (Events, Log, Writer) {
    let events = Events::default();
    (events.clone(), Log { events: events.clone(), fail: false, pending: false },
        Writer { events, max: 2, fail: false, flush_fail: false, pending: false })
}

#[tokio::test]
async fn multichunk_partial_writes_follow_durable_logs_and_preserve_bytes() {
    let a = admission(true); let mut r = a.admit(&[11; 32], 7).unwrap();
    let (events, mut log, mut writer) = io_pair();
    let stats = copy_body(&mut r, &mut &b"abcdefg"[..], &mut writer, &mut log, Direction::Upload).await.unwrap();
    assert_eq!(stats, TransferStats { accepted_bytes: 7, audit_gap: false });
    assert_eq!(*events.lock().unwrap(), vec![
        Event::Log(1, Direction::Upload, b"abc".to_vec()), Event::Write(b"ab".to_vec()), Event::Write(b"c".to_vec()),
        Event::Log(2, Direction::Upload, b"def".to_vec()), Event::Write(b"de".to_vec()), Event::Write(b"f".to_vec()),
        Event::Log(3, Direction::Upload, b"g".to_vec()), Event::Write(b"g".to_vec()),
    ]);
    let stats = copy_body(&mut r, &mut &b"data: ok\n\n"[..], &mut writer, &mut log, Direction::Download).await.unwrap();
    assert_eq!(stats.accepted_bytes, 10);
    assert!(events.lock().unwrap().iter().any(|e| matches!(e, Event::Log(4, Direction::Download, _))));
}

#[tokio::test]
async fn logger_failure_is_closed_in_strict_mode_and_reported_in_availability_mode() {
    for strict in [true, false] {
        let a = admission(strict); let mut r = a.admit(&[11; 32], 7).unwrap();
        let (events, mut log, mut writer) = io_pair(); log.fail = true;
        let result = copy_body(&mut r, &mut &b"abcdef"[..], &mut writer, &mut log, Direction::Upload).await;
        if strict {
            assert_eq!(result, Err(TransferError::Log));
            assert!(!events.lock().unwrap().iter().any(|e| matches!(e, Event::Write(_))));
            assert!(r.is_closed());
        } else {
            assert_eq!(result, Ok(TransferStats { accepted_bytes: 6, audit_gap: true }));
            assert_eq!(events.lock().unwrap().iter().filter(|e| matches!(e, Event::Log(..))).count(), 1);
            // Degradation persists across directions even if a later log call could succeed.
            log.fail = false;
            assert!(copy_body(&mut r, &mut &b"z"[..], &mut writer, &mut log, Direction::Download).await.unwrap().audit_gap);
            assert_eq!(events.lock().unwrap().iter().filter(|e| matches!(e, Event::Log(..))).count(), 1);
        }
    }
}

#[tokio::test]
async fn zero_error_and_flush_failures_close_without_replay() {
    for expected in [TransferError::WriteZero, TransferError::Write, TransferError::Flush] {
        let a = admission(false); let mut r = a.admit(&[11; 32], 7).unwrap();
        let (_, mut log, mut writer) = io_pair();
        writer.max = if expected == TransferError::WriteZero { 0 } else { 2 };
        writer.fail = expected == TransferError::Write;
        writer.flush_fail = expected == TransferError::Flush;
        assert_eq!(copy_body(&mut r, &mut &b"abc"[..], &mut writer, &mut log, Direction::Upload).await, Err(expected));
        assert!(r.is_closed());
        assert!(r.prepare(1).is_none());
        assert_eq!(copy_body(&mut r, &mut &b""[..], &mut writer, &mut log, Direction::Download).await,
            Err(TransferError::InvalidState));
    }
}

#[tokio::test]
async fn canceling_pending_log_or_write_closes_the_request_and_retains_its_lease() {
    for pending_log in [true, false] {
        let a = admission(true); let mut r = a.admit(&[11; 32], 7).unwrap();
        let (_, mut log, mut writer) = io_pair();
        log.pending = pending_log; writer.pending = !pending_log;
        assert!(tokio::time::timeout(Duration::from_millis(10),
            copy_body(&mut r, &mut &b"abc"[..], &mut writer, &mut log, Direction::Upload)).await.is_err());
        assert!(r.is_closed());
        assert!(a.admit(&[11; 32], 7).is_err());
        drop(r);
        assert!(a.admit(&[11; 32], 7).is_ok());
    }
}

#[tokio::test]
async fn real_async_backpressure_preserves_fragmented_sse_bytes() {
    let a = admission(true); let mut r = a.admit(&[11; 32], 7).unwrap();
    let (_, mut log, _) = io_pair();
    let (mut input, mut source) = tokio::io::duplex(2);
    let (mut sink, mut output) = tokio::io::duplex(1);
    let expected = b"data: {\"delta\":\"hello\"}\n\ndata: [DONE]\n\n";
    let produce = async {
        for part in expected.chunks(2) { source.write_all(part).await.unwrap(); tokio::task::yield_now().await; }
        source.shutdown().await.unwrap();
    };
    let transfer = async {
        let result = copy_body(&mut r, &mut input, &mut sink, &mut log, Direction::Download).await;
        sink.shutdown().await.unwrap(); result
    };
    let consume = async { let mut bytes = Vec::new(); output.read_to_end(&mut bytes).await.unwrap(); bytes };
    let (_, result, received) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(produce, transfer, consume)
    }).await.unwrap();
    assert_eq!(received, expected);
    assert_eq!(result.unwrap().accepted_bytes, expected.len() as u64);
}

#[tokio::test]
async fn read_failure_and_cancellation_close_before_any_write() {
    struct FailingRead;
    impl AsyncRead for FailingRead {
        fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, _: &mut tokio::io::ReadBuf<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()))
        }
    }
    let a = admission(true); let mut r = a.admit(&[11; 32], 7).unwrap();
    let (events, mut log, mut writer) = io_pair();
    assert_eq!(copy_body(&mut r, &mut FailingRead, &mut writer, &mut log, Direction::Upload).await,
        Err(TransferError::Read));
    assert!(r.is_closed());
    assert!(events.lock().unwrap().is_empty());
    drop(r);
    let mut r = a.admit(&[11; 32], 7).unwrap();
    let (mut reader, _keep_open) = tokio::io::duplex(1);
    assert!(tokio::time::timeout(Duration::from_millis(10),
        copy_body(&mut r, &mut reader, &mut writer, &mut log, Direction::Upload)).await.is_err());
    assert!(r.is_closed());
    assert!(events.lock().unwrap().is_empty());
}
