use super::*;
use crate::test_support::admission;
use std::{net::{TcpListener, TcpStream}, sync::{Arc, Mutex}, time::Duration};

#[derive(Clone, Debug, PartialEq, Eq)]
enum Event { Log(u64, Direction, Vec<u8>), Write(Vec<u8>) }
type Events = Arc<Mutex<Vec<Event>>>;
struct Log { events: Events, fail: bool, panics: bool }
impl AuditLog for Log {
    fn session_id(&self) -> u128 { 0 }
    fn append(&mut self, record: LogRecord<'_>) -> io::Result<crate::transfer::AuditReceipt> {
        assert_eq!(record.tenant, 1);
        assert!(record.request != 0);
        if self.panics { panic!("injected logger failure mid-append"); }
        self.events.lock().unwrap().push(Event::Log(record.chunk, record.kind.direction().unwrap(), record.bytes.to_vec()));
        if self.fail { Err(io::ErrorKind::Other.into()) } else { Ok(receipt_for_test(record)) }
    }
}
struct Writer { events: Events, max: usize, fail: bool, flush_fail: bool, panics: bool }
impl Write for Writer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.panics { panic!("injected writer failure mid-write"); }
        if self.fail { return Err(io::ErrorKind::BrokenPipe.into()); }
        let n = self.max.min(bytes.len());
        self.events.lock().unwrap().push(Event::Write(bytes[..n].to_vec()));
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.flush_fail { Err(io::ErrorKind::BrokenPipe.into()) } else { Ok(()) }
    }
}
fn io_pair() -> (Events, Log, Writer) {
    let events = Events::default();
    (events.clone(), Log { events: events.clone(), fail: false, panics: false },
        Writer { events, max: 2, fail: false, flush_fail: false, panics: false })
}

#[test]
fn multichunk_partial_writes_follow_durable_logs_and_preserve_bytes() {
    let a = admission(1, 3, true); let mut r = a.admit(&[11; 32], 7).unwrap();
    let (events, mut log, mut writer) = io_pair();
    let stats = copy_body(&mut r, &mut &b"abcdefg"[..], &mut writer, &mut log, Direction::Upload).unwrap();
    assert_eq!((stats.accepted_bytes(), stats.audit_gap()), (7, false));
    assert_eq!(*events.lock().unwrap(), vec![
        Event::Log(1, Direction::Upload, b"abc".to_vec()), Event::Write(b"ab".to_vec()), Event::Write(b"c".to_vec()),
        Event::Log(2, Direction::Upload, b"def".to_vec()), Event::Write(b"de".to_vec()), Event::Write(b"f".to_vec()),
        Event::Log(3, Direction::Upload, b"g".to_vec()), Event::Write(b"g".to_vec()),
    ]);
    let stats = copy_body(&mut r, &mut &b"data: ok\n\n"[..], &mut writer, &mut log, Direction::Download).unwrap();
    assert_eq!(stats.accepted_bytes(), 10);
    assert!(events.lock().unwrap().iter().any(|e| matches!(e, Event::Log(4, Direction::Download, _))));
}

#[test]
fn logger_failure_is_closed_in_strict_mode_and_reported_in_availability_mode() {
    for strict in [true, false] {
        let a = admission(1, 3, strict); let mut r = a.admit(&[11; 32], 7).unwrap();
        let (events, mut log, mut writer) = io_pair(); log.fail = true;
        let result = copy_body(&mut r, &mut &b"abcdef"[..], &mut writer, &mut log, Direction::Upload);
        if strict {
            assert_eq!(result.err().unwrap(), TransferError::Log);
            assert!(!events.lock().unwrap().iter().any(|e| matches!(e, Event::Write(_))));
            assert!(r.is_closed());
        } else {
            let stats = result.unwrap();
            assert_eq!((stats.accepted_bytes(), stats.audit_gap()), (6, true));
            assert_eq!(events.lock().unwrap().iter().filter(|e| matches!(e, Event::Log(..))).count(), 1);
            // Degradation persists across directions even if a later log call could succeed.
            log.fail = false;
            assert!(copy_body(&mut r, &mut &b"z"[..], &mut writer, &mut log, Direction::Download).unwrap().audit_gap());
            assert_eq!(events.lock().unwrap().iter().filter(|e| matches!(e, Event::Log(..))).count(), 1);
        }
    }
}

#[test]
fn zero_error_and_flush_failures_close_without_replay() {
    for expected in [TransferError::WriteZero, TransferError::Write, TransferError::Flush] {
        let a = admission(1, 3, false); let mut r = a.admit(&[11; 32], 7).unwrap();
        let (_, mut log, mut writer) = io_pair();
        writer.max = if expected == TransferError::WriteZero { 0 } else { 2 };
        writer.fail = expected == TransferError::Write;
        writer.flush_fail = expected == TransferError::Flush;
        assert_eq!(copy_body(&mut r, &mut &b"abc"[..], &mut writer, &mut log, Direction::Upload).err().unwrap(), expected);
        assert!(r.is_closed());
        assert!(r.prepare(1, Direction::Upload).is_none());
        assert_eq!(copy_body(&mut r, &mut &b""[..], &mut writer, &mut log, Direction::Download).err().unwrap(),
            TransferError::InvalidState);
    }
}

#[test]
fn abandoning_a_log_or_write_mid_effect_closes_the_request_and_retains_its_lease() {
    // The copy left by unwinding (the blocking analogue of a dropped pending
    // future) closes the stream: the effect's completion is unknown.
    for panicking_log in [true, false] {
        let a = admission(1, 3, true); let mut r = a.admit(&[11; 32], 7).unwrap();
        let (_, mut log, mut writer) = io_pair();
        log.panics = panicking_log; writer.panics = !panicking_log;
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = copy_body(&mut r, &mut &b"abc"[..], &mut writer, &mut log, Direction::Upload);
        })).is_err());
        assert!(r.is_closed());
        assert!(a.admit(&[11; 32], 7).is_err());
        drop(r);
        assert!(a.admit(&[11; 32], 7).is_ok());
    }
}

#[test]
fn real_socket_backpressure_preserves_fragmented_sse_bytes() {
    let a = admission(1, 3, true); let mut r = a.admit(&[11; 32], 7).unwrap();
    let (_, mut log, _) = io_pair();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let mut source = TcpStream::connect(address).unwrap();
    let (mut input, _) = listener.accept().unwrap();
    let mut sink = TcpStream::connect(address).unwrap();
    let (mut output, _) = listener.accept().unwrap();
    input.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    output.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let expected = b"data: {\"delta\":\"hello\"}\n\ndata: [DONE]\n\n";
    let producer = std::thread::spawn(move || {
        for part in expected.chunks(2) {
            source.write_all(part).unwrap(); source.flush().unwrap();
            std::thread::sleep(Duration::from_millis(1));
        }
        source.shutdown(std::net::Shutdown::Write).unwrap();
        source
    });
    let consumer = std::thread::spawn(move || {
        let mut bytes = Vec::new(); output.read_to_end(&mut bytes).unwrap(); bytes
    });
    let result = copy_body(&mut r, &mut input, &mut sink, &mut log, Direction::Download);
    sink.shutdown(std::net::Shutdown::Write).unwrap();
    let received = consumer.join().unwrap();
    let _source = producer.join().unwrap();
    assert_eq!(received, expected);
    assert_eq!(result.unwrap().accepted_bytes(), expected.len() as u64);
}

#[test]
fn read_failure_and_abandonment_close_before_any_write() {
    struct FailingRead;
    impl Read for FailingRead {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> { Err(io::ErrorKind::ConnectionReset.into()) }
    }
    struct PanickingRead;
    impl Read for PanickingRead {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> { panic!("injected reader failure mid-read") }
    }
    let a = admission(1, 3, true); let mut r = a.admit(&[11; 32], 7).unwrap();
    let (events, mut log, mut writer) = io_pair();
    assert_eq!(copy_body(&mut r, &mut FailingRead, &mut writer, &mut log, Direction::Upload).err().unwrap(),
        TransferError::Read);
    assert!(r.is_closed());
    assert!(events.lock().unwrap().is_empty());
    drop(r);
    let mut r = a.admit(&[11; 32], 7).unwrap();
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = copy_body(&mut r, &mut PanickingRead, &mut writer, &mut log, Direction::Upload);
    })).is_err());
    assert!(r.is_closed());
    assert!(events.lock().unwrap().is_empty());
}
