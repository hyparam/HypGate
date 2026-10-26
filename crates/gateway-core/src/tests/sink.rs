//! Executable checks of the writing drivers against a scripted sink. The
//! proofs cover every sink; these pin the concrete outcomes.
use crate::http1_exchange::ChunkStream;
use crate::sink::*;

/// A sink that accepts scripted prefix lengths, then closes or fails.
struct Scripted { accepts: Vec<usize>, then: Put, taken: Vec<u8>, offers: usize }
impl Scripted {
    fn new(accepts: &[usize], then: Put) -> Self { Scripted { accepts: accepts.iter().rev().copied().collect(), then, taken: Vec::new(), offers: 0 } }
}
impl Sink for Scripted {
    fn put(&mut self, bytes: &[u8]) -> Put {
        self.offers += 1;
        match self.accepts.pop() {
            Some(n) => { let n = n.min(bytes.len()).max(1); self.taken.extend_from_slice(&bytes[..n]); Put::Wrote(n) }
            None => self.then,
        }
    }
}

#[test]
fn partial_writes_are_resumed_where_they_stopped() {
    let mut sink = Scripted::new(&[2, 1, 100], Put::Closed);
    assert_eq!(write_all(&mut sink, b"abcdefgh").result, Ok(()));
    assert_eq!((sink.taken.as_slice(), sink.offers), (&b"abcdefgh"[..], 3));
    let mut sink = Scripted::new(&[], Put::Closed);
    assert_eq!(write_all(&mut sink, b"").result, Ok(()));
    assert_eq!(sink.offers, 0, "nothing to offer");
}

#[test]
fn a_close_or_failure_stops_the_loop_with_a_prefix_handed_over() {
    let mut sink = Scripted::new(&[3], Put::Closed);
    assert_eq!(write_all(&mut sink, b"abcdefgh").result, Err(WriteError::Closed));
    assert_eq!(sink.taken, b"abc");
    let mut sink = Scripted::new(&[], Put::Failed);
    assert_eq!(write_all(&mut sink, b"abc").result, Err(WriteError::Failed));
    assert!(sink.taken.is_empty());
}

#[test]
fn each_write_is_one_chunk_and_finish_is_the_last() {
    let mut writer = ChunkWriter::new(Scripted::new(&[1, 1, 1, 100, 100, 100], Put::Closed), ChunkStream::new());
    assert_eq!(writer.write(b"abc"), Ok(()));
    assert_eq!(writer.write(b"de"), Ok(()));
    assert!(!writer.is_ended());
    assert_eq!(writer.finish(), Ok(()));
    assert!(writer.is_ended() && !writer.has_failed());
    let (sink, stream) = writer.into_parts();
    assert_eq!(sink.taken, b"3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n");
    assert!(stream.is_ended());
}

#[test]
fn a_failed_chunk_marks_the_writer_failed() {
    let mut writer = ChunkWriter::new(Scripted::new(&[2], Put::Failed), ChunkStream::new());
    assert_eq!(writer.write(b"abc"), Err(WriteError::Failed));
    assert!(writer.has_failed() && !writer.is_ended());
    let (sink, _) = writer.into_parts();
    assert_eq!(sink.taken, b"3\r", "the prefix handed over before the failure");
}
