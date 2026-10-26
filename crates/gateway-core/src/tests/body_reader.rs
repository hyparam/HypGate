//! Executable checks of the reading drivers against a scripted source. The
//! proofs cover every source; these pin the concrete outcomes.
use crate::body_reader::*;
use crate::http1_framing::Framing;

/// A source that hands out scripted reads, then closes or fails.
struct Scripted { reads: Vec<Vec<u8>>, then: Fill, fills: usize }
impl Scripted {
    fn new(reads: &[&[u8]], then: Fill) -> Self { Scripted { reads: reads.iter().rev().map(|r| r.to_vec()).collect(), then, fills: 0 } }
}
impl Source for Scripted {
    fn fill(&mut self, buffer: &mut Vec<u8>, max: usize) -> Fill {
        self.fills += 1;
        match self.reads.pop() {
            Some(bytes) => { assert!(!bytes.is_empty() && bytes.len() <= max); buffer.extend_from_slice(&bytes); Fill::Bytes }
            None => self.then,
        }
    }
}

fn drain(reader: &mut BodyReader, source: &mut Scripted, room: usize) -> (Vec<u8>, Read) {
    let mut out = Vec::new();
    loop {
        match reader.read(source, room) {
            Read::Data(start, n) => out.extend_from_slice(&reader.buffer()[start..start + n]),
            other => return (out, other),
        }
    }
}

#[test]
fn a_fixed_length_body_is_delivered_in_order_across_fills_and_leftover() {
    let mut source = Scripted::new(&[b"cde", b"fgh", b"ignored"], Fill::Closed);
    let mut reader = BodyReader::new(b"ab".to_vec(), Framing::Length(8));
    let (body, end) = drain(&mut reader, &mut source, 3);
    assert_eq!((body, end), (b"abcdefgh".to_vec(), Read::End));
    assert!(reader.is_complete());
    assert_eq!(source.fills, 2, "no read past the body's end");
}

#[test]
fn a_chunked_body_yields_only_data_and_ends_at_the_last_chunk() {
    let mut source = Scripted::new(&[b"3\r\nabc\r\n", b"2\r\nd", b"e\r\n0\r\n\r\n"], Fill::Closed);
    let mut reader = BodyReader::new(Vec::new(), Framing::Chunked);
    assert_eq!(drain(&mut reader, &mut source, 1024), (b"abcde".to_vec(), Read::End));
}

#[test]
fn stopping_early_faults_and_closing_ends_an_open_ended_body() {
    let mut source = Scripted::new(&[b"abc"], Fill::Closed);
    let mut reader = BodyReader::new(Vec::new(), Framing::Length(5));
    assert_eq!(drain(&mut reader, &mut source, 16), (b"abc".to_vec(), Read::Truncated));
    assert_eq!(reader.read(&mut source, 16), Read::Failed, "a truncated body stays failed");
    let mut source = Scripted::new(&[b"abc"], Fill::Closed);
    let mut reader = BodyReader::new(Vec::new(), Framing::UntilClose);
    assert_eq!(drain(&mut reader, &mut source, 16), (b"abc".to_vec(), Read::End));
    let mut source = Scripted::new(&[b"zz\r\n"], Fill::Closed);
    let mut reader = BodyReader::new(Vec::new(), Framing::Chunked);
    assert_eq!(drain(&mut reader, &mut source, 16), (Vec::new(), Read::Malformed));
    let mut source = Scripted::new(&[], Fill::Failed);
    let mut reader = BodyReader::new(Vec::new(), Framing::Length(1));
    assert_eq!(drain(&mut reader, &mut source, 16), (Vec::new(), Read::Failed));
}

#[test]
fn heads_are_parsed_from_the_bytes_received_and_the_rest_is_leftover() {
    let mut source = Scripted::new(&[b" HTTP/1.1\r\nhost: h\r\n", b"\r\nBODY"], Fill::Closed);
    let read = read_request_head(&mut source, b"POST /v1".to_vec()).unwrap();
    assert_eq!(read.rest, b"BODY");
    let mut source = Scripted::new(&[b"HTTP/1.1 200 OK\r\n\r\nrest"], Fill::Closed);
    let read = read_status_head(&mut source, Vec::new()).unwrap();
    assert_eq!((read.head.status, read.rest.as_slice()), (200, &b"rest"[..]));
    let mut source = Scripted::new(&[b"HTTP/1.1 200 OK\r\n"], Fill::Closed);
    assert_eq!(read_status_head(&mut source, Vec::new()).err(), Some(HeadError::Closed));
    let mut source = Scripted::new(&[b"HTTP/1.1 200 OK\r\n"], Fill::Failed);
    assert_eq!(read_status_head(&mut source, Vec::new()).err(), Some(HeadError::Io));
    let mut source = Scripted::new(&[b"garbage\r\n\r\n"], Fill::Closed);
    assert_eq!(read_status_head(&mut source, Vec::new()).err(), Some(HeadError::Malformed));
    let long = vec![b'x'; 32 * 1024];
    let mut source = Scripted::new(&[&long[..16 * 1024], &long[..16 * 1024]], Fill::Closed);
    assert_eq!(read_request_head(&mut source, Vec::new()).err(), Some(HeadError::TooLarge));
}
