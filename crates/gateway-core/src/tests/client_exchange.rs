//! Executable checks of the client exchange driver against a scripted wire.
//! The proofs cover every wire; these pin the concrete outcomes.
use crate::body_reader::{Fill, Source};
use crate::client_exchange::*;
use crate::sink::{Put, Sink};

/// A wire that takes everything offered and answers with scripted reads.
struct Scripted { reads: Vec<Vec<u8>>, then: Fill, taken: Vec<u8>, accept: Option<usize> }
impl Scripted {
    fn new(reads: &[&[u8]], then: Fill) -> Self {
        Scripted { reads: reads.iter().rev().map(|r| r.to_vec()).collect(), then, taken: Vec::new(), accept: None }
    }
    fn accepting(mut self, bytes: usize) -> Self { self.accept = Some(bytes); self }
}
impl Source for Scripted {
    fn fill(&mut self, buffer: &mut Vec<u8>, max: usize) -> Fill {
        match self.reads.pop() {
            Some(bytes) => { assert!(!bytes.is_empty() && bytes.len() <= max); buffer.extend_from_slice(&bytes); Fill::Bytes }
            None => self.then,
        }
    }
}
impl Sink for Scripted {
    fn put(&mut self, bytes: &[u8]) -> Put {
        match self.accept {
            Some(0) => Put::Closed,
            Some(n) => { let n = n.min(bytes.len()); self.accept = Some(0); self.taken.extend_from_slice(&bytes[..n]); Put::Wrote(n) }
            None => { self.taken.extend_from_slice(bytes); Put::Wrote(bytes.len()) }
        }
    }
}

fn fault(out: Exchanged) -> ClientFault { match out.result { Err(fault) => fault, Ok(_) => panic!("a reply where a fault was expected") } }

const HEAD: &[u8] = b"POST /p HTTP/1.1\r\nhost: h\r\n\r\n";

#[test]
fn the_request_is_sent_whole_and_the_reply_body_is_read_to_its_framing() {
    let mut wire = Scripted::new(&[b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\nretry-after: 3\r\n\r\nhel", b"lo", b"ignored"], Fill::Closed);
    let out = exchange(&mut wire, HEAD, b"body", 64);
    let reply = out.result.unwrap();
    assert_eq!((reply.head.status, reply.body.as_slice()), (200, &b"hello"[..]));
    assert_eq!(reply.head.fields.iter().find(|f| f.name == b"retry-after").unwrap().value, b"3");
    assert_eq!(wire.taken, [HEAD, b"body"].concat());
    let mut wire = Scripted::new(&[b"HTTP/1.1 202 Accepted\r\ntransfer-encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n"], Fill::Closed);
    assert_eq!(exchange(&mut wire, HEAD, b"", 64).result.unwrap().body, b"{}");
    let mut wire = Scripted::new(&[b"HTTP/1.1 204 No Content\r\ncontent-length: 9\r\n\r\n"], Fill::Closed);
    let reply = exchange(&mut wire, HEAD, b"", 64).result.unwrap();
    assert_eq!((reply.head.status, reply.body.len()), (204, 0), "no body after 204, whatever the fields say");
    let mut wire = Scripted::new(&[b"HTTP/1.1 503 Busy\r\n\r\nuntil close"], Fill::Closed);
    assert_eq!(exchange(&mut wire, HEAD, b"", 64).result.unwrap().body, b"until close");
}

#[test]
fn interim_heads_are_skipped_up_to_the_bound() {
    let mut wire = Scripted::new(&[b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 102 Processing\r\n\r\nHTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n"], Fill::Closed);
    assert_eq!(exchange(&mut wire, HEAD, b"", 64).result.unwrap().head.status, 200);
    let many = b"HTTP/1.1 100 Continue\r\n\r\n".repeat(9);
    let mut wire = Scripted::new(&[&many, b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n"], Fill::Closed);
    assert_eq!(fault(exchange(&mut wire, HEAD, b"", 64)), ClientFault::Refused);
    let mut wire = Scripted::new(&[b"HTTP/1.1 101 Switching Protocols\r\n\r\n"], Fill::Closed);
    assert_eq!(fault(exchange(&mut wire, HEAD, b"", 64)), ClientFault::Refused);
    let mut wire = Scripted::new(&[b"HTTP/1.1 200 OK\r\ncontent-length: 1\r\ncontent-length: 2\r\n\r\n"], Fill::Closed);
    assert_eq!(fault(exchange(&mut wire, HEAD, b"", 64)), ClientFault::Refused, "ambiguous framing");
}

#[test]
fn faults_name_the_step_that_failed() {
    let mut wire = Scripted::new(&[], Fill::Closed).accepting(3);
    assert_eq!(fault(exchange(&mut wire, HEAD, b"body", 64)), ClientFault::Send);
    assert_eq!(wire.taken, &HEAD[..3], "a proper prefix was sent");
    let mut wire = Scripted::new(&[], Fill::Closed);
    assert_eq!(fault(exchange(&mut wire, HEAD, b"", 64)), ClientFault::Head, "closed before a head");
    let mut wire = Scripted::new(&[b"HTTP/1.1 200 OK\r\ncontent-length: 70\r\n\r\n"], Fill::Closed);
    assert_eq!(fault(exchange(&mut wire, HEAD, b"", 64)), ClientFault::TooLarge, "declared over the cap");
    let mut wire = Scripted::new(&[b"HTTP/1.1 200 OK\r\n\r\n", &[b'x'; 65]], Fill::Closed);
    assert_eq!(fault(exchange(&mut wire, HEAD, b"", 64)), ClientFault::TooLarge, "grew over the cap");
    let mut wire = Scripted::new(&[b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhel"], Fill::Closed);
    assert_eq!(fault(exchange(&mut wire, HEAD, b"", 64)), ClientFault::Body, "truncated");
    let mut wire = Scripted::new(&[b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\nzz\r\n"], Fill::Closed);
    assert_eq!(fault(exchange(&mut wire, HEAD, b"", 64)), ClientFault::Body, "malformed chunk");
    let mut wire = Scripted::new(&[b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\n"], Fill::Failed);
    assert_eq!(fault(exchange(&mut wire, HEAD, b"", 64)), ClientFault::Body, "the wire failed");
}
