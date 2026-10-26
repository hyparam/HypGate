//! Executable checks of body delimiting. The proofs cover every input under
//! every framing; these pin concrete bodies at every split of the input and
//! every caller room, and what a closed connection means to each framing.
use crate::http1_body::*;
use crate::http1_framing::Framing;

/// Drive a decoder over `wire` as a reader would: offer it pieces of `piece`
/// bytes with `room` bytes of room per data step, and close the connection
/// when the wire runs out. Returns the body, whether the decoder finished,
/// and how many wire bytes it consumed; `None` when it rejected.
fn decode(framing: Framing, wire: &[u8], piece: usize, room: usize) -> Option<(Vec<u8>, bool, usize)> {
    let mut decoder = BodyDecoder::new(framing);
    let mut body = Vec::new();
    let mut at = 0;
    while at < wire.len() && !decoder.is_done() {
        let end = (at + piece).min(wire.len());
        let mut window = &wire[at..end];
        while !window.is_empty() && !decoder.is_done() {
            match decoder.step(window, room) {
                Step::Framing(n) => { window = &window[n..]; at += n; }
                Step::Data(n) => { assert!(n <= room); body.extend_from_slice(&window[..n]); window = &window[n..]; at += n; }
                Step::Done(n) => { window = &window[n..]; at += n; }
                Step::Rejected => return None,
            }
        }
    }
    if !decoder.is_done() && !decoder.close() { return None; }
    Some((body, decoder.is_done(), at))
}

#[test]
fn a_fixed_length_body_stops_at_its_count() {
    let wire = b"hello worldtrailing";
    for piece in 1..=wire.len() {
        for room in 1..=12 {
            let (body, done, consumed) = decode(Framing::Length(11), wire, piece, room).unwrap();
            assert_eq!(body, b"hello world", "piece {piece} room {room}");
            assert!(done);
            assert_eq!(consumed, 11);
        }
    }
}

#[test]
fn an_empty_fixed_length_body_is_complete_at_once() {
    let decoder = BodyDecoder::new(Framing::Length(0));
    assert!(decoder.is_done());
    assert!(!decoder.is_failed());
    assert_eq!(decode(Framing::Length(0), b"anything", 3, 4), Some((Vec::new(), true, 0)));
}

#[test]
fn a_short_fixed_length_body_is_truncated_by_close() {
    assert_eq!(decode(Framing::Length(11), b"hello", 2, 8), None);
    let mut decoder = BodyDecoder::new(Framing::Length(3));
    assert_eq!(decoder.step(b"ab", 8), Step::Data(2));
    assert!(!decoder.close());
    assert!(decoder.is_failed());
    assert!(!decoder.is_done());
}

#[test]
fn a_data_step_takes_all_it_can_within_the_room() {
    let mut decoder = BodyDecoder::new(Framing::Length(10));
    assert_eq!(decoder.step(b"abcdefgh", 3), Step::Data(3));
    assert_eq!(decoder.step(b"defgh", 100), Step::Data(5));
    assert_eq!(decoder.step(b"ijklmnop", 100), Step::Data(2));
    assert!(decoder.is_done());
    let mut close = BodyDecoder::new(Framing::UntilClose);
    assert_eq!(close.step(b"abcdefgh", 3), Step::Data(3));
    assert_eq!(close.step(b"abcdefgh", 100), Step::Data(8));
    assert!(!close.is_done());
}

#[test]
fn a_chunked_body_is_decoded_at_every_split_and_room() {
    let wire = b"4\r\nWiki\r\n5\r\npedia\r\nE\r\n in\r\n\r\nchunks.\r\n0\r\n\r\ntrailing bytes";
    let end = wire.len() - b"trailing bytes".len();
    for piece in 1..=wire.len() {
        for room in [1, 2, 3, 5, 7, 16, 1024] {
            let (body, done, consumed) = decode(Framing::Chunked, wire, piece, room).unwrap();
            assert_eq!(body, b"Wikipedia in\r\n\r\nchunks.", "piece {piece} room {room}");
            assert!(done);
            assert_eq!(consumed, end);
        }
    }
}

#[test]
fn a_malformed_chunked_body_is_rejected_without_consuming() {
    let mut decoder = BodyDecoder::new(Framing::Chunked);
    assert_eq!(decoder.step(b"3\r\nabc\r\n", 8), Step::Framing(1));
    assert_eq!(decoder.step(b"\r\nabc\r\n", 8), Step::Framing(1));
    assert_eq!(decoder.step(b"\nabc\r\n", 8), Step::Framing(1));
    assert_eq!(decoder.step(b"abc\r\n", 2), Step::Data(2));
    assert_eq!(decoder.step(b"c\r\n", 2), Step::Data(1));
    assert_eq!(decoder.step(b"\r\n", 2), Step::Framing(1));
    assert_eq!(decoder.step(b"\n", 2), Step::Framing(1));
    assert_eq!(decoder.step(b"zz", 2), Step::Rejected);
    assert!(decoder.is_failed());
    assert_eq!(decode(Framing::Chunked, b"4\r\nWiki\r\n0\r\n", 1, 8), None, "closed before the last CRLF");
    assert_eq!(decode(Framing::Chunked, b"4\r\nWikipedia\r\n0\r\n\r\n", 3, 8), None, "bad chunk delimiter");
}

#[test]
fn a_read_to_close_body_is_everything_until_close() {
    let wire = b"all of it, whatever it says\r\n0\r\n\r\n";
    for piece in 1..=wire.len() {
        for room in [1, 4, 1024] {
            let (body, done, consumed) = decode(Framing::UntilClose, wire, piece, room).unwrap();
            assert_eq!(body, wire);
            assert!(done);
            assert_eq!(consumed, wire.len());
        }
    }
    assert_eq!(decode(Framing::UntilClose, b"", 1, 1), Some((Vec::new(), true, 0)));
}

#[test]
fn an_abandoned_decoder_is_failed() {
    let mut decoder = BodyDecoder::new(Framing::UntilClose);
    assert_eq!(decoder.step(b"ab", 8), Step::Data(2));
    decoder.abandon();
    assert!(decoder.is_failed());
    assert!(!decoder.is_done());
}
