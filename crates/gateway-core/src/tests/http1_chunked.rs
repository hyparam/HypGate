//! Executable checks of the chunked decoder and encoder. The proofs cover
//! every input the decoder accepts; these pin that it accepts the encodings a
//! peer sends, at every split of the input, and refuses the malformed ones.
use crate::http1_chunked::*;

/// Feed `bytes` to a fresh decoder in pieces of `piece` bytes; return the body
/// and whether the decoder finished (None when it rejected).
fn decode(bytes: &[u8], piece: usize) -> Option<(Vec<u8>, bool, usize)> {
    let mut decoder = ChunkDecoder::new();
    let mut body = Vec::new();
    let mut at = 0;
    while at < bytes.len() && !decoder.is_done() {
        let end = (at + piece).min(bytes.len());
        let mut window = &bytes[at..end];
        while !window.is_empty() && !decoder.is_done() {
            match decoder.feed(window) {
                Step::Framing(n) => { window = &window[n..]; at += n; }
                Step::Data(n) => { body.extend_from_slice(&window[..n]); window = &window[n..]; at += n; }
                Step::Done(n) => { window = &window[n..]; at += n; }
                Step::Rejected => return None,
            }
        }
    }
    Some((body, decoder.is_done(), at))
}

fn encode(chunks: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in chunks {
        write_chunk_header(chunk.len(), &mut out);
        out.extend_from_slice(chunk);
        write_chunk_end(&mut out);
    }
    write_last_chunk(&mut out);
    out
}

#[test]
fn decodes_a_chunked_body_at_every_split() {
    let wire = b"4\r\nWiki\r\n5\r\npedia\r\nE\r\n in\r\n\r\nchunks.\r\n0\r\n\r\ntrailing bytes";
    let body_len = wire.len() - b"trailing bytes".len();
    for piece in 1..=wire.len() {
        let (body, done, at) = decode(wire, piece).expect("accepted");
        assert_eq!(body, b"Wikipedia in\r\n\r\nchunks.".to_vec(), "piece {piece}");
        assert!(done);
        assert_eq!(at, body_len, "stops exactly at the end of the body");
    }
}

#[test]
fn accepts_hex_case_leading_zeros_and_extensions() {
    let (body, done, _) = decode(b"000a\r\n0123456789\r\nA;name=value\r\nabcdefghij\r\n0;last\r\n\r\n", 3).unwrap();
    assert_eq!(body, b"0123456789abcdefghij".to_vec());
    assert!(done);
    let (body, done, _) = decode(b"0\r\n\r\n", 1).unwrap();
    assert!(body.is_empty() && done);
}

#[test]
fn rejects_malformed_chunked_bodies() {
    for bad in [
        &b"\r\n\r\n"[..],                          // no size digits
        b";ext\r\n\r\n",                           // extension without digits
        b"g\r\n\r\n",                              // not a hex digit
        b"4\nWiki\r\n0\r\n\r\n",                   // bare LF after the size
        b"4\r\nWiki\n0\r\n\r\n",                   // bare LF after the data
        b"4\r\nWikipedia\r\n0\r\n\r\n",            // data longer than its size
        b"4\r\nWik\r\n0\r\n\r\n",                  // data shorter than its size
        b"0\r\nTrailer: x\r\n\r\n",                // trailer fields
        b"0\r\n\n",                                // bare LF ending the body
        b"10000000000000000\r\n",                  // seventeen digits
        b"4 \r\nWiki\r\n0\r\n\r\n",                // blank after the size
    ] {
        assert!(decode(bad, 1).is_none(), "{:?}", String::from_utf8_lossy(bad));
        assert!(decode(bad, bad.len()).is_none(), "{:?}", String::from_utf8_lossy(bad));
    }
}

#[test]
fn accepts_sixteen_digit_sizes_without_overflow() {
    // The size is read; the body is simply never completed here.
    let mut decoder = ChunkDecoder::new();
    for b in b"ffffffffffffffff\r\n" { assert!(matches!(decoder.feed(&[*b]), Step::Framing(1))); }
    assert!(!decoder.is_failed());
    let mut decoder = ChunkDecoder::new();
    let mut failed = false;
    for b in b"1ffffffffffffffff" { if matches!(decoder.feed(&[*b]), Step::Rejected) { failed = true; break; } }
    assert!(failed);
}

#[test]
fn encoder_output_decodes_to_the_same_body() {
    let big = vec![b'x'; 70000];
    let chunks: [&[u8]; 4] = [b"hello", b"\r\n", &big, b"!"];
    let wire = encode(&chunks);
    assert!(wire.starts_with(b"5\r\nhello\r\n2\r\n\r\n\r\n11170\r\n"));
    assert!(wire.ends_with(b"\r\n1\r\n!\r\n0\r\n\r\n"));
    for piece in [1usize, 7, 4096, wire.len()] {
        let (body, done, at) = decode(&wire, piece).unwrap();
        assert_eq!(body, chunks.concat());
        assert!(done);
        assert_eq!(at, wire.len());
    }
    assert_eq!(encode(&[]), b"0\r\n\r\n".to_vec());
    let mut header = Vec::new();
    write_chunk_header(0, &mut header);
    assert_eq!(header, b"0\r\n".to_vec());
    let mut header = Vec::new();
    write_chunk_header(0xdead_beef, &mut header);
    assert_eq!(header, b"deadbeef\r\n".to_vec());
}
