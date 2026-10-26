//! The SHA-256 spec is a transcription of FIPS 180-4; these checks pin it to
//! the standard's vectors and to an independent implementation, so the
//! theorem `digest(m) == hash(m)` is a theorem about SHA-256.
use crate::sha256::{digest, Hasher, MAX_BYTES};
use sha2::Digest;

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

#[test]
fn the_fips_vectors_hash_as_the_standard_says() {
    assert_eq!(hex(&digest(b"")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert_eq!(hex(&digest(b"abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert_eq!(hex(&digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    assert_eq!(hex(&digest(&vec![b'a'; 1_000_000])), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

#[test]
fn every_length_around_the_block_boundaries_matches_an_independent_implementation() {
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    let mut byte = move || { seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17; (seed >> 11) as u8 };
    for n in 0..300usize {
        let message: Vec<u8> = (0..n).map(|_| byte()).collect();
        assert_eq!(digest(&message)[..], sha2::Sha256::digest(&message)[..], "length {n}");
    }
}

#[test]
fn feeding_in_pieces_hashes_the_concatenation() {
    let message: Vec<u8> = (0..1000u32).map(|i| (i * 7 % 251) as u8).collect();
    let expected = digest(&message);
    for piece in [1usize, 3, 63, 64, 65, 100, 128, 999] {
        let mut hasher = Hasher::new();
        for chunk in message.chunks(piece) { hasher.update(chunk); }
        assert_eq!(hasher.finish(), expected, "pieces of {piece}");
    }
    let mut hasher = Hasher::new();
    hasher.update(&message[..300]);
    assert_eq!(hasher.finish(), digest(&message[..300]), "finish does not consume");
    hasher.update(&message[300..]);
    assert_eq!(hasher.finish(), expected);
    assert_eq!(MAX_BYTES, u64::MAX / 8);
}
