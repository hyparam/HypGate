use gateway_core::{s3, shipping_identity::hex};
fn text(bytes: Vec<u8>) -> String { String::from_utf8(bytes).unwrap() }

#[test]
fn hmac_matches_rfc4231_including_long_keys() {
    assert_eq!(text(hex(&s3::mac(&[0x0b; 20], b"Hi There"))), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    assert_eq!(text(hex(&s3::mac(b"Jefe", b"what do ya want for nothing?"))), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    assert_eq!(text(hex(&s3::mac(&[0xaa; 131], b"Test Using Larger Than Block-Size Key - Hash Key First"))), "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
}

#[test]
fn sigv4_matches_independent_python_hashlib_hmac_vectors() {
    for (token, expected) in [("", "d79c85c67f1ce38a854170fd8e49cb585e06847413ae1354a9dfb1667b9156be"),
        ("session/token+=", "55e820997e18cea1c2b3a266cac24c0801d87f8c6ed0e995307fe98be571f829")] {
        let signed = s3::sign(b"examplebucket.s3.amazonaws.com", b"/logs/test.ndjson", b"20130524T000000Z", b"us-east-1", b"AKIDEXAMPLE",
            b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", token.as_bytes(), b"Welcome to Amazon S3.");
        let auth = text(signed.authorization);
        assert!(auth.ends_with(expected), "{auth}");
        assert_eq!(auth.contains(";x-amz-security-token"), !token.is_empty());
    }
}

#[test]
fn s3_errors_never_acknowledge_or_poison() {
    for status in 0..=599 {
        let reply = s3::upload_reply(status, Some(10));
        assert_eq!(reply.status, if status == 200 { 200 } else if status == 429 || status == 503 { 503 } else { 0 });
        assert!(!reply.revocation && reply.credential.is_none());
        assert_eq!(reply.retry_after, Some(10));
    }
}

#[test]
fn keys_are_stable_and_bind_content_and_batch() {
    let key = s3::object_path(b"/bucket/logs/", b"batch", b"rows\n");
    assert_eq!(key, s3::object_path(b"/bucket/logs/", b"batch", b"rows\n"));
    assert_ne!(key, s3::object_path(b"/bucket/logs/", b"batch", b"changed\n"));
    assert_ne!(key, s3::object_path(b"/bucket/logs/", b"other", b"rows\n"));
    for bad in [b"/../".as_slice(), b"/a%20b/", b"/a?b/", b"/a\r\nb/"] { assert!(!s3::safe_exec(bad, true)); }
    assert!(s3::safe_exec(b"/bucket/prefix-012_A/", true));
}
