//! Executable checks of the shipping wire readers: the proofs say what a
//! result means; these pin the concrete outcomes for the server's shapes.
use crate::base64url::encode;
use crate::headers::Field;
use crate::shipper::{Path, Request};
use crate::shipping_wire::*;

fn b64(bytes: &[u8]) -> String { String::from_utf8(encode(bytes)).unwrap() }
fn jwt(payload: &[u8]) -> Vec<u8> { format!("{}.{}.{}", b64(br#"{"alg":"HS256"}"#), b64(payload), b64(b"sig")).into_bytes() }
fn field(name: &str, value: &str) -> Field { Field { name: name.as_bytes().to_vec(), value: value.as_bytes().to_vec(), sensitive: false } }

#[test]
fn claims_are_the_subject_and_expiry_of_a_three_segment_token() {
    let c = jws_claims(&jwt(br#"{"sub":"gw-0123456789abcdef","exp":1800000000,"iat":5}"#)).unwrap();
    assert_eq!((c.subject.as_slice(), c.expires), (&b"gw-0123456789abcdef"[..], 1_800_000_000));
    assert!(jws_claims(b"not.a").is_none(), "two segments");
    assert!(jws_claims(b"a.b.c.d").is_none(), "four segments");
    assert!(jws_claims(format!("x.{}.y", b64(br#"{"exp":1}"#)).as_bytes()).is_none(), "no sub");
    assert!(jws_claims(format!("x.{}.y", b64(br#"{"sub":"g"}"#)).as_bytes()).is_none(), "no exp");
    assert!(jws_claims(format!("x.{}.y", b64(br#"{"sub":"","exp":1}"#)).as_bytes()).is_none(), "empty sub");
    assert!(jws_claims(format!("x.{}.y", b64(format!("{{\"sub\":\"{}\",\"exp\":1}}", "s".repeat(129)).as_bytes())).as_bytes()).is_none(), "sub too long");
    assert!(jws_claims(b"x.!!!!.y").is_none(), "not base64url");
    assert!(jws_claims(format!("x.{}.y", b64(b"[1]")).as_bytes()).is_none(), "not an object");
    let long = format!("{}.{}.{}", b64(b"{}"), b64(br#"{"sub":"g","exp":1}"#), "s".repeat(16 * 1024));
    assert!(jws_claims(long.as_bytes()).is_none(), "over the token cap");
}

#[test]
fn an_issued_credential_expires_at_the_earlier_of_the_two_expiries() {
    let token = jwt(br#"{"sub":"gw-1","exp":100}"#);
    let body = format!("{{\"jwt\":\"{}\",\"expires_at\":200,\"org\":\"acme\"}}", String::from_utf8(token.clone()).unwrap());
    let i = issued(body.as_bytes()).unwrap();
    assert_eq!((i.jwt, i.subject, i.expires_at), (token.clone(), b"gw-1".to_vec(), 100));
    let body = format!("{{\"jwt\":\"{}\",\"expires_at\":50}}", String::from_utf8(token).unwrap());
    assert_eq!(issued(body.as_bytes()).unwrap().expires_at, 50);
    assert!(issued(b"{\"expires_at\":5}").is_none(), "no token");
    assert!(issued(b"{\"jwt\":\"a.b.c\"}").is_none(), "no expiry");
    assert!(issued(b"{\"jwt\":\"a.b.c\",\"expires_at\":5}").is_none(), "token without claims");
    assert!(issued(b"nope").is_none());
}

#[test]
fn revocation_is_exactly_the_two_permanent_error_codes() {
    assert!(revocation(br#"{"error":"service_token_revoked"}"#));
    assert!(revocation(br#"{"error":"service_account_disabled","detail":"x"}"#));
    assert!(!revocation(br#"{"error":"jwt_invalid_or_revoked"}"#));
    assert!(!revocation(br#"{"error":"service_token_revoke"}"#));
    assert!(!revocation(br#"{"error":1}"#));
    assert!(!revocation(br#"{}"#));
    assert!(!revocation(b""));
    assert!(!revocation(b"service_token_revoked"));
}

#[test]
fn retry_after_reads_the_first_field_as_blank_padded_digits() {
    assert_eq!(retry_after(&vec![field("retry-after", "30")]), Some(30));
    assert_eq!(retry_after(&vec![field("x", "1"), field("retry-after", " \t007 ")]), Some(7));
    assert_eq!(retry_after(&vec![field("retry-after", "0")]), Some(0));
    assert_eq!(retry_after(&vec![field("retry-after", "18446744073709551615")]), Some(u64::MAX));
    assert_eq!(retry_after(&vec![field("retry-after", "18446744073709551616")]), None, "overflow");
    assert_eq!(retry_after(&vec![field("retry-after", "+5")]), None, "a sign");
    assert_eq!(retry_after(&vec![field("retry-after", "Wed, 21 Oct 2015 07:28:00 GMT")]), None, "a date");
    assert_eq!(retry_after(&vec![field("retry-after", "")]), None);
    assert_eq!(retry_after(&vec![field("retry-after", "  ")]), None);
    assert_eq!(retry_after(&vec![field("retry-after", "1 2")]), None, "a blank inside");
    assert_eq!(retry_after(&vec![field("retry-after", "x"), field("retry-after", "9")]), None, "the first field decides");
    assert_eq!(retry_after(&vec![field("x-retry-after", "9")]), None);
    assert_eq!(retry_after(&vec![]), None);
}

fn request(path: Path, bearer: Option<&[u8]>, body: &[u8], batch_id: Option<&[u8]>) -> Request {
    Request { path, bearer: bearer.map(<[u8]>::to_vec), body: body.to_vec(), batch_id: batch_id.map(<[u8]>::to_vec) }
}

#[test]
fn request_heads_name_the_path_the_fields_and_the_credential_once() {
    let head = request_head(b"cloud.example:8443", &request(Path::Bootstrap, None, b"{\"t\":1}", None)).unwrap();
    assert_eq!(head, b"POST /v1/identity/bootstrap HTTP/1.1\r\nhost: cloud.example:8443\r\nconnection: close\r\ncontent-length: 7\r\ncontent-type: application/json\r\n\r\n");
    let head = request_head(b"h", &request(Path::Refresh, Some(b"ey.x.y"), b"", None)).unwrap();
    assert_eq!(head, b"POST /v1/identity/refresh HTTP/1.1\r\nhost: h\r\nconnection: close\r\ncontent-length: 0\r\nauthorization: Bearer ey.x.y\r\n\r\n");
    let head = request_head(b"h", &request(Path::Ingest, Some(b"t"), b"{}\n", Some(&[0xab, 0x01]))).unwrap();
    assert_eq!(head, b"POST /v1/ingest/proxy HTTP/1.1\r\nhost: h\r\nconnection: close\r\ncontent-length: 3\r\nauthorization: Bearer t\r\ncontent-type: application/x-ndjson\r\nx-hyp-batch-id: ab01\r\n\r\n");
    assert!(request_head(b"h\r\nx: y", &request(Path::Refresh, None, b"", None)).is_none(), "a line break in a value");
    assert!(request_head(b"h", &request(Path::Refresh, Some(b"a b"), b"", None)).is_some(), "blanks inside a value are value bytes");
    assert!(request_head(b"h", &request(Path::Refresh, Some(b"a\x00"), b"", None)).is_none(), "a control byte in the token");
}
