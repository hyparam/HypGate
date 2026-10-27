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

fn configuration() -> gateway_core::s3_config::Config {
    gateway_core::s3_config::Config { authority: b"bucket.s3.us-west-1.amazonaws.com".to_vec(), prefix: b"/logs/".to_vec(), region: b"us-west-1".to_vec(),
        access_key: b"AKID".to_vec(), secret_key: b"secret".to_vec(), session_token: Vec::new() }
}
#[test]
fn verified_dates_cover_leap_days_rollover_and_year_limit() {
    use gateway_core::s3_delivery::date;
    for (ms, expected) in [(0, "19700101T000000Z"), (951_782_400_000, "20000229T000000Z"),
        (1_704_067_199_999, "20231231T235959Z"), (1_704_067_200_000, "20240101T000000Z"),
        (253_402_300_799_999, "99991231T235959Z")] {
        assert_eq!(text(date(ms).unwrap()), expected);
    }
    assert!(date(253_402_300_800_000).is_none());
    assert!(date(u64::MAX).is_none());
}

#[test]
fn checkpoint_scope_is_exact_and_legacy_or_malformed_progress_replays() {
    use gateway_core::{shipping_checkpoint as cp, s3_driver, json};
    let c = configuration(); let session = [3; 16]; let id = cp::identity(&c, &session);
    for field in 0..4 {
        let mut other = configuration(); let mut other_session = session;
        match field { 0 => other.authority.push(b'x'), 1 => other.prefix.push(b'/'), 2 => other.region.push(b'x'), _ => other_session[0] = 4 }
        assert_ne!(id, cp::identity(&other, &other_session));
    }
    let saved = cp::Checkpoint { session: id, resolved: 7, poisoned: 2, max_open_exchanges: 64, max_exchange_bytes: 4096 };
    let bytes = json::write(&cp::value(&saved)).unwrap();
    assert_eq!(cp::parse(&json::parse(&bytes).unwrap()).unwrap(), saved);
    assert_eq!(s3_driver::restore(&c, session, 64, 4096, &Some(saved)).progress(), (7,2));
    let legacy = cp::Checkpoint { session: b"s3:old-hash".to_vec(), resolved: 7, poisoned: 2, max_open_exchanges: 64, max_exchange_bytes: 4096 };
    assert_eq!(s3_driver::restore(&c, session, 64, 4096, &Some(legacy)).progress(), (0,0));
    for malformed in [br#"{"session":"x","resolved":7,"resolved":99,"poisoned":0,"max_open_exchanges":64,"max_exchange_bytes":4096}"#.as_slice(),
        br#"{"session":"x","resolved":-1,"poisoned":0,"max_open_exchanges":64,"max_exchange_bytes":4096}"#,
        br#"{"session":"x","resolved":7,"poisoned":0}"#] {
        assert!(cp::parse(&json::parse(malformed).unwrap()).is_none());
    }
}

#[test]
fn verified_delivery_sends_only_ingest_and_preserves_the_body() {
    use gateway_core::{s3_delivery::{self, Put, Response, Transport}, shipper::{Path, Request}};
    struct Io { sent: Vec<Put>, status: u16 }
    impl Transport for Io {
        fn milliseconds(&mut self) -> u64 { 0 }
        fn put(&mut self, p: Put) -> Response { self.sent.push(p); Response { status: self.status, retry_after: None } }
    }
    let mut io = Io { sent: Vec::new(), status: 200 };
    for path in [Path::Bootstrap, Path::Refresh] {
        let reply = s3_delivery::send(&configuration(), &mut io, Request { path, bearer: None, body: b"never sent".to_vec(), batch_id: None }, 0);
        assert_eq!(reply.status, 200); assert!(io.sent.is_empty());
    }
    for status in [200, 202, 400, 401, 403, 429, 503] {
        io.status = status;
        let reply = s3_delivery::send(&configuration(), &mut io, Request { path: Path::Ingest, bearer: Some(b"not transmitted".to_vec()),
            body: b"rows\n".to_vec(), batch_id: Some(vec![1; 40]) }, 0);
        assert_eq!(reply.status == 200, status == 200);
        let last = io.sent.last().unwrap(); assert_eq!(last.method, b"PUT"); assert_eq!(last.body, b"rows\n");
        assert_eq!(last.headers.len(), 7); assert!(last.headers.iter().find(|h| h.name == b"authorization").unwrap().sensitive);
        assert!(last.headers.iter().all(|h| h.value != b"not transmitted"));
    }
    let count = io.sent.len();
    let reply = s3_delivery::send(&configuration(), &mut io, Request { path: Path::Ingest, bearer: None, body: vec![], batch_id: None }, 0);
    assert_eq!(reply.status, 0); assert_eq!(io.sent.len(), count);
}

#[test]
fn credential_loader_reads_only_the_selected_configured_names() {
    use gateway_core::{s3_config::{self, Secrets, Backend}, config_schema, destination, json};
    struct Env { reads: Vec<Vec<u8>> }
    impl Secrets for Env {
        fn read(&mut self, name: &[u8]) -> Option<Vec<u8>> {
            self.reads.push(name.to_vec());
            match name { b"SECRET" => Some(b"secret".to_vec()), b"ACCESS" => Some(b"AKID".to_vec()), b"SESSION" => Some(b"session/token+=".to_vec()), _ => None }
        }
    }
    let value = json::parse(br#"{"shipping":{"server":"https://example.com/logs/","state_dir":"/tmp","token_env":"SECRET","s3_region":"us-west-1","s3_access_key_env":"ACCESS","s3_session_token_env":"SESSION"}}"#).unwrap();
    let section = config_schema::read_shipping(&value).unwrap().unwrap();
    let parts = destination::parse(&section.server).unwrap();
    let mut env = Env { reads: vec![] };
    let Backend::S3(c) = s3_config::load(&section, &parts, &mut env).unwrap() else { panic!("wrong backend") };
    assert_eq!(env.reads, [b"SECRET".to_vec(), b"ACCESS".to_vec(), b"SESSION".to_vec()]);
    assert_eq!(c.secret_key, b"secret"); assert_eq!(c.access_key, b"AKID"); assert_eq!(c.session_token, b"session/token+=");
    assert!(c.is_valid());
}
