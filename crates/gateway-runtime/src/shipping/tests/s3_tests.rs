use super::*;
use sha2::{Digest, Sha256};

const SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const SESSION_TOKEN: &str = "session/token+=";
fn resolve(name: &str) -> Option<String> {
    match name { "HYP_TOKEN" => Some(SECRET.into()), "AWS_ACCESS_KEY_ID" => Some("AKIDEXAMPLE".into()),
        "AWS_SESSION_TOKEN" => Some(SESSION_TOKEN.into()), _ => None }
}
fn config(port: u16, state_dir: &std::path::Path, prefix: &str) -> ShippingConfig {
    ShippingConfig::from_root_json(&shipping_json(port, state_dir, json!({
        "server": format!("https://localhost:{port}/{prefix}/"), "s3_region": "us-east-1",
        "s3_access_key_env": "AWS_ACCESS_KEY_ID", "s3_session_token_env": "AWS_SESSION_TOKEN"
    })), resolve).unwrap().unwrap()
}
fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let key = if key.len() > 64 { Sha256::digest(key).to_vec() } else { key.to_vec() };
    let mut inner = [0x36; 64]; let mut outer = [0x5c; 64];
    for (i, b) in key.iter().enumerate() { inner[i] ^= b; outer[i] ^= b; }
    let mut h = Sha256::new(); h.update(inner); h.update(data);
    let mut o = Sha256::new(); o.update(outer); o.update(h.finalize()); o.finalize().to_vec()
}
// Independent verifier: sha2 rather than the production SHA/HMAC; reconstruct from wire headers.
fn verify(request: &Received) {
    assert_eq!(request.head.method, b"PUT");
    assert!(request.target().starts_with("/bucket/"));
    assert_eq!(request.header("content-type"), Some("application/x-ndjson"));
    assert_eq!(request.header("x-amz-security-token"), Some(SESSION_TOKEN));
    let hash = hex(&Sha256::digest(&request.body));
    assert_eq!(request.header("x-amz-content-sha256"), Some(hash.as_str()));
    assert!(request.target().ends_with(&format!("-{hash}.ndjson")));
    let date = request.header("x-amz-date").unwrap();
    assert_eq!(date.len(), 16);
    let names = "host;x-amz-content-sha256;x-amz-date;x-amz-security-token";
    let headers: String = names.split(';').map(|name| format!("{name}:{}\n", request.header(name).unwrap())).collect();
    let canonical = format!("PUT\n{}\n\n{headers}\n{names}\n{hash}", request.target());
    let scope = format!("{}/us-east-1/s3/aws4_request", &date[..8]);
    let message = format!("AWS4-HMAC-SHA256\n{date}\n{scope}\n{}", hex(&Sha256::digest(canonical.as_bytes())));
    let mut key = format!("AWS4{SECRET}").into_bytes();
    for part in [&date[..8], "us-east-1", "s3", "aws4_request"] { key = hmac(&key, part.as_bytes()); }
    let expected = format!("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/{scope}, SignedHeaders={names}, Signature={}", hex(&hmac(&key, message.as_bytes())));
    assert_eq!(request.header("authorization"), Some(expected.as_str()));
    assert!(!String::from_utf8_lossy(&request.body).contains(SECRET));
    assert!(request.header("x-hyp-batch-id").is_none());
}

#[test]
fn s3_signed_put_retries_resumes_and_scopes_checkpoints_to_destination() {
    let (_, tls_config, roots) = self_signed();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let received = Arc::new(Mutex::new(Vec::<(String, Vec<u8>)>::new()));
    let thread = {
        let stop = stop.clone(); let received = received.clone();
        thread::spawn(move || {
            for socket in listener.incoming() {
                if stop.load(Ordering::SeqCst) { break; }
                let mut tls = tls_server(socket.unwrap(), &tls_config).unwrap();
                let request = read_request(&mut tls).unwrap();
                verify(&request);
                let count = { let mut all = received.lock().unwrap(); all.push((request.target().to_owned(), request.body)); all.len() };
                // Both throttling and a non-poisonable permanent-looking error must preserve the batch.
                let status = match count { 1 => 503, 2 => 400, _ => 200 };
                write_response(&mut tls, status, &[("retry-after", "1")], b"").unwrap();
                tls.conn.send_close_notify(); let _ = tls.flush();
            }
        })
    };
    let _server = FakeServer { stop, address, thread: Some(thread) };
    let dir = TempDir::new(); let state_dir = dir.0.join("state"); std::fs::create_dir(&state_dir).unwrap();
    let log_path = dir.0.join("audit.log");
    let mut log = DiskLog::create_rotating(&log_path, 4, Duration::from_secs(2), crate::disk_log::MAX_RECORD_BYTES,
        crate::disk_log::Rotation { max_bytes: 128, ..Default::default() }).unwrap();
    write_exchange(&mut log, 1, "https://api.anthropic.com/v1/messages", ANTHROPIC_REQUEST.as_bytes(), 200, &[ANTHROPIC_RESPONSE.as_bytes()], 0);
    log.shutdown(Duration::from_secs(5)).unwrap();
    let ship = |prefix: &str| ship_to_end_with_roots(config(address.port(), &state_dir, prefix), log_path.clone(), Some(roots.clone())).unwrap();
    let metrics = ship("bucket/logs");
    assert_eq!(metrics.batches_acknowledged(), 1); assert_eq!(metrics.poisoned_batches(), 0);
    assert!(!state_dir.join("identity.json").exists());
    let checkpoint = load_checkpoint(&state_dir).unwrap();
    assert_eq!(checkpoint.resolved, 1); assert!(checkpoint.session.starts_with("s3:"));
    assert_eq!(received.lock().unwrap().len(), 3);
    assert_eq!(ship("bucket/logs").batches_acknowledged(), 0);
    assert_eq!(received.lock().unwrap().len(), 3);
    // A lost checkpoint (including crash after accepted PUT) overwrites the same object.
    std::fs::remove_file(state_dir.join("checkpoint.json")).unwrap();
    assert_eq!(ship("bucket/logs").batches_acknowledged(), 1);
    { let all = received.lock().unwrap(); assert_eq!(all.len(), 4); for item in &all[1..] { assert_eq!(item, &all[0]); } }
    assert_eq!(ship("bucket/other").batches_acknowledged(), 1);
    let all = received.lock().unwrap(); assert_eq!(all.len(), 5);
    assert!(all[4].0.starts_with("/bucket/other/")); assert_eq!(all[4].1, all[0].1);
}

#[test]
fn s3_configuration_rejects_incomplete_or_unsafe_settings() {
    let dir = TempDir::new();
    assert!(config(443, &dir.0, "bucket/logs").s3.is_some());
    let base = json!({"s3_region": "us-east-1", "s3_access_key_env": "AWS_ACCESS_KEY_ID"});
    for extra in [json!({"s3_region": 1}), json!({"s3_region": ""}), json!({"s3_region": "us east"}),
        json!({"s3_access_key_env": ""}), json!({"s3_access_key_env": "MISSING"}),
        json!({"s3_session_token_env": "MISSING"}), json!({"server": "https://localhost/bucket"}),
        json!({"server": "https://localhost/a/../"}), json!({"server": "https://localhost/a%20b/"})] {
        let mut fields = base.clone(); for (key, value) in extra.as_object().unwrap() { fields[key] = value.clone(); }
        assert!(ShippingConfig::from_root_json(&shipping_json(443, &dir.0, fields), resolve).is_err(), "{extra}");
    }
    for bad in ["", "with space", "has\r\nnewline", &"x".repeat(16385)] {
        let raw = shipping_json(443, &dir.0, json!({"s3_region":"us-east-1", "s3_access_key_env":"AWS_ACCESS_KEY_ID", "s3_session_token_env":"AWS_SESSION_TOKEN"}));
        assert!(ShippingConfig::from_root_json(&raw, |name| if name == "AWS_SESSION_TOKEN" { Some(bad.into()) } else { resolve(name) }).is_err());
    }
    let duplicate = br#"{"shipping":{"server":"https://localhost/","token_env":"HYP_TOKEN","state_dir":"/tmp","s3_region":"us-east-1","s3_region":"eu-west-1"}}"#;
    assert!(ShippingConfig::from_root_json(duplicate, resolve).is_err());
}
