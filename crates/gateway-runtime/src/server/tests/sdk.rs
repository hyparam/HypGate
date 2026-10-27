//! Real Python SDKs talking through the gateway to a local TLS provider.
use super::*;

fn response(path: &str, streaming: bool) -> Vec<u8> {
    let message = json!({"id":"msg_fixture","type":"message","role":"assistant","model":"sdk-test",
        "content":[{"type":"text","text":"hello"}],"stop_reason":"end_turn","stop_sequence":null,
        "usage":{"input_tokens":1,"output_tokens":1}});
    let value = match path {
        "/v1/messages" => message.clone(),
        "/v1/responses" => json!({"id":"resp_fixture","object":"response","created_at":1,"status":"completed",
            "model":"sdk-test","output":[{"id":"msg_fixture","type":"message","role":"assistant","status":"completed",
                "content":[{"type":"output_text","text":"hello","annotations":[]}]}]}),
        _ => json!({"id":"chat_fixture","object":"chat.completion","created":1,"model":"sdk-test",
            "choices":[{"index":0,"message":{"role":"assistant","content":"hello"},"finish_reason":"stop"}]}),
    };
    if !streaming { return serde_json::to_vec(&value).unwrap(); }
    let events = match path {
        "/v1/responses" => vec![json!({"type":"response.output_text.delta","delta":"hello","item_id":"msg_fixture","output_index":0,"content_index":0,"sequence_number":0}),
            json!({"type":"response.completed","response":value,"sequence_number":1})],
        "/v1/messages" => {
            let mut start = message; start["content"] = json!([]); start["stop_reason"] = json!(null);
            vec![json!({"type":"message_start","message":start}),
                json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}),
                json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hello"}}),
                json!({"type":"content_block_stop","index":0}),
                json!({"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":1}}),
                json!({"type":"message_stop"})]
        }
        _ => vec![json!({"id":"chat_fixture","object":"chat.completion.chunk","created":1,"model":"sdk-test",
            "choices":[{"index":0,"delta":{"role":"assistant","content":"hello"},"finish_reason":null}]}),
            json!({"id":"chat_fixture","object":"chat.completion.chunk","created":1,"model":"sdk-test",
            "choices":[{"index":0,"delta":{},"finish_reason":"stop"}]})],
    };
    let mut bytes = Vec::new();
    for event in events {
        if let Some(kind) = event.get("type").and_then(|v| v.as_str()) {
            bytes.extend_from_slice(format!("event: {kind}\n").as_bytes());
        }
        bytes.extend_from_slice(format!("data: {event}\n\n").as_bytes());
    }
    if path == "/v1/chat/completions" { bytes.extend_from_slice(b"data: [DONE]\n\n"); }
    bytes
}

#[test]
#[ignore = "requires Python with openai and anthropic; set HYPGATE_SDK_PYTHON"]
fn real_python_sdks_preserve_json_streams_credentials_and_audit_bytes() {
    let python = std::env::var("HYPGATE_SDK_PYTHON").expect("set HYPGATE_SDK_PYTHON to the SDK virtualenv's python");
    let (listener, tls_config, roots) = tls();
    let port = listener.local_addr().unwrap().port();
    let paths = ["/v1/responses", "/v1/chat/completions", "/v1/messages"];
    let routes: Vec<_> = (0..3).map(|i| json!({"tenant":1,"selector":7+i,"origin":i,"credential":i})).collect();
    let root = json!({"identities":[{"tenant":1,"sha256":format!("{:x}",Sha256::digest(b"gateway"))}],
        "destinations":paths.iter().map(|p| format!("https://localhost:{port}{p}")).collect::<Vec<_>>(),
        "credentials":[{"tenant":1,"kind":"bearer","env":"KEY"},{"tenant":1,"kind":"bearer","env":"KEY"},{"tenant":1,"kind":"api_key","env":"KEY"}],
        "grants":routes,"limits":{"requests":8,"chunk_bytes":4096},"logging":"strict"});
    let config = GatewayConfig::from_json(&serde_json::to_vec(&root).unwrap(),
        |_| Some("provider-secret".into())).unwrap();
    let dir = TempDir::new(); let log = dir.0.join("sdk.log");
    let app = Gateway::new(config, HttpsTransport::with_roots(roots, Duration::from_secs(10)).unwrap(),
        DiskLog::create(&log, 16, Duration::from_secs(2)).unwrap());
    let gateway = spawn_gateway(&app, 32, Duration::from_secs(15));
    listener.set_nonblocking(true).unwrap();
    let provider = std::thread::spawn(move || {
        let mut bodies = Vec::new();
        for path in paths {
            for streaming in [false, true] {
                let mut accepted = None;
                assert!(wait_until(Duration::from_secs(30), || {
                    match listener.accept() {
                        Ok((socket, _)) => { accepted = Some(socket); true },
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => false,
                        Err(e) => panic!("{e}"),
                    }
                }), "SDK did not send the expected request");
                let mut socket = tls_accept(accepted.unwrap(), &tls_config);
                let request = read_request(&mut socket).unwrap();
                assert_eq!(request.head.target, path.as_bytes());
                if path == "/v1/messages" {
                    assert_eq!(request.header("x-api-key"), Some("provider-secret"));
                    assert!(request.header("authorization").is_none());
                } else {
                    assert_eq!(request.header("authorization"), Some("Bearer provider-secret"));
                    assert!(request.header("x-api-key").is_none());
                }
                let parsed: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                assert_eq!(parsed["model"], "sdk-test");
                assert_eq!(parsed["stream"].as_bool().unwrap_or(false), streaming);
                let bytes = response(path, streaming);
                if streaming {
                    let mut stream = start_streaming(&mut socket, 200, &[("content-type", "text/event-stream")]).unwrap();
                    for chunk in bytes.chunks(17) { stream.send(chunk).unwrap(); }
                    stream.finish().unwrap();
                } else {
                    write_response(&mut socket, 200, &[("content-type", "application/json")], &bytes).unwrap();
                }
                bodies.push((request.body, bytes));
            }
        }
        bodies
    });
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/check_sdks.py");
    let result = std::process::Command::new(python).arg(script).arg(format!("http://127.0.0.1:{}", gateway.port))
        .env_remove("ANTHROPIC_API_KEY").env_remove("ANTHROPIC_AUTH_TOKEN").output().unwrap();
    gateway.stop().unwrap();
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    println!("{}", String::from_utf8_lossy(&result.stdout));
    let expected = provider.join().unwrap();
    let records = audit_records(&log);
    let mut ids: Vec<_> = records.iter().map(|r| r.request).collect(); ids.sort(); ids.dedup();
    assert_eq!(ids.len(), 6);
    for (id, (upload, download)) in ids.into_iter().zip(expected) {
        for (direction, bytes) in [(crate::transfer::Direction::Upload, upload), (crate::transfer::Direction::Download, download)] {
            let logged: Vec<_> = records.iter().filter(|r| r.request == id && r.direction() == Some(direction)).flat_map(|r| r.bytes.clone()).collect();
            assert_eq!(logged, bytes);
        }
    }
}
