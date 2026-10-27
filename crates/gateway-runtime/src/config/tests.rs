use super::*;
use serde_json::{json, Value};

fn root() -> Value {
    let hash = crate::shipping::state::hex(&gateway_core::sha256::digest(b"test-gateway-token"));
    json!({
        "identities": [{"tenant": 1, "sha256": hash}],
        "destinations": ["https://api.openai.com/v1/responses", "https://api.anthropic.com/v1/messages"],
        "credentials": [{"tenant": 1, "kind": "bearer", "env": "OPENAI_KEY"},
                        {"tenant": 1, "kind": "api_key", "env": "ANTHROPIC_KEY"}],
        "grants": [{"tenant": 1, "selector": 7, "origin": 0, "credential": 0},
                   {"tenant": 1, "selector": 8, "origin": 1, "credential": 1}],
        "limits": {"requests": 2, "chunk_bytes": 4096}, "logging": "strict"
    })
}
fn load(root: &Value) -> Result<GatewayConfig, ConfigError> {
    GatewayConfig::from_json(&serde_json::to_vec(root).unwrap(),
        |name| Some(format!("secret-{name}")))
}

#[test]
fn native_provider_endpoints_keep_their_own_credentials() {
    let r = root();
    let c = load(&r).unwrap();
    assert!(matches!(c.admit(b"incorrect", 7), Err(AdmissionError::Unauthorized)));
    assert!(matches!(c.admit(b"test-gateway-token", 9), Err(AdmissionError::Unauthorized)));
    let one = c.admit(b"test-gateway-token", 7).unwrap();
    // The egress permit names exactly the resolved destination and its route.
    let permit = one.egress();
    assert_eq!(permit.target().text, one.destination_text().as_bytes());
    assert!(matches!(permit.kind(), gateway_core::egress::Origin::Provider { origin: 0, credential: 0, .. }));
    let two = c.admit(b"test-gateway-token", 8).unwrap();
    assert_eq!(one.destination_text(), "https://api.openai.com/v1/responses");
    assert_eq!(two.destination_text(), "https://api.anthropic.com/v1/messages");
    assert_eq!(one.credential_header().0, b"authorization");
    assert_eq!(one.credential_header().1, b"Bearer secret-OPENAI_KEY");
    assert_eq!(two.credential_header().0, b"x-api-key");
    assert_eq!(two.credential_header().1, b"secret-ANTHROPIC_KEY");
}

#[test]
fn configuration_rejects_invalid_routes_and_cross_tenant_credentials() {
    for field in ["tenant", "origin", "credential"] {
        let mut r = root();
        r["grants"][0][field] = json!(99);
        assert!(matches!(load(&r), Err(ConfigError::Policy)), "{field}");
    }
    let mut r = root();
    r["credentials"][0]["tenant"] = json!(2);
    assert!(matches!(load(&r), Err(ConfigError::Policy)));
    let mut r = root();
    r["grants"] = json!([]);
    assert!(matches!(load(&r).unwrap().admit(b"test-gateway-token", 7), Err(AdmissionError::Unauthorized)));
}

#[test]
fn malformed_or_ambiguous_destinations_are_rejected() {
    for input in ["http://example.com/v1", "HTTPS://example.com/v1", "//example.com/v1",
        "https://user:pass@example.com/", "https://example.com/#fragment", "https://example.com/?override=x",
        "https://example.com\\@attacker.example/", "https://example.com:0/", "https://example.com:65536/",
        "https://example.com:/", "https://example.com:abc/", "https://example.com./", "https://-bad.example/",
        "https://example.com//attacker.example/", "https://example.com\r\nX: y", "https://%65xample.com/",
        "https://[::1%25zone]/", "https://example..com/", "https://éxample.com/"] {
        assert!(destination(input).is_err(), "accepted {input:?}");
    }
    for input in ["https://example.com/v1", "https://example.com:8443/v1", "https://[::1]:443/v1"] {
        assert!(destination(input).is_ok(), "rejected {input}");
    }
}

#[test]
fn malformed_limits_and_identity_fail_before_secret_loading() {
    for (field, value) in [("requests", 0), ("requests", 65537), ("chunk_bytes", 0), ("chunk_bytes", 1048577)] {
        let mut r = root(); r["limits"][field] = json!(value);
        assert!(matches!(load(&r), Err(ConfigError::Limits)));
    }
    let mut r = root(); r["limits"] = json!({"requests": 65536, "chunk_bytes": 1048576});
    assert!(matches!(load(&r), Err(ConfigError::Limits)));
    let mut r = root(); r["identities"][0]["sha256"] = json!("not-a-digest");
    assert!(matches!(load(&r), Err(ConfigError::Identity)));
    let mut r = root(); r["grants"][0]["tenant"] = json!(2);
    assert!(matches!(GatewayConfig::from_json(&serde_json::to_vec(&r).unwrap(),
        |_| panic!("must validate before loading secrets")),
        Err(ConfigError::Policy)));
}

#[test]
fn secret_errors_are_redacted_and_invalid_headers_rejected() {
    let r = root(); let root_bytes = serde_json::to_vec(&r).unwrap();
    for secret in [None, Some(""), Some("secret\r\nInjected: header"), Some("contains space")] {
        let result = GatewayConfig::from_json(&root_bytes, |_| secret.map(String::from));
        assert!(matches!(result, Err(ConfigError::Credential)));
    }
    assert_eq!(format!("{:?}", ConfigError::Credential), "Credential");
}

#[test]
fn schemas_reject_unknown_duplicate_and_oversized_input() {
    let mut r = root(); r["fallback"] = json!(true);
    assert!(matches!(load(&r), Err(ConfigError::Syntax)));
    let mut r = root(); r["routes"] = r["grants"].clone();
    assert!(matches!(load(&r), Err(ConfigError::Syntax)));
    let raw = serde_json::to_string(&root()).unwrap();
    let duplicate = raw.replacen("{", "{\"grants\":[],", 1);
    assert!(matches!(GatewayConfig::from_json(duplicate.as_bytes(), |_| None), Err(ConfigError::Syntax)));
    assert!(matches!(GatewayConfig::from_json(&vec![b' '; MAX_CONFIG + 1], |_| None), Err(ConfigError::Limits)));
}

#[test]
fn destination_size_is_bounded_before_secret_loading() {
    let prefix = "https://api.example.com/";
    let endpoint = format!("{prefix}{}", "p".repeat(MAX_DESTINATION_BYTES - prefix.len()));
    let mut r = root(); r["destinations"][0] = json!(endpoint);
    assert!(load(&r).is_ok());
    r["destinations"][0] = json!(format!("{endpoint}x"));
    let mut secret_calls = 0;
    let result = GatewayConfig::from_json(&serde_json::to_vec(&r).unwrap(),
        |_| { secret_calls += 1; Some("secret".into()) });
    assert!(matches!(result, Err(ConfigError::Destination)));
    assert_eq!(secret_calls, 0);
}

#[test]
fn durability_is_explicit_optional_and_independent_of_failure_policy() {
    use gateway_core::audit_receipt::Durability;
    assert_eq!(load(&root()).unwrap().durability(), Durability::Durable);
    for logging in ["strict", "availability"] {
        for (name, expected) in [("durable", Durability::Durable), ("buffered", Durability::Buffered)] {
            let mut r = root(); r["logging"] = json!(logging); r["durability"] = json!(name);
            assert_eq!(load(&r).unwrap().durability(), expected);
        }
    }
    for invalid in [json!(null), json!(true), json!(1), json!(""), json!("async"), json!("Durable")] {
        let mut r = root(); r["durability"] = invalid;
        assert!(load(&r).is_err());
    }
    let raw = serde_json::to_string(&root()).unwrap();
    let duplicate = raw.replacen('{', "{\"durability\":\"durable\",\"durability\":\"buffered\",", 1);
    assert!(GatewayConfig::from_json(duplicate.as_bytes(), |_| Some("secret".into())).is_err());
}

#[test]
fn configured_request_checks_real_logger_receipt_strength() {
    use crate::{disk_log::{DiskLog, Durability}, transfer::Direction, test_support::TempDir};
    use std::time::Duration;
    for logging in ["strict", "availability"] {
        for configured in ["durable", "buffered"] {
            for actual in [Durability::Durable, Durability::Buffered] {
                let mut r = root(); r["logging"] = json!(logging); r["durability"] = json!(configured);
                let config = load(&r).unwrap();
                let dir = TempDir::new();
                let mut log = DiskLog::create_with_durability(&dir.0.join("audit.log"), 16, Duration::from_secs(2), actual).unwrap();
                let mut request = config.admit(b"test-gateway-token", 7).unwrap();
                request.stream().advance(vec![7, 8]).unwrap();
                let accepted = configured == "buffered" || actual == Durability::Durable;
                assert_eq!(request.stream().audit_current(&mut log, Direction::Upload).is_ok(), accepted);
                assert_eq!(request.stream().prepare(2, Direction::Upload).is_some(), accepted);
                log.shutdown(Duration::from_secs(2)).unwrap();
            }
        }
    }
}
