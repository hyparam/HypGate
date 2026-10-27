use gateway_core::inbound::{matches_endpoint, route_target};

#[test]
fn sdk_target_preserves_canonical_route_and_exact_endpoint() {
    for route in [0, 1, 7, u64::MAX] {
        let prefix = format!("/routes/{route}");
        for suffix in ["", "/v1/responses", "/v1/chat/completions", "/v1/messages"] {
            let path = format!("{prefix}{suffix}");
            assert_eq!(route_target(path.as_bytes()), Some((route, prefix.len())));
            assert!(matches_endpoint(path.as_bytes(), prefix.len(), suffix.as_bytes()));
            if !suffix.is_empty() {
                assert!(!matches_endpoint(path.as_bytes(), prefix.len(), b"/other"));
            }
        }
    }
    for path in ["", "/routes/", "/routes//v1/messages", "/routes/07/v1/messages",
        "/routes/+7/v1/messages", "/routes/18446744073709551616/v1/messages",
        "https://host/routes/7/v1/messages", "/routes/7?x=1"] {
        assert_eq!(route_target(path.as_bytes()), None, "{path}");
    }
}
