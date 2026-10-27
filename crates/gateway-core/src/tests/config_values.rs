//! Executable checks of the configuration value rules. The proofs cover
//! every input; these pin the rules against concrete values.
use crate::config_schema::CredentialKind;
use crate::config_values::*;

#[test]
fn digests_are_64_hex_digits_in_either_case() {
    let text = "00ff10AbCdEf".repeat(5) + "0123";
    let bytes = digest(text.as_bytes()).unwrap();
    assert_eq!(bytes.len(), 32);
    assert_eq!(&bytes[..6], &[0x00, 0xff, 0x10, 0xab, 0xcd, 0xef]);
    assert_eq!(&bytes[30..], &[0x01, 0x23]);
    for bad in [&text[..63], &format!("{}g", &text[..63]), &format!("{text}0"), "", "zz"] { assert!(digest(bad.as_bytes()).is_none(), "{bad:?}"); }
}

#[test]
fn secret_names_and_values_follow_the_rules() {
    assert!(secret_name_ok_exec(b"OPENAI_KEY_2") && secret_name_ok_exec(b"a") && secret_name_ok_exec(&[b'x'; 128]));
    for bad in [&b""[..], b"has space", b"dash-name", b"caf\xc3\xa9", &[b'x'; 129]] { assert!(!secret_name_ok_exec(bad), "{bad:?}"); }
    assert!(secret_ok_exec(b"sk-abc!~", 8) && secret_ok_exec(b"x", 1));
    for (bad, max) in [(&b""[..], 8usize), (b"too long", 7), (b"has space", 16), (b"tab\there", 16), (b"nl\n", 16), (b"\x7f", 16), (b"\xc3\xa9", 16)] {
        assert!(!secret_ok_exec(bad, max), "{bad:?}");
    }
}

#[test]
fn credential_values_carry_the_bearer_prefix_and_no_control_bytes() {
    assert_eq!(credential_value_exec(CredentialKind::Bearer, b"tok"), b"Bearer tok");
    assert_eq!(credential_value_exec(CredentialKind::ApiKey, b"tok"), b"tok");
    let long = vec![b'~'; MAX_CREDENTIAL_BYTES];
    let value = credential_value_exec(CredentialKind::Bearer, &long);
    assert_eq!(value.len(), MAX_CREDENTIAL_BYTES + 7);
    assert!(value.iter().all(|b| (32..=126).contains(b)));
    assert!(shipping_limits_ok_exec(1, MIN_EXCHANGE_BYTES, MIN_POLL_MS) && shipping_limits_ok_exec(MAX_OPEN_EXCHANGES, MAX_EXCHANGE_BYTES, MAX_POLL_MS));
    for (open, bytes, poll) in [(0, MIN_EXCHANGE_BYTES, MIN_POLL_MS), (MAX_OPEN_EXCHANGES + 1, MIN_EXCHANGE_BYTES, MIN_POLL_MS),
        (1, MIN_EXCHANGE_BYTES - 1, MIN_POLL_MS), (1, MAX_EXCHANGE_BYTES + 1, MIN_POLL_MS), (1, MIN_EXCHANGE_BYTES, MIN_POLL_MS - 1), (1, MIN_EXCHANGE_BYTES, MAX_POLL_MS + 1)] {
        assert!(!shipping_limits_ok_exec(open, bytes, poll));
    }
    assert!(state_dir_ok_exec(b"/var/lib/hypgate") && !state_dir_ok_exec(b"") && !state_dir_ok_exec(&[b'p'; MAX_STATE_DIR + 1]));
}
