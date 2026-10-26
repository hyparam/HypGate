//! The rules on configuration values, after the schema: an identity digest
//! is 64 hex digits and decodes to 32 bytes; a secret's environment name is
//! 1 to 128 alphanumeric or underscore bytes; a provider credential or cloud
//! token is visible ASCII within its length limit, so the header value built
//! from it carries no control byte and no line break; the shipping limits
//! and state directory are within their ranges. Each check is proved to
//! decide exactly its rule.
use vstd::prelude::*;

verus! {

pub const MAX_CREDENTIAL_BYTES: usize = 8192;
pub const MAX_TOKEN_BYTES: usize = 512;
pub const MAX_SECRET_NAME: usize = 128;
pub const MAX_STATE_DIR: usize = 4096;
pub const MIN_EXCHANGE_BYTES: usize = 4096;
pub const MAX_EXCHANGE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_OPEN_EXCHANGES: usize = 65_536;
pub const MIN_POLL_MS: u64 = 100;
pub const MAX_POLL_MS: u64 = 60_000;

// ---- identity digests ------------------------------------------------------------------

pub open spec fn all_hex(s: Seq<u8>) -> bool { forall|k: int| 0 <= k < s.len() ==> crate::http1_chunked::is_hex(#[trigger] s[k]) }
/// 64 hex digits, either case.
pub open spec fn digest_ok(text: Seq<u8>) -> bool { text.len() == 64 && all_hex(text) }
/// The 32 bytes the digits spell, most significant digit first.
pub open spec fn digest_of(text: Seq<u8>) -> Seq<u8> {
    Seq::new(32, |i: int| (crate::http1_chunked::hex_val(text[2 * i]) * 16 + crate::http1_chunked::hex_val(text[2 * i + 1])) as u8)
}
fn is_hex_exec(b: u8) -> (out: bool)
    ensures out == crate::http1_chunked::is_hex(b),
{
    (48 <= b && b <= 57) || (65 <= b && b <= 70) || (97 <= b && b <= 102)
}
fn hex_val_exec(b: u8) -> (out: u8)
    requires crate::http1_chunked::is_hex(b),
    ensures out == crate::http1_chunked::hex_val(b), out < 16,
{
    if 48 <= b && b <= 57 { b - 48 } else if 65 <= b && b <= 70 { b - 55 } else { b - 87 }
}
/// The digest a hex text spells, or `None` unless it is 64 hex digits.
#[verifier::loop_isolation(false)]
pub fn digest(text: &[u8]) -> (out: Option<Vec<u8>>)
    ensures match out { Some(d) => digest_ok(text@) && d@ == digest_of(text@) && d@.len() == 32, None => !digest_ok(text@) },
{
    if text.len() != 64 { return None; }
    let mut out: Vec<u8> = Vec::new();
    let mut i: usize = 0;
    while i < 32
        invariant i <= 32, out@.len() == i, forall|k: int| 0 <= k < 2 * i ==> crate::http1_chunked::is_hex(#[trigger] text@[k]),
            forall|k: int| 0 <= k < i ==> out@[k] == digest_of(text@)[k],
        decreases 32 - i,
    {
        let hi = text[2 * i];
        let lo = text[2 * i + 1];
        if !is_hex_exec(hi) || !is_hex_exec(lo) { return None; }
        out.push(hex_val_exec(hi) * 16 + hex_val_exec(lo));
        i = i + 1;
    }
    proof { assert(out@ =~= digest_of(text@)); }
    Some(out)
}

// ---- secrets ---------------------------------------------------------------------------

pub open spec fn is_name_byte(b: u8) -> bool { (48 <= b <= 57) || (65 <= b <= 90) || (97 <= b <= 122) || b == 95 }
/// An environment variable name the gateway will read: 1 to 128 ASCII
/// letters, digits, or underscores.
pub open spec fn secret_name_ok(name: Seq<u8>) -> bool {
    1 <= name.len() <= MAX_SECRET_NAME && forall|k: int| 0 <= k < name.len() ==> is_name_byte(#[trigger] name[k])
}
pub open spec fn visible(b: u8) -> bool { 33 <= b <= 126 }
/// A secret value: 1 to `max` visible ASCII bytes.
pub open spec fn secret_ok(raw: Seq<u8>, max: int) -> bool {
    1 <= raw.len() <= max && forall|k: int| 0 <= k < raw.len() ==> visible(#[trigger] raw[k])
}
#[verifier::loop_isolation(false)]
pub fn secret_name_ok_exec(name: &[u8]) -> (out: bool)
    ensures out == secret_name_ok(name@),
{
    if name.len() == 0 || name.len() > MAX_SECRET_NAME { return false; }
    let mut k: usize = 0;
    while k < name.len()
        invariant k <= name.len(), forall|j: int| 0 <= j < k ==> is_name_byte(#[trigger] name@[j]),
        decreases name.len() - k,
    {
        let b = name[k];
        if !((48 <= b && b <= 57) || (65 <= b && b <= 90) || (97 <= b && b <= 122) || b == 95) { return false; }
        k = k + 1;
    }
    true
}
#[verifier::loop_isolation(false)]
pub fn secret_ok_exec(raw: &[u8], max: usize) -> (out: bool)
    ensures out == secret_ok(raw@, max as int),
{
    if raw.len() == 0 || raw.len() > max { return false; }
    let mut k: usize = 0;
    while k < raw.len()
        invariant k <= raw.len(), forall|j: int| 0 <= j < k ==> visible(#[trigger] raw@[j]),
        decreases raw.len() - k,
    {
        let b = raw[k];
        if b < 33 || b > 126 { return false; }
        k = k + 1;
    }
    true
}
/// The bytes of `Bearer `.
pub open spec fn bearer_prefix() -> Seq<u8> { seq![66u8, 101, 97, 114, 101, 114, 32] }
/// The header value for a credential: `Bearer ` and the secret, or the secret alone.
pub open spec fn credential_value(kind: crate::config_schema::CredentialKind, raw: Seq<u8>) -> Seq<u8> {
    match kind { crate::config_schema::CredentialKind::Bearer => bearer_prefix() + raw, crate::config_schema::CredentialKind::ApiKey => raw }
}
/// A header value with no control byte: nothing below space and no DEL, so
/// no CR, LF, or NUL. A credential value is one for every accepted secret.
pub open spec fn header_safe(s: Seq<u8>) -> bool { forall|k: int| 0 <= k < s.len() ==> 32 <= #[trigger] s[k] <= 126 }
pub fn credential_value_exec(kind: crate::config_schema::CredentialKind, raw: &[u8]) -> (out: Vec<u8>)
    requires secret_ok(raw@, MAX_CREDENTIAL_BYTES as int),
    ensures out@ == credential_value(kind, raw@), header_safe(out@), out@.len() <= MAX_CREDENTIAL_BYTES + 7,
{
    let mut out: Vec<u8> = Vec::new();
    match kind {
        crate::config_schema::CredentialKind::Bearer => {
            out.push(66); out.push(101); out.push(97); out.push(114); out.push(101); out.push(114); out.push(32);
            proof { assert(out@ =~= bearer_prefix()); }
        }
        crate::config_schema::CredentialKind::ApiKey => {}
    }
    let ghost prefix = out@;
    crate::framing::append(&mut out, raw);
    proof {
        assert forall|k: int| 0 <= k < out@.len() implies 32 <= #[trigger] out@[k] <= 126 by {
            if k < prefix.len() { assert(out@[k] == prefix[k]); } else { assert(out@[k] == raw@[k - prefix.len()]); assert(visible(raw@[k - prefix.len()])); }
        }
    }
    out
}
// ---- shipping limits -------------------------------------------------------------------

pub open spec fn shipping_limits_ok(open_exchanges: int, exchange_bytes: int, poll_ms: int) -> bool {
    1 <= open_exchanges <= MAX_OPEN_EXCHANGES && MIN_EXCHANGE_BYTES <= exchange_bytes <= MAX_EXCHANGE_BYTES && MIN_POLL_MS <= poll_ms <= MAX_POLL_MS
}
pub fn shipping_limits_ok_exec(open_exchanges: usize, exchange_bytes: usize, poll_ms: u64) -> (out: bool)
    ensures out == shipping_limits_ok(open_exchanges as int, exchange_bytes as int, poll_ms as int),
{
    open_exchanges >= 1 && open_exchanges <= MAX_OPEN_EXCHANGES && exchange_bytes >= MIN_EXCHANGE_BYTES && exchange_bytes <= MAX_EXCHANGE_BYTES
        && poll_ms >= MIN_POLL_MS && poll_ms <= MAX_POLL_MS
}
pub open spec fn state_dir_ok(dir: Seq<u8>) -> bool { 1 <= dir.len() <= MAX_STATE_DIR }
pub fn state_dir_ok_exec(dir: &[u8]) -> (out: bool)
    ensures out == state_dir_ok(dir@),
{
    dir.len() >= 1 && dir.len() <= MAX_STATE_DIR
}

} // verus!
