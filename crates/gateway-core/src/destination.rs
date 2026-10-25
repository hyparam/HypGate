//! Verified destination validation. A configured destination is accepted only
//! as `https://` followed by an authority and an optional origin-form path,
//! where the authority is a conventional DNS name or a bracketed IPv6 literal
//! with an optional nonzero port. The parts the runtime connects to, names in
//! TLS, and forwards in Host are proved to be exactly the substrings of the
//! operator's text that the grammar names; nothing else can influence them.
use vstd::prelude::*;
use vstd::slice::{slice_subrange, slice_to_vec};
use crate::headers::eq;

verus! {
pub const MAX_TEXT: usize = 8192;
pub const MAX_HOST: usize = 253;
pub const MAX_LABEL: usize = 63;
pub const MAX_IPV6: usize = 45;
pub const DEFAULT_PORT: u16 = 443;
pub const HTTPS: [u8; 8] = *b"https://";
pub const ROOT: [u8; 1] = *b"/";

/// The parts of a validated destination.
pub struct Parts {
    /// The configured text, exactly as the operator wrote it.
    pub text: Vec<u8>,
    /// The authority exactly as configured: host text, and `:port` if given.
    pub authority: Vec<u8>,
    /// The host for name resolution and TLS: the DNS name, or the IPv6
    /// literal without its brackets.
    pub host: Vec<u8>,
    pub port: u16,
    /// The origin-form path, `/` when the text has none.
    pub path: Vec<u8>,
}

/// Visible ASCII, excluding backslash and `#`.
pub open spec fn printable(b: u8) -> bool { 33 <= b <= 126 && b != 92 && b != 35 }
pub open spec fn all_printable(s: Seq<u8>) -> bool { forall|k: int| 0 <= k < s.len() ==> printable(#[trigger] s[k]) }
pub open spec fn label_char(b: u8) -> bool { (48 <= b <= 57) || (65 <= b <= 90) || (97 <= b <= 122) || b == 45 }
pub open spec fn ipv6_char(b: u8) -> bool { (48 <= b <= 57) || (65 <= b <= 70) || (97 <= b <= 102) || b == 58 || b == 46 }

/// A conventional DNS name: one to 253 bytes of letters, digits, hyphens, and
/// dots; no empty label; no label starting or ending with a hyphen; no label
/// longer than 63 bytes (every 64-byte window contains a dot).
pub open spec fn dns_name(s: Seq<u8>) -> bool {
    1 <= s.len() <= MAX_HOST
    && s[0] != 46 && s[0] != 45 && s[s.len() - 1] != 46 && s[s.len() - 1] != 45
    && (forall|k: int| 0 <= k < s.len() ==> label_char(#[trigger] s[k]) || s[k] == 46)
    && (forall|k: int| 0 < k < s.len() && #[trigger] s[k] == 46 ==> s[k - 1] != 46 && s[k - 1] != 45 && (k + 1 < s.len() ==> s[k + 1] != 45))
    && (forall|i: int| 0 <= i && i + MAX_LABEL < s.len() ==> #[trigger] dot_in_window(s, i))
}
/// Some byte of `s[i..=i+63]` is a dot.
pub open spec fn dot_in_window(s: Seq<u8>, i: int) -> bool {
    exists|k: int| i <= k <= i + MAX_LABEL && #[trigger] s[k] == 46
}
/// A bracketed IPv6 literal's contents: one to 45 bytes of hex digits, colons, and dots.
pub open spec fn ipv6_literal(s: Seq<u8>) -> bool {
    1 <= s.len() <= MAX_IPV6 && forall|k: int| 0 <= k < s.len() ==> ipv6_char(#[trigger] s[k])
}
/// The host part of an authority, with its spelling in the text.
pub open spec fn host_text(host: Seq<u8>, spelled: Seq<u8>) -> bool {
    (dns_name(host) && spelled == host) || (ipv6_literal(host) && spelled == seq![91u8] + host + seq![93u8])
}
/// The port suffix of an authority: nothing (port 443) or `:` and one to five
/// digits reading as a nonzero port.
pub open spec fn port_text(port: u16, suffix: Seq<u8>) -> bool {
    (suffix.len() == 0 && port == DEFAULT_PORT)
    || (suffix.len() >= 2 && suffix.len() <= 6 && suffix[0] == 58 && crate::inbound::all_digits(suffix.subrange(1, suffix.len() as int))
        && crate::inbound::value_of(suffix.subrange(1, suffix.len() as int)) == port && port >= 1)
}
/// The raw path of a destination: empty, or an origin-form path that does not
/// start with `//` and has no query.
pub open spec fn raw_path_ok(raw: Seq<u8>) -> bool {
    raw.len() == 0 || (raw[0] == 47 && (raw.len() < 2 || raw[1] != 47) && forall|k: int| 0 <= k < raw.len() ==> #[trigger] raw[k] != 63)
}
/// `text` splits into `https://`, the host spelling, the port suffix, and the
/// raw path, and `parts` are exactly those pieces.
pub open spec fn destination_split(text: Seq<u8>, parts: Parts, spelled: Seq<u8>, suffix: Seq<u8>, raw: Seq<u8>) -> bool {
    parts.text@ == text && host_text(parts.host@, spelled) && port_text(parts.port, suffix) && raw_path_ok(raw)
    && parts.authority@ == spelled + suffix
    && text == HTTPS@ + parts.authority@ + raw
    && parts.path@ == (if raw.len() == 0 { ROOT@ } else { raw })
}
/// Everything `parse` establishes about an accepted destination.
pub open spec fn destination_ok(text: Seq<u8>, parts: Parts) -> bool {
    text.len() <= MAX_TEXT && all_printable(text)
    && exists|spelled: Seq<u8>, suffix: Seq<u8>, raw: Seq<u8>| #[trigger] destination_split(text, parts, spelled, suffix, raw)
}

fn is_printable(b: u8) -> (out: bool)
    ensures out == printable(b),
{ b >= 33 && b <= 126 && b != 92 && b != 35 }
fn is_label_char(b: u8) -> (out: bool)
    ensures out == label_char(b),
{ (b >= 48 && b <= 57) || (b >= 65 && b <= 90) || (b >= 97 && b <= 122) || b == 45 }
fn is_ipv6_char(b: u8) -> (out: bool)
    ensures out == ipv6_char(b),
{ (b >= 48 && b <= 57) || (b >= 65 && b <= 70) || (b >= 97 && b <= 102) || b == 58 || b == 46 }

fn all_printable_bytes(s: &[u8]) -> (out: bool)
    ensures out == all_printable(s@),
{
    let mut k: usize = 0;
    while k < s.len()
        invariant k <= s.len(), forall|j: int| 0 <= j < k ==> printable(#[trigger] s@[j]),
        decreases s.len() - k,
    {
        if !is_printable(s[k]) { return false; }
        k = k + 1;
    }
    true
}

/// The index of the first `b` in `s` at or after `from`, or `s.len()`.
fn find(s: &[u8], from: usize, b: u8) -> (out: usize)
    requires from <= s.len(),
    ensures from <= out <= s.len(), forall|j: int| from <= j < out ==> #[trigger] s@[j] != b,
        out < s.len() ==> s@[out as int] == b,
{
    let mut k: usize = from;
    while k < s.len()
        invariant from <= k <= s.len(), forall|j: int| from <= j < k ==> #[trigger] s@[j] != b,
        decreases s.len() - k,
    {
        if s[k] == b { return k; }
        k = k + 1;
    }
    k
}

/// Accept exactly the names that satisfy `dns_name`.
fn is_dns_name(s: &[u8]) -> (out: bool)
    ensures out == dns_name(s@),
{
    if s.len() == 0 || s.len() > MAX_HOST { return false; }
    if s[0] == 45 || s[s.len() - 1] == 45 || s[s.len() - 1] == 46 { return false; }
    // `start` is where the current label begins; every byte from `start` to
    // `k` (exclusive) is a label character.
    let mut k: usize = 0;
    let mut start: usize = 0;
    while k < s.len()
        invariant k <= s.len(), start <= k, k - start <= MAX_LABEL, 1 <= s.len() <= MAX_HOST,
            s@[0] != 45, s@[s.len() - 1] != 45, s@[s.len() - 1] != 46, k > 0 ==> s@[0] != 46,
            start == 0 || s@[start as int - 1] == 46,
            forall|j: int| start <= j < k ==> #[trigger] s@[j] != 46,
            forall|j: int| 0 <= j < k ==> label_char(#[trigger] s@[j]) || s@[j] == 46,
            forall|j: int| 0 < j < k && #[trigger] s@[j] == 46 ==> s@[j - 1] != 46 && s@[j - 1] != 45 && (j + 1 < s@.len() ==> s@[j + 1] != 45),
            forall|i: int| 0 <= i && i + MAX_LABEL < k ==> #[trigger] dot_in_window(s@, i),
        decreases s.len() - k,
    {
        let b = s[k];
        if b == 46 {
            if k == 0 || s[k - 1] == 46 || s[k - 1] == 45 { return false; }
            if k + 1 < s.len() && s[k + 1] == 45 { return false; }
            start = k + 1;
        } else if is_label_char(b) {
            if k + 1 - start > MAX_LABEL {
                proof {
                    // A 64-byte label: the window starting at it has no dot.
                    assert(!dns_name(s@)) by {
                        if dns_name(s@) {
                            assert(dot_in_window(s@, start as int));
                            let m = choose|m: int| start <= m <= start + MAX_LABEL && #[trigger] s@[m] == 46;
                            assert(false);
                        }
                    }
                }
                return false;
            }
        } else {
            return false;
        }
        proof {
            // A new 64-byte window ending at k holds the dot before this label.
            assert forall|i: int| 0 <= i && i + MAX_LABEL < k + 1 implies #[trigger] dot_in_window(s@, i) by {
                if i + MAX_LABEL == k {
                    if s@[k as int] == 46 {
                        assert(dot_in_window(s@, i));
                    } else {
                        // The label containing k started at `start` >= 1 and the byte before it is a dot inside the window.
                        assert(k + 1 - start <= MAX_LABEL);
                        assert(start >= 1);
                        assert(s@[start as int - 1] == 46);
                        assert(i <= start - 1 <= i + MAX_LABEL);
                        assert(dot_in_window(s@, i));
                    }
                }
            }
        }
        k = k + 1;
    }
    true
}

fn is_ipv6_literal(s: &[u8]) -> (out: bool)
    ensures out == ipv6_literal(s@),
{
    if s.len() == 0 || s.len() > MAX_IPV6 { return false; }
    let mut k: usize = 0;
    while k < s.len()
        invariant k <= s.len(), forall|j: int| 0 <= j < k ==> ipv6_char(#[trigger] s@[j]),
        decreases s.len() - k,
    {
        if !is_ipv6_char(s[k]) { return false; }
        k = k + 1;
    }
    true
}

pub open spec fn pow10(n: nat) -> nat decreases n { if n == 0 { 1 } else { pow10((n - 1) as nat) * 10 } }
proof fn lemma_pow10_monotone(a: nat, b: nat)
    requires a <= b,
    ensures pow10(a) <= pow10(b),
    decreases b - a,
{
    if a < b { lemma_pow10_monotone(a, (b - 1) as nat); }
}

/// No port reads from `suffix`.
pub open spec fn no_port(suffix: Seq<u8>) -> bool { forall|port: u16| !(#[trigger] port_text(port, suffix)) }

/// Parse a `:port` suffix. Accepts exactly one to five digits reading as 1 to 65535.
fn parse_port(suffix: &[u8]) -> (out: Option<u16>)
    ensures match out { Some(port) => port_text(port, suffix@), None => no_port(suffix@) },
{
    if suffix.len() == 0 { return Some(DEFAULT_PORT); }
    if suffix.len() < 2 || suffix.len() > 6 || suffix[0] != 58 { return None; }
    let digits = slice_subrange(suffix, 1, suffix.len());
    let mut value: u32 = 0;
    let mut i: usize = 0;
    while i < digits.len()
        invariant i <= digits.len(), digits.len() <= 5, crate::inbound::all_digits(digits@.subrange(0, i as int)),
            2 <= suffix@.len() <= 6, suffix@[0] == 58, digits@ == suffix@.subrange(1, suffix@.len() as int),
            value == crate::inbound::value_of(digits@.subrange(0, i as int)), value < pow10(i as nat),
        decreases digits.len() - i,
    {
        let b = digits[i];
        if b < 48 || b > 57 {
            proof { assert(!crate::inbound::is_digit(digits@[i as int])); }
            return None;
        }
        proof {
            assert(digits@.subrange(0, i as int + 1).drop_last() =~= digits@.subrange(0, i as int));
            assert(pow10(i as nat + 1) == pow10(i as nat) * 10);
            assert(pow10(5nat) == 100000) by (compute);
            lemma_pow10_monotone(i as nat + 1, 5nat);
        }
        value = value * 10 + ((b - 48) as u32);
        i = i + 1;
    }
    proof { assert(digits@.subrange(0, digits.len() as int) =~= digits@); assert(digits@ == suffix@.subrange(1, suffix@.len() as int)); }
    if value == 0 || value > 65535 { return None; }
    Some(value as u16)
}

/// No accepted destination exists for `text`.
pub open spec fn rejected(text: Seq<u8>) -> bool { forall|parts: Parts| !destination_ok(text, parts) }

/// What any split of `text` forces on its bytes: the shape `parse` looks for.
proof fn lemma_split_facts(text: Seq<u8>, parts: Parts, spelled: Seq<u8>, suffix: Seq<u8>, raw: Seq<u8>)
    requires destination_split(text, parts, spelled, suffix, raw),
    ensures
        text.len() == 8 + parts.authority@.len() + raw.len(),
        parts.authority@.len() >= 1, spelled.len() >= 1,
        text.subrange(0, 8) == HTTPS@,
        forall|k: int| 0 <= k < parts.authority@.len() ==> #[trigger] text[8 + k] == parts.authority@[k] && parts.authority@[k] != 47,
        forall|k: int| 0 <= k < raw.len() ==> #[trigger] text[8 + parts.authority@.len() + k] == raw[k],
        raw.len() == 0 || raw[0] == 47,
        parts.authority@ == spelled + suffix,
        suffix.len() == 0 || suffix[0] == 58,
        forall|k: int| 0 <= k < suffix.len() ==> #[trigger] suffix[k] != 93 && suffix[k] != 47,
        parts.authority@[0] == 91 ==> ipv6_literal(parts.host@) && spelled == seq![91u8] + parts.host@ + seq![93u8]
            && spelled.len() == parts.host@.len() + 2
            && (forall|k: int| 1 <= k < 1 + parts.host@.len() as int ==> #[trigger] parts.authority@[k] != 93)
            && parts.authority@[1 + parts.host@.len() as int] == 93
            && parts.host@ == parts.authority@.subrange(1, 1 + parts.host@.len() as int),
        parts.authority@[0] != 91 ==> dns_name(parts.host@) && spelled == parts.host@
            && (forall|k: int| 0 <= k < parts.host@.len() ==> #[trigger] parts.authority@[k] != 58)
            && parts.host@ == parts.authority@.subrange(0, parts.host@.len() as int),
{
    let a = parts.authority@;
    assert(text.subrange(0, 8) =~= HTTPS@);
    assert forall|k: int| 0 <= k < a.len() implies #[trigger] text[8 + k] == a[k] && a[k] != 47 by {
        if k < spelled.len() {
            if dns_name(parts.host@) && spelled == parts.host@ {
                assert(label_char(parts.host@[k]) || parts.host@[k] == 46);
            } else {
                if 0 < k < spelled.len() - 1 { assert(ipv6_char(parts.host@[k - 1])); }
            }
        } else {
            assert(a[k] == suffix[k - spelled.len()]);
            if k - spelled.len() > 0 { assert(crate::inbound::is_digit(suffix.subrange(1, suffix.len() as int)[k - spelled.len() - 1])); }
        }
    }
    assert forall|k: int| 0 <= k < suffix.len() implies #[trigger] suffix[k] != 93 && suffix[k] != 47 by {
        if k > 0 { assert(crate::inbound::is_digit(suffix.subrange(1, suffix.len() as int)[k - 1])); }
    }
    if dns_name(parts.host@) && spelled == parts.host@ {
        assert(label_char(parts.host@[0]) || parts.host@[0] == 46);
        assert(a[0] != 91);
        assert forall|k: int| 0 <= k < parts.host@.len() implies #[trigger] a[k] != 58 by {
            assert(label_char(parts.host@[k]) || parts.host@[k] == 46);
        }
        assert(parts.host@ =~= a.subrange(0, parts.host@.len() as int));
    } else {
        assert(a[0] == 91);
        assert forall|k: int| 1 <= k < 1 + parts.host@.len() implies #[trigger] a[k] != 93 by {
            assert(ipv6_char(parts.host@[k - 1]));
        }
        assert(parts.host@ =~= a.subrange(1, 1 + parts.host@.len() as int));
    }
}

/// The first `/` at or after byte 8 ends the authority, so the authority and
/// raw path `parse` cuts are the split's.
proof fn lemma_locate(text: Seq<u8>, parts: Parts, spelled: Seq<u8>, suffix: Seq<u8>, raw: Seq<u8>, auth_end: int)
    requires destination_split(text, parts, spelled, suffix, raw), cut_at(text, auth_end),
    ensures auth_end == 8 + parts.authority@.len(),
        text.subrange(8, auth_end) == parts.authority@,
        text.subrange(auth_end, text.len() as int) == raw,
{
    lemma_split_facts(text, parts, spelled, suffix, raw);
    let a = parts.authority@;
    if auth_end < 8 + a.len() { assert(text[auth_end] == a[auth_end - 8]); }
    if auth_end > 8 + a.len() { assert(text[8 + a.len() as int] == raw[0]); }
    assert(text.subrange(8, auth_end) =~= a);
    assert(text.subrange(auth_end, text.len() as int) =~= raw);
}

/// `auth_end` is where `find(text, 8, 47)` stops.
pub open spec fn cut_at(text: Seq<u8>, auth_end: int) -> bool {
    8 <= auth_end <= text.len() && (forall|j: int| 8 <= j < auth_end ==> #[trigger] text[j] != 47)
        && (auth_end < text.len() ==> text[auth_end] == 47)
}
/// `index` is where `find(s, from, b)` stops.
pub open spec fn first_at(s: Seq<u8>, from: int, b: u8, index: int) -> bool {
    from <= index <= s.len() && (forall|j: int| from <= j < index ==> #[trigger] s[j] != b) && (index < s.len() ==> s[index] == b)
}

proof fn lemma_reject_shape(text: Seq<u8>)
    requires text.len() < 9 || text.subrange(0, 8) != HTTPS@,
    ensures rejected(text),
{
    assert forall|parts: Parts| !destination_ok(text, parts) by { if destination_ok(text, parts) {
        let (sp, su, ra) = choose|sp: Seq<u8>, su: Seq<u8>, ra: Seq<u8>| #[trigger] destination_split(text, parts, sp, su, ra);
        lemma_split_facts(text, parts, sp, su, ra);
    } }
}

proof fn lemma_reject_path(text: Seq<u8>, auth_end: int, query: int)
    requires cut_at(text, auth_end), first_at(text.subrange(auth_end, text.len() as int), 0, 63, query),
        ({ let raw = text.subrange(auth_end, text.len() as int);
            (raw.len() >= 2 && raw[1] == 47) || query < raw.len() || auth_end == 8 }),
    ensures rejected(text),
{
    assert forall|parts: Parts| !destination_ok(text, parts) by { if destination_ok(text, parts) {
        let (sp, su, ra) = choose|sp: Seq<u8>, su: Seq<u8>, ra: Seq<u8>| #[trigger] destination_split(text, parts, sp, su, ra);
        lemma_locate(text, parts, sp, su, ra, auth_end);
        if query < ra.len() { assert(ra[query] == 63); }
    } }
}

proof fn lemma_reject_bracket(text: Seq<u8>, auth_end: int, close: int)
    requires cut_at(text, auth_end), auth_end > 8, text[8] == 91,
        first_at(text.subrange(8, auth_end), 1, 93, close),
        close >= auth_end - 8 || !ipv6_literal(text.subrange(8, auth_end).subrange(1, close)),
    ensures rejected(text),
{
    assert forall|parts: Parts| !destination_ok(text, parts) by { if destination_ok(text, parts) {
        let (sp, su, ra) = choose|sp: Seq<u8>, su: Seq<u8>, ra: Seq<u8>| #[trigger] destination_split(text, parts, sp, su, ra);
        lemma_locate(text, parts, sp, su, ra, auth_end);
        lemma_split_facts(text, parts, sp, su, ra);
        let a = parts.authority@;
        assert(a[0] == 91);
        assert(close == 1 + parts.host@.len()) by {
            if close < 1 + parts.host@.len() { assert(a[close] != 93); }
            if close > 1 + parts.host@.len() { assert(a[1 + parts.host@.len() as int] == 93); }
        }
    } }
}

proof fn lemma_reject_dns(text: Seq<u8>, auth_end: int, colon: int)
    requires cut_at(text, auth_end), auth_end > 8, text[8] != 91,
        first_at(text.subrange(8, auth_end), 0, 58, colon),
        !dns_name(text.subrange(8, auth_end).subrange(0, colon)),
    ensures rejected(text),
{
    assert forall|parts: Parts| !destination_ok(text, parts) by { if destination_ok(text, parts) {
        let (sp, su, ra) = choose|sp: Seq<u8>, su: Seq<u8>, ra: Seq<u8>| #[trigger] destination_split(text, parts, sp, su, ra);
        lemma_locate(text, parts, sp, su, ra, auth_end);
        lemma_split_facts(text, parts, sp, su, ra);
        let a = parts.authority@;
        assert(a[0] == text[8]);
        assert(dns_name(parts.host@));
        assert(colon == parts.host@.len()) by {
            if colon < parts.host@.len() { assert(a[colon] != 58); }
            if colon > parts.host@.len() { assert(a[parts.host@.len() as int] == su[0]); }
        }
        assert(parts.host@ == a.subrange(0, colon));
    } }
}

proof fn lemma_reject_port(text: Seq<u8>, auth_end: int, spelled_end: int)
    requires cut_at(text, auth_end), auth_end > 8,
        ({ let a = text.subrange(8, auth_end);
            1 <= spelled_end <= a.len()
            && if a[0] == 91 { first_at(a, 1, 93, spelled_end - 1) && spelled_end - 1 < a.len() }
               else { first_at(a, 0, 58, spelled_end) } }),
        no_port(text.subrange(8, auth_end).subrange(spelled_end, auth_end - 8)),
    ensures rejected(text),
{
    assert forall|parts: Parts| !destination_ok(text, parts) by { if destination_ok(text, parts) {
        let (sp, su, ra) = choose|sp: Seq<u8>, su: Seq<u8>, ra: Seq<u8>| #[trigger] destination_split(text, parts, sp, su, ra);
        lemma_locate(text, parts, sp, su, ra, auth_end);
        lemma_split_facts(text, parts, sp, su, ra);
        let a = parts.authority@;
        if a[0] == 91 {
            assert(spelled_end == 2 + parts.host@.len()) by {
                if spelled_end - 1 < 1 + parts.host@.len() { assert(a[spelled_end - 1] != 93); }
                if spelled_end - 1 > 1 + parts.host@.len() { assert(a[1 + parts.host@.len() as int] == 93); }
            }
        } else {
            assert(spelled_end == parts.host@.len()) by {
                if spelled_end < parts.host@.len() { assert(a[spelled_end] != 58); }
                if spelled_end > parts.host@.len() { assert(a[parts.host@.len() as int] == su[0]); }
            }
        }
        assert(a.subrange(spelled_end, a.len() as int) =~= su);
        assert(port_text(parts.port, su));
    } }
}

/// Validate a configured destination and extract its parts. Accepts exactly
/// the texts that have a split: `None` means no `Parts` satisfy `destination_ok`.
pub fn parse(text: &[u8]) -> (out: Option<Parts>)
    ensures match out { Some(parts) => destination_ok(text@, parts), None => rejected(text@) },
{
    if text.len() > MAX_TEXT || text.len() < 9 {
        proof { if text@.len() < 9 { lemma_reject_shape(text@); } }
        return None;
    }
    if !all_printable_bytes(text) { return None; }
    if !eq(slice_subrange(text, 0, 8), HTTPS.as_slice()) {
        proof { lemma_reject_shape(text@); }
        return None;
    }
    let auth_end = find(text, 8, 47);
    let authority = slice_subrange(text, 8, auth_end);
    let raw = slice_subrange(text, auth_end, text.len());
    let query = find(raw, 0, 63);
    if (raw.len() >= 2 && raw[1] == 47) || query < raw.len() || authority.len() == 0 {
        proof { lemma_reject_path(text@, auth_end as int, query as int); }
        return None;
    }
    // Host, then the rest of the authority.
    let (host, spelled_end): (Vec<u8>, usize) = if authority[0] == 91 {
        let close = find(authority, 1, 93);
        if close >= authority.len() {
            proof { lemma_reject_bracket(text@, auth_end as int, close as int); }
            return None;
        }
        let inner = slice_subrange(authority, 1, close);
        if !is_ipv6_literal(inner) {
            proof { lemma_reject_bracket(text@, auth_end as int, close as int); }
            return None;
        }
        (slice_to_vec(inner), close + 1)
    } else {
        let colon = find(authority, 0, 58);
        let name = slice_subrange(authority, 0, colon);
        if !is_dns_name(name) {
            proof { lemma_reject_dns(text@, auth_end as int, colon as int); }
            return None;
        }
        (slice_to_vec(name), colon)
    };
    let suffix = slice_subrange(authority, spelled_end, authority.len());
    let port = match parse_port(suffix) {
        Some(port) => port,
        None => {
            proof { lemma_reject_port(text@, auth_end as int, spelled_end as int); }
            return None;
        }
    };
    let path = if raw.len() == 0 { slice_to_vec(ROOT.as_slice()) } else { slice_to_vec(raw) };
    let parts = Parts { text: slice_to_vec(text), authority: slice_to_vec(authority), host, port, path };
    proof {
        let spelled = authority@.subrange(0, spelled_end as int);
        assert(parts.authority@ =~= spelled + suffix@);
        assert(text@ =~= HTTPS@ + parts.authority@ + raw@);
        if authority@[0] == 91 {
            assert(spelled =~= seq![91u8] + parts.host@ + seq![93u8]);
        } else {
            assert(spelled =~= parts.host@);
        }
        assert(host_text(parts.host@, spelled));
        assert(port_text(parts.port, suffix@));
        assert(raw_path_ok(raw@));
        assert(parts.path@ == (if raw@.len() == 0 { ROOT@ } else { raw@ }));
        assert(destination_split(text@, parts, spelled, suffix@, raw@));
    }
    Some(parts)
}
}
