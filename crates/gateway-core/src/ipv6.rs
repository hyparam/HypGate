//! IPv6 address text (RFC 4291 section 2.2, as the standard library reads
//! it): eight groups of one to four hex digits separated by colons, or a
//! head, `::` standing for one or more zero groups, and a tail, with at most
//! seven groups between them; the last two groups may be a dotted-decimal
//! IPv4 address whose octets have no leading zero. `literal_ok` is proved
//! to accept exactly that grammar; the configuration loader uses it to
//! refuse a bracketed destination host that is not an address.
use vstd::prelude::*;
use vstd::slice::slice_subrange;

verus! {

pub const COLON: u8 = 58;
pub const DOT: u8 = 46;

pub open spec fn is_hex(b: u8) -> bool { crate::http1_chunked::is_hex(b) }
pub open spec fn all_hex(s: Seq<u8>) -> bool { forall|k: int| 0 <= k < s.len() ==> is_hex(#[trigger] s[k]) }
/// One to four hex digits.
pub open spec fn hex_group(s: Seq<u8>) -> bool { 1 <= s.len() <= 4 && all_hex(s) }
/// A decimal octet: `0`, or one to three digits without a leading zero, at most 255.
pub open spec fn octet_ok(s: Seq<u8>) -> bool {
    1 <= s.len() <= 3 && crate::inbound::all_digits(s) && (s[0] != 48 || s.len() == 1) && crate::inbound::value_of(s) <= 255
}
/// Four octets separated by dots.
pub open spec fn ipv4_ok(s: Seq<u8>) -> bool {
    exists|a: int, b: int, c: int| 0 < a < b < c < s.len() && #[trigger] s[a] == DOT && #[trigger] s[b] == DOT && #[trigger] s[c] == DOT
        && octet_ok(s.subrange(0, a)) && octet_ok(s.subrange(a + 1, b)) && octet_ok(s.subrange(b + 1, c)) && octet_ok(s.subrange(c + 1, s.len() as int))
}
/// Exactly `n` hex groups separated by colons.
pub open spec fn groups(s: Seq<u8>, n: nat) -> bool
    decreases n,
{
    if n == 0 { s.len() == 0 }
    else if n == 1 { hex_group(s) }
    else { exists|k: int| 0 <= k < s.len() && hex_group(s.subrange(0, k)) && #[trigger] s[k] == COLON && groups(s.subrange(k + 1, s.len() as int), (n - 1) as nat) }
}
/// `n` groups' worth, the last two possibly an IPv4 address.
pub open spec fn tail(s: Seq<u8>, n: nat) -> bool {
    groups(s, n) || (n == 2 && ipv4_ok(s))
        || (n > 2 && exists|k: int| 0 <= k < s.len() && groups(s.subrange(0, k), (n - 2) as nat) && #[trigger] s[k] == COLON && ipv4_ok(s.subrange(k + 1, s.len() as int)))
}
/// `::` at `i`.
pub open spec fn double_colon(s: Seq<u8>, i: int) -> bool { 0 <= i && i + 2 <= s.len() && s[i] == COLON && s[i + 1] == COLON }
pub open spec fn groups_at(s: Seq<u8>, i: int, h: nat) -> bool { groups(s.subrange(0, i), h) }
pub open spec fn tail_from(s: Seq<u8>, i: int, t: nat) -> bool { tail(s.subrange(i + 2, s.len() as int), t) }
/// An IPv6 address text.
pub open spec fn ipv6_ok(s: Seq<u8>) -> bool {
    tail(s, 8) || exists|i: int, h: nat, t: nat| #[trigger] double_colon(s, i) && #[trigger] groups_at(s, i, h) && #[trigger] tail_from(s, i, t) && h + t <= 7
}

// ---- what the grammar rules out ------------------------------------------------------------

proof fn lemma_hex_not_colon(b: u8) ensures is_hex(b) ==> b != COLON && b != DOT {}

/// A hex group is a single piece: no colon and no dot in it.
proof fn lemma_group_plain(s: Seq<u8>, k: int)
    requires hex_group(s), 0 <= k < s.len(),
    ensures s[k] != COLON, s[k] != DOT,
{
    assert(is_hex(s[k]));
}
/// A string of groups never holds two colons in a row, nor a dot.
proof fn lemma_groups_plain(s: Seq<u8>, n: nat)
    requires groups(s, n),
    ensures forall|i: int| 0 <= i < s.len() ==> #[trigger] s[i] != DOT, forall|i: int| 0 <= i && i + 1 < s.len() && #[trigger] s[i] == COLON ==> s[i + 1] != COLON,
        n >= 1 ==> s.len() >= 1 && s[0] != COLON, n >= 1 ==> s[s.len() - 1] != COLON,
    decreases n,
{
    if n == 1 {
        assert forall|i: int| 0 <= i < s.len() implies #[trigger] s[i] != DOT by { lemma_group_plain(s, i); }
        assert forall|i: int| 0 <= i && i + 1 < s.len() && #[trigger] s[i] == COLON implies s[i + 1] != COLON by { lemma_group_plain(s, i); }
        lemma_group_plain(s, 0);
        lemma_group_plain(s, s.len() - 1);
    } else if n >= 2 {
        let k = choose|k: int| 0 <= k < s.len() && hex_group(s.subrange(0, k)) && #[trigger] s[k] == COLON && groups(s.subrange(k + 1, s.len() as int), (n - 1) as nat);
        let g = s.subrange(0, k);
        let rest = s.subrange(k + 1, s.len() as int);
        lemma_groups_plain(rest, (n - 1) as nat);
        assert forall|i: int| 0 <= i < s.len() implies #[trigger] s[i] != DOT by {
            if i < k { lemma_group_plain(g, i); assert(g[i] == s[i]); } else if i > k { assert(rest[i - k - 1] == s[i]); }
        }
        assert forall|i: int| 0 <= i && i + 1 < s.len() && #[trigger] s[i] == COLON implies s[i + 1] != COLON by {
            if i < k { lemma_group_plain(g, i); assert(g[i] == s[i]); }
            else if i == k { assert(rest[0] == s[k + 1]); }
            else { assert(rest[i - k - 1] == s[i]); assert(rest[i - k] == s[i + 1]); }
        }
        lemma_group_plain(g, 0);
        assert(g[0] == s[0]);
        assert(rest[rest.len() - 1] == s[s.len() - 1]);
    }
}
/// An IPv4 address holds no colon.
proof fn lemma_ipv4_plain(s: Seq<u8>)
    requires ipv4_ok(s),
    ensures forall|i: int| 0 <= i < s.len() ==> #[trigger] s[i] != COLON, s.len() >= 7,
{
    let (a, b, c) = choose|a: int, b: int, c: int| 0 < a < b < c < s.len() && #[trigger] s[a] == DOT && #[trigger] s[b] == DOT && #[trigger] s[c] == DOT
        && octet_ok(s.subrange(0, a)) && octet_ok(s.subrange(a + 1, b)) && octet_ok(s.subrange(b + 1, c)) && octet_ok(s.subrange(c + 1, s.len() as int));
    assert forall|i: int| 0 <= i < s.len() implies #[trigger] s[i] != COLON by {
        if i < a { assert(crate::inbound::is_digit(s.subrange(0, a)[i])); }
        else if a < i < b { assert(crate::inbound::is_digit(s.subrange(a + 1, b)[i - a - 1])); }
        else if b < i < c { assert(crate::inbound::is_digit(s.subrange(b + 1, c)[i - b - 1])); }
        else if c < i { assert(crate::inbound::is_digit(s.subrange(c + 1, s.len() as int)[i - c - 1])); }
    }
}
/// A tail holds no two colons in a row.
proof fn lemma_tail_plain(s: Seq<u8>, n: nat)
    requires tail(s, n),
    ensures forall|i: int| 0 <= i && i + 1 < s.len() && #[trigger] s[i] == COLON ==> s[i + 1] != COLON,
{
    if groups(s, n) { lemma_groups_plain(s, n); }
    else if n == 2 && ipv4_ok(s) { lemma_ipv4_plain(s); }
    else {
        let k = choose|k: int| 0 <= k < s.len() && groups(s.subrange(0, k), (n - 2) as nat) && #[trigger] s[k] == COLON && ipv4_ok(s.subrange(k + 1, s.len() as int));
        let g = s.subrange(0, k);
        let v4 = s.subrange(k + 1, s.len() as int);
        lemma_groups_plain(g, (n - 2) as nat);
        lemma_ipv4_plain(v4);
        assert forall|i: int| 0 <= i && i + 1 < s.len() && #[trigger] s[i] == COLON implies s[i + 1] != COLON by {
            if i + 1 < k { assert(g[i] == s[i]); assert(g[i + 1] == s[i + 1]); }
            else if i + 1 == k { assert(g[i] == s[i]); assert(g[g.len() - 1] != COLON); }
            else if i == k { assert(v4[0] == s[k + 1]); }
            else { assert(v4[i - k - 1] == s[i]); }
        }
    }
}

/// The first group of a string of groups ends at its first colon.
proof fn lemma_groups_split(s: Seq<u8>, q: int, n: nat)
    requires 0 <= q < s.len(), s[q] == COLON, all_hex(s.subrange(0, q)), groups(s, n),
    ensures n >= 2, hex_group(s.subrange(0, q)), groups(s.subrange(q + 1, s.len() as int), (n - 1) as nat),
{
    if n == 0 { assert(false); }
    else if n == 1 { assert(is_hex(s[q])); assert(false); }
    else {
        let k = choose|k: int| 0 <= k < s.len() && hex_group(s.subrange(0, k)) && #[trigger] s[k] == COLON && groups(s.subrange(k + 1, s.len() as int), (n - 1) as nat);
        if k < q { assert(is_hex(s.subrange(0, q)[k])); assert(false); }
        if k > q { assert(is_hex(s.subrange(0, k)[q])); assert(false); }
    }
}
/// A string of groups whose bytes up to `q` are hex and whose byte at `q` is neither hex nor a colon: none.
proof fn lemma_groups_stuck(s: Seq<u8>, q: int, n: nat)
    requires 0 <= q < s.len(), !is_hex(s[q]), s[q] != COLON, all_hex(s.subrange(0, q)),
    ensures !groups(s, n),
{
    if groups(s, n) {
        if n == 1 { assert(is_hex(s[q])); }
        else if n >= 2 {
            let k = choose|k: int| 0 <= k < s.len() && hex_group(s.subrange(0, k)) && #[trigger] s[k] == COLON && groups(s.subrange(k + 1, s.len() as int), (n - 1) as nat);
            if k < q { assert(is_hex(s.subrange(0, q)[k])); }
            if k > q { assert(is_hex(s.subrange(0, k)[q])); }
        }
    }
}
/// A string whose first piece is empty or longer than four hex digits: no groups.
proof fn lemma_groups_bad_first(s: Seq<u8>, q: int, n: nat)
    requires 0 <= q <= s.len(), all_hex(s.subrange(0, q)), q == s.len() || !is_hex(s[q]), q == 0 || q > 4, s.len() >= 1,
    ensures !groups(s, n),
{
    if groups(s, n) {
        if n == 1 {
            assert(hex_group(s));
            if q == 0 { assert(is_hex(s[0])); assert(false); }
            else { assert(s.len() >= q); if q < s.len() { assert(is_hex(s[q])); } assert(false); }
        } else if n >= 2 {
            let k = choose|k: int| 0 <= k < s.len() && hex_group(s.subrange(0, k)) && #[trigger] s[k] == COLON && groups(s.subrange(k + 1, s.len() as int), (n - 1) as nat);
            if k < q { assert(is_hex(s.subrange(0, q)[k])); }
            else if q == 0 { assert(k >= 1); assert(is_hex(s.subrange(0, k)[0])); if 0 < s.len() { assert(!is_hex(s[0])); } }
            else { assert(k >= q); assert(k <= 4); }
        }
    }
}
/// A string of only hex digits is one group or none.
proof fn lemma_groups_last(s: Seq<u8>, n: nat)
    requires all_hex(s), s.len() >= 1,
    ensures groups(s, n) == (n == 1 && s.len() <= 4),
{
    if n >= 2 && groups(s, n) {
        let k = choose|k: int| 0 <= k < s.len() && hex_group(s.subrange(0, k)) && #[trigger] s[k] == COLON && groups(s.subrange(k + 1, s.len() as int), (n - 1) as nat);
        assert(is_hex(s[k]));
    }
}

/// A string is some one number of groups, if any.
proof fn lemma_groups_unique(s: Seq<u8>, n: nat, m: nat)
    requires groups(s, n), groups(s, m),
    ensures n == m,
    decreases n,
{
    if n == 0 {
        if m == 1 { assert(hex_group(s)); assert(false); }
        if m >= 2 {
            let k = choose|k: int| 0 <= k < s.len() && hex_group(s.subrange(0, k)) && #[trigger] s[k] == COLON && groups(s.subrange(k + 1, s.len() as int), (m - 1) as nat);
            assert(false);
        }
    } else if n == 1 {
        if m == 0 { assert(false); }
        if m >= 2 {
            let k = choose|k: int| 0 <= k < s.len() && hex_group(s.subrange(0, k)) && #[trigger] s[k] == COLON && groups(s.subrange(k + 1, s.len() as int), (m - 1) as nat);
            lemma_group_plain(s, k);
        }
    } else {
        let k = choose|k: int| 0 <= k < s.len() && hex_group(s.subrange(0, k)) && #[trigger] s[k] == COLON && groups(s.subrange(k + 1, s.len() as int), (n - 1) as nat);
        if m == 0 { assert(false); }
        else if m == 1 { lemma_group_plain(s, k); }
        else {
            let k2 = choose|k2: int| 0 <= k2 < s.len() && hex_group(s.subrange(0, k2)) && #[trigger] s[k2] == COLON && groups(s.subrange(k2 + 1, s.len() as int), (m - 1) as nat);
            if k < k2 { assert(is_hex(s.subrange(0, k2)[k])); assert(false); }
            if k2 < k { assert(is_hex(s.subrange(0, k)[k2])); assert(false); }
            lemma_groups_unique(s.subrange(k + 1, s.len() as int), (n - 1) as nat, (m - 1) as nat);
        }
    }
}
/// A string of groups is not an IPv4 tail: it holds no dot.
proof fn lemma_groups_not_v4(s: Seq<u8>, n: nat, m: nat)
    requires groups(s, n),
    ensures !(m == 2 && ipv4_ok(s)),
        !(m > 2 && exists|k: int| 0 <= k < s.len() && groups(s.subrange(0, k), (m - 2) as nat) && #[trigger] s[k] == COLON && ipv4_ok(s.subrange(k + 1, s.len() as int))),
{
    lemma_groups_plain(s, n);
    if m == 2 && ipv4_ok(s) { lemma_ipv4_has_dot(s); }
    if m > 2 {
        if exists|k: int| 0 <= k < s.len() && groups(s.subrange(0, k), (m - 2) as nat) && #[trigger] s[k] == COLON && ipv4_ok(s.subrange(k + 1, s.len() as int)) {
            let k = choose|k: int| 0 <= k < s.len() && groups(s.subrange(0, k), (m - 2) as nat) && #[trigger] s[k] == COLON && ipv4_ok(s.subrange(k + 1, s.len() as int));
            let v4 = s.subrange(k + 1, s.len() as int);
            lemma_ipv4_has_dot(v4);
            let j = choose|j: int| 0 <= j < v4.len() && #[trigger] v4[j] == DOT;
            assert(s[k + 1 + j] == DOT);
        }
    }
}
/// A tail is some one number of groups' worth, if any.
#[verifier::rlimit(200)]
proof fn lemma_tail_unique(s: Seq<u8>, n: nat, m: nat)
    requires tail(s, n), tail(s, m),
    ensures n == m,
{
    if groups(s, n) && groups(s, m) { lemma_groups_unique(s, n, m); }
    else if groups(s, n) { lemma_groups_not_v4(s, n, m); }
    else if groups(s, m) { lemma_groups_not_v4(s, m, n); }
    else if n == 2 && ipv4_ok(s) {
        lemma_ipv4_plain(s);
        if m > 2 {
            let k = choose|k: int| 0 <= k < s.len() && groups(s.subrange(0, k), (m - 2) as nat) && #[trigger] s[k] == COLON && ipv4_ok(s.subrange(k + 1, s.len() as int));
            assert(false);
        }
    } else if m == 2 && ipv4_ok(s) {
        lemma_ipv4_plain(s);
        let k = choose|k: int| 0 <= k < s.len() && groups(s.subrange(0, k), (n - 2) as nat) && #[trigger] s[k] == COLON && ipv4_ok(s.subrange(k + 1, s.len() as int));
        assert(false);
    } else {
        let k = choose|k: int| 0 <= k < s.len() && groups(s.subrange(0, k), (n - 2) as nat) && #[trigger] s[k] == COLON && ipv4_ok(s.subrange(k + 1, s.len() as int));
        let k2 = choose|k2: int| 0 <= k2 < s.len() && groups(s.subrange(0, k2), (m - 2) as nat) && #[trigger] s[k2] == COLON && ipv4_ok(s.subrange(k2 + 1, s.len() as int));
        lemma_ipv4_plain(s.subrange(k + 1, s.len() as int));
        lemma_ipv4_plain(s.subrange(k2 + 1, s.len() as int));
        if k < k2 { assert(s.subrange(k + 1, s.len() as int)[k2 - k - 1] == COLON); assert(false); }
        if k2 < k { assert(s.subrange(k2 + 1, s.len() as int)[k - k2 - 1] == COLON); assert(false); }
        lemma_groups_unique(s.subrange(0, k), (n - 2) as nat, (m - 2) as nat);
    }
}

// ---- reading -------------------------------------------------------------------------------

fn is_hex_exec(b: u8) -> (out: bool) ensures out == is_hex(b) { (48 <= b && b <= 57) || (65 <= b && b <= 70) || (97 <= b && b <= 102) }
fn is_digit_exec(b: u8) -> (out: bool) ensures out == crate::inbound::is_digit(b) { 48 <= b && b <= 57 }

/// The first position at or after `i` that is not a hex digit.
fn skip_hex(s: &[u8], i: usize) -> (j: usize)
    requires i <= s.len(),
    ensures i <= j <= s.len(), all_hex(s@.subrange(i as int, j as int)), j < s.len() ==> !is_hex(s@[j as int]),
{
    let mut j = i;
    while j < s.len() && is_hex_exec(s[j])
        invariant i <= j <= s.len(), forall|k: int| i <= k < j ==> is_hex(#[trigger] s@[k]),
        decreases s.len() - j,
    {
        j = j + 1;
    }
    proof { assert forall|k: int| 0 <= k < j - i implies is_hex(#[trigger] s@.subrange(i as int, j as int)[k]) by { assert(s@.subrange(i as int, j as int)[k] == s@[i + k]); } }
    j
}
/// How many hex groups `s` is, exactly.
#[verifier::loop_isolation(false)]
#[verifier::rlimit(60)]
fn count_groups(s: &[u8]) -> (out: Option<usize>)
    ensures match out { Some(n) => groups(s@, n as nat) && n <= s.len(), None => forall|n: nat| !groups(s@, n) },
{
    if s.len() == 0 { return Some(0); }
    let mut p: usize = 0;
    let mut done: usize = 0;
    proof { assert(s@.subrange(0, s@.len() as int) =~= s@); }
    loop
        invariant p <= s.len(), done <= p, done <= s.len(),
            forall|n: nat| groups(s@, n) == (n > done && groups(s@.subrange(p as int, s@.len() as int), (n - done) as nat)),
        decreases s.len() - p,
    {
        let ghost rest = s@.subrange(p as int, s@.len() as int);
        let q = skip_hex(s, p);
        proof { assert(rest.subrange(0, q - p) =~= s@.subrange(p as int, q as int)); }
        if q == p || q - p > 4 {
            proof {
                assert(rest.len() >= 1 || p == s.len());
                if p < s.len() {
                    if q < s.len() { assert(rest[q - p] == s@[q as int]); }
                    assert forall|n: nat| !groups(s@, n) by { lemma_groups_bad_first(rest, q - p, (if n > done { n - done } else { 0 }) as nat); }
                } else {
                    assert forall|n: nat| !groups(s@, n) by { if n > done { assert(groups(rest, (n - done) as nat) ==> false); } }
                }
            }
            return None;
        }
        if q == s.len() {
            proof {
                assert(all_hex(rest));
                assert forall|n: nat| groups(s@, n) == (n == done + 1) by { if n > done { lemma_groups_last(rest, (n - done) as nat); } }
            }
            return Some(done + 1);
        }
        if s[q] != COLON {
            proof {
                assert(rest[q - p] == s@[q as int]);
                assert forall|n: nat| !groups(s@, n) by { if n > done { lemma_groups_stuck(rest, q - p, (n - done) as nat); } }
            }
            return None;
        }
        proof {
            assert(rest[q - p] == COLON);
            let next = s@.subrange(q + 1, s@.len() as int);
            assert(rest.subrange(q - p + 1, rest.len() as int) =~= next);
            assert forall|n: nat| groups(s@, n) == (n > done + 1 && groups(next, (n - done - 1) as nat)) by {
                if n > done {
                    if groups(rest, (n - done) as nat) { lemma_groups_split(rest, q - p, (n - done) as nat); }
                    if n > done + 1 && groups(next, (n - done - 1) as nat) {
                        assert(hex_group(rest.subrange(0, q - p)));
                        assert(groups(rest, (n - done) as nat));
                    }
                }
            }
        }
        p = q + 1;
        done = done + 1;
    }
}
/// The value of up to three decimal digits.
fn octet_exec(s: &[u8]) -> (out: bool)
    ensures out == octet_ok(s@),
{
    if s.len() == 0 || s.len() > 3 { return false; }
    let mut value: u64 = 0;
    let mut k: usize = 0;
    while k < s.len()
        invariant k <= s.len(), s.len() <= 3, forall|j: int| 0 <= j < k ==> crate::inbound::is_digit(#[trigger] s@[j]),
            value == crate::inbound::value_of(s@.subrange(0, k as int)), k == 0 ==> value == 0, k <= 1 ==> value < 10, k <= 2 ==> value < 100, value < 1000,
        decreases s.len() - k,
    {
        if !is_digit_exec(s[k]) { return false; }
        proof {
            assert(s@.subrange(0, k + 1).drop_last() =~= s@.subrange(0, k as int));
            assert(s@.subrange(0, k + 1).last() == s@[k as int]);
        }
        value = value * 10 + (s[k] - 48) as u64;
        k = k + 1;
    }
    proof { assert(s@.subrange(0, s@.len() as int) =~= s@); }
    (s[0] != 48 || s.len() == 1) && value <= 255
}
/// A dot inside an octet's span: impossible.
proof fn lemma_octet_no_dot(s: Seq<u8>, i: int, j: int, k: int)
    requires 0 <= i <= j <= s.len(), octet_ok(s.subrange(i, j)), i <= k < j,
    ensures s[k] != DOT,
{
    assert(crate::inbound::is_digit(s.subrange(i, j)[k - i]));
}
/// In an address with dots at `x`, `y`, `z`, every dot is one of them.
proof fn lemma_dot_is_boundary(s: Seq<u8>, x: int, y: int, z: int, p: int)
    requires 0 < x < y < z < s.len(), octet_ok(s.subrange(0, x)), octet_ok(s.subrange(x + 1, y)), octet_ok(s.subrange(y + 1, z)), octet_ok(s.subrange(z + 1, s.len() as int)),
        0 <= p < s.len(), s[p] == DOT,
    ensures p == x || p == y || p == z,
{
    if p < x { lemma_octet_no_dot(s, 0, x, p); }
    else if x < p < y { lemma_octet_no_dot(s, x + 1, y, p); }
    else if y < p < z { lemma_octet_no_dot(s, y + 1, z, p); }
    else if z < p { lemma_octet_no_dot(s, z + 1, s.len() as int, p); }
}
/// Four dots cannot all be the dots of an address.
proof fn lemma_four_dots(s: Seq<u8>, a: int, b: int, c: int, d: int)
    requires 0 <= a < b < c < d < s.len(), s[a] == DOT, s[b] == DOT, s[c] == DOT, s[d] == DOT,
    ensures !ipv4_ok(s),
{
    if ipv4_ok(s) {
        let (x, y, z) = choose|x: int, y: int, z: int| 0 < x < y < z < s.len() && #[trigger] s[x] == DOT && #[trigger] s[y] == DOT && #[trigger] s[z] == DOT
            && octet_ok(s.subrange(0, x)) && octet_ok(s.subrange(x + 1, y)) && octet_ok(s.subrange(y + 1, z)) && octet_ok(s.subrange(z + 1, s.len() as int));
        lemma_dot_is_boundary(s, x, y, z, a); lemma_dot_is_boundary(s, x, y, z, b); lemma_dot_is_boundary(s, x, y, z, c); lemma_dot_is_boundary(s, x, y, z, d);
    }
}
/// The three dots of an address are its only dots, in order.
proof fn lemma_dots_forced(s: Seq<u8>, a: int, b: int, c: int, x: int, y: int, z: int)
    requires 0 < a < b < c < s.len(), s[a] == DOT, s[b] == DOT, s[c] == DOT,
        octet_ok(s.subrange(0, a)), octet_ok(s.subrange(a + 1, b)), octet_ok(s.subrange(b + 1, c)), octet_ok(s.subrange(c + 1, s.len() as int)),
        0 <= x < y < z < s.len(), s[x] == DOT, s[y] == DOT, s[z] == DOT,
    ensures x == a, y == b, z == c,
{
    lemma_dot_is_boundary(s, a, b, c, x); lemma_dot_is_boundary(s, a, b, c, y); lemma_dot_is_boundary(s, a, b, c, z);
}
/// Whether `s` is a dotted-decimal IPv4 address.
#[verifier::loop_isolation(false)]
#[verifier::rlimit(60)]
fn ipv4_exec(s: &[u8]) -> (out: bool)
    ensures out == ipv4_ok(s@),
{
    // The dots are forced: octets hold only digits, so the three dots of an address are its only dots.
    let mut first: usize = 0;
    let mut second: usize = 0;
    let mut third: usize = 0;
    let mut found: usize = 0;
    let mut i: usize = 0;
    while i < s.len()
        invariant i <= s.len(), found <= 3,
            found >= 1 ==> first < i && s@[first as int] == DOT,
            found >= 2 ==> first < second < i && s@[second as int] == DOT,
            found >= 3 ==> second < third < i && s@[third as int] == DOT,
            forall|j: int| 0 <= j < i && #[trigger] s@[j] == DOT ==> (found >= 1 && j == first) || (found >= 2 && j == second) || (found >= 3 && j == third),
        decreases s.len() - i,
    {
        if s[i] == DOT {
            if found == 3 {
                proof { lemma_four_dots(s@, first as int, second as int, third as int, i as int); }
                return false;
            }
            if found == 0 { first = i; } else if found == 1 { second = i; } else { third = i; }
            found = found + 1;
        }
        i = i + 1;
    }
    if found < 3 {
        proof {
            if ipv4_ok(s@) {
                let (a, b, c) = choose|a: int, b: int, c: int| 0 < a < b < c < s@.len() && #[trigger] s@[a] == DOT && #[trigger] s@[b] == DOT && #[trigger] s@[c] == DOT
                    && octet_ok(s@.subrange(0, a)) && octet_ok(s@.subrange(a + 1, b)) && octet_ok(s@.subrange(b + 1, c)) && octet_ok(s@.subrange(c + 1, s@.len() as int));
                assert(false);
            }
        }
        return false;
    }
    if first == 0 { return false; }
    let ok = octet_exec(slice_subrange(s, 0, first)) && octet_exec(slice_subrange(s, first + 1, second))
        && octet_exec(slice_subrange(s, second + 1, third)) && octet_exec(slice_subrange(s, third + 1, s.len()));
    proof {
        if ok { assert(ipv4_ok(s@)); }
        if !ok && ipv4_ok(s@) {
            let (a, b, c) = choose|a: int, b: int, c: int| 0 < a < b < c < s@.len() && #[trigger] s@[a] == DOT && #[trigger] s@[b] == DOT && #[trigger] s@[c] == DOT
                && octet_ok(s@.subrange(0, a)) && octet_ok(s@.subrange(a + 1, b)) && octet_ok(s@.subrange(b + 1, c)) && octet_ok(s@.subrange(c + 1, s@.len() as int));
            lemma_dots_forced(s@, a, b, c, first as int, second as int, third as int);
        }
    }
    ok
}

/// How many groups' worth `s` is as a tail, exactly.
#[verifier::rlimit(60)]
fn tail_groups(s: &[u8]) -> (out: Option<usize>)
    ensures match out { Some(n) => tail(s@, n as nat) && n <= s.len(), None => forall|n: nat| !tail(s@, n) },
{
    // The last piece decides: a dot in it makes it an IPv4 address, which holds no colon.
    let mut last_colon: Option<usize> = None;
    let mut has_dot = false;
    let mut i: usize = 0;
    while i < s.len()
        invariant i <= s.len(), has_dot == exists|j: int| 0 <= j < i && #[trigger] s@[j] == DOT,
            match last_colon { Some(k) => k < i && s@[k as int] == COLON && forall|j: int| k < j < i ==> #[trigger] s@[j] != COLON, None => forall|j: int| 0 <= j < i ==> #[trigger] s@[j] != COLON },
        decreases s.len() - i,
    {
        if s[i] == COLON { last_colon = Some(i); }
        if s[i] == DOT { has_dot = true; }
        i = i + 1;
    }
    if !has_dot {
        let counted = count_groups(s);
        proof {
            assert forall|n: nat| tail(s@, n) == groups(s@, n) by {
                if n == 2 && ipv4_ok(s@) { lemma_ipv4_has_dot(s@); }
                if n > 2 && tail(s@, n) && !groups(s@, n) {
                    let k = choose|k: int| 0 <= k < s@.len() && groups(s@.subrange(0, k), (n - 2) as nat) && #[trigger] s@[k] == COLON && ipv4_ok(s@.subrange(k + 1, s@.len() as int));
                    let v4 = s@.subrange(k + 1, s@.len() as int);
                    lemma_ipv4_has_dot(v4);
                    let j = choose|j: int| 0 <= j < v4.len() && #[trigger] v4[j] == DOT;
                    assert(s@[k + 1 + j] == DOT);
                }
            }
        }
        return counted;
    }
    proof { assert forall|n: nat| groups(s@, n) implies false by { lemma_groups_plain(s@, n); } }
    match last_colon {
        None => {
            let v4 = ipv4_exec(s);
            proof {
                assert forall|n: nat| tail(s@, n) == (n == 2 && v4) by {
                    if n > 2 && tail(s@, n) {
                        let k = choose|k: int| 0 <= k < s@.len() && groups(s@.subrange(0, k), (n - 2) as nat) && #[trigger] s@[k] == COLON && ipv4_ok(s@.subrange(k + 1, s@.len() as int));
                    }
                }
            }
            if v4 {
                proof { lemma_ipv4_plain(s@); assert(tail(s@, 2)); assert(2 <= s.len()); }
                Some(2)
            } else {
                proof { assert forall|n: nat| !tail(s@, n) by {} }
                None
            }
        }
        Some(k) => {
            let head = count_groups(slice_subrange(s, 0, k));
            let v4 = ipv4_exec(slice_subrange(s, k + 1, s.len()));
            proof {
                assert forall|n: nat| tail(s@, n) == (n > 2 && v4 && (match head { Some(h) => h + 2 == n, None => false })) by {
                    if n > 2 && tail(s@, n) && !groups(s@, n) {
                        let k2 = choose|k2: int| 0 <= k2 < s@.len() && groups(s@.subrange(0, k2), (n - 2) as nat) && #[trigger] s@[k2] == COLON && ipv4_ok(s@.subrange(k2 + 1, s@.len() as int));
                        if k2 != k {
                            lemma_ipv4_plain(s@.subrange(k2 + 1, s@.len() as int));
                            if k2 < k { assert(s@.subrange(k2 + 1, s@.len() as int)[k - k2 - 1] == COLON); }
                            assert(false);
                        }
                        match head { Some(h) => { lemma_groups_unique(s@.subrange(0, k as int), h as nat, (n - 2) as nat); } None => { assert(false); } }
                    }
                    if n == 2 && ipv4_ok(s@) { lemma_ipv4_plain(s@); assert(false); }
                    if n > 2 && v4 && (match head { Some(h) => h + 2 == n, None => false }) {
                        assert(groups(s@.subrange(0, k as int), (n - 2) as nat) && s@[k as int] == COLON && ipv4_ok(s@.subrange(k + 1, s@.len() as int)));
                    }
                }
            }
            // An empty head before the colon (`:1.2.3.4`) is no address: the groups before an IPv4 tail are at least one.
            match head {
                Some(h) => if v4 && h >= 1 {
                    proof {
                        lemma_ipv4_plain(s@.subrange(k + 1, s@.len() as int));
                        assert(tail(s@, (h + 2) as nat));
                    }
                    Some(h + 2)
                } else {
                    proof { assert forall|n: nat| !tail(s@, n) by {} }
                    None
                },
                None => {
                    proof { assert forall|n: nat| !tail(s@, n) by {} }
                    None
                }
            }
        }
    }
}
/// An IPv4 address has a dot.
proof fn lemma_ipv4_has_dot(s: Seq<u8>)
    requires ipv4_ok(s),
    ensures exists|j: int| 0 <= j < s.len() && #[trigger] s[j] == DOT,
{
    let (a, b, c) = choose|a: int, b: int, c: int| 0 < a < b < c < s.len() && #[trigger] s[a] == DOT && #[trigger] s[b] == DOT && #[trigger] s[c] == DOT
        && octet_ok(s.subrange(0, a)) && octet_ok(s.subrange(a + 1, b)) && octet_ok(s.subrange(b + 1, c)) && octet_ok(s.subrange(c + 1, s.len() as int));
    assert(s[a] == DOT);
}

/// Whether `s` is an IPv6 address text.
#[verifier::rlimit(60)]
pub fn literal_ok(s: &[u8]) -> (out: bool)
    ensures out == ipv6_ok(s@),
{
    // The first `::`, if any; the grammar allows only one, so any address has it there.
    let mut found = false;
    let mut f: usize = 0;
    let mut i: usize = 0;
    while !found && i < s.len() && i + 1 < s.len()
        invariant i <= s.len(), !found ==> forall|j: int| 0 <= j < i ==> !double_colon(s@, j),
            found ==> f == i && double_colon(s@, f as int) && forall|j: int| 0 <= j < f ==> !double_colon(s@, j),
        decreases (if found { 0int } else { s.len() - i + 1 }),
    {
        if s[i] == COLON && s[i + 1] == COLON { found = true; f = i; } else { i = i + 1; }
    }
    let first: Option<usize> = if found { Some(f) } else { None };
    proof {
        if !found { assert forall|j: int| !double_colon(s@, j) by { if j >= i { assert(j + 2 > s@.len()); } } }
    }
    match first {
        None => {
            let whole = tail_groups(s);
            let ok = match whole { Some(8) => true, _ => false };
            proof {
                assert forall|j: int| !double_colon(s@, j) by {}
                if ipv6_ok(s@) && !tail(s@, 8) {
                    let (i2, h, t) = choose|i2: int, h: nat, t: nat| #[trigger] double_colon(s@, i2) && #[trigger] groups_at(s@, i2, h) && #[trigger] tail_from(s@, i2, t) && h + t <= 7;
                    assert(false);
                }
                if tail(s@, 8) { match whole { Some(n) => { lemma_tail_unique(s@, n as nat, 8); } None => { assert(false); } } }
            }
            ok
        }
        Some(f) => {
            let head = count_groups(slice_subrange(s, 0, f));
            let rest = tail_groups(slice_subrange(s, f + 2, s.len()));
            let ok = match (head, rest) { (Some(h), Some(t)) => h + t <= 7, _ => false };
            proof {
                let hs = s@.subrange(0, f as int);
                let ts = s@.subrange(f + 2, s@.len() as int);
                // No eight-group address holds `::`.
                if tail(s@, 8) { lemma_tail_plain(s@, 8); assert(false); }
                if ok {
                    let h = head.unwrap(); let t = rest.unwrap();
                    assert(double_colon(s@, f as int) && groups_at(s@, f as int, h as nat) && tail_from(s@, f as int, t as nat) && h + t <= 7);
                    assert(ipv6_ok(s@));
                }
                if !ok && ipv6_ok(s@) {
                    let (i2, h, t) = choose|i2: int, h: nat, t: nat| #[trigger] double_colon(s@, i2) && #[trigger] groups_at(s@, i2, h) && #[trigger] tail_from(s@, i2, t) && h + t <= 7;
                    if i2 < f { assert(!double_colon(s@, i2)); assert(false); }
                    if i2 > f {
                        lemma_groups_plain(s@.subrange(0, i2), h);
                        assert(s@.subrange(0, i2)[f as int] == COLON);
                        assert(s@.subrange(0, i2)[f + 1] == COLON);
                        assert(false);
                    }
                    assert(groups(hs, h) && tail(ts, t));
                    match head { Some(h0) => { lemma_groups_unique(hs, h0 as nat, h); } None => { assert(false); } }
                    match rest { Some(t0) => { lemma_tail_unique(ts, t0 as nat, t); } None => { assert(false); } }
                    assert(false);
                }
            }
            ok
        }
    }
}

} // verus!
