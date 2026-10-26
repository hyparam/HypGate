//! UTF-8 well-formedness (RFC 3629, table 3-7) and a lossy sanitizer:
//! `sanitize` keeps every well-formed sequence and replaces each other byte
//! with U+FFFD, so its output is always well formed and well-formed input
//! passes through unchanged; `cap` cuts a well-formed text at a character
//! boundary within a byte limit.
use vstd::prelude::*;
use vstd::slice::{slice_subrange, slice_to_vec};

verus! {

pub const REPLACEMENT: [u8; 3] = [0xEF, 0xBF, 0xBD];

pub open spec fn cont(b: u8) -> bool { 0x80 <= b <= 0xBF }

/// The length of the well-formed sequence starting at `i`, or 0 when none
/// does: overlong forms, surrogates, and code points past U+10FFFF are
/// excluded by the ranges of the second byte.
pub open spec fn char_len(s: Seq<u8>, i: int) -> int {
    if !(0 <= i < s.len()) { 0 }
    else {
        let b = s[i];
        if b < 0x80 { 1 }
        else if 0xC2 <= b <= 0xDF { if i + 1 < s.len() && cont(s[i + 1]) { 2 } else { 0 } }
        else if 0xE0 <= b <= 0xEF {
            if i + 2 < s.len() && cont(s[i + 2]) && (
                (b == 0xE0 && 0xA0 <= s[i + 1] <= 0xBF) || (0xE1 <= b <= 0xEC && cont(s[i + 1]))
                || (b == 0xED && 0x80 <= s[i + 1] <= 0x9F) || (0xEE <= b && cont(s[i + 1]))
            ) { 3 } else { 0 }
        } else if 0xF0 <= b <= 0xF4 {
            if i + 3 < s.len() && cont(s[i + 2]) && cont(s[i + 3]) && (
                (b == 0xF0 && 0x90 <= s[i + 1] <= 0xBF) || (0xF1 <= b <= 0xF3 && cont(s[i + 1]))
                || (b == 0xF4 && 0x80 <= s[i + 1] <= 0x8F)
            ) { 4 } else { 0 }
        } else { 0 }
    }
}
/// `s` is a sequence of well-formed characters.
pub open spec fn valid(s: Seq<u8>) -> bool
    decreases s.len(),
{
    s.len() == 0 || (char_len(s, 0) > 0 && valid(s.subrange(char_len(s, 0), s.len() as int)))
}
/// The lossy conversion: each well-formed character kept, each other byte
/// replaced by U+FFFD.
pub open spec fn sanitized(s: Seq<u8>) -> Seq<u8>
    decreases s.len(),
{
    if s.len() == 0 { Seq::empty() }
    else {
        let n = char_len(s, 0);
        if n > 0 { s.subrange(0, n) + sanitized(s.subrange(n, s.len() as int)) }
        else { REPLACEMENT@ + sanitized(s.subrange(1, s.len() as int)) }
    }
}
pub open spec fn ascii(s: Seq<u8>) -> bool { forall|k: int| 0 <= k < s.len() ==> #[trigger] s[k] < 0x80 }

/// `char_len` looks only at the bytes of the character.
proof fn lemma_char_len_prefix(s: Seq<u8>, t: Seq<u8>, n: int)
    requires char_len(s, 0) == n, n > 0, n <= t.len(), t.subrange(0, n) == s.subrange(0, n),
    ensures char_len(t, 0) == n,
{
    assert forall|k: int| 0 <= k < n implies t[k] == s[k] by {
        assert(t.subrange(0, n)[k] == t[k]);
        assert(s.subrange(0, n)[k] == s[k]);
    }
}
/// `char_len` at `p` is `char_len` of the suffix at 0.
proof fn lemma_char_len_suffix(s: Seq<u8>, p: int)
    requires 0 <= p <= s.len(),
    ensures char_len(s, p) == char_len(s.subrange(p, s.len() as int), 0),
{
    let t = s.subrange(p, s.len() as int);
    if p < s.len() {
        assert(t[0] == s[p]);
        if p + 1 < s.len() { assert(t[1] == s[p + 1]); }
        if p + 2 < s.len() { assert(t[2] == s[p + 2]); }
        if p + 3 < s.len() { assert(t[3] == s[p + 3]); }
    }
}
/// A well-formed text followed by one well-formed character is well formed.
proof fn lemma_valid_push_char(a: Seq<u8>, c: Seq<u8>)
    requires valid(a), c.len() > 0, char_len(c, 0) == c.len(),
    ensures valid(a + c),
    decreases a.len(),
{
    if a.len() == 0 {
        assert(a + c =~= c);
        assert(c.subrange(c.len() as int, c.len() as int).len() == 0);
        assert(valid(c.subrange(c.len() as int, c.len() as int)));
        assert(valid(c));
    } else {
        let n = char_len(a, 0);
        let ac = a + c;
        assert(ac.subrange(0, n) =~= a.subrange(0, n));
        lemma_char_len_prefix(a, ac, n);
        lemma_valid_push_char(a.subrange(n, a.len() as int), c);
        assert(ac.subrange(n, ac.len() as int) =~= a.subrange(n, a.len() as int) + c);
        assert(valid(ac.subrange(n, ac.len() as int)));
        assert(valid(ac));
    }
}
/// Two well-formed texts concatenate to one.
pub proof fn lemma_valid_append(a: Seq<u8>, b: Seq<u8>)
    requires valid(a), valid(b),
    ensures valid(a + b),
    decreases b.len(),
{
    if b.len() == 0 {
        assert(a + b =~= a);
    } else {
        let n = char_len(b, 0);
        let c = b.subrange(0, n);
        assert(c.subrange(0, n) =~= b.subrange(0, n));
        lemma_char_len_prefix(b, c, n);
        lemma_valid_push_char(a, c);
        lemma_valid_append(a + c, b.subrange(n, b.len() as int));
        assert(a + c + b.subrange(n, b.len() as int) =~= a + b);
    }
}
/// The sanitized form of any bytes is well formed.
pub proof fn lemma_sanitized_valid(s: Seq<u8>)
    ensures valid(sanitized(s)),
    decreases s.len(),
{
    if s.len() > 0 {
        let n = char_len(s, 0);
        if n > 0 {
            let c = s.subrange(0, n);
            lemma_sanitized_valid(s.subrange(n, s.len() as int));
            assert(c.subrange(0, n) =~= s.subrange(0, n));
            lemma_char_len_prefix(s, c, n);
            assert(c.subrange(n, n).len() == 0);
            assert(valid(c.subrange(n, n)));
            assert(valid(c));
            lemma_valid_append(c, sanitized(s.subrange(n, s.len() as int)));
        } else {
            lemma_sanitized_valid(s.subrange(1, s.len() as int));
            assert(REPLACEMENT@.len() == 3 && REPLACEMENT@[0] == 0xEF && REPLACEMENT@[1] == 0xBF && REPLACEMENT@[2] == 0xBD);
            assert(char_len(REPLACEMENT@, 0) == 3);
            assert(REPLACEMENT@.subrange(3, 3).len() == 0);
            assert(valid(REPLACEMENT@.subrange(3, 3)));
            assert(valid(REPLACEMENT@));
            lemma_valid_append(REPLACEMENT@, sanitized(s.subrange(1, s.len() as int)));
        }
    }
}
/// Well-formed text passes through the sanitizer unchanged.
pub proof fn lemma_valid_fixed(s: Seq<u8>)
    requires valid(s),
    ensures sanitized(s) == s,
    decreases s.len(),
{
    if s.len() > 0 {
        let n = char_len(s, 0);
        lemma_valid_fixed(s.subrange(n, s.len() as int));
        assert(s.subrange(0, n) + s.subrange(n, s.len() as int) =~= s);
    }
}
/// ASCII bytes are well formed.
pub proof fn lemma_ascii_valid(s: Seq<u8>)
    requires ascii(s),
    ensures valid(s),
    decreases s.len(),
{
    if s.len() > 0 {
        assert(s[0] < 0x80);
        assert(char_len(s, 0) == 1);
        let rest = s.subrange(1, s.len() as int);
        assert forall|k: int| 0 <= k < rest.len() implies #[trigger] rest[k] < 0x80 by { assert(rest[k] == s[k + 1]); }
        lemma_ascii_valid(rest);
    }
}

fn is_cont(b: u8) -> (out: bool) ensures out == cont(b) { 0x80 <= b && b <= 0xBF }

/// The length of the well-formed character at `i`, or 0.
pub fn char_len_exec(s: &[u8], i: usize) -> (out: usize)
    ensures out == char_len(s@, i as int), out <= 4, i + out <= s.len() || out == 0,
{
    if i >= s.len() { return 0; }
    let left = s.len() - i;
    let b = s[i];
    if b < 0x80 { 1 }
    else if 0xC2 <= b && b <= 0xDF { if left > 1 && is_cont(s[i + 1]) { 2 } else { 0 } }
    else if 0xE0 <= b && b <= 0xEF {
        if left > 2 && is_cont(s[i + 2]) {
            let second = s[i + 1];
            if (b == 0xE0 && 0xA0 <= second && second <= 0xBF) || (0xE1 <= b && b <= 0xEC && is_cont(second))
                || (b == 0xED && 0x80 <= second && second <= 0x9F) || (0xEE <= b && is_cont(second)) { 3 } else { 0 }
        } else { 0 }
    } else if 0xF0 <= b && b <= 0xF4 {
        if left > 3 && is_cont(s[i + 2]) && is_cont(s[i + 3]) {
            let second = s[i + 1];
            if (b == 0xF0 && 0x90 <= second && second <= 0xBF) || (0xF1 <= b && b <= 0xF3 && is_cont(second))
                || (b == 0xF4 && 0x80 <= second && second <= 0x8F) { 4 } else { 0 }
        } else { 0 }
    } else { 0 }
}

/// The lossy conversion of `bytes`: well formed, and `bytes` itself when
/// `bytes` is.
#[verifier::loop_isolation(false)]
pub fn sanitize(bytes: &[u8]) -> (out: Vec<u8>)
    ensures out@ == sanitized(bytes@), valid(out@), valid(bytes@) ==> out@ == bytes@,
{
    let mut out: Vec<u8> = Vec::new();
    let mut p: usize = 0;
    proof { assert(bytes@.subrange(0, bytes@.len() as int) =~= bytes@); }
    while p < bytes.len()
        invariant p <= bytes.len(), sanitized(bytes@) == out@ + sanitized(bytes@.subrange(p as int, bytes@.len() as int)),
        decreases bytes.len() - p,
    {
        let ghost rest = bytes@.subrange(p as int, bytes@.len() as int);
        let n = char_len_exec(bytes, p);
        proof { lemma_char_len_suffix(bytes@, p as int); }
        if n > 0 {
            let ghost before = out@;
            crate::framing::append(&mut out, slice_subrange(bytes, p, p + n));
            proof {
                assert(rest.subrange(0, n as int) =~= bytes@.subrange(p as int, p + n));
                assert(rest.subrange(n as int, rest.len() as int) =~= bytes@.subrange(p + n, bytes@.len() as int));
                assert(sanitized(rest) == rest.subrange(0, n as int) + sanitized(rest.subrange(n as int, rest.len() as int)));
                assert(before + sanitized(rest) =~= out@ + sanitized(bytes@.subrange(p + n, bytes@.len() as int)));
            }
            p = p + n;
        } else {
            let ghost before = out@;
            out.push(0xEF); out.push(0xBF); out.push(0xBD);
            proof {
                assert(out@ =~= before + REPLACEMENT@);
                assert(rest.subrange(1, rest.len() as int) =~= bytes@.subrange(p + 1, bytes@.len() as int));
                assert(sanitized(rest) == REPLACEMENT@ + sanitized(rest.subrange(1, rest.len() as int)));
                assert(before + sanitized(rest) =~= out@ + sanitized(bytes@.subrange(p + 1, bytes@.len() as int)));
            }
            p = p + 1;
        }
    }
    proof {
        assert(bytes@.subrange(p as int, bytes@.len() as int).len() == 0);
        assert(out@ + sanitized(bytes@.subrange(p as int, bytes@.len() as int)) =~= out@);
        lemma_sanitized_valid(bytes@);
        if valid(bytes@) { lemma_valid_fixed(bytes@); }
    }
    out
}

/// Whether `bytes` is well-formed UTF-8.
#[verifier::loop_isolation(false)]
pub fn is_valid(bytes: &[u8]) -> (out: bool)
    ensures out == valid(bytes@),
{
    let mut p: usize = 0;
    proof { assert(bytes@.subrange(0, bytes@.len() as int) =~= bytes@); }
    while p < bytes.len()
        invariant p <= bytes.len(), valid(bytes@) == valid(bytes@.subrange(p as int, bytes@.len() as int)),
        decreases bytes.len() - p,
    {
        let ghost rest = bytes@.subrange(p as int, bytes@.len() as int);
        let n = char_len_exec(bytes, p);
        proof { lemma_char_len_suffix(bytes@, p as int); }
        if n == 0 { return false; }
        proof { assert(rest.subrange(n as int, rest.len() as int) =~= bytes@.subrange(p + n, bytes@.len() as int)); }
        p = p + n;
    }
    proof { assert(bytes@.subrange(p as int, bytes@.len() as int).len() == 0); }
    true
}

/// The longest prefix of a well-formed `text` within `limit` bytes that ends
/// at a character boundary: `text` itself when it fits.
#[verifier::loop_isolation(false)]
pub fn cap(text: &[u8], limit: usize) -> (out: Vec<u8>)
    requires valid(text@),
    ensures out@.len() <= limit, out@ == text@.subrange(0, out@.len() as int), valid(out@),
        text@.len() <= limit ==> out@ == text@,
        out@.len() < text@.len() ==> valid(text@.subrange(out@.len() as int, text@.len() as int)) && out@.len() + char_len(text@, out@.len() as int) > limit,
{
    if text.len() <= limit {
        let out = slice_to_vec(text);
        proof { assert(text@.subrange(0, text@.len() as int) =~= text@); }
        return out;
    }
    let mut p: usize = 0;
    proof { assert(text@.subrange(0, 0).len() == 0); assert(text@.subrange(0, text@.len() as int) =~= text@); }
    loop
        invariant p <= limit, p <= text.len(), valid(text@.subrange(0, p as int)), valid(text@.subrange(p as int, text@.len() as int)),
        decreases text.len() - p,
    {
        let ghost rest = text@.subrange(p as int, text@.len() as int);
        let n = char_len_exec(text, p);
        proof { lemma_char_len_suffix(text@, p as int); }
        if p >= text.len() || n == 0 || p + n > limit {
            proof { if p < text.len() { assert(rest.len() > 0); assert(char_len(rest, 0) > 0); } }
            break;
        }
        proof {
            let c = text@.subrange(p as int, p + n);
            assert(c.subrange(0, n as int) =~= rest.subrange(0, n as int));
            assert(rest.subrange(0, n as int) =~= rest.subrange(0, n as int));
            lemma_char_len_prefix(rest, c, n as int);
            lemma_valid_push_char(text@.subrange(0, p as int), c);
            assert(text@.subrange(0, p as int) + c =~= text@.subrange(0, p + n));
            assert(rest.subrange(n as int, rest.len() as int) =~= text@.subrange(p + n, text@.len() as int));
        }
        p = p + n;
    }
    let out = slice_to_vec(slice_subrange(text, 0, p));
    out
}

} // verus!
