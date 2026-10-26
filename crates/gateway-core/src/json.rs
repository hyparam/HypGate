//! Verified JSON reader. `parse` turns a byte string into a `Value` tree, or
//! refuses it. The specification is the RFC 8259 grammar written out as
//! predicates over byte positions (`document`, `encodes`, `string_body`,
//! `number_ok`), and the theorem on `parse` is soundness: a value it returns
//! is encoded by exactly the bytes it was given, whitespace aside. Nothing is
//! guessed at: a string with a bad escape, a lone surrogate, or a control
//! byte, a number with a leading zero or a dangling point or exponent, a
//! trailing comma, trailing bytes, or nesting past `MAX_DEPTH` is refused.
//! Numbers keep their lexeme; `as_u64` reads the canonical decimals the
//! gateway uses. Strings decode to UTF-8 bytes: `\u` escapes become the
//! code point's UTF-8, surrogate pairs become one code point. Raw bytes in
//! strings are passed through as written and not checked for UTF-8 validity.
//! Duplicate keys are kept in order; `get` finds the first.
//!
//! This module depends only on `vstd` and the hex and decimal helpers in
//! this crate, so it can stand on its own. Completeness (that every document
//! of the grammar is accepted) is not yet proved; see `docs/json.md`.
use vstd::prelude::*;
use vstd::slice::{slice_index_get, slice_subrange, slice_to_vec};

verus! {
pub const MAX_DEPTH: u32 = 64;

pub const QUOTE: u8 = 34;
pub const BSLASH: u8 = 92;
pub const SLASH: u8 = 47;
pub const LBRACKET: u8 = 91;
pub const RBRACKET: u8 = 93;
pub const LBRACE: u8 = 123;
pub const RBRACE: u8 = 125;
pub const COMMA: u8 = 44;
pub const COLON: u8 = 58;
pub const MINUS: u8 = 45;
pub const PLUS: u8 = 43;
pub const DOT: u8 = 46;
pub const SP: u8 = 32;
pub const TAB: u8 = 9;
pub const LF: u8 = 10;
pub const CR: u8 = 13;
pub const ZERO: u8 = 48;
pub const NINE: u8 = 57;
pub const UPPER_E: u8 = 69;
pub const LOWER_B: u8 = 98;
pub const LOWER_E: u8 = 101;
pub const LOWER_F: u8 = 102;
pub const LOWER_N: u8 = 110;
pub const LOWER_R: u8 = 114;
pub const LOWER_T: u8 = 116;
pub const LOWER_U: u8 = 117;

/// A JSON value. Numbers keep their lexeme; strings are decoded bytes.
#[derive(Debug, PartialEq, Eq)]
pub enum Value { Null, Bool(bool), Number(Vec<u8>), Str(Vec<u8>), Array(Vec<Value>), Object(Vec<Member>) }
#[derive(Debug, PartialEq, Eq)]
pub struct Member { pub key: Vec<u8>, pub value: Value }

// ---- the grammar -------------------------------------------------------------------

pub open spec fn is_ws(b: u8) -> bool { b == SP || b == TAB || b == LF || b == CR }
/// `s[i..j)` is whitespace.
pub open spec fn ws(s: Seq<u8>, i: int, j: int) -> bool {
    0 <= i <= j <= s.len() && forall|k: int| i <= k < j ==> is_ws(#[trigger] s[k])
}
pub open spec fn is_digit(b: u8) -> bool { ZERO <= b <= NINE }
pub open spec fn all_digits(s: Seq<u8>) -> bool { forall|k: int| 0 <= k < s.len() ==> is_digit(#[trigger] s[k]) }
/// `-? ( 0 | [1-9] [0-9]* )`
pub open spec fn int_ok(s: Seq<u8>) -> bool {
    let d = if s.len() >= 1 && s[0] == MINUS { s.drop_first() } else { s };
    d.len() >= 1 && all_digits(d) && (d[0] != ZERO || d.len() == 1)
}
/// Empty, or `. [0-9]+`
pub open spec fn frac_ok(s: Seq<u8>) -> bool { s.len() == 0 || (s.len() >= 2 && s[0] == DOT && all_digits(s.drop_first())) }
/// Empty, or `[eE] [+-]? [0-9]+`
pub open spec fn exp_ok(s: Seq<u8>) -> bool {
    s.len() == 0 || (s.len() >= 2 && (s[0] == LOWER_E || s[0] == UPPER_E) && {
        let d = if s[1] == PLUS || s[1] == MINUS { s.subrange(2, s.len() as int) } else { s.drop_first() };
        d.len() >= 1 && all_digits(d)
    })
}
/// The number grammar: an integer part, then an optional fraction and exponent.
pub open spec fn number_ok(s: Seq<u8>) -> bool {
    exists|a: int, b: int| 0 <= a <= b <= s.len() && int_ok(#[trigger] s.subrange(0, a)) && frac_ok(#[trigger] s.subrange(a, b))
        && exp_ok(s.subrange(b, s.len() as int))
}

/// The UTF-8 encoding of a code point below 0x110000.
pub open spec fn utf8(cp: nat) -> Seq<u8> {
    if cp < 0x80 { seq![cp as u8] }
    else if cp < 0x800 { seq![(0xC0 + cp / 0x40) as u8, (0x80 + cp % 0x40) as u8] }
    else if cp < 0x10000 { seq![(0xE0 + cp / 0x1000) as u8, (0x80 + (cp / 0x40) % 0x40) as u8, (0x80 + cp % 0x40) as u8] }
    else { seq![(0xF0 + cp / 0x40000) as u8, (0x80 + (cp / 0x1000) % 0x40) as u8, (0x80 + (cp / 0x40) % 0x40) as u8, (0x80 + cp % 0x40) as u8] }
}
/// The byte a two-character escape stands for.
pub open spec fn simple_escape(b: u8) -> Option<u8> {
    if b == QUOTE { Some(QUOTE) } else if b == BSLASH { Some(BSLASH) } else if b == SLASH { Some(SLASH) }
    else if b == LOWER_B { Some(8) } else if b == LOWER_F { Some(12) } else if b == LOWER_N { Some(LF) }
    else if b == LOWER_R { Some(CR) } else if b == LOWER_T { Some(TAB) } else { None }
}
/// Four hex digits at `i`.
pub open spec fn hex4(s: Seq<u8>, i: int) -> bool { 0 <= i && i + 4 <= s.len() && crate::http1_chunked::all_hex(s.subrange(i, i + 4)) }
/// The code unit the four hex digits at `i` spell.
pub open spec fn unit(s: Seq<u8>, i: int) -> nat { crate::http1_chunked::hex_value(s.subrange(i, i + 4)) }
pub open spec fn is_high(u: nat) -> bool { 0xD800 <= u <= 0xDBFF }
pub open spec fn is_low(u: nat) -> bool { 0xDC00 <= u <= 0xDFFF }
pub open spec fn pair(hi: nat, lo: nat) -> nat { (0x10000 + (hi - 0xD800) * 0x400 + (lo - 0xDC00)) as nat }
/// `esc` is one escape sequence and `dec` the bytes it stands for: a simple
/// escape, a `\u` escape outside the surrogates, or a surrogate pair.
pub open spec fn escape(esc: Seq<u8>, dec: Seq<u8>) -> bool {
    esc.len() >= 2 && esc[0] == BSLASH && (
        (esc.len() == 2 && dec.len() == 1 && simple_escape(esc[1]) == Some(dec[0]))
        || (esc.len() == 6 && esc[1] == LOWER_U && hex4(esc, 2) && !is_high(unit(esc, 2)) && !is_low(unit(esc, 2)) && dec == utf8(unit(esc, 2)))
        || (esc.len() == 12 && esc[1] == LOWER_U && hex4(esc, 2) && is_high(unit(esc, 2)) && esc[6] == BSLASH && esc[7] == LOWER_U
            && hex4(esc, 8) && is_low(unit(esc, 8)) && dec == utf8(pair(unit(esc, 2), unit(esc, 8))))
    )
}
/// A byte that stands for itself inside a string.
pub open spec fn plain(b: u8) -> bool { b >= 0x20 && b != QUOTE && b != BSLASH }
/// `inside`, the bytes between the quotes, decodes to `text`.
pub open spec fn string_body(inside: Seq<u8>, text: Seq<u8>) -> bool
    decreases inside.len(),
{
    if inside.len() == 0 { text.len() == 0 }
    else if inside[0] == BSLASH {
        exists|n: int, m: int| 2 <= n <= inside.len() && 0 <= m <= text.len() && escape(#[trigger] inside.subrange(0, n), #[trigger] text.subrange(0, m))
            && string_body(inside.subrange(n, inside.len() as int), text.subrange(m, text.len() as int))
    } else {
        plain(inside[0]) && text.len() >= 1 && text[0] == inside[0] && string_body(inside.drop_first(), text.drop_first())
    }
}
/// `s[i..j)` is a quoted string decoding to `text`.
pub open spec fn string_at(s: Seq<u8>, i: int, j: int, text: Seq<u8>) -> bool {
    0 <= i && i + 2 <= j <= s.len() && s[i] == QUOTE && s[j - 1] == QUOTE && string_body(s.subrange(i + 1, j - 1), text)
}

pub open spec fn null_word() -> Seq<u8> { seq![LOWER_N, LOWER_U, 108u8, 108u8] }
pub open spec fn true_word() -> Seq<u8> { seq![LOWER_T, LOWER_R, LOWER_U, LOWER_E] }
pub open spec fn false_word() -> Seq<u8> { seq![LOWER_F, 97u8, 108u8, 115u8, LOWER_E] }

/// `s[i..j)` is exactly one value `v`, with no whitespace around it.
pub open spec fn encodes(s: Seq<u8>, i: int, j: int, v: Value) -> bool
    decreases v, 0int,
{
    0 <= i <= j <= s.len() && match v {
        Value::Null => s.subrange(i, j) == null_word(),
        Value::Bool(b) => s.subrange(i, j) == if b { true_word() } else { false_word() },
        Value::Number(lex) => s.subrange(i, j) == lex@ && number_ok(lex@),
        Value::Str(text) => string_at(s, i, j, text@),
        Value::Array(items) => j - i >= 2 && s[i] == LBRACKET && s[j - 1] == RBRACKET && elements(s, i + 1, j - 1, items@),
        Value::Object(ms) => j - i >= 2 && s[i] == LBRACE && s[j - 1] == RBRACE && members(s, i + 1, j - 1, ms@),
    }
}
/// Whitespace, then `v` ending at `j`.
pub open spec fn padded(s: Seq<u8>, i: int, j: int, v: Value) -> bool
    decreases v, 1int,
{
    exists|d: int| #[trigger] ws(s, i, d) && encodes(s, d, j, v)
}
/// `s[i..j)` is `items` separated by commas, with whitespace around each,
/// ending right after the last one.
pub open spec fn items_ok(s: Seq<u8>, i: int, j: int, items: Seq<Value>) -> bool
    decreases items, 3int,
{
    if items.len() == 0 { false }
    else if items.len() == 1 { padded(s, i, j, items[0]) }
    else {
        exists|c: int, a: int| items_ok(s, i, c, items.drop_last()) && #[trigger] ws(s, c, a) && a < s.len() && s[a] == COMMA
            && padded(s, a + 1, j, items.last())
    }
}
/// The inside of an array: whitespace, or `items_ok` then whitespace.
pub open spec fn elements(s: Seq<u8>, i: int, j: int, items: Seq<Value>) -> bool
    decreases items, 4int,
{
    if items.len() == 0 { ws(s, i, j) } else { exists|b: int| items_ok(s, i, b, items) && #[trigger] ws(s, b, j) }
}
/// Whitespace, a colon, then `padded`.
pub open spec fn colon_then(s: Seq<u8>, b: int, j: int, v: Value) -> bool
    decreases v, 2int,
{
    exists|c: int| #[trigger] ws(s, b, c) && c < s.len() && s[c] == COLON && padded(s, c + 1, j, v)
}
/// The quoted key of `m` starting at `a`, then `colon_then` its value.
pub open spec fn key_then(s: Seq<u8>, a: int, j: int, m: Member) -> bool
    decreases m, 2int,
{
    exists|b: int| #[trigger] string_at(s, a, b, m.key@) && colon_then(s, b, j, m.value)
}
/// `s[i..j)` is whitespace, a quoted key, whitespace, a colon, whitespace, and a value.
pub open spec fn member_ok(s: Seq<u8>, i: int, j: int, m: Member) -> bool
    decreases m, 3int,
{
    exists|a: int| #[trigger] ws(s, i, a) && key_then(s, a, j, m)
}
pub open spec fn members_ok(s: Seq<u8>, i: int, j: int, ms: Seq<Member>) -> bool
    decreases ms, 4int,
{
    if ms.len() == 0 { false }
    else if ms.len() == 1 { member_ok(s, i, j, ms[0]) }
    else {
        exists|c: int, a: int| members_ok(s, i, c, ms.drop_last()) && #[trigger] ws(s, c, a) && a < s.len() && s[a] == COMMA
            && member_ok(s, a + 1, j, ms.last())
    }
}
/// The inside of an object: whitespace, or `members_ok` then whitespace.
pub open spec fn members(s: Seq<u8>, i: int, j: int, ms: Seq<Member>) -> bool
    decreases ms, 5int,
{
    if ms.len() == 0 { ws(s, i, j) } else { exists|b: int| members_ok(s, i, b, ms) && #[trigger] ws(s, b, j) }
}
/// `s` is one value with whitespace around it.
pub open spec fn document(s: Seq<u8>, v: Value) -> bool {
    exists|i: int, j: int| ws(s, 0, i) && encodes(s, i, j, v) && ws(s, j, s.len() as int)
}

// ---- lemmas about the grammar ----------------------------------------------------------

/// Decoded strings concatenate: the bytes of one body followed by another
/// decode to the two texts in order.
pub proof fn lemma_body_append(a: Seq<u8>, ta: Seq<u8>, b: Seq<u8>, tb: Seq<u8>)
    requires string_body(a, ta), string_body(b, tb),
    ensures string_body(a + b, ta + tb),
    decreases a.len(),
{
    if a.len() == 0 {
        assert(a + b =~= b);
        assert(ta + tb =~= tb);
    } else if a[0] == BSLASH {
        let (n, m) = choose|n: int, m: int| 2 <= n <= a.len() && 0 <= m <= ta.len() && escape(#[trigger] a.subrange(0, n), #[trigger] ta.subrange(0, m))
            && string_body(a.subrange(n, a.len() as int), ta.subrange(m, ta.len() as int));
        lemma_body_append(a.subrange(n, a.len() as int), ta.subrange(m, ta.len() as int), b, tb);
        let ab = a + b;
        let tab = ta + tb;
        assert(ab.subrange(0, n) =~= a.subrange(0, n));
        assert(tab.subrange(0, m) =~= ta.subrange(0, m));
        assert(ab.subrange(n, ab.len() as int) =~= a.subrange(n, a.len() as int) + b);
        assert(tab.subrange(m, tab.len() as int) =~= ta.subrange(m, ta.len() as int) + tb);
    } else {
        lemma_body_append(a.drop_first(), ta.drop_first(), b, tb);
        let ab = a + b;
        let tab = ta + tb;
        assert(ab.drop_first() =~= a.drop_first() + b);
        assert(tab.drop_first() =~= ta.drop_first() + tb);
    }
}
/// One escape sequence is a string body on its own.
proof fn lemma_escape_body(esc: Seq<u8>, dec: Seq<u8>)
    requires escape(esc, dec),
    ensures string_body(esc, dec),
{
    let n = esc.len() as int;
    let m = dec.len() as int;
    assert(esc.subrange(0, n) =~= esc);
    assert(dec.subrange(0, m) =~= dec);
    assert(escape(esc.subrange(0, n), dec.subrange(0, m)));
    assert(esc.subrange(n, n).len() == 0);
    assert(dec.subrange(m, m).len() == 0);
    assert(string_body(esc.subrange(n, n), dec.subrange(m, m)));
}
/// A decoded body extended by one escape sequence.
proof fn lemma_extend_escape(s: Seq<u8>, i: int, p: int, n: int, before: Seq<u8>, after: Seq<u8>)
    requires 0 <= i, i + 1 <= p, 0 <= n, p + n <= s.len(), string_body(s.subrange(i + 1, p), before), after.len() >= before.len(),
        after.subrange(0, before.len() as int) == before, escape(s.subrange(p, p + n), after.subrange(before.len() as int, after.len() as int)),
    ensures string_body(s.subrange(i + 1, p + n), after),
{
    let esc = s.subrange(p, p + n);
    let dec = after.subrange(before.len() as int, after.len() as int);
    lemma_escape_body(esc, dec);
    lemma_body_append(s.subrange(i + 1, p), before, esc, dec);
    assert(s.subrange(i + 1, p + n) =~= s.subrange(i + 1, p) + esc);
    assert(after =~= before + dec);
}
/// One plain byte is a string body on its own.
proof fn lemma_plain_body(b: u8)
    requires plain(b),
    ensures string_body(seq![b], seq![b]),
{
    let one = seq![b];
    assert(one[0] == b);
    assert(one.drop_first().len() == 0);
    assert(string_body(one.drop_first(), one.drop_first()));
}

// ---- the reader ------------------------------------------------------------------------

fn is_ws_exec(b: u8) -> (out: bool) ensures out == is_ws(b) { b == SP || b == TAB || b == LF || b == CR }
fn is_digit_exec(b: u8) -> (out: bool) ensures out == is_digit(b) { ZERO <= b && b <= NINE }
fn is_hex_exec(b: u8) -> (out: bool) ensures out == crate::http1_chunked::is_hex(b) { (48 <= b && b <= 57) || (65 <= b && b <= 70) || (97 <= b && b <= 102) }
fn hex_val_exec(b: u8) -> (out: u8)
    requires crate::http1_chunked::is_hex(b),
    ensures out == crate::http1_chunked::hex_val(b), out < 16,
{
    if 48 <= b && b <= 57 { b - 48 } else if 65 <= b && b <= 70 { b - 55 } else { b - 87 }
}

proof fn lemma_pow16_mono(a: nat, b: nat)
    requires a <= b,
    ensures crate::http1_chunked::pow16(a) <= crate::http1_chunked::pow16(b),
    decreases b - a,
{
    if a < b { lemma_pow16_mono(a, (b - 1) as nat); }
}

/// The first non-whitespace position at or after `i`.
fn skip_ws(s: &[u8], i: usize) -> (j: usize)
    requires i <= s.len(),
    ensures i <= j <= s.len(), ws(s@, i as int, j as int), j < s.len() ==> !is_ws(s@[j as int]),
{
    let mut j = i;
    while j < s.len() && is_ws_exec(s[j])
        invariant i <= j <= s.len(), ws(s@, i as int, j as int),
        decreases s.len() - j,
    {
        j = j + 1;
    }
    j
}
/// The first non-digit position at or after `i`.
fn skip_digits(s: &[u8], i: usize) -> (j: usize)
    requires i <= s.len(),
    ensures i <= j <= s.len(), all_digits(s@.subrange(i as int, j as int)), j < s.len() ==> !is_digit(s@[j as int]),
{
    let mut j = i;
    while j < s.len() && is_digit_exec(s[j])
        invariant i <= j <= s.len(), all_digits(s@.subrange(i as int, j as int)),
        decreases s.len() - j,
    {
        proof { assert(s@.subrange(i as int, j + 1) =~= s@.subrange(i as int, j as int).push(s@[j as int])); }
        j = j + 1;
    }
    j
}

/// The end of the number lexeme starting at `i`, which must be a minus or a digit.
fn number(s: &[u8], i: usize) -> (out: Option<usize>)
    requires i < s.len(),
    ensures match out { Some(j) => i < j <= s.len() && number_ok(s@.subrange(i as int, j as int)), None => true },
{
    let mut j = i;
    if s[j] == MINUS { j = j + 1; }
    if j >= s.len() || !is_digit_exec(s[j]) { return None; }
    let ghost digits_start = j as int;
    if s[j] == ZERO { j = j + 1; } else { j = skip_digits(s, j); }
    let ghost a = j as int;
    proof {
        let lex_int = s@.subrange(i as int, a);
        if s@[i as int] == MINUS {
            assert(lex_int.drop_first() =~= s@.subrange(digits_start, a));
        } else {
            assert(lex_int =~= s@.subrange(digits_start, a));
        }
        if s@[digits_start] == ZERO {
            assert(s@.subrange(digits_start, a) =~= seq![ZERO]);
        }
        assert(int_ok(lex_int));
    }
    if j < s.len() && s[j] == DOT {
        j = j + 1;
        if j >= s.len() || !is_digit_exec(s[j]) { return None; }
        j = skip_digits(s, j);
        proof { assert(s@.subrange(a, j as int).drop_first() =~= s@.subrange(a + 1, j as int)); }
    } else {
        proof { assert(s@.subrange(a, j as int).len() == 0); }
    }
    let ghost b = j as int;
    assert(frac_ok(s@.subrange(a, b)));
    if j < s.len() && (s[j] == LOWER_E || s[j] == UPPER_E) {
        j = j + 1;
        if j < s.len() && (s[j] == PLUS || s[j] == MINUS) { j = j + 1; }
        let ghost exp_digits = j as int;
        if j >= s.len() || !is_digit_exec(s[j]) { return None; }
        j = skip_digits(s, j);
        proof {
            let lex_exp = s@.subrange(b, j as int);
            if s@[b + 1] == PLUS || s@[b + 1] == MINUS {
                assert(lex_exp.subrange(2, lex_exp.len() as int) =~= s@.subrange(exp_digits, j as int));
            } else {
                assert(lex_exp.drop_first() =~= s@.subrange(exp_digits, j as int));
            }
        }
    } else {
        proof { assert(s@.subrange(b, j as int).len() == 0); }
    }
    assert(exp_ok(s@.subrange(b, j as int)));
    proof {
        let lex = s@.subrange(i as int, j as int);
        assert(lex.subrange(0, a - i) =~= s@.subrange(i as int, a));
        assert(lex.subrange(a - i, b - i) =~= s@.subrange(a, b));
        assert(lex.subrange(b - i, lex.len() as int) =~= s@.subrange(b, j as int));
        assert(number_ok(lex));
    }
    Some(j)
}

/// Four hex digits at `i`, as a code unit.
fn hex4_exec(s: &[u8], i: usize) -> (out: Option<u32>)
    requires i <= s.len(),
    ensures match out { Some(u) => hex4(s@, i as int) && u == unit(s@, i as int) && u <= 0xFFFF, None => true },
{
    if s.len() < 4 || i > s.len() - 4 { return None; }
    let mut u: u32 = 0;
    let mut k: usize = 0;
    while k < 4
        invariant i + 4 <= s.len(), k <= 4, crate::http1_chunked::all_hex(s@.subrange(i as int, i + k)), u == crate::http1_chunked::hex_value(s@.subrange(i as int, i + k)), u < crate::http1_chunked::pow16(k as nat),
        decreases 4 - k,
    {
        let b = s[i + k];
        if !is_hex_exec(b) { return None; }
        proof {
            let sofar = s@.subrange(i as int, i + k);
            let next = s@.subrange(i as int, i + k + 1);
            assert(next.drop_last() =~= sofar);
            assert(next.last() == b);
            assert forall|x: int| 0 <= x < next.len() implies crate::http1_chunked::is_hex(#[trigger] next[x]) by {
                if x < k { assert(next[x] == sofar[x]); }
            }
            assert(crate::http1_chunked::pow16((k + 1) as nat) == crate::http1_chunked::pow16(k as nat) * 16);
            assert(crate::http1_chunked::pow16(k as nat) <= crate::http1_chunked::pow16(4)) by { lemma_pow16_mono(k as nat, 4); }
            assert(crate::http1_chunked::pow16(4) == 0x10000) by (compute_only);
        }
        u = u * 16 + hex_val_exec(b) as u32;
        k = k + 1;
    }
    proof { assert(crate::http1_chunked::pow16(4) == 0x10000) by (compute_only); }
    Some(u)
}

/// Append the UTF-8 encoding of `cp`.
fn push_utf8(text: &mut Vec<u8>, cp: u32)
    requires cp < 0x110000,
    ensures final(text)@ == old(text)@ + utf8(cp as nat),
{
    if cp < 0x80 {
        text.push(cp as u8);
    } else if cp < 0x800 {
        text.push((0xC0 + cp / 0x40) as u8);
        text.push((0x80 + cp % 0x40) as u8);
    } else if cp < 0x10000 {
        text.push((0xE0 + cp / 0x1000) as u8);
        text.push((0x80 + (cp / 0x40) % 0x40) as u8);
        text.push((0x80 + cp % 0x40) as u8);
    } else {
        text.push((0xF0 + cp / 0x40000) as u8);
        text.push((0x80 + (cp / 0x1000) % 0x40) as u8);
        text.push((0x80 + (cp / 0x40) % 0x40) as u8);
        text.push((0x80 + cp % 0x40) as u8);
    }
    proof { assert(final(text)@ =~= old(text)@ + utf8(cp as nat)); }
}

/// The quoted string starting at `i`: its decoded text and the position after the closing quote.
#[verifier::loop_isolation(false)]
fn string(s: &[u8], i: usize) -> (out: Option<(Vec<u8>, usize)>)
    requires i < s.len(), s@[i as int] == QUOTE,
    ensures match out { Some((text, j)) => i + 2 <= j <= s.len() && string_at(s@, i as int, j as int, text@), None => true },
{
    let mut text: Vec<u8> = Vec::new();
    let mut p = i + 1;
    proof { assert(s@.subrange(i + 1, p as int).len() == 0); }
    loop
        invariant i + 1 <= p <= s.len(), string_body(s@.subrange(i + 1, p as int), text@),
        decreases s.len() - p,
    {
        if p >= s.len() { return None; }
        let b = s[p];
        if b == QUOTE {
            proof {
                let j = p + 1;
                assert(i + 2 <= j);
                assert(j <= s@.len());
                assert(s@[i as int] == QUOTE);
                assert(s@[j - 1] == QUOTE);
                assert(s@.subrange(i + 1, j - 1) =~= s@.subrange(i + 1, p as int));
                assert(string_body(s@.subrange(i + 1, j - 1), text@));
                assert(string_at(s@, i as int, j, text@));
            }
            return Some((text, p + 1));
        }
        let ghost inside_before = s@.subrange(i + 1, p as int);
        let ghost text_before = text@;
        if b == BSLASH {
            if p + 1 >= s.len() { return None; }
            let e = s[p + 1];
            if e == LOWER_U {
                let u = match hex4_exec(s, p + 2) { Some(u) => u, None => return None };
                if 0xD800 <= u && u <= 0xDBFF {
                    if s.len() - p < 8 || s[p + 6] != BSLASH || s[p + 7] != LOWER_U { return None; }
                    let lo = match hex4_exec(s, p + 8) { Some(lo) => lo, None => return None };
                    if !(0xDC00 <= lo && lo <= 0xDFFF) { return None; }
                    let cp = 0x10000 + (u - 0xD800) * 0x400 + (lo - 0xDC00);
                    push_utf8(&mut text, cp);
                    proof {
                        let esc = s@.subrange(p as int, p + 12);
                        let dec = text@.subrange(text_before.len() as int, text@.len() as int);
                        assert(esc.subrange(2, 6) =~= s@.subrange(p + 2, p + 6));
                        assert(esc.subrange(8, 12) =~= s@.subrange(p + 8, p + 12));
                        assert(dec =~= utf8(cp as nat));
                        assert(text@.subrange(0, text_before.len() as int) =~= text_before);
                        assert(escape(esc, dec));
                        lemma_extend_escape(s@, i as int, p as int, 12, text_before, text@);
                    }
                    p = p + 12;
                } else if 0xDC00 <= u && u <= 0xDFFF {
                    return None;
                } else {
                    push_utf8(&mut text, u);
                    proof {
                        let esc = s@.subrange(p as int, p + 6);
                        let dec = text@.subrange(text_before.len() as int, text@.len() as int);
                        assert(esc.subrange(2, 6) =~= s@.subrange(p + 2, p + 6));
                        assert(dec =~= utf8(u as nat));
                        assert(text@.subrange(0, text_before.len() as int) =~= text_before);
                        assert(escape(esc, dec));
                        lemma_extend_escape(s@, i as int, p as int, 6, text_before, text@);
                    }
                    p = p + 6;
                }
            } else {
                let d: u8 = if e == QUOTE { QUOTE } else if e == BSLASH { BSLASH } else if e == SLASH { SLASH }
                    else if e == LOWER_B { 8 } else if e == LOWER_F { 12 } else if e == LOWER_N { LF }
                    else if e == LOWER_R { CR } else if e == LOWER_T { TAB } else { return None };
                text.push(d);
                proof {
                    let esc = s@.subrange(p as int, p + 2);
                    let dec = text@.subrange(text_before.len() as int, text@.len() as int);
                    assert(dec =~= seq![d]);
                    assert(text@.subrange(0, text_before.len() as int) =~= text_before);
                    assert(escape(esc, dec));
                    lemma_extend_escape(s@, i as int, p as int, 2, text_before, text@);
                }
                p = p + 2;
            }
        } else if b < 0x20 {
            return None;
        } else {
            text.push(b);
            proof {
                lemma_plain_body(b);
                lemma_body_append(inside_before, text_before, seq![b], seq![b]);
                assert(s@.subrange(i + 1, p + 1) =~= inside_before + seq![b]);
                assert(text@ =~= text_before + seq![b]);
            }
            p = p + 1;
        }
    }
}

/// `null`, `true`, or `false` at `i`.
fn literal(s: &[u8], i: usize) -> (out: Option<(Value, usize)>)
    requires i < s.len(),
    ensures match out { Some((v, j)) => i < j <= s.len() && encodes(s@, i as int, j as int, v), None => true },
{
    let b = s[i];
    if b == LOWER_N {
        if s.len() - i >= 4 && s[i + 1] == LOWER_U && s[i + 2] == 108 && s[i + 3] == 108 {
            proof { assert(s@.subrange(i as int, i + 4) =~= null_word()); }
            return Some((Value::Null, i + 4));
        }
    } else if b == LOWER_T {
        if s.len() - i >= 4 && s[i + 1] == LOWER_R && s[i + 2] == LOWER_U && s[i + 3] == LOWER_E {
            proof { assert(s@.subrange(i as int, i + 4) =~= true_word()); }
            return Some((Value::Bool(true), i + 4));
        }
    } else if b == LOWER_F {
        if s.len() - i >= 5 && s[i + 1] == 97 && s[i + 2] == 108 && s[i + 3] == 115 && s[i + 4] == LOWER_E {
            proof { assert(s@.subrange(i as int, i + 5) =~= false_word()); }
            return Some((Value::Bool(false), i + 5));
        }
    }
    None
}

/// The value at `i`, with no leading whitespace, and the position after it.
fn value(s: &[u8], i: usize, depth: u32) -> (out: Option<(Value, usize)>)
    requires i <= s.len(),
    ensures match out { Some((v, j)) => i < j <= s.len() && encodes(s@, i as int, j as int, v), None => true },
    decreases s.len() - i, 0int,
{
    if i >= s.len() { return None; }
    let b = s[i];
    if b == QUOTE {
        match string(s, i) { Some((text, j)) => Some((Value::Str(text), j)), None => None }
    } else if b == LBRACKET {
        if depth == 0 { return None; }
        array(s, i + 1, depth - 1)
    } else if b == LBRACE {
        if depth == 0 { return None; }
        object(s, i + 1, depth - 1)
    } else if b == MINUS || is_digit_exec(b) {
        match number(s, i) {
            Some(j) => {
                let lex = slice_to_vec(slice_subrange(s, i, j));
                Some((Value::Number(lex), j))
            }
            None => None,
        }
    } else {
        literal(s, i)
    }
}

/// The rest of an array whose `[` is at `i - 1`.
#[verifier::loop_isolation(false)]
fn array(s: &[u8], i: usize, depth: u32) -> (out: Option<(Value, usize)>)
    requires 1 <= i <= s.len(), s@[i - 1] == LBRACKET,
    ensures match out { Some((v, j)) => i <= j <= s.len() && encodes(s@, i - 1, j as int, v), None => true },
    decreases s.len() - i, 2int,
{
    let mut items: Vec<Value> = Vec::new();
    let a = skip_ws(s, i);
    if a < s.len() && s[a] == RBRACKET {
        proof { assert(elements(s@, i as int, a as int, items@)); }
        return Some((Value::Array(items), a + 1));
    }
    let (first, mut p) = match value(s, a, depth) { Some(r) => r, None => return None };
    items.push(first);
    proof {
        assert(ws(s@, i as int, a as int));
        assert(padded(s@, i as int, p as int, items@[0]));
        assert(items_ok(s@, i as int, p as int, items@));
    }
    loop
        invariant 1 <= i <= p <= s.len(), items@.len() >= 1, items_ok(s@, i as int, p as int, items@), s@[i - 1] == LBRACKET,
        decreases s.len() - p,
    {
        let c = skip_ws(s, p);
        if c >= s.len() { return None; }
        if s[c] == RBRACKET {
            proof { assert(elements(s@, i as int, c as int, items@)); }
            return Some((Value::Array(items), c + 1));
        }
        if s[c] != COMMA { return None; }
        let d = skip_ws(s, c + 1);
        let (next, q) = match value(s, d, depth) { Some(r) => r, None => return None };
        let ghost before = items@;
        items.push(next);
        proof {
            assert(items@.drop_last() =~= before);
            assert(items@.last() == next);
            assert(items_ok(s@, i as int, p as int, items@.drop_last()));
            assert(ws(s@, c + 1, d as int));
            assert(padded(s@, c + 1, q as int, items@.last()));
            assert(ws(s@, p as int, c as int));
            assert(items_ok(s@, i as int, q as int, items@));
        }
        p = q;
    }
}

/// A member: whitespace, a quoted key, whitespace, a colon, whitespace, a value.
fn member(s: &[u8], i: usize, depth: u32) -> (out: Option<(Member, usize)>)
    requires i <= s.len(),
    ensures match out { Some((m, j)) => i < j <= s.len() && member_ok(s@, i as int, j as int, m), None => true },
    decreases s.len() - i, 1int,
{
    let a = skip_ws(s, i);
    if a >= s.len() || s[a] != QUOTE { return None; }
    let (key, b) = match string(s, a) { Some(r) => r, None => return None };
    let c = skip_ws(s, b);
    if c >= s.len() || s[c] != COLON { return None; }
    let d = skip_ws(s, c + 1);
    let (v, j) = match value(s, d, depth) { Some(r) => r, None => return None };
    let m = Member { key, value: v };
    proof {
        assert(ws(s@, c + 1, d as int));
        assert(padded(s@, c + 1, j as int, m.value));
        assert(ws(s@, b as int, c as int));
        assert(colon_then(s@, b as int, j as int, m.value));
        assert(string_at(s@, a as int, b as int, m.key@));
        assert(key_then(s@, a as int, j as int, m));
        assert(ws(s@, i as int, a as int));
        assert(member_ok(s@, i as int, j as int, m));
    }
    Some((m, j))
}

/// The rest of an object whose `{` is at `i - 1`.
#[verifier::loop_isolation(false)]
fn object(s: &[u8], i: usize, depth: u32) -> (out: Option<(Value, usize)>)
    requires 1 <= i <= s.len(), s@[i - 1] == LBRACE,
    ensures match out { Some((v, j)) => i <= j <= s.len() && encodes(s@, i - 1, j as int, v), None => true },
    decreases s.len() - i, 2int,
{
    let mut ms: Vec<Member> = Vec::new();
    let a = skip_ws(s, i);
    if a < s.len() && s[a] == RBRACE {
        proof { assert(members(s@, i as int, a as int, ms@)); }
        return Some((Value::Object(ms), a + 1));
    }
    let (first, mut p) = match member(s, i, depth) { Some(r) => r, None => return None };
    ms.push(first);
    proof { assert(members_ok(s@, i as int, p as int, ms@)); }
    loop
        invariant 1 <= i <= p <= s.len(), ms@.len() >= 1, members_ok(s@, i as int, p as int, ms@), s@[i - 1] == LBRACE,
        decreases s.len() - p,
    {
        let c = skip_ws(s, p);
        if c >= s.len() { return None; }
        if s[c] == RBRACE {
            proof { assert(members(s@, i as int, c as int, ms@)); }
            return Some((Value::Object(ms), c + 1));
        }
        if s[c] != COMMA { return None; }
        let (next, q) = match member(s, c + 1, depth) { Some(r) => r, None => return None };
        let ghost before = ms@;
        ms.push(next);
        proof {
            assert(ms@.drop_last() =~= before);
            assert(ms@.last() == next);
            assert(members_ok(s@, i as int, p as int, ms@.drop_last()));
            assert(ws(s@, p as int, c as int));
            assert(member_ok(s@, c + 1, q as int, ms@.last()));
            assert(members_ok(s@, i as int, q as int, ms@));
        }
        p = q;
    }
}

/// Read one JSON document. `Some(v)` only when `bytes` is `v` with
/// whitespace around it and nothing else; nesting is limited to `MAX_DEPTH`.
pub fn parse(bytes: &[u8]) -> (out: Option<Value>)
    ensures match out { Some(v) => document(bytes@, v), None => true },
{
    let i = skip_ws(bytes, 0);
    let (v, j) = match value(bytes, i, MAX_DEPTH) { Some(r) => r, None => return None };
    let k = skip_ws(bytes, j);
    if k != bytes.len() { return None; }
    Some(v)
}

// ---- reading a value --------------------------------------------------------------------

/// The members of an object, in order; empty for anything else.
pub open spec fn members_of(v: Value) -> Seq<Member> { match v { Value::Object(ms) => ms@, _ => Seq::empty() } }

impl Value {
    /// The value under `key` in an object: the first member with that key.
    #[verifier::loop_isolation(false)]
    pub fn get(&self, key: &[u8]) -> (out: Option<&Value>)
        ensures match out {
            Some(v) => exists|k: int| 0 <= k < members_of(*self).len() && members_of(*self)[k].key@ == key@ && members_of(*self)[k].value == *v,
            None => forall|k: int| 0 <= k < members_of(*self).len() ==> members_of(*self)[k].key@ != key@,
        },
    {
        match self {
            Value::Object(ms) => {
                let mut k: usize = 0;
                while k < ms.len()
                    invariant k <= ms.len(), forall|j: int| 0 <= j < k ==> ms@[j].key@ != key@,
                    decreases ms.len() - k,
                {
                    let slice = ms.as_slice();
                    let m = slice_index_get(slice, k);
                    if bytes_eq(m.key.as_slice(), key) {
                        proof {
                            assert(*self == Value::Object(*ms));
                            assert(members_of(*self) == ms@);
                            assert(slice@ == ms@);
                            assert(*m == ms@[k as int]);
                            assert(members_of(*self)[k as int] == *m);
                        }
                        return Some(&m.value);
                    }
                    k = k + 1;
                }
                proof { assert(members_of(*self) =~= ms@); }
                None
            }
            _ => None,
        }
    }
    pub fn as_str(&self) -> (out: Option<&Vec<u8>>)
        ensures match out { Some(text) => *self == Value::Str(*text), None => !(self is Str) },
    {
        match self { Value::Str(text) => Some(text), _ => None }
    }
    pub fn as_array(&self) -> (out: Option<&Vec<Value>>)
        ensures match out { Some(items) => *self == Value::Array(*items), None => !(self is Array) },
    {
        match self { Value::Array(items) => Some(items), _ => None }
    }
    pub fn as_object(&self) -> (out: Option<&Vec<Member>>)
        ensures match out { Some(ms) => *self == Value::Object(*ms), None => !(self is Object) },
    {
        match self { Value::Object(ms) => Some(ms), _ => None }
    }
    pub fn as_bool(&self) -> (out: Option<bool>)
        ensures match out { Some(b) => *self == Value::Bool(b), None => !(self is Bool) },
    {
        match self { Value::Bool(b) => Some(*b), _ => None }
    }
    pub fn is_null(&self) -> (out: bool) ensures out == (*self == Value::Null) { match self { Value::Null => true, _ => false } }
    /// A number whose lexeme is the canonical decimal of a `u64`.
    pub fn as_u64(&self) -> (out: Option<u64>)
        ensures match out { Some(n) => self is Number && self->Number_0@ == crate::inbound::decimal(n as nat), None => true },
    {
        match self {
            Value::Number(lex) => {
                let parsed = crate::http1_framing::parse_decimal(lex.as_slice());
                proof { if parsed.is_some() { assert(lex@ == crate::inbound::decimal(parsed.unwrap() as nat)); } }
                parsed
            }
            _ => None,
        }
    }
}

fn bytes_eq(a: &[u8], b: &[u8]) -> (out: bool)
    ensures out == (a@ == b@),
{
    if a.len() != b.len() { return false; }
    let mut k: usize = 0;
    while k < a.len()
        invariant k <= a.len(), a.len() == b.len(), forall|j: int| 0 <= j < k ==> a@[j] == b@[j],
        decreases a.len() - k,
    {
        if a[k] != b[k] { return false; }
        k = k + 1;
    }
    proof { assert(a@ =~= b@); }
    true
}
} // verus!
