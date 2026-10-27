//! Verified JSON reader and writer. `parse` turns a byte string into a
//! `Value` tree, or refuses it; `write` turns a `Value` tree into one compact
//! document. The specification is the RFC 8259 grammar written out as
//! predicates over byte positions (`document`, `encodes`, `string_body`,
//! `number_ok`). The reader is sound (a value it returns is encoded by
//! exactly the bytes it was given, whitespace aside) and complete (every
//! document of the grammar within the depth limit is accepted, with the
//! same value). Nothing is guessed at: a string with a bad escape, a lone
//! surrogate, or a control byte, a number with a leading zero or a dangling
//! point or exponent, a trailing comma, trailing bytes, or nesting past
//! `MAX_DEPTH` is refused. Numbers keep their lexeme; `as_u64` reads the
//! canonical decimals the gateway uses and `Value::from_u64` makes them.
//! Strings decode to UTF-8 bytes: `\u` escapes become the code point's
//! UTF-8, surrogate pairs become one code point. Raw bytes in strings are
//! passed through as written and not checked for UTF-8 validity. Duplicate
//! keys are kept in order; `get` finds the first. The writer emits exactly
//! its value (`encodes`) whenever every number in it is a number of the
//! grammar, and `round_trip` composes the two.
//!
//! This module depends only on `vstd` and the hex and decimal helpers in
//! this crate, so it can stand on its own; see `docs/json.md`.
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

// ---- completeness: what the grammar is, seen from the reader ------------------------

/// What may follow a value: the end, whitespace, or a closing delimiter or
/// comma. A value in a document, an array, or an object is always followed
/// by one of these, and none of them continues a number.
pub open spec fn boundary(s: Seq<u8>, j: int) -> bool {
    j == s.len() || is_ws(s[j]) || s[j] == COMMA || s[j] == RBRACKET || s[j] == RBRACE
}
/// Nesting depth: arrays and objects count, their contents add.
pub open spec fn depth(v: Value) -> nat
    decreases v, 0int,
{
    match v { Value::Array(items) => 1 + depths(items@), Value::Object(ms) => 1 + member_depths(ms@), _ => 0 }
}
pub open spec fn depths(items: Seq<Value>) -> nat
    decreases items, 1int,
{
    if items.len() == 0 { 0 } else { let d = depth(items[0]); let r = depths(items.drop_first()); if d >= r { d } else { r } }
}
pub open spec fn member_depths(ms: Seq<Member>) -> nat
    decreases ms, 1int,
{
    if ms.len() == 0 { 0 } else { let d = depth(ms[0].value); let r = member_depths(ms.drop_first()); if d >= r { d } else { r } }
}
/// Structural equality of two values: the same tree with the same bytes.
pub open spec fn same(a: Value, b: Value) -> bool
    decreases a, 0int,
{
    match a {
        Value::Null => b is Null,
        Value::Bool(x) => b == Value::Bool(x),
        Value::Number(x) => b is Number && b->Number_0@ == x@,
        Value::Str(x) => b is Str && b->Str_0@ == x@,
        Value::Array(xs) => b is Array && same_items(xs@, b->Array_0@),
        Value::Object(xs) => b is Object && same_members(xs@, b->Object_0@),
    }
}
pub open spec fn same_items(xs: Seq<Value>, ys: Seq<Value>) -> bool
    decreases xs, 1int,
{
    xs.len() == ys.len() && (xs.len() == 0 || (same(xs[0], ys[0]) && same_items(xs.drop_first(), ys.drop_first())))
}
pub open spec fn same_members(xs: Seq<Member>, ys: Seq<Member>) -> bool
    decreases xs, 1int,
{
    xs.len() == ys.len() && (xs.len() == 0 || (xs[0].key@ == ys[0].key@ && same(xs[0].value, ys[0].value) && same_members(xs.drop_first(), ys.drop_first())))
}

/// A run of whitespace ends where the first non-whitespace byte is.
proof fn lemma_ws_unique(s: Seq<u8>, i: int, x: int, y: int)
    requires ws(s, i, x), x == s.len() || !is_ws(s[x]), ws(s, i, y), y == s.len() || !is_ws(s[y]),
    ensures x == y,
{
    if x < y { assert(is_ws(s[x])); }
    if y < x { assert(is_ws(s[y])); }
}
/// A run of digits ends where the first non-digit byte is.
proof fn lemma_digits_unique(s: Seq<u8>, i: int, x: int, y: int)
    requires 0 <= i <= x <= s.len(), all_digits(s.subrange(i, x)), x == s.len() || !is_digit(s[x]),
        i <= y <= s.len(), all_digits(s.subrange(i, y)), y == s.len() || !is_digit(s[y]),
    ensures x == y,
{
    if x < y { assert(s.subrange(i, y)[x - i] == s[x]); }
    if y < x { assert(s.subrange(i, x)[y - i] == s[y]); }
}

/// Where a number lexeme `s[i..j)` followed by a boundary has its parts: the
/// digits start at `m`, the integer part ends at `a`, the fraction at `b`,
/// the exponent at `j`, and every run of digits is maximal.
pub open spec fn shape(s: Seq<u8>, i: int, m: int, a: int, b: int, j: int) -> bool {
    0 <= i && i <= m <= i + 1 && m < a <= b <= j <= s.len()
    && (m == i + 1 <==> s[i] == MINUS)
    && all_digits(s.subrange(m, a)) && (s[m] == ZERO ==> a == m + 1) && (a < s.len() ==> !is_digit(s[a]))
    && (a == b ==> !(a < s.len() && s[a] == DOT))
    && (a < b ==> b >= a + 2 && s[a] == DOT && all_digits(s.subrange(a + 1, b)) && (b < s.len() ==> !is_digit(s[b])))
    && (b == j ==> !(b < s.len() && (s[b] == LOWER_E || s[b] == UPPER_E)))
    && (b < j ==> j >= b + 2 && (s[b] == LOWER_E || s[b] == UPPER_E) && exp_start(s, b) < j
        && all_digits(s.subrange(exp_start(s, b), j)) && (j < s.len() ==> !is_digit(s[j])))
}
/// Where the exponent's digits start: after the `e` and an optional sign.
pub open spec fn exp_start(s: Seq<u8>, b: int) -> int { if s[b + 1] == PLUS || s[b + 1] == MINUS { b + 2 } else { b + 1 } }

/// A number lexeme followed by a boundary has a shape.
proof fn lemma_number_shape(s: Seq<u8>, i: int, j: int)
    requires 0 <= i < j <= s.len(), number_ok(s.subrange(i, j)), boundary(s, j),
    ensures exists|m: int, a: int, b: int| #[trigger] shape(s, i, m, a, b, j),
{
    let lex = s.subrange(i, j);
    let (a0, b0) = choose|a0: int, b0: int| 0 <= a0 <= b0 <= lex.len() && int_ok(#[trigger] lex.subrange(0, a0))
        && frac_ok(#[trigger] lex.subrange(a0, b0)) && exp_ok(lex.subrange(b0, lex.len() as int));
    let a = i + a0;
    let b = i + b0;
    let ip = s.subrange(i, a);
    let fp = s.subrange(a, b);
    let ep = s.subrange(b, j);
    assert(lex.subrange(0, a0) =~= ip);
    assert(lex.subrange(a0, b0) =~= fp);
    assert(lex.subrange(b0, lex.len() as int) =~= ep);
    assert(ip.len() >= 1);
    let m = if s[i] == MINUS { i + 1 } else { i };
    if s[i] == MINUS { assert(ip.drop_first() =~= s.subrange(m, a)); } else { assert(ip =~= s.subrange(m, a)); }
    assert(all_digits(s.subrange(m, a)));
    assert(s.subrange(m, a)[0] == s[m]);
    if a < b {
        assert(fp.drop_first() =~= s.subrange(a + 1, b));
        assert(fp[0] == s[a]);
        assert(s.subrange(a + 1, b)[0] == s[a + 1]);
    }
    if b < j {
        assert(ep[0] == s[b]);
        assert(ep[1] == s[b + 1]);
        if s[b + 1] == PLUS || s[b + 1] == MINUS {
            assert(ep.subrange(2, ep.len() as int) =~= s.subrange(b + 2, j));
        } else {
            assert(ep.drop_first() =~= s.subrange(b + 1, j));
        }
        assert(s.subrange(exp_start(s, b), j)[0] == s[exp_start(s, b)]);
    }
    assert(shape(s, i, m, a, b, j));
}

/// `encodes`, as a trigger: the same relation under a name that is not recursive.
pub open spec fn value_at(s: Seq<u8>, i: int, j: int, v: Value) -> bool { encodes(s, i, j, v) }
pub open spec fn member_at(s: Seq<u8>, i: int, j: int, m: Member) -> bool { member_ok(s, i, j, m) }
/// An array whose `[` is at `i - 1` ends at `j` with `items`.
pub open spec fn array_at(s: Seq<u8>, i: int, j: int, items: Seq<Value>) -> bool {
    1 <= i && i <= j - 1 && j <= s.len() && s[j - 1] == RBRACKET && elements(s, i, j - 1, items)
}
/// An object whose `{` is at `i - 1` ends at `j` with `ms`.
pub open spec fn object_at(s: Seq<u8>, i: int, j: int, ms: Seq<Member>) -> bool {
    1 <= i && i <= j - 1 && j <= s.len() && s[j - 1] == RBRACE && members(s, i, j - 1, ms)
}
/// After an item, at `a` with whitespace skipped: the closing bracket at
/// `j - 1`, or a comma and then `rest`, item by item, from the left.
pub open spec fn stop(s: Seq<u8>, a: int, j: int, rest: Seq<Value>) -> bool
    decreases rest, 6int,
{
    if rest.len() == 0 { a == j - 1 && 0 <= a < s.len() && s[a] == RBRACKET }
    else {
        0 <= a < s.len() && s[a] == COMMA
            && exists|c: int, a2: int| #[trigger] ws(s, c, a2) && padded(s, a + 1, c, rest[0]) && stop(s, a2, j, rest.drop_first())
    }
}
/// The inside of an array from the left: empty, or the first item then `stop`.
pub open spec fn head_tail(s: Seq<u8>, i: int, j: int, all: Seq<Value>) -> bool
    decreases all, 7int,
{
    if all.len() == 0 { exists|a: int| #[trigger] ws(s, i, a) && a == j - 1 && a < s.len() && s[a] == RBRACKET }
    else { exists|c: int, a2: int| #[trigger] ws(s, c, a2) && padded(s, i, c, all[0]) && stop(s, a2, j, all.drop_first()) }
}
pub open spec fn mstop(s: Seq<u8>, a: int, j: int, rest: Seq<Member>) -> bool
    decreases rest, 6int,
{
    if rest.len() == 0 { a == j - 1 && 0 <= a < s.len() && s[a] == RBRACE }
    else {
        0 <= a < s.len() && s[a] == COMMA
            && exists|e: int, a2: int| #[trigger] ws(s, e, a2) && member_ok(s, a + 1, e, rest[0]) && mstop(s, a2, j, rest.drop_first())
    }
}
pub open spec fn mhead_tail(s: Seq<u8>, i: int, j: int, all: Seq<Member>) -> bool
    decreases all, 7int,
{
    if all.len() == 0 { exists|a: int| #[trigger] ws(s, i, a) && a == j - 1 && a < s.len() && s[a] == RBRACE }
    else { exists|e: int, a2: int| #[trigger] ws(s, e, a2) && member_ok(s, i, e, all[0]) && mstop(s, a2, j, all.drop_first()) }
}

/// Items read from the right, followed by what `stop` says, are the same
/// items read from the left.
proof fn lemma_items_to_tail(s: Seq<u8>, i: int, b: int, items: Seq<Value>, a2: int, j: int, rest: Seq<Value>)
    requires items.len() >= 1, items_ok(s, i, b, items), ws(s, b, a2), stop(s, a2, j, rest),
    ensures head_tail(s, i, j, items + rest),
    decreases items.len(),
{
    let all = items + rest;
    assert(all[0] == items[0]);
    if items.len() == 1 {
        assert(all.drop_first() =~= rest);
        assert(head_tail(s, i, j, all));
    } else {
        let (c0, a) = choose|c0: int, a: int| items_ok(s, i, c0, items.drop_last()) && #[trigger] ws(s, c0, a) && a < s.len() && s[a] == COMMA
            && padded(s, a + 1, b, items.last());
        let more = seq![items.last()] + rest;
        assert(more[0] == items.last());
        assert(more.drop_first() =~= rest);
        assert(stop(s, a, j, more));
        lemma_items_to_tail(s, i, c0, items.drop_last(), a, j, more);
        assert(items.drop_last() + more =~= all);
    }
}
proof fn lemma_members_to_tail(s: Seq<u8>, i: int, b: int, ms: Seq<Member>, a2: int, j: int, rest: Seq<Member>)
    requires ms.len() >= 1, members_ok(s, i, b, ms), ws(s, b, a2), mstop(s, a2, j, rest),
    ensures mhead_tail(s, i, j, ms + rest),
    decreases ms.len(),
{
    let all = ms + rest;
    assert(all[0] == ms[0]);
    if ms.len() == 1 {
        assert(all.drop_first() =~= rest);
        assert(mhead_tail(s, i, j, all));
    } else {
        let (c0, a) = choose|c0: int, a: int| members_ok(s, i, c0, ms.drop_last()) && #[trigger] ws(s, c0, a) && a < s.len() && s[a] == COMMA
            && member_ok(s, a + 1, b, ms.last());
        let more = seq![ms.last()] + rest;
        assert(more[0] == ms.last());
        assert(more.drop_first() =~= rest);
        assert(mstop(s, a, j, more));
        lemma_members_to_tail(s, i, c0, ms.drop_last(), a, j, more);
        assert(ms.drop_last() + more =~= all);
    }
}
proof fn lemma_array_head_tail(s: Seq<u8>, i: int, j: int, items: Seq<Value>)
    requires array_at(s, i, j, items),
    ensures head_tail(s, i, j, items),
{
    if items.len() > 0 {
        let b = choose|b: int| items_ok(s, i, b, items) && #[trigger] ws(s, b, j - 1);
        assert(stop(s, j - 1, j, Seq::<Value>::empty()));
        lemma_items_to_tail(s, i, b, items, j - 1, j, Seq::<Value>::empty());
        assert(items + Seq::<Value>::empty() =~= items);
    }
}
proof fn lemma_object_head_tail(s: Seq<u8>, i: int, j: int, ms: Seq<Member>)
    requires object_at(s, i, j, ms),
    ensures mhead_tail(s, i, j, ms),
{
    if ms.len() > 0 {
        let b = choose|b: int| members_ok(s, i, b, ms) && #[trigger] ws(s, b, j - 1);
        assert(mstop(s, j - 1, j, Seq::<Member>::empty()));
        lemma_members_to_tail(s, i, b, ms, j - 1, j, Seq::<Member>::empty());
        assert(ms + Seq::<Member>::empty() =~= ms);
    }
}

/// A value starts with a byte that says what it is, and never with
/// whitespace or a delimiter.
pub proof fn lemma_value_start(s: Seq<u8>, i: int, j: int, v: Value)
    requires encodes(s, i, j, v),
    ensures i < j, !is_ws(s[i]), s[i] != COMMA, s[i] != RBRACKET, s[i] != RBRACE,
        (s[i] == QUOTE <==> v is Str), (s[i] == LBRACKET <==> v is Array), (s[i] == LBRACE <==> v is Object),
        ((s[i] == MINUS || is_digit(s[i])) <==> v is Number),
        (s[i] == LOWER_N <==> v is Null), (s[i] == LOWER_T <==> v == Value::Bool(true)), (s[i] == LOWER_F <==> v == Value::Bool(false)),
{
    let w = s.subrange(i, j);
    match v {
        Value::Null => { assert(w == null_word()); assert(w[0] == s[i]); }
        Value::Bool(b) => {
            assert(w == (if b { true_word() } else { false_word() }));
            if b { assert(w == true_word()); assert(w.len() == 4); } else { assert(w == false_word()); assert(w.len() == 5); }
            assert(w[0] == s[i]);
        }
        Value::Number(lex) => {
            let (a0, b0) = choose|a0: int, b0: int| 0 <= a0 <= b0 <= lex@.len() && int_ok(#[trigger] lex@.subrange(0, a0))
                && frac_ok(#[trigger] lex@.subrange(a0, b0)) && exp_ok(lex@.subrange(b0, lex@.len() as int));
            let ip = lex@.subrange(0, a0);
            assert(ip.len() >= 1);
            assert(ip[0] == lex@[0]);
            assert(lex@[0] == s[i]);
            if ip[0] != MINUS { assert(is_digit(ip[0])); }
        }
        Value::Str(_) => {}
        Value::Array(_) => {}
        Value::Object(_) => {}
    }
}
/// What comes after an item: the next byte is a boundary.
proof fn lemma_after_item(s: Seq<u8>, c: int, a2: int)
    requires ws(s, c, a2), a2 < s.len(), s[a2] == COMMA || s[a2] == RBRACKET || s[a2] == RBRACE,
    ensures boundary(s, c),
{
    if c < a2 { assert(is_ws(s[c])); }
}
proof fn lemma_depths_bound(items: Seq<Value>, k: int)
    requires 0 <= k < items.len(),
    ensures depth(items[k]) <= depths(items),
    decreases k,
{
    if k > 0 { lemma_depths_bound(items.drop_first(), k - 1); assert(items.drop_first()[k - 1] == items[k]); }
}
proof fn lemma_member_depths_bound(ms: Seq<Member>, k: int)
    requires 0 <= k < ms.len(),
    ensures depth(ms[k].value) <= member_depths(ms),
    decreases k,
{
    if k > 0 { lemma_member_depths_bound(ms.drop_first(), k - 1); assert(ms.drop_first()[k - 1] == ms[k]); }
}
proof fn lemma_same_push(xs: Seq<Value>, ys: Seq<Value>, x: Value, y: Value)
    requires same_items(xs, ys), same(x, y),
    ensures same_items(xs.push(x), ys.push(y)),
    decreases xs.len(),
{
    if xs.len() == 0 {
        assert(xs.push(x)[0] == x);
        assert(ys.push(y)[0] == y);
        assert(xs.push(x).drop_first().len() == 0);
        assert(ys.push(y).drop_first().len() == 0);
        assert(same_items(xs.push(x).drop_first(), ys.push(y).drop_first()));
    } else {
        lemma_same_push(xs.drop_first(), ys.drop_first(), x, y);
        assert(xs.push(x)[0] == xs[0]);
        assert(ys.push(y)[0] == ys[0]);
        assert(xs.push(x).drop_first() =~= xs.drop_first().push(x));
        assert(ys.push(y).drop_first() =~= ys.drop_first().push(y));
    }
}
proof fn lemma_same_members_push(xs: Seq<Member>, ys: Seq<Member>, x: Member, y: Member)
    requires same_members(xs, ys), x.key@ == y.key@, same(x.value, y.value),
    ensures same_members(xs.push(x), ys.push(y)),
    decreases xs.len(),
{
    if xs.len() == 0 {
        assert(xs.push(x)[0] == x);
        assert(ys.push(y)[0] == y);
        assert(xs.push(x).drop_first().len() == 0);
        assert(ys.push(y).drop_first().len() == 0);
        assert(same_members(xs.push(x).drop_first(), ys.push(y).drop_first()));
    } else {
        lemma_same_members_push(xs.drop_first(), ys.drop_first(), x, y);
        assert(xs.push(x)[0] == xs[0]);
        assert(ys.push(y)[0] == ys[0]);
        assert(xs.push(x).drop_first() =~= xs.drop_first().push(x));
        assert(ys.push(y).drop_first() =~= ys.drop_first().push(y));
    }
}

/// The first item of an array, seen from the reader standing at `a`, the
/// first non-whitespace position after the bracket.
proof fn lemma_array_first(s: Seq<u8>, i: int, j: int, items: Seq<Value>, a: int)
    requires array_at(s, i, j, items), ws(s, i, a), a == s.len() || !is_ws(s[a]),
    ensures items.len() == 0 ==> a == j - 1 && a < s.len() && s[a] == RBRACKET,
        items.len() >= 1 ==> a < s.len() && s[a] != RBRACKET && depth(items[0]) <= depths(items)
            && exists|c: int, a2: int| #[trigger] ws(s, c, a2) && value_at(s, a, c, items[0]) && boundary(s, c) && stop(s, a2, j, items.drop_first()),
{
    lemma_array_head_tail(s, i, j, items);
    if items.len() == 0 {
        let a0 = choose|a0: int| #[trigger] ws(s, i, a0) && a0 == j - 1 && a0 < s.len() && s[a0] == RBRACKET;
        lemma_ws_unique(s, i, a0, a);
    } else {
        let (c, a2) = choose|c: int, a2: int| #[trigger] ws(s, c, a2) && padded(s, i, c, items[0]) && stop(s, a2, j, items.drop_first());
        let d = choose|d: int| #[trigger] ws(s, i, d) && encodes(s, d, c, items[0]);
        lemma_value_start(s, d, c, items[0]);
        lemma_ws_unique(s, i, d, a);
        if items.drop_first().len() == 0 { } else { }
        lemma_after_item(s, c, a2);
        lemma_depths_bound(items, 0);
    }
}
/// The next step of an array, seen from the reader standing at `c`, the
/// first non-whitespace position after the last item: the bracket, or a
/// comma and the next item.
proof fn lemma_array_next(s: Seq<u8>, p: int, c: int, q: int, j: int, items: Seq<Value>, k: int)
    requires 0 <= k <= items.len(), exists|a2: int| #[trigger] ws(s, p, a2) && stop(s, a2, j, items.skip(k)),
        ws(s, p, c), c == s.len() || !is_ws(s[c]), q == c + 1,
    ensures c < s.len(), s[c] == RBRACKET || s[c] == COMMA,
        s[c] == RBRACKET ==> items.len() == k && j == c + 1,
        s[c] == COMMA ==> k < items.len() && depth(items[k]) <= depths(items)
            && exists|d: int, c2: int, a3: int| #[trigger] ws(s, q, d) && #[trigger] ws(s, c2, a3) && value_at(s, d, c2, items[k])
                && boundary(s, c2) && stop(s, a3, j, items.skip(k + 1)),
{
    let a2 = choose|a2: int| #[trigger] ws(s, p, a2) && stop(s, a2, j, items.skip(k));
    lemma_ws_unique(s, p, a2, c);
    if items.skip(k).len() == 0 {
    } else {
        let rest = items.skip(k);
        assert(rest[0] == items[k]);
        assert(rest.drop_first() =~= items.skip(k + 1));
        let (c2, a3) = choose|c2: int, a3: int| #[trigger] ws(s, c2, a3) && padded(s, c + 1, c2, rest[0]) && stop(s, a3, j, rest.drop_first());
        let d = choose|d: int| #[trigger] ws(s, c + 1, d) && encodes(s, d, c2, rest[0]);
        lemma_after_item(s, c2, a3);
        lemma_depths_bound(items, k);
    }
}
proof fn lemma_object_first(s: Seq<u8>, i: int, j: int, ms: Seq<Member>, a: int)
    requires object_at(s, i, j, ms), ws(s, i, a), a == s.len() || !is_ws(s[a]),
    ensures ms.len() == 0 ==> a == j - 1 && a < s.len() && s[a] == RBRACE,
        ms.len() >= 1 ==> a < s.len() && s[a] != RBRACE && depth(ms[0].value) <= member_depths(ms)
            && exists|e: int, a2: int| #[trigger] ws(s, e, a2) && member_at(s, i, e, ms[0]) && boundary(s, e) && mstop(s, a2, j, ms.drop_first()),
{
    lemma_object_head_tail(s, i, j, ms);
    if ms.len() == 0 {
        let a0 = choose|a0: int| #[trigger] ws(s, i, a0) && a0 == j - 1 && a0 < s.len() && s[a0] == RBRACE;
        lemma_ws_unique(s, i, a0, a);
    } else {
        let (e, a2) = choose|e: int, a2: int| #[trigger] ws(s, e, a2) && member_ok(s, i, e, ms[0]) && mstop(s, a2, j, ms.drop_first());
        let a0 = choose|a0: int| #[trigger] ws(s, i, a0) && key_then(s, a0, e, ms[0]);
        lemma_ws_unique(s, i, a0, a);
        lemma_after_item(s, e, a2);
        lemma_member_depths_bound(ms, 0);
    }
}
proof fn lemma_object_next(s: Seq<u8>, p: int, c: int, q: int, j: int, ms: Seq<Member>, k: int)
    requires 0 <= k <= ms.len(), exists|a2: int| #[trigger] ws(s, p, a2) && mstop(s, a2, j, ms.skip(k)),
        ws(s, p, c), c == s.len() || !is_ws(s[c]), q == c + 1,
    ensures c < s.len(), s[c] == RBRACE || s[c] == COMMA,
        s[c] == RBRACE ==> ms.len() == k && j == c + 1,
        s[c] == COMMA ==> k < ms.len() && depth(ms[k].value) <= member_depths(ms)
            && exists|e: int, a3: int| #[trigger] ws(s, e, a3) && member_at(s, q, e, ms[k]) && boundary(s, e) && mstop(s, a3, j, ms.skip(k + 1)),
{
    let a2 = choose|a2: int| #[trigger] ws(s, p, a2) && mstop(s, a2, j, ms.skip(k));
    lemma_ws_unique(s, p, a2, c);
    if ms.skip(k).len() == 0 {
    } else {
        let rest = ms.skip(k);
        assert(rest[0] == ms[k]);
        assert(rest.drop_first() =~= ms.skip(k + 1));
        let (e, a3) = choose|e: int, a3: int| #[trigger] ws(s, e, a3) && member_ok(s, c + 1, e, rest[0]) && mstop(s, a3, j, rest.drop_first());
        lemma_after_item(s, e, a3);
        lemma_member_depths_bound(ms, k);
    }
}
/// A member, seen from the reader: the key's quote is the first
/// non-whitespace byte, the colon the first after the key, the value the
/// first after the colon.
proof fn lemma_member_parts(s: Seq<u8>, i: int, j: int, m: Member, a: int)
    requires member_at(s, i, j, m), ws(s, i, a), a == s.len() || !is_ws(s[a]),
    ensures a < s.len(), s[a] == QUOTE,
        exists|b: int, c: int, d: int| #[trigger] string_at(s, a, b, m.key@) && #[trigger] ws(s, b, c) && c < s.len() && s[c] == COLON
            && #[trigger] ws(s, c + 1, d) && value_at(s, d, j, m.value),
{
    let a0 = choose|a0: int| #[trigger] ws(s, i, a0) && key_then(s, a0, j, m);
    let b = choose|b: int| #[trigger] string_at(s, a0, b, m.key@) && colon_then(s, b, j, m.value);
    lemma_ws_unique(s, i, a0, a);
    let c = choose|c: int| #[trigger] ws(s, b, c) && c < s.len() && s[c] == COLON && padded(s, c + 1, j, m.value);
    let d = choose|d: int| #[trigger] ws(s, c + 1, d) && encodes(s, d, j, m.value);
    assert(string_at(s, a, b, m.key@) && ws(s, b, c) && ws(s, c + 1, d) && value_at(s, d, j, m.value));
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
        forall|x: int| #[trigger] ws(s@, i as int, x) && (x == s@.len() || !is_ws(s@[x])) ==> x == j,
{
    let mut j = i;
    while j < s.len() && is_ws_exec(s[j])
        invariant i <= j <= s.len(), ws(s@, i as int, j as int),
        decreases s.len() - j,
    {
        j = j + 1;
    }
    proof {
        assert forall|x: int| #[trigger] ws(s@, i as int, x) && (x == s@.len() || !is_ws(s@[x])) implies x == j by {
            lemma_ws_unique(s@, i as int, x, j as int);
        }
    }
    j
}
/// The first non-digit position at or after `i`.
fn skip_digits(s: &[u8], i: usize) -> (j: usize)
    requires i <= s.len(),
    ensures i <= j <= s.len(), all_digits(s@.subrange(i as int, j as int)), j < s.len() ==> !is_digit(s@[j as int]),
        forall|x: int| i <= x <= s@.len() && all_digits(#[trigger] s@.subrange(i as int, x)) && (x == s@.len() || !is_digit(s@[x])) ==> x == j,
{
    let mut j = i;
    while j < s.len() && is_digit_exec(s[j])
        invariant i <= j <= s.len(), all_digits(s@.subrange(i as int, j as int)),
        decreases s.len() - j,
    {
        proof { assert(s@.subrange(i as int, j + 1) =~= s@.subrange(i as int, j as int).push(s@[j as int])); }
        j = j + 1;
    }
    proof {
        assert forall|x: int| i <= x <= s@.len() && all_digits(#[trigger] s@.subrange(i as int, x)) && (x == s@.len() || !is_digit(s@[x])) implies x == j by {
            lemma_digits_unique(s@, i as int, x, j as int);
        }
    }
    j
}

/// The end of the number lexeme starting at `i`, which must be a minus or a
/// digit. Complete: a lexeme at `i` that a boundary follows is found, and
/// found whole.
#[verifier::rlimit(80)]
fn number(s: &[u8], i: usize) -> (out: Option<usize>)
    requires i < s.len(),
    ensures match out { Some(j) => i < j <= s.len() && number_ok(s@.subrange(i as int, j as int)), None => true },
        forall|j: int| i < j <= s@.len() && number_ok(s@.subrange(i as int, j)) && boundary(s@, j)
            ==> (match out { Some(jj) => jj == j, None => false }),
{
    let mut j = i;
    if s[j] == MINUS { j = j + 1; }
    let ghost m = j as int;
    if j >= s.len() || !is_digit_exec(s[j]) {
        proof {
            assert forall|j2: int| i < j2 <= s@.len() && number_ok(s@.subrange(i as int, j2)) && boundary(s@, j2) implies false by {
                lemma_number_shape(s@, i as int, j2);
                let (m2, a2, b2) = choose|m2: int, a2: int, b2: int| #[trigger] shape(s@, i as int, m2, a2, b2, j2);
                assert(s@.subrange(m2, a2)[0] == s@[m2]);
            }
        }
        return None;
    }
    if s[j] == ZERO { j = j + 1; } else { j = skip_digits(s, j); }
    let ghost a = j as int;
    proof {
        let lex_int = s@.subrange(i as int, a);
        if s@[i as int] == MINUS {
            assert(lex_int.drop_first() =~= s@.subrange(m, a));
        } else {
            assert(lex_int =~= s@.subrange(m, a));
        }
        if s@[m] == ZERO {
            assert(s@.subrange(m, a) =~= seq![ZERO]);
        }
        assert(int_ok(lex_int));
        // Every shaped lexeme at `i` has its integer part end here.
        assert forall|m2: int, a2: int, b2: int, j2: int| #[trigger] shape(s@, i as int, m2, a2, b2, j2) implies m2 == m && a2 == a by {
            if s@[m] != ZERO { lemma_digits_unique(s@, m, a2, a); }
        }
    }
    if j < s.len() && s[j] == DOT {
        j = j + 1;
        if j >= s.len() || !is_digit_exec(s[j]) {
            proof {
                assert forall|j2: int| i < j2 <= s@.len() && number_ok(s@.subrange(i as int, j2)) && boundary(s@, j2) implies false by {
                    lemma_number_shape(s@, i as int, j2);
                    let (m2, a2, b2) = choose|m2: int, a2: int, b2: int| #[trigger] shape(s@, i as int, m2, a2, b2, j2);
                    assert(a2 < b2);
                    assert(s@.subrange(a2 + 1, b2)[0] == s@[a2 + 1]);
                }
            }
            return None;
        }
        j = skip_digits(s, j);
        proof { assert(s@.subrange(a, j as int).drop_first() =~= s@.subrange(a + 1, j as int)); }
    } else {
        proof { assert(s@.subrange(a, j as int).len() == 0); }
    }
    let ghost b = j as int;
    assert(frac_ok(s@.subrange(a, b)));
    proof {
        assert forall|m2: int, a2: int, b2: int, j2: int| #[trigger] shape(s@, i as int, m2, a2, b2, j2) implies b2 == b by {
            if a2 < b2 { lemma_digits_unique(s@, a + 1, b2, b); }
        }
    }
    if j < s.len() && (s[j] == LOWER_E || s[j] == UPPER_E) {
        j = j + 1;
        if j < s.len() && (s[j] == PLUS || s[j] == MINUS) { j = j + 1; }
        let ghost exp_digits = j as int;
        if j >= s.len() || !is_digit_exec(s[j]) {
            proof {
                assert forall|j2: int| i < j2 <= s@.len() && number_ok(s@.subrange(i as int, j2)) && boundary(s@, j2) implies false by {
                    lemma_number_shape(s@, i as int, j2);
                    let (m2, a2, b2) = choose|m2: int, a2: int, b2: int| #[trigger] shape(s@, i as int, m2, a2, b2, j2);
                    assert(b2 < j2);
                    assert(exp_start(s@, b) == exp_digits);
                    assert(s@.subrange(exp_start(s@, b2), j2)[0] == s@[exp_start(s@, b2)]);
                }
            }
            return None;
        }
        j = skip_digits(s, j);
        proof {
            let lex_exp = s@.subrange(b, j as int);
            if s@[b + 1] == PLUS || s@[b + 1] == MINUS {
                assert(lex_exp.subrange(2, lex_exp.len() as int) =~= s@.subrange(exp_digits, j as int));
            } else {
                assert(lex_exp.drop_first() =~= s@.subrange(exp_digits, j as int));
            }
            assert(exp_ok(lex_exp));
            assert forall|j2: int| i < j2 <= s@.len() && number_ok(s@.subrange(i as int, j2)) && boundary(s@, j2) implies j2 == j by {
                lemma_number_shape(s@, i as int, j2);
                let (m2, a2, b2) = choose|m2: int, a2: int, b2: int| #[trigger] shape(s@, i as int, m2, a2, b2, j2);
                assert(b2 < j2);
                assert(exp_start(s@, b) == exp_digits);
                lemma_digits_unique(s@, exp_digits, j2, j as int);
            }
        }
    } else {
        proof {
            assert(s@.subrange(b, j as int).len() == 0);
            assert forall|j2: int| i < j2 <= s@.len() && number_ok(s@.subrange(i as int, j2)) && boundary(s@, j2) implies j2 == j by {
                lemma_number_shape(s@, i as int, j2);
                let (m2, a2, b2) = choose|m2: int, a2: int, b2: int| #[trigger] shape(s@, i as int, m2, a2, b2, j2);
            }
        }
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
        hex4(s@, i as int) ==> out.is_some(),
{
    if s.len() < 4 || i > s.len() - 4 { return None; }
    let mut u: u32 = 0;
    let mut k: usize = 0;
    while k < 4
        invariant i + 4 <= s.len(), k <= 4, crate::http1_chunked::all_hex(s@.subrange(i as int, i + k)), u == crate::http1_chunked::hex_value(s@.subrange(i as int, i + k)), u < crate::http1_chunked::pow16(k as nat),
        decreases 4 - k,
    {
        let b = s[i + k];
        if !is_hex_exec(b) {
            proof { assert(s@.subrange(i as int, i + 4)[k as int] == b); }
            return None;
        }
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

/// What every encoding of the string at `i` that ends at `j` with `text`
/// has in common with a scan that stands at `p` having decoded `acc`: the
/// text so far is a prefix, and the bytes left decode to the rest.
pub open spec fn string_progress(s: Seq<u8>, p: int, acc: Seq<u8>, j: int, text: Seq<u8>) -> bool {
    p <= j - 1 && text.len() >= acc.len() && text.subrange(0, acc.len() as int) == acc
        && string_body(s.subrange(p, j - 1), text.subrange(acc.len() as int, text.len() as int))
}
/// At a quote, the string ends: this is its closing quote and the text is complete.
proof fn lemma_string_quote(s: Seq<u8>, p: int, acc: Seq<u8>, j: int, text: Seq<u8>)
    requires 0 <= p < s.len(), j <= s.len(), string_progress(s, p, acc, j, text), s[p] == QUOTE,
    ensures j == p + 1, text == acc,
{
    let rem = s.subrange(p, j - 1);
    if p < j - 1 { assert(rem[0] == QUOTE); assert(!plain(QUOTE)); }
    assert(text.subrange(0, text.len() as int) =~= text);
}
/// A control byte is in no string.
proof fn lemma_string_control(s: Seq<u8>, p: int, acc: Seq<u8>, j: int, text: Seq<u8>, b: u8)
    requires 0 <= p < s.len(), j <= s.len(), s[j - 1] == QUOTE, string_progress(s, p, acc, j, text), s[p] == b, b < 0x20,
    ensures false,
{
    let rem = s.subrange(p, j - 1);
    if p < j - 1 { assert(rem[0] == b); }
}
/// A plain byte is the next byte of the text.
proof fn lemma_string_plain(s: Seq<u8>, p: int, acc: Seq<u8>, j: int, text: Seq<u8>, b: u8)
    requires 0 <= p < s.len(), j <= s.len(), s[j - 1] == QUOTE, string_progress(s, p, acc, j, text), s[p] == b, plain(b),
    ensures string_progress(s, p + 1, acc.push(b), j, text),
{
    let rem = s.subrange(p, j - 1);
    if p == j - 1 { assert(s[j - 1] == QUOTE); }
    assert(rem[0] == b);
    let rest = text.subrange(acc.len() as int, text.len() as int);
    assert(rest[0] == b);
    assert(rem.drop_first() =~= s.subrange(p + 1, j - 1));
    assert(rest.drop_first() =~= text.subrange(acc.len() as int + 1, text.len() as int));
    assert(text.subrange(0, acc.len() as int + 1) =~= acc.push(b));
}
/// A backslash starts one escape sequence, which decodes to the next bytes of the text.
proof fn lemma_string_escape(s: Seq<u8>, p: int, acc: Seq<u8>, j: int, text: Seq<u8>)
    requires 0 <= p < s.len(), j <= s.len(), s[j - 1] == QUOTE, string_progress(s, p, acc, j, text), s[p] == BSLASH,
    ensures exists|n: int, m: int| 2 <= n && p + n <= j - 1 && 0 <= m && acc.len() as int + m <= text.len()
        && escape(#[trigger] s.subrange(p, p + n), #[trigger] text.subrange(acc.len() as int, acc.len() as int + m))
        && string_progress(s, p + n, acc + text.subrange(acc.len() as int, acc.len() as int + m), j, text),
{
    let rem = s.subrange(p, j - 1);
    if p == j - 1 { assert(s[j - 1] == QUOTE); }
    assert(rem[0] == BSLASH);
    let rest = text.subrange(acc.len() as int, text.len() as int);
    let (n, m) = choose|n: int, m: int| 2 <= n <= rem.len() && 0 <= m <= rest.len() && escape(#[trigger] rem.subrange(0, n), #[trigger] rest.subrange(0, m))
        && string_body(rem.subrange(n, rem.len() as int), rest.subrange(m, rest.len() as int));
    assert(rem.subrange(0, n) =~= s.subrange(p, p + n));
    assert(rest.subrange(0, m) =~= text.subrange(acc.len() as int, acc.len() as int + m));
    let dec = text.subrange(acc.len() as int, acc.len() as int + m);
    assert(rem.subrange(n, rem.len() as int) =~= s.subrange(p + n, j - 1));
    assert(rest.subrange(m, rest.len() as int) =~= text.subrange(acc.len() as int + m, text.len() as int));
    assert(text.subrange(0, acc.len() as int + m) =~= acc + dec);
    assert(string_progress(s, p + n, acc + dec, j, text));
}
/// An escape sequence is determined by its bytes: its length and decoding
/// follow from the character after the backslash and the hex digits.
proof fn lemma_escape_determined(s: Seq<u8>, p: int, n: int, dec: Seq<u8>)
    requires 0 <= p, 2 <= n, p + n <= s.len(), escape(s.subrange(p, p + n), dec),
    ensures s[p] == BSLASH, p + 1 < s.len(),
        s[p + 1] != LOWER_U ==> n == 2 && dec.len() == 1 && simple_escape(s[p + 1]) == Some(dec[0]),
        s[p + 1] == LOWER_U ==> hex4(s, p + 2) && (
            (is_high(unit(s, p + 2)) && n == 12 && s[p + 6] == BSLASH && s[p + 7] == LOWER_U && hex4(s, p + 8)
                && is_low(unit(s, p + 8)) && dec == utf8(pair(unit(s, p + 2), unit(s, p + 8))))
            || (!is_high(unit(s, p + 2)) && !is_low(unit(s, p + 2)) && n == 6 && dec == utf8(unit(s, p + 2)))),
{
    let esc = s.subrange(p, p + n);
    assert(esc[0] == s[p]);
    assert(esc[1] == s[p + 1]);
    if esc.len() >= 6 {
        assert(esc.subrange(2, 6) =~= s.subrange(p + 2, p + 6));
    }
    if esc.len() == 12 {
        assert(esc[6] == s[p + 6]);
        assert(esc[7] == s[p + 7]);
        assert(esc.subrange(8, 12) =~= s.subrange(p + 8, p + 12));
    }
}

/// The quoted string starting at `i`: its decoded text and the position
/// after the closing quote. Complete: a string at `i` is found, with its text.
#[verifier::loop_isolation(false)]
#[verifier::rlimit(80)]
fn string(s: &[u8], i: usize) -> (out: Option<(Vec<u8>, usize)>)
    requires i < s.len(), s@[i as int] == QUOTE,
    ensures match out { Some((text, j)) => i + 2 <= j <= s.len() && string_at(s@, i as int, j as int, text@), None => true },
        forall|j: int, text: Seq<u8>| #[trigger] string_at(s@, i as int, j, text)
            ==> (match out { Some((t, jj)) => jj == j && t@ == text, None => false }),
{
    let mut text: Vec<u8> = Vec::new();
    let mut p = i + 1;
    proof {
        assert(s@.subrange(i + 1, p as int).len() == 0);
        assert forall|j: int, t: Seq<u8>| #[trigger] string_at(s@, i as int, j, t) implies string_progress(s@, p as int, text@, j, t) by {
            assert(t.subrange(0, 0) =~= text@);
            assert(t.subrange(0, t.len() as int) =~= t);
        }
    }
    loop
        invariant i + 1 <= p <= s.len(), string_body(s@.subrange(i + 1, p as int), text@),
            forall|j: int, t: Seq<u8>| #[trigger] string_at(s@, i as int, j, t) ==> string_progress(s@, p as int, text@, j, t),
        decreases s.len() - p,
    {
        if p >= s.len() { return None; }
        let b = s[p];
        if b == QUOTE {
            proof {
                let j = p + 1;
                assert(s@[j - 1] == QUOTE);
                assert(s@.subrange(i + 1, j - 1) =~= s@.subrange(i + 1, p as int));
                assert(string_at(s@, i as int, j, text@));
                assert forall|j2: int, t: Seq<u8>| #[trigger] string_at(s@, i as int, j2, t) implies j2 == p + 1 && t == text@ by {
                    lemma_string_quote(s@, p as int, text@, j2, t);
                }
            }
            return Some((text, p + 1));
        }
        let ghost inside_before = s@.subrange(i + 1, p as int);
        let ghost text_before = text@;
        if b == BSLASH {
            proof {
                assert forall|j2: int, t: Seq<u8>| #[trigger] string_at(s@, i as int, j2, t) implies p + 2 < s@.len() by {
                    lemma_string_escape(s@, p as int, text_before, j2, t);
                }
            }
            if p + 1 >= s.len() { return None; }
            let e = s[p + 1];
            if e == LOWER_U {
                let u = match hex4_exec(s, p + 2) {
                    Some(u) => u,
                    None => {
                        proof {
                            assert forall|j2: int, t: Seq<u8>| #[trigger] string_at(s@, i as int, j2, t) implies false by {
                                lemma_string_escape(s@, p as int, text_before, j2, t);
                                let (n, m) = choose|n: int, m: int| 2 <= n && p + n <= j2 - 1 && 0 <= m && text_before.len() as int + m <= t.len()
                                    && escape(#[trigger] s@.subrange(p as int, p + n), #[trigger] t.subrange(text_before.len() as int, text_before.len() as int + m))
                                    && string_progress(s@, p + n, text_before + t.subrange(text_before.len() as int, text_before.len() as int + m), j2, t);
                                lemma_escape_determined(s@, p as int, n, t.subrange(text_before.len() as int, text_before.len() as int + m));
                            }
                        }
                        return None;
                    }
                };
                if 0xD800 <= u && u <= 0xDBFF {
                    proof {
                        assert forall|j2: int, t: Seq<u8>| #[trigger] string_at(s@, i as int, j2, t) implies
                            s@.len() - p >= 8 && s@[p + 6] == BSLASH && s@[p + 7] == LOWER_U && hex4(s@, p + 8) && is_low(unit(s@, p + 8)) by {
                            lemma_string_escape(s@, p as int, text_before, j2, t);
                            let (n, m) = choose|n: int, m: int| 2 <= n && p + n <= j2 - 1 && 0 <= m && text_before.len() as int + m <= t.len()
                                && escape(#[trigger] s@.subrange(p as int, p + n), #[trigger] t.subrange(text_before.len() as int, text_before.len() as int + m))
                                && string_progress(s@, p + n, text_before + t.subrange(text_before.len() as int, text_before.len() as int + m), j2, t);
                            lemma_escape_determined(s@, p as int, n, t.subrange(text_before.len() as int, text_before.len() as int + m));
                        }
                    }
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
                        assert forall|j2: int, t: Seq<u8>| #[trigger] string_at(s@, i as int, j2, t) implies string_progress(s@, p + 12, text@, j2, t) by {
                            lemma_string_escape(s@, p as int, text_before, j2, t);
                            let (n, m) = choose|n: int, m: int| 2 <= n && p + n <= j2 - 1 && 0 <= m && text_before.len() as int + m <= t.len()
                                && escape(#[trigger] s@.subrange(p as int, p + n), #[trigger] t.subrange(text_before.len() as int, text_before.len() as int + m))
                                && string_progress(s@, p + n, text_before + t.subrange(text_before.len() as int, text_before.len() as int + m), j2, t);
                            lemma_escape_determined(s@, p as int, n, t.subrange(text_before.len() as int, text_before.len() as int + m));
                            assert(text@ =~= text_before + t.subrange(text_before.len() as int, text_before.len() as int + m));
                        }
                    }
                    p = p + 12;
                } else if 0xDC00 <= u && u <= 0xDFFF {
                    proof {
                        assert forall|j2: int, t: Seq<u8>| #[trigger] string_at(s@, i as int, j2, t) implies false by {
                            lemma_string_escape(s@, p as int, text_before, j2, t);
                            let (n, m) = choose|n: int, m: int| 2 <= n && p + n <= j2 - 1 && 0 <= m && text_before.len() as int + m <= t.len()
                                && escape(#[trigger] s@.subrange(p as int, p + n), #[trigger] t.subrange(text_before.len() as int, text_before.len() as int + m))
                                && string_progress(s@, p + n, text_before + t.subrange(text_before.len() as int, text_before.len() as int + m), j2, t);
                            lemma_escape_determined(s@, p as int, n, t.subrange(text_before.len() as int, text_before.len() as int + m));
                        }
                    }
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
                        assert forall|j2: int, t: Seq<u8>| #[trigger] string_at(s@, i as int, j2, t) implies string_progress(s@, p + 6, text@, j2, t) by {
                            lemma_string_escape(s@, p as int, text_before, j2, t);
                            let (n, m) = choose|n: int, m: int| 2 <= n && p + n <= j2 - 1 && 0 <= m && text_before.len() as int + m <= t.len()
                                && escape(#[trigger] s@.subrange(p as int, p + n), #[trigger] t.subrange(text_before.len() as int, text_before.len() as int + m))
                                && string_progress(s@, p + n, text_before + t.subrange(text_before.len() as int, text_before.len() as int + m), j2, t);
                            lemma_escape_determined(s@, p as int, n, t.subrange(text_before.len() as int, text_before.len() as int + m));
                            assert(text@ =~= text_before + t.subrange(text_before.len() as int, text_before.len() as int + m));
                        }
                    }
                    p = p + 6;
                }
            } else {
                let d: u8 = if e == QUOTE { QUOTE } else if e == BSLASH { BSLASH } else if e == SLASH { SLASH }
                    else if e == LOWER_B { 8 } else if e == LOWER_F { 12 } else if e == LOWER_N { LF }
                    else if e == LOWER_R { CR } else if e == LOWER_T { TAB } else {
                        proof {
                            assert(simple_escape(e).is_none());
                            assert forall|j2: int, t: Seq<u8>| #[trigger] string_at(s@, i as int, j2, t) implies false by {
                                lemma_string_escape(s@, p as int, text_before, j2, t);
                                let (n, m) = choose|n: int, m: int| 2 <= n && p + n <= j2 - 1 && 0 <= m && text_before.len() as int + m <= t.len()
                                    && escape(#[trigger] s@.subrange(p as int, p + n), #[trigger] t.subrange(text_before.len() as int, text_before.len() as int + m))
                                    && string_progress(s@, p + n, text_before + t.subrange(text_before.len() as int, text_before.len() as int + m), j2, t);
                                lemma_escape_determined(s@, p as int, n, t.subrange(text_before.len() as int, text_before.len() as int + m));
                            }
                        }
                        return None
                    };
                text.push(d);
                proof {
                    let esc = s@.subrange(p as int, p + 2);
                    let dec = text@.subrange(text_before.len() as int, text@.len() as int);
                    assert(dec =~= seq![d]);
                    assert(text@.subrange(0, text_before.len() as int) =~= text_before);
                    assert(simple_escape(e) == Some(d));
                    assert(escape(esc, dec));
                    lemma_extend_escape(s@, i as int, p as int, 2, text_before, text@);
                    assert forall|j2: int, t: Seq<u8>| #[trigger] string_at(s@, i as int, j2, t) implies string_progress(s@, p + 2, text@, j2, t) by {
                        lemma_string_escape(s@, p as int, text_before, j2, t);
                        let (n, m) = choose|n: int, m: int| 2 <= n && p + n <= j2 - 1 && 0 <= m && text_before.len() as int + m <= t.len()
                            && escape(#[trigger] s@.subrange(p as int, p + n), #[trigger] t.subrange(text_before.len() as int, text_before.len() as int + m))
                            && string_progress(s@, p + n, text_before + t.subrange(text_before.len() as int, text_before.len() as int + m), j2, t);
                        lemma_escape_determined(s@, p as int, n, t.subrange(text_before.len() as int, text_before.len() as int + m));
                        assert(text@ =~= text_before + t.subrange(text_before.len() as int, text_before.len() as int + m));
                    }
                }
                p = p + 2;
            }
        } else if b < 0x20 {
            proof {
                assert forall|j2: int, t: Seq<u8>| #[trigger] string_at(s@, i as int, j2, t) implies false by {
                    lemma_string_control(s@, p as int, text_before, j2, t, b);
                }
            }
            return None;
        } else {
            text.push(b);
            proof {
                lemma_plain_body(b);
                lemma_body_append(inside_before, text_before, seq![b], seq![b]);
                assert(s@.subrange(i + 1, p + 1) =~= inside_before + seq![b]);
                assert(text@ =~= text_before + seq![b]);
                assert forall|j2: int, t: Seq<u8>| #[trigger] string_at(s@, i as int, j2, t) implies string_progress(s@, p + 1, text@, j2, t) by {
                    lemma_string_plain(s@, p as int, text_before, j2, t, b);
                    assert(text@ =~= text_before.push(b));
                }
            }
            p = p + 1;
        }
    }
}

/// `null`, `true`, or `false` at `i`. Complete: a literal at `i` is found.
fn literal(s: &[u8], i: usize) -> (out: Option<(Value, usize)>)
    requires i < s.len(),
    ensures match out { Some((v, j)) => i < j <= s.len() && encodes(s@, i as int, j as int, v), None => true },
        forall|j: int, v: Value| encodes(s@, i as int, j, v) && (v is Null || v is Bool)
            ==> (match out { Some((w, jj)) => jj == j && same(w, v), None => false }),
{
    let b = s[i];
    if b == LOWER_N {
        if s.len() - i >= 4 && s[i + 1] == LOWER_U && s[i + 2] == 108 && s[i + 3] == 108 {
            proof {
                assert(s@.subrange(i as int, i + 4) =~= null_word());
                assert forall|j: int, v: Value| encodes(s@, i as int, j, v) && (v is Null || v is Bool) implies j == i + 4 && same(Value::Null, v) by {
                    lemma_literal_shape(s@, i as int, j, v);
                }
            }
            return Some((Value::Null, i + 4));
        }
    } else if b == LOWER_T {
        if s.len() - i >= 4 && s[i + 1] == LOWER_R && s[i + 2] == LOWER_U && s[i + 3] == LOWER_E {
            proof {
                assert(s@.subrange(i as int, i + 4) =~= true_word());
                assert forall|j: int, v: Value| encodes(s@, i as int, j, v) && (v is Null || v is Bool) implies j == i + 4 && same(Value::Bool(true), v) by {
                    lemma_literal_shape(s@, i as int, j, v);
                }
            }
            return Some((Value::Bool(true), i + 4));
        }
    } else if b == LOWER_F {
        if s.len() - i >= 5 && s[i + 1] == 97 && s[i + 2] == 108 && s[i + 3] == 115 && s[i + 4] == LOWER_E {
            proof {
                assert(s@.subrange(i as int, i + 5) =~= false_word());
                assert forall|j: int, v: Value| encodes(s@, i as int, j, v) && (v is Null || v is Bool) implies j == i + 5 && same(Value::Bool(false), v) by {
                    lemma_literal_shape(s@, i as int, j, v);
                }
            }
            return Some((Value::Bool(false), i + 5));
        }
    }
    proof {
        assert forall|j: int, v: Value| encodes(s@, i as int, j, v) && (v is Null || v is Bool) implies false by {
            lemma_literal_shape(s@, i as int, j, v);
        }
    }
    None
}

/// A literal's bytes, one by one.
proof fn lemma_literal_shape(s: Seq<u8>, i: int, j: int, v: Value)
    requires encodes(s, i, j, v), v is Null || v is Bool,
    ensures match v {
        Value::Null => j == i + 4 && s[i] == LOWER_N && s[i + 1] == LOWER_U && s[i + 2] == 108 && s[i + 3] == 108,
        Value::Bool(true) => j == i + 4 && s[i] == LOWER_T && s[i + 1] == LOWER_R && s[i + 2] == LOWER_U && s[i + 3] == LOWER_E,
        Value::Bool(false) => j == i + 5 && s[i] == LOWER_F && s[i + 1] == 97 && s[i + 2] == 108 && s[i + 3] == 115 && s[i + 4] == LOWER_E,
        _ => true,
    },
{
    let w = s.subrange(i, j);
    match v {
        Value::Null => { assert(w == null_word()); assert(w.len() == 4); assert(w[0] == s[i] && w[1] == s[i + 1] && w[2] == s[i + 2] && w[3] == s[i + 3]); }
        Value::Bool(true) => { assert(w == true_word()); assert(w.len() == 4); assert(w[0] == s[i] && w[1] == s[i + 1] && w[2] == s[i + 2] && w[3] == s[i + 3]); }
        Value::Bool(false) => { assert(w == false_word()); assert(w.len() == 5); assert(w[0] == s[i] && w[1] == s[i + 1] && w[2] == s[i + 2] && w[3] == s[i + 3] && w[4] == s[i + 4]); }
        _ => {}
    }
}

/// The value at `i`, with no leading whitespace, and the position after
/// it. Complete: a value at `i` within the limit limit and followed by a
/// boundary is found, whole and the same.
#[verifier::rlimit(100)]
fn value(s: &[u8], i: usize, limit: u32) -> (out: Option<(Value, usize)>)
    requires i <= s.len(),
    ensures match out { Some((v, j)) => i < j <= s.len() && encodes(s@, i as int, j as int, v), None => true },
        forall|j: int, v: Value| #[trigger] value_at(s@, i as int, j, v) && depth(v) <= limit && boundary(s@, j)
            ==> (match out { Some((w, jj)) => jj == j && same(w, v), None => false }),
    decreases s.len() - i, 0int,
{
    if i >= s.len() {
        proof {
            assert forall|j: int, v: Value| #[trigger] value_at(s@, i as int, j, v) implies false by { lemma_value_start(s@, i as int, j, v); }
        }
        return None;
    }
    let b = s[i];
    if b == QUOTE {
        let out = match string(s, i) { Some((text, j)) => Some((Value::Str(text), j)), None => None };
        proof {
            assert forall|j: int, v: Value| #[trigger] value_at(s@, i as int, j, v) && depth(v) <= limit && boundary(s@, j)
                implies (match out { Some((w, jj)) => jj == j && same(w, v), None => false }) by {
                lemma_value_start(s@, i as int, j, v);
                assert(string_at(s@, i as int, j, v->Str_0@));
            }
        }
        out
    } else if b == LBRACKET {
        if limit == 0 {
            proof {
                assert forall|j: int, v: Value| #[trigger] value_at(s@, i as int, j, v) && depth(v) <= limit implies false by {
                    lemma_value_start(s@, i as int, j, v);
                }
            }
            return None;
        }
        let out = array(s, i + 1, limit - 1);
        proof {
            assert forall|j: int, v: Value| #[trigger] value_at(s@, i as int, j, v) && depth(v) <= limit && boundary(s@, j)
                implies (match out { Some((w, jj)) => jj == j && same(w, v), None => false }) by {
                lemma_value_start(s@, i as int, j, v);
                assert(array_at(s@, i + 1, j, v->Array_0@));
            }
        }
        out
    } else if b == LBRACE {
        if limit == 0 {
            proof {
                assert forall|j: int, v: Value| #[trigger] value_at(s@, i as int, j, v) && depth(v) <= limit implies false by {
                    lemma_value_start(s@, i as int, j, v);
                }
            }
            return None;
        }
        let out = object(s, i + 1, limit - 1);
        proof {
            assert forall|j: int, v: Value| #[trigger] value_at(s@, i as int, j, v) && depth(v) <= limit && boundary(s@, j)
                implies (match out { Some((w, jj)) => jj == j && same(w, v), None => false }) by {
                lemma_value_start(s@, i as int, j, v);
                assert(object_at(s@, i + 1, j, v->Object_0@));
            }
        }
        out
    } else if b == MINUS || is_digit_exec(b) {
        match number(s, i) {
            Some(j) => {
                let lex = slice_to_vec(slice_subrange(s, i, j));
                proof {
                    assert forall|j2: int, v: Value| #[trigger] value_at(s@, i as int, j2, v) && depth(v) <= limit && boundary(s@, j2)
                        implies j2 == j && same(Value::Number(lex), v) by {
                        lemma_value_start(s@, i as int, j2, v);
                        assert(number_ok(s@.subrange(i as int, j2)));
                    }
                }
                Some((Value::Number(lex), j))
            }
            None => {
                proof {
                    assert forall|j2: int, v: Value| #[trigger] value_at(s@, i as int, j2, v) && depth(v) <= limit && boundary(s@, j2) implies false by {
                        lemma_value_start(s@, i as int, j2, v);
                        assert(number_ok(s@.subrange(i as int, j2)));
                    }
                }
                None
            }
        }
    } else {
        let out = literal(s, i);
        proof {
            assert forall|j: int, v: Value| #[trigger] value_at(s@, i as int, j, v) && depth(v) <= limit && boundary(s@, j)
                implies (match out { Some((w, jj)) => jj == j && same(w, v), None => false }) by {
                lemma_value_start(s@, i as int, j, v);
            }
        }
        out
    }
}

/// The rest of an array whose `[` is at `i - 1`. Complete: an array within
/// the limit limit is found, whole and the same.
#[verifier::loop_isolation(false)]
#[verifier::rlimit(300)]
fn array(s: &[u8], i: usize, limit: u32) -> (out: Option<(Value, usize)>)
    requires 1 <= i <= s.len(), s@[i - 1] == LBRACKET,
    ensures match out { Some((v, j)) => i <= j <= s.len() && encodes(s@, i - 1, j as int, v), None => true },
        forall|j: int, items: Seq<Value>| #[trigger] array_at(s@, i as int, j, items) && depths(items) <= limit
            ==> (match out { Some((v, jj)) => jj == j && v is Array && same_items(v->Array_0@, items), None => false }),
    decreases s.len() - i, 2int,
{
    let mut items: Vec<Value> = Vec::new();
    let a = skip_ws(s, i);
    if a < s.len() && s[a] == RBRACKET {
        proof {
            assert(elements(s@, i as int, a as int, items@));
            assert forall|j: int, its: Seq<Value>| #[trigger] array_at(s@, i as int, j, its) && depths(its) <= limit
                implies j == a + 1 && same_items(items@, its) by {
                lemma_array_first(s@, i as int, j, its, a as int);
            }
        }
        return Some((Value::Array(items), a + 1));
    }
    let (first, mut p) = match value(s, a, limit) {
        Some(r) => r,
        None => {
            proof {
                assert forall|j: int, its: Seq<Value>| #[trigger] array_at(s@, i as int, j, its) && depths(its) <= limit implies false by {
                    lemma_array_first(s@, i as int, j, its, a as int);
                }
            }
            return None;
        }
    };
    items.push(first);
    proof {
        assert(ws(s@, i as int, a as int));
        assert(padded(s@, i as int, p as int, items@[0]));
        assert(items_ok(s@, i as int, p as int, items@));
        assert forall|j: int, its: Seq<Value>| #[trigger] array_at(s@, i as int, j, its) && depths(its) <= limit
            implies its.len() >= items@.len() && same_items(items@, its.take(items@.len() as int))
                && exists|a2: int| #[trigger] ws(s@, p as int, a2) && stop(s@, a2, j, its.skip(items@.len() as int)) by {
            lemma_array_first(s@, i as int, j, its, a as int);
            let (c, a2) = choose|c: int, a2: int| #[trigger] ws(s@, c, a2) && value_at(s@, a as int, c, its[0]) && boundary(s@, c) && stop(s@, a2, j, its.drop_first());
            assert(same(first, its[0]));
            assert(items@[0] == first);
            assert(its.take(1)[0] == its[0]);
            assert(its.take(1).drop_first().len() == 0);
            assert(items@.drop_first().len() == 0);
            assert(same_items(items@.drop_first(), its.take(1).drop_first()));
            assert(same_items(items@, its.take(1)));
            assert(its.skip(1) =~= its.drop_first());
        }
    }
    loop
        invariant 1 <= i <= p <= s.len(), items@.len() >= 1, items_ok(s@, i as int, p as int, items@), s@[i - 1] == LBRACKET,
            forall|j: int, its: Seq<Value>| #[trigger] array_at(s@, i as int, j, its) && depths(its) <= limit
                ==> its.len() >= items@.len() && same_items(items@, its.take(items@.len() as int))
                    && exists|a2: int| #[trigger] ws(s@, p as int, a2) && stop(s@, a2, j, its.skip(items@.len() as int)),
        decreases s.len() - p,
    {
        let c = skip_ws(s, p);
        if c >= s.len() {
            proof {
                assert forall|j: int, its: Seq<Value>| #[trigger] array_at(s@, i as int, j, its) && depths(its) <= limit implies false by {
                    lemma_array_next(s@, p as int, c as int, c + 1, j, its, items@.len() as int);
                }
            }
            return None;
        }
        if s[c] == RBRACKET {
            proof {
                assert(elements(s@, i as int, c as int, items@));
                assert forall|j: int, its: Seq<Value>| #[trigger] array_at(s@, i as int, j, its) && depths(its) <= limit
                    implies j == c + 1 && same_items(items@, its) by {
                    lemma_array_next(s@, p as int, c as int, c + 1, j, its, items@.len() as int);
                    assert(its.take(items@.len() as int) =~= its);
                }
            }
            return Some((Value::Array(items), c + 1));
        }
        if s[c] != COMMA {
            proof {
                assert forall|j: int, its: Seq<Value>| #[trigger] array_at(s@, i as int, j, its) && depths(its) <= limit implies false by {
                    lemma_array_next(s@, p as int, c as int, c + 1, j, its, items@.len() as int);
                }
            }
            return None;
        }
        let d = skip_ws(s, c + 1);
        let ghost k = items@.len() as int;
        proof {
            assert forall|j: int, its: Seq<Value>| #[trigger] array_at(s@, i as int, j, its) && depths(its) <= limit
                implies k < its.len() && depth(its[k]) <= limit
                    && exists|c2: int, a3: int| #[trigger] ws(s@, c2, a3) && value_at(s@, d as int, c2, its[k]) && boundary(s@, c2) && stop(s@, a3, j, its.skip(k + 1)) by {
                lemma_array_next(s@, p as int, c as int, c + 1, j, its, k);
                let (d0, c2, a3) = choose|d0: int, c2: int, a3: int| #[trigger] ws(s@, c + 1, d0) && #[trigger] ws(s@, c2, a3) && value_at(s@, d0, c2, its[k])
                    && boundary(s@, c2) && stop(s@, a3, j, its.skip(k + 1));
                lemma_value_start(s@, d0, c2, its[k]);
                lemma_ws_unique(s@, c + 1, d0, d as int);
            }
        }
        let (next, q) = match value(s, d, limit) {
            Some(r) => r,
            None => {
                proof {
                    assert forall|j: int, its: Seq<Value>| #[trigger] array_at(s@, i as int, j, its) && depths(its) <= limit implies false by {}
                }
                return None;
            }
        };
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
            assert forall|j: int, its: Seq<Value>| #[trigger] array_at(s@, i as int, j, its) && depths(its) <= limit
                implies its.len() >= items@.len() && same_items(items@, its.take(items@.len() as int))
                    && exists|a2: int| #[trigger] ws(s@, q as int, a2) && stop(s@, a2, j, its.skip(items@.len() as int)) by {
                let (c2, a3) = choose|c2: int, a3: int| #[trigger] ws(s@, c2, a3) && value_at(s@, d as int, c2, its[k]) && boundary(s@, c2) && stop(s@, a3, j, its.skip(k + 1));
                assert(same(next, its[k]));
                lemma_same_push(before, its.take(k), next, its[k]);
                assert(its.take(k).push(its[k]) =~= its.take(k + 1));
                assert(items@ =~= before.push(next));
            }
        }
        p = q;
    }
}

/// A member: whitespace, a quoted key, whitespace, a colon, whitespace, a
/// value. Complete: a member at `i` within the limit limit and followed by a
/// boundary is found, whole and the same.
#[verifier::rlimit(100)]
fn member(s: &[u8], i: usize, limit: u32) -> (out: Option<(Member, usize)>)
    requires i <= s.len(),
    ensures match out { Some((m, j)) => i < j <= s.len() && member_ok(s@, i as int, j as int, m), None => true },
        forall|j: int, m: Member| #[trigger] member_at(s@, i as int, j, m) && depth(m.value) <= limit && boundary(s@, j)
            ==> (match out { Some((w, jj)) => jj == j && w.key@ == m.key@ && same(w.value, m.value), None => false }),
    decreases s.len() - i, 1int,
{
    let a = skip_ws(s, i);
    if a >= s.len() || s[a] != QUOTE {
        proof {
            assert forall|j: int, m: Member| #[trigger] member_at(s@, i as int, j, m) implies false by { lemma_member_parts(s@, i as int, j, m, a as int); }
        }
        return None;
    }
    let (key, b) = match string(s, a) {
        Some(r) => r,
        None => {
            proof {
                assert forall|j: int, m: Member| #[trigger] member_at(s@, i as int, j, m) implies false by { lemma_member_parts(s@, i as int, j, m, a as int); }
            }
            return None;
        }
    };
    let c = skip_ws(s, b);
    proof {
        assert forall|j: int, m: Member| #[trigger] member_at(s@, i as int, j, m) implies key@ == m.key@ && c < s@.len() && s@[c as int] == COLON
            && exists|d: int| #[trigger] ws(s@, c + 1, d) && value_at(s@, d, j, m.value) by {
            lemma_member_parts(s@, i as int, j, m, a as int);
            let (b0, c0, d0) = choose|b0: int, c0: int, d0: int| #[trigger] string_at(s@, a as int, b0, m.key@) && #[trigger] ws(s@, b0, c0) && c0 < s@.len() && s@[c0] == COLON
                && #[trigger] ws(s@, c0 + 1, d0) && value_at(s@, d0, j, m.value);
            lemma_ws_unique(s@, b as int, c0, c as int);
        }
    }
    if c >= s.len() || s[c] != COLON { return None; }
    let d = skip_ws(s, c + 1);
    proof {
        assert forall|j: int, m: Member| #[trigger] member_at(s@, i as int, j, m) implies value_at(s@, d as int, j, m.value) by {
            let d0 = choose|d0: int| #[trigger] ws(s@, c + 1, d0) && value_at(s@, d0, j, m.value);
            lemma_value_start(s@, d0, j, m.value);
            lemma_ws_unique(s@, c + 1, d0, d as int);
        }
    }
    let (v, j) = match value(s, d, limit) {
        Some(r) => r,
        None => {
            proof {
                assert forall|j: int, m: Member| #[trigger] member_at(s@, i as int, j, m) && depth(m.value) <= limit && boundary(s@, j) implies false by {}
            }
            return None;
        }
    };
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

/// The rest of an object whose `{` is at `i - 1`. Complete: an object
/// within the limit limit is found, whole and the same.
// Keep this quantifier-heavy proof independent of earlier solver queries.
#[verifier::spinoff_prover]
#[verifier::loop_isolation(false)]
#[verifier::rlimit(300)]
fn object(s: &[u8], i: usize, limit: u32) -> (out: Option<(Value, usize)>)
    requires 1 <= i <= s.len(), s@[i - 1] == LBRACE,
    ensures match out { Some((v, j)) => i <= j <= s.len() && encodes(s@, i - 1, j as int, v), None => true },
        forall|j: int, ms: Seq<Member>| #[trigger] object_at(s@, i as int, j, ms) && member_depths(ms) <= limit
            ==> (match out { Some((v, jj)) => jj == j && v is Object && same_members(v->Object_0@, ms), None => false }),
    decreases s.len() - i, 2int,
{
    let mut ms: Vec<Member> = Vec::new();
    let a = skip_ws(s, i);
    if a < s.len() && s[a] == RBRACE {
        proof {
            assert(members(s@, i as int, a as int, ms@));
            assert forall|j: int, mss: Seq<Member>| #[trigger] object_at(s@, i as int, j, mss) && member_depths(mss) <= limit
                implies j == a + 1 && same_members(ms@, mss) by {
                lemma_object_first(s@, i as int, j, mss, a as int);
            }
        }
        return Some((Value::Object(ms), a + 1));
    }
    let (first, mut p) = match member(s, i, limit) {
        Some(r) => r,
        None => {
            proof {
                assert forall|j: int, mss: Seq<Member>| #[trigger] object_at(s@, i as int, j, mss) && member_depths(mss) <= limit implies false by {
                    lemma_object_first(s@, i as int, j, mss, a as int);
                }
            }
            return None;
        }
    };
    ms.push(first);
    proof {
        assert(members_ok(s@, i as int, p as int, ms@));
        assert forall|j: int, mss: Seq<Member>| #[trigger] object_at(s@, i as int, j, mss) && member_depths(mss) <= limit
            implies mss.len() >= ms@.len() && same_members(ms@, mss.take(ms@.len() as int))
                && exists|a2: int| #[trigger] ws(s@, p as int, a2) && mstop(s@, a2, j, mss.skip(ms@.len() as int)) by {
            lemma_object_first(s@, i as int, j, mss, a as int);
            let (e, a2) = choose|e: int, a2: int| #[trigger] ws(s@, e, a2) && member_at(s@, i as int, e, mss[0]) && boundary(s@, e) && mstop(s@, a2, j, mss.drop_first());
            assert(first.key@ == mss[0].key@ && same(first.value, mss[0].value));
            assert(ms@[0] == first);
            assert(mss.take(1)[0] == mss[0]);
            assert(mss.take(1).drop_first().len() == 0);
            assert(ms@.drop_first().len() == 0);
            assert(same_members(ms@.drop_first(), mss.take(1).drop_first()));
            assert(same_members(ms@, mss.take(1)));
            assert(mss.skip(1) =~= mss.drop_first());
        }
    }
    loop
        invariant 1 <= i <= p <= s.len(), ms@.len() >= 1, members_ok(s@, i as int, p as int, ms@), s@[i - 1] == LBRACE,
            forall|j: int, mss: Seq<Member>| #[trigger] object_at(s@, i as int, j, mss) && member_depths(mss) <= limit
                ==> mss.len() >= ms@.len() && same_members(ms@, mss.take(ms@.len() as int))
                    && exists|a2: int| #[trigger] ws(s@, p as int, a2) && mstop(s@, a2, j, mss.skip(ms@.len() as int)),
        decreases s.len() - p,
    {
        let c = skip_ws(s, p);
        if c >= s.len() {
            proof {
                assert forall|j: int, mss: Seq<Member>| #[trigger] object_at(s@, i as int, j, mss) && member_depths(mss) <= limit implies false by {
                    lemma_object_next(s@, p as int, c as int, c + 1, j, mss, ms@.len() as int);
                }
            }
            return None;
        }
        if s[c] == RBRACE {
            proof {
                assert(members(s@, i as int, c as int, ms@));
                assert forall|j: int, mss: Seq<Member>| #[trigger] object_at(s@, i as int, j, mss) && member_depths(mss) <= limit
                    implies j == c + 1 && same_members(ms@, mss) by {
                    lemma_object_next(s@, p as int, c as int, c + 1, j, mss, ms@.len() as int);
                    assert(mss.take(ms@.len() as int) =~= mss);
                }
            }
            return Some((Value::Object(ms), c + 1));
        }
        if s[c] != COMMA {
            proof {
                assert forall|j: int, mss: Seq<Member>| #[trigger] object_at(s@, i as int, j, mss) && member_depths(mss) <= limit implies false by {
                    lemma_object_next(s@, p as int, c as int, c + 1, j, mss, ms@.len() as int);
                }
            }
            return None;
        }
        let ghost k = ms@.len() as int;
        proof {
            assert forall|j: int, mss: Seq<Member>| #[trigger] object_at(s@, i as int, j, mss) && member_depths(mss) <= limit
                implies k < mss.len() && depth(mss[k].value) <= limit
                    && exists|e: int, a3: int| #[trigger] ws(s@, e, a3) && member_at(s@, c + 1, e, mss[k]) && boundary(s@, e) && mstop(s@, a3, j, mss.skip(k + 1)) by {
                lemma_object_next(s@, p as int, c as int, c + 1, j, mss, k);
            }
        }
        let (next, q) = match member(s, c + 1, limit) {
            Some(r) => r,
            None => {
                proof {
                    assert forall|j: int, mss: Seq<Member>| #[trigger] object_at(s@, i as int, j, mss) && member_depths(mss) <= limit implies false by {}
                }
                return None;
            }
        };
        let ghost before = ms@;
        ms.push(next);
        proof {
            assert(ms@.drop_last() =~= before);
            assert(ms@.last() == next);
            assert(members_ok(s@, i as int, p as int, ms@.drop_last()));
            assert(ws(s@, p as int, c as int));
            assert(member_ok(s@, c + 1, q as int, ms@.last()));
            assert(members_ok(s@, i as int, q as int, ms@));
            assert forall|j: int, mss: Seq<Member>| #[trigger] object_at(s@, i as int, j, mss) && member_depths(mss) <= limit
                implies mss.len() >= ms@.len() && same_members(ms@, mss.take(ms@.len() as int))
                    && exists|a2: int| #[trigger] ws(s@, q as int, a2) && mstop(s@, a2, j, mss.skip(ms@.len() as int)) by {
                let (e, a3) = choose|e: int, a3: int| #[trigger] ws(s@, e, a3) && member_at(s@, c + 1, e, mss[k]) && boundary(s@, e) && mstop(s@, a3, j, mss.skip(k + 1));
                assert(next.key@ == mss[k].key@ && same(next.value, mss[k].value));
                lemma_same_members_push(before, mss.take(k), next, mss[k]);
                assert(mss.take(k).push(mss[k]) =~= mss.take(k + 1));
                assert(ms@ =~= before.push(next));
            }
        }
        p = q;
    }
}

/// Read one JSON document. Sound: `Some(v)` only when `bytes` is `v` with
/// whitespace around it and nothing else. Complete: when `bytes` is some
/// value `v` of the grammar nested at most `MAX_DEPTH` deep, the result is
/// `Some` of a value the same as `v`. Together: the reader accepts exactly
/// the grammar, within the depth limit, and returns its value.
pub fn parse(bytes: &[u8]) -> (out: Option<Value>)
    ensures match out { Some(v) => document(bytes@, v), None => true },
        forall|v: Value| #[trigger] document(bytes@, v) && depth(v) <= MAX_DEPTH ==> (match out { Some(w) => same(w, v), None => false }),
{
    let i = skip_ws(bytes, 0);
    proof {
        assert forall|v: Value| #[trigger] document(bytes@, v) implies exists|j: int| #[trigger] value_at(bytes@, i as int, j, v) && boundary(bytes@, j) && ws(bytes@, j, bytes@.len() as int) by {
            let (i0, j0) = choose|i0: int, j0: int| ws(bytes@, 0, i0) && #[trigger] encodes(bytes@, i0, j0, v) && ws(bytes@, j0, bytes@.len() as int);
            lemma_value_start(bytes@, i0, j0, v);
            lemma_ws_unique(bytes@, 0, i0, i as int);
            if j0 < bytes@.len() { assert(is_ws(bytes@[j0])); }
            assert(value_at(bytes@, i as int, j0, v) && boundary(bytes@, j0));
        }
    }
    let (v, j) = match value(bytes, i, MAX_DEPTH) {
        Some(r) => r,
        None => {
            proof { assert forall|v: Value| #[trigger] document(bytes@, v) && depth(v) <= MAX_DEPTH implies false by {} }
            return None;
        }
    };
    let k = skip_ws(bytes, j);
    proof {
        assert forall|w: Value| #[trigger] document(bytes@, w) && depth(w) <= MAX_DEPTH implies k == bytes@.len() && same(v, w) by {
            let j0 = choose|j0: int| #[trigger] value_at(bytes@, i as int, j0, w) && boundary(bytes@, j0) && ws(bytes@, j0, bytes@.len() as int);
            lemma_ws_unique(bytes@, j as int, bytes@.len() as int, k as int);
        }
    }
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

// ---- writing ------------------------------------------------------------------------------

/// Every number lexeme in `v` satisfies the number grammar. Values the reader
/// returns are well formed (soundness), as are the numbers `Value::from_u64`
/// builds; the writer refuses any other number.
pub open spec fn well_formed(v: Value) -> bool
    decreases v, 0int,
{
    match v {
        Value::Number(lex) => number_ok(lex@),
        Value::Array(items) => well_formed_items(items@),
        Value::Object(ms) => well_formed_members(ms@),
        _ => true,
    }
}
pub open spec fn well_formed_items(items: Seq<Value>) -> bool
    decreases items, 1int,
{
    items.len() == 0 || (well_formed(items.last()) && well_formed_items(items.drop_last()))
}
pub open spec fn well_formed_members(ms: Seq<Member>) -> bool
    decreases ms, 1int,
{
    ms.len() == 0 || (well_formed(ms.last().value) && well_formed_members(ms.drop_last()))
}
proof fn lemma_well_formed_item(items: Seq<Value>, k: int)
    requires well_formed_items(items), 0 <= k < items.len(),
    ensures well_formed(items[k]),
    decreases items.len(),
{
    if k < items.len() - 1 {
        lemma_well_formed_item(items.drop_last(), k);
        assert(items.drop_last()[k] == items[k]);
    }
}
proof fn lemma_well_formed_member(ms: Seq<Member>, k: int)
    requires well_formed_members(ms), 0 <= k < ms.len(),
    ensures well_formed(ms[k].value),
    decreases ms.len(),
{
    if k < ms.len() - 1 {
        lemma_well_formed_member(ms.drop_last(), k);
        assert(ms.drop_last()[k] == ms[k]);
    }
}

/// `t` begins with `s`. The grammar only looks at bytes inside the span it
/// is asked about, so what holds of a span of `s` holds of the same span of
/// `t`; the writer appends and keeps what it has already established.
pub open spec fn extends(s: Seq<u8>, t: Seq<u8>) -> bool {
    s.len() <= t.len() && forall|k: int| 0 <= k < s.len() ==> #[trigger] t[k] == s[k]
}
proof fn lemma_extends_trans(a: Seq<u8>, b: Seq<u8>, c: Seq<u8>)
    requires extends(a, b), extends(b, c),
    ensures extends(a, c),
{
    assert forall|k: int| 0 <= k < a.len() implies #[trigger] c[k] == a[k] by { assert(b[k] == a[k]); }
}
proof fn lemma_ws_extends(s: Seq<u8>, t: Seq<u8>, i: int, j: int)
    requires extends(s, t), ws(s, i, j),
    ensures ws(t, i, j),
{
    assert forall|k: int| i <= k < j implies is_ws(#[trigger] t[k]) by { assert(t[k] == s[k]); }
}
proof fn lemma_string_at_extends(s: Seq<u8>, t: Seq<u8>, i: int, j: int, text: Seq<u8>)
    requires extends(s, t), string_at(s, i, j, text),
    ensures string_at(t, i, j, text),
{
    assert(t.subrange(i + 1, j - 1) =~= s.subrange(i + 1, j - 1));
}
proof fn lemma_encodes_extends(s: Seq<u8>, t: Seq<u8>, i: int, j: int, v: Value)
    requires extends(s, t), encodes(s, i, j, v),
    ensures encodes(t, i, j, v),
    decreases v, 0int,
{
    assert(t.subrange(i, j) =~= s.subrange(i, j));
    match v {
        Value::Str(text) => lemma_string_at_extends(s, t, i, j, text@),
        Value::Array(items) => lemma_elements_extends(s, t, i + 1, j - 1, items@),
        Value::Object(ms) => lemma_members_extends(s, t, i + 1, j - 1, ms@),
        _ => {}
    }
}
proof fn lemma_padded_extends(s: Seq<u8>, t: Seq<u8>, i: int, j: int, v: Value)
    requires extends(s, t), padded(s, i, j, v),
    ensures padded(t, i, j, v),
    decreases v, 1int,
{
    let d = choose|d: int| #[trigger] ws(s, i, d) && encodes(s, d, j, v);
    lemma_ws_extends(s, t, i, d);
    lemma_encodes_extends(s, t, d, j, v);
    assert(ws(t, i, d) && encodes(t, d, j, v));
}
proof fn lemma_items_ok_extends(s: Seq<u8>, t: Seq<u8>, i: int, j: int, items: Seq<Value>)
    requires extends(s, t), items_ok(s, i, j, items),
    ensures items_ok(t, i, j, items),
    decreases items, 3int,
{
    if items.len() == 1 {
        lemma_padded_extends(s, t, i, j, items[0]);
    } else {
        let (c, a) = choose|c: int, a: int| items_ok(s, i, c, items.drop_last()) && #[trigger] ws(s, c, a) && a < s.len() && s[a] == COMMA
            && padded(s, a + 1, j, items.last());
        lemma_items_ok_extends(s, t, i, c, items.drop_last());
        lemma_ws_extends(s, t, c, a);
        lemma_padded_extends(s, t, a + 1, j, items.last());
        assert(t[a] == s[a]);
        assert(items_ok(t, i, c, items.drop_last()) && ws(t, c, a) && a < t.len() && t[a] == COMMA && padded(t, a + 1, j, items.last()));
    }
}
proof fn lemma_elements_extends(s: Seq<u8>, t: Seq<u8>, i: int, j: int, items: Seq<Value>)
    requires extends(s, t), elements(s, i, j, items),
    ensures elements(t, i, j, items),
    decreases items, 4int,
{
    if items.len() == 0 {
        lemma_ws_extends(s, t, i, j);
    } else {
        let b = choose|b: int| items_ok(s, i, b, items) && #[trigger] ws(s, b, j);
        lemma_items_ok_extends(s, t, i, b, items);
        lemma_ws_extends(s, t, b, j);
        assert(items_ok(t, i, b, items) && ws(t, b, j));
    }
}
proof fn lemma_colon_then_extends(s: Seq<u8>, t: Seq<u8>, b: int, j: int, v: Value)
    requires extends(s, t), colon_then(s, b, j, v),
    ensures colon_then(t, b, j, v),
    decreases v, 2int,
{
    let c = choose|c: int| #[trigger] ws(s, b, c) && c < s.len() && s[c] == COLON && padded(s, c + 1, j, v);
    lemma_ws_extends(s, t, b, c);
    lemma_padded_extends(s, t, c + 1, j, v);
    assert(t[c] == s[c]);
    assert(ws(t, b, c) && c < t.len() && t[c] == COLON && padded(t, c + 1, j, v));
}
proof fn lemma_key_then_extends(s: Seq<u8>, t: Seq<u8>, a: int, j: int, m: Member)
    requires extends(s, t), key_then(s, a, j, m),
    ensures key_then(t, a, j, m),
    decreases m, 2int,
{
    let b = choose|b: int| #[trigger] string_at(s, a, b, m.key@) && colon_then(s, b, j, m.value);
    lemma_string_at_extends(s, t, a, b, m.key@);
    lemma_colon_then_extends(s, t, b, j, m.value);
    assert(string_at(t, a, b, m.key@) && colon_then(t, b, j, m.value));
}
proof fn lemma_member_ok_extends(s: Seq<u8>, t: Seq<u8>, i: int, j: int, m: Member)
    requires extends(s, t), member_ok(s, i, j, m),
    ensures member_ok(t, i, j, m),
    decreases m, 3int,
{
    let a = choose|a: int| #[trigger] ws(s, i, a) && key_then(s, a, j, m);
    lemma_ws_extends(s, t, i, a);
    lemma_key_then_extends(s, t, a, j, m);
    assert(ws(t, i, a) && key_then(t, a, j, m));
}
proof fn lemma_members_ok_extends(s: Seq<u8>, t: Seq<u8>, i: int, j: int, ms: Seq<Member>)
    requires extends(s, t), members_ok(s, i, j, ms),
    ensures members_ok(t, i, j, ms),
    decreases ms, 4int,
{
    if ms.len() == 1 {
        lemma_member_ok_extends(s, t, i, j, ms[0]);
    } else {
        let (c, a) = choose|c: int, a: int| members_ok(s, i, c, ms.drop_last()) && #[trigger] ws(s, c, a) && a < s.len() && s[a] == COMMA
            && member_ok(s, a + 1, j, ms.last());
        lemma_members_ok_extends(s, t, i, c, ms.drop_last());
        lemma_ws_extends(s, t, c, a);
        lemma_member_ok_extends(s, t, a + 1, j, ms.last());
        assert(t[a] == s[a]);
        assert(members_ok(t, i, c, ms.drop_last()) && ws(t, c, a) && a < t.len() && t[a] == COMMA && member_ok(t, a + 1, j, ms.last()));
    }
}
proof fn lemma_members_extends(s: Seq<u8>, t: Seq<u8>, i: int, j: int, ms: Seq<Member>)
    requires extends(s, t), members(s, i, j, ms),
    ensures members(t, i, j, ms),
    decreases ms, 5int,
{
    if ms.len() == 0 {
        lemma_ws_extends(s, t, i, j);
    } else {
        let b = choose|b: int| members_ok(s, i, b, ms) && #[trigger] ws(s, b, j);
        lemma_members_ok_extends(s, t, i, b, ms);
        lemma_ws_extends(s, t, b, j);
        assert(members_ok(t, i, b, ms) && ws(t, b, j));
    }
}

/// The canonical decimal of any `n` is a number of the grammar.
pub proof fn lemma_decimal_number_ok(n: nat)
    ensures number_ok(crate::inbound::decimal(n)),
{
    crate::inbound::lemma_decimal_shape(n);
    let s = crate::inbound::decimal(n);
    let len = s.len() as int;
    assert(s.subrange(0, len) =~= s);
    assert forall|k: int| 0 <= k < s.len() implies is_digit(#[trigger] s[k]) by { assert(crate::inbound::is_digit(s[k])); }
    assert(all_digits(s));
    assert(s[0] != MINUS);
    if n == 0 { assert(s =~= seq![48u8]); }
    assert(int_ok(s));
    assert(s.subrange(len, len).len() == 0);
    assert(frac_ok(s.subrange(len, len)));
    assert(exp_ok(s.subrange(len, len)));
    assert(int_ok(s.subrange(0, len)) && frac_ok(s.subrange(len, len)) && exp_ok(s.subrange(len, len)));
}
/// `00XY` in hex, for two nibbles.
proof fn lemma_two_nibbles(h: Seq<u8>, d1: nat, d0: nat)
    requires d1 < 16, d0 < 16, h == seq![ZERO, ZERO, crate::http1_chunked::hex_digit(d1), crate::http1_chunked::hex_digit(d0)],
    ensures crate::http1_chunked::all_hex(h), crate::http1_chunked::hex_value(h) == d1 * 16 + d0,
{
    let h3 = seq![ZERO, ZERO, crate::http1_chunked::hex_digit(d1)];
    let h2 = seq![ZERO, ZERO];
    let h1 = seq![ZERO];
    assert(h.drop_last() =~= h3);
    assert(h3.drop_last() =~= h2);
    assert(h2.drop_last() =~= h1);
    assert(h1.drop_last() =~= Seq::<u8>::empty());
    assert(crate::http1_chunked::hex_value(Seq::<u8>::empty()) == 0);
    assert(h1.last() == ZERO && crate::http1_chunked::hex_val(ZERO) == 0);
    assert(crate::http1_chunked::hex_value(h1) == 0);
    assert(crate::http1_chunked::hex_value(h2) == 0);
    assert(crate::http1_chunked::hex_val(crate::http1_chunked::hex_digit(d1)) == d1);
    assert(crate::http1_chunked::hex_val(crate::http1_chunked::hex_digit(d0)) == d0);
    assert(crate::http1_chunked::hex_value(h3) == d1);
    assert forall|k: int| 0 <= k < h.len() implies crate::http1_chunked::is_hex(#[trigger] h[k]) by {}
}

fn hex_digit_exec(d: u8) -> (out: u8)
    requires d < 16,
    ensures out == crate::http1_chunked::hex_digit(d as nat),
{
    if d < 10 { 48 + d } else { 87 + d }
}
/// Whether `lex` is a number of the grammar, decided by the reader's scanner.
fn number_ok_exec(lex: &[u8]) -> (out: bool)
    ensures out == number_ok(lex@),
{
    if lex.len() == 0 {
        proof {
            assert forall|a: int| 0 <= a <= lex@.len() implies !int_ok(#[trigger] lex@.subrange(0, a)) by {
                assert(lex@.subrange(0, a).len() == 0);
            }
        }
        return false;
    }
    let scanned = number(lex, 0);
    proof {
        assert(lex@.subrange(0, lex@.len() as int) =~= lex@);
        assert(boundary(lex@, lex@.len() as int));
    }
    match scanned { Some(j) => j == lex.len(), None => false }
}

/// A decoded body extended by one plain byte.
proof fn lemma_push_plain(s: Seq<u8>, start: int, before: Seq<u8>, text: Seq<u8>, k: int, b: u8)
    requires 0 <= start, start + 1 <= before.len(), s == before.push(b), plain(b), 0 <= k < text.len(), text[k] == b,
        string_body(before.subrange(start + 1, before.len() as int), text.subrange(0, k)),
    ensures string_body(s.subrange(start + 1, s.len() as int), text.subrange(0, k + 1)),
{
    lemma_plain_body(b);
    lemma_body_append(before.subrange(start + 1, before.len() as int), text.subrange(0, k), seq![b], seq![b]);
    assert(s.subrange(start + 1, s.len() as int) =~= before.subrange(start + 1, before.len() as int) + seq![b]);
    assert(text.subrange(0, k + 1) =~= text.subrange(0, k) + seq![b]);
}
/// A decoded body extended by one escape sequence standing for `b`.
proof fn lemma_push_escape(s: Seq<u8>, start: int, before: Seq<u8>, esc: Seq<u8>, text: Seq<u8>, k: int, b: u8)
    requires 0 <= start, start + 1 <= before.len(), s == before + esc, escape(esc, seq![b]), 0 <= k < text.len(), text[k] == b,
        string_body(before.subrange(start + 1, before.len() as int), text.subrange(0, k)),
    ensures string_body(s.subrange(start + 1, s.len() as int), text.subrange(0, k + 1)),
{
    lemma_escape_body(esc, seq![b]);
    lemma_body_append(before.subrange(start + 1, before.len() as int), text.subrange(0, k), esc, seq![b]);
    assert(s.subrange(start + 1, s.len() as int) =~= before.subrange(start + 1, before.len() as int) + esc);
    assert(text.subrange(0, k + 1) =~= text.subrange(0, k) + seq![b]);
}

/// One string, quoted and escaped: plain bytes as themselves, the quote,
/// backslash, and the five named controls as two-character escapes, other
/// control bytes as `\u00XX`.
#[verifier::loop_isolation(false)]
#[verifier::rlimit(100)]
fn emit_string(text: &[u8], out: &mut Vec<u8>)
    ensures extends(old(out)@, final(out)@), string_at(final(out)@, old(out)@.len() as int, final(out)@.len() as int, text@),
{
    let ghost start = old(out)@.len() as int;
    out.push(QUOTE);
    let mut k: usize = 0;
    proof {
        assert(out@.subrange(start + 1, out@.len() as int).len() == 0);
        assert(text@.subrange(0, 0).len() == 0);
    }
    while k < text.len()
        invariant k <= text.len(), extends(old(out)@, out@), out@.len() >= start + 1, out@[start] == QUOTE,
            string_body(out@.subrange(start + 1, out@.len() as int), text@.subrange(0, k as int)),
        decreases text.len() - k,
    {
        let b = text[k];
        let ghost before = out@;
        if b >= 0x20 && b != QUOTE && b != BSLASH {
            out.push(b);
            proof { lemma_push_plain(out@, start, before, text@, k as int, b); }
        } else if b == QUOTE || b == BSLASH || b == LF || b == CR || b == TAB || b == 8 || b == 12 {
            let second = if b == QUOTE { QUOTE } else if b == BSLASH { BSLASH } else if b == LF { LOWER_N } else if b == CR { LOWER_R }
                else if b == TAB { LOWER_T } else if b == 8 { LOWER_B } else { LOWER_F };
            out.push(BSLASH);
            out.push(second);
            proof {
                let esc = seq![BSLASH, second];
                assert(out@ =~= before + esc);
                assert(simple_escape(second) == Some(b));
                assert(escape(esc, seq![b]));
                lemma_push_escape(out@, start, before, esc, text@, k as int, b);
            }
        } else {
            let high = hex_digit_exec(b / 16);
            let low = hex_digit_exec(b % 16);
            out.push(BSLASH);
            out.push(LOWER_U);
            out.push(ZERO);
            out.push(ZERO);
            out.push(high);
            out.push(low);
            proof {
                let esc = seq![BSLASH, LOWER_U, ZERO, ZERO, high, low];
                assert(out@ =~= before + esc);
                let h = esc.subrange(2, 6);
                assert(h =~= seq![ZERO, ZERO, crate::http1_chunked::hex_digit((b / 16) as nat), crate::http1_chunked::hex_digit((b % 16) as nat)]);
                lemma_two_nibbles(h, (b / 16) as nat, (b % 16) as nat);
                assert(unit(esc, 2) == b as nat);
                assert(utf8(b as nat) =~= seq![b]);
                assert(escape(esc, seq![b]));
                lemma_push_escape(out@, start, before, esc, text@, k as int, b);
            }
        }
        proof { lemma_extends_trans(old(out)@, before, out@); }
        k = k + 1;
    }
    let ghost before = out@;
    out.push(QUOTE);
    proof {
        assert(text@.subrange(0, text@.len() as int) =~= text@);
        assert(out@.subrange(start + 1, out@.len() - 1) =~= before.subrange(start + 1, before.len() as int));
        lemma_extends_trans(old(out)@, before, out@);
    }
}

/// Append `v`. `ok` exactly when `v` is well formed; then the appended bytes
/// encode `v`.
#[verifier::rlimit(100)]
fn emit(v: &Value, out: &mut Vec<u8>) -> (ok: bool)
    ensures ok == well_formed(*v), extends(old(out)@, final(out)@),
        ok ==> encodes(final(out)@, old(out)@.len() as int, final(out)@.len() as int, *v),
    decreases *v, 0int,
{
    let ghost start = old(out)@.len() as int;
    match v {
        Value::Null => {
            let w = null_word_bytes();
            crate::framing::append(out, w.as_slice());
            proof { assert(out@.subrange(start, out@.len() as int) =~= null_word()); }
            true
        }
        Value::Bool(b) => {
            let w = if *b { true_word_bytes() } else { false_word_bytes() };
            crate::framing::append(out, w.as_slice());
            proof { assert(out@.subrange(start, out@.len() as int) =~= if *b { true_word() } else { false_word() }); }
            true
        }
        Value::Number(lex) => {
            if !number_ok_exec(lex.as_slice()) { return false; }
            crate::framing::append(out, lex.as_slice());
            proof { assert(out@.subrange(start, out@.len() as int) =~= lex@); }
            true
        }
        Value::Str(text) => { emit_string(text.as_slice(), out); true }
        Value::Array(items) => { proof { assert(*v == Value::Array(*items)); } emit_array(items, out) }
        Value::Object(ms) => { proof { assert(*v == Value::Object(*ms)); } emit_object(ms, out) }
    }
}
fn null_word_bytes() -> (out: Vec<u8>) ensures out@ == null_word() {
    let mut w: Vec<u8> = Vec::new(); w.push(LOWER_N); w.push(LOWER_U); w.push(108); w.push(108);
    proof { assert(w@ =~= null_word()); }
    w
}
fn true_word_bytes() -> (out: Vec<u8>) ensures out@ == true_word() {
    let mut w: Vec<u8> = Vec::new(); w.push(LOWER_T); w.push(LOWER_R); w.push(LOWER_U); w.push(LOWER_E);
    proof { assert(w@ =~= true_word()); }
    w
}
fn false_word_bytes() -> (out: Vec<u8>) ensures out@ == false_word() {
    let mut w: Vec<u8> = Vec::new(); w.push(LOWER_F); w.push(97); w.push(108); w.push(115); w.push(LOWER_E);
    proof { assert(w@ =~= false_word()); }
    w
}

#[verifier::loop_isolation(false)]
#[verifier::rlimit(300)]
fn emit_array(items: &Vec<Value>, out: &mut Vec<u8>) -> (ok: bool)
    ensures ok == well_formed_items(items@), extends(old(out)@, final(out)@),
        ok ==> encodes(final(out)@, old(out)@.len() as int, final(out)@.len() as int, Value::Array(*items)),
    decreases items@, 1int,
{
    let ghost start = old(out)@.len() as int;
    out.push(LBRACKET);
    let mut k: usize = 0;
    while k < items.len()
        invariant k <= items.len(), extends(old(out)@, out@), out@.len() >= start + 1, out@[start] == LBRACKET,
            k == 0 ==> out@.len() == start + 1,
            k >= 1 ==> items_ok(out@, start + 1, out@.len() as int, items@.subrange(0, k as int)),
            well_formed_items(items@.subrange(0, k as int)),
        decreases items.len() - k,
    {
        let ghost b0 = out@;
        if k > 0 { out.push(COMMA); }
        let ghost b1 = out@;
        let slice = items.as_slice();
        let item = slice_index_get(slice, k);
        proof { assert(*item == items@[k as int]); }
        let ok = emit(item, out);
        proof {
            lemma_extends_trans(old(out)@, b0, b1);
            lemma_extends_trans(old(out)@, b1, out@);
        }
        if !ok {
            proof { if well_formed_items(items@) { lemma_well_formed_item(items@, k as int); } }
            return false;
        }
        proof {
            let p = b1.len() as int;
            let q = out@.len() as int;
            let next = items@.subrange(0, k + 1);
            assert(next.drop_last() =~= items@.subrange(0, k as int));
            assert(next.last() == items@[k as int]);
            assert(ws(out@, p, p));
            assert(padded(out@, p, q, items@[k as int]));
            if k == 0 {
                assert(next.len() == 1 && next[0] == items@[0]);
                assert(items_ok(out@, start + 1, q, next));
            } else {
                let c = b0.len() as int;
                lemma_items_ok_extends(b0, out@, start + 1, c, items@.subrange(0, k as int));
                assert(ws(out@, c, c));
                assert(out@[c] == COMMA);
                assert(items_ok(out@, start + 1, q, next));
            }
        }
        k = k + 1;
    }
    let ghost b2 = out@;
    out.push(RBRACKET);
    proof {
        let j = out@.len() as int;
        assert(items@.subrange(0, items@.len() as int) =~= items@);
        lemma_extends_trans(old(out)@, b2, out@);
        if items.len() == 0 {
            assert(ws(out@, start + 1, j - 1));
        } else {
            lemma_items_ok_extends(b2, out@, start + 1, j - 1, items@);
            assert(ws(out@, j - 1, j - 1));
            assert(elements(out@, start + 1, j - 1, items@));
        }
    }
    true
}

#[verifier::loop_isolation(false)]
#[verifier::rlimit(300)]
fn emit_object(ms: &Vec<Member>, out: &mut Vec<u8>) -> (ok: bool)
    ensures ok == well_formed_members(ms@), extends(old(out)@, final(out)@),
        ok ==> encodes(final(out)@, old(out)@.len() as int, final(out)@.len() as int, Value::Object(*ms)),
    decreases ms@, 1int,
{
    let ghost start = old(out)@.len() as int;
    out.push(LBRACE);
    let mut k: usize = 0;
    while k < ms.len()
        invariant k <= ms.len(), extends(old(out)@, out@), out@.len() >= start + 1, out@[start] == LBRACE,
            k == 0 ==> out@.len() == start + 1,
            k >= 1 ==> members_ok(out@, start + 1, out@.len() as int, ms@.subrange(0, k as int)),
            well_formed_members(ms@.subrange(0, k as int)),
        decreases ms.len() - k,
    {
        let ghost b0 = out@;
        if k > 0 { out.push(COMMA); }
        let ghost b1 = out@;
        let slice = ms.as_slice();
        let m = slice_index_get(slice, k);
        proof { assert(*m == ms@[k as int]); }
        emit_string(m.key.as_slice(), out);
        let ghost b2 = out@;
        out.push(COLON);
        let ghost b3 = out@;
        let ok = emit(&m.value, out);
        proof {
            lemma_extends_trans(old(out)@, b0, b1);
            lemma_extends_trans(b1, b2, b3);
            lemma_extends_trans(b1, b3, out@);
            lemma_extends_trans(old(out)@, b1, out@);
        }
        if !ok {
            proof { if well_formed_members(ms@) { lemma_well_formed_member(ms@, k as int); } }
            return false;
        }
        proof {
            let i = b1.len() as int;
            let bpos = b2.len() as int;
            let q = out@.len() as int;
            lemma_extends_trans(b2, b3, out@);
            lemma_string_at_extends(b2, out@, i, bpos, m.key@);
            assert(out@[bpos] == COLON);
            assert(ws(out@, bpos + 1, bpos + 1));
            assert(padded(out@, bpos + 1, q, m.value));
            assert(ws(out@, bpos, bpos));
            assert(colon_then(out@, bpos, q, m.value));
            assert(key_then(out@, i, q, *m));
            assert(ws(out@, i, i));
            assert(member_ok(out@, i, q, *m));
            let next = ms@.subrange(0, k + 1);
            assert(next.drop_last() =~= ms@.subrange(0, k as int));
            assert(next.last() == ms@[k as int]);
            if k == 0 {
                assert(next.len() == 1 && next[0] == ms@[0]);
                assert(members_ok(out@, start + 1, q, next));
            } else {
                let c = b0.len() as int;
                lemma_members_ok_extends(b0, out@, start + 1, c, ms@.subrange(0, k as int));
                assert(ws(out@, c, c));
                assert(out@[c] == COMMA);
                assert(members_ok(out@, start + 1, q, next));
            }
        }
        k = k + 1;
    }
    let ghost b2 = out@;
    out.push(RBRACE);
    proof {
        let j = out@.len() as int;
        assert(ms@.subrange(0, ms@.len() as int) =~= ms@);
        lemma_extends_trans(old(out)@, b2, out@);
        if ms.len() == 0 {
            assert(ws(out@, start + 1, j - 1));
        } else {
            lemma_members_ok_extends(b2, out@, start + 1, j - 1, ms@);
            assert(ws(out@, j - 1, j - 1));
            assert(members(out@, start + 1, j - 1, ms@));
        }
    }
    true
}

/// Write `v` as one compact document: no whitespace, strings escaped,
/// numbers as their lexeme. `Some` exactly when `v` is well formed, and
/// then the bytes are `v` and nothing else, so the reader gives `v` back
/// (`round_trip`).
pub fn write(v: &Value) -> (out: Option<Vec<u8>>)
    ensures out is Some <==> well_formed(*v),
        match out { Some(s) => encodes(s@, 0, s@.len() as int, *v) && document(s@, *v), None => true },
{
    let mut bytes: Vec<u8> = Vec::new();
    if emit(v, &mut bytes) {
        proof {
            assert(ws(bytes@, 0, 0));
            assert(ws(bytes@, bytes@.len() as int, bytes@.len() as int));
        }
        Some(bytes)
    } else {
        None
    }
}

/// Writing then reading gives the value back: the writer's theorem and the
/// reader's completeness, composed.
pub fn round_trip(v: &Value) -> (out: Option<Value>)
    requires well_formed(*v), depth(*v) <= MAX_DEPTH,
    ensures match out { Some(w) => same(w, *v), None => false },
{
    match write(v) { Some(bytes) => parse(bytes.as_slice()), None => None }
}

impl Value {
    /// The number whose lexeme is the canonical decimal of `n`; `as_u64`
    /// reads it back and the writer accepts it.
    pub fn from_u64(n: u64) -> (out: Value)
        ensures out is Number, out->Number_0@ == crate::inbound::decimal(n as nat), well_formed(out),
    {
        let lex = crate::http1_exchange::decimal_bytes(n);
        proof { lemma_decimal_number_ok(n as nat); }
        Value::Number(lex)
    }
}
} // verus!
