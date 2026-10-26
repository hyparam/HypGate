//! Base64url (RFC 4648 section 5) without padding, as compact JWS segments
//! use it. The encoding is a spec over byte sequences; the encoder produces
//! exactly it, and the decoder is proved to be its inverse: a text decodes to
//! `b` if and only if, once trailing `=` is dropped, it is the encoding of
//! `b`. Non-canonical texts, with leftover bits set or a length of one more
//! than a multiple of four, are no encoding of anything and are refused.
use vstd::prelude::*;

verus! {

/// The alphabet character for a six-bit value.
pub open spec fn alphabet(v: int) -> u8 {
    if v < 26 { (65 + v) as u8 } else if v < 52 { (97 + v - 26) as u8 } else if v < 62 { (48 + v - 52) as u8 } else if v == 62 { 45 } else { 95 }
}

/// The six-bit value of an alphabet character.
pub open spec fn value_of(c: u8) -> Option<int> {
    if 65 <= c <= 90 { Some(c - 65) } else if 97 <= c <= 122 { Some(c - 97 + 26) } else if 48 <= c <= 57 { Some(c - 48 + 52) }
    else if c == 45 { Some(62) } else if c == 95 { Some(63) } else { None }
}

/// The encoding of `s`: four characters per three bytes, two or three for a
/// one or two byte tail, no padding.
pub open spec fn encoded(s: Seq<u8>) -> Seq<u8>
    decreases s.len(),
{
    if s.len() == 0 { Seq::empty() }
    else if s.len() == 1 { seq![alphabet((s[0] >> 2) as int), alphabet(((s[0] & 3) << 4) as int)] }
    else if s.len() == 2 { seq![alphabet((s[0] >> 2) as int), alphabet((((s[0] & 3) << 4) | (s[1] >> 4)) as int), alphabet(((s[1] & 15) << 2) as int)] }
    else {
        seq![alphabet((s[0] >> 2) as int), alphabet((((s[0] & 3) << 4) | (s[1] >> 4)) as int),
             alphabet((((s[1] & 15) << 2) | (s[2] >> 6)) as int), alphabet((s[2] & 63) as int)] + encoded(s.skip(3))
    }
}

/// `t` without its trailing `=` characters.
pub open spec fn stripped(t: Seq<u8>) -> Seq<u8>
    decreases t.len(),
{
    if t.len() > 0 && t.last() == 61 { stripped(t.drop_last()) } else { t }
}

/// Short byte sequences, named so they can trigger quantifiers.
pub open spec fn group1(b0: u8) -> Seq<u8> { seq![b0] }
pub open spec fn group2(b0: u8, b1: u8) -> Seq<u8> { seq![b0, b1] }
pub open spec fn group3(b0: u8, b1: u8, b2: u8) -> Seq<u8> { seq![b0, b1, b2] }

pub proof fn lemma_encoded_len(s: Seq<u8>)
    ensures encoded(s).len() == 4 * (s.len() / 3) + (if s.len() % 3 == 0 { 0 } else { s.len() % 3 + 1 }),
    decreases s.len(),
{
    if s.len() >= 3 { lemma_encoded_len(s.skip(3)); }
}

/// Encoding is by groups of three: a prefix of whole groups encodes on its own.
pub proof fn lemma_encoded_append(a: Seq<u8>, b: Seq<u8>)
    requires a.len() % 3 == 0,
    ensures encoded(a + b) == encoded(a) + encoded(b),
    decreases a.len(),
{
    if a.len() == 0 {
        assert(a + b =~= b);
        assert(encoded(a) + encoded(b) =~= encoded(b));
    } else {
        assert((a + b).skip(3) =~= a.skip(3) + b);
        lemma_encoded_append(a.skip(3), b);
        assert(encoded(a + b) =~= encoded(a) + encoded(b));
    }
}

pub proof fn lemma_split(b: Seq<u8>, m: int)
    requires 0 <= m <= b.len(), m % 3 == 0,
    ensures encoded(b) == encoded(b.take(m)) + encoded(b.skip(m)),
{
    assert(b =~= b.take(m) + b.skip(m));
    lemma_encoded_append(b.take(m), b.skip(m));
}

/// What the text after position `i` says about the bytes after position
/// `m`, when the first `m` bytes encode the first `i` characters.
proof fn lemma_rest(b: Seq<u8>, t: Seq<u8>, m: int, i: int)
    requires encoded(b) == t, 0 <= m <= b.len(), m % 3 == 0, 0 <= i <= t.len(), encoded(b.take(m)) == t.take(i),
    ensures
        t.len() - i >= 4 ==> b.len() >= m + 3 && t.subrange(i, i + 4) == encoded(group3(b[m], b[m + 1], b[m + 2])),
        t.len() - i == 0 ==> b.len() == m,
        t.len() - i == 1 ==> false,
        t.len() - i == 2 ==> b.len() == m + 1 && t.skip(i) == encoded(group1(b[m])),
        t.len() - i == 3 ==> b.len() == m + 2 && t.skip(i) == encoded(group2(b[m], b[m + 1])),
{
    lemma_split(b, m);
    let r = b.skip(m);
    assert(encoded(r) =~= t.skip(i));
    lemma_encoded_len(r);
    if t.len() - i >= 4 {
        assert(r.len() >= 3);
        let g = group3(b[m], b[m + 1], b[m + 2]);
        assert(encoded(g.skip(3)) =~= Seq::<u8>::empty());
        assert(t.subrange(i, i + 4) =~= encoded(g));
    } else {
        assert(r.len() < 3);
        if r.len() == 1 { assert(r =~= group1(b[m])); }
        if r.len() == 2 { assert(r =~= group2(b[m], b[m + 1])); }
    }
}

/// The six-bit pieces of three bytes are six-bit values, and the pieces that
/// end a short tail have their low bits clear.
proof fn lemma_pieces(b0: u8, b1: u8, b2: u8)
    ensures b0 >> 2 < 64, ((b0 & 3) << 4) | (b1 >> 4) < 64, ((b1 & 15) << 2) | (b2 >> 6) < 64, b2 & 63 < 64,
        (b0 & 3) << 4 < 64, ((b0 & 3) << 4) & 15 == 0, (b1 & 15) << 2 < 64, ((b1 & 15) << 2) & 3 == 0,
{
    assert(b0 >> 2 < 64 && ((b0 & 3) << 4) | (b1 >> 4) < 64 && ((b1 & 15) << 2) | (b2 >> 6) < 64 && b2 & 63 < 64
        && (b0 & 3) << 4 < 64 && ((b0 & 3) << 4) & 15 == 0 && (b1 & 15) << 2 < 64 && ((b1 & 15) << 2) & 3 == 0) by (bit_vector);
}

pub proof fn lemma_value_alphabet(v: int)
    requires 0 <= v < 64,
    ensures value_of(alphabet(v)) == Some(v),
{
}

pub proof fn lemma_alphabet_value(c: u8)
    requires value_of(c) is Some,
    ensures alphabet(value_of(c).unwrap()) == c,
{
}

fn alphabet_exec(v: u8) -> (out: u8)
    requires v < 64,
    ensures out == alphabet(v as int),
{
    if v < 26 { 65 + v } else if v < 52 { 97 + (v - 26) } else if v < 62 { 48 + (v - 52) } else if v == 62 { 45 } else { 95 }
}

fn value_exec(c: u8) -> (out: Option<u8>)
    ensures out is Some <==> value_of(c) is Some, out is Some ==> out.unwrap() < 64 && out.unwrap() as int == value_of(c).unwrap(),
{
    if 65 <= c && c <= 90 { Some(c - 65) } else if 97 <= c && c <= 122 { Some(c - 97 + 26) } else if 48 <= c && c <= 57 { Some(c - 48 + 52) }
    else if c == 45 { Some(62) } else if c == 95 { Some(63) } else { None }
}

/// The encoding of `bytes`.
pub fn encode(bytes: &[u8]) -> (out: Vec<u8>)
    ensures out@ == encoded(bytes@),
{
    let mut out: Vec<u8> = Vec::new();
    let mut i: usize = 0;
    proof { assert(bytes@.skip(0) =~= bytes@); }
    while bytes.len() - i >= 3
        invariant i <= bytes.len(), encoded(bytes@) == out@ + encoded(bytes@.skip(i as int)),
        decreases bytes.len() - i,
    {
        let (b0, b1, b2) = (bytes[i], bytes[i + 1], bytes[i + 2]);
        let ghost before = out@;
        proof { lemma_pieces(b0, b1, b2); }
        out.push(alphabet_exec(b0 >> 2));
        out.push(alphabet_exec(((b0 & 3) << 4) | (b1 >> 4)));
        out.push(alphabet_exec(((b1 & 15) << 2) | (b2 >> 6)));
        out.push(alphabet_exec(b2 & 63));
        proof {
            let rest = bytes@.skip(i as int);
            assert(rest.skip(3) =~= bytes@.skip(i + 3));
            assert(before + encoded(rest) =~= out@ + encoded(bytes@.skip(i + 3)));
        }
        i = i + 3;
    }
    let ghost before = out@;
    let ghost rest = bytes@.skip(i as int);
    if bytes.len() - i == 1 {
        let b0 = bytes[i];
        proof { lemma_pieces(b0, 0, 0); }
        out.push(alphabet_exec(b0 >> 2));
        out.push(alphabet_exec((b0 & 3) << 4));
        proof { assert(before + encoded(rest) =~= out@); }
    } else if bytes.len() - i == 2 {
        let (b0, b1) = (bytes[i], bytes[i + 1]);
        proof { lemma_pieces(b0, b1, 0); }
        out.push(alphabet_exec(b0 >> 2));
        out.push(alphabet_exec(((b0 & 3) << 4) | (b1 >> 4)));
        out.push(alphabet_exec((b1 & 15) << 2));
        proof { assert(before + encoded(rest) =~= out@); }
    } else {
        proof { assert(before + encoded(rest) =~= out@); }
    }
    out
}

/// Three bytes from four characters: the bytes whose encoding is exactly
/// these characters, if there are any.
fn decode_group(c0: u8, c1: u8, c2: u8, c3: u8) -> (out: Option<(u8, u8, u8)>)
    ensures
        out is Some ==> encoded(group3(out.unwrap().0, out.unwrap().1, out.unwrap().2)) == seq![c0, c1, c2, c3],
        forall|b0: u8, b1: u8, b2: u8| #[trigger] encoded(group3(b0, b1, b2)) == seq![c0, c1, c2, c3] ==> out == Some((b0, b1, b2)),
{
    let (v0, v1, v2, v3) = match (value_exec(c0), value_exec(c1), value_exec(c2), value_exec(c3)) {
        (Some(v0), Some(v1), Some(v2), Some(v3)) => (v0, v1, v2, v3),
        _ => {
            proof {
                assert forall|b0: u8, b1: u8, b2: u8| #[trigger] encoded(group3(b0, b1, b2)) == seq![c0, c1, c2, c3] implies false by {
                    lemma_pieces(b0, b1, b2);
                    lemma_value_alphabet((b0 >> 2) as int);
                    lemma_value_alphabet((((b0 & 3) << 4) | (b1 >> 4)) as int);
                    lemma_value_alphabet((((b1 & 15) << 2) | (b2 >> 6)) as int);
                    lemma_value_alphabet((b2 & 63) as int);
                }
            }
            return None;
        }
    };
    let (x0, x1, x2) = ((v0 << 2) | (v1 >> 4), ((v1 & 15) << 4) | (v2 >> 2), ((v2 & 3) << 6) | v3);
    proof {
        assert(x0 >> 2 == v0 && ((x0 & 3) << 4) | (x1 >> 4) == v1 && ((x1 & 15) << 2) | (x2 >> 6) == v2 && x2 & 63 == v3) by (bit_vector)
            requires v0 < 64, v1 < 64, v2 < 64, v3 < 64, x0 == (v0 << 2) | (v1 >> 4), x1 == ((v1 & 15) << 4) | (v2 >> 2), x2 == ((v2 & 3) << 6) | v3;
        lemma_alphabet_value(c0); lemma_alphabet_value(c1); lemma_alphabet_value(c2); lemma_alphabet_value(c3);
        assert(encoded(group3(x0, x1, x2).skip(3)) =~= Seq::<u8>::empty());
        assert(encoded(group3(x0, x1, x2)) =~= seq![c0, c1, c2, c3]);
        assert forall|b0: u8, b1: u8, b2: u8| #[trigger] encoded(group3(b0, b1, b2)) == seq![c0, c1, c2, c3] implies (x0, x1, x2) == (b0, b1, b2) by {
            lemma_pieces(b0, b1, b2);
            lemma_value_alphabet((b0 >> 2) as int);
            lemma_value_alphabet((((b0 & 3) << 4) | (b1 >> 4)) as int);
            lemma_value_alphabet((((b1 & 15) << 2) | (b2 >> 6)) as int);
            lemma_value_alphabet((b2 & 63) as int);
            assert(v0 == b0 >> 2 && v1 == ((b0 & 3) << 4) | (b1 >> 4) && v2 == ((b1 & 15) << 2) | (b2 >> 6) && v3 == b2 & 63);
            assert(x0 == b0 && x1 == b1 && x2 == b2) by (bit_vector)
                requires x0 == (v0 << 2) | (v1 >> 4), x1 == ((v1 & 15) << 4) | (v2 >> 2), x2 == ((v2 & 3) << 6) | v3,
                    v0 == b0 >> 2, v1 == ((b0 & 3) << 4) | (b1 >> 4), v2 == ((b1 & 15) << 2) | (b2 >> 6), v3 == b2 & 63;
        }
    }
    Some((x0, x1, x2))
}

/// One byte from two characters.
fn decode_tail1(c0: u8, c1: u8) -> (out: Option<u8>)
    ensures
        out is Some ==> encoded(group1(out.unwrap())) == seq![c0, c1],
        forall|b0: u8| #[trigger] encoded(group1(b0)) == seq![c0, c1] ==> out == Some(b0),
{
    let (v0, v1) = match (value_exec(c0), value_exec(c1)) {
        (Some(v0), Some(v1)) if v1 & 15 == 0 => (v0, v1),
        _ => {
            proof {
                assert forall|b0: u8| #[trigger] encoded(group1(b0)) == seq![c0, c1] implies false by {
                    lemma_pieces(b0, 0, 0);
                    lemma_value_alphabet((b0 >> 2) as int);
                    lemma_value_alphabet(((b0 & 3) << 4) as int);
                }
            }
            return None;
        }
    };
    let x0 = (v0 << 2) | (v1 >> 4);
    proof {
        assert(x0 >> 2 == v0 && (x0 & 3) << 4 == v1) by (bit_vector) requires v0 < 64, v1 < 64, v1 & 15 == 0, x0 == (v0 << 2) | (v1 >> 4);
        lemma_alphabet_value(c0); lemma_alphabet_value(c1);
        assert(encoded(group1(x0)) =~= seq![c0, c1]);
        assert forall|b0: u8| #[trigger] encoded(group1(b0)) == seq![c0, c1] implies x0 == b0 by {
            lemma_pieces(b0, 0, 0);
            lemma_value_alphabet((b0 >> 2) as int);
            lemma_value_alphabet(((b0 & 3) << 4) as int);
            assert(v0 == b0 >> 2 && v1 == (b0 & 3) << 4);
            assert(x0 == b0) by (bit_vector) requires x0 == (v0 << 2) | (v1 >> 4), v0 == b0 >> 2, v1 == (b0 & 3) << 4;
        }
    }
    Some(x0)
}

/// Two bytes from three characters.
fn decode_tail2(c0: u8, c1: u8, c2: u8) -> (out: Option<(u8, u8)>)
    ensures
        out is Some ==> encoded(group2(out.unwrap().0, out.unwrap().1)) == seq![c0, c1, c2],
        forall|b0: u8, b1: u8| #[trigger] encoded(group2(b0, b1)) == seq![c0, c1, c2] ==> out == Some((b0, b1)),
{
    let (v0, v1, v2) = match (value_exec(c0), value_exec(c1), value_exec(c2)) {
        (Some(v0), Some(v1), Some(v2)) if v2 & 3 == 0 => (v0, v1, v2),
        _ => {
            proof {
                assert forall|b0: u8, b1: u8| #[trigger] encoded(group2(b0, b1)) == seq![c0, c1, c2] implies false by {
                    lemma_pieces(b0, b1, 0);
                    lemma_value_alphabet((b0 >> 2) as int);
                    lemma_value_alphabet((((b0 & 3) << 4) | (b1 >> 4)) as int);
                    lemma_value_alphabet(((b1 & 15) << 2) as int);
                }
            }
            return None;
        }
    };
    let (x0, x1) = ((v0 << 2) | (v1 >> 4), ((v1 & 15) << 4) | (v2 >> 2));
    proof {
        assert(x0 >> 2 == v0 && ((x0 & 3) << 4) | (x1 >> 4) == v1 && (x1 & 15) << 2 == v2) by (bit_vector)
            requires v0 < 64, v1 < 64, v2 < 64, v2 & 3 == 0, x0 == (v0 << 2) | (v1 >> 4), x1 == ((v1 & 15) << 4) | (v2 >> 2);
        lemma_alphabet_value(c0); lemma_alphabet_value(c1); lemma_alphabet_value(c2);
        assert(encoded(group2(x0, x1)) =~= seq![c0, c1, c2]);
        assert forall|b0: u8, b1: u8| #[trigger] encoded(group2(b0, b1)) == seq![c0, c1, c2] implies (x0, x1) == (b0, b1) by {
            lemma_pieces(b0, b1, 0);
            lemma_value_alphabet((b0 >> 2) as int);
            lemma_value_alphabet((((b0 & 3) << 4) | (b1 >> 4)) as int);
            lemma_value_alphabet(((b1 & 15) << 2) as int);
            assert(v0 == b0 >> 2 && v1 == ((b0 & 3) << 4) | (b1 >> 4) && v2 == (b1 & 15) << 2);
            assert(x0 == b0 && x1 == b1) by (bit_vector)
                requires x0 == (v0 << 2) | (v1 >> 4), x1 == ((v1 & 15) << 4) | (v2 >> 2),
                    v0 == b0 >> 2, v1 == ((b0 & 3) << 4) | (b1 >> 4), v2 == (b1 & 15) << 2;
        }
    }
    Some((x0, x1))
}

/// The bytes `text` encodes, if it is the encoding of some bytes once its
/// trailing `=` are dropped.
pub fn decode(text: &[u8]) -> (out: Option<Vec<u8>>)
    ensures
        out is Some ==> encoded(out.unwrap()@) == stripped(text@),
        forall|b: Seq<u8>| #[trigger] encoded(b) == stripped(text@) ==> out is Some && out.unwrap()@ == b,
{
    let mut n: usize = text.len();
    proof { assert(text@.take(n as int) =~= text@); }
    while n > 0 && text[n - 1] == 61
        invariant n <= text.len(), stripped(text@) == stripped(text@.take(n as int)),
        decreases n,
    {
        proof { assert(text@.take(n as int).drop_last() =~= text@.take(n as int - 1)); }
        n = n - 1;
    }
    let ghost t = text@.take(n as int);
    proof { assert(stripped(t) == t); }
    let mut out: Vec<u8> = Vec::new();
    let mut i: usize = 0;
    proof { assert(t.take(0) =~= Seq::<u8>::empty()); }
    while n - i >= 4
        invariant i <= n, n <= text.len(), t == text@.take(n as int), stripped(text@) == t, out@.len() % 3 == 0,
            encoded(out@) == t.take(i as int),
            forall|b: Seq<u8>| #[trigger] encoded(b) == t ==> b.len() >= out@.len() && out@ == b.take(out@.len() as int),
        decreases n - i,
    {
        let ghost m = out@.len() as int;
        let (c0, c1, c2, c3) = (text[i], text[i + 1], text[i + 2], text[i + 3]);
        proof {
            assert(t.subrange(i as int, i + 4) =~= seq![c0, c1, c2, c3]);
            assert forall|b: Seq<u8>| #[trigger] encoded(b) == t implies b.len() >= m + 3 && encoded(group3(b[m], b[m + 1], b[m + 2])) == seq![c0, c1, c2, c3] by {
                lemma_rest(b, t, m, i as int);
            }
        }
        let group = decode_group(c0, c1, c2, c3);
        let (x0, x1, x2) = match group {
            Some(group) => group,
            None => {
                proof { assert forall|b: Seq<u8>| #[trigger] encoded(b) == t implies false by {} }
                return None;
            }
        };
        let ghost before = out@;
        out.push(x0); out.push(x1); out.push(x2);
        proof {
            assert(out@ =~= before + group3(x0, x1, x2));
            lemma_encoded_append(before, group3(x0, x1, x2));
            assert(encoded(out@) =~= t.take(i + 4));
            assert forall|b: Seq<u8>| #[trigger] encoded(b) == t implies b.len() >= m + 3 && out@ == b.take(m + 3) by {
                assert(out@ =~= b.take(m + 3));
            }
        }
        i = i + 4;
    }
    let ghost m = out@.len() as int;
    let rem = n - i;
    proof {
        assert forall|b: Seq<u8>| #[trigger] encoded(b) == t implies (rem == 0 ==> b.len() == m) && rem != 1
            && (rem == 2 ==> b.len() == m + 1 && t.skip(i as int) == encoded(group1(b[m])))
            && (rem == 3 ==> b.len() == m + 2 && t.skip(i as int) == encoded(group2(b[m], b[m + 1]))) by {
            lemma_rest(b, t, m, i as int);
        }
    }
    if rem == 0 {
        proof {
            assert(t.take(i as int) =~= t);
            assert forall|b: Seq<u8>| #[trigger] encoded(b) == t implies out@ == b by { assert(b.take(m) =~= b); }
        }
        Some(out)
    } else if rem == 2 {
        let (c0, c1) = (text[i], text[i + 1]);
        proof { assert(t.skip(i as int) =~= seq![c0, c1]); }
        let tail = decode_tail1(c0, c1);
        let x0 = match tail {
            Some(x0) => x0,
            None => {
                proof { assert forall|b: Seq<u8>| #[trigger] encoded(b) == t implies false by {} }
                return None;
            }
        };
        let ghost before = out@;
        out.push(x0);
        proof {
            assert(out@ =~= before + group1(x0));
            lemma_encoded_append(before, group1(x0));
            assert(encoded(out@) =~= t);
            assert forall|b: Seq<u8>| #[trigger] encoded(b) == t implies out@ == b by { assert(out@ =~= b); }
        }
        Some(out)
    } else if rem == 3 {
        let (c0, c1, c2) = (text[i], text[i + 1], text[i + 2]);
        proof { assert(t.skip(i as int) =~= seq![c0, c1, c2]); }
        let tail = decode_tail2(c0, c1, c2);
        let (x0, x1) = match tail {
            Some(pair) => pair,
            None => {
                proof { assert forall|b: Seq<u8>| #[trigger] encoded(b) == t implies false by {} }
                return None;
            }
        };
        let ghost before = out@;
        out.push(x0); out.push(x1);
        proof {
            assert(out@ =~= before + group2(x0, x1));
            lemma_encoded_append(before, group2(x0, x1));
            assert(encoded(out@) =~= t);
            assert forall|b: Seq<u8>| #[trigger] encoded(b) == t implies out@ == b by { assert(out@ =~= b); }
        }
        Some(out)
    } else {
        None
    }
}

} // verus!
