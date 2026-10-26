//! Verified parsing of the two inbound fields the gateway routes on: the
//! route selector in the request path and the gateway bearer token. A selector
//! is accepted only when the path is exactly `/routes/` followed by the
//! canonical decimal spelling of one `u64`, and every such path is accepted.
//! A bearer token is accepted only when exactly one Authorization field is
//! present and it is `Bearer <token>` with one to 512 token characters.
use vstd::prelude::*;
use vstd::slice::{slice_subrange, slice_to_vec};
use crate::headers::{AUTHORIZATION, Field, count, eq, lowercase};

verus! {
pub const MAX_TOKEN: usize = 512;
pub const BEARER: [u8; 6] = *b"bearer";
pub const ROUTES: [u8; 8] = *b"/routes/";

/// Characters a gateway token may contain: alphanumerics and `-._~+/=`.
pub open spec fn token_char(b: u8) -> bool {
    (48 <= b <= 57) || (65 <= b <= 90) || (97 <= b <= 122)
        || b == 45 || b == 46 || b == 95 || b == 126 || b == 43 || b == 47 || b == 61
}
fn is_token_char(b: u8) -> (out: bool)
    ensures out == token_char(b),
{
    (b >= 48 && b <= 57) || (b >= 65 && b <= 90) || (b >= 97 && b <= 122)
        || b == 45 || b == 46 || b == 95 || b == 126 || b == 43 || b == 47 || b == 61
}

/// The token of a well-formed `Bearer <token>` value, scheme case-insensitive.
pub open spec fn bearer_token(value: Seq<u8>) -> Option<Seq<u8>> {
    if value.len() >= 8 && crate::headers::lower_seq(value.subrange(0, 6)) == BEARER@ && value[6] == 32
        && value.len() - 7 <= MAX_TOKEN
        && (forall|k: int| 7 <= k < value.len() ==> token_char(#[trigger] value[k]))
    { Some(value.subrange(7, value.len() as int)) } else { None }
}

fn parse_bearer(value: &[u8]) -> (out: Option<Vec<u8>>)
    ensures match out {
        Some(token) => bearer_token(value@) == Some(token@),
        None => bearer_token(value@).is_none(),
    },
{
    if value.len() < 8 || value.len() - 7 > MAX_TOKEN { return None; }
    let scheme = lowercase(slice_subrange(value, 0, 6));
    if !eq(scheme.as_slice(), BEARER.as_slice()) || value[6] != 32 { return None; }
    let mut k: usize = 7;
    while k < value.len()
        invariant 7 <= k <= value.len(), forall|j: int| 7 <= j < k ==> token_char(#[trigger] value@[j]),
        decreases value.len() - k,
    {
        if !is_token_char(value[k]) { return None; }
        k = k + 1;
    }
    Some(slice_to_vec(slice_subrange(value, 7, value.len())))
}

/// The gateway token, when exactly one Authorization field is present and it
/// is a well-formed bearer. Rejected otherwise.
pub fn bearer(fields: &Vec<Field>) -> (out: Option<Vec<u8>>)
    ensures match out {
        Some(token) => crate::headers::count_named(fields@, AUTHORIZATION@) == 1
            && exists|i: int| 0 <= i < fields@.len() && #[trigger] fields@[i].name@ == AUTHORIZATION@
                && bearer_token(fields@[i].value@) == Some(token@),
        None => crate::headers::count_named(fields@, AUTHORIZATION@) != 1
            || exists|i: int| 0 <= i < fields@.len() && #[trigger] fields@[i].name@ == AUTHORIZATION@
                && bearer_token(fields@[i].value@).is_none(),
    },
{
    if count(fields, AUTHORIZATION.as_slice()) != 1 { return None; }
    let mut i: usize = 0;
    while i < fields.len()
        invariant i <= fields.len(), crate::headers::count_named(fields@, AUTHORIZATION@) == 1,
            forall|j: int| 0 <= j < i ==> #[trigger] fields@[j].name@ != AUTHORIZATION@,
        decreases fields.len() - i,
    {
        if eq(fields[i].name.as_slice(), AUTHORIZATION.as_slice()) {
            proof { assert(fields@[i as int].name@ == AUTHORIZATION@); }
            return match parse_bearer(fields[i].value.as_slice()) {
                Some(token) => Some(token),
                None => None,
            };
        }
        i = i + 1;
    }
    proof { crate::headers::lemma_filter_none(fields@, AUTHORIZATION@); }
    None
}

/// The canonical decimal spelling of `n`: no sign, no leading zero.
pub open spec fn decimal(n: nat) -> Seq<u8>
    decreases n,
{
    if n < 10 { seq![(48 + n) as u8] } else { decimal(n / 10).push((48 + n % 10) as u8) }
}
/// The value of a string of decimal digits.
pub open spec fn value_of(digits: Seq<u8>) -> nat
    decreases digits.len(),
{
    if digits.len() == 0 { 0 } else { value_of(digits.drop_last()) * 10 + (digits.last() - 48) as nat }
}
pub open spec fn is_digit(b: u8) -> bool { 48 <= b <= 57 }
pub open spec fn all_digits(digits: Seq<u8>) -> bool { forall|k: int| 0 <= k < digits.len() ==> is_digit(#[trigger] digits[k]) }
/// The only path that selects route `n`.
pub open spec fn selector_path(n: u64) -> Seq<u8> { ROUTES@ + decimal(n as nat) }

proof fn lemma_cancel_prefix(a: Seq<u8>, b: Seq<u8>, c: Seq<u8>)
    requires a + b == a + c,
    ensures b == c,
{
    assert(b =~= (a + b).subrange(a.len() as int, (a + b).len() as int));
    assert(c =~= (a + c).subrange(a.len() as int, (a + c).len() as int));
}

pub proof fn lemma_decimal_shape(n: nat)
    ensures decimal(n).len() >= 1, all_digits(decimal(n)), n >= 1 ==> decimal(n)[0] != 48,
        value_of(decimal(n)) == n,
    decreases n,
{
    if n < 10 {
        let s = decimal(n);
        assert(s =~= seq![(48 + n) as u8]);
        assert(s.last() == (48 + n) as u8);
        assert(s.drop_last() =~= Seq::<u8>::empty());
        assert(value_of(s.drop_last()) == 0);
        assert((s.last() - 48) as nat == n);
    } else {
        lemma_decimal_shape(n / 10);
        let d = decimal(n / 10);
        let s = decimal(n);
        assert(s == d.push((48 + n % 10) as u8));
        assert(s.drop_last() =~= d);
        assert(s.last() == (48 + n % 10) as u8);
        assert(s[0] == d[0]);
        assert(n / 10 >= 1);
        assert((s.last() - 48) as nat == n % 10);
        assert(value_of(s) == value_of(d) * 10 + n % 10);
        assert(n == (n / 10) * 10 + n % 10) by (nonlinear_arith);
    }
}

// A digit string with a nonzero first digit spells its own value.
pub proof fn lemma_digits_roundtrip(digits: Seq<u8>)
    requires digits.len() >= 1, all_digits(digits), digits[0] != 48,
    ensures value_of(digits) >= 1, decimal(value_of(digits)) == digits,
    decreases digits.len(),
{
    let last = digits.last();
    let d = (last - 48) as nat;
    if digits.len() == 1 {
        assert(digits.drop_last() =~= Seq::<u8>::empty());
        assert(value_of(digits.drop_last()) == 0);
        assert(value_of(digits) == d);
        assert(decimal(d) =~= seq![(48 + d) as u8]);
        assert(decimal(d) =~= digits);
    } else {
        let rest = digits.drop_last();
        assert(rest[0] == digits[0]);
        lemma_digits_roundtrip(rest);
        let v = value_of(rest);
        assert(value_of(digits) == v * 10 + d);
        assert(v * 10 + d >= 10) by (nonlinear_arith) requires v >= 1;
        assert((v * 10 + d) / 10 == v && (v * 10 + d) % 10 == d) by (nonlinear_arith) requires d < 10;
        assert(decimal(v * 10 + d) == decimal(v).push((48 + d) as u8));
        assert(decimal(v).push((48 + d) as u8) =~= digits);
    }
}

// The single digit "0" or a string with a nonzero first digit spells its own value.
pub proof fn lemma_digits_canonical(digits: Seq<u8>)
    requires digits.len() >= 1, all_digits(digits), digits[0] == 48 ==> digits.len() == 1,
    ensures decimal(value_of(digits)) == digits,
{
    if digits[0] == 48 {
        assert(digits =~= seq![48u8]);
        assert(digits.drop_last() =~= Seq::<u8>::empty());
        assert(value_of(digits.drop_last()) == 0);
        assert(value_of(digits) == 0);
        assert(decimal(0) =~= seq![48u8]);
    } else {
        lemma_digits_roundtrip(digits);
    }
}

// Every prefix of a canonical spelling reads back as a value no larger than
// the number spelled.
pub proof fn lemma_prefix_value(n: nat, i: int)
    requires 0 <= i <= decimal(n).len(),
    ensures value_of(decimal(n).subrange(0, i)) <= n,
    decreases n,
{
    lemma_decimal_shape(n);
    if i == decimal(n).len() {
        assert(decimal(n).subrange(0, i) =~= decimal(n));
    } else if n < 10 {
        assert(decimal(n).subrange(0, i) =~= Seq::<u8>::empty());
    } else {
        lemma_decimal_shape(n / 10);
        assert(decimal(n).drop_last() =~= decimal(n / 10));
        assert(decimal(n).subrange(0, i) =~= decimal(n / 10).subrange(0, i));
        lemma_prefix_value(n / 10, i);
    }
}

// Why a rejected path selects no route: it lacks the prefix, has a leading
// zero, has a non-digit, or its value exceeds u64.
proof fn lemma_no_prefix(path: Seq<u8>)
    requires path.len() <= 8 || path.subrange(0, 8) != ROUTES@,
    ensures forall|n: u64| path != #[trigger] selector_path(n),
{
    assert forall|n: u64| path != #[trigger] selector_path(n) by {
        lemma_decimal_shape(n as nat);
        assert(selector_path(n).len() >= 9);
        assert(selector_path(n).subrange(0, 8) =~= ROUTES@);
    }
}
proof fn lemma_leading_zero(path: Seq<u8>, digits: Seq<u8>)
    requires path == ROUTES@ + digits, digits.len() > 1, digits[0] == 48,
    ensures forall|n: u64| path != #[trigger] selector_path(n),
{
    assert forall|n: u64| path != #[trigger] selector_path(n) by {
        if path == selector_path(n) {
            lemma_cancel_prefix(ROUTES@, digits, decimal(n as nat));
            lemma_decimal_shape(n as nat);
            if n == 0 { assert(decimal(0) =~= seq![48u8]); }
        }
    }
}
proof fn lemma_non_digit(path: Seq<u8>, digits: Seq<u8>, i: int)
    requires path == ROUTES@ + digits, 0 <= i < digits.len(), !is_digit(digits[i]),
    ensures forall|n: u64| path != #[trigger] selector_path(n),
{
    assert forall|n: u64| path != #[trigger] selector_path(n) by {
        if path == selector_path(n) {
            lemma_cancel_prefix(ROUTES@, digits, decimal(n as nat));
            lemma_decimal_shape(n as nat);
        }
    }
}
proof fn lemma_overflow(path: Seq<u8>, digits: Seq<u8>, i: int, acc: u64, d: u64)
    requires path == ROUTES@ + digits, 0 <= i < digits.len(), all_digits(digits.subrange(0, i + 1)),
        acc == value_of(digits.subrange(0, i)), d < 10, digits[i] == (48 + d) as u8, acc > (u64::MAX - d) / 10,
    ensures forall|n: u64| path != #[trigger] selector_path(n),
{
    assert forall|n: u64| path != #[trigger] selector_path(n) by {
        if path == selector_path(n) {
            lemma_cancel_prefix(ROUTES@, digits, decimal(n as nat));
            lemma_prefix_value(n as nat, i + 1);
            let step = digits.subrange(0, i + 1);
            assert(step.drop_last() =~= digits.subrange(0, i));
            assert(step.last() == digits[i]);
            assert(value_of(step) == acc * 10 + d);
            assert(acc * 10 + d <= u64::MAX);
            assert(acc <= (u64::MAX - d) / 10) by (nonlinear_arith) requires acc * 10 + d <= u64::MAX, d < 10;
        }
    }
}

/// Parse the route selector from an origin-form path. Accepts exactly the
/// paths `/routes/<n>` with `<n>` the canonical decimal of a `u64`.
pub fn route_selector(path: &[u8]) -> (out: Option<u64>)
    ensures match out {
        Some(n) => path@ == selector_path(n),
        None => forall|n: u64| path@ != #[trigger] selector_path(n),
    },
{
    if path.len() <= 8 || !eq(slice_subrange(path, 0, 8), ROUTES.as_slice()) {
        proof { lemma_no_prefix(path@); }
        return None;
    }
    let digits = slice_subrange(path, 8, path.len());
    proof { assert(path@ =~= ROUTES@ + digits@); }
    if digits[0] == 48 && digits.len() > 1 {
        proof { lemma_leading_zero(path@, digits@); }
        return None;
    }
    let mut acc: u64 = 0;
    let mut i: usize = 0;
    while i < digits.len()
        invariant i <= digits.len(), digits.len() >= 1, path@ == ROUTES@ + digits@,
            digits@[0] == 48 ==> digits@.len() == 1,
            all_digits(digits@.subrange(0, i as int)),
            acc == value_of(digits@.subrange(0, i as int)),
        decreases digits.len() - i,
    {
        let b = digits[i];
        if b < 48 || b > 57 {
            proof { lemma_non_digit(path@, digits@, i as int); }
            return None;
        }
        let d = (b - 48) as u64;
        proof {
            assert(digits@.subrange(0, i as int + 1).drop_last() =~= digits@.subrange(0, i as int));
            assert(all_digits(digits@.subrange(0, i as int + 1)));
        }
        if acc > (u64::MAX - d) / 10 {
            proof { lemma_overflow(path@, digits@, i as int, acc, d); }
            return None;
        }
        proof { assert(acc * 10 <= u64::MAX - d) by (nonlinear_arith) requires acc <= (u64::MAX - d) / 10; }
        acc = acc * 10 + d;
        i = i + 1;
    }
    proof {
        assert(digits@.subrange(0, digits.len() as int) =~= digits@);
        lemma_digits_canonical(digits@);
    }
    Some(acc)
}
}
