//! Verified message-framing selection. From a parsed head's fields the body
//! is framed in exactly one of three ways: a Content-Length count, chunked
//! transfer coding, or, for a response only, the bytes until the connection
//! closes. The checked facts: a head carrying both Content-Length and
//! Transfer-Encoding is refused, so the two can never disagree about where a
//! message ends (the request-smuggling ambiguity); repeated fields are
//! refused; the only transfer coding accepted is `chunked` alone; and a
//! Content-Length is accepted exactly when it is the canonical decimal of a
//! `u64`, so every well-formed count is accepted and nothing else is.
use vstd::prelude::*;
use crate::headers::{Field, Rejection, count, eq, lowercase};

verus! {
pub const TRANSFER_ENCODING: [u8; 17] = *b"transfer-encoding";
pub const CONTENT_LENGTH: [u8; 14] = *b"content-length";
pub const CHUNKED: [u8; 7] = *b"chunked";

#[derive(PartialEq, Eq, Structural, Clone, Copy, Debug)]
pub enum Framing { Length(u64), Chunked, UntilClose }

/// Some field named `name` has a value satisfying `ok`.
pub open spec fn value_is_chunked(fields: Seq<Field>, i: int) -> bool {
    0 <= i < fields.len() && fields[i].name@ == TRANSFER_ENCODING@ && crate::headers::lower_seq(fields[i].value@) == CHUNKED@
}
pub open spec fn value_is_length(fields: Seq<Field>, i: int, n: u64) -> bool {
    0 <= i < fields.len() && fields[i].name@ == CONTENT_LENGTH@ && fields[i].value@ == crate::inbound::decimal(n as nat)
}
/// Some Transfer-Encoding field says `chunked`.
pub open spec fn some_chunked(fields: Seq<Field>) -> bool { exists|i: int| #[trigger] value_is_chunked(fields, i) }
/// Some Content-Length field spells `n`.
pub open spec fn some_length(fields: Seq<Field>, n: u64) -> bool { exists|i: int| #[trigger] value_is_length(fields, i, n) }
/// Some Transfer-Encoding field says something other than `chunked`.
pub open spec fn some_other_coding(fields: Seq<Field>) -> bool {
    exists|i: int| 0 <= i < fields.len() && #[trigger] fields[i].name@ == TRANSFER_ENCODING@ && !value_is_chunked(fields, i)
}
/// Some Content-Length field spells no `u64`.
pub open spec fn some_bad_length(fields: Seq<Field>) -> bool {
    exists|i: int| 0 <= i < fields.len() && #[trigger] fields[i].name@ == CONTENT_LENGTH@ && (forall|n: u64| !value_is_length(fields, i, n))
}
pub open spec fn te_count(fields: Seq<Field>) -> nat { crate::headers::count_named(fields, TRANSFER_ENCODING@) }
/// What `framing` establishes for a response head when it returns `f`.
pub open spec fn framing_spec_ok(fields: Seq<Field>, f: Framing) -> bool {
    match f {
        Framing::Chunked => te_count(fields) == 1 && cl_count(fields) == 0 && some_chunked(fields),
        Framing::Length(n) => cl_count(fields) == 1 && te_count(fields) == 0 && some_length(fields, n),
        Framing::UntilClose => cl_count(fields) == 0 && te_count(fields) == 0,
    }
}
/// What `framing` establishes when it refuses a head.
pub open spec fn framing_spec_refused(fields: Seq<Field>) -> bool {
    (te_count(fields) >= 1 && cl_count(fields) >= 1) || te_count(fields) > 1 || cl_count(fields) > 1
        || some_other_coding(fields) || some_bad_length(fields)
}
pub open spec fn cl_count(fields: Seq<Field>) -> nat { crate::headers::count_named(fields, CONTENT_LENGTH@) }

/// The framing a head's fields select, or a refusal.
pub fn framing(fields: &Vec<Field>, request: bool) -> (out: Result<Framing, Rejection>)
    ensures match out {
        Ok(Framing::Chunked) => te_count(fields@) == 1 && cl_count(fields@) == 0 && some_chunked(fields@),
        Ok(Framing::Length(n)) => (cl_count(fields@) == 1 && te_count(fields@) == 0 && some_length(fields@, n))
            || (request && n == 0 && cl_count(fields@) == 0 && te_count(fields@) == 0),
        Ok(Framing::UntilClose) => !request && cl_count(fields@) == 0 && te_count(fields@) == 0,
        Err(_) => (te_count(fields@) >= 1 && cl_count(fields@) >= 1) || te_count(fields@) > 1 || cl_count(fields@) > 1
            || some_other_coding(fields@) || some_bad_length(fields@),
    },
{
    let te = count(fields, TRANSFER_ENCODING.as_slice());
    let cl = count(fields, CONTENT_LENGTH.as_slice());
    if (te >= 1 && cl >= 1) || te > 1 || cl > 1 { return Err(Rejection::BadRequest); }
    if te == 1 {
        let i = find_named(fields, TRANSFER_ENCODING.as_slice());
        let lower = lowercase(fields[i].value.as_slice());
        if eq(lower.as_slice(), CHUNKED.as_slice()) {
            proof { assert(value_is_chunked(fields@, i as int)); assert(some_chunked(fields@)); }
            return Ok(Framing::Chunked);
        }
        proof { assert(!value_is_chunked(fields@, i as int)); assert(some_other_coding(fields@)); }
        return Err(Rejection::BadRequest);
    }
    if cl == 1 {
        let i = find_named(fields, CONTENT_LENGTH.as_slice());
        match parse_decimal(fields[i].value.as_slice()) {
            Some(n) => {
                proof {
                    assert(value_is_length(fields@, i as int, n));
                    assert(some_length(fields@, n));
                }
                return Ok(Framing::Length(n));
            }
            None => {
                proof {
                    assert(fields@[i as int].name@ == CONTENT_LENGTH@);
                    assert(forall|n: u64| !value_is_length(fields@, i as int, n));
                    assert(some_bad_length(fields@));
                }
                return Err(Rejection::BadRequest);
            }
        }
    }
    if request { Ok(Framing::Length(0)) } else { Ok(Framing::UntilClose) }
}

/// The index of a field named `name`, given that exactly one exists.
fn find_named(fields: &Vec<Field>, name: &[u8]) -> (out: usize)
    requires crate::headers::count_named(fields@, name@) == 1,
    ensures out < fields.len(), fields@[out as int].name@ == name@,
{
    let mut i: usize = 0;
    while i < fields.len()
        invariant i <= fields.len(), forall|j: int| 0 <= j < i ==> #[trigger] fields@[j].name@ != name@,
            crate::headers::count_named(fields@, name@) == 1,
        decreases fields.len() - i,
    {
        if eq(fields[i].name.as_slice(), name) { return i; }
        i = i + 1;
    }
    proof { crate::headers::lemma_filter_none(fields@, name@); }
    // Unreachable: the count is one, so some field carries the name.
    0
}

/// The `u64` whose canonical decimal is `value`, if any.
pub fn parse_decimal(value: &[u8]) -> (out: Option<u64>)
    ensures match out {
        Some(n) => value@ == crate::inbound::decimal(n as nat),
        None => forall|n: u64| value@ != crate::inbound::decimal(n as nat),
    },
{
    if value.len() == 0 {
        proof { assert forall|n: u64| value@ != crate::inbound::decimal(n as nat) by { crate::inbound::lemma_decimal_shape(n as nat); } }
        return None;
    }
    if value[0] == 48 && value.len() > 1 {
        proof { assert forall|n: u64| value@ != crate::inbound::decimal(n as nat) by {
            crate::inbound::lemma_decimal_shape(n as nat);
            if value@ == crate::inbound::decimal(n as nat) { assert(n >= 1 || crate::inbound::decimal(n as nat).len() == 1); }
        } }
        return None;
    }
    let mut acc: u64 = 0;
    let mut i: usize = 0;
    while i < value.len()
        invariant i <= value.len(), value.len() >= 1, value@[0] == 48 ==> value@.len() == 1,
            crate::inbound::all_digits(value@.subrange(0, i as int)), acc == crate::inbound::value_of(value@.subrange(0, i as int)),
        decreases value.len() - i,
    {
        let b = value[i];
        if b < 48 || b > 57 {
            proof { assert forall|n: u64| value@ != crate::inbound::decimal(n as nat) by {
                crate::inbound::lemma_decimal_shape(n as nat);
                if value@ == crate::inbound::decimal(n as nat) { assert(crate::inbound::is_digit(value@[i as int])); }
            } }
            return None;
        }
        let d = (b - 48) as u64;
        proof {
            assert(value@.subrange(0, i as int + 1).drop_last() =~= value@.subrange(0, i as int));
            assert(crate::inbound::all_digits(value@.subrange(0, i as int + 1)));
        }
        if acc > (u64::MAX - d) / 10 {
            // The digits so far already spell more than any u64.
            proof { assert forall|n: u64| value@ != crate::inbound::decimal(n as nat) by {
                if value@ == crate::inbound::decimal(n as nat) {
                    crate::inbound::lemma_prefix_value(n as nat, i as int + 1);
                    assert(crate::inbound::value_of(value@.subrange(0, i as int + 1)) == acc * 10 + d);
                    assert(acc * 10 + d > u64::MAX) by (nonlinear_arith) requires acc > (u64::MAX - d) / 10, d < 10;
                }
            } }
            return None;
        }
        proof { assert(acc * 10 <= u64::MAX - d) by (nonlinear_arith) requires acc <= (u64::MAX - d) / 10; }
        acc = acc * 10 + d;
        i = i + 1;
    }
    proof {
        assert(value@.subrange(0, value.len() as int) =~= value@);
        crate::inbound::lemma_digits_canonical(value@);
    }
    Some(acc)
}
}
