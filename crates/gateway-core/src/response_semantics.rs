//! Total response-error interpretation. JSON has priority; otherwise every
//! complete SSE payload is interpreted, including after unknown/malformed events.
//! These contracts compose the JSON grammar, event grammar, and row error flag.
//! Provider vocabulary is an explicit protocol assumption, not inferred from HTTP 200.
use vstd::prelude::*;
use crate::json::{self, Value};

verus! {
pub const ERROR: [u8; 5] = *b"error";
pub const TYPE: [u8; 4] = *b"type";
pub const STATUS: [u8; 6] = *b"status";
pub const RESPONSE: [u8; 8] = *b"response";
pub const FAILED: [u8; 6] = *b"failed";
pub const INCOMPLETE: [u8; 10] = *b"incomplete";
pub const CANCELLED: [u8; 9] = *b"cancelled";
pub const RESPONSE_FAILED: [u8; 15] = *b"response.failed";
pub const RESPONSE_INCOMPLETE: [u8; 19] = *b"response.incomplete";

pub open spec fn first(v: Value, key: Seq<u8>, i: int) -> bool {
    0 <= i < json::members_of(v).len() && json::members_of(v)[i].key@ == key
        && forall|j: int| 0 <= j < i ==> json::members_of(v)[j].key@ != key
}
pub open spec fn field(v: Value, key: Seq<u8>) -> Option<Value> {
    if exists|i: int| first(v, key, i) {
        Some(json::members_of(v)[choose|i: int| first(v, key, i)].value)
    } else { None }
}
fn get<'a>(v: &'a Value, key: &[u8]) -> (out: Option<&'a Value>)
    ensures match out { Some(w) => field(*v, key@) == Some(*w), None => field(*v, key@).is_none() },
{
    let out = v.get(key);
    proof {
        if let Some(w) = out {
            let i = choose|i: int| 0 <= i < json::members_of(*v).len() && json::members_of(*v)[i].key@ == key@ && json::members_of(*v)[i].value == *w
                && forall|j: int| 0 <= j < i ==> json::members_of(*v)[j].key@ != key@;
            assert(first(*v, key@, i));
            assert(exists|k: int| first(*v, key@, k));
            let j = choose|j: int| first(*v, key@, j);
            assert(i == j) by {
                if i < j { assert(json::members_of(*v)[i].key@ != key@); }
                if j < i { assert(json::members_of(*v)[j].key@ != key@); }
            }
        }
    }
    out
}
pub open spec fn named(v: Option<Value>, name: Seq<u8>) -> bool {
    match v { Some(Value::Str(s)) => s@ == name, _ => false }
}
fn is_named(v: Option<&Value>, name: &[u8]) -> (out: bool)
    ensures out == named(match v { Some(w) => Some(*w), None => None }, name@),
{
    match v { Some(Value::Str(s)) => crate::headers::eq(s.as_slice(), name), _ => false }
}
pub open spec fn local_failure(v: Value) -> bool {
    (match field(v, ERROR@) { Some(w) => !(w is Null), None => false })
    || named(field(v, TYPE@), ERROR@)
    || named(field(v, TYPE@), RESPONSE_FAILED@)
    || named(field(v, TYPE@), RESPONSE_INCOMPLETE@)
    || named(field(v, STATUS@), FAILED@)
    || named(field(v, STATUS@), INCOMPLETE@)
    || named(field(v, STATUS@), CANCELLED@)
}
fn local(v: &Value) -> (out: bool)
    ensures out == local_failure(*v),
{
    let error = get(v, ERROR.as_slice());
    let kind = get(v, TYPE.as_slice());
    let status = get(v, STATUS.as_slice());
    (match error { Some(w) => !matches!(w, Value::Null), None => false })
        || is_named(kind, ERROR.as_slice()) || is_named(kind, RESPONSE_FAILED.as_slice())
        || is_named(kind, RESPONSE_INCOMPLETE.as_slice()) || is_named(status, FAILED.as_slice())
        || is_named(status, INCOMPLETE.as_slice()) || is_named(status, CANCELLED.as_slice())
}
pub open spec fn failure(v: Value) -> bool {
    local_failure(v) || match field(v, RESPONSE@) { Some(w) => local_failure(w), None => false }
}
pub fn failed(v: &Value) -> (out: bool)
    ensures out == failure(*v),
{
    local(v) || match get(v, RESPONSE.as_slice()) { Some(w) => local(w), None => false }
}

/// Soundness plus depth-bounded completeness of a JSON interpretation. A
/// missing interpretation is allowed only if no supported JSON document exists.
pub open spec fn parsed(bytes: Seq<u8>, result: Option<Value>) -> bool {
    (match result { Some(v) => json::document(bytes, v), None => true })
    && forall|v: Value| #[trigger] json::document(bytes, v) && json::depth(v) <= json::MAX_DEPTH ==>
        match result { Some(w) => json::same(w, v), None => false }
}
pub open spec fn optional_failure(v: Option<Value>) -> bool {
    match v { Some(w) => failure(w), None => false }
}
/// Every payload has an interpretation, in order, including unrecognized ones.
pub open spec fn decoded(events: Seq<Seq<u8>>, values: Seq<Option<Value>>) -> bool {
    events.len() == values.len()
        && forall|i: int| 0 <= i < events.len() ==> parsed(events[i], #[trigger] values[i])
}
pub open spec fn any_failure(values: Seq<Option<Value>>) -> bool {
    exists|i: int| 0 <= i < values.len() && optional_failure(#[trigger] values[i])
}
/// A complete fold over all event payloads, with no prefix gate or early exit.
pub open spec fn stream(events: Seq<Seq<u8>>, failed: bool) -> bool {
    exists|values: Seq<Option<Value>>| decoded(events, values) && failed == any_failure(values)
}
pub proof fn empty_stream()
    ensures stream(Seq::empty(), false),
{
    let values = Seq::<Option<Value>>::empty();
    assert(decoded(Seq::empty(), values));
    assert(!any_failure(values));
}
pub proof fn prepend(events: Seq<Seq<u8>>, v: Option<Value>, rest: bool)
    requires events.len() > 0, parsed(events[0], v), stream(events.drop_first(), rest),
    ensures stream(events, optional_failure(v) || rest),
{
    let tail = choose|values: Seq<Option<Value>>| decoded(events.drop_first(), values) && rest == any_failure(values);
    let values = seq![v] + tail;
    assert forall|i: int| 0 <= i < events.len() implies parsed(events[i], #[trigger] values[i]) by {
        if i > 0 { assert(values[i] == tail[i - 1]); assert(events[i] == events.drop_first()[i - 1]); }
    }
    assert(decoded(events, values));
    assert(any_failure(values) == (optional_failure(v) || rest)) by {
        if any_failure(values) {
            let i = choose|i: int| 0 <= i < values.len() && optional_failure(values[i]);
            if i > 0 { assert(optional_failure(tail[i - 1])); }
        }
        if rest {
            let i = choose|i: int| 0 <= i < tail.len() && optional_failure(tail[i]);
            assert(optional_failure(values[i + 1]));
        }
        if optional_failure(v) { assert(optional_failure(values[0])); }
    }
}
/// The union covers JSON, SSE, malformed bodies, unknown events, and raw-text
/// fallback. It does not claim that an unrecognized provider schema succeeded.
pub open spec fn interpretation(bytes: Seq<u8>, failed: bool) -> bool {
    (exists|v: Value| parsed(bytes, Some(v)) && failed == failure(v))
    || (parsed(bytes, None) && stream(crate::sse::event_data(bytes), failed))
}
/// Transport/log failures and provider failures are independent evidence.
pub open spec fn exchange_error(e: crate::exchange_assembler::Exchange, provider_failed: bool) -> bool {
    provider_failed || e.incomplete
        || (match e.head { Some(h) => h.status >= 400, None => false })
        || (match e.completion { Some(c) => c.outcome != 0, None => false })
}
}
