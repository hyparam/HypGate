//! Provider usage semantics, independent of the projection's executable fold.
//! Counts are cumulative observations, not deltas to add. Absent observations
//! preserve state; an explicit zero replaces an earlier count.
use vstd::prelude::*;
use crate::{json::Value, projection::*, response_semantics as sem, config_schema as schema};
verus! {
pub open spec fn at(v: Value, key: Seq<u8>) -> Option<u64> {
    match sem::field(v, key) {
        Some(w) => if schema::is_u64(w) { Some(schema::u64_of(w)) } else { None },
        None => None,
    }
}
pub open spec fn at2(v: Value, a: Seq<u8>, b: Seq<u8>) -> Option<u64> {
    match sem::field(v, a) { Some(w) => at(w, b), None => None }
}
pub open spec fn first(a: Option<u64>, b: Option<u64>, c: Option<u64>) -> u64 {
    match a { Some(n) => n, None => match b { Some(n) => n, None => match c { Some(n) => n, None => 0 } } }
}
pub open spec fn normalized(u: Value) -> Usage {
    let cache = first(at(u, P_CACHE_READ_INPUT_TOKENS@), at2(u, P_INPUT_TOKENS_DETAILS@, P_CACHED_TOKENS@), at2(u, P_PROMPT_TOKENS_DETAILS@, P_CACHED_TOKENS@));
    let total = first(at(u, P_INPUT_TOKENS@), at(u, P_PROMPT_TOKENS@), None);
    let anthropic = sem::field(u, P_CACHE_READ_INPUT_TOKENS@).is_some() || sem::field(u, P_CACHE_CREATION_INPUT_TOKENS@).is_some();
    Usage { input: if anthropic { total } else if total >= cache { (total - cache) as u64 } else { 0 },
        cache_read: cache, cache_write: first(at(u, P_CACHE_CREATION_INPUT_TOKENS@), None, None),
        output: first(at(u, P_OUTPUT_TOKENS@), at(u, P_COMPLETION_TOKENS@), None) }
}
pub open spec fn observation(v: Value) -> Option<Usage> {
    match sem::field(v, P_USAGE@) { Some(u) => if u is Object { Some(normalized(u)) } else { None }, None => None }
}
pub open spec fn zero() -> Usage { Usage { input: 0, cache_read: 0, cache_write: 0, output: 0 } }
pub open spec fn replace(previous: Option<Usage>, next: Option<Usage>) -> Option<Usage> {
    if next.is_some() { next } else { previous }
}
/// Each supported event has an explicit cumulative accounting interpretation.
/// Start observations include output, even when no message_delta ever follows.
pub open spec fn step(v: Value, previous: Option<Usage>) -> Option<Usage> {
    let kind = sem::field(v, P_TYPE@);
    if sem::named(kind, P_MESSAGE_START@) {
        replace(previous, match sem::field(v, P_MESSAGE@) { Some(m) => observation(m), None => None })
    } else if sem::named(kind, P_MESSAGE_DELTA@) {
        match at2(v, P_USAGE@, P_OUTPUT_TOKENS@) {
            Some(n) => { let p = previous.unwrap_or(zero()); Some(Usage { output: n, ..p }) },
            None => previous,
        }
    } else if sem::named(kind, P_CONTENT_BLOCK_DELTA@) || sem::named(kind, P_OUTPUT_TEXT_DELTA@) { previous }
    else if sem::named(kind, P_RESPONSE_COMPLETED@) || sem::named(kind, sem::RESPONSE_FAILED@) || sem::named(kind, sem::RESPONSE_INCOMPLETE@) {
        replace(previous, match sem::field(v, P_RESPONSE@) { Some(r) => observation(r), None => None })
    } else { replace(previous, observation(v)) }
}
pub open spec fn optional_step(v: Option<Value>, previous: Option<Usage>) -> Option<Usage> {
    match v { Some(w) => step(w, previous), None => previous }
}
pub open spec fn fold(values: Seq<Option<Value>>, initial: Option<Usage>) -> Option<Usage>
    decreases values.len(),
{
    if values.len() == 0 { initial } else { fold(values.drop_first(), optional_step(values[0], initial)) }
}
pub open spec fn stream(events: Seq<Seq<u8>>, initial: Option<Usage>, result: Option<Usage>) -> bool {
    exists|values: Seq<Option<Value>>| sem::decoded(events, values) && result == fold(values, initial)
}
pub proof fn empty(initial: Option<Usage>)
    ensures stream(Seq::empty(), initial, initial),
{
    assert(sem::decoded(Seq::empty(), Seq::empty()));
}
pub proof fn prepend(events: Seq<Seq<u8>>, v: Option<Value>, initial: Option<Usage>, result: Option<Usage>)
    requires events.len() > 0, sem::parsed(events[0], v), stream(events.drop_first(), optional_step(v, initial), result),
    ensures stream(events, initial, result),
{
    let tail = choose|values: Seq<Option<Value>>| sem::decoded(events.drop_first(), values) && result == fold(values, optional_step(v, initial));
    let values = seq![v] + tail;
    assert forall|i: int| 0 <= i < events.len() implies sem::parsed(events[i], #[trigger] values[i]) by {
        if i > 0 { assert(values[i] == tail[i - 1]); assert(events[i] == events.drop_first()[i - 1]); }
    }
    assert(sem::decoded(events, values));
    assert(values.drop_first() =~= tail);
    assert(result == fold(values, initial));
}
pub open spec fn interpretation(bytes: Seq<u8>, result: Option<Usage>) -> bool {
    (exists|v: Value| sem::parsed(bytes, Some(v)) && result == observation(v))
    || (sem::parsed(bytes, None) && stream(crate::sse::event_data(bytes), None, result))
}
/// The final usage payload must contain every field and their saturated sum.
pub open spec fn total(u: Usage) -> nat {
    let n = u.input as nat + u.cache_read as nat + u.cache_write as nat + u.output as nat;
    if n <= u64::MAX { n } else { u64::MAX as nat }
}
pub open spec fn payload(v: Value, u: Usage) -> bool {
    keys_of(v) == seq![K_INPUT_TOKENS@, K_CACHE_READ_TOKENS@, K_CACHE_WRITE_TOKENS@, K_OUTPUT_TOKENS@, K_TOTAL_TOKENS@]
    && is_number(value_at(v, 0), u.input as nat) && is_number(value_at(v, 1), u.cache_read as nat)
    && is_number(value_at(v, 2), u.cache_write as nat) && is_number(value_at(v, 3), u.output as nat)
    && is_number(value_at(v, 4), total(u))
}
pub open spec fn serialized(row: Value, usage: Option<Usage>) -> bool {
    let attrs = value_at(row, 22);
    match usage {
        Some(u) => keys_of(attrs) == seq![K_GATEWAY@, K_USAGE@] && payload(value_at(attrs, 1), u),
        None => keys_of(attrs) == seq![K_GATEWAY@],
    }
}
/// A partial output observation replaces output exactly and preserves all
/// other cumulative fields, for arbitrary values including zero and u64::MAX.
pub proof fn partial_output_preserves(v: Value, previous: Usage, n: u64)
    requires sem::named(sem::field(v, P_TYPE@), P_MESSAGE_DELTA@), at2(v, P_USAGE@, P_OUTPUT_TOKENS@) == Some(n),
    ensures step(v, Some(previous)) == Some(Usage { output: n, ..previous }),
{
    reveal(P_MESSAGE_START); reveal(P_MESSAGE_DELTA);
    assert(P_MESSAGE_START@[8] != P_MESSAGE_DELTA@[8]);
}
pub proof fn start_preserves_every_reported_count(v: Value, message: Value, u: Usage, previous: Option<Usage>)
    requires sem::named(sem::field(v, P_TYPE@), P_MESSAGE_START@), sem::field(v, P_MESSAGE@) == Some(message), observation(message) == Some(u),
    ensures step(v, previous) == Some(u),
{}
pub proof fn malformed_preserves(previous: Option<Usage>)
    ensures optional_step(None, previous) == previous,
{}
/// Sufficient structural condition for an event to carry no supported count
/// observation, independent of the previous accounting state.
pub open spec fn silent(v: Option<Value>) -> bool {
    match v {
        None => true,
        Some(w) => observation(w).is_none() && at2(w, P_USAGE@, P_OUTPUT_TOKENS@).is_none()
            && (match sem::field(w, P_MESSAGE@) { Some(m) => observation(m).is_none(), None => true })
            && (match sem::field(w, P_RESPONSE@) { Some(r) => observation(r).is_none(), None => true }),
    }
}
pub proof fn silent_event_preserves(v: Option<Value>, previous: Option<Usage>)
    requires silent(v),
    ensures optional_step(v, previous) == previous,
{}
/// Any number of errors, unknown events, malformed payloads or other events
/// without a count observation preserve every previously recorded count.
pub proof fn silent_suffix_preserves(values: Seq<Option<Value>>, previous: Option<Usage>)
    requires forall|i: int| 0 <= i < values.len() ==> silent(#[trigger] values[i]),
    ensures fold(values, previous) == previous,
    decreases values.len(),
{
    if values.len() > 0 {
        silent_event_preserves(values[0], previous);
        assert forall|i: int| 0 <= i < values.drop_first().len() implies silent(#[trigger] values.drop_first()[i]) by {
            assert(values.drop_first()[i] == values[i + 1]);
        }
        silent_suffix_preserves(values.drop_first(), previous);
    }
}

}
