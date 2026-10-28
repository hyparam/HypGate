//! Chat completion alternatives are independent streams, identified by index.
//! Preserve each stream's exact fragment order, then join alternatives in
//! first-appearance order with LF. Never concatenate different indexes mid-text.
use vstd::prelude::*;
use crate::{json::Value, response_semantics as sem, projection::*, utf8};
verus! {
pub struct Piece { pub index: u64, pub text: Vec<u8> }
pub open spec fn view(p: Seq<Piece>) -> Seq<(u64, Seq<u8>)> { p.map(|i: int, x: Piece| (x.index, x.text@)) }
pub open spec fn valid(p: Seq<Piece>) -> bool { forall|i: int| 0 <= i < p.len() ==> utf8::valid(#[trigger] p[i].text@) }
pub open spec fn index(v: Value) -> Option<u64> {
    match sem::field(v, b"index"@) {
        None => Some(0), // legacy single-choice chunks without an explicit index
        Some(n) => if crate::config_schema::is_u64(n) { Some(crate::config_schema::u64_of(n)) } else { None },
    }
}
pub open spec fn piece(v: Value) -> Seq<(u64, Seq<u8>)> {
    match (index(v), nested(v, P_DELTA@, P_CONTENT@)) {
        (Some(i), Some(Value::Str(t))) => if t.len() > 0 { seq![(i, utf8::sanitized(t@))] } else { Seq::empty() },
        _ => Seq::empty(),
    }
}
pub open spec fn items(v: Seq<Value>) -> Seq<(u64, Seq<u8>)>
    decreases v.len(),
{ if v.len() == 0 { Seq::empty() } else { items(v.drop_last()) + piece(v.last()) } }
pub open spec fn event(v: Option<Value>) -> Seq<(u64, Seq<u8>)> {
    match v { Some(w) => match sem::field(w, P_CHOICES@) { Some(Value::Array(a)) => items(a@), _ => Seq::empty() }, None => Seq::empty() }
}
fn add(v: &Value, out: &mut Vec<Piece>)
    requires valid(old(out)@),
    ensures valid(final(out)@), view(final(out)@) == view(old(out)@) + piece(*v),
{
    let id = match sem::get(v, b"index") {
        None => 0,
        Some(n) => match crate::config_schema::u64_exec(n) { Some(i) => i, None => return },
    };
    let delta = match sem::get(v, P_DELTA.as_slice()) { Some(d) => d, None => return };
    let text = match sem::get(delta, P_CONTENT.as_slice()) { Some(Value::Str(t)) => t, _ => return };
    if text.len() == 0 { return; }
    let t = utf8::sanitize(text.as_slice());
    out.push(Piece { index: id, text: t });
    proof { assert(view(out@) =~= view(old(out)@) + piece(*v)); }
}
#[verifier::loop_isolation(false)]
fn extend(v: &Value, out: &mut Vec<Piece>)
    requires valid(old(out)@),
    ensures valid(final(out)@), view(final(out)@) == view(old(out)@) + event(Some(*v)),
{
    let choices = match sem::get(v, P_CHOICES.as_slice()) { Some(Value::Array(a)) => a, _ => return };
    let mut i = 0;
    while i < choices.len()
        invariant i <= choices.len(), valid(out@), view(out@) == view(old(out)@) + items(choices@.subrange(0, i as int)),
        decreases choices.len() - i,
    {
        add(&choices[i], out);
        proof { assert(choices@.subrange(0, i as int + 1).drop_last() =~= choices@.subrange(0, i as int)); }
        i += 1;
    }
    proof { assert(choices@.subrange(0, choices.len() as int) =~= choices@); }
}
pub open spec fn accumulated(v: Seq<Option<Value>>) -> Seq<(u64, Seq<u8>)>
    decreases v.len(),
{ if v.len() == 0 { Seq::empty() } else { event(v[0]) + accumulated(v.drop_first()) } }
pub open spec fn stream(events: Seq<Seq<u8>>, initial: Seq<(u64, Seq<u8>)>, result: Seq<(u64, Seq<u8>)>) -> bool {
    exists|values: Seq<Option<Value>>| sem::decoded(events, values) && result == initial + accumulated(values)
}
pub proof fn empty(initial: Seq<(u64, Seq<u8>)>)
    ensures stream(Seq::empty(), initial, initial),
{ assert(sem::decoded(Seq::empty(), Seq::empty())); }
pub proof fn prepend(events: Seq<Seq<u8>>, v: Option<Value>, initial: Seq<(u64, Seq<u8>)>, result: Seq<(u64, Seq<u8>)>)
    requires events.len() > 0, sem::parsed(events[0], v), stream(events.drop_first(), initial + event(v), result),
    ensures stream(events, initial, result),
{
    let tail = choose|values: Seq<Option<Value>>| sem::decoded(events.drop_first(), values) && result == initial + event(v) + accumulated(values);
    let values = seq![v] + tail;
    assert forall|i: int| 0 <= i < events.len() implies sem::parsed(events[i], #[trigger] values[i]) by {
        if i > 0 { assert(values[i] == tail[i - 1]); assert(events[i] == events.drop_first()[i - 1]); }
    }
    assert(sem::decoded(events, values));
    assert(values.drop_first() =~= tail);
    assert(result =~= initial + accumulated(values));
}
pub open spec fn seen(p: Seq<(u64, Seq<u8>)>, i: int) -> bool {
    exists|j: int| 0 <= j < i && #[trigger] p[j].0 == p[i].0
}
pub open spec fn for_index(p: Seq<(u64, Seq<u8>)>, id: u64) -> Seq<u8>
    decreases p.len(),
{
    if p.len() == 0 { Seq::empty() }
    else { for_index(p.drop_last(), id) + if p.last().0 == id { p.last().1 } else { Seq::empty() } }
}
pub open spec fn rendered(p: Seq<(u64, Seq<u8>)>, n: int) -> Seq<u8>
    decreases n,
{
    if n <= 0 || n > p.len() { Seq::empty() }
    else { rendered(p, n - 1) + if seen(p, n - 1) { Seq::empty() }
        else { (if n == 1 { Seq::empty() } else { seq![10u8] }) + for_index(p, p[n - 1].0) } }
}
#[verifier::loop_isolation(false)]
fn was_seen(p: &Vec<Piece>, i: usize) -> (out: bool)
    requires i < p.len(),
    ensures out == seen(view(p@), i as int),
{
    let mut j = 0;
    while j < i
        invariant j <= i, forall|k: int| 0 <= k < j ==> #[trigger] p@[k].index != p@[i as int].index,
        decreases i - j,
    {
        if p[j].index == p[i].index {
            proof { assert(view(p@)[j as int].0 == view(p@)[i as int].0); }
            return true;
        }
        j += 1;
    }
    false
}
#[verifier::loop_isolation(false)]
fn collect(p: &Vec<Piece>, id: u64) -> (out: Vec<u8>)
    requires valid(p@),
    ensures utf8::valid(out@), out@ == for_index(view(p@), id),
{
    let mut out = Vec::new();
    let mut i = 0;
    proof { assert(utf8::valid(out@)); }
    while i < p.len()
        invariant i <= p.len(), utf8::valid(out@), out@ == for_index(view(p@).subrange(0, i as int), id),
        decreases p.len() - i,
    {
        if p[i].index == id { append_line(&mut out, false, p[i].text.as_slice()); }
        proof { assert(view(p@).subrange(0, i as int + 1).drop_last() =~= view(p@).subrange(0, i as int)); }
        i += 1;
    }
    proof { assert(view(p@).subrange(0, p.len() as int) =~= view(p@)); }
    out
}
#[verifier::loop_isolation(false)]
fn render(p: &Vec<Piece>) -> (out: Vec<u8>)
    requires valid(p@),
    ensures utf8::valid(out@), out@ == rendered(view(p@), p.len() as int),
{
    let mut out = Vec::new();
    let mut i = 0;
    proof { assert(utf8::valid(out@)); }
    while i < p.len()
        invariant i <= p.len(), utf8::valid(out@), out@ == rendered(view(p@), i as int),
        decreases p.len() - i,
    {
        if !was_seen(p, i) {
            let text = collect(p, p[i].index);
            append_line(&mut out, i > 0, text.as_slice());
        }
        i += 1;
    }
    out
}
pub open spec fn interpretation(bytes: Seq<u8>, text: Seq<u8>, known: bool) -> bool {
    exists|p: Seq<(u64, Seq<u8>)>| stream(crate::sse::event_data(bytes), Seq::empty(), p)
        && text == rendered(p, p.len() as int) && known == (p.len() > 0)
}
pub open spec fn response_interpretation(bytes: Seq<u8>, text: Seq<u8>, known: bool) -> bool {
    (exists|v: Value| sem::parsed(bytes, Some(v)) && !known)
    || (sem::parsed(bytes, None) && exists|t: Seq<u8>| interpretation(bytes, t, known) && (known ==> text == t))
}
/// Noninterference: appending another choice never changes this one's text.
pub proof fn other_choice_cannot_change_text(p: Seq<(u64, Seq<u8>)>, id: u64, other: u64, text: Seq<u8>)
    requires id != other,
    ensures for_index(p.push((other, text)), id) == for_index(p, id),
{ assert(p.push((other, text)).drop_last() =~= p); }
/// Conservation: every fragment for a choice is appended exactly once, in order.
pub proof fn same_choice_appends_exactly(p: Seq<(u64, Seq<u8>)>, id: u64, text: Seq<u8>)
    ensures for_index(p.push((id, text)), id) == for_index(p, id) + text,
{ assert(p.push((id, text)).drop_last() =~= p); }
/// Complete SSE dispatch: malformed, unknown and unfinished events cannot
/// contaminate any choice's text. All recognized alternatives are retained.
#[verifier::loop_isolation(false)]
pub fn parse(bytes: &[u8]) -> (out: (Vec<u8>, bool))
    ensures utf8::valid(out.0@), interpretation(bytes@, out.0@, out.1),
{
    let mut p: Vec<Piece> = Vec::new();
    let mut reader = crate::sse::Reader::new(bytes);
    loop
        invariant reader.valid(), valid(p@),
            forall|end: Seq<(u64, Seq<u8>)>| stream(reader.remaining(), view(p@), end) ==> stream(crate::sse::event_data(bytes@), Seq::empty(), end),
        decreases reader.left() + 1,
    {
        let ghost before = reader.remaining();
        let ghost initial = view(p@);
        let next = reader.next_json();
        match next {
            Some(Some(v)) => extend(&v, &mut p),
            Some(None) => {},
            None => {
                proof {
                    assert(before =~= Seq::<Seq<u8>>::empty());
                    empty(initial);
                    assert(stream(before, initial, initial));
                    assert(stream(crate::sse::event_data(bytes@), Seq::empty(), initial));
                }
                break;
            }
        }
        proof {
            let v = next.unwrap();
            assert(view(p@) == initial + event(v));
            assert(reader.remaining() =~= before.drop_first());
            assert forall|end: Seq<(u64, Seq<u8>)>| stream(reader.remaining(), view(p@), end) implies stream(crate::sse::event_data(bytes@), Seq::empty(), end) by {
                prepend(before, v, initial, end);
            }
        }
    }
    let text = render(&p);
    proof { assert(stream(crate::sse::event_data(bytes@), Seq::empty(), view(p@))); }
    (text, p.len() > 0)
}
}
