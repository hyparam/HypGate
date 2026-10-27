//! Proof-visible trace of the production rotating writer's primitive effects.
use vstd::prelude::*;

verus! {
pub ghost enum Event { Seal(u64, bool), Create(u64, bool), Append(u64, bool), Sync(u64, bool) }
pub ghost struct State { pub index: u64, pub sealed: bool, pub failed: bool }
pub open spec fn initial() -> State { State { index: 0, sealed: false, failed: false } }
pub open spec fn step(state: State, event: Event) -> Option<State> {
    if state.failed { None }
    else { match event {
        Event::Seal(index, ok) => if index == state.index && !state.sealed {
            Some(State { index, sealed: ok, failed: !ok })
        } else { None },
        Event::Create(index, ok) => if state.sealed && state.index < u64::MAX && index == state.index + 1 {
            Some(State { index: if ok { index } else { state.index }, sealed: !ok, failed: !ok })
        } else { None },
        Event::Append(index, ok) | Event::Sync(index, ok) => if index == state.index && !state.sealed {
            Some(State { index, sealed: false, failed: !ok })
        } else { None },
    } }
}
pub open spec fn run(trace: Seq<Event>) -> Option<State>
    decreases trace.len(),
{
    if trace.len() == 0 { Some(initial()) }
    else { match run(trace.drop_last()) { Some(state) => step(state, trace.last()), None => None } }
}
pub proof fn push(trace: Seq<Event>, event: Event)
    ensures run(trace.push(event)) == match run(trace) { Some(state) => step(state, event), None => None },
{
    assert(trace.push(event).drop_last() =~= trace);
}

/// Every prefix is legal, segment indices never go backward, and no event
/// follows a failed effect. These are properties of actual primitive calls.
pub proof fn prefix(trace: Seq<Event>, length: int)
    requires run(trace).is_some(), 0 <= length <= trace.len(),
    ensures run(trace.take(length)).is_some(),
        run(trace.take(length)).unwrap().index <= run(trace).unwrap().index,
        length < trace.len() ==> !run(trace.take(length)).unwrap().failed,
    decreases trace.len() - length,
{
    if length < trace.len() {
        prefix(trace.drop_last(), length);
        assert(trace.drop_last().take(length) =~= trace.take(length));
    } else { assert(trace.take(length) =~= trace); }
}

proof fn sealed_last(trace: Seq<Event>)
    requires run(trace).is_some(), run(trace).unwrap().sealed, !run(trace).unwrap().failed,
    ensures trace.len() > 0 && trace.last() == Event::Seal(run(trace).unwrap().index, true),
{}

/// The immediately preceding effect must have successfully sealed the old
/// segment before any successor creation is attempted, even if creation fails.
pub proof fn creation_follows_seal(trace: Seq<Event>, at: int)
    requires run(trace).is_some(), 0 <= at < trace.len(), trace[at] is Create,
    ensures at > 0 && trace[at - 1] == Event::Seal((trace[at]->Create_0 - 1) as u64, true),
{
    prefix(trace, at + 1);
    let through = trace.take(at + 1);
    assert(through.drop_last() =~= trace.take(at));
    assert(through.last() == trace[at]);
    sealed_last(trace.take(at));
}

/// Once creation of segment `next` was attempted, every later append targets
/// that segment or a later one. A failed creation allows no subsequent effects.
pub proof fn no_append_to_predecessor(trace: Seq<Event>, creation: int, later: int)
    requires run(trace).is_some(), 0 <= creation < later < trace.len(),
        trace[creation] is Create, trace[later] is Append,
    ensures trace[creation]->Create_1,
        trace[later]->Append_0 >= trace[creation]->Create_0,
{
    prefix(trace, creation + 1);
    prefix(trace, later);
    prefix(trace, later + 1);
    let created = trace.take(creation + 1);
    assert(created.last() == trace[creation]);
    assert(created.drop_last() =~= trace.take(creation));
    assert(!run(created).unwrap().failed);
    prefix(trace.take(later), creation + 1);
    assert(trace.take(later).take(creation + 1) =~= created);
    let appended = trace.take(later + 1);
    assert(appended.last() == trace[later]);
    assert(appended.drop_last() =~= trace.take(later));
}
}
