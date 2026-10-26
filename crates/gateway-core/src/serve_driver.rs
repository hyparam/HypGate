//! Verified driver for the accept loop and the shutdown drain. The runtime
//! supplies an `Effects` implementation with no decisions in it: it reads the
//! shutdown flag, blocks on accept, takes a connection credit, starts a
//! connection thread, drops the listener, closes worker admission, waits on
//! the registries, cancels what is live, and closes the logger. This driver
//! sequences those effects, so what the shutdown argument promises is checked
//! here rather than promised by the runtime: a connection is served only
//! after the flag was seen clear for it, nothing is accepted or served once
//! the flag was seen set or accept failed, worker admission closes before any
//! wait, in-flight exchanges are cancelled only after a drain window that did
//! not drain, and the logger closes exactly once, after the drain succeeded or
//! after the wait that follows cancellation. The effects themselves stay
//! trusted, as does the signal that sets the flag.
//!
//! The driver keeps a ghost trace of the steps it took; `run` is the
//! specification of which traces are allowed, and the lemmas at the end read
//! the ordering properties off any allowed trace.
use vstd::prelude::*;

verus! {
/// What one blocking accept produced.
#[derive(PartialEq, Eq, Structural, Clone, Copy, Debug)]
pub enum Accepted { Connection, Interrupted, Failed }
/// Which wait: the drain window after acceptance stops, or the one after cancellation.
#[derive(PartialEq, Eq, Structural, Clone, Copy, Debug)]
pub enum Window { Drain, Cancel }

/// What the runtime does for the driver. Every method is trusted to perform
/// exactly the effect named and report what happened; none decides anything.
pub trait Effects {
    /// Whether shutdown has been triggered.
    fn triggered(&mut self) -> bool;
    /// Block for the next inbound connection; the socket stays with the
    /// effects until it is served or discarded.
    fn accept(&mut self) -> Accepted;
    /// Take a connection credit for the accepted socket; false closes it unanswered.
    fn admit_connection(&mut self) -> bool;
    /// Hand the admitted socket and its credit to a connection thread.
    fn serve_connection(&mut self);
    /// Drop the accepted socket: shutdown was triggered after it arrived.
    fn discard_connection(&mut self);
    /// Close the listening socket.
    fn stop_accepting(&mut self);
    /// Permanently close worker admission.
    fn close_workers(&mut self);
    /// Wait up to the window for connection and worker credits to drain; true when both did.
    fn wait_drained(&mut self, window: Window) -> bool;
    /// Cancel every in-flight exchange.
    fn cancel_live(&mut self);
    /// Close, drain, and join the logger; false when it did not finish in its window.
    fn close_log(&mut self) -> bool;
}

// ---- the allowed traces ------------------------------------------------------

/// One step the driver took, as the trace records it.
pub ghost enum Step {
    /// The shutdown flag, as observed.
    Triggered(bool),
    Accept(Accepted),
    /// Whether the accepted socket got a connection credit.
    Admitted(bool),
    Served,
    Discarded,
    StopAccepting,
    CloseWorkers,
    /// A wait on the registries, and whether both drained.
    Wait(Window, bool),
    Cancel,
    /// The logger closed, and whether it finished in its window.
    CloseLog(bool),
}

/// Where the accepted socket stands.
pub ghost enum Pending { Idle, Accepted, Checked(bool), Admitted }

/// What the trace so far has established.
pub ghost struct Progress {
    /// The flag was seen set, or accept failed: no more acceptance.
    pub stop_seen: bool,
    /// The flag was seen clear with no socket pending: an accept may follow.
    pub checked: bool,
    pub pending: Pending,
    pub stopped: bool, pub workers_closed: bool, pub drained: Option<bool>, pub cancelled: bool, pub cancel_waited: bool,
    pub log_closed: Option<bool>,
}
pub open spec fn initial() -> Progress {
    Progress { stop_seen: false, checked: false, pending: Pending::Idle, stopped: false, workers_closed: false,
        drained: None, cancelled: false, cancel_waited: false, log_closed: None }
}
/// The one step relation: which step may follow which progress.
pub open spec fn step_ok(p: Progress, s: Step) -> Option<Progress> {
    match s {
        Step::Triggered(b) => if !p.stop_seen && !p.stopped && (p.pending is Idle || p.pending is Accepted) {
            Some(Progress { stop_seen: b, checked: !b && p.pending is Idle,
                pending: if p.pending is Accepted { Pending::Checked(b) } else { Pending::Idle }, ..p })
        } else { None },
        Step::Accept(a) => if p.checked && !p.stop_seen && p.pending is Idle {
            Some(Progress { checked: false, stop_seen: a == Accepted::Failed,
                pending: if a == Accepted::Connection { Pending::Accepted } else { Pending::Idle }, ..p })
        } else { None },
        Step::Admitted(ok) => if p.pending == Pending::Checked(false) {
            Some(Progress { pending: if ok { Pending::Admitted } else { Pending::Idle }, ..p })
        } else { None },
        Step::Served => if p.pending is Admitted { Some(Progress { pending: Pending::Idle, ..p }) } else { None },
        Step::Discarded => if p.pending == Pending::Checked(true) { Some(Progress { pending: Pending::Idle, ..p }) } else { None },
        Step::StopAccepting => if p.stop_seen && !p.stopped && p.pending is Idle { Some(Progress { stopped: true, ..p }) } else { None },
        Step::CloseWorkers => if p.stopped && !p.workers_closed { Some(Progress { workers_closed: true, ..p }) } else { None },
        Step::Wait(Window::Drain, ok) => if p.workers_closed && p.drained.is_none() { Some(Progress { drained: Some(ok), ..p }) } else { None },
        Step::Cancel => if p.drained == Some(false) && !p.cancelled { Some(Progress { cancelled: true, ..p }) } else { None },
        Step::Wait(Window::Cancel, _) => if p.cancelled && !p.cancel_waited { Some(Progress { cancel_waited: true, ..p }) } else { None },
        Step::CloseLog(ok) => if p.workers_closed && (p.drained == Some(true) || p.cancel_waited) && p.log_closed.is_none() {
            Some(Progress { log_closed: Some(ok), ..p })
        } else { None },
    }
}
/// The progress a trace establishes, or `None` for a trace the driver may not take.
pub open spec fn run(trace: Seq<Step>) -> Option<Progress>
    decreases trace.len(),
{
    if trace.len() == 0 { Some(initial()) }
    else { match run(trace.drop_last()) { Some(p) => step_ok(p, trace.last()), None => None } }
}

proof fn lemma_run_push(t: Seq<Step>, s: Step)
    ensures run(t.push(s)) == (match run(t) { Some(p) => step_ok(p, s), None => None }),
{
    assert(t.push(s).drop_last() =~= t);
}

// ---- the driver state ----------------------------------------------------------

struct Driver { trace: Ghost<Seq<Step>>, progress: Ghost<Progress> }

/// The result: whether accepting ended by the flag rather than a failure,
/// whether the logger finished, and the trace for the theorems.
pub struct Driven { pub accept_ok: bool, pub log_ok: bool, pub trace: Ghost<Seq<Step>>, pub progress: Ghost<Progress> }

impl Driver {
    spec fn inv(&self) -> bool { run(self.trace@) == Some(self.progress@) }

    fn new() -> (out: Self)
        ensures out.inv(), out.progress@ == initial(),
    {
        Driver { trace: Ghost(Seq::empty()), progress: Ghost(initial()) }
    }

    /// Record a step the progress allows.
    fn record(&mut self, Ghost(s): Ghost<Step>)
        requires old(self).inv(), step_ok(old(self).progress@, s).is_some(),
        ensures final(self).inv(), final(self).progress@ == step_ok(old(self).progress@, s).unwrap(),
            final(self).trace@ == old(self).trace@.push(s),
    {
        proof { lemma_run_push(self.trace@, s); }
        self.trace = Ghost(self.trace@.push(s));
        self.progress = Ghost(step_ok(self.progress@, s).unwrap());
    }

    /// Accept until the flag is seen set or accept fails. Every connection
    /// served was accepted and then found the flag clear.
    #[verifier::exec_allows_no_decreases_clause]
    fn accept_loop<E: Effects>(&mut self, effects: &mut E) -> (ok: bool)
        requires old(self).inv(), old(self).progress@ == initial(),
        ensures final(self).inv(), final(self).progress@ == (Progress { stop_seen: true, ..initial() }),
    {
        loop
            invariant self.inv(), self.progress@ == initial(),
        {
            let t = effects.triggered();
            self.record(Ghost(Step::Triggered(t)));
            if t { return true; }
            let a = effects.accept();
            self.record(Ghost(Step::Accept(a)));
            match a {
                Accepted::Failed => return false,
                Accepted::Interrupted => {}
                Accepted::Connection => {
                    let t = effects.triggered();
                    self.record(Ghost(Step::Triggered(t)));
                    if t {
                        effects.discard_connection();
                        self.record(Ghost(Step::Discarded));
                        return true;
                    }
                    let ok = effects.admit_connection();
                    self.record(Ghost(Step::Admitted(ok)));
                    if ok {
                        effects.serve_connection();
                        self.record(Ghost(Step::Served));
                    }
                }
            }
        }
    }
}

/// Serve until shutdown is triggered or accept fails, then drain: stop
/// accepting, close worker admission, wait one window, cancel and wait once
/// more if that did not drain, and close the logger.
pub fn serve<E: Effects>(effects: &mut E) -> (out: Driven)
    ensures run(out.trace@) == Some(out.progress@), out.progress@.stop_seen, out.progress@.stopped, out.progress@.workers_closed,
        out.progress@.drained == Some(true) || out.progress@.cancel_waited, out.progress@.log_closed == Some(out.log_ok),
        out.progress@.pending is Idle,
{
    let mut d = Driver::new();
    let accept_ok = d.accept_loop(effects);
    effects.stop_accepting();
    d.record(Ghost(Step::StopAccepting));
    effects.close_workers();
    d.record(Ghost(Step::CloseWorkers));
    let drained = effects.wait_drained(Window::Drain);
    d.record(Ghost(Step::Wait(Window::Drain, drained)));
    if !drained {
        effects.cancel_live();
        d.record(Ghost(Step::Cancel));
        let again = effects.wait_drained(Window::Cancel);
        d.record(Ghost(Step::Wait(Window::Cancel, again)));
    }
    let log_ok = effects.close_log();
    d.record(Ghost(Step::CloseLog(log_ok)));
    Driven { accept_ok, log_ok, trace: d.trace, progress: d.progress }
}

// ---- what an allowed trace guarantees ---------------------------------------------

/// Every prefix of an allowed trace is allowed.
pub proof fn lemma_prefix_runs(t: Seq<Step>, n: int)
    requires run(t).is_some(), 0 <= n <= t.len(),
    ensures run(t.take(n)).is_some(),
    decreases t.len() - n,
{
    if n < t.len() {
        let shorter = t.drop_last();
        assert(shorter =~= t.take(t.len() - 1));
        assert(shorter.take(n) =~= t.take(n));
        lemma_prefix_runs(shorter, n);
    } else {
        assert(t.take(n) =~= t);
    }
}

/// The progress fields that are set have the step that set them in the
/// trace, a pending socket has its last steps at the end of the trace, and
/// once the stop was seen nothing is pending but a socket to discard.
pub proof fn lemma_progress_reflects(t: Seq<Step>)
    requires run(t).is_some(),
    ensures ({
        let p = run(t).unwrap();
        (p.stop_seen ==> exists|j: int| 0 <= j < t.len() && (t[j] == Step::Triggered(true) || t[j] == Step::Accept(Accepted::Failed)))
        && (p.stop_seen ==> p.pending is Idle || p.pending == Pending::Checked(true))
        && (p.pending is Accepted ==> t.len() >= 1 && t.last() == Step::Accept(Accepted::Connection))
        && (forall|b: bool| p.pending == Pending::Checked(b) ==> t.len() >= 2 && t.last() == Step::Triggered(b)
            && t[t.len() - 2] == Step::Accept(Accepted::Connection))
        && (p.pending is Admitted ==> t.len() >= 3 && t.last() == Step::Admitted(true) && t[t.len() - 2] == Step::Triggered(false)
            && t[t.len() - 3] == Step::Accept(Accepted::Connection))
        && (p.stopped ==> p.stop_seen && exists|j: int| 0 <= j < t.len() && t[j] == Step::StopAccepting)
        && (p.workers_closed ==> p.stopped && exists|j: int| 0 <= j < t.len() && t[j] == Step::CloseWorkers)
        && (p.drained.is_some() ==> p.workers_closed && exists|j: int| 0 <= j < t.len() && t[j] == Step::Wait(Window::Drain, p.drained.unwrap()))
        && (p.cancelled ==> p.drained == Some(false) && exists|j: int| 0 <= j < t.len() && t[j] == Step::Cancel)
        && (p.cancel_waited ==> p.cancelled && exists|j: int, b: bool| 0 <= j < t.len() && t[j] == Step::Wait(Window::Cancel, b))
        && (p.log_closed.is_some() ==> exists|j: int| 0 <= j < t.len() && t[j] == Step::CloseLog(p.log_closed.unwrap()))
    }),
    decreases t.len(),
{
    if t.len() > 0 {
        let shorter = t.drop_last();
        lemma_progress_reflects(shorter);
        let p = run(t).unwrap();
        let q = run(shorter).unwrap();
        let last = t.len() - 1;
        assert(forall|j: int| 0 <= j < shorter.len() ==> t[j] == shorter[j]);
        if p.stop_seen && q.stop_seen {
            let j = choose|j: int| 0 <= j < shorter.len() && (shorter[j] == Step::Triggered(true) || shorter[j] == Step::Accept(Accepted::Failed));
            assert(t[j] == Step::Triggered(true) || t[j] == Step::Accept(Accepted::Failed));
        }
        if p.stopped && q.stopped {
            let j = choose|j: int| 0 <= j < shorter.len() && shorter[j] == Step::StopAccepting;
            assert(t[j] == Step::StopAccepting);
        }
        if p.workers_closed && q.workers_closed {
            let j = choose|j: int| 0 <= j < shorter.len() && shorter[j] == Step::CloseWorkers;
            assert(t[j] == Step::CloseWorkers);
        }
        if p.drained.is_some() && q.drained.is_some() {
            let j = choose|j: int| 0 <= j < shorter.len() && shorter[j] == Step::Wait(Window::Drain, q.drained.unwrap());
            assert(t[j] == Step::Wait(Window::Drain, p.drained.unwrap()));
        }
        if p.cancelled && q.cancelled {
            let j = choose|j: int| 0 <= j < shorter.len() && shorter[j] == Step::Cancel;
            assert(t[j] == Step::Cancel);
        }
        if p.cancel_waited && q.cancel_waited {
            let (j, b) = choose|j: int, b: bool| 0 <= j < shorter.len() && shorter[j] == Step::Wait(Window::Cancel, b);
            assert(t[j] == Step::Wait(Window::Cancel, b));
        }
        if p.log_closed.is_some() && q.log_closed.is_some() {
            let j = choose|j: int| 0 <= j < shorter.len() && shorter[j] == Step::CloseLog(q.log_closed.unwrap());
            assert(t[j] == Step::CloseLog(p.log_closed.unwrap()));
        }
    }
}

/// Each step preserves the fields that only ever get set.
proof fn lemma_step_monotone(p: Progress, s: Step)
    requires step_ok(p, s).is_some(),
    ensures ({
        let q = step_ok(p, s).unwrap();
        (p.stop_seen ==> q.stop_seen) && (p.stopped ==> q.stopped) && (p.workers_closed ==> q.workers_closed)
        && (p.drained.is_some() ==> q.drained == p.drained) && (p.cancelled ==> q.cancelled) && (p.cancel_waited ==> q.cancel_waited)
        && (p.log_closed.is_some() ==> q.log_closed == p.log_closed)
    }),
{}

/// What a prefix established, the whole trace still has.
pub proof fn lemma_monotone(t: Seq<Step>, n: int)
    requires run(t).is_some(), 0 <= n <= t.len(),
    ensures ({
        let p = run(t.take(n)).unwrap();
        let q = run(t).unwrap();
        (p.stop_seen ==> q.stop_seen) && (p.stopped ==> q.stopped) && (p.workers_closed ==> q.workers_closed)
        && (p.drained.is_some() ==> q.drained == p.drained) && (p.cancelled ==> q.cancelled) && (p.cancel_waited ==> q.cancel_waited)
        && (p.log_closed.is_some() ==> q.log_closed == p.log_closed)
    }),
    decreases t.len() - n,
{
    lemma_prefix_runs(t, n);
    if n < t.len() {
        let shorter = t.drop_last();
        assert(shorter =~= t.take(t.len() - 1));
        assert(shorter.take(n) =~= t.take(n));
        lemma_monotone(shorter, n);
        lemma_step_monotone(run(shorter).unwrap(), t.last());
    } else {
        assert(t.take(n) =~= t);
    }
}

/// Once the flag was seen set or accept failed, nothing is accepted or served.
pub proof fn lemma_nothing_served_after_stop(t: Seq<Step>, i: int, j: int)
    requires run(t).is_some(), 0 <= i < j < t.len(), t[i] == Step::Triggered(true) || t[i] == Step::Accept(Accepted::Failed),
    ensures !(t[j] is Served), !(t[j] is Accept), !(t[j] is Admitted),
{
    lemma_prefix_runs(t, j + 1);
    let upto = t.take(j + 1);
    let before = t.take(j);
    assert(upto.drop_last() =~= before);
    lemma_prefix_runs(before, i + 1);
    assert(before.take(i + 1) =~= t.take(i + 1));
    assert(t.take(i + 1).drop_last() =~= t.take(i));
    lemma_prefix_runs(t, i);
    assert(run(t.take(i + 1)).unwrap().stop_seen);
    lemma_monotone(before, i + 1);
    lemma_progress_reflects(before);
}

/// A served connection was accepted, then found the flag clear, then got a credit.
pub proof fn lemma_served_sequence(t: Seq<Step>, i: int)
    requires run(t).is_some(), 0 <= i < t.len(), t[i] is Served,
    ensures i >= 3, t[i - 1] == Step::Admitted(true), t[i - 2] == Step::Triggered(false), t[i - 3] == Step::Accept(Accepted::Connection),
{
    lemma_prefix_runs(t, i + 1);
    let upto = t.take(i + 1);
    let before = t.take(i);
    assert(upto.drop_last() =~= before);
    lemma_progress_reflects(before);
}

/// Cancellation follows a drain window that did not drain, after worker
/// admission closed, after acceptance stopped.
pub proof fn lemma_cancel_after_failed_drain(t: Seq<Step>, i: int)
    requires run(t).is_some(), 0 <= i < t.len(), t[i] is Cancel,
    ensures exists|j: int| 0 <= j < i && t[j] == Step::Wait(Window::Drain, false),
        exists|j: int| 0 <= j < i && t[j] == Step::CloseWorkers,
        exists|j: int| 0 <= j < i && t[j] == Step::StopAccepting,
{
    lemma_prefix_runs(t, i + 1);
    let upto = t.take(i + 1);
    let before = t.take(i);
    assert(upto.drop_last() =~= before);
    lemma_progress_reflects(before);
    let p = run(before).unwrap();
    let j = choose|j: int| 0 <= j < before.len() && before[j] == Step::Wait(Window::Drain, p.drained.unwrap());
    assert(t[j] == Step::Wait(Window::Drain, false));
    let k = choose|k: int| 0 <= k < before.len() && before[k] == Step::CloseWorkers;
    assert(t[k] == Step::CloseWorkers);
    let m = choose|m: int| 0 <= m < before.len() && before[m] == Step::StopAccepting;
    assert(t[m] == Step::StopAccepting);
}

/// The logger closes after worker admission closed and after the drain
/// succeeded or, cancellation having happened, the wait that follows it.
pub proof fn lemma_log_closes_last(t: Seq<Step>, i: int)
    requires run(t).is_some(), 0 <= i < t.len(), t[i] is CloseLog,
    ensures exists|j: int| 0 <= j < i && t[j] == Step::CloseWorkers,
        (exists|j: int| 0 <= j < i && t[j] == Step::Wait(Window::Drain, true))
            || (exists|j: int, k: int, b: bool| 0 <= j < k < i && t[j] == Step::Cancel && t[k] == Step::Wait(Window::Cancel, b)),
{
    lemma_prefix_runs(t, i + 1);
    let upto = t.take(i + 1);
    let before = t.take(i);
    assert(upto.drop_last() =~= before);
    lemma_progress_reflects(before);
    let p = run(before).unwrap();
    let k = choose|k: int| 0 <= k < before.len() && before[k] == Step::CloseWorkers;
    assert(t[k] == Step::CloseWorkers);
    if p.drained == Some(true) {
        let j = choose|j: int| 0 <= j < before.len() && before[j] == Step::Wait(Window::Drain, true);
        assert(t[j] == Step::Wait(Window::Drain, true));
    } else {
        let (k, b) = choose|k: int, b: bool| 0 <= k < before.len() && before[k] == Step::Wait(Window::Cancel, b);
        lemma_prefix_runs(before, k + 1);
        assert(before.take(k + 1).drop_last() =~= before.take(k));
        lemma_prefix_runs(before, k);
        let q = run(before.take(k)).unwrap();
        lemma_progress_reflects(before.take(k));
        let j = choose|j: int| 0 <= j < k && before.take(k)[j] == Step::Cancel;
        assert(t[j] == Step::Cancel && t[k] == Step::Wait(Window::Cancel, b));
    }
}

/// Acceptance stops, worker admission closes, cancellation happens, and the
/// logger closes at most once each.
pub proof fn lemma_once(t: Seq<Step>, i: int, j: int)
    requires run(t).is_some(), 0 <= i < j < t.len(),
    ensures !(t[i] is StopAccepting && t[j] is StopAccepting), !(t[i] is CloseWorkers && t[j] is CloseWorkers),
        !(t[i] is Cancel && t[j] is Cancel), !(t[i] is CloseLog && t[j] is CloseLog),
        !((t[i] is Wait && t[i]->Wait_0 == Window::Drain) && (t[j] is Wait && t[j]->Wait_0 == Window::Drain)),
{
    lemma_prefix_runs(t, j + 1);
    let upto = t.take(j + 1);
    let before = t.take(j);
    assert(upto.drop_last() =~= before);
    lemma_prefix_runs(before, i + 1);
    assert(before.take(i + 1) =~= t.take(i + 1));
    assert(t.take(i + 1).drop_last() =~= t.take(i));
    lemma_prefix_runs(t, i);
    lemma_monotone(before, i + 1);
}
} // verus!
