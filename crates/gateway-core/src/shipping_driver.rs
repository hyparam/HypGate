//! Verified driver for the shipper machine. The runtime supplies an `Effects`
//! implementation with no decisions in it: a clock, a record source, a row
//! projector, one request sender, sleeps, a checkpoint writer, and a metrics
//! sink. This loop is what calls the machine, so the machine's turn-taking
//! (one reply per request, every emitted token projected and queued at once,
//! checkpoints only from its own progress) is checked here rather than
//! promised by the runtime. The effects themselves stay trusted.
use vstd::prelude::*;
use crate::exchange_assembler::Exchange;
use crate::framing::Header;
use crate::shipper::{Action, Machine, Outcome, Reply, Request};

verus! {
/// One step of the record source.
pub enum Read { Record(Header, Vec<u8>), End, Failed }

/// An exchange's NDJSON rows, each followed by a newline, and the row count.
pub struct Projected { pub body: Vec<u8>, pub rows: usize }

#[derive(PartialEq, Eq, Structural, Clone, Copy, Debug)]
pub enum Event { RecordRead, ExchangeEmitted, Replied(Outcome), PoisonedUnsent, Stopped, Waiting }

#[derive(PartialEq, Eq, Structural, Clone, Copy, Debug)]
pub enum Mode { Follow, Drain }

#[derive(PartialEq, Eq, Structural, Clone, Copy, Debug)]
pub enum Halt { StopRequested, Drained, Revoked }

/// Idle polls with nothing read before a drain run flushes open exchanges.
pub const DRAIN_IDLE_POLLS: u32 = 5;

/// What the runtime does for the driver. Every method is trusted; none of
/// them decides anything about what is shipped.
pub trait Effects {
    fn stop_requested(&mut self) -> bool;
    fn now(&mut self) -> u64;
    fn read(&mut self) -> Read;
    fn project(&mut self, exchange: &Exchange) -> Projected;
    fn send(&mut self, request: Request) -> Reply;
    /// False when a stop was requested during the wait.
    fn sleep(&mut self, seconds: u64) -> bool;
    /// One poll interval; false when a stop was requested during the wait.
    fn idle(&mut self) -> bool;
    /// Only the machine's own progress may be written down.
    fn checkpoint(&mut self, machine: &Machine, resolved: u64, poisoned: u64)
        requires resolved == machine.resolved(), poisoned == machine.poisoned();
    fn observe(&mut self, event: Event, machine: &Machine);
}

fn header_ok(header: &Header, len: usize) -> (out: bool)
    ensures out == (crate::framing::valid(*header) && header.payload == len),
{
    header.payload <= 1048576 && header.request != 0 && header.kind <= 4 && header.payload as usize == len
}

// Project an emitted exchange and queue it. With no token outstanding, the
// token's index is exactly the next the machine counts, so this never fails.
fn settle<E: Effects>(machine: &mut Machine, effects: &mut E, token: crate::shipper::Emitted)
    requires old(machine).valid(), token.index() == old(machine).counted(), token.index() < old(machine).emitted(),
        token.request() == old(machine).emissions()[token.index() as int],
    ensures final(machine).valid(), final(machine).outstanding() == 0 || final(machine).counted() == old(machine).counted() + 1,
        final(machine).counted() == old(machine).counted() + 1, final(machine).emitted() == old(machine).emitted(),
        final(machine).awaiting() == old(machine).awaiting(), final(machine).same_credential(old(machine)),
        final(machine).at_end() == old(machine).at_end(), final(machine).read_failed() == old(machine).read_failed(),
        final(machine).open_count() == old(machine).open_count(),
{
    proof { old(machine).valid_bounds(); }
    effects.observe(Event::ExchangeEmitted, machine);
    let projected = effects.project(token.exchange());
    match machine.enqueue(token, projected.body, projected.rows) {
        Ok(()) => {}
        Err(_) => { proof { assert(false); } }
    }
}

/// The most records one `pump` reads before returning to the drive loop, so
/// a stop request is seen within a bounded batch and the read loop terminates
/// whatever the log holds.
pub const PUMP_BATCH: u32 = 1024;

/// Read while the machine wants records, at most `PUMP_BATCH` of them.
/// Returns the number of records read.
fn pump<E: Effects>(machine: &mut Machine, effects: &mut E) -> (count: u32)
    requires old(machine).valid(), old(machine).outstanding() == 0, old(machine).awaiting().is_none(),
    ensures final(machine).valid(), final(machine).outstanding() == 0, final(machine).awaiting().is_none(),
        count <= PUMP_BATCH,
{
    let mut count: u32 = 0;
    while count < PUMP_BATCH && machine.wants_records()
        invariant machine.valid(), machine.outstanding() == 0, machine.awaiting().is_none(), count <= PUMP_BATCH,
        decreases PUMP_BATCH - count,
    {
        proof { machine.valid_bounds(); }
        match effects.read() {
            Read::Record(header, payload) => {
                count = count + 1;
                effects.observe(Event::RecordRead, machine);
                if header_ok(&header, payload.len()) {
                    match machine.admit(header, payload.as_slice()) {
                        Some(token) => settle(machine, effects, token),
                        None => {}
                    }
                } else {
                    machine.log_failed();
                }
            }
            // The machine stops wanting records; leave without another round.
            Read::End => { machine.end_of_log(); break; }
            Read::Failed => { machine.log_failed(); break; }
        }
        proof { machine.valid_bounds(); }
    }
    count
}

/// Drain mode: emit every open exchange as incomplete. True while anything
/// remains to ship.
fn flush<E: Effects>(machine: &mut Machine, effects: &mut E) -> (remaining: bool)
    requires old(machine).valid(), old(machine).outstanding() == 0, old(machine).awaiting().is_none(),
    ensures final(machine).valid(), final(machine).outstanding() == 0, final(machine).awaiting().is_none(),
{
    let mut emitted = false;
    while machine.open_exchanges() > 0 && machine.has_room() && !machine.has_read_failed()
        invariant machine.valid(), machine.outstanding() == 0, machine.awaiting().is_none(),
        decreases machine.open_count(),
    {
        proof { machine.valid_bounds(); }
        match machine.flush() {
            Some(token) => { settle(machine, effects, token); emitted = true; }
            None => { proof { machine.valid_bounds(); } break; }
        }
        proof { machine.valid_bounds(); }
    }
    emitted || machine.queue_len() > 0 || machine.open_exchanges() > 0
}

/// One round of the drive loop: a stop check, then the machine's next action
/// performed against the effects. `Some` when the loop is over. Every round
/// terminates: the read and flush loops inside it are measured.
fn drive_step<E: Effects>(machine: &mut Machine, effects: &mut E, mode: Mode, idle_polls: &mut u32) -> (out: Option<Halt>)
    requires old(machine).valid(), old(machine).awaiting().is_none(), old(machine).outstanding() == 0,
    ensures final(machine).valid(), final(machine).awaiting().is_none(), final(machine).outstanding() == 0,
        out == Some(Halt::Revoked) ==> final(machine).stopped(),
{
    proof { machine.valid_bounds(); }
    if effects.stop_requested() { return Some(Halt::StopRequested); }
    let now = effects.now();
    match machine.next(now) {
        Action::Stopped => {
            effects.observe(Event::Stopped, machine);
            if mode == Mode::Drain { return Some(Halt::Revoked); }
            if !effects.idle() { return Some(Halt::StopRequested); }
        }
        Action::Sleep(seconds) => {
            effects.observe(Event::Waiting, machine);
            if !effects.sleep(seconds) { return Some(Halt::StopRequested); }
        }
        Action::Read => {
            let read = pump(machine, effects);
            *idle_polls = if read == 0 { if *idle_polls < u32::MAX { *idle_polls + 1 } else { *idle_polls } } else { 0 };
        }
        Action::Idle => {
            if mode == Mode::Drain && *idle_polls >= DRAIN_IDLE_POLLS {
                if !flush(machine, effects) { return Some(Halt::Drained); }
                *idle_polls = 0;
            } else {
                effects.observe(Event::Waiting, machine);
                if !effects.idle() { return Some(Halt::StopRequested); }
            }
        }
        Action::Poisoned => {
            let (resolved, poisoned) = machine.progress();
            effects.checkpoint(machine, resolved, poisoned);
            effects.observe(Event::PoisonedUnsent, machine);
        }
        Action::Send(request) => {
            let reply = effects.send(request);
            let replied_at = effects.now();
            let outcome = machine.reply(replied_at, reply);
            match outcome {
                Outcome::Acknowledged(_) | Outcome::Poisoned => {
                    let (resolved, poisoned) = machine.progress();
                    effects.checkpoint(machine, resolved, poisoned);
                }
                _ => {}
            }
            effects.observe(Event::Replied(outcome), machine);
        }
    }
    None
}

/// Run the machine against the effects until a stop is requested, a drain
/// finishes, or the credential is revoked. The machine is always valid, never
/// holds a token across iterations, and has no request outstanding between
/// a send and its reply.
///
/// This is a service loop: each round is the verified, terminating
/// `drive_step`, and the loop ends when a round reports a halt. A round that
/// sees `stop_requested` halts at once, so the loop ends within one round of
/// a stop request; that the effects eventually report one is the liveness
/// assumption on the environment, not a theorem here.
#[verifier::exec_allows_no_decreases_clause]
pub fn drive<E: Effects>(machine: &mut Machine, effects: &mut E, mode: Mode) -> (out: Halt)
    requires old(machine).valid(), old(machine).awaiting().is_none(), old(machine).outstanding() == 0,
    ensures final(machine).valid(), final(machine).awaiting().is_none(), final(machine).outstanding() == 0,
        out == Halt::Revoked ==> final(machine).stopped(),
{
    let mut idle_polls: u32 = 0;
    loop
        invariant machine.valid(), machine.awaiting().is_none(), machine.outstanding() == 0,
    {
        match drive_step(machine, effects, mode, &mut idle_polls) {
            Some(halt) => return halt,
            None => {}
        }
    }
}
}
