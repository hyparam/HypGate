//! Verified join from S3 effects to the existing shipping driver and checkpoint machine.
use vstd::prelude::*;
use crate::{shipping_driver::{self, Effects, Read, Projected, Event, Mode, Halt},
    s3_config::Config, s3_delivery::{self, Transport}, shipping_checkpoint::{self as checkpoint, Checkpoint},
    shipper::{Machine, Request, Reply}, exchange_assembler::Exchange};

verus! {
/// Persistence remains an external effect. The executable codec and all selection/capture decisions are verified.
pub trait Store {
    spec fn saved(&self) -> Seq<Checkpoint>;
    // Reads may fail and return None; successful writes must persist the captured value.
    spec fn persisted(&self) -> Option<Checkpoint>;
    fn load(&mut self) -> (out: Option<Checkpoint>)
        ensures out.is_some() ==> out == old(self).persisted(), final(self).persisted() == old(self).persisted(), final(self).saved() == old(self).saved();
    fn save(&mut self, value: Checkpoint) -> (ok: bool)
        ensures final(self).saved() == old(self).saved().push(value),
            ok ==> final(self).persisted() == Some(value),
            !ok ==> (final(self).persisted() == old(self).persisted() || final(self).persisted() == Some(value));
}
struct Adapter<'a, E> { config: &'a Config, io: &'a mut E, identity: Vec<u8>, open: usize, bytes: usize }
impl<'a, E: Effects + Transport + Store> Effects for Adapter<'a, E> {
    open spec fn is_s3(&self) -> bool { true }
    fn stop_requested(&mut self) -> bool { self.io.stop_requested() }
    fn now(&mut self) -> u64 { self.io.now() }
    fn read(&mut self) -> Read { self.io.read() }
    fn project(&mut self, exchange: &Exchange) -> Projected { self.io.project(exchange) }
    fn send(&mut self, request: Request) -> (out: Reply) {
        let ms = self.io.milliseconds();
        s3_delivery::send(self.config, self.io, request, ms)
    }
    fn sleep(&mut self, seconds: u64) -> bool { self.io.sleep(seconds) }
    fn idle(&mut self) -> bool { self.io.idle() }
    fn checkpoint(&mut self, machine: &Machine, resolved: u64, poisoned: u64) {
        let value = checkpoint::capture(machine, self.identity.as_slice(), self.open, self.bytes, resolved, poisoned);
        let _ = self.io.save(value);
    }
    fn observe(&mut self, event: Event, machine: &Machine) { self.io.observe(event, machine); }
}
/// Exact matching checkpoint or replay from zero; the machine never receives an AWS secret.
pub fn restore(c: &Config, session: [u8; 16], open: usize, bytes: usize, saved: &Option<Checkpoint>) -> (out: Machine)
    requires open > 0,
    ensures out.valid(), out.token().len() == 0, out.session() == session@,
        out.max_open() == open, out.max_bytes() == bytes,
        out.resolved() == (match saved { Some(s) => if checkpoint::matches(*s, checkpoint::identity_spec(*c, session@), open, bytes) { s.resolved } else { 0 }, None => 0 }),
        out.poisoned() == (match saved { Some(s) => if checkpoint::matches(*s, checkpoint::identity_spec(*c, session@), open, bytes) { s.poisoned } else { 0 }, None => 0 }),
        out.outstanding() == 0, out.awaiting().is_none(),
{
    let identity = checkpoint::identity(c, &session);
    let (resolved, poisoned) = checkpoint::select(saved, identity.as_slice(), open, bytes);
    Machine::new(Vec::new(), session, open, bytes, resolved, poisoned)
}
/// Uses the same scope for restore and every saved checkpoint and the verified S3 send for every request.
pub fn run<E: Effects + Transport + Store>(config: &Config, io: &mut E, session: [u8; 16], open: usize, bytes: usize, mode: Mode) -> (out: Halt)
    requires open > 0,
{
    let saved = io.load();
    let mut machine = restore(config, session, open, bytes, &saved);
    let mut adapter = Adapter { config, io, identity: checkpoint::identity(config, &session), open, bytes };
    shipping_driver::drive(&mut machine, &mut adapter, mode)
}
} // verus!
