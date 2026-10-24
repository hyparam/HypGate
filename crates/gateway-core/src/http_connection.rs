//! One response-body permit per connection. The production adapter reports
//! completed receiver destruction; registry identity and mutex ordering are trusted.
use vstd::prelude::*;
use crate::{resource::{RequestKey, ResourceAdmission}, task_credit::TaskCredit};

verus! {
pub struct ResponsePermit { owner: u64 }
impl ResponsePermit {
    pub closed spec fn owner(&self) -> u64 { self.owner }
}
pub struct ResponseSlot { owner: u64, issued: bool, active: bool, retired: bool }
impl ResponseSlot {
    pub closed spec fn owner(&self) -> u64 { self.owner }
    pub closed spec fn issued(&self) -> bool { self.issued }
    pub closed spec fn active(&self) -> bool { self.active }
    pub closed spec fn retired(&self) -> bool { self.retired }

    pub fn reserve(key: RequestKey) -> (out: (Self, TaskCredit))
        ensures out.0.owner() == key.id(), !out.0.issued(), !out.0.active(), !out.0.retired(),
            out.1.key() == key, out.1.phase() == crate::task_credit::Phase::Reserved,
    {
        let slot = Self { owner: key.owner(), issued: false, active: false, retired: false };
        (slot, TaskCredit::new(key))
    }

    pub fn issue(&mut self) -> (out: Option<ResponsePermit>)
        ensures final(self).owner() == old(self).owner(),
            final(self).retired() == old(self).retired(),
            out.is_some() == (!old(self).issued() && !old(self).retired()),
            match out {
                Some(p) => p.owner() == old(self).owner() && final(self).issued() && final(self).active(),
                None => *final(self) == *old(self),
            },
    {
        if self.issued || self.retired { return None; }
        self.issued = true;
        self.active = true;
        Some(ResponsePermit { owner: self.owner })
    }

    // Consumes the non-cloneable permit only after receiver destruction returns.
    pub fn finish(&mut self, permit: ResponsePermit) -> (ok: bool)
        ensures final(self).owner() == old(self).owner(),
            final(self).issued() == old(self).issued(),
            final(self).retired() == old(self).retired(),
            ok == (old(self).active() && permit.owner() == old(self).owner()),
            ok ==> !final(self).active(), !ok ==> *final(self) == *old(self),
    {
        if !self.active || permit.owner != self.owner { return false; }
        self.active = false;
        true
    }

    pub fn release_task(&mut self, task: TaskCredit, registry: &mut ResourceAdmission) -> (ok: bool)
        requires old(registry).valid(),
        ensures final(registry).valid(), final(self).retired(),
            final(self).owner() == old(self).owner(),
            final(self).issued() == old(self).issued(), final(self).active() == old(self).active(),
            final(registry).limit() == old(registry).limit(),
            final(registry).per_request() == old(registry).per_request(),
            final(registry).next_id() == old(registry).next_id(),
            ok == (!old(self).active() && old(self).owner() == task.key().id()
                && task.releasable() && !task.key().stream_claimed() && old(registry).owns(&task.key())),
            ok ==> !final(registry).owns(&task.key()),
            !ok ==> *final(registry) == *old(registry),
            old(self).active() ==> *final(registry) == *old(registry),
    {
        self.retired = true;
        if self.active || self.owner != task.owner_id() { return false; }
        task.release(registry)
    }
}
}
