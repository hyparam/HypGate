//! Executable task cleanup gate. Reporting actual future destruction remains a
//! trusted adapter obligation; cancellation or beginning cleanup is insufficient.
use vstd::prelude::*;
use crate::{drain::DrainRegistry, resource::{ResourceAdmission, RequestKey}};

verus! {
pub enum Phase { Reserved, Running, AwaitingAdoption, Cleaning, Cleaned, HandedOff(u64) }

pub struct TaskCredit { key: RequestKey, phase: Phase }
impl TaskCredit {
    pub closed spec fn key(&self) -> RequestKey { self.key }
    pub closed spec fn phase(&self) -> Phase { self.phase }
    pub open spec fn retaining(&self) -> bool {
        self.phase() == Phase::Running || self.phase() == Phase::AwaitingAdoption || self.phase() == Phase::Cleaning
    }
    pub open spec fn releasable(&self) -> bool { !self.retaining() }

    pub fn new(key: RequestKey) -> (out: Self)
        ensures out.key() == key, out.phase() == Phase::Reserved,
    { Self { key, phase: Phase::Reserved } }

    pub fn start(&mut self) -> (ok: bool)
        ensures final(self).key() == old(self).key(),
            ok == (old(self).phase() == Phase::Reserved),
            ok ==> final(self).phase() == Phase::Running,
            !ok ==> *final(self) == *old(self),
    {
        if !matches!(self.phase, Phase::Reserved) { return false; }
        self.phase = Phase::Running;
        true
    }

    pub fn begin_cleanup(&mut self) -> (ok: bool)
        ensures final(self).key() == old(self).key(),
            ok == (old(self).phase() == Phase::Running || old(self).phase() == Phase::AwaitingAdoption),
            ok ==> final(self).phase() == Phase::Cleaning,
            !ok ==> *final(self) == *old(self),
            old(self).retaining() ==> final(self).retaining(),
    {
        if !matches!(self.phase, Phase::Running | Phase::AwaitingAdoption) { return false; }
        self.phase = Phase::Cleaning;
        true
    }

    /// Call only after the task's future and its captures have been destroyed.
    /// Verus checks the transition, not the external destructor correspondence.
    pub fn finish_cleanup(&mut self) -> (ok: bool)
        ensures final(self).key() == old(self).key(),
            ok == (old(self).phase() == Phase::Cleaning),
            ok ==> final(self).phase() == Phase::Cleaned,
            !ok ==> *final(self) == *old(self),
    {
        if !matches!(self.phase, Phase::Cleaning) { return false; }
        self.phase = Phase::Cleaned;
        true
    }

    pub fn can_release(&self) -> (ok: bool)
        ensures ok == self.releasable(),
    { matches!(self.phase, Phase::Reserved | Phase::Cleaned | Phase::HandedOff(_)) }

    /// Report that work/captures have finished and only its owned result remains.
    /// The reply still retains capacity; completion is not release or adoption.
    pub fn finish_work(&mut self) -> (ok: bool)
        ensures final(self).key() == old(self).key(),
            ok == (old(self).phase() == Phase::Running),
            ok ==> final(self).phase() == Phase::AwaitingAdoption && final(self).retaining(),
            !ok ==> *final(self) == *old(self),
    {
        if !matches!(self.phase, Phase::Running) { return false; }
        self.phase = Phase::AwaitingAdoption;
        true
    }

    /// Move result accounting to an actually live admitted stream before the
    /// background registry can release its credit. The adapter moves the value.
    pub fn handoff_to(&mut self, registry: &ResourceAdmission,
        owner: &crate::owned_stream::OwnedStream) -> (ok: bool)
        requires registry.valid(), owner.valid(),
        ensures final(self).key() == old(self).key(),
            ok == (old(self).phase() == Phase::AwaitingAdoption && registry.owns(&owner.key())
                && !owner.state().closed()),
            ok ==> final(self).phase() == Phase::HandedOff(owner.key().id())
                && final(self).releasable() && registry.owns(&owner.key()),
            !ok ==> *final(self) == *old(self),
    {
        if !matches!(self.phase, Phase::AwaitingAdoption) || !owner.is_live(registry) { return false; }
        self.phase = Phase::HandedOff(owner.owner_id());
        true
    }

    pub fn release(self, registry: &mut ResourceAdmission) -> (ok: bool)
        requires old(registry).valid(),
        ensures final(registry).valid(),
            final(registry).limit() == old(registry).limit(),
            final(registry).per_request() == old(registry).per_request(),
            final(registry).next_id() == old(registry).next_id(),
            ok == (self.releasable() && !self.key().stream_claimed() && old(registry).owns(&self.key())),
            ok ==> !self.retaining() && !final(registry).owns(&self.key())
                && crate::resource::occupied(final(registry).entries()) + 1 == crate::resource::occupied(old(registry).entries()),
            !ok ==> *final(registry) == *old(registry),
            self.retaining() ==> *final(registry) == *old(registry),
    {
        if !self.can_release() { return false; }
        registry.release(&self.key)
    }

    pub fn release_worker(self, registry: &mut DrainRegistry) -> (ok: bool)
        requires old(registry).valid(),
        ensures final(registry).valid(),
            final(registry).closed() == old(registry).closed(),
            final(registry).limit() == old(registry).limit(),
            ok == (self.releasable() && !self.key().stream_claimed() && old(registry).owns(&self.key())),
            ok ==> !self.retaining() && !final(registry).owns(&self.key())
                && final(registry).remaining() + 1 == old(registry).remaining(),
            !ok ==> *final(registry) == *old(registry),
            self.retaining() ==> *final(registry) == *old(registry),
    {
        if !self.can_release() { return false; }
        registry.release(&self.key)
    }
}

// A retained task's slot is occupied, so admission cannot choose that slot.
// This derives non-reuse from the actual acquire contract rather than assuming
// that a caller's next ownership snapshot already satisfies the invariant.
pub proof fn acquire_preserves_retained_task(before: ResourceAdmission,
    after: ResourceAdmission, task: TaskCredit, issued: RequestKey)
    requires before.owns(&task.key()), task.retaining(), issued.slot() < before.limit(),
        before.entries()[issued.slot() as int] == 0,
        forall|i: int| 0 <= i < before.limit() && i != issued.slot()
            ==> #[trigger] after.entries()[i] == before.entries()[i],
        after.limit() == before.limit(),
    ensures issued.slot() != task.key().slot(), after.owns(&task.key()),
{
    before.ownership_facts(&task.key());
    after.layout();
    assert(issued.slot() != task.key().slot());
    // Expose the private ownership predicate through a core helper.
    after.entry_owns(&task.key());
}
}
