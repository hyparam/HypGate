//! Executable task cleanup gate. Reporting actual future destruction remains a
//! trusted adapter obligation; cancellation or beginning cleanup is insufficient.
use vstd::prelude::*;
use crate::{drain::DrainRegistry, resource::{ResourceAdmission, RequestKey}};

verus! {
pub enum Phase { Reserved, Running, AwaitingAdoption, Cleaning, Cleaned, HandedOff(u64) }

// Non-cloneable cleanup owner issued by the exact task that enters Cleaning.
// The value is the real future/captures/reply supplied by the runtime adapter.
pub struct TaskCleanup<T> { owner: u64, cleanup: crate::mailbox::Cleanup<T> }
impl<T> TaskCleanup<T> {
    pub closed spec fn owner(&self) -> u64 { self.owner }
    pub closed spec fn valid(&self) -> bool { self.cleanup.valid() }
    pub closed spec fn original(&self) -> Option<T> { self.cleanup.original() }
    pub closed spec fn finished(&self) -> bool { self.cleanup.finished() }
    pub closed spec fn started(&self) -> bool { self.cleanup.started() }
    pub fn take(&mut self) -> (out: Option<T>)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).owner() == old(self).owner(),
            final(self).original() == old(self).original(), final(self).finished() == old(self).finished(),
            final(self).started(), out == (if old(self).started() { None } else { old(self).original() }),
    { self.cleanup.begin() }
    // Adapter reports normal return from destruction of the extracted value.
    pub fn finish(&mut self) -> (ok: bool)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).owner() == old(self).owner(),
            final(self).original() == old(self).original(), ok ==> final(self).finished(),
            ok == (old(self).started() && !old(self).finished()),
            !old(self).finished() && !ok ==> !final(self).finished(),
    { self.cleanup.finish() }
}

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

    pub fn begin_cleanup_with<T>(&mut self, value: T) -> (out: Result<TaskCleanup<T>, T>)
        ensures final(self).key() == old(self).key(),
            match out {
                Ok(cleanup) => cleanup.valid() && cleanup.original() == Some(value)
                    && cleanup.owner() == old(self).key().id() && !cleanup.finished()
                    && final(self).phase() == Phase::Cleaning && final(self).retaining(),
                Err(returned) => returned == value && *final(self) == *old(self)
                    && old(self).phase() != Phase::Running && old(self).phase() != Phase::AwaitingAdoption,
            },
    {
        if !self.begin_cleanup() { return Err(value); }
        Ok(TaskCleanup { owner: self.key.owner(), cleanup: crate::mailbox::Cleanup::new(Some(value)) })
    }
    pub fn finish_cleanup_with<T>(&mut self, cleanup: &TaskCleanup<T>) -> (ok: bool)
        requires cleanup.valid(),
        ensures final(self).key() == old(self).key(),
            ok == (old(self).phase() == Phase::Cleaning && cleanup.finished() && cleanup.owner() == old(self).key().id()),
            ok ==> final(self).phase() == Phase::Cleaned,
            !ok ==> *final(self) == *old(self),
            !cleanup.finished() && old(self).retaining() ==> final(self).retaining(),
    {
        if !cleanup.cleanup.is_finished() || cleanup.owner != self.key.owner() { return false; }
        self.finish_cleanup()
    }

    pub fn slot_index(&self) -> (out: usize)
        ensures out == self.key().slot(),
    { self.key.slot_index() }

    pub fn owner_id(&self) -> (out: u64)
        ensures out == self.key().id(),
    { self.key.owner() }

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
                && crate::resource::occupied(final(registry).entries()) + 1 == crate::resource::occupied(old(registry).entries())
                && final(registry).entries()[self.key().slot() as int] == 0
                && (forall|i: int| 0 <= i < old(registry).limit() && i != self.key().slot()
                    ==> #[trigger] final(registry).entries()[i] == old(registry).entries()[i]),
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
