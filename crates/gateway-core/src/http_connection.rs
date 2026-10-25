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
        ensures final(self).retired(), final(self).owner() == old(self).owner(),
            final(self).issued() == old(self).issued(), final(self).active() == old(self).active(),
            ResourceAdmission::released(*old(registry), *final(registry), &task.key(), ok),
            ok == (!old(self).active() && old(self).owner() == task.key().id()
                && task.releasable() && !task.key().stream_claimed() && old(registry).owns(&task.key())),
    {
        self.retired = true;
        if self.active || self.owner != task.owner_id() { return false; }
        task.release(registry)
    }
}

// The registry stores the actual response states, not a caller-supplied count.
// Issuers may be shared; only the registry can mint a non-cloneable permit.
pub struct ResponseIssuer { index: usize, owner: u64 }
impl ResponseIssuer {
    pub closed spec fn index(&self) -> nat { self.index as nat }
    pub closed spec fn owner(&self) -> u64 { self.owner }
}
pub struct RegisteredResponse { index: usize, permit: ResponsePermit }
impl RegisteredResponse {
    pub closed spec fn index(&self) -> nat { self.index as nat }
    pub closed spec fn owner(&self) -> u64 { self.permit.owner() }
}
pub struct ResponseRegistry { admission: ResourceAdmission, responses: Vec<ResponseSlot> }

pub open spec fn active_responses(slots: Seq<ResponseSlot>) -> nat {
    crate::resource::count_where(slots, |s: ResponseSlot| s.active())
}
impl ResponseRegistry {
    pub closed spec fn owns_task(&self, task: &TaskCredit) -> bool { self.admission.owns(&task.key()) }
    pub closed spec fn slots(&self) -> Seq<ResponseSlot> { self.responses@ }
    pub closed spec fn entries(&self) -> Seq<u64> { self.admission.entries() }
    pub closed spec fn limit(&self) -> nat { self.admission.limit() }
    pub closed spec fn valid(&self) -> bool {
        self.admission.valid() && self.responses.len() == self.admission.limit()
            && forall|i: int| 0 <= i < self.responses.len() ==>
                (#[trigger] self.responses@[i].active() ==> self.responses@[i].issued())
                && ((self.responses@[i].active() || !self.responses@[i].retired())
                    ==> self.responses@[i].owner() != 0 && self.responses@[i].owner() == self.admission.entries()[i])
    }
    pub closed spec fn can_release_task(&self, task: &TaskCredit) -> bool {
        task.key().slot() < self.responses.len() && !self.responses@[task.key().slot() as int].active()
            && self.responses@[task.key().slot() as int].owner() == task.key().id()
            && task.releasable() && !task.key().stream_claimed() && self.owns_task(task)
    }
    pub closed spec fn issuer_matches(&self, issuer: &ResponseIssuer) -> bool {
        issuer.index < self.responses.len() && self.responses@[issuer.index as int].owner() == issuer.owner
    }
    pub closed spec fn can_issue(&self, issuer: &ResponseIssuer) -> bool {
        self.issuer_matches(issuer) && !self.responses@[issuer.index as int].issued()
            && !self.responses@[issuer.index as int].retired()
    }
    pub closed spec fn owns_response(&self, response: &RegisteredResponse) -> bool {
        response.index < self.responses.len() && self.responses@[response.index as int].active()
            && self.responses@[response.index as int].owner() == response.permit.owner()
    }
    pub fn new(limit: usize) -> (out: Self)
        ensures out.valid(), out.limit() == limit, active_responses(out.slots()) == 0,
    {
        let admission = ResourceAdmission::new(limit, 0);
        let mut responses = Vec::new();
        while responses.len() < limit
            invariant responses.len() <= limit, active_responses(responses@) == 0,
                forall|i: int| 0 <= i < responses.len() ==> !#[trigger] responses@[i].active()
                    && responses@[i].retired(),
            decreases limit - responses.len(),
        {
            let ghost before = responses@;
            responses.push(ResponseSlot { owner: 0, issued: false, active: false, retired: true });
            proof { assert(responses@.subrange(0, responses.len() as int - 1) =~= before); }
        }
        Self { admission, responses }
    }
    pub fn acquire(&mut self) -> (out: Option<(TaskCredit, ResponseIssuer)>)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).limit() == old(self).limit(),
            forall|i: int| 0 <= i < old(self).limit()
                ==> #[trigger] final(self).slots()[i].active() == old(self).slots()[i].active(),
            match out {
                Some((task, issuer)) => final(self).owns_task(&task)
                    && final(self).can_issue(&issuer) && task.key().slot() == issuer.index()
                    && task.key().id() == issuer.owner() && task.phase() == crate::task_credit::Phase::Reserved
                    && (forall|i: int| 0 <= i < old(self).limit() && i != issuer.index()
                        ==> #[trigger] final(self).slots()[i] == old(self).slots()[i]
                            && final(self).entries()[i] == old(self).entries()[i]),
                None => final(self).slots() == old(self).slots() && final(self).entries() == old(self).entries(),
            },
    {
        let key = match self.admission.acquire() { Some(key) => key, None => return None };
        let index = key.slot_index();
        let owner = key.owner();
        let (slot, task) = ResponseSlot::reserve(key);
        self.responses.set(index, slot);
        Some((task, ResponseIssuer { index, owner }))
    }
    pub fn issue(&mut self, issuer: &ResponseIssuer) -> (out: Option<RegisteredResponse>)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).limit() == old(self).limit(),
            final(self).entries() == old(self).entries(),
            out.is_some() == old(self).can_issue(issuer),
            forall|i: int| 0 <= i < old(self).limit() && i != issuer.index()
                ==> #[trigger] final(self).slots()[i] == old(self).slots()[i],
            match out {
                Some(response) => final(self).owns_response(&response) && !final(self).can_issue(issuer)
                    && response.index() == issuer.index() && response.owner() == issuer.owner(),
                None => final(self).slots() == old(self).slots() && final(self).entries() == old(self).entries(),
            },
    {
        if issuer.index >= self.responses.len() || self.responses[issuer.index].owner != issuer.owner { return None; }
        let ghost before = *self;
        let permit = match self.responses[issuer.index].issue() {
            Some(p) => p,
            None => { proof { assert(self.responses@ =~= before.responses@); } return None; }
        };
        proof {
            assert forall|i: int| 0 <= i < self.responses.len() implies
                (#[trigger] self.responses@[i].active() ==> self.responses@[i].issued())
                && ((self.responses@[i].active() || !self.responses@[i].retired())
                    ==> self.responses@[i].owner() != 0 && self.responses@[i].owner() == self.admission.entries()[i]) by {
                assert((before.responses@[i].active() || !before.responses@[i].retired())
                    ==> before.responses@[i].owner() != 0 && before.responses@[i].owner() == before.admission.entries()[i]);
                if i == issuer.index { assert(!before.responses@[i].retired()); }
                else { assert(self.responses@[i] == before.responses@[i]); }
            }
        }
        Some(RegisteredResponse { index: issuer.index, permit })
    }
    pub fn finish(&mut self, response: RegisteredResponse) -> (ok: bool)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).limit() == old(self).limit(),
            final(self).entries() == old(self).entries(),
            ok == old(self).owns_response(&response),
            forall|i: int| 0 <= i < old(self).limit() ==>
                #[trigger] final(self).slots()[i].issued() == old(self).slots()[i].issued()
                && final(self).slots()[i].owner() == old(self).slots()[i].owner()
                && final(self).slots()[i].retired() == old(self).slots()[i].retired()
                && (i != response.index() ==> final(self).slots()[i].active() == old(self).slots()[i].active()),
            ok ==> !final(self).owns_response(&response),
            !ok ==> final(self).slots() == old(self).slots(),
    {
        if response.index >= self.responses.len() { return false; }
        let ghost before = *self;
        let ok = self.responses[response.index].finish(response.permit);
        proof { if !ok { assert(self.responses@ =~= before.responses@); } }
        ok
    }
    pub fn release_task(&mut self, task: TaskCredit) -> (ok: bool)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).limit() == old(self).limit(),
            ok == old(self).can_release_task(&task),
            forall|i: int| 0 <= i < old(self).limit() && i != task.key().slot()
                ==> #[trigger] final(self).slots()[i] == old(self).slots()[i]
                    && final(self).entries()[i] == old(self).entries()[i],
            forall|i: int| 0 <= i < old(self).limit()
                ==> #[trigger] final(self).slots()[i].active() == old(self).slots()[i].active(),
            ok ==> !final(self).owns_task(&task),
            !ok ==> final(self).entries() == old(self).entries(),
            forall|issuer: &ResponseIssuer| issuer.index() == task.key().slot() && issuer.owner() == task.key().id()
                ==> !#[trigger] final(self).can_issue(issuer),
    {
        let index = task.slot_index();
        if index >= self.responses.len() { return false; }
        self.responses[index].release_task(task, &mut self.admission)
    }
    pub fn usage(&self) -> (out: (usize, usize))
        ensures out.0 == crate::resource::occupied(self.entries()), out.1 == self.limit(), out.0 <= out.1,
    { self.admission.usage() }

    pub proof fn retained_response_blocks_release(&self, task: &TaskCredit, response: &RegisteredResponse)
        requires self.valid(), self.owns_response(response),
            response.index() == task.key().slot(), response.owner() == task.key().id(),
        ensures self.owns_task(task), !self.can_release_task(task),
            self.entries()[task.key().slot() as int] == task.key().id(), task.key().id() != 0,
    {}

    pub fn response_count(&self) -> (out: usize)
        requires self.valid(),
        ensures out == active_responses(self.slots()), out <= self.limit(),
            out <= crate::resource::occupied(self.entries()),
    {
        let mut i: usize = 0;
        let mut count: usize = 0;
        while i < self.responses.len()
            invariant i <= self.responses.len(), count <= i,
                count == active_responses(self.responses@.subrange(0, i as int)),
            decreases self.responses.len() - i,
        {
            if self.responses[i].active { count = count + 1; }
            proof {
                assert(self.responses@.subrange(0, i as int + 1).subrange(0, i as int)
                    =~= self.responses@.subrange(0, i as int));
            }
            i = i + 1;
        }
        proof {
            assert(self.responses@.subrange(0, i as int) =~= self.responses@);
            self.response_count_bound();
        }
        count
    }

    pub proof fn response_count_bound(&self)
        requires self.valid(),
        ensures active_responses(self.slots()) <= crate::resource::occupied(self.entries()),
            active_responses(self.slots()) <= self.limit(),
    {
        crate::resource::count_pointwise_le(self.slots(), |s: ResponseSlot| s.active(), self.entries(), |v: u64| v != 0);
        crate::resource::occupied_bound(self.entries());
    }
}
}
