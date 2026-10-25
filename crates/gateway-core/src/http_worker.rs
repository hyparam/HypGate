//! Worker HTTP roles share the existing closeable admission limit. A role is
//! issued once per worker generation and remains active through reported cleanup.
use vstd::prelude::*;
use crate::{drain::DrainRegistry, task_credit::TaskCredit};
verus! {
pub const INPUT_READER: usize = 0;
pub const OUTPUT_READER: usize = 1;
pub const UPLOAD_CHANNEL: usize = 2;
pub const RESPONSE_WRITER: usize = 3;
pub struct WorkerIssuer { index: usize, owner: u64 }
pub struct HttpPermit { index: usize, owner: u64, role: usize }
pub struct Roles { owner: u64, issued: [bool; 4], active: [bool; 4], retired: bool }
pub struct WorkerRegistry { admission: DrainRegistry, slots: Vec<Roles> }
impl WorkerIssuer {
    pub closed spec fn index(&self) -> nat { self.index as nat }
    pub closed spec fn owner(&self) -> u64 { self.owner }
}
impl HttpPermit {
    pub closed spec fn index(&self) -> nat { self.index as nat }
    pub closed spec fn owner(&self) -> u64 { self.owner }
    pub closed spec fn kind(&self) -> nat { self.role as nat }
    pub fn role(&self) -> (out: usize) ensures out == self.kind(), { self.role }
}
impl Roles {
    pub closed spec fn owner(&self) -> u64 { self.owner }
    pub closed spec fn issued(&self, role: int) -> bool { self.issued@[role] }
    pub closed spec fn active(&self, role: int) -> bool { self.active@[role] }
    pub closed spec fn retired(&self) -> bool { self.retired }
    pub open spec fn any_active(&self) -> bool {
        self.active(0) || self.active(1) || self.active(2) || self.active(3)
    }
    pub open spec fn valid(&self) -> bool {
        (self.active(0) ==> self.issued(0)) && (self.active(1) ==> self.issued(1))
            && (self.active(2) ==> self.issued(2)) && (self.active(3) ==> self.issued(3))
    }
    pub open spec fn matches_entry(&self, entry: u64) -> bool {
        self.valid() && ((self.any_active() || !self.retired()) ==> self.owner() != 0 && self.owner() == entry)
    }
    fn is_active(&self) -> (out: bool) ensures out == self.any_active(),
    { self.active[0] || self.active[1] || self.active[2] || self.active[3] }
}
pub open spec fn role_count(slots: Seq<Roles>, role: int) -> nat {
    crate::resource::count_where(slots, |r: Roles| r.active(role))
}
impl WorkerRegistry {
    pub closed spec fn slots(&self) -> Seq<Roles> { self.slots@ }
    pub closed spec fn entries(&self) -> Seq<u64> { self.admission.state().entries() }
    pub closed spec fn limit(&self) -> nat { self.admission.limit() }
    pub closed spec fn closed(&self) -> bool { self.admission.closed() }
    pub closed spec fn owns_task(&self, task: &TaskCredit) -> bool { self.admission.owns(&task.key()) }
    pub closed spec fn valid(&self) -> bool {
        self.admission.valid() && self.slots.len() == self.admission.limit()
            && forall|i: int| 0 <= i < self.slots.len() ==> (#[trigger] self.slots@[i]).matches_entry(self.entries()[i])
    }
    pub closed spec fn can_issue(&self, issuer: &WorkerIssuer, role: nat) -> bool {
        role < 4 && issuer.index < self.slots.len() && self.slots@[issuer.index as int].owner() == issuer.owner
            && !self.slots@[issuer.index as int].retired() && !self.slots@[issuer.index as int].issued(role as int)
    }
    pub closed spec fn owns_permit(&self, permit: &HttpPermit) -> bool {
        permit.role < 4 && permit.index < self.slots.len() && self.slots@[permit.index as int].owner() == permit.owner
            && self.slots@[permit.index as int].active(permit.role as int)
    }
    pub closed spec fn can_release(&self, task: &TaskCredit) -> bool {
        task.key().slot() < self.slots.len() && !self.slots@[task.key().slot() as int].any_active()
            && self.slots@[task.key().slot() as int].owner() == task.key().id()
            && self.owns_task(task) && task.releasable() && !task.key().stream_claimed()
    }
    pub fn new(limit: usize) -> (out: Self)
        ensures out.valid(), out.limit() == limit, !out.closed(),
    {
        let admission = DrainRegistry::new(limit);
        let mut slots: Vec<Roles> = Vec::new();
        while slots.len() < limit
            invariant slots.len() <= limit,
                forall|i: int| 0 <= i < slots.len() ==> !(#[trigger] slots@[i]).any_active() && slots@[i].retired() && slots@[i].valid(),
            decreases limit - slots.len(),
        {
            slots.push(Roles { owner: 0, issued: [false; 4], active: [false; 4], retired: true });
        }
        Self { admission, slots }
    }
    pub fn acquire(&mut self) -> (out: Option<(TaskCredit, WorkerIssuer)>)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).limit() == old(self).limit(), final(self).closed() == old(self).closed(),
            forall|i: int, r: int| 0 <= i < old(self).limit() && 0 <= r < 4
                ==> #[trigger] final(self).slots()[i].active(r) == old(self).slots()[i].active(r),
            match out {
                Some((task, issuer)) => !old(self).closed() && final(self).owns_task(&task)
                    && task.key().slot() == issuer.index() && task.key().id() == issuer.owner()
                    && task.phase() == crate::task_credit::Phase::Reserved
                    && (forall|i: int| 0 <= i < old(self).limit() && i != issuer.index()
                        ==> #[trigger] final(self).slots()[i] == old(self).slots()[i]
                            && final(self).entries()[i] == old(self).entries()[i])
                    && (forall|r: nat| r < 4 ==> final(self).can_issue(&issuer, r)),
                None => *final(self) == *old(self),
            },
    {
        let key = match self.admission.acquire() { Some(key) => key, None => return None };
        let index = key.slot_index();
        let owner = key.owner();
        self.slots.set(index, Roles { owner, issued: [false; 4], active: [false; 4], retired: false });
        Some((TaskCredit::new(key), WorkerIssuer { index, owner }))
    }
    pub fn issue(&mut self, issuer: &WorkerIssuer, role: usize) -> (out: Option<HttpPermit>)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).limit() == old(self).limit(), final(self).closed() == old(self).closed(),
            final(self).entries() == old(self).entries(), out.is_some() == old(self).can_issue(issuer, role as nat),
            match out {
                Some(p) => final(self).owns_permit(&p) && p.index() == issuer.index()
                    && p.owner() == issuer.owner() && p.kind() == role && !final(self).can_issue(issuer, role as nat),
                None => *final(self) == *old(self),
            },
            forall|i: int, r: int| 0 <= i < old(self).limit() && 0 <= r < 4 && (i != issuer.index() || r != role)
                ==> #[trigger] final(self).slots()[i].active(r) == old(self).slots()[i].active(r),
    {
        if role >= 4 || issuer.index >= self.slots.len() || self.slots[issuer.index].owner != issuer.owner
            || self.slots[issuer.index].retired || self.slots[issuer.index].issued[role] { return None; }
        self.slots[issuer.index].issued[role] = true;
        self.slots[issuer.index].active[role] = true;
        Some(HttpPermit { index: issuer.index, owner: issuer.owner, role })
    }
    pub fn finish(&mut self, permit: HttpPermit) -> (ok: bool)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).limit() == old(self).limit(), final(self).closed() == old(self).closed(),
            final(self).entries() == old(self).entries(), ok == old(self).owns_permit(&permit),
            ok ==> !final(self).owns_permit(&permit), !ok ==> *final(self) == *old(self),
            forall|i: int, r: int| 0 <= i < old(self).limit() && 0 <= r < 4 ==>
                #[trigger] final(self).slots()[i].issued(r) == old(self).slots()[i].issued(r)
                && (i != permit.index() || r != permit.kind() ==> final(self).slots()[i].active(r) == old(self).slots()[i].active(r)),
    {
        if permit.role >= 4 || permit.index >= self.slots.len() || self.slots[permit.index].owner != permit.owner
            || !self.slots[permit.index].active[permit.role] { return false; }
        self.slots[permit.index].active[permit.role] = false;
        true
    }
    // Failed cleanup closes admission, matching the worker adapter's prior policy.
    pub fn release_task(&mut self, task: TaskCredit) -> (ok: bool)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).limit() == old(self).limit(),
            old(self).closed() ==> final(self).closed(), !ok ==> final(self).closed(),
            ok == old(self).can_release(&task), ok ==> !final(self).owns_task(&task),
            forall|i: int| 0 <= i < old(self).limit() && i != task.key().slot()
                ==> #[trigger] final(self).slots()[i] == old(self).slots()[i]
                    && final(self).entries()[i] == old(self).entries()[i],
            !ok ==> final(self).entries() == old(self).entries(),
            forall|i: int, r: int| 0 <= i < old(self).limit() && 0 <= r < 4
                ==> #[trigger] final(self).slots()[i].active(r) == old(self).slots()[i].active(r),
            forall|issuer: &WorkerIssuer, r: nat| issuer.index() == task.key().slot() && issuer.owner() == task.key().id()
                ==> !#[trigger] final(self).can_issue(issuer, r),
    {
        let index = task.slot_index();
        if index >= self.slots.len() { self.admission.close(); return false; }
        self.slots[index].retired = true;
        if self.slots[index].owner != task.owner_id() || self.slots[index].is_active() {
            self.admission.close(); return false;
        }
        let ok = task.release_worker(&mut self.admission);
        if !ok { self.admission.close(); }
        ok
    }
    pub fn is_closed(&self) -> (out: bool) ensures out == self.closed(), { self.admission.is_closed() }
    pub fn close(&mut self)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).closed(), final(self).slots() == old(self).slots(),
            final(self).entries() == old(self).entries(), final(self).limit() == old(self).limit(),
    { self.admission.close(); }
    pub fn usage(&self) -> (out: (usize, usize))
        requires self.valid(),
        ensures out.0 == crate::resource::occupied(self.entries()), out.1 == self.limit(), out.0 <= out.1,
    { self.admission.usage() }
    pub proof fn retained_permit_blocks_release(&self, task: &TaskCredit, permit: &HttpPermit)
        requires self.valid(), self.owns_permit(permit),
            permit.index() == task.key().slot(), permit.owner() == task.key().id(),
        ensures self.owns_task(task), !self.can_release(task),
            self.entries()[task.key().slot() as int] == task.key().id(), task.key().id() != 0,
    {
        assert(self.slots@[permit.index() as int].any_active());
    }

    pub fn role_usage(&self, role: usize) -> (out: usize)
        requires self.valid(), role < 4,
        ensures out == role_count(self.slots(), role as int), out <= self.limit(),
    {
        let mut i: usize = 0;
        let mut count: usize = 0;
        while i < self.slots.len()
            invariant i <= self.slots.len(), count <= i, role < 4,
                count == role_count(self.slots@.subrange(0, i as int), role as int),
            decreases self.slots.len() - i,
        {
            if self.slots[i].active[role] { count = count + 1; }
            proof { assert(self.slots@.subrange(0, i as int + 1).subrange(0, i as int)
                =~= self.slots@.subrange(0, i as int)); }
            i = i + 1;
        }
        proof {
            assert(self.slots@.subrange(0, i as int) =~= self.slots@);
            self.role_count_bound(role as int);
        }
        count
    }

    pub proof fn role_count_bound(&self, role: int)
        requires self.valid(), 0 <= role < 4,
        ensures role_count(self.slots(), role) <= crate::resource::occupied(self.entries()),
            role_count(self.slots(), role) <= self.limit(),
    {
        assert forall|i: int| 0 <= i < self.slots.len() && #[trigger] self.slots@[i].active(role)
            implies self.entries()[i] != 0 by {
            assert(self.slots@[i].any_active());
        }
        crate::resource::count_pointwise_le(self.slots(), |r: Roles| r.active(role), self.entries(), |v: u64| v != 0);
        crate::resource::occupied_bound(self.entries());
    }
}
}
