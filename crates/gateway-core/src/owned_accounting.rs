//! Lift each production owner's stream/read bound to the registry and the
//! combined buffer-accounting snapshot. Runtime map completeness is explicit.
use vstd::prelude::*;

verus! {
// Concatenation is ghost-only. The owner invariant permits at most one nonempty
// side, so this represents the retained chunk across both lifecycle phases.
pub open spec fn owner_buffers(owners: Seq<Option<crate::owned_stream::OwnedStream>>) -> Seq<Seq<u8>> {
    owners.map(|i: int, owner: Option<crate::owned_stream::OwnedStream>| match owner {
        Some(o) => o.state().body() + o.read_bytes(),
        None => Seq::empty(),
    })
}

pub open spec fn owners_match(slots: Seq<u64>, owners: Seq<Option<crate::owned_stream::OwnedStream>>, capacity: nat) -> bool {
    slots.len() == owners.len()
        && forall|i: int| 0 <= i < owners.len() ==> match #[trigger] owners[i] {
            Some(o) => o.valid() && o.key().slot() == i && slots[i] != 0
                && o.key().id() == slots[i] && o.state().capacity() <= capacity,
            None => true,
        }
}

// Ensures that dropping the read-buffer side from the model cannot silently
// make a weaker total pass the upper-bound theorem.
pub proof fn single_owner_covers_both_buffers(owner: crate::owned_stream::OwnedStream)
    ensures crate::buffer_accounting::byte_sum(owner_buffers(seq![Some(owner)]))
        == owner.state().body().len() + owner.read_bytes().len(),
{
    let buffers = owner_buffers(seq![Some(owner)]);
    assert(buffers.len() == 1);
    assert(buffers[0] == owner.state().body() + owner.read_bytes());
    reveal_with_fuel(crate::buffer_accounting::byte_sum, 2);
}

proof fn bound_prefix(slots: Seq<u64>, owners: Seq<Option<crate::owned_stream::OwnedStream>>, capacity: nat)
    requires owners_match(slots, owners, capacity),
    ensures crate::resource::occupied(slots) <= slots.len(),
        crate::buffer_accounting::byte_sum(owner_buffers(owners)) <= crate::resource::occupied(slots) * capacity,
        crate::buffer_accounting::bounded(owner_buffers(owners), slots.len(), capacity),
    decreases slots.len(),
{
    crate::resource::occupied_bound(slots);
    assert forall|i: int| 0 <= i < owners.len() implies
        #[trigger] owner_buffers(owners)[i].len() <= capacity by {
        match owners[i] { Some(o) => { o.payload_bound(); }, None => {} }
    }
    if slots.len() > 0 {
        let last = slots.len() as int - 1;
        let prefix_slots = slots.subrange(0, last);
        let prefix_owners = owners.subrange(0, last);
        assert(owners_match(prefix_slots, prefix_owners, capacity));
        bound_prefix(prefix_slots, prefix_owners, capacity);
        assert(owner_buffers(prefix_owners) =~= owner_buffers(owners).subrange(0, last));
        let bytes = owner_buffers(owners)[last].len();
        if slots[last] == 0 {
            assert(owners[last].is_none());
            assert(bytes == 0);
        } else {
            assert(crate::buffer_accounting::byte_sum(owner_buffers(prefix_owners)) + bytes
                <= (crate::resource::occupied(prefix_slots) + 1) * capacity) by(nonlinear_arith)
                requires crate::buffer_accounting::byte_sum(owner_buffers(prefix_owners)) <= crate::resource::occupied(prefix_slots) * capacity,
                    bytes <= capacity;
        }
    }
}

// Replacement covers a mutating owner transition: its postcondition preserves
// the key and capacity and establishes validity for the next snapshot.
pub proof fn replace_owner(slots: Seq<u64>, owners: Seq<Option<crate::owned_stream::OwnedStream>>, capacity: nat,
    index: int, replacement: crate::owned_stream::OwnedStream)
    requires owners_match(slots, owners, capacity), 0 <= index < slots.len(),
        replacement.valid(), replacement.key().slot() == index,
        slots[index] != 0, replacement.key().id() == slots[index], replacement.state().capacity() <= capacity,
    ensures owners_match(slots, owners.update(index, Some(replacement)), capacity),
{
    assert forall|i: int| 0 <= i < owners.len() implies match
        #[trigger] owners.update(index, Some(replacement))[i] {
        Some(o) => o.valid() && o.key().slot() == i && slots[i] != 0
            && o.key().id() == slots[i] && o.state().capacity() <= capacity,
        None => true,
    } by { }
}

pub proof fn reserve_owner_slot(slots: Seq<u64>, owners: Seq<Option<crate::owned_stream::OwnedStream>>, capacity: nat,
    index: int, id: u64)
    requires owners_match(slots, owners, capacity), 0 <= index < slots.len(), slots[index] == 0, id != 0,
    ensures owners_match(slots.update(index, id), owners, capacity), owners[index].is_none(),
{
    assert(owners[index].is_none());
    assert forall|i: int| 0 <= i < owners.len() implies match #[trigger] owners[i] {
        Some(o) => o.valid() && o.key().slot() == i && slots.update(index, id)[i] != 0
            && o.key().id() == slots.update(index, id)[i] && o.state().capacity() <= capacity,
        None => true,
    } by { }
}

pub proof fn retire_owner_slot(slots: Seq<u64>, owners: Seq<Option<crate::owned_stream::OwnedStream>>, capacity: nat, index: int)
    requires owners_match(slots, owners, capacity), 0 <= index < slots.len(),
    ensures owners_match(slots.update(index, 0), owners.update(index, None), capacity),
{
    assert forall|i: int| 0 <= i < owners.len() implies match #[trigger] owners.update(index, None)[i] {
        Some(o) => o.valid() && o.key().slot() == i && slots.update(index, 0)[i] != 0
            && o.key().id() == slots.update(index, 0)[i] && o.state().capacity() <= capacity,
        None => true,
    } by { }
}

pub proof fn registry_owned_payload_bound(registry: &crate::resource::ResourceAdmission, owners: Seq<Option<crate::owned_stream::OwnedStream>>)
    requires registry.valid(), owners.len() == registry.limit(),
        forall|i: int| 0 <= i < owners.len() ==> match #[trigger] owners[i] {
            Some(o) => o.valid() && registry.owns(&o.key()) && o.key().slot() == i
                && o.state().capacity() <= registry.per_request(),
            None => true,
        },
    ensures crate::buffer_accounting::bounded(owner_buffers(owners), registry.limit(), registry.per_request()),
        crate::buffer_accounting::byte_sum(owner_buffers(owners)) <= crate::resource::occupied(registry.entries()) * registry.per_request(),
        crate::buffer_accounting::byte_sum(owner_buffers(owners)) <= registry.limit() * registry.per_request(),
        registry.limit() * registry.per_request() <= 134217728
            ==> crate::buffer_accounting::byte_sum(owner_buffers(owners)) <= 134217728,
{
    registry.layout();
    assert forall|i: int| 0 <= i < owners.len() implies match #[trigger] owners[i] {
        Some(o) => o.valid() && o.key().slot() == i && registry.entries()[i] != 0
            && o.key().id() == registry.entries()[i] && o.state().capacity() <= registry.per_request(),
        None => true,
    } by {
        match owners[i] { Some(o) => { registry.ownership_facts(&o.key()); }, None => {} }
    }
    bound_prefix(registry.entries(), owners, registry.per_request());
    assert(crate::resource::occupied(registry.entries()) * registry.per_request() <= registry.limit() * registry.per_request())
        by(nonlinear_arith)
        requires crate::resource::occupied(registry.entries()) <= registry.limit(), registry.per_request() >= 0;
}
}
