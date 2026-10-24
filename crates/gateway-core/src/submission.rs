//! Production body-write capability binds a stream ticket to its authorization.
//! Concrete URL/secret resolution and the AsyncWrite call remain adapter joins.
use vstd::prelude::*;
use crate::{owned_stream::OwnedStream, policy::{AuthorizedRequest, Route}, stream::Ticket};

verus! {
pub struct AuthorizedWrite { ticket: Ticket, route: Route, request: u64, direction: u8 }
impl AuthorizedWrite {
    pub closed spec fn direction(&self) -> u8 { self.direction }
    pub closed spec fn route(&self) -> Route { self.route }
    pub closed spec fn request(&self) -> u64 { self.request }
    pub closed spec fn ticket(&self) -> Ticket { self.ticket }
    pub open spec fn bound_to(&self, authority: &AuthorizedRequest) -> bool {
        self.request() == authority.request() && self.route().tenant == authority.tenant()
            && self.route().origin == authority.binding().origin
            && self.route().credential == authority.binding().credential
            && self.route().selector == authority.binding().selector
    }
    pub fn prepare(stream: &mut OwnedStream, authority: &AuthorizedRequest, journal: &crate::journal_binding::JournalBinding, direction: u8, max: usize)
        -> (out: Option<Self>)
        requires old(stream).valid(), authority.valid(),
        ensures final(stream).valid(), final(stream).key() == old(stream).key(),
            final(stream).state().body() == old(stream).state().body(),
            final(stream).state().owner() == old(stream).state().owner(),
            match out {
                Some(write) => write.direction() == direction && direction <= 1 && write.bound_to(authority)
                    && authority.grants(write.route())
                    && write.request() == final(stream).state().owner()
                    && final(stream).state().matches(&write.ticket())
                    && !final(stream).state().closed()
                    && final(stream).state().end() > final(stream).state().position()
                    && final(stream).state().end() - final(stream).state().position() <= max
                    && (final(stream).state().strict() ==> final(stream).state().end() <= final(stream).state().durable()
                        && final(stream).audited_for(authority, journal) && final(stream).audit_direction() == direction),
                None => final(stream).state() == old(stream).state(),
            },
    {
        if direction > 1 { return None; }
        if stream.owner_id() != authority.request_id() { return None; }
        if stream.stream().requires_audit() && (!stream.is_audited_for(authority, journal) || stream.recorded_direction() != direction) { return None; }
        let ticket = match stream.prepare(max) { Some(ticket) => ticket, None => return None };
        let route = authority.route();
        proof { stream.payload_bound(); stream.state().payload_within_capacity(); }
        Some(Self { ticket, route, request: authority.request_id(), direction })
    }
    pub fn bytes<'a>(&self, owner: &'a OwnedStream, authority: &AuthorizedRequest, journal: &crate::journal_binding::JournalBinding, direction: u8)
        -> (out: Option<&'a [u8]>)
        requires owner.valid(), authority.valid(),
        ensures match out {
            Some(bytes) => self.direction() == direction && direction <= 1 && self.bound_to(authority)
                && authority.grants(self.route()) && self.request() == owner.state().owner()
                && owner.state().matches(&self.ticket()) && !owner.state().closed()
                && bytes@ == owner.state().body().subrange(owner.state().position() as int, owner.state().end() as int)
                && (owner.state().strict() ==> owner.state().end() <= owner.state().durable()
                    && owner.audited_for(authority, journal) && owner.receipt().is_some()
                    && owner.receipt().unwrap().valid()
                    && journal.session() == Some(owner.receipt().unwrap().session())
                    && owner.receipt().unwrap().record()
                        == owner.state().audit_frame(authority.tenant(), direction, owner.receipt().unwrap().checksum())),
            None => direction > 1 || self.direction() != direction || (owner.state().strict() && (!owner.audited_for(authority, journal) || owner.audit_direction() != direction)) || !self.bound_to(authority) || self.request() != owner.state().owner()
                || !owner.state().matches(&self.ticket()) || owner.state().closed(),
        },
    {
        if direction > 1 || self.direction != direction { return None; }
        if owner.stream().requires_audit() && (!owner.is_audited_for(authority, journal) || owner.recorded_direction() != direction) { return None; }
        let stream = owner.stream();
        let route = authority.route();
        if self.request != authority.request_id() || self.request != stream.owner_id()
            || self.route.tenant != authority.tenant_id() || self.route.origin != route.origin
            || self.route.credential != route.credential || self.route.selector != route.selector { return None; }
        proof { stream.payload_within_capacity(); if stream.strict() { owner.receipt_evidence(); } }
        stream.pending_bytes(&self.ticket)
    }
    pub fn complete(&self, stream: &mut OwnedStream, count: usize) -> (ok: bool)
        requires old(stream).valid(),
        ensures final(stream).valid(), final(stream).key() == old(stream).key(),
            ok == (old(stream).state().matches(&self.ticket())
                && count <= old(stream).state().end() - old(stream).state().position()),
            ok ==> final(stream).state().completed() == old(stream).state().completed()
                + old(stream).state().body().subrange(old(stream).state().position() as int,
                    (old(stream).state().position() + count) as int),
            !ok ==> final(stream).state() == old(stream).state(),
    { stream.complete(&self.ticket, count) }
}
}
