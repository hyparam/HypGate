//! Production body-write capability binds a stream ticket to its authorization.
//! Concrete URL/secret resolution and the AsyncWrite call remain adapter joins.
use vstd::prelude::*;
use crate::{owned_stream::OwnedStream, policy::{AuthorizedRequest, Route}, stream::{StreamChunk, Ticket}};

verus! {
pub struct AuthorizedWrite { ticket: Ticket, route: Route, request: u64 }
impl AuthorizedWrite {
    pub closed spec fn route(&self) -> Route { self.route }
    pub closed spec fn request(&self) -> u64 { self.request }
    pub closed spec fn ticket(&self) -> Ticket { self.ticket }
    pub open spec fn bound_to(&self, authority: &AuthorizedRequest) -> bool {
        self.request() == authority.request() && self.route().tenant == authority.tenant()
            && self.route().origin == authority.binding().origin
            && self.route().credential == authority.binding().credential
            && self.route().selector == authority.binding().selector
    }
    pub fn prepare(stream: &mut OwnedStream, authority: &AuthorizedRequest, max: usize)
        -> (out: Option<Self>)
        requires old(stream).valid(), authority.valid(),
        ensures final(stream).valid(), final(stream).key() == old(stream).key(),
            final(stream).state().body() == old(stream).state().body(),
            final(stream).state().owner() == old(stream).state().owner(),
            match out {
                Some(write) => write.bound_to(authority)
                    && crate::policy::allowed(write.route(), authority.policy().roots(), authority.policy().origins(), authority.policy().credentials())
                    && write.request() == final(stream).state().owner()
                    && final(stream).state().matches(&write.ticket())
                    && !final(stream).state().closed()
                    && final(stream).state().end() > final(stream).state().position()
                    && final(stream).state().end() - final(stream).state().position() <= max
                    && (final(stream).state().strict() ==> final(stream).state().end() <= final(stream).state().durable()),
                None => final(stream).state() == old(stream).state(),
            },
    {
        if stream.owner_id() != authority.request_id() { return None; }
        let ticket = match stream.prepare(max) { Some(ticket) => ticket, None => return None };
        let route = authority.route();
        proof { stream.state().payload_within_capacity(); }
        Some(Self { ticket, route, request: authority.request_id() })
    }
    pub fn bytes<'a>(&self, stream: &'a StreamChunk, authority: &AuthorizedRequest)
        -> (out: Option<&'a [u8]>)
        requires stream.valid(), authority.valid(),
        ensures match out {
            Some(bytes) => self.bound_to(authority)
                && crate::policy::allowed(self.route(), authority.policy().roots(), authority.policy().origins(), authority.policy().credentials()) && self.request() == stream.owner()
                && stream.matches(&self.ticket()) && !stream.closed()
                && bytes@ == stream.body().subrange(stream.position() as int, stream.end() as int)
                && (stream.strict() ==> stream.end() <= stream.durable()),
            None => !self.bound_to(authority) || self.request() != stream.owner()
                || !stream.matches(&self.ticket()) || stream.closed(),
        },
    {
        let route = authority.route();
        if self.request != authority.request_id() || self.request != stream.owner_id()
            || self.route.tenant != authority.tenant_id() || self.route.origin != route.origin
            || self.route.credential != route.credential || self.route.selector != route.selector { return None; }
        proof { stream.payload_within_capacity(); }
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
