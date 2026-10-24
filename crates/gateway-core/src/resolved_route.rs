//! Select concrete configured values using the validated authority's indices.
//! Configuration parsing and the meaning of the values remain adapter concerns.
use vstd::prelude::*;
use crate::policy::{AuthorizedRequest, Route};
verus! {
pub struct ResolvedRoute<'a, D, C> {
    destination: &'a D,
    credential: &'a C,
    route: Route,
    request: u64,
}
impl<'a, D, C> ResolvedRoute<'a, D, C> {
    pub closed spec fn route(&self) -> Route { self.route }
    pub closed spec fn request(&self) -> u64 { self.request }
    pub closed spec fn destination_value(&self) -> D { *self.destination }
    pub closed spec fn credential_value(&self) -> C { *self.credential }
    pub open spec fn bound_to(&self, authority: &AuthorizedRequest) -> bool {
        self.request() == authority.request() && self.route() == authority.binding()
    }
    pub fn resolve(authority: &AuthorizedRequest, destinations: &'a Vec<D>, credentials: &'a Vec<C>)
        -> (out: Option<Self>)
        requires authority.valid(),
        ensures match out {
            Some(resolved) => resolved.bound_to(authority)
                && resolved.route().origin < destinations.len() && resolved.route().credential < credentials.len()
                && resolved.destination_value() == destinations@[resolved.route().origin as int]
                && resolved.credential_value() == credentials@[resolved.route().credential as int]
                && crate::policy::allowed(resolved.route(), authority.policy().roots(), authority.policy().origins(), authority.policy().credentials()),
            None => authority.binding().origin >= destinations.len() || authority.binding().credential >= credentials.len(),
        },
    {
        let route = authority.route();
        if route.origin >= destinations.len() || route.credential >= credentials.len() { return None; }
        Some(Self { destination: &destinations[route.origin], credential: &credentials[route.credential],
            route, request: authority.request_id() })
    }
    pub fn write_bytes<'b>(&self, write: &crate::submission::AuthorizedWrite,
        owner: &'b crate::owned_stream::OwnedStream, authority: &AuthorizedRequest,
        journal: &crate::journal_binding::JournalBinding, direction: u8) -> (out: Option<&'b [u8]>)
        requires owner.valid(), authority.valid(),
        ensures match out {
            Some(bytes) => self.bound_to(authority) && write.route() == self.route() && write.direction() == direction && direction <= 1 && write.bound_to(authority)
                && crate::policy::allowed(write.route(), authority.policy().roots(), authority.policy().origins(), authority.policy().credentials()) && write.request() == owner.state().owner()
                && owner.state().matches(&write.ticket()) && !owner.state().closed()
                && bytes@ == owner.state().body().subrange(owner.state().position() as int, owner.state().end() as int)
                && (owner.state().strict() ==> owner.state().end() <= owner.state().durable()
                    && owner.audited_for(authority, journal) && owner.receipt().is_some()
                    && owner.receipt().unwrap().valid()
                    && journal.session() == Some(owner.receipt().unwrap().session())
                    && owner.receipt().unwrap().record() == crate::framing::encoding(crate::framing::Header {
                        payload: owner.state().body().len() as u32, tenant: authority.tenant(),
                        request: authority.request(), chunk: owner.state().chunk(), direction })
                        + owner.state().body() + owner.receipt().unwrap().checksum()),
            None => !self.bound_to(authority) || direction > 1 || write.direction() != direction || (owner.state().strict() && (!owner.audited_for(authority, journal) || owner.audit_direction() != direction)) || !write.bound_to(authority) || write.request() != owner.state().owner()
                || !owner.state().matches(&write.ticket()) || owner.state().closed(),
        },
    {
        if !self.matches(authority) { return None; }
        let _route = authority.route();
        write.bytes(owner, authority, journal, direction)
    }
    pub fn matches(&self, authority: &AuthorizedRequest) -> (ok: bool)
        requires authority.valid(),
        ensures ok == self.bound_to(authority),
    {
        let route = authority.route();
        self.request == authority.request_id() && self.route.tenant == route.tenant
            && self.route.selector == route.selector && self.route.origin == route.origin
            && self.route.credential == route.credential
    }
    pub fn destination(&self, authority: &AuthorizedRequest) -> (out: Option<&'a D>)
        requires authority.valid(),
        ensures match out {
            Some(value) => self.bound_to(authority) && *value == self.destination_value(),
            None => !self.bound_to(authority),
        },
    { if self.matches(authority) { Some(self.destination) } else { None } }
    pub fn credential(&self, authority: &AuthorizedRequest) -> (out: Option<&'a C>)
        requires authority.valid(),
        ensures match out {
            Some(value) => self.bound_to(authority) && *value == self.credential_value(),
            None => !self.bound_to(authority),
        },
    { if self.matches(authority) { Some(self.credential) } else { None } }
}
}
