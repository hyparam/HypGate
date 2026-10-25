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
                && authority.grants(resolved.route()),
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
            Some(bytes) => self.bound_to(authority) && write.route() == self.route()
                && write.delivers(owner, authority, journal, direction, bytes@),
            None => !self.bound_to(authority) || write.refused(owner, authority, journal, direction),
        },
    {
        if !self.matches(authority) { return None; }
        let out = write.bytes(owner, authority, journal, direction);
        proof { authority.binding_tenant(); }
        out
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
