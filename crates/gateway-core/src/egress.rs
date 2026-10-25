//! The one permit for opening an outbound connection. A provider permit can
//! only be minted from a resolved route bound to the authorized request, so its
//! target is the destination the root grant named; a cloud permit records
//! that the target came from the shipping configuration. The runtime's socket
//! sites take a permit and nothing else names a host, which is what makes
//! "traffic goes only where you said" a property of types rather than of a
//! reviewed table.
use vstd::prelude::*;
use crate::policy::AuthorizedRequest;
use crate::resolved_route::ResolvedRoute;

verus! {
#[derive(PartialEq, Eq, Structural, Clone, Copy, Debug)]
pub enum Origin { Provider { tenant: u64, origin: usize, credential: usize }, Cloud }

pub struct Egress<'a, D> { target: &'a D, origin: Origin }

impl<'a, D> Egress<'a, D> {
    pub closed spec fn target_value(&self) -> D { *self.target }
    pub closed spec fn origin(&self) -> Origin { self.origin }

    /// A provider permit: only for the destination the authorized request's
    /// route resolved to, and only when that route is bound to this request.
    pub fn provider<C>(resolved: &ResolvedRoute<'a, D, C>, authority: &AuthorizedRequest) -> (out: Option<Self>)
        requires authority.valid(),
        ensures match out {
            Some(permit) => resolved.bound_to(authority)
                && permit.target_value() == resolved.destination_value()
                && permit.origin() == (Origin::Provider { tenant: authority.tenant(),
                    origin: resolved.route().origin, credential: resolved.route().credential }),
            None => !resolved.bound_to(authority),
        },
    {
        let target = match resolved.destination(authority) { Some(target) => target, None => return None };
        let route = authority.route();
        proof { authority.binding_tenant(); }
        Some(Egress { target, origin: Origin::Provider { tenant: authority.tenant_id(), origin: route.origin, credential: route.credential } })
    }

    /// A cloud permit for the configured shipping server. The runtime mints
    /// this only from a parsed `shipping` section.
    pub fn cloud(target: &'a D) -> (out: Self)
        ensures out.origin() == Origin::Cloud, out.target_value() == *target,
    { Egress { target, origin: Origin::Cloud } }

    pub fn target(&self) -> (out: &'a D) ensures *out == self.target_value(), { self.target }
    pub fn kind(&self) -> (out: Origin) ensures out == self.origin(), { self.origin }
}
}
