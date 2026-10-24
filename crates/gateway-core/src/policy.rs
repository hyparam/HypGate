use vstd::prelude::*;
use crate::framing::equal_bytes;

verus! {

// The operator supplies the root grants and identity digests. Candidate routes are untrusted.
pub struct Identity { pub tenant: u64, pub digest: Vec<u8> }
pub struct Route {
    pub tenant: u64,
    pub selector: u64,
    pub origin: usize,
    pub credential: usize,
}

#[allow(dead_code)] // Ghost root snapshots are erased from runtime dispatch.
pub struct Policy {
    identities: Vec<Identity>,
    grants: Ghost<Seq<Route>>,
    routes: Vec<Route>,
    origin_count: Ghost<nat>,
    credential_tenants: Ghost<Seq<u64>>,
}

// Neither token has a public constructor, deserializer, or Clone implementation.
// The policy borrow binds tokens to the actual immutable policy, not a caller-supplied epoch.
pub struct Authenticated<'a> {
    policy: &'a Policy,
    tenant: u64,
    #[allow(dead_code)]
    digest: Ghost<Seq<u8>>,
}
pub struct AuthorizedRequest<'a> {
    policy: &'a Policy,
    route: usize,
    request: u64,
    tenant: u64,
    #[allow(dead_code)]
    digest: Ghost<Seq<u8>>,
}

pub open spec fn allowed(r: Route, grants: Seq<Route>, origins: nat, credentials: Seq<u64>) -> bool {
    r.origin < origins && r.credential < credentials.len()
    && credentials[r.credential as int] == r.tenant
    && exists|i: int| 0 <= i < grants.len() && grants[i] == r
}

fn root_contains(grants: &Vec<Route>, route: &Route) -> (found: bool)
    ensures found == (exists|i: int| 0 <= i < grants.len() && grants@[i] == *route),
{
    let mut i: usize = 0;
    while i < grants.len()
        invariant i <= grants.len(),
            forall|j: int| 0 <= j < i ==> #[trigger] grants@[j] != *route,
        decreases grants.len() - i,
    {
        let g = &grants[i];
        if g.tenant == route.tenant && g.selector == route.selector
            && g.origin == route.origin && g.credential == route.credential { return true; }
        i = i + 1;
    }
    false
}

fn tenant_known(identities: &Vec<Identity>, tenant: u64) -> (found: bool)
    ensures found == (exists|i: int| 0 <= i < identities.len() && identities@[i].tenant == tenant),
{
    let mut i: usize = 0;
    while i < identities.len()
        invariant i <= identities.len(),
            forall|j: int| 0 <= j < i ==> #[trigger] identities@[j].tenant != tenant,
        decreases identities.len() - i,
    {
        if identities[i].tenant == tenant { return true; }
        i = i + 1;
    }
    false
}

impl Policy {
    pub closed spec fn valid(&self) -> bool {
        (forall|i: int| 0 <= i < self.identities.len()
            ==> #[trigger] self.identities@[i].digest.len() == 32)
        && (forall|i: int, j: int| 0 <= i < j < self.identities.len()
            ==> self.identities@[i].tenant != self.identities@[j].tenant
                && self.identities@[i].digest@ != self.identities@[j].digest@)
        && (forall|i: int| 0 <= i < self.routes.len()
            ==> allowed(#[trigger] self.routes@[i], self.grants@,
                self.origin_count@, self.credential_tenants@)
                && (exists|j: int| 0 <= j < self.identities.len() && self.identities@[j].tenant == self.routes@[i].tenant))
        && (forall|i: int, j: int| 0 <= i < j < self.routes.len()
            ==> self.routes@[i].tenant != self.routes@[j].tenant
                || self.routes@[i].selector != self.routes@[j].selector)
    }
    pub closed spec fn roots(&self) -> Seq<Route> { self.grants@ }
    pub closed spec fn configured(&self) -> Seq<Route> { self.routes@ }
    pub closed spec fn identities(&self) -> Seq<Identity> { self.identities@ }
    pub closed spec fn origins(&self) -> nat { self.origin_count@ }
    pub closed spec fn credentials(&self) -> Seq<u64> { self.credential_tenants@ }

    pub fn validate(identities: Vec<Identity>, grants: Vec<Route>, routes: Vec<Route>,
        origin_count: usize, credential_tenants: Vec<u64>) -> (out: Option<Self>)
        ensures match out {
            Some(p) => p.valid() && p.roots() == grants@ && p.configured() == routes@
                && p.identities() == identities@ && p.origins() == origin_count
                && p.credentials() == credential_tenants@,
            None => true,
        },
    {
        let mut i: usize = 0;
        while i < identities.len()
            invariant i <= identities.len(),
                forall|k: int| 0 <= k < i ==> #[trigger] identities@[k].digest.len() == 32,
                forall|k: int, l: int| 0 <= k < l < i
                    ==> identities@[k].tenant != identities@[l].tenant
                        && identities@[k].digest@ != identities@[l].digest@,
            decreases identities.len() - i,
        {
            if identities[i].digest.len() != 32 { return None; }
            let mut j: usize = 0;
            while j < i
                invariant j <= i < identities.len(),
                    forall|k: int| 0 <= k < j ==> identities@[k].tenant != identities@[i as int].tenant
                        && identities@[k].digest@ != identities@[i as int].digest@,
                decreases i - j,
            {
                if identities[j].tenant == identities[i].tenant
                    || equal_bytes(identities[j].digest.as_slice(), identities[i].digest.as_slice()) {
                    return None;
                }
                j = j + 1;
            }
            i = i + 1;
        }
        let mut r: usize = 0;
        while r < routes.len()
            invariant r <= routes.len(),
                forall|k: int| 0 <= k < r ==> allowed(#[trigger] routes@[k], grants@,
                    origin_count as nat, credential_tenants@)
                    && (exists|j: int| 0 <= j < identities.len() && identities@[j].tenant == routes@[k].tenant),
                forall|k: int, l: int| 0 <= k < l < r
                    ==> routes@[k].tenant != routes@[l].tenant || routes@[k].selector != routes@[l].selector,
            decreases routes.len() - r,
        {
            let route = &routes[r];
            if route.origin >= origin_count || route.credential >= credential_tenants.len()
                || credential_tenants[route.credential] != route.tenant || !root_contains(&grants, route)
                || !tenant_known(&identities, route.tenant) {
                return None;
            }
            let mut j: usize = 0;
            while j < r
                invariant j <= r < routes.len(),
                    forall|k: int| 0 <= k < j ==> routes@[k].tenant != routes@[r as int].tenant
                        || routes@[k].selector != routes@[r as int].selector,
                decreases r - j,
            {
                if routes[j].tenant == routes[r].tenant && routes[j].selector == routes[r].selector {
                    return None;
                }
                j = j + 1;
            }
            r = r + 1;
        }
        Some(Policy { identities, grants: Ghost(grants@), routes,
            origin_count: Ghost(origin_count as nat), credential_tenants: Ghost(credential_tenants@) })
    }

    pub fn authenticate<'a>(&'a self, digest: &[u8]) -> (out: Option<Authenticated<'a>>)
        requires self.valid(),
        ensures match out {
            Some(a) => a.valid() && a.policy() == *self && a.proof_digest() == digest@,
            None => forall|i: int| 0 <= i < self.identities().len()
                ==> #[trigger] self.identities()[i].digest@ != digest@,
        },
    {
        let mut i: usize = 0;
        while i < self.identities.len()
            invariant self.valid(), i <= self.identities.len(),
                forall|j: int| 0 <= j < i ==> #[trigger] self.identities@[j].digest@ != digest@,
            decreases self.identities.len() - i,
        {
            if equal_bytes(self.identities[i].digest.as_slice(), digest) {
                return Some(Authenticated { policy: self, tenant: self.identities[i].tenant,
                    digest: Ghost(digest@) });
            }
            i = i + 1;
        }
        None
    }
}

impl<'a> Authenticated<'a> {
    pub closed spec fn policy(&self) -> Policy { *self.policy }
    pub closed spec fn proof_digest(&self) -> Seq<u8> { self.digest@ }
    pub closed spec fn valid(&self) -> bool {
        self.policy.valid() && exists|i: int| 0 <= i < self.policy.identities.len()
            && self.policy.identities@[i].tenant == self.tenant
            && self.policy.identities@[i].digest@ == self.digest@
    }
    pub closed spec fn tenant(&self) -> u64 { self.tenant }

    pub fn authorize(&self, selector: u64, request: u64) -> (out: Option<AuthorizedRequest<'a>>)
        requires self.valid(),
        ensures match out {
            Some(a) => a.valid() && a.tenant() == self.tenant() && a.request() == request
                && a.binding().selector == selector && a.policy() == self.policy()
                && a.proof_digest() == self.proof_digest(),
            None => true,
        },
    {
        if request == 0 { return None; }
        let mut i: usize = 0;
        while i < self.policy.routes.len()
            invariant self.valid(), request != 0, i <= self.policy.routes.len(),
            decreases self.policy.routes.len() - i,
        {
            let r = &self.policy.routes[i];
            if r.tenant == self.tenant && r.selector == selector {
                return Some(AuthorizedRequest { policy: self.policy, route: i, request, tenant: self.tenant, digest: Ghost(self.digest@) });
            }
            i = i + 1;
        }
        None
    }
}

impl<'a> AuthorizedRequest<'a> {
    // The route is an operator grant with this tenant's credential under this policy.
    pub open spec fn grants(&self, r: Route) -> bool {
        allowed(r, self.policy().roots(), self.policy().origins(), self.policy().credentials())
    }
    pub fn route(&self) -> (out: Route)
        requires self.valid(),
        ensures out == self.binding(), out.tenant == self.tenant(), self.grants(out),
    {
        let r = &self.policy.routes[self.route];
        Route { tenant: r.tenant, selector: r.selector, origin: r.origin, credential: r.credential }
    }

    pub closed spec fn proof_digest(&self) -> Seq<u8> { self.digest@ }
    pub closed spec fn policy(&self) -> Policy { *self.policy }
    pub closed spec fn binding(&self) -> Route { self.policy.routes@[self.route as int] }
    pub closed spec fn tenant(&self) -> u64 { self.tenant }
    pub closed spec fn request(&self) -> u64 { self.request }
    pub closed spec fn valid(&self) -> bool {
        self.policy.valid() && self.route < self.policy.routes.len() && self.request != 0
        && (exists|i: int| 0 <= i < self.policy.identities.len()
            && self.policy.identities@[i].tenant == self.tenant
            && self.policy.identities@[i].digest@ == self.digest@)
        && self.binding().tenant == self.tenant
        && self.grants(self.binding())
    }
    pub fn tenant_id(&self) -> (out: u64)
        requires self.valid(),
        ensures out == self.tenant(),
    { self.tenant }

    pub fn request_id(&self) -> (out: u64)
        requires self.valid(),
        ensures out == self.request(),
    { self.request }
}
}
