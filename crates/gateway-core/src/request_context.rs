//! Configuration, inbound authentication, provider selection and body authorization
//! joined in one sealed context. The runtime supplies resource ownership and I/O.
use vstd::prelude::*;
use crate::{config_build::{self as build, Credential, Secrets, BuildError},
    config_schema::{Root, Candidate, Limits, Logging}, policy::{Policy, AuthorizedRequest, Route},
    destination::Parts, resolved_route::ResolvedRoute, egress::Egress,
    headers::{self, Field}, http1_head::RequestHead, http1_exchange::Refusal,
    body_copy::BodyCopy, owned_stream::OwnedStream, journal_binding::JournalBinding,
    audit_receipt::Durability};

verus! {
fn equal(a: &[u8], b: &[u8]) -> (out: bool)
    ensures out == (a@ == b@),
{
    if a.len() != b.len() { return false; }
    let mut i = 0;
    while i < a.len()
        invariant a.len() == b.len(), i <= a.len(), forall|k: int| 0 <= k < i ==> a@[k] == b@[k],
        decreases a.len() - i,
    {
        if a[i] != b[i] { return false; }
        i = i + 1;
    }
    proof { assert(a@ =~= b@); }
    true
}

/// Semantic identity shared by the provider head and both body copies. Include
/// token digest and concrete destination, not only configuration-local indices.
pub ghost struct TransferIdentity { pub request: u64, pub route: Route, pub digest: Seq<u8>, pub destination: Option<Seq<u8>> }
pub struct TransferKey { request: u64, route: Route, digest: Vec<u8>, destination: Option<Vec<u8>> }
impl TransferKey {
    pub closed spec fn identity(&self) -> TransferIdentity {
        TransferIdentity { request: self.request, route: self.route, digest: self.digest@,
            destination: match self.destination { Some(d) => Some(d@), None => None } }
    }
    pub fn same(&self, other: &Self) -> (out: bool)
        ensures out == (self.identity() == other.identity()),
    {
        if self.request != other.request || self.route.tenant != other.route.tenant || self.route.selector != other.route.selector
            || self.route.origin != other.route.origin || self.route.credential != other.route.credential
            || !equal(self.digest.as_slice(), other.digest.as_slice()) { return false; }
        match (&self.destination, &other.destination) {
            (Some(a), Some(b)) => equal(a.as_slice(), b.as_slice()), (None, None) => true, _ => false,
        }
    }
}

/// Own the policy and its concrete tables together. No runtime can replace a table
/// after validation or combine the policy of one loaded configuration with another.
pub struct ProviderConfig {
    policy: Policy, destinations: Vec<Parts>, credentials: Vec<Credential>,
    limits: Limits, logging: Logging, durability: Durability,
    root: Ghost<Option<Root>>, fetched: Ghost<Seq<(Seq<u8>, Seq<u8>)>>,
}
impl ProviderConfig {
    pub closed spec fn policy_value(&self) -> Policy { self.policy }
    pub closed spec fn roots(&self) -> Option<Root> { self.root@ }
    pub closed spec fn destinations(&self) -> Seq<Parts> { self.destinations@ }
    pub closed spec fn fetched(&self) -> Seq<(Seq<u8>, Seq<u8>)> { self.fetched@ }
    pub closed spec fn credentials(&self) -> Seq<Credential> { self.credentials@ }
    pub closed spec fn valid(&self) -> bool {
        self.policy.valid() && match self.root@ {
            Some(root) => self.policy.roots() == root.grants@ && self.policy.configured() == root.grants@
                && build::identities_match(root.identities@, self.policy.identities())
                && build::destinations_match(root.destinations@, self.destinations@)
                && build::credentials_match(root.credentials@, self.fetched@, self.credentials@)
                && self.policy.origins() == self.destinations.len()
                && self.policy.credentials().len() == self.credentials.len()
                && (forall|i: int| 0 <= i < self.credentials.len() ==> self.policy.credentials()[i] == self.credentials@[i].tenant)
                && self.limits == root.limits && self.logging == root.logging && self.durability == root.durability,
            None => self.destinations.len() == 0 && self.credentials.len() == 0,
        }
    }
    pub fn load<S: Secrets>(root: Root, secrets: &mut S) -> (out: Result<Self, BuildError>)
        ensures match out { Ok(config) => config.valid() && config.roots() == Some(root)
            && final(secrets).reads() == old(secrets).reads() + build::fetched_names(config.fetched())
            && build::fetched_values(config.fetched(), old(secrets).values()), Err(_) => true },
    {
        let mut routes: Vec<Route> = Vec::new();
        let mut i = 0;
        while i < root.grants.len()
            invariant i <= root.grants.len(), routes@ == root.grants@.take(i as int),
            decreases root.grants.len() - i,
        {
            let r = &root.grants[i];
            routes.push(Route { tenant: r.tenant, selector: r.selector, origin: r.origin, credential: r.credential });
            proof { assert(routes@ =~= root.grants@.take(i as int + 1)); }
            i = i + 1;
        }
        proof { assert(routes@ =~= root.grants@); }
        let built = match build::build(root, Candidate { routes }, secrets) { Ok(b) => b, Err(e) => return Err(e) };
        Ok(Self { policy: built.policy, destinations: built.destinations, credentials: built.credentials,
            limits: built.limits, logging: built.logging, durability: built.durability,
            root: Ghost(Some(root)), fetched: built.fetched })
    }
    /// Standalone stream users have no provider tables and cannot prepare an HTTP head.
    pub fn policy_only(policy: Policy, requests: usize, chunk_bytes: usize, strict: bool, durability: Durability) -> (out: Self)
        requires policy.valid(),
        ensures out.valid(), out.roots().is_none(), out.policy_value() == policy,
    {
        Self { policy, destinations: Vec::new(), credentials: Vec::new(),
            limits: Limits { requests, chunk_bytes }, logging: if strict { Logging::Strict } else { Logging::Availability }, durability,
            root: Ghost(None), fetched: Ghost(Seq::empty()) }
    }
    pub closed spec fn limits_value(&self) -> Limits { self.limits }
    pub closed spec fn logging_value(&self) -> Logging { self.logging }
    pub closed spec fn durability_value(&self) -> Durability { self.durability }
    pub fn limits(&self) -> (out: &Limits) ensures *out == self.limits_value(), { &self.limits }
    pub fn strict(&self) -> (out: bool) ensures out == (self.logging_value() == Logging::Strict), { matches!(self.logging, Logging::Strict) }
    pub fn durability(&self) -> (out: Durability) ensures out == self.durability_value(), { self.durability }
    pub open spec fn permits(&self, digest: Seq<u8>, selector: u64, request: u64) -> bool {
        request != 0 && exists|i: int, j: int| 0 <= i < self.policy_value().identities().len()
            && 0 <= j < self.policy_value().configured().len()
            && self.policy_value().identities()[i].digest@ == digest
            && self.policy_value().identities()[i].tenant == self.policy_value().configured()[j].tenant
            && self.policy_value().configured()[j].selector == selector
    }
    pub fn recognizes(&self, digest: &[u8]) -> (out: bool)
        requires self.valid(),
        ensures out == (exists|i: int| 0 <= i < self.policy_value().identities().len() && self.policy_value().identities()[i].digest@ == digest@),
    {
        match self.policy.authenticate(digest) {
            Some(identity) => { proof {
                identity.identity_evidence();
                let i = choose|i: int| 0 <= i < identity.policy().identities().len()
                    && identity.policy().identities()[i].tenant == identity.tenant()
                    && identity.policy().identities()[i].digest@ == identity.proof_digest();
                assert(self.policy_value().identities()[i].digest@ == digest@);
            } true }, None => false,
        }
    }

    pub fn authorize<'a>(&'a self, digest: &[u8], selector: u64, request: u64) -> (out: Option<Context<'a>>)
        requires self.valid(),
        ensures self.permits(digest@, selector, request) ==> out.is_some(),
            match out {
            Some(ctx) => ctx.valid() && ctx.config() == *self && ctx.digest() == digest@
                && ctx.authority_value().request() == request && ctx.authority_value().binding().selector == selector,
            None => true,
        },
    {
        let identity = match self.policy.authenticate(digest) { Some(a) => a, None => return None };
        proof {
            if self.permits(digest@, selector, request) {
                let (i, j) = choose|i: int, j: int| 0 <= i < self.policy.identities().len()
                    && 0 <= j < self.policy.configured().len()
                    && self.policy.identities()[i].digest@ == digest@
                    && self.policy.identities()[i].tenant == self.policy.configured()[j].tenant
                    && self.policy.configured()[j].selector == selector;
                identity.matching_identity(i);
                assert(self.policy.configured()[j].tenant == identity.tenant());
            }
        }
        let authority = match identity.authorize(selector, request) { Some(a) => a, None => return None };
        proof { authority.authorization_evidence(); }
        let provider = if self.destinations.len() == 0 { None } else {
            let resolved = match ResolvedRoute::resolve(&authority, &self.destinations, &self.credentials) { Some(r) => r, None => return None };
            let destination = match resolved.destination(&authority) { Some(d) => d, None => return None };
            let credential = match resolved.credential(&authority) { Some(c) => c, None => return None };
            let egress = match Egress::provider(&resolved, &authority) { Some(e) => e, None => return None };
            Some(Provider { resolved, destination, credential, egress })
        };
        Some(Context { config: self, authority, digest: vstd::slice::slice_to_vec(digest), provider })
    }
}

struct Provider<'a> { resolved: ResolvedRoute<'a, Parts, Credential>, destination: &'a Parts, credential: &'a Credential, egress: Egress<'a, Parts> }
/// The only authority and route used for this request's metadata and body writes.
pub struct Context<'a> { config: &'a ProviderConfig, authority: AuthorizedRequest<'a>, digest: Vec<u8>, provider: Option<Provider<'a>> }
impl<'a> Context<'a> {
    pub closed spec fn config(&self) -> ProviderConfig { *self.config }
    pub closed spec fn authority_value(&self) -> AuthorizedRequest<'a> { self.authority }
    pub closed spec fn digest(&self) -> Seq<u8> { self.digest@ }
    pub closed spec fn destination_value(&self) -> Option<Parts> { match self.provider { Some(p) => Some(*p.destination), None => None } }
    pub closed spec fn credential_value(&self) -> Option<Credential> { match self.provider { Some(p) => Some(*p.credential), None => None } }
    pub closed spec fn valid(&self) -> bool {
        self.config.valid() && self.authority.valid() && self.authority.policy() == self.config.policy_value()
            && self.authority.proof_digest() == self.digest@
            && match self.provider {
                Some(p) => p.resolved.bound_to(&self.authority)
                    && p.resolved.destination_value() == *p.destination && p.resolved.credential_value() == *p.credential
                    && self.authority.binding().origin < self.config.destinations().len()
                    && self.authority.binding().credential < self.config.credentials().len()
                    && *p.destination == self.config.destinations()[self.authority.binding().origin as int]
                    && *p.credential == self.config.credentials()[self.authority.binding().credential as int]
                    && p.egress.target_value() == *p.destination
                    && p.egress.origin() == (crate::egress::Origin::Provider { tenant: self.authority.tenant(), origin: self.authority.binding().origin, credential: self.authority.binding().credential }),
                None => true,
            }
    }
    pub closed spec fn transfer_identity(&self) -> TransferIdentity {
        TransferIdentity { request: self.authority.request(), route: self.authority.binding(), digest: self.digest@,
            destination: match self.provider { Some(p) => Some(p.destination.text@), None => None } }
    }
    pub fn transfer_key(&self) -> (out: TransferKey)
        requires self.valid(), ensures out.identity() == self.transfer_identity(),
    {
        TransferKey { request: self.authority.request_id(), route: self.authority.route(),
            digest: vstd::slice::slice_to_vec(self.digest.as_slice()),
            destination: match &self.provider { Some(p) => Some(vstd::slice::slice_to_vec(p.destination.text.as_slice())), None => None } }
    }
    pub proof fn transfer_evidence(&self)
        requires self.valid(),
        ensures self.transfer_identity().request == self.authority_value().request(),
            self.transfer_identity().route == self.authority_value().binding(),
    {}
    pub fn authority(&self) -> (out: &AuthorizedRequest<'a>) requires self.valid(), ensures *out == self.authority_value(), out.valid(), { &self.authority }
    pub fn destination(&self) -> (out: Option<&'a Parts>)
        requires self.valid(), ensures match out { Some(d) => self.destination_value() == Some(*d), None => self.destination_value().is_none() },
    { match &self.provider { Some(p) => Some(p.destination), None => None } }
    pub fn credential(&self) -> (out: Option<&'a Credential>)
        requires self.valid(), ensures match out { Some(c) => self.credential_value() == Some(*c), None => self.credential_value().is_none() },
    { match &self.provider { Some(p) => Some(p.credential), None => None } }
    pub fn egress(&self) -> (out: Option<&Egress<'a, Parts>>)
        requires self.valid(), ensures match out { Some(e) => Some(e.target_value()) == self.destination_value(), None => self.destination_value().is_none() },
    { match &self.provider { Some(p) => Some(&p.egress), None => None } }
    pub fn start_record(&self, time: u64) -> (out: Option<Vec<u8>>)
        requires self.valid(),
        ensures out.is_some() ==> self.destination_value().is_some() && crate::metadata::decoded_request_start(out.unwrap()@)
            == Some((time, self.authority_value().binding().selector, self.destination_value().unwrap().text@)),
    { match &self.provider { Some(p) => crate::exchange_lifecycle::start_record(&self.authority, &p.resolved, time), None => None } }

    pub fn write_bytes<'s>(&self, copy: &mut BodyCopy, stream: &'s mut OwnedStream, journal: &JournalBinding) -> (out: Option<crate::body_copy::Delivery<'s>>)
        requires self.valid(), old(copy).valid(old(stream)), old(copy).audited(),
        ensures final(copy).valid(final(stream)), final(copy).same_copy(old(copy)), final(copy).accepted() == old(copy).accepted(),
            final(stream).key() == old(stream).key(),
            match out {
                Some(delivery) => final(copy).writing() && delivery.write_value().ticket() == final(copy).ticket()
                    && delivery.write_value().delivers(final(stream), &self.authority_value(), journal, old(copy).direction(), delivery.bytes_value())
                    && delivery.permits(&self.authority_value(), old(copy).direction())
                    && self.authority_value().grants(delivery.write_value().route()) && delivery.bytes_value().len() > 0
                    && delivery.write_value().route() == self.authority_value().binding()
                    && (self.destination_value().is_some() ==> delivery.write_value().route().origin < self.config().destinations().len()
                        && self.destination_value() == Some(self.config().destinations()[delivery.write_value().route().origin as int])
                        && self.credential_value() == Some(self.config().credentials()[delivery.write_value().route().credential as int])),
                None => final(copy).failure() == Some(crate::body_copy::Failure::InvalidState),
            },
    {
        proof { self.authority.binding_tenant(); }
        let route = match &self.provider { Some(p) => Some(&p.resolved), None => None };
        copy.write_bytes(stream, &self.authority, journal, route)
    }

    /// A supported checked head for this selected provider cannot be refused.
    pub open spec fn can_prepare(&self, checked: &CheckedHead) -> bool {
        checked.valid() && self.destination_value().is_some()
            && self.authority_value().binding().selector == checked.selector_value() && self.digest() == checked.digest_value()
            && (checked.endpoint_value() == checked.input().target.len()
                || checked.input().target@.subrange(checked.endpoint_value(), checked.input().target.len() as int) == self.destination_value().unwrap().path@)
            && !headers::bad_connection_element(checked.input().fields@)
    }

    pub fn prepare(&self, checked: &CheckedHead) -> (out: Result<ProviderHead, Refusal>)
        requires self.valid(), checked.valid(),
        ensures self.can_prepare(checked) ==> out.is_ok(),
            match out { Ok(head) => head.valid() && head.input() == checked.input() && head.policy() == self.config().policy_value()
            && head.request() == self.authority_value().request(), Err(_) => true },
    {
        if self.authority.route().selector != checked.selector || !equal(self.digest.as_slice(), checked.digest.as_slice()) { return Err(Refusal::Unauthorized); }
        let p = match &self.provider { Some(p) => p, None => return Err(Refusal::Unavailable) };
        if !crate::inbound::matches_endpoint(checked.head.target.as_slice(), checked.end, p.destination.path.as_slice()) { return Err(Refusal::Malformed); }
        proof {
            self.authority.authorization_evidence();
            let root = self.config.root@.unwrap();
            let index = self.authority.binding().credential as int;
            assert(p.credential.tenant == root.credentials@[index].tenant);
            assert(p.credential.name@ == build::header_name(root.credentials@[index].kind));
            reveal(headers::AUTHORIZATION); reveal(headers::X_API_KEY);
            assert(headers::AUTHORIZATION@ =~= build::header_name(crate::config_schema::CredentialKind::Bearer));
            assert(headers::X_API_KEY@ =~= build::header_name(crate::config_schema::CredentialKind::ApiKey));
        }
        let fields = match headers::forward_request(&checked.head.fields, &p.destination.authority, p.credential.name.as_slice(), p.credential.value.as_slice()) {
            Ok(f) => f, Err(e) => return Err(rejected(e)),
        };
        let path = vstd::slice::slice_to_vec(p.destination.path.as_slice());
        let evidence = Ghost(Evidence { input: *checked.head, policy: self.authority.policy(), request: self.authority.request(), route: self.authority.binding(),
            digest: self.digest@, endpoint: checked.end as int, destination: *p.destination, credential: *p.credential,
            config: *self.config });
        Ok(ProviderHead { path, fields, evidence, key: self.transfer_key() })
    }
}

fn rejected(e: headers::Rejection) -> Refusal {
    match e { headers::Rejection::TooLarge => Refusal::HeadTooLarge, headers::Rejection::BadRequest => Refusal::Malformed }
}
/// Checked before reserving a request slot; all policy inputs derive from this head.
pub struct CheckedHead<'a> { head: &'a RequestHead, digest: Vec<u8>, selector: u64, end: usize }
impl<'a> CheckedHead<'a> {
    pub closed spec fn input(&self) -> RequestHead { *self.head }
    pub closed spec fn digest_value(&self) -> Seq<u8> { self.digest@ }
    pub closed spec fn endpoint_value(&self) -> int { self.end as int }
    pub closed spec fn selector_value(&self) -> u64 { self.selector }
    pub closed spec fn valid(&self) -> bool {
        self.head.method@ == crate::http1_exchange::post() && headers::request_input_ok(self.head.fields@)
            && crate::inbound::sdk_target(self.head.target@, self.selector, self.end as int)
            && bearer_digest(self.head.fields@, self.digest@)
    }
    pub fn digest(&self) -> (out: &[u8]) ensures out@ == self.digest_value(), { self.digest.as_slice() }
    pub fn selector(&self) -> (out: u64) ensures out == self.selector_value(), { self.selector }
    pub fn parse(head: &'a RequestHead) -> (out: Result<Self, Refusal>)
        ensures supported_input(*head) ==> out.is_ok(),
            match out { Ok(c) => c.valid() && c.input() == *head, Err(_) => true },
    {
        if head.method.len() != 4 || head.method[0] != 80 || head.method[1] != 79 || head.method[2] != 83 || head.method[3] != 84 { return Err(Refusal::MethodNotAllowed); }
        proof { assert(head.method@ =~= crate::http1_exchange::post()); }
        if !headers::fits(&head.fields) { return Err(Refusal::HeadTooLarge); }
        let (selector, end) = match crate::inbound::route_target(head.target.as_slice()) { Some(p) => p, None => return Err(Refusal::Malformed) };
        let token = match crate::inbound::bearer(&head.fields) { Some(t) => t, None => return Err(Refusal::Unauthorized) };
        if token.len() == 0 || token.len() > 512 { return Err(Refusal::Unauthorized); }
        match headers::check_request(&head.fields) { Ok(_) => {}, Err(e) => return Err(rejected(e)) };
        let digest = crate::sha256::digest(token.as_slice());
        proof { assert(bearer_digest(head.fields@, digest@)); }
        Ok(Self { head, digest, selector, end })
    }
}
/// Independent input criteria: canonical route syntax, one bounded bearer,
/// and supported request headers. Parsing may not reject this family.
pub open spec fn supported_input(head: RequestHead) -> bool {
    head.method@ == crate::http1_exchange::post() && headers::request_input_ok(head.fields@)
        && !headers::bad_connection_element(head.fields@)
        && (exists|selector: u64, end: int| crate::inbound::sdk_target(head.target@, selector, end))
        && headers::count_named(head.fields@, headers::AUTHORIZATION@) == 1
        && (forall|i: int| 0 <= i < head.fields.len() && head.fields@[i].name@ == headers::AUTHORIZATION@
            ==> crate::inbound::bearer_token(head.fields@[i].value@).is_some()
                && 0 < crate::inbound::bearer_token(head.fields@[i].value@).unwrap().len() <= 512)
}
/// Non-vacuity: an auth-only POST to any canonical selector path is supported
/// for every well-formed bounded bearer value, independently of parser success.
pub proof fn bearer_post_is_supported(head: RequestHead, selector: u64, end: int, token: Seq<u8>)
    requires head.method@ == crate::http1_exchange::post(),
        crate::inbound::sdk_target(head.target@, selector, end),
        head.fields.len() == 1, head.fields@[0].name@ == headers::AUTHORIZATION@,
        head.fields@[0].value.len() <= 519,
        crate::inbound::bearer_token(head.fields@[0].value@) == Some(token), 0 < token.len() <= 512,
    ensures supported_input(head),
{
    reveal(Seq::filter);
    reveal_with_fuel(headers::names_total, 2);
    assert(head.fields@ =~= seq![head.fields@[0]]);
}
pub open spec fn bearer_digest(fields: Seq<Field>, digest: Seq<u8>) -> bool {
    headers::count_named(fields, headers::AUTHORIZATION@) == 1 && exists|i: int, token: Seq<u8>| 0 <= i < fields.len()
        && fields[i].name@ == headers::AUTHORIZATION@ && crate::inbound::bearer_token(fields[i].value@) == Some(token)
        && digest == crate::sha256::hash(token)
}

pub ghost struct Evidence { pub input: RequestHead, pub policy: Policy, pub request: u64, pub route: Route,
    pub digest: Seq<u8>, pub endpoint: int, pub destination: Parts, pub credential: Credential, pub config: ProviderConfig }
impl Evidence {
    pub open spec fn transfer_identity(&self) -> TransferIdentity {
        TransferIdentity { request: self.request, route: self.route, digest: self.digest, destination: Some(self.destination.text@) }
    }
    pub open spec fn valid(&self) -> bool {
        self.config.valid() && self.policy == self.config.policy_value() && self.policy.valid() && self.request != 0
            && self.input.method@ == crate::http1_exchange::post() && bearer_digest(self.input.fields@, self.digest)
            && (exists|i: int| 0 <= i < self.policy.identities().len() && self.policy.identities()[i].tenant == self.route.tenant && self.policy.identities()[i].digest@ == self.digest)
            && crate::policy::allowed(self.route, self.policy.roots(), self.policy.origins(), self.policy.credentials())
            && crate::inbound::sdk_target(self.input.target@, self.route.selector, self.endpoint)
            && (self.endpoint == self.input.target.len() || self.input.target@.subrange(self.endpoint, self.input.target.len() as int) == self.destination.path@)
            && self.route.origin < self.config.destinations().len() && self.route.credential < self.config.credentials().len()
            && self.destination == self.config.destinations()[self.route.origin as int]
            && self.credential == self.config.credentials()[self.route.credential as int]
    }
    pub open spec fn binds(&self, path: Seq<u8>, fields: Seq<Field>) -> bool {
        self.valid() && path == self.destination.path@ && headers::request_head_ok(self.input.fields@, fields,
            self.destination.authority@, self.credential.name@, self.credential.value@)
    }
}
/// A sealed, single-use outgoing head; callers cannot replace its path or fields.
pub struct ProviderHead { path: Vec<u8>, fields: Vec<Field>, evidence: Ghost<Evidence>, key: TransferKey }
impl ProviderHead {
    pub closed spec fn evidence(&self) -> Evidence { self.evidence@ }
    pub open spec fn input(&self) -> RequestHead { self.evidence().input }
    pub open spec fn policy(&self) -> Policy { self.evidence().policy }
    pub open spec fn request(&self) -> u64 { self.evidence().request }
    pub closed spec fn path(&self) -> Seq<u8> { self.path@ }
    pub closed spec fn fields(&self) -> Seq<Field> { self.fields@ }
    pub closed spec fn valid(&self) -> bool { self.evidence@.binds(self.path@, self.fields@) && self.key.identity() == self.evidence@.transfer_identity() }
    pub fn into_dispatch(self) -> (out: (Vec<u8>, Vec<Field>, TransferKey))
        requires self.valid(),
        ensures self.evidence().binds(out.0@, out.1@), out.0@ == self.path(), out.1@ == self.fields(),
            out.2.identity() == self.evidence().transfer_identity(),
    { (self.path, self.fields, self.key) }
    pub fn into_parts(self) -> (out: (Vec<u8>, Vec<Field>))
        requires self.valid(), ensures self.evidence().binds(out.0@, out.1@), out.0@ == self.path(), out.1@ == self.fields(),
    { (self.path, self.fields) }
    pub fn fields_ref(&self) -> (out: &Vec<Field>) ensures out@ == self.fields(), { &self.fields }
}
}
