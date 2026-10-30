//! The gateway configuration assembled from the schema reader's output: the
//! identities with their decoded digests, the destinations parsed, the
//! credentials with their secrets fetched and formed into header values, and
//! the policy validated over them, each list in the order the file gives it.
//! Secrets come from a trait the runtime implements over the environment;
//! the assembly is proved against it: credential `i` carries entry `i`'s
//! tenant and kind, its header name is the one that kind takes, and its value
//! is formed from the secret fetched under entry `i`'s name, which is the
//! `i`th fetch made. That reading a variable returns its value remains the
//! runtime's effect.
use vstd::prelude::*;
use crate::config_schema::{Candidate, CredentialInput, CredentialKind, IdentityInput, Limits, Logging, Root};
use crate::config_values::{MAX_CREDENTIAL_BYTES, credential_value_exec, digest, secret_name_ok_exec, secret_ok_exec};
use crate::destination::{Parts, parse};
use crate::policy::{Identity, Policy};

verus! {

/// The secret store as the assembly sees it: the bytes under a name, if any.
pub trait Secrets {
    spec fn values(&self) -> Map<Seq<u8>, Seq<u8>>;
    spec fn reads(&self) -> Seq<Seq<u8>>;
    fn get(&mut self, name: &[u8]) -> (out: Option<Vec<u8>>)
        ensures final(self).values() == old(self).values(),
            final(self).reads() == old(self).reads().push(name@),
            crate::s3_config::optional_bytes(out) ==
                (if old(self).values().contains_key(name@) { Some(old(self).values()[name@]) } else { None });
}
pub open spec fn fetched_names(fetched: Seq<(Seq<u8>, Seq<u8>)>) -> Seq<Seq<u8>> {
    fetched.map(|i: int, f: (Seq<u8>, Seq<u8>)| f.0)
}
pub open spec fn fetched_values(fetched: Seq<(Seq<u8>, Seq<u8>)>, values: Map<Seq<u8>, Seq<u8>>) -> bool {
    forall|i: int| 0 <= i < fetched.len() ==> values.contains_key(#[trigger] fetched[i].0) && fetched[i].1 == values[fetched[i].0]
}

#[derive(PartialEq, Eq, Structural, Clone, Copy, Debug)]
pub enum BuildError { Limits, Identity, Destination, Credential, Policy }

/// A provider credential: the header it is sent in and the value, formed by
/// the verified rule from the secret.
pub struct Credential { pub tenant: u64, pub kind: CredentialKind, pub name: Vec<u8>, pub value: Vec<u8> }

/// The header a credential kind is sent in.
pub open spec fn header_name(kind: CredentialKind) -> Seq<u8> {
    match kind {
        CredentialKind::Bearer => seq![97u8, 117, 116, 104, 111, 114, 105, 122, 97, 116, 105, 111, 110],
        CredentialKind::ApiKey => seq![120u8, 45, 97, 112, 105, 45, 107, 101, 121],
    }
}

fn header_name_exec(kind: CredentialKind) -> (out: Vec<u8>)
    ensures out@ == header_name(kind),
{
    let mut out: Vec<u8> = Vec::new();
    match kind {
        CredentialKind::Bearer => {
            out.push(97); out.push(117); out.push(116); out.push(104); out.push(111); out.push(114); out.push(105);
            out.push(122); out.push(97); out.push(116); out.push(105); out.push(111); out.push(110);
        }
        CredentialKind::ApiKey => {
            out.push(120); out.push(45); out.push(97); out.push(112); out.push(105); out.push(45); out.push(107); out.push(101); out.push(121);
        }
    }
    proof { assert(out@ =~= header_name(kind)); }
    out
}

/// A destination the gateway may connect to: parsed by the verified grammar,
/// and a bracketed host is a real IPv6 address.
pub open spec fn destination_accepted(text: Seq<u8>, parts: Parts) -> bool {
    crate::destination::destination_ok(text, parts) && (parts.authority@.len() > 0 && parts.authority@[0] == 91 ==> crate::ipv6::ipv6_ok(parts.host@))
}

pub fn destination_exec(text: &[u8]) -> (out: Option<Parts>)
    ensures out is Some ==> destination_accepted(text@, out.unwrap()),
{
    let parts = match parse(text) { Some(parts) => parts, None => return None };
    if parts.authority.len() > 0 && parts.authority[0] == 91 && !crate::ipv6::literal_ok(parts.host.as_slice()) { return None; }
    Some(parts)
}

/// Identity `i` of the output is entry `i` of the file with its digest decoded.
pub open spec fn identities_match(inputs: Seq<IdentityInput>, out: Seq<Identity>) -> bool {
    out.len() == inputs.len()
    && forall|i: int| 0 <= i < inputs.len() ==> #[trigger] out[i].tenant == inputs[i].tenant && crate::config_values::digest_ok(inputs[i].sha256@) && out[i].digest@ == crate::config_values::digest_of(inputs[i].sha256@)
}
/// Destination `i` of the output is entry `i` of the file parsed.
pub open spec fn destinations_match(inputs: Seq<Vec<u8>>, out: Seq<Parts>) -> bool {
    out.len() == inputs.len() && forall|i: int| 0 <= i < inputs.len() ==> destination_accepted(#[trigger] inputs[i]@, out[i])
}
/// Credential `i` of the output is entry `i` of the file with the secret
/// fetched under its name, the `i`th fetch, formed into the header value.
pub open spec fn credentials_match(inputs: Seq<CredentialInput>, fetched: Seq<(Seq<u8>, Seq<u8>)>, out: Seq<Credential>) -> bool {
    out.len() == inputs.len() && fetched.len() == inputs.len()
    && forall|i: int| 0 <= i < inputs.len() ==>
        #[trigger] out[i].tenant == inputs[i].tenant && out[i].kind == inputs[i].kind && out[i].name@ == header_name(inputs[i].kind)
        && crate::config_values::secret_name_ok(inputs[i].env@) && fetched[i].0 == inputs[i].env@ && crate::config_values::secret_ok(fetched[i].1, MAX_CREDENTIAL_BYTES as int)
        && out[i].value@ == crate::config_values::credential_value(inputs[i].kind, fetched[i].1) && crate::config_values::header_safe(out[i].value@)
}

/// The assembled configuration. `fetched` is every secret fetch made, in
/// order: the name asked for and the bytes returned.
pub struct Built {
    pub policy: Policy,
    pub destinations: Vec<Parts>,
    pub credentials: Vec<Credential>,
    pub limits: Limits,
    pub logging: Logging,
    pub durability: crate::audit_receipt::Durability,
    pub fetched: Ghost<Seq<(Seq<u8>, Seq<u8>)>>,
}

fn build_identities(inputs: &Vec<IdentityInput>) -> (out: Option<Vec<Identity>>)
    ensures out is Some ==> identities_match(inputs@, out.unwrap()@),
{
    let mut out: Vec<Identity> = Vec::new();
    let mut i: usize = 0;
    while i < inputs.len()
        invariant i <= inputs.len(), out@.len() == i,
            forall|k: int| 0 <= k < i ==> #[trigger] out@[k].tenant == inputs@[k].tenant && crate::config_values::digest_ok(inputs@[k].sha256@) && out@[k].digest@ == crate::config_values::digest_of(inputs@[k].sha256@),
        decreases inputs.len() - i,
    {
        let decoded = match digest(inputs[i].sha256.as_slice()) { Some(d) => d, None => return None };
        out.push(Identity { tenant: inputs[i].tenant, digest: decoded });
        i = i + 1;
    }
    Some(out)
}

fn build_destinations(inputs: &Vec<Vec<u8>>) -> (out: Option<Vec<Parts>>)
    ensures out is Some ==> destinations_match(inputs@, out.unwrap()@),
{
    let mut out: Vec<Parts> = Vec::new();
    let mut i: usize = 0;
    while i < inputs.len()
        invariant i <= inputs.len(), out@.len() == i,
            forall|k: int| 0 <= k < i ==> destination_accepted(#[trigger] inputs@[k]@, out@[k]),
        decreases inputs.len() - i,
    {
        let parts = match destination_exec(inputs[i].as_slice()) { Some(p) => p, None => return None };
        out.push(parts);
        i = i + 1;
    }
    Some(out)
}

/// Each entry's tenant, for the policy's ownership check.
fn tenants_of(inputs: &Vec<CredentialInput>) -> (out: Vec<u64>)
    ensures out@.len() == inputs@.len(), forall|i: int| 0 <= i < inputs@.len() ==> #[trigger] out@[i] == inputs@[i].tenant,
{
    let mut tenants: Vec<u64> = Vec::new();
    let mut i: usize = 0;
    while i < inputs.len()
        invariant i <= inputs.len(), tenants@.len() == i, forall|k: int| 0 <= k < i ==> #[trigger] tenants@[k] == inputs@[k].tenant,
        decreases inputs.len() - i,
    {
        tenants.push(inputs[i].tenant);
        i = i + 1;
    }
    tenants
}

/// The credentials, each from the secret fetched under its entry's name.
fn build_credentials<S: Secrets>(inputs: &Vec<CredentialInput>, secrets: &mut S) -> (out: Option<(Vec<Credential>, Ghost<Seq<(Seq<u8>, Seq<u8>)>>)>)
    ensures final(secrets).values() == old(secrets).values(),
        out is Some ==> credentials_match(inputs@, out.unwrap().1@, out.unwrap().0@)
            && final(secrets).reads() == old(secrets).reads() + fetched_names(out.unwrap().1@)
            && fetched_values(out.unwrap().1@, old(secrets).values()),
{
    let mut out: Vec<Credential> = Vec::new();
    let ghost mut fetched: Seq<(Seq<u8>, Seq<u8>)> = Seq::empty();
    let mut i: usize = 0;
    while i < inputs.len()
        invariant i <= inputs.len(), out@.len() == i, fetched.len() == i,
            secrets.values() == old(secrets).values(),
            secrets.reads() == old(secrets).reads() + fetched_names(fetched),
            fetched_values(fetched, secrets.values()),
            forall|k: int| 0 <= k < i ==> #[trigger] out@[k].tenant == inputs@[k].tenant,
            forall|k: int| 0 <= k < i ==> #[trigger] out@[k].kind == inputs@[k].kind,
            forall|k: int| 0 <= k < i ==> #[trigger] out@[k].name@ == header_name(inputs@[k].kind),
            forall|k: int| 0 <= k < i ==> crate::config_values::secret_name_ok(#[trigger] inputs@[k].env@),
            forall|k: int| 0 <= k < i ==> #[trigger] fetched[k].0 == inputs@[k].env@,
            forall|k: int| 0 <= k < i ==> crate::config_values::secret_ok(#[trigger] fetched[k].1, MAX_CREDENTIAL_BYTES as int),
            forall|k: int| 0 <= k < i ==> #[trigger] out@[k].value@ == crate::config_values::credential_value(inputs@[k].kind, fetched[k].1),
            forall|k: int| 0 <= k < i ==> crate::config_values::header_safe(#[trigger] out@[k].value@),
        decreases inputs.len() - i,
    {
        let entry = &inputs[i];
        if !secret_name_ok_exec(entry.env.as_slice()) { return None; }
        let raw = match secrets.get(entry.env.as_slice()) { Some(raw) => raw, None => return None };
        proof {
            let before = fetched;
            fetched = fetched.push((entry.env@, raw@));
            assert(fetched_names(fetched) =~= fetched_names(before).push(entry.env@));
        }
        if !secret_ok_exec(raw.as_slice(), MAX_CREDENTIAL_BYTES) { return None; }
        let value = credential_value_exec(entry.kind, raw.as_slice());
        let name = header_name_exec(entry.kind);
        let ghost before = out@;
        out.push(Credential { tenant: entry.tenant, kind: entry.kind, name, value });
        proof {
            assert forall|k: int| 0 <= k < i implies
                #[trigger] out@[k].tenant == inputs@[k].tenant && out@[k].kind == inputs@[k].kind && out@[k].name@ == header_name(inputs@[k].kind)
                && out@[k].value@ == crate::config_values::credential_value(inputs@[k].kind, fetched[k].1) && crate::config_values::header_safe(out@[k].value@) by {
                assert(out@[k] == before[k]);
                assert(before[k].tenant == inputs@[k].tenant);
            }
        }
        i = i + 1;
    }
    Some((out, Ghost(fetched)))
}

/// Assemble the configuration from the file's contents and the secret store.
#[allow(non_shorthand_field_patterns)] // the macro expands the shorthand
pub fn build<S: Secrets>(root: Root, candidate: Candidate, secrets: &mut S) -> (out: Result<Built, BuildError>)
    ensures final(secrets).values() == old(secrets).values(), match out {
        Ok(b) => {
            &&& final(secrets).reads() == old(secrets).reads() + fetched_names(b.fetched@)
            &&& fetched_values(b.fetched@, old(secrets).values())
            &&& 0 < root.limits.requests <= 65536 && 0 < root.limits.chunk_bytes <= 1048576
            &&& (root.limits.requests as int) * (root.limits.chunk_bytes as int) <= 134217728
            &&& b.limits == root.limits && b.logging == root.logging && b.durability == root.durability
            &&& b.policy.valid() && b.policy.roots() == root.grants@ && b.policy.configured() == candidate.routes@
            &&& identities_match(root.identities@, b.policy.identities())
            &&& destinations_match(root.destinations@, b.destinations@) && b.policy.origins() == root.destinations@.len()
            &&& credentials_match(root.credentials@, b.fetched@, b.credentials@)
            &&& b.policy.credentials().len() == root.credentials@.len()
            &&& forall|i: int| 0 <= i < root.credentials@.len() ==> #[trigger] b.policy.credentials()[i] == root.credentials@[i].tenant
        }
        Err(_) => true,
    },
{
    let Root { identities, destinations, credentials, grants, limits, logging, durability } = root;
    if !crate::resource::validate_limits(limits.requests, limits.chunk_bytes) { return Err(BuildError::Limits); }
    let identities = match build_identities(&identities) { Some(v) => v, None => return Err(BuildError::Identity) };
    let destinations = match build_destinations(&destinations) { Some(v) => v, None => return Err(BuildError::Destination) };
    // The policy is validated before any secret is fetched: a rejected file never touches the store.
    let policy = match Policy::validate(identities, grants, candidate.routes, destinations.len(), tenants_of(&credentials)) {
        Some(p) => p, None => return Err(BuildError::Policy),
    };
    let (credentials, fetched) = match build_credentials(&credentials, secrets) { Some(v) => v, None => return Err(BuildError::Credential) };
    Ok(Built { policy, destinations, credentials, limits, logging, durability, fetched })
}

} // verus!

