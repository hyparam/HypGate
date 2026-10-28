//! The shape of the configuration files: which keys an object may hold, each
//! at most once, which are required, and what kind each must be. `read_root`
//! and `read_candidate` turn a parsed root policy or candidate routes file
//! into the structures the policy core validates; `read_shipping` reads the
//! optional `shipping` section. Each reader is proved to accept exactly the
//! values of its shape predicate and to return the fields the value holds
//! (`reads_root`, `reads_candidate`, `reads_section`). What the fields mean,
//! and the checks on their values (limits, destinations, digests, secret
//! names), live in the policy core and the runtime.
use vstd::prelude::*;
use vstd::slice::slice_to_vec;
use crate::json::{Member, Value};
use crate::policy::Route;
use crate::audit_receipt::Durability;

verus! {

pub const K_IDENTITIES: [u8; 10] = *b"identities";
pub const K_DESTINATIONS: [u8; 12] = *b"destinations";
pub const K_CREDENTIALS: [u8; 11] = *b"credentials";
pub const K_GRANTS: [u8; 6] = *b"grants";
pub const K_LIMITS: [u8; 6] = *b"limits";
pub const K_DURABILITY: [u8; 10] = *b"durability";
pub const V_DURABLE: [u8; 7] = *b"durable";
pub const V_BUFFERED: [u8; 8] = *b"buffered";
pub const K_LOGGING: [u8; 7] = *b"logging";
pub const K_SHIPPING: [u8; 8] = *b"shipping";
pub const K_TENANT: [u8; 6] = *b"tenant";
pub const K_SHA256: [u8; 6] = *b"sha256";
pub const K_KIND: [u8; 4] = *b"kind";
pub const K_ENV: [u8; 3] = *b"env";
pub const K_SELECTOR: [u8; 8] = *b"selector";
pub const K_ORIGIN: [u8; 6] = *b"origin";
pub const K_CREDENTIAL: [u8; 10] = *b"credential";
pub const K_REQUESTS: [u8; 8] = *b"requests";
pub const K_CHUNK_BYTES: [u8; 11] = *b"chunk_bytes";
pub const K_ROUTES: [u8; 6] = *b"routes";
pub const K_SERVER: [u8; 6] = *b"server";
pub const K_TOKEN_ENV: [u8; 9] = *b"token_env";
pub const K_STATE_DIR: [u8; 9] = *b"state_dir";
// Concrete arrays expose byte distinctions to the checkpoint codec proof across modules.
pub const K_MAX_OPEN_EXCHANGES: [u8; 18] = [b'm', b'a', b'x', b'_', b'o', b'p', b'e', b'n', b'_', b'e', b'x', b'c', b'h', b'a', b'n', b'g', b'e', b's'];
pub const K_MAX_EXCHANGE_BYTES: [u8; 18] = [b'm', b'a', b'x', b'_', b'e', b'x', b'c', b'h', b'a', b'n', b'g', b'e', b'_', b'b', b'y', b't', b'e', b's'];
pub const K_S3_REGION: [u8; 9] = *b"s3_region";
pub const K_S3_ACCESS_KEY_ENV: [u8; 17] = *b"s3_access_key_env";
pub const K_S3_SESSION_TOKEN_ENV: [u8; 20] = *b"s3_session_token_env";
pub const K_SESSION: [u8; 7] = *b"session";
pub const K_RESOLVED: [u8; 8] = [b'r', b'e', b's', b'o', b'l', b'v', b'e', b'd'];
pub const K_POISONED: [u8; 8] = [b'p', b'o', b'i', b's', b'o', b'n', b'e', b'd'];
pub const K_POLL_MS: [u8; 7] = *b"poll_ms";
pub const V_BEARER: [u8; 6] = *b"bearer";
pub const V_API_KEY: [u8; 7] = *b"api_key";
pub const V_STRICT: [u8; 6] = *b"strict";
pub const V_AVAILABILITY: [u8; 12] = *b"availability";

pub const DEFAULT_MAX_OPEN_EXCHANGES: usize = 64;
pub const DEFAULT_MAX_EXCHANGE_BYTES: usize = 1024 * 1024;
pub const DEFAULT_POLL_MS: u64 = 1000;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Schema { Root, Identity, Credential, Route, Limits, Candidate, Shipping, Checkpoint }

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum CredentialKind { Bearer, ApiKey }
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Logging { Strict, Availability }
pub struct IdentityInput { pub tenant: u64, pub sha256: Vec<u8> }
pub struct CredentialInput { pub tenant: u64, pub kind: CredentialKind, pub env: Vec<u8> }
pub struct Limits { pub requests: usize, pub chunk_bytes: usize }
pub struct Root {
    pub identities: Vec<IdentityInput>,
    pub destinations: Vec<Vec<u8>>,
    pub credentials: Vec<CredentialInput>,
    pub grants: Vec<Route>,
    pub limits: Limits,
    pub logging: Logging,
    pub durability: Durability,
}
pub struct Candidate { pub routes: Vec<Route> }
pub struct Shipping {
    pub s3_session_token_env: Vec<u8>,
    pub s3_access_key_env: Vec<u8>,
    pub s3_region: Vec<u8>,
    pub server: Vec<u8>,
    pub token_env: Vec<u8>,
    pub state_dir: Vec<u8>,
    pub max_open_exchanges: usize,
    pub max_exchange_bytes: usize,
    pub poll_ms: u64,
}

// ---- the shape ----------------------------------------------------------------------------

pub open spec fn allowed_keys(schema: Schema) -> Seq<Seq<u8>> {
    match schema {
        Schema::Root => seq![K_IDENTITIES@, K_DESTINATIONS@, K_CREDENTIALS@, K_GRANTS@, K_LIMITS@, K_LOGGING@, K_SHIPPING@, K_DURABILITY@],
        Schema::Identity => seq![K_TENANT@, K_SHA256@],
        Schema::Credential => seq![K_TENANT@, K_KIND@, K_ENV@],
        Schema::Route => seq![K_TENANT@, K_SELECTOR@, K_ORIGIN@, K_CREDENTIAL@],
        Schema::Limits => seq![K_REQUESTS@, K_CHUNK_BYTES@],
        Schema::Candidate => seq![K_ROUTES@],
        Schema::Checkpoint => seq![K_SESSION@, K_RESOLVED@, K_POISONED@, K_MAX_OPEN_EXCHANGES@, K_MAX_EXCHANGE_BYTES@],
        Schema::Shipping => seq![K_SERVER@, K_TOKEN_ENV@, K_STATE_DIR@, K_MAX_OPEN_EXCHANGES@, K_MAX_EXCHANGE_BYTES@, K_POLL_MS@, K_S3_REGION@, K_S3_ACCESS_KEY_ENV@, K_S3_SESSION_TOKEN_ENV@],
    }
}
pub open spec fn key_allowed(schema: Schema, key: Seq<u8>) -> bool { allowed_keys(schema).contains(key) }
pub open spec fn ms(v: Value) -> Seq<Member> { crate::json::members_of(v) }
/// No key appears twice.
pub open spec fn distinct_keys(v: Value) -> bool {
    forall|i: int, j: int| 0 <= i < j < ms(v).len() ==> #[trigger] ms(v)[i].key@ != #[trigger] ms(v)[j].key@
}
/// `key` appears at most once.
pub open spec fn unique_key(v: Value, key: Seq<u8>) -> bool {
    forall|i: int, j: int| 0 <= i < j < ms(v).len() && #[trigger] ms(v)[i].key@ == key ==> #[trigger] ms(v)[j].key@ != key
}
/// An object whose keys are all allowed by `schema`, each at most once.
pub open spec fn object_ok(v: Value, schema: Schema) -> bool {
    v is Object && distinct_keys(v) && forall|k: int| 0 <= k < ms(v).len() ==> key_allowed(schema, #[trigger] ms(v)[k].key@)
}
pub open spec fn has_key(v: Value, key: Seq<u8>) -> bool { exists|k: int| 0 <= k < ms(v).len() && #[trigger] ms(v)[k].key@ == key }
/// The value under `key`; meaningful when the key is unique.
pub open spec fn at(v: Value, key: Seq<u8>) -> Value {
    ms(v)[choose|k: int| 0 <= k < ms(v).len() && #[trigger] ms(v)[k].key@ == key].value
}
pub open spec fn is_u64(v: Value) -> bool { v is Number && exists|n: u64| v->Number_0@ == crate::inbound::decimal(n as nat) }
pub open spec fn u64_of(v: Value) -> u64 { choose|n: u64| v->Number_0@ == crate::inbound::decimal(n as nat) }
pub open spec fn is_usize(v: Value) -> bool { is_u64(v) && u64_of(v) <= usize::MAX }
pub open spec fn text_of(v: Value) -> Seq<u8> { v->Str_0@ }
pub open spec fn items(v: Value) -> Seq<Value> { v->Array_0@ }

pub open spec fn identity_ok(v: Value) -> bool {
    object_ok(v, Schema::Identity) && has_key(v, K_TENANT@) && is_u64(at(v, K_TENANT@)) && has_key(v, K_SHA256@) && at(v, K_SHA256@) is Str
}
pub open spec fn kind_ok(v: Value) -> bool { v is Str && (text_of(v) == V_BEARER@ || text_of(v) == V_API_KEY@) }
pub open spec fn credential_ok(v: Value) -> bool {
    object_ok(v, Schema::Credential) && has_key(v, K_TENANT@) && is_u64(at(v, K_TENANT@)) && has_key(v, K_KIND@) && kind_ok(at(v, K_KIND@))
        && has_key(v, K_ENV@) && at(v, K_ENV@) is Str
}
pub open spec fn route_ok(v: Value) -> bool {
    object_ok(v, Schema::Route) && has_key(v, K_TENANT@) && is_u64(at(v, K_TENANT@)) && has_key(v, K_SELECTOR@) && is_u64(at(v, K_SELECTOR@))
        && has_key(v, K_ORIGIN@) && is_usize(at(v, K_ORIGIN@)) && has_key(v, K_CREDENTIAL@) && is_usize(at(v, K_CREDENTIAL@))
}
pub open spec fn routes_ok(v: Value) -> bool { v is Array && forall|k: int| 0 <= k < items(v).len() ==> route_ok(#[trigger] items(v)[k]) }
pub open spec fn limits_ok(v: Value) -> bool {
    object_ok(v, Schema::Limits) && has_key(v, K_REQUESTS@) && is_usize(at(v, K_REQUESTS@)) && has_key(v, K_CHUNK_BYTES@) && is_usize(at(v, K_CHUNK_BYTES@))
}
pub open spec fn logging_ok(v: Value) -> bool { v is Str && (text_of(v) == V_STRICT@ || text_of(v) == V_AVAILABILITY@) }
/// The root policy: six required sections of the right kinds, and an
/// optional `shipping` section that `read_shipping` reads on its own.
pub open spec fn durability_ok(v: Value) -> bool { v is Str && (text_of(v) == V_DURABLE@ || text_of(v) == V_BUFFERED@) }
pub open spec fn durability_of(v: Value) -> Durability {
    if !has_key(v, K_DURABILITY@) || text_of(at(v, K_DURABILITY@)) == V_DURABLE@ { Durability::Durable } else { Durability::Buffered }
}
pub open spec fn root_ok(v: Value) -> bool {
    object_ok(v, Schema::Root)
        && has_key(v, K_IDENTITIES@) && at(v, K_IDENTITIES@) is Array
        && (forall|k: int| 0 <= k < items(at(v, K_IDENTITIES@)).len() ==> identity_ok(#[trigger] items(at(v, K_IDENTITIES@))[k]))
        && has_key(v, K_DESTINATIONS@) && at(v, K_DESTINATIONS@) is Array
        && (forall|k: int| 0 <= k < items(at(v, K_DESTINATIONS@)).len() ==> (#[trigger] items(at(v, K_DESTINATIONS@))[k]) is Str)
        && has_key(v, K_CREDENTIALS@) && at(v, K_CREDENTIALS@) is Array
        && (forall|k: int| 0 <= k < items(at(v, K_CREDENTIALS@)).len() ==> credential_ok(#[trigger] items(at(v, K_CREDENTIALS@))[k]))
        && has_key(v, K_GRANTS@) && routes_ok(at(v, K_GRANTS@))
        && has_key(v, K_LIMITS@) && limits_ok(at(v, K_LIMITS@))
        && has_key(v, K_LOGGING@) && logging_ok(at(v, K_LOGGING@))
        && (!has_key(v, K_DURABILITY@) || durability_ok(at(v, K_DURABILITY@)))
}
pub open spec fn candidate_ok(v: Value) -> bool { object_ok(v, Schema::Candidate) && has_key(v, K_ROUTES@) && routes_ok(at(v, K_ROUTES@)) }
/// The `shipping` section: three required strings and three optional numbers.
pub open spec fn section_ok(s: Value) -> bool {
    object_ok(s, Schema::Shipping) && has_key(s, K_SERVER@) && at(s, K_SERVER@) is Str && has_key(s, K_TOKEN_ENV@) && at(s, K_TOKEN_ENV@) is Str
        && has_key(s, K_STATE_DIR@) && at(s, K_STATE_DIR@) is Str
        && (has_key(s, K_MAX_OPEN_EXCHANGES@) ==> is_usize(at(s, K_MAX_OPEN_EXCHANGES@)))
        && (has_key(s, K_MAX_EXCHANGE_BYTES@) ==> is_usize(at(s, K_MAX_EXCHANGE_BYTES@)))
        && (has_key(s, K_POLL_MS@) ==> is_u64(at(s, K_POLL_MS@)))
        && (has_key(s, K_S3_REGION@) ==> at(s, K_S3_REGION@) is Str)
        && (has_key(s, K_S3_ACCESS_KEY_ENV@) ==> at(s, K_S3_ACCESS_KEY_ENV@) is Str)
        && (has_key(s, K_S3_SESSION_TOKEN_ENV@) ==> at(s, K_S3_SESSION_TOKEN_ENV@) is Str)

}
/// A root policy with no `shipping` section, or a null one.
pub open spec fn shipping_absent(v: Value) -> bool {
    v is Object && unique_key(v, K_SHIPPING@) && (!has_key(v, K_SHIPPING@) || at(v, K_SHIPPING@) is Null)
}
pub open spec fn shipping_ok(v: Value) -> bool { v is Object && unique_key(v, K_SHIPPING@) && has_key(v, K_SHIPPING@) && section_ok(at(v, K_SHIPPING@)) }

// ---- what is read -------------------------------------------------------------------------

pub open spec fn reads_identity(v: Value, out: IdentityInput) -> bool {
    out.tenant == u64_of(at(v, K_TENANT@)) && out.sha256@ == text_of(at(v, K_SHA256@))
}
pub open spec fn kind_of(v: Value) -> CredentialKind { if text_of(v) == V_BEARER@ { CredentialKind::Bearer } else { CredentialKind::ApiKey } }
pub open spec fn reads_credential(v: Value, out: CredentialInput) -> bool {
    out.tenant == u64_of(at(v, K_TENANT@)) && out.kind == kind_of(at(v, K_KIND@)) && out.env@ == text_of(at(v, K_ENV@))
}
pub open spec fn reads_route(v: Value, out: Route) -> bool {
    out.tenant == u64_of(at(v, K_TENANT@)) && out.selector == u64_of(at(v, K_SELECTOR@))
        && out.origin == u64_of(at(v, K_ORIGIN@)) as usize && out.credential == u64_of(at(v, K_CREDENTIAL@)) as usize
}
pub open spec fn reads_routes(v: Value, out: Seq<Route>) -> bool {
    out.len() == items(v).len() && forall|k: int| 0 <= k < out.len() ==> reads_route(items(v)[k], #[trigger] out[k])
}
pub open spec fn logging_of(v: Value) -> Logging { if text_of(v) == V_STRICT@ { Logging::Strict } else { Logging::Availability } }
pub open spec fn reads_root(v: Value, out: Root) -> bool {
    out.identities@.len() == items(at(v, K_IDENTITIES@)).len()
        && (forall|k: int| 0 <= k < out.identities@.len() ==> reads_identity(items(at(v, K_IDENTITIES@))[k], #[trigger] out.identities@[k]))
        && out.destinations@.len() == items(at(v, K_DESTINATIONS@)).len()
        && (forall|k: int| 0 <= k < out.destinations@.len() ==> (#[trigger] out.destinations@[k])@ == text_of(items(at(v, K_DESTINATIONS@))[k]))
        && out.credentials@.len() == items(at(v, K_CREDENTIALS@)).len()
        && (forall|k: int| 0 <= k < out.credentials@.len() ==> reads_credential(items(at(v, K_CREDENTIALS@))[k], #[trigger] out.credentials@[k]))
        && reads_routes(at(v, K_GRANTS@), out.grants@)
        && out.limits.requests == u64_of(at(at(v, K_LIMITS@), K_REQUESTS@)) as usize
        && out.limits.chunk_bytes == u64_of(at(at(v, K_LIMITS@), K_CHUNK_BYTES@)) as usize
        && out.logging == logging_of(at(v, K_LOGGING@))
        && out.durability == durability_of(v)
}
pub open spec fn reads_section(s: Value, out: Shipping) -> bool {
    out.s3_region@ == (if has_key(s, K_S3_REGION@) { text_of(at(s, K_S3_REGION@)) } else { Seq::empty() }) &&
        out.s3_access_key_env@ == (if has_key(s, K_S3_ACCESS_KEY_ENV@) { text_of(at(s, K_S3_ACCESS_KEY_ENV@)) } else { Seq::empty() }) &&
        out.s3_session_token_env@ == (if has_key(s, K_S3_SESSION_TOKEN_ENV@) { text_of(at(s, K_S3_SESSION_TOKEN_ENV@)) } else { Seq::empty() }) &&
        out.server@ == text_of(at(s, K_SERVER@)) && out.token_env@ == text_of(at(s, K_TOKEN_ENV@)) && out.state_dir@ == text_of(at(s, K_STATE_DIR@))
        && out.max_open_exchanges == (if has_key(s, K_MAX_OPEN_EXCHANGES@) { u64_of(at(s, K_MAX_OPEN_EXCHANGES@)) as usize } else { DEFAULT_MAX_OPEN_EXCHANGES })
        && out.max_exchange_bytes == (if has_key(s, K_MAX_EXCHANGE_BYTES@) { u64_of(at(s, K_MAX_EXCHANGE_BYTES@)) as usize } else { DEFAULT_MAX_EXCHANGE_BYTES })
        && out.poll_ms == (if has_key(s, K_POLL_MS@) { u64_of(at(s, K_POLL_MS@)) } else { DEFAULT_POLL_MS })
}

// ---- lemmas -------------------------------------------------------------------------------

/// With `key` unique, the member holding it is the one `at` names.
proof fn lemma_at(v: Value, key: Seq<u8>, k: int)
    requires unique_key(v, key), 0 <= k < ms(v).len(), ms(v)[k].key@ == key,
    ensures has_key(v, key), at(v, key) == ms(v)[k].value,
{
    let c = choose|c: int| 0 <= c < ms(v).len() && #[trigger] ms(v)[c].key@ == key;
    if c < k { assert(ms(v)[k].key@ != key); }
    if k < c { assert(ms(v)[c].key@ != key); }
}
proof fn lemma_distinct_unique(v: Value, key: Seq<u8>)
    requires distinct_keys(v),
    ensures unique_key(v, key),
{
    assert forall|i: int, j: int| 0 <= i < j < ms(v).len() && #[trigger] ms(v)[i].key@ == key implies #[trigger] ms(v)[j].key@ != key by {
        assert(ms(v)[i].key@ != ms(v)[j].key@);
    }
}
/// Canonical decimals name one integer.
pub(crate) proof fn lemma_u64_of(v: Value, n: u64)
    requires v is Number, v->Number_0@ == crate::inbound::decimal(n as nat),
    ensures is_u64(v), u64_of(v) == n,
{
    let m = u64_of(v);
    assert(v->Number_0@ == crate::inbound::decimal(m as nat));
    crate::inbound::lemma_decimal_shape(n as nat);
    crate::inbound::lemma_decimal_shape(m as nat);
}

// ---- reading ------------------------------------------------------------------------------

fn bytes_eq(a: &[u8], b: &[u8]) -> (out: bool)
    ensures out == (a@ == b@),
{
    if a.len() != b.len() { return false; }
    let mut k: usize = 0;
    while k < a.len()
        invariant k <= a.len(), a.len() == b.len(), forall|j: int| 0 <= j < k ==> a@[j] == b@[j],
        decreases a.len() - k,
    {
        if a[k] != b[k] { return false; }
        k = k + 1;
    }
    proof { assert(a@ =~= b@); }
    true
}
#[verifier::rlimit(60)]
fn key_allowed_exec(schema: Schema, key: &[u8]) -> (out: bool)
    ensures out == key_allowed(schema, key@),
{
    let found = match schema {
        Schema::Root => bytes_eq(key, K_IDENTITIES.as_slice()) || bytes_eq(key, K_DESTINATIONS.as_slice()) || bytes_eq(key, K_CREDENTIALS.as_slice())
            || bytes_eq(key, K_GRANTS.as_slice()) || bytes_eq(key, K_LIMITS.as_slice()) || bytes_eq(key, K_LOGGING.as_slice()) || bytes_eq(key, K_SHIPPING.as_slice()) || bytes_eq(key, K_DURABILITY.as_slice()),
        Schema::Identity => bytes_eq(key, K_TENANT.as_slice()) || bytes_eq(key, K_SHA256.as_slice()),
        Schema::Credential => bytes_eq(key, K_TENANT.as_slice()) || bytes_eq(key, K_KIND.as_slice()) || bytes_eq(key, K_ENV.as_slice()),
        Schema::Route => bytes_eq(key, K_TENANT.as_slice()) || bytes_eq(key, K_SELECTOR.as_slice()) || bytes_eq(key, K_ORIGIN.as_slice()) || bytes_eq(key, K_CREDENTIAL.as_slice()),
        Schema::Limits => bytes_eq(key, K_REQUESTS.as_slice()) || bytes_eq(key, K_CHUNK_BYTES.as_slice()),
        Schema::Candidate => bytes_eq(key, K_ROUTES.as_slice()),
        Schema::Checkpoint => bytes_eq(key, K_SESSION.as_slice()) || bytes_eq(key, K_RESOLVED.as_slice()) || bytes_eq(key, K_POISONED.as_slice())
            || bytes_eq(key, K_MAX_OPEN_EXCHANGES.as_slice()) || bytes_eq(key, K_MAX_EXCHANGE_BYTES.as_slice()),
        Schema::Shipping => bytes_eq(key, K_SERVER.as_slice()) || bytes_eq(key, K_TOKEN_ENV.as_slice()) || bytes_eq(key, K_STATE_DIR.as_slice())
            || bytes_eq(key, K_MAX_OPEN_EXCHANGES.as_slice()) || bytes_eq(key, K_MAX_EXCHANGE_BYTES.as_slice()) || bytes_eq(key, K_POLL_MS.as_slice()) || bytes_eq(key, K_S3_REGION.as_slice()) || bytes_eq(key, K_S3_ACCESS_KEY_ENV.as_slice()) || bytes_eq(key, K_S3_SESSION_TOKEN_ENV.as_slice()),
    };
    proof {
        let keys = allowed_keys(schema);
        match schema {
            Schema::Root => {
                assert(keys[0] == K_IDENTITIES@); assert(keys[1] == K_DESTINATIONS@); assert(keys[2] == K_CREDENTIALS@); assert(keys[3] == K_GRANTS@);
                assert(keys[4] == K_LIMITS@); assert(keys[5] == K_LOGGING@); assert(keys[6] == K_SHIPPING@); assert(keys[7] == K_DURABILITY@);
            }
            Schema::Identity => { assert(keys[0] == K_TENANT@); assert(keys[1] == K_SHA256@); }
            Schema::Credential => { assert(keys[0] == K_TENANT@); assert(keys[1] == K_KIND@); assert(keys[2] == K_ENV@); }
            Schema::Route => { assert(keys[0] == K_TENANT@); assert(keys[1] == K_SELECTOR@); assert(keys[2] == K_ORIGIN@); assert(keys[3] == K_CREDENTIAL@); }
            Schema::Limits => { assert(keys[0] == K_REQUESTS@); assert(keys[1] == K_CHUNK_BYTES@); }
            Schema::Candidate => { assert(keys[0] == K_ROUTES@); }
            Schema::Checkpoint => { assert(keys[0] == K_SESSION@); assert(keys[1] == K_RESOLVED@); assert(keys[2] == K_POISONED@);
                assert(keys[3] == K_MAX_OPEN_EXCHANGES@); assert(keys[4] == K_MAX_EXCHANGE_BYTES@); }
            Schema::Shipping => {
                assert(keys[0] == K_SERVER@); assert(keys[1] == K_TOKEN_ENV@); assert(keys[2] == K_STATE_DIR@);
                assert(keys[3] == K_MAX_OPEN_EXCHANGES@); assert(keys[4] == K_MAX_EXCHANGE_BYTES@); assert(keys[5] == K_POLL_MS@); assert(keys[6] == K_S3_REGION@); assert(keys[7] == K_S3_ACCESS_KEY_ENV@); assert(keys[8] == K_S3_SESSION_TOKEN_ENV@);
            }
        }
        if found {
            assert(exists|i: int| 0 <= i < keys.len() && keys[i] == key@);
        } else {
            assert forall|i: int| 0 <= i < keys.len() implies keys[i] != key@ by {}
        }
    }
    found
}
/// The members of `v` when it is an object of `schema`'s shape.
#[verifier::loop_isolation(false)]
pub(crate) fn object(v: &Value, schema: Schema) -> (out: Option<&Vec<Member>>)
    ensures match out { Some(members) => object_ok(*v, schema) && members@ == ms(*v), None => !object_ok(*v, schema) },
{
    let members = match v { Value::Object(members) => members, _ => return None };
    proof { assert(ms(*v) == members@); }
    let mut k: usize = 0;
    while k < members.len()
        invariant k <= members.len(),
            forall|i: int| 0 <= i < k ==> key_allowed(schema, #[trigger] members@[i].key@),
            forall|i: int, j: int| 0 <= i < j < k ==> #[trigger] members@[i].key@ != #[trigger] members@[j].key@,
        decreases members.len() - k,
    {
        let m = vstd::slice::slice_index_get(members.as_slice(), k);
        if !key_allowed_exec(schema, m.key.as_slice()) { return None; }
        let mut p: usize = 0;
        while p < k
            invariant p <= k, k < members.len(), forall|i: int| 0 <= i < p ==> members@[i].key@ != members@[k as int].key@,
            decreases k - p,
        {
            let earlier = vstd::slice::slice_index_get(members.as_slice(), p);
            if bytes_eq(earlier.key.as_slice(), m.key.as_slice()) { return None; }
            p = p + 1;
        }
        k = k + 1;
    }
    Some(members)
}
/// The value under `key`, with keys distinct.
fn field<'a>(v: &'a Value, key: &[u8]) -> (out: Option<&'a Value>)
    requires distinct_keys(*v),
    ensures match out { Some(x) => has_key(*v, key@) && *x == at(*v, key@), None => !has_key(*v, key@) },
{
    let out = v.get(key);
    proof {
        lemma_distinct_unique(*v, key@);
        if let Some(x) = out {
            let k = choose|k: int| 0 <= k < ms(*v).len() && ms(*v)[k].key@ == key@ && ms(*v)[k].value == *x;
            lemma_at(*v, key@, k);
        }
    }
    out
}
pub(crate) fn u64_exec(v: &Value) -> (out: Option<u64>)
    ensures match out { Some(n) => is_u64(*v) && u64_of(*v) == n, None => !is_u64(*v) },
{
    match v {
        Value::Number(lex) => {
            let parsed = crate::http1_framing::parse_decimal(lex.as_slice());
            proof { if let Some(n) = parsed { lemma_u64_of(*v, n); } }
            parsed
        }
        _ => None,
    }
}
fn usize_exec(v: &Value) -> (out: Option<usize>)
    ensures match out { Some(n) => is_usize(*v) && u64_of(*v) == n as u64, None => !is_usize(*v) },
{
    match u64_exec(v) { Some(n) => if n <= usize::MAX as u64 { Some(n as usize) } else { None }, None => None }
}
fn str_exec(v: &Value) -> (out: Option<Vec<u8>>)
    ensures match out { Some(t) => *v is Str && t@ == text_of(*v), None => !(*v is Str) },
{
    match v { Value::Str(t) => Some(slice_to_vec(t.as_slice())), _ => None }
}
pub(crate) fn required_u64(v: &Value, key: &[u8]) -> (out: Option<u64>)
    requires distinct_keys(*v),
    ensures match out { Some(n) => has_key(*v, key@) && is_u64(at(*v, key@)) && u64_of(at(*v, key@)) == n, None => !(has_key(*v, key@) && is_u64(at(*v, key@))) },
{
    match field(v, key) { Some(x) => u64_exec(x), None => None }
}
pub(crate) fn required_usize(v: &Value, key: &[u8]) -> (out: Option<usize>)
    requires distinct_keys(*v),
    ensures match out { Some(n) => has_key(*v, key@) && is_usize(at(*v, key@)) && u64_of(at(*v, key@)) == n as u64, None => !(has_key(*v, key@) && is_usize(at(*v, key@))) },
{
    match field(v, key) { Some(x) => usize_exec(x), None => None }
}
pub(crate) fn required_str(v: &Value, key: &[u8]) -> (out: Option<Vec<u8>>)
    requires distinct_keys(*v),
    ensures match out { Some(t) => has_key(*v, key@) && at(*v, key@) is Str && t@ == text_of(at(*v, key@)), None => !(has_key(*v, key@) && at(*v, key@) is Str) },
{
    match field(v, key) { Some(x) => str_exec(x), None => None }
}

fn read_identity(v: &Value) -> (out: Option<IdentityInput>)
    ensures match out { Some(i) => identity_ok(*v) && reads_identity(*v, i), None => !identity_ok(*v) },
{
    if object(v, Schema::Identity).is_none() { return None; }
    let tenant = match required_u64(v, K_TENANT.as_slice()) { Some(n) => n, None => return None };
    let sha256 = match required_str(v, K_SHA256.as_slice()) { Some(t) => t, None => return None };
    Some(IdentityInput { tenant, sha256 })
}
fn read_credential(v: &Value) -> (out: Option<CredentialInput>)
    ensures match out { Some(c) => credential_ok(*v) && reads_credential(*v, c), None => !credential_ok(*v) },
{
    if object(v, Schema::Credential).is_none() { return None; }
    let tenant = match required_u64(v, K_TENANT.as_slice()) { Some(n) => n, None => return None };
    let kind_text = match required_str(v, K_KIND.as_slice()) { Some(t) => t, None => return None };
    let kind = if bytes_eq(kind_text.as_slice(), V_BEARER.as_slice()) { CredentialKind::Bearer }
        else if bytes_eq(kind_text.as_slice(), V_API_KEY.as_slice()) { CredentialKind::ApiKey }
        else { return None };
    let env = match required_str(v, K_ENV.as_slice()) { Some(t) => t, None => return None };
    Some(CredentialInput { tenant, kind, env })
}
fn read_route(v: &Value) -> (out: Option<Route>)
    ensures match out { Some(r) => route_ok(*v) && reads_route(*v, r), None => !route_ok(*v) },
{
    if object(v, Schema::Route).is_none() { return None; }
    let tenant = match required_u64(v, K_TENANT.as_slice()) { Some(n) => n, None => return None };
    let selector = match required_u64(v, K_SELECTOR.as_slice()) { Some(n) => n, None => return None };
    let origin = match required_usize(v, K_ORIGIN.as_slice()) { Some(n) => n, None => return None };
    let credential = match required_usize(v, K_CREDENTIAL.as_slice()) { Some(n) => n, None => return None };
    Some(Route { tenant, selector, origin, credential })
}
#[verifier::loop_isolation(false)]
fn read_routes(v: &Value) -> (out: Option<Vec<Route>>)
    ensures match out { Some(rs) => routes_ok(*v) && reads_routes(*v, rs@), None => !routes_ok(*v) },
{
    let list = match v { Value::Array(list) => list, _ => return None };
    proof { assert(items(*v) == list@); }
    let mut out: Vec<Route> = Vec::new();
    let mut k: usize = 0;
    while k < list.len()
        invariant k <= list.len(), out@.len() == k,
            forall|i: int| 0 <= i < k ==> route_ok(#[trigger] list@[i]) && reads_route(list@[i], out@[i]),
        decreases list.len() - k,
    {
        let item = vstd::slice::slice_index_get(list.as_slice(), k);
        match read_route(item) { Some(r) => out.push(r), None => return None }
        k = k + 1;
    }
    Some(out)
}
fn read_limits(v: &Value) -> (out: Option<Limits>)
    ensures match out { Some(l) => limits_ok(*v) && l.requests as u64 == u64_of(at(*v, K_REQUESTS@)) && l.chunk_bytes as u64 == u64_of(at(*v, K_CHUNK_BYTES@)), None => !limits_ok(*v) },
{
    if object(v, Schema::Limits).is_none() { return None; }
    let requests = match required_usize(v, K_REQUESTS.as_slice()) { Some(n) => n, None => return None };
    let chunk_bytes = match required_usize(v, K_CHUNK_BYTES.as_slice()) { Some(n) => n, None => return None };
    Some(Limits { requests, chunk_bytes })
}

/// The root policy, when it has the shape `root_ok`.
#[verifier::loop_isolation(false)]
#[verifier::rlimit(100)]
pub fn read_root(v: &Value) -> (out: Option<Root>)
    ensures match out { Some(r) => root_ok(*v) && reads_root(*v, r), None => !root_ok(*v) },
{
    if object(v, Schema::Root).is_none() { return None; }
    let identity_list_value = match field(v, K_IDENTITIES.as_slice()) { Some(x) => x, None => return None };
    let identity_list = match identity_list_value { Value::Array(list) => list, _ => return None };
    proof { assert(*identity_list_value == Value::Array(*identity_list)); assert(items(at(*v, K_IDENTITIES@)) == identity_list@); }
    let mut identities: Vec<IdentityInput> = Vec::new();
    let mut k: usize = 0;
    while k < identity_list.len()
        invariant k <= identity_list.len(), identities@.len() == k,
            forall|i: int| 0 <= i < k ==> identity_ok(#[trigger] identity_list@[i]) && reads_identity(identity_list@[i], identities@[i]),
        decreases identity_list.len() - k,
    {
        let item = vstd::slice::slice_index_get(identity_list.as_slice(), k);
        match read_identity(item) { Some(i) => identities.push(i), None => return None }
        k = k + 1;
    }
    let destination_list_value = match field(v, K_DESTINATIONS.as_slice()) { Some(x) => x, None => return None };
    let destination_list = match destination_list_value { Value::Array(list) => list, _ => return None };
    proof { assert(*destination_list_value == Value::Array(*destination_list)); assert(items(at(*v, K_DESTINATIONS@)) == destination_list@); }
    let mut destinations: Vec<Vec<u8>> = Vec::new();
    let mut k: usize = 0;
    while k < destination_list.len()
        invariant k <= destination_list.len(), destinations@.len() == k,
            forall|i: int| 0 <= i < k ==> (#[trigger] destination_list@[i]) is Str && destinations@[i]@ == text_of(destination_list@[i]),
        decreases destination_list.len() - k,
    {
        let item = vstd::slice::slice_index_get(destination_list.as_slice(), k);
        match str_exec(item) { Some(t) => destinations.push(t), None => return None }
        k = k + 1;
    }
    let credential_list_value = match field(v, K_CREDENTIALS.as_slice()) { Some(x) => x, None => return None };
    let credential_list = match credential_list_value { Value::Array(list) => list, _ => return None };
    proof { assert(*credential_list_value == Value::Array(*credential_list)); assert(items(at(*v, K_CREDENTIALS@)) == credential_list@); }
    let mut credentials: Vec<CredentialInput> = Vec::new();
    let mut k: usize = 0;
    while k < credential_list.len()
        invariant k <= credential_list.len(), credentials@.len() == k,
            forall|i: int| 0 <= i < k ==> credential_ok(#[trigger] credential_list@[i]) && reads_credential(credential_list@[i], credentials@[i]),
        decreases credential_list.len() - k,
    {
        let item = vstd::slice::slice_index_get(credential_list.as_slice(), k);
        match read_credential(item) { Some(c) => credentials.push(c), None => return None }
        k = k + 1;
    }
    let grants = match field(v, K_GRANTS.as_slice()) { Some(g) => match read_routes(g) { Some(rs) => rs, None => return None }, None => return None };
    let limits = match field(v, K_LIMITS.as_slice()) { Some(l) => match read_limits(l) { Some(l) => l, None => return None }, None => return None };
    let logging_text = match required_str(v, K_LOGGING.as_slice()) { Some(t) => t, None => return None };
    let logging = if bytes_eq(logging_text.as_slice(), V_STRICT.as_slice()) { Logging::Strict }
        else if bytes_eq(logging_text.as_slice(), V_AVAILABILITY.as_slice()) { Logging::Availability }
        else { return None };
    let durability = match field(v, K_DURABILITY.as_slice()) {
        None => Durability::Durable,
        Some(value) => {
            let text = match str_exec(value) { Some(t) => t, None => return None };
            if bytes_eq(text.as_slice(), V_DURABLE.as_slice()) { Durability::Durable }
            else if bytes_eq(text.as_slice(), V_BUFFERED.as_slice()) { Durability::Buffered }
            else { return None; }
        },
    };
    proof { assert(durability == durability_of(*v)); assert(root_ok(*v)); }
    Some(Root { identities, destinations, credentials, grants, limits, logging, durability })
}
/// The candidate routes file, when it has the shape `candidate_ok`.
pub fn read_candidate(v: &Value) -> (out: Option<Candidate>)
    ensures match out { Some(c) => candidate_ok(*v) && reads_routes(at(*v, K_ROUTES@), c.routes@), None => !candidate_ok(*v) },
{
    if object(v, Schema::Candidate).is_none() { return None; }
    match field(v, K_ROUTES.as_slice()) {
        Some(r) => match read_routes(r) { Some(routes) => Some(Candidate { routes }), None => None },
        None => None,
    }
}
/// Whether `key` appears at most once among the members.
#[verifier::loop_isolation(false)]
fn key_unique(members: &Vec<Member>, key: &[u8]) -> (out: bool)
    ensures out == (forall|i: int, j: int| 0 <= i < j < members@.len() && #[trigger] members@[i].key@ == key@ ==> #[trigger] members@[j].key@ != key@),
{
    let mut seen = false;
    let mut k: usize = 0;
    while k < members.len()
        invariant k <= members.len(), seen == exists|i: int| 0 <= i < k && #[trigger] members@[i].key@ == key@,
            forall|i: int, j: int| 0 <= i < j < k && #[trigger] members@[i].key@ == key@ ==> #[trigger] members@[j].key@ != key@,
        decreases members.len() - k,
    {
        let m = vstd::slice::slice_index_get(members.as_slice(), k);
        if bytes_eq(m.key.as_slice(), key) {
            if seen { return false; }
            seen = true;
        }
        k = k + 1;
    }
    true
}
/// The optional `shipping` section of a root policy: `Ok(None)` when absent
/// or null, `Ok(Some)` when it has the shape `section_ok`, `Err` otherwise,
/// including when `shipping` appears twice.
pub fn read_shipping(v: &Value) -> (out: Result<Option<Shipping>, ()>)
    ensures match out {
        Ok(None) => shipping_absent(*v),
        Ok(Some(s)) => shipping_ok(*v) && reads_section(at(*v, K_SHIPPING@), s),
        Err(()) => !shipping_absent(*v) && !shipping_ok(*v),
    },
{
    let members = match v { Value::Object(members) => members, _ => return Err(()) };
    proof { assert(ms(*v) == members@); }
    if !key_unique(members, K_SHIPPING.as_slice()) { return Err(()); }
    let section = match v.get(K_SHIPPING.as_slice()) {
        Some(section) => {
            proof {
                let k = choose|k: int| 0 <= k < ms(*v).len() && ms(*v)[k].key@ == K_SHIPPING@ && ms(*v)[k].value == *section;
                lemma_at(*v, K_SHIPPING@, k);
            }
            section
        }
        None => return Ok(None),
    };
    if section.is_null() { return Ok(None); }
    if object(section, Schema::Shipping).is_none() { return Err(()); }
    let server = match required_str(section, K_SERVER.as_slice()) { Some(t) => t, None => return Err(()) };
    let token_env = match required_str(section, K_TOKEN_ENV.as_slice()) { Some(t) => t, None => return Err(()) };
    let state_dir = match required_str(section, K_STATE_DIR.as_slice()) { Some(t) => t, None => return Err(()) };
    let max_open_exchanges = match field(section, K_MAX_OPEN_EXCHANGES.as_slice()) {
        Some(x) => match usize_exec(x) { Some(n) => n, None => return Err(()) },
        None => DEFAULT_MAX_OPEN_EXCHANGES,
    };
    let max_exchange_bytes = match field(section, K_MAX_EXCHANGE_BYTES.as_slice()) {
        Some(x) => match usize_exec(x) { Some(n) => n, None => return Err(()) },
        None => DEFAULT_MAX_EXCHANGE_BYTES,
    };
    let poll_ms = match field(section, K_POLL_MS.as_slice()) {
        Some(x) => match u64_exec(x) { Some(n) => n, None => return Err(()) },
        None => DEFAULT_POLL_MS,
    };
    let s3_region = match field(section, K_S3_REGION.as_slice()) {
        Some(x) => match x.as_str() { Some(t) => t.clone(), None => return Err(()) },
        None => Vec::new(),
    };
    let s3_access_key_env = match field(section, K_S3_ACCESS_KEY_ENV.as_slice()) {
        Some(x) => match x.as_str() { Some(t) => t.clone(), None => return Err(()) },
        None => Vec::new(),
    };
    let s3_session_token_env = match field(section, K_S3_SESSION_TOKEN_ENV.as_slice()) {
        Some(x) => match x.as_str() { Some(t) => t.clone(), None => return Err(()) },
        None => Vec::new(),
    };
    Ok(Some(Shipping { s3_region, s3_access_key_env, s3_session_token_env, server, token_env, state_dir, max_open_exchanges, max_exchange_bytes, poll_ms }))
}

} // verus!
