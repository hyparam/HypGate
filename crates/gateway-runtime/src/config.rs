//! Configuration loading. The JSON is read by the verified `gateway_core::json`
//! reader, its shape (which keys, once each, which kinds) by the verified
//! `gateway_core::config_schema`, and the normalized grant relation is checked
//! by the verified core, including selection of concrete destination/credential
//! values; destinations are parsed by the verified core and a bracketed host
//! checked by the verified IPv6 grammar; strings are checked by the verified
//! UTF-8 predicate; digests, secret names and values, and the credential
//! header value follow the verified rules in `gateway_core::config_values`.
//! Hashing and secret provisioning remain trusted.
use crate::admission::{Admission, AdmissionError, Request};
use gateway_core::config_schema as schema;
use gateway_core::config_values as values;
use gateway_core::json;
use gateway_core::policy::{Identity, Policy, Route};

const MAX_CONFIG: usize = 1024 * 1024;
#[cfg(test)]
pub(crate) const MAX_DESTINATION_BYTES: usize = 8192;
pub(crate) use gateway_core::config_values::MAX_CREDENTIAL_BYTES;

#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError { Syntax, Limits, Identity, Destination, Credential, Policy }

/// Text from the verified schema reader: the configuration's strings must be
/// UTF-8, decided by the verified check; the conversion then cannot fail.
pub(crate) fn utf8(bytes: Vec<u8>) -> Result<String, ConfigError> {
    if !gateway_core::utf8::is_valid(&bytes) { return Err(ConfigError::Syntax); }
    String::from_utf8(bytes).map_err(|_| ConfigError::Syntax)
}

struct Root {
    identities: Vec<IdentityInput>,
    destinations: Vec<String>,
    credentials: Vec<CredentialInput>,
    grants: Vec<Route>,
    limits: Limits,
    logging: Logging,
}
impl Root {
    /// The root policy through the verified reader and schema. `shipping` is
    /// read separately by `shipping::ShippingConfig`; the gateway's own
    /// configuration never holds the cloud token or server.
    fn read(bytes: &[u8]) -> Result<Self, ConfigError> {
        let value = json::parse(bytes).ok_or(ConfigError::Syntax)?;
        let root = schema::read_root(&value).ok_or(ConfigError::Syntax)?;
        let identities = root.identities.into_iter().map(|i| Ok(IdentityInput { tenant: i.tenant, sha256: utf8(i.sha256)? }))
            .collect::<Result<Vec<_>, ConfigError>>()?;
        let destinations = root.destinations.into_iter().map(utf8).collect::<Result<Vec<_>, _>>()?;
        let credentials = root.credentials.into_iter().map(|c| Ok(CredentialInput { tenant: c.tenant, kind: c.kind, env: utf8(c.env)? }))
            .collect::<Result<Vec<_>, ConfigError>>()?;
        Ok(Root { identities, destinations, credentials, grants: root.grants, limits: root.limits, logging: root.logging })
    }
}
struct IdentityInput { tenant: u64, sha256: String }
struct CredentialInput { tenant: u64, kind: CredentialKind, env: String }
pub(crate) use schema::{CredentialKind, Limits, Logging};
struct Candidate { routes: Vec<Route> }
impl Candidate {
    fn read(bytes: &[u8]) -> Result<Self, ConfigError> {
        let value = json::parse(bytes).ok_or(ConfigError::Syntax)?;
        Ok(Candidate { routes: schema::read_candidate(&value).ok_or(ConfigError::Syntax)?.routes })
    }
}

// Intentionally no Debug implementation: neither errors nor diagnostics should
// accidentally format loaded credentials.
struct Credential { kind: CredentialKind, value: Vec<u8> }

// A destination is the verified `gateway_core::destination::Parts`: the text the
// operator wrote and the authority, host, port, and path proved to be its
// substrings. The resolved route hands the core these parts directly, so the
// request-start record and the Host header are built from them by proof.
pub(crate) type Destination = gateway_core::destination::Parts;

pub struct GatewayConfig {
    chunk_bytes: usize,
    admission: Admission,
    destinations: Vec<Destination>,
    credentials: Vec<Credential>,
}

/// The route and credential references come from the same immutable configuration
/// that admitted the owned request. No caller-supplied URI or secret override.
pub struct RoutedRequest<'a> {
    request: Request<'a>,
    resolved: gateway_core::resolved_route::ResolvedRoute<'a, Destination, Credential>,
}

/// The verified parts are visible ASCII, so this never fails for a destination
/// `parse` accepted.
fn ascii(bytes: &[u8]) -> &str { std::str::from_utf8(bytes).expect("verified destination part is ASCII") }

/// Validate a destination with the verified parser. The parts are what the
/// runtime connects to, names in TLS, writes as Host, and uses as the request target.
pub(crate) fn destination(text: &str) -> Result<Destination, ConfigError> {
    let parts = gateway_core::destination::parse(text.as_bytes()).ok_or(ConfigError::Destination)?;
    // A bracketed literal must also be a real IPv6 address, not just IPv6 characters (verified grammar).
    if parts.authority.first() == Some(&b'[') && !gateway_core::ipv6::literal_ok(&parts.host) {
        return Err(ConfigError::Destination);
    }
    Ok(parts)
}

/// The verified decoding of a 64-digit hex digest.
fn digest(text: &str) -> Result<Vec<u8>, ConfigError> { values::digest(text.as_bytes()).ok_or(ConfigError::Identity) }

impl GatewayConfig {
    pub fn chunk_bytes(&self) -> usize { self.chunk_bytes }
    /// Configured request slots, independent of registry health.
    pub fn request_limit(&self) -> usize { self.admission.request_limit() }
    pub(crate) fn admission_healthy(&self) -> bool { self.admission.healthy() }
    #[cfg(test)]
    pub(crate) fn poison_admission_for_test(&self) { self.admission.poison_for_test(); }
    pub(crate) fn usage(&self) -> Option<(usize, usize)> { self.admission.usage().ok() }
    pub(crate) fn requires_audit(&self) -> bool { self.admission.requires_audit() }
    /// Root policy and secret resolver are operator-controlled. Candidate JSON
    /// can select only grants already in root policy. Errors never echo inputs.
    pub fn from_json(root: &[u8], candidate: &[u8], mut secret: impl FnMut(&str) -> Option<String>)
        -> Result<Self, ConfigError>
    {
        if root.len() > MAX_CONFIG || candidate.len() > MAX_CONFIG { return Err(ConfigError::Limits); }
        let root = Root::read(root)?;
        let candidate = Candidate::read(candidate)?;
        if !gateway_core::resource::validate_limits(root.limits.requests, root.limits.chunk_bytes) {
            return Err(ConfigError::Limits);
        }
        let identities = root.identities.into_iter().map(|i| Ok(Identity {
            tenant: i.tenant, digest: digest(&i.sha256)?,
        })).collect::<Result<Vec<_>, ConfigError>>()?;
        let destinations = root.destinations.into_iter().map(|s| destination(&s))
            .collect::<Result<Vec<_>, _>>()?;
        let owners = root.credentials.iter().map(|c| c.tenant).collect();
        let policy = Policy::validate(identities, root.grants, candidate.routes, destinations.len(), owners)
            .ok_or(ConfigError::Policy)?;
        let mut credentials = Vec::new();
        // The secret name, the secret's bytes, and the header value built from
        // them are checked and formed by the verified rules: the value is
        // visible ASCII with the `Bearer ` prefix, so it cannot break a header.
        for input in root.credentials {
            if !values::secret_name_ok_exec(input.env.as_bytes()) { return Err(ConfigError::Credential); }
            let raw = secret(&input.env).ok_or(ConfigError::Credential)?;
            if !values::secret_ok_exec(raw.as_bytes(), MAX_CREDENTIAL_BYTES) { return Err(ConfigError::Credential); }
            credentials.push(Credential { kind: input.kind, value: values::credential_value_exec(input.kind, raw.as_bytes()) });
        }
        Ok(Self { chunk_bytes: root.limits.chunk_bytes, admission: Admission::new(policy, root.limits.requests, root.limits.chunk_bytes,
            matches!(root.logging, Logging::Strict)), destinations, credentials })
    }

    pub fn admit(&self, token: &[u8], selector: u64) -> Result<RoutedRequest<'_>, AdmissionError> {
        if token.is_empty() || token.len() > 512 { return Err(AdmissionError::Unauthorized); }
        let digest = gateway_core::sha256::digest(token);
        let request = self.admission.admit(&digest, selector)?;
        let resolved = gateway_core::resolved_route::ResolvedRoute::resolve(
            request.authority(), &self.destinations, &self.credentials).ok_or(AdmissionError::Unavailable)?;
        Ok(RoutedRequest { request, resolved })
    }
}

impl<'a> RoutedRequest<'a> {
    pub(crate) fn copy_body<R, W, L>(&mut self, reader: &mut R, writer: &mut W, log: &mut L,
        direction: crate::transfer::Direction) -> Result<gateway_core::body_copy::BodyCopy, crate::transfer::TransferError>
    where R: std::io::Read, W: std::io::Write, L: crate::transfer::AuditLog {
        crate::transfer::copy_body_bound(&mut self.request, reader, writer, log, direction, Some(&self.resolved))
    }
    pub(crate) fn stream(&mut self) -> &mut Request<'a> { &mut self.request }
    /// The verified parts of the resolved destination.
    pub fn destination(&self) -> &Destination { self.parts() }
    fn parts(&self) -> &Destination { self.resolved.destination(self.request.authority()).expect("private request/route binding") }
    /// The permit a socket may be opened under: the verified core binds it to
    /// this request's resolved destination and route.
    pub(crate) fn egress(&self) -> gateway_core::egress::Egress<'_, Destination> {
        gateway_core::egress::Egress::provider(&self.resolved, self.request.authority()).expect("private request/route binding")
    }
    /// The configured destination string exactly as the operator wrote it.
    pub fn destination_text(&self) -> &str { ascii(&self.parts().text) }
    /// The request-start record payload, built by the verified core from the
    /// authorized selector and the resolved destination's configured text.
    pub(crate) fn start_record(&self, time_ms: u64) -> Option<Vec<u8>> {
        gateway_core::exchange_lifecycle::start_record(self.request.authority(), &self.resolved, time_ms)
    }

    // Only the trusted HTTP boundary may inject provider credentials.
    pub(crate) fn credential_header(&self) -> (&'static [u8], &[u8]) {
        let credential = self.resolved.credential(self.request.authority()).expect("private request/route binding");
        let name: &'static [u8] = match credential.kind { CredentialKind::Bearer => b"authorization", CredentialKind::ApiKey => b"x-api-key" };
        (name, &credential.value)
    }
}

#[cfg(test)]
mod tests;
