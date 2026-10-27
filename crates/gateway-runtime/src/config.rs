//! Configuration loading. The JSON is read by the verified `gateway_core::json`
//! reader, its shape (which keys, once each, which kinds) by the verified
//! `gateway_core::config_schema`, and the normalized grant relation is checked
//! by the verified core, including selection of concrete destination/credential
//! values; destinations are parsed by the verified core and a bracketed host
//! checked by the verified IPv6 grammar; digests, secret names and values,
//! and the credential header value follow the verified rules in
//! `gateway_core::config_values` (each stricter than UTF-8, so the root
//! policy's strings need no separate UTF-8 check; the shipping section's get
//! one);
//! and the assembly of all of it, each list in file order with credential
//! `i` formed from the secret fetched under entry `i`'s name, is the verified
//! `gateway_core::config_build`. Reading an environment variable and the
//! hash function's strength remain trusted.
use crate::admission::{Admission, AdmissionError, Request};
use gateway_core::config_build as build;
use gateway_core::config_schema as schema;
use gateway_core::json;

const MAX_CONFIG: usize = 1024 * 1024;
#[cfg(test)]
pub(crate) const MAX_DESTINATION_BYTES: usize = 8192;
#[cfg(test)]
pub(crate) use gateway_core::config_values::MAX_CREDENTIAL_BYTES;

#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError { Syntax, Limits, Identity, Destination, Credential, Policy }

/// Text from the verified schema reader: the configuration's strings must be
/// UTF-8, decided by the verified check; the conversion then cannot fail.
pub(crate) fn utf8(bytes: Vec<u8>) -> Result<String, ConfigError> {
    if !gateway_core::utf8::is_valid(&bytes) { return Err(ConfigError::Syntax); }
    String::from_utf8(bytes).map_err(|_| ConfigError::Syntax)
}

/// The root policy through the verified reader and schema. `shipping` is
/// read separately by `shipping::ShippingConfig`; the gateway's own
/// configuration never holds the cloud token or server.
fn read_root(bytes: &[u8]) -> Result<schema::Root, ConfigError> {
    let value = json::parse(bytes).ok_or(ConfigError::Syntax)?;
    schema::read_root(&value).ok_or(ConfigError::Syntax)
}
pub(crate) use schema::Logging;

/// The environment as the verified assembly's secret store. Names reach it
/// only after the verified name rule, so they are ASCII.
struct Env<F>(F);
impl<F: FnMut(&str) -> Option<String>> build::Secrets for Env<F> {
    fn get(&mut self, name: &[u8]) -> Option<Vec<u8>> {
        let name = std::str::from_utf8(name).ok()?;
        (self.0)(name).map(String::into_bytes)
    }
}

// The verified assembly's credential: no Debug implementation, so neither
// errors nor diagnostics can format a loaded value.
type Credential = build::Credential;

// A destination is the verified `gateway_core::destination::Parts`: the text the
// operator wrote and the authority, host, port, and path proved to be its
// substrings. The resolved route hands the core these parts directly, so the
// request-start record and the Host header are built from them by proof.
pub(crate) type Destination = gateway_core::destination::Parts;

pub struct GatewayConfig {
    chunk_bytes: usize,
    durability: gateway_core::audit_receipt::Durability,
    admission: Admission,
    destinations: Vec<Destination>,
    credentials: Vec<Credential>,
}

/// The route and credential references come from the same immutable configuration
/// that admitted the owned request. No caller-supplied URI or secret override.
pub struct RoutedRequest<'a> {
    request: Request<'a>,
    resolved: gateway_core::resolved_route::ResolvedRoute<'a, Destination, Credential>,
    // Read once from `resolved` for this request's authority at admission.
    destination: &'a Destination,
    credential: &'a Credential,
    egress: gateway_core::egress::Egress<'a, Destination>,
}

/// The verified parts are visible ASCII, so this never fails for a destination
/// `parse` accepted.
#[cfg(test)]
fn ascii(bytes: &[u8]) -> &str { std::str::from_utf8(bytes).expect("verified destination part is ASCII") }

/// Validate a destination with the verified parser and, for a bracketed
/// host, the verified IPv6 grammar. The parts are what the runtime connects
/// to, names in TLS, writes as Host, and uses as the request target.
pub(crate) fn destination(text: &str) -> Result<Destination, ConfigError> {
    build::destination_exec(text.as_bytes()).ok_or(ConfigError::Destination)
}

impl GatewayConfig {
    pub fn durability(&self) -> gateway_core::audit_receipt::Durability { self.durability }
    pub fn chunk_bytes(&self) -> usize { self.chunk_bytes }
    /// Configured request slots, independent of registry health.
    pub fn request_limit(&self) -> usize { self.admission.request_limit() }
    pub(crate) fn admission_healthy(&self) -> bool { self.admission.healthy() }
    #[cfg(test)]
    pub(crate) fn poison_admission_for_test(&self) { self.admission.poison_for_test(); }
    pub(crate) fn usage(&self) -> Option<(usize, usize)> { self.admission.usage().ok() }
    pub(crate) fn requires_audit(&self) -> bool { self.admission.requires_audit() }
    /// Configuration and secret resolver are operator-controlled. Every configured
    /// grant is active. Errors never echo inputs.
    pub fn from_json(root: &[u8], secret: impl FnMut(&str) -> Option<String>)
        -> Result<Self, ConfigError>
    {
        if root.len() > MAX_CONFIG { return Err(ConfigError::Limits); }
        let root = read_root(root)?;
        // Select every configured grant for the existing verified policy builder.
        let candidate = schema::Candidate { routes: root.grants.iter().map(|route|
            gateway_core::policy::Route { tenant: route.tenant, selector: route.selector,
                origin: route.origin, credential: route.credential }).collect() };
        // The verified assembly: identity, destination, and credential `i`
        // come from entry `i`, with the secret fetched under that entry's
        // name and formed into the header value by the verified rules.
        let built = build::build(root, candidate, &mut Env(secret)).map_err(|e| match e {
            build::BuildError::Limits => ConfigError::Limits,
            build::BuildError::Identity => ConfigError::Identity,
            build::BuildError::Destination => ConfigError::Destination,
            build::BuildError::Credential => ConfigError::Credential,
            build::BuildError::Policy => ConfigError::Policy,
        })?;
        Ok(Self { chunk_bytes: built.limits.chunk_bytes, durability: built.durability,
            admission: Admission::with_durability(built.policy, built.limits.requests, built.limits.chunk_bytes, matches!(built.logging, Logging::Strict), built.durability),
            destinations: built.destinations, credentials: built.credentials })
    }

    pub fn admit(&self, token: &[u8], selector: u64) -> Result<RoutedRequest<'_>, AdmissionError> {
        if token.is_empty() || token.len() > 512 { return Err(AdmissionError::Unauthorized); }
        let digest = gateway_core::sha256::digest(token);
        let request = self.admission.admit(&digest, selector)?;
        let resolved = gateway_core::resolved_route::ResolvedRoute::resolve(
            request.authority(), &self.destinations, &self.credentials).ok_or(AdmissionError::Unavailable)?;
        // Bound here, from the route just resolved for this authority, so the
        // accessors below are plain field reads.
        let (Some(destination), Some(credential), Some(egress)) = (
            resolved.destination(request.authority()),
            resolved.credential(request.authority()),
            gateway_core::egress::Egress::provider(&resolved, request.authority()),
        ) else { return Err(AdmissionError::Unavailable) };
        Ok(RoutedRequest { request, resolved, destination, credential, egress })
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
    pub fn destination(&self) -> &Destination { self.destination }
    /// The permit a socket may be opened under: the verified core bound it to
    /// this request's resolved destination and route at admission.
    pub(crate) fn egress(&self) -> &gateway_core::egress::Egress<'a, Destination> { &self.egress }
    /// The configured destination string exactly as the operator wrote it.
    #[cfg(test)]
    pub fn destination_text(&self) -> &str { ascii(&self.destination.text) }
    /// The request-start record payload, built by the verified core from the
    /// authorized selector and the resolved destination's configured text.
    pub(crate) fn start_record(&self, time_ms: u64) -> Option<Vec<u8>> {
        gateway_core::exchange_lifecycle::start_record(self.request.authority(), &self.resolved, time_ms)
    }

    // Only the trusted HTTP boundary may inject provider credentials. The
    // header name and value are the verified assembly's for this credential.
    pub(crate) fn credential_header(&self) -> (&[u8], &[u8]) {
        (&self.credential.name, &self.credential.value)
    }
}

#[cfg(test)]
mod tests;
