//! Trusted parsing and secret loading. The normalized grant relation is checked
//! by the verified core, including selection of concrete destination/credential
//! values. JSON parsing, hashing, and secret provisioning remain trusted;
//! destinations are parsed by the verified core.
use crate::admission::{Admission, AdmissionError, Request};
use gateway_core::policy::{Identity, Policy, Route};
use serde::Deserialize;
use sha2::{Digest, Sha256};

const MAX_CONFIG: usize = 1024 * 1024;
#[cfg(test)]
pub(crate) const MAX_DESTINATION_BYTES: usize = 8192;
pub(crate) const MAX_CREDENTIAL_BYTES: usize = 8192;

#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError { Syntax, Limits, Identity, Destination, Credential, Policy }

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Root {
    identities: Vec<IdentityInput>,
    destinations: Vec<String>,
    credentials: Vec<CredentialInput>,
    grants: Vec<RouteInput>,
    limits: Limits,
    logging: Logging,
    // Parsed separately by `shipping::ShippingConfig`; the gateway's own
    // configuration never holds the cloud token or server.
    #[serde(default)]
    #[allow(dead_code)]
    shipping: Option<serde::de::IgnoredAny>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityInput { tenant: u64, sha256: String }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialInput { tenant: u64, kind: CredentialKind, env: String }
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum CredentialKind { Bearer, ApiKey }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteInput { tenant: u64, selector: u64, origin: usize, credential: usize }
impl From<RouteInput> for Route {
    fn from(input: RouteInput) -> Self {
        Self { tenant: input.tenant, selector: input.selector, origin: input.origin, credential: input.credential }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Candidate { routes: Vec<RouteInput> }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Limits { requests: usize, chunk_bytes: usize }
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Logging { Strict, Availability }

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
    // A bracketed literal must also be a real IPv6 address, not just IPv6 characters.
    if parts.authority.first() == Some(&b'[')
        && std::str::from_utf8(&parts.host).ok().and_then(|h| h.parse::<std::net::Ipv6Addr>().ok()).is_none() {
        return Err(ConfigError::Destination);
    }
    Ok(parts)
}

fn digest(text: &str) -> Result<Vec<u8>, ConfigError> {
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ConfigError::Identity);
    }
    (0..64).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16)
        .map_err(|_| ConfigError::Identity)).collect()
}

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
        let root: Root = serde_json::from_slice(root).map_err(|_| ConfigError::Syntax)?;
        let candidate: Candidate = serde_json::from_slice(candidate).map_err(|_| ConfigError::Syntax)?;
        if !gateway_core::resource::validate_limits(root.limits.requests, root.limits.chunk_bytes) {
            return Err(ConfigError::Limits);
        }
        let identities = root.identities.into_iter().map(|i| Ok(Identity {
            tenant: i.tenant, digest: digest(&i.sha256)?,
        })).collect::<Result<Vec<_>, ConfigError>>()?;
        let destinations = root.destinations.into_iter().map(|s| destination(&s))
            .collect::<Result<Vec<_>, _>>()?;
        let owners = root.credentials.iter().map(|c| c.tenant).collect();
        let policy = Policy::validate(identities, root.grants.into_iter().map(Route::from).collect(),
            candidate.routes.into_iter().map(Route::from).collect(), destinations.len(), owners)
            .ok_or(ConfigError::Policy)?;
        let mut credentials = Vec::new();
        for input in root.credentials {
            if input.env.is_empty() || input.env.len() > 128
                || !input.env.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
                return Err(ConfigError::Credential);
            }
            let raw = secret(&input.env).ok_or(ConfigError::Credential)?;
            if raw.is_empty() || raw.len() > MAX_CREDENTIAL_BYTES || !raw.bytes().all(|b| (33..=126).contains(&b)) {
                return Err(ConfigError::Credential);
            }
            let text = match input.kind { CredentialKind::Bearer => format!("Bearer {raw}"), CredentialKind::ApiKey => raw };
            credentials.push(Credential { kind: input.kind, value: text.into_bytes() });
        }
        Ok(Self { chunk_bytes: root.limits.chunk_bytes, admission: Admission::new(policy, root.limits.requests, root.limits.chunk_bytes,
            matches!(root.logging, Logging::Strict)), destinations, credentials })
    }

    pub fn admit(&self, token: &[u8], selector: u64) -> Result<RoutedRequest<'_>, AdmissionError> {
        if token.is_empty() || token.len() > 512 { return Err(AdmissionError::Unauthorized); }
        let digest = Sha256::digest(token);
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
