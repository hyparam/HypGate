//! Trusted parsing and secret loading. The normalized grant relation is checked
//! by the verified core; JSON, URI parsing, hashing, and mappings are not proved.
use crate::admission::{Admission, AdmissionError, Request};
use gateway_core::policy::{Identity, Policy, Route};
use http::{HeaderValue, Uri};
use serde::Deserialize;
use sha2::{Digest, Sha256};

const MAX_CONFIG: usize = 1024 * 1024;

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
impl RouteInput {
    fn core(self) -> Route {
        Route { tenant: self.tenant, selector: self.selector, origin: self.origin, credential: self.credential }
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
struct Credential { kind: CredentialKind, value: HeaderValue }

pub struct GatewayConfig {
    admission: Admission,
    destinations: Vec<Uri>,
    credentials: Vec<Credential>,
}

/// The route and credential references come from the same immutable configuration
/// that admitted the owned request. No caller-supplied URI or secret override.
pub struct RoutedRequest<'a> {
    request: Request<'a>,
    destination: &'a Uri,
    credential: &'a Credential,
}

fn destination(text: &str) -> Result<Uri, ConfigError> {
    // Keep spelling strict rather than rely on permissive URL normalization.
    if !text.starts_with("https://") || !text.is_ascii()
        || text.bytes().any(|b| b <= 32 || b == 127 || b == b'\\' || b == b'#') {
        return Err(ConfigError::Destination);
    }
    let uri: Uri = text.parse().map_err(|_| ConfigError::Destination)?;
    let authority = uri.authority().ok_or(ConfigError::Destination)?;
    let host = uri.host().ok_or(ConfigError::Destination)?;
    if authority.as_str().contains('@') || authority.as_str().contains('%')
        || host.is_empty() || uri.query().is_some() || uri.path().starts_with("//")
         {
        return Err(ConfigError::Destination);
    }
    let suffix = &authority.as_str()[host.len()..];
    if !suffix.is_empty() && !suffix.strip_prefix(':').is_some_and(|port|
        !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit())
            && port.parse::<u16>().is_ok_and(|n| n != 0)) {
        return Err(ConfigError::Destination);
    }
    // Restrict to conventional ASCII DNS names or bracketed IPv6 addresses.
    if host.starts_with('[') {
        host.strip_prefix('[').and_then(|s| s.strip_suffix(']'))
            .and_then(|s| s.parse::<std::net::Ipv6Addr>().ok()).ok_or(ConfigError::Destination)?;
    } else if host.len() > 253 || host.split('.').any(|label| label.is_empty()
        || label.len() > 63 || label.starts_with('-') || label.ends_with('-')
        || !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')) {
        return Err(ConfigError::Destination);
    }
    Ok(uri)
}

fn digest(text: &str) -> Result<Vec<u8>, ConfigError> {
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ConfigError::Identity);
    }
    (0..64).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16)
        .map_err(|_| ConfigError::Identity)).collect()
}

impl GatewayConfig {
    pub(crate) fn requires_audit(&self) -> bool { self.admission.requires_audit() }
    /// Root policy and secret resolver are operator-controlled. Candidate JSON
    /// can select only grants already in root policy. Errors never echo inputs.
    pub fn from_json(root: &[u8], candidate: &[u8], mut secret: impl FnMut(&str) -> Option<String>)
        -> Result<Self, ConfigError>
    {
        if root.len() > MAX_CONFIG || candidate.len() > MAX_CONFIG { return Err(ConfigError::Limits); }
        let root: Root = serde_json::from_slice(root).map_err(|_| ConfigError::Syntax)?;
        let candidate: Candidate = serde_json::from_slice(candidate).map_err(|_| ConfigError::Syntax)?;
        if root.limits.requests == 0 || root.limits.requests > 65536
            || root.limits.chunk_bytes == 0 || root.limits.chunk_bytes > 1024 * 1024
            || root.limits.requests.checked_mul(root.limits.chunk_bytes)
                .is_none_or(|n| n > 128 * 1024 * 1024) {
            return Err(ConfigError::Limits);
        }
        let identities = root.identities.into_iter().map(|i| Ok(Identity {
            tenant: i.tenant, digest: digest(&i.sha256)?,
        })).collect::<Result<Vec<_>, ConfigError>>()?;
        let destinations = root.destinations.iter().map(|s| destination(s))
            .collect::<Result<Vec<_>, _>>()?;
        let owners = root.credentials.iter().map(|c| c.tenant).collect();
        let policy = Policy::validate(identities, root.grants.into_iter().map(RouteInput::core).collect(),
            candidate.routes.into_iter().map(RouteInput::core).collect(), destinations.len(), owners)
            .ok_or(ConfigError::Policy)?;
        let mut credentials = Vec::new();
        for input in root.credentials {
            if input.env.is_empty() || input.env.len() > 128
                || !input.env.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
                return Err(ConfigError::Credential);
            }
            let raw = secret(&input.env).ok_or(ConfigError::Credential)?;
            if raw.is_empty() || raw.len() > 8192 || !raw.bytes().all(|b| (33..=126).contains(&b)) {
                return Err(ConfigError::Credential);
            }
            let text = match input.kind { CredentialKind::Bearer => format!("Bearer {raw}"), CredentialKind::ApiKey => raw };
            let mut value = HeaderValue::from_str(&text).map_err(|_| ConfigError::Credential)?;
            value.set_sensitive(true);
            credentials.push(Credential { kind: input.kind, value });
        }
        Ok(Self { admission: Admission::new(policy, root.limits.requests, root.limits.chunk_bytes,
            matches!(root.logging, Logging::Strict)), destinations, credentials })
    }

    pub fn admit(&self, token: &[u8], selector: u64) -> Result<RoutedRequest<'_>, AdmissionError> {
        if token.is_empty() || token.len() > 512 { return Err(AdmissionError::Unauthorized); }
        let digest = Sha256::digest(token);
        let request = self.admission.admit(&digest, selector)?;
        let destination = &self.destinations[request.origin()];
        let credential = &self.credentials[request.credential()];
        Ok(RoutedRequest { request, destination, credential })
    }
}

impl<'a> RoutedRequest<'a> {
    pub(crate) fn stream(&mut self) -> &mut Request<'a> { &mut self.request }
    pub fn request_id(&self) -> u64 { self.request.request_id() }
    pub fn tenant_id(&self) -> u64 { self.request.tenant_id() }
    pub fn destination(&self) -> &Uri { self.destination }

    // Only the trusted HTTP boundary may inject provider credentials.
    pub(crate) fn credential_header(&self) -> (&'static str, &HeaderValue) {
        let name = match self.credential.kind { CredentialKind::Bearer => "authorization", CredentialKind::ApiKey => "x-api-key" };
        (name, &self.credential.value)
    }
}

#[cfg(test)]
mod tests;
