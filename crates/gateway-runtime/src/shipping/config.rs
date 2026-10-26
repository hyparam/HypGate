//! The optional `shipping` section of the root policy. Parsed on its own so the
//! gateway configuration never carries the cloud server or its token.
use crate::config::{destination, ConfigError, MAX_CREDENTIAL_BYTES};
use serde::Deserialize;
use std::path::PathBuf;

const MAX_CONFIG: usize = 1024 * 1024;
pub const MIN_EXCHANGE_BYTES: usize = 4096;
pub const MAX_EXCHANGE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_OPEN_EXCHANGES: usize = 65_536;
pub const MIN_POLL_MS: u64 = 100;
pub const MAX_POLL_MS: u64 = 60_000;

#[derive(Deserialize)]
struct Root { #[serde(default)] shipping: Option<Section> }

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Section {
    server: String,
    token_env: String,
    state_dir: String,
    #[serde(default = "default_open")] max_open_exchanges: usize,
    #[serde(default = "default_bytes")] max_exchange_bytes: usize,
    #[serde(default = "default_poll")] poll_ms: u64,
}
fn default_open() -> usize { 64 }
fn default_bytes() -> usize { 1024 * 1024 }
fn default_poll() -> u64 { 1000 }

/// The configured HypAware server. Only `ShippingConfig::from_root_json`
/// makes one, so a cloud egress permit exists only when the root policy has a
/// `shipping` section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShippingServer { url: String, authority: String, host: String, port: u16 }
impl ShippingServer {
    /// The server as `https://authority/path`, the name the identity file records.
    pub fn url(&self) -> &str { &self.url }
    /// The authority exactly as configured, for the Host header.
    pub fn authority(&self) -> &str { &self.authority }
    /// The host for name resolution and TLS, from the verified destination parts.
    pub fn host(&self) -> &str { &self.host }
    pub fn port(&self) -> u16 { self.port }
}

/// Everything the shipper thread receives. No handle to the gateway's own
/// configuration, admission, logger, or routes.
pub struct ShippingConfig {
    pub server: ShippingServer,
    pub state_dir: PathBuf,
    pub max_open_exchanges: usize,
    pub max_exchange_bytes: usize,
    pub poll_ms: u64,
    token: Vec<u8>,
}

impl ShippingConfig {
    /// `Ok(None)` when the root policy has no `shipping` section. The token is
    /// resolved through the operator's secret resolver and validated like a
    /// provider credential: 1 to 512 visible ASCII bytes.
    pub fn from_root_json(root: &[u8], mut secret: impl FnMut(&str) -> Option<String>) -> Result<Option<Self>, ConfigError> {
        if root.len() > MAX_CONFIG { return Err(ConfigError::Limits); }
        let root: Root = serde_json::from_slice(root).map_err(|_| ConfigError::Syntax)?;
        let Some(section) = root.shipping else { return Ok(None); };
        let parts = destination(&section.server)?;
        let host = String::from_utf8(parts.host).map_err(|_| ConfigError::Destination)?;
        let authority = String::from_utf8(parts.authority).map_err(|_| ConfigError::Destination)?;
        let path = String::from_utf8(parts.path).map_err(|_| ConfigError::Destination)?;
        let url = format!("https://{authority}{path}");
        let server = ShippingServer { url, authority, host, port: parts.port };
        if section.max_open_exchanges == 0 || section.max_open_exchanges > MAX_OPEN_EXCHANGES
            || section.max_exchange_bytes < MIN_EXCHANGE_BYTES || section.max_exchange_bytes > MAX_EXCHANGE_BYTES
            || section.poll_ms < MIN_POLL_MS || section.poll_ms > MAX_POLL_MS {
            return Err(ConfigError::Limits);
        }
        if section.state_dir.is_empty() || section.state_dir.len() > 4096 { return Err(ConfigError::Limits); }
        if section.token_env.is_empty() || section.token_env.len() > 128
            || !section.token_env.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Err(ConfigError::Credential);
        }
        let raw = secret(&section.token_env).ok_or(ConfigError::Credential)?;
        if raw.is_empty() || raw.len() > 512.min(MAX_CREDENTIAL_BYTES) || !raw.bytes().all(|b| (33..=126).contains(&b)) {
            return Err(ConfigError::Credential);
        }
        Ok(Some(Self { server, state_dir: PathBuf::from(section.state_dir), max_open_exchanges: section.max_open_exchanges,
            max_exchange_bytes: section.max_exchange_bytes, poll_ms: section.poll_ms, token: raw.into_bytes() }))
    }

    /// Only the enrollment code path reads the token.
    pub(super) fn token(&self) -> &[u8] { &self.token }
}
