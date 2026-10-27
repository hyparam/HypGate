//! The optional `shipping` section of the root policy. Parsed on its own so the
//! gateway configuration never carries the cloud server or its token.
use crate::config::{destination, utf8, ConfigError};
use gateway_core::{config_schema, config_values as values, json};
use std::path::PathBuf;

const MAX_CONFIG: usize = 1024 * 1024;
pub use gateway_core::config_values::{MAX_EXCHANGE_BYTES, MAX_OPEN_EXCHANGES, MAX_POLL_MS, MAX_TOKEN_BYTES, MIN_EXCHANGE_BYTES, MIN_POLL_MS};

fn section(root: &[u8]) -> Result<Option<config_schema::Shipping>, ConfigError> {
    let value = json::parse(root).ok_or(ConfigError::Syntax)?;
    config_schema::read_shipping(&value).map_err(|()| ConfigError::Syntax)
}

/// The sole credential effect: return the requested variable without selecting or interpreting it.
struct Resolver<'a, F>(&'a mut F);
impl<F: FnMut(&str) -> Option<String>> gateway_core::s3_config::Secrets for Resolver<'_, F> {
    fn read(&mut self, name: &[u8]) -> Option<Vec<u8>> {
        (self.0)(std::str::from_utf8(name).ok()?).map(String::into_bytes)
    }
}

/// The configured shipping endpoint. Only `ShippingConfig::from_root_json`
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
    pub(super) s3: Option<gateway_core::s3_config::Config>,
}

impl ShippingConfig {
    /// `Ok(None)` when the root policy has no `shipping` section. The token is
    /// resolved through the operator's secret resolver and validated by the
    /// verified rule: 1 to 512 visible ASCII bytes.
    pub fn from_root_json(root: &[u8], mut secret: impl FnMut(&str) -> Option<String>) -> Result<Option<Self>, ConfigError> {
        if root.len() > MAX_CONFIG { return Err(ConfigError::Limits); }
        let Some(section) = section(root)? else { return Ok(None); };
        let parts = destination(&utf8(section.server.clone())?)?;
        if !values::shipping_limits_ok_exec(section.max_open_exchanges, section.max_exchange_bytes, section.poll_ms) {
            return Err(ConfigError::Limits);
        }
        if !values::state_dir_ok_exec(&section.state_dir) { return Err(ConfigError::Limits); }
        let backend = gateway_core::s3_config::load(&section, &parts, &mut Resolver(&mut secret)).map_err(|error| match error {
            gateway_core::s3_config::Error::Destination => ConfigError::Destination,
            gateway_core::s3_config::Error::Credential => ConfigError::Credential,
        })?;
        let (token, s3) = match backend {
            gateway_core::s3_config::Backend::HypAware(token) => (token, None),
            gateway_core::s3_config::Backend::S3(config) => (Vec::new(), Some(config)),
        };
        let host = utf8(parts.host)?;
        let authority = utf8(parts.authority)?;
        let path = utf8(parts.path)?;
        let server = ShippingServer { url: format!("https://{authority}{path}"), authority, host, port: parts.port };
        Ok(Some(Self { s3, server, state_dir: PathBuf::from(utf8(section.state_dir)?), max_open_exchanges: section.max_open_exchanges,
            max_exchange_bytes: section.max_exchange_bytes, poll_ms: section.poll_ms, token }))
    }

    /// HypAware enrollment token; empty for S3, whose credentials belong to its verified configuration.
    pub(super) fn token(&self) -> &[u8] { &self.token }
}
