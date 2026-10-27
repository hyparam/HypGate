//! The optional `shipping` section of the root policy. Parsed on its own so the
//! gateway configuration never carries the cloud server or its token.
use crate::config::{destination, utf8, ConfigError};
use gateway_core::{config_schema, config_values as values, json};
use std::path::PathBuf;

const MAX_CONFIG: usize = 1024 * 1024;
pub use gateway_core::config_values::{MAX_EXCHANGE_BYTES, MAX_OPEN_EXCHANGES, MAX_POLL_MS, MAX_TOKEN_BYTES, MIN_EXCHANGE_BYTES, MIN_POLL_MS};

struct Section {
    s3_region: String,
    s3_access_key_env: String,
    s3_session_token_env: String,
    server: String,
    token_env: String,
    state_dir: String,
    max_open_exchanges: usize,
    max_exchange_bytes: usize,
    poll_ms: u64,
}
/// The `shipping` section of the root policy, if present and not null,
/// through the verified reader and schema.
fn section(root: &[u8]) -> Result<Option<Section>, ConfigError> {
    let value = json::parse(root).ok_or(ConfigError::Syntax)?;
    let Some(s) = config_schema::read_shipping(&value).map_err(|()| ConfigError::Syntax)? else { return Ok(None); };
    Ok(Some(Section { s3_region: utf8(s.s3_region)?, s3_access_key_env: utf8(s.s3_access_key_env)?,
        s3_session_token_env: utf8(s.s3_session_token_env)?, server: utf8(s.server)?, token_env: utf8(s.token_env)?, state_dir: utf8(s.state_dir)?,
        max_open_exchanges: s.max_open_exchanges, max_exchange_bytes: s.max_exchange_bytes, poll_ms: s.poll_ms }))
}

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
    pub(super) s3: Option<S3Config>,
}

/// AWS secrets are read once through the same resolver as other shipping credentials.
/// No Debug implementation: credentials must never enter diagnostics.
pub(super) struct S3Config {
    pub region: String,
    pub access_key: String,
    pub session_token: String,
    pub prefix: String,
}

impl ShippingConfig {
    /// `Ok(None)` when the root policy has no `shipping` section. The token is
    /// resolved through the operator's secret resolver and validated by the
    /// verified rule: 1 to 512 visible ASCII bytes.
    pub fn from_root_json(root: &[u8], mut secret: impl FnMut(&str) -> Option<String>) -> Result<Option<Self>, ConfigError> {
        if root.len() > MAX_CONFIG { return Err(ConfigError::Limits); }
        let Some(section) = section(root)? else { return Ok(None); };
        let parts = destination(&section.server)?;
        let host = String::from_utf8(parts.host).map_err(|_| ConfigError::Destination)?;
        let authority = String::from_utf8(parts.authority).map_err(|_| ConfigError::Destination)?;
        let path = String::from_utf8(parts.path).map_err(|_| ConfigError::Destination)?;
        let prefix = path.clone();
        let url = format!("https://{authority}{path}");
        let server = ShippingServer { url, authority, host, port: parts.port };
        // Limits, state directory, token name, and token bytes follow the verified rules.
        if !values::shipping_limits_ok_exec(section.max_open_exchanges, section.max_exchange_bytes, section.poll_ms) {
            return Err(ConfigError::Limits);
        }
        if !values::state_dir_ok_exec(section.state_dir.as_bytes()) { return Err(ConfigError::Limits); }
        if !values::secret_name_ok_exec(section.token_env.as_bytes()) { return Err(ConfigError::Credential); }
        let raw = secret(&section.token_env).ok_or(ConfigError::Credential)?;
        if !values::secret_ok_exec(raw.as_bytes(), MAX_TOKEN_BYTES) { return Err(ConfigError::Credential); }
        let s3 = if section.s3_region.is_empty() {
            if !section.s3_access_key_env.is_empty() || !section.s3_session_token_env.is_empty() { return Err(ConfigError::Credential); }
            None
        } else {
            if !gateway_core::s3::safe_exec(section.s3_region.as_bytes(), false)
                || !gateway_core::s3::safe_exec(prefix.as_bytes(), true) || !prefix.ends_with('/')
                || server.authority().len() > 4096 {
                return Err(ConfigError::Destination);
            }
            if !values::secret_name_ok_exec(section.s3_access_key_env.as_bytes()) { return Err(ConfigError::Credential); }
            let access_key = secret(&section.s3_access_key_env).ok_or(ConfigError::Credential)?;
            if !gateway_core::s3::safe_exec(access_key.as_bytes(), false) { return Err(ConfigError::Credential); }
            let session_token = if section.s3_session_token_env.is_empty() { String::new() } else {
                if !values::secret_name_ok_exec(section.s3_session_token_env.as_bytes()) { return Err(ConfigError::Credential); }
                let value = secret(&section.s3_session_token_env).ok_or(ConfigError::Credential)?;
                if !values::secret_ok_exec(value.as_bytes(), 16384) { return Err(ConfigError::Credential); }
                value
            };
            Some(S3Config { region: section.s3_region, access_key, session_token, prefix })
        };
        Ok(Some(Self { s3, server, state_dir: PathBuf::from(section.state_dir), max_open_exchanges: section.max_open_exchanges,
            max_exchange_bytes: section.max_exchange_bytes, poll_ms: section.poll_ms, token: raw.into_bytes() }))
    }

    /// Only the enrollment code path reads the token.
    pub(super) fn token(&self) -> &[u8] { &self.token }
}
