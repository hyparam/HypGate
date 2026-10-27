//! Shipper state on disk: the enrollment identity and the progress checkpoint.
//! Both are small JSON documents, written by the verified writer to a private temporary file and
//! renamed into place, mode 0600 on Unix. The identity file holds the server's
//! gateway credential and a fingerprint of the operator token, never the token.
use gateway_core::json::{self, Value};
use crate::json_build::{self, object, write};
use std::{fs, io::{self, Write}, path::Path};

pub const IDENTITY_FILE: &str = "identity.json";
pub const CHECKPOINT_FILE: &str = "checkpoint.json";
const MAX_STATE_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub jwt: String,
    pub expires_at: u64,
    pub gateway_id: String,
    pub server: String,
    pub token_fingerprint: String,
}

pub use gateway_core::shipping_checkpoint::Checkpoint;

/// Lowercase hex from the verified encoder; every byte it returns is ASCII.
pub fn hex(bytes: &[u8]) -> String { gateway_core::shipping_identity::hex(bytes).into_iter().map(char::from).collect() }
pub fn fingerprint(token: &[u8]) -> String { hex(&gateway_core::sha256::digest(token)) }

// Effect site: the shipper's two state files, under the configured state directory.
#[allow(clippy::disallowed_methods)]
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut temporary = path.as_os_str().to_owned(); temporary.push(".tmp");
    let temporary = Path::new(&temporary);
    let _ = fs::remove_file(temporary);
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
    let mut file = options.open(temporary)?;
    file.write_all(bytes)?; file.sync_all()?;
    drop(file);
    fs::rename(temporary, path)?;
    fs::File::open(path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new(".")))?.sync_all()
}

fn read_bounded(path: &Path) -> Option<Value> {
    let metadata = fs::metadata(path).ok()?;
    if metadata.len() > MAX_STATE_BYTES { return None; }
    json::parse(&fs::read(path).ok()?)
}
fn text(value: &Value, key: &str) -> Option<String> { String::from_utf8(value.get(key.as_bytes())?.as_str()?.clone()).ok() }
fn number(value: &Value, key: &str) -> Option<u64> { value.get(key.as_bytes())?.as_u64() }

pub fn load_identity(dir: &Path) -> Option<Identity> {
    let value = read_bounded(&dir.join(IDENTITY_FILE))?;
    Some(Identity { jwt: text(&value, "jwt")?, expires_at: number(&value, "expires_at")?, gateway_id: text(&value, "gateway_id")?,
        server: text(&value, "server")?, token_fingerprint: text(&value, "token_fingerprint")? })
}
pub fn save_identity(dir: &Path, identity: &Identity) -> io::Result<()> {
    let value = object(vec![("jwt", json_build::text(&identity.jwt)), ("expires_at", json_build::number(identity.expires_at)),
        ("gateway_id", json_build::text(&identity.gateway_id)), ("server", json_build::text(&identity.server)),
        ("token_fingerprint", json_build::text(&identity.token_fingerprint))]);
    write_private(&dir.join(IDENTITY_FILE), &write(&value))
}
pub fn load_checkpoint(dir: &Path) -> Option<Checkpoint> {
    gateway_core::shipping_checkpoint::parse(&read_bounded(&dir.join(CHECKPOINT_FILE))?)
}
pub fn save_checkpoint(dir: &Path, checkpoint: &Checkpoint) -> io::Result<()> {
    let value = gateway_core::shipping_checkpoint::value(checkpoint);
    write_private(&dir.join(CHECKPOINT_FILE), &write(&value))
}

/// The `sub` and `exp` claims of a compact JWS, read without verifying the
/// signature: the shipper only needs to know which gateway it is and when to
/// renew. The server verifies the signature on every request.
pub fn jwt_claims(jwt: &str) -> Option<(String, u64)> {
    let mut parts = jwt.split('.');
    let (_, payload, _) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || payload.len() > 16 * 1024 { return None; }
    let claims = json::parse(&base64url_decode(payload)?)?;
    let sub = text(&claims, "sub")?;
    if sub.is_empty() || sub.len() > 128 { return None; }
    Some((sub, number(&claims, "exp")?))
}

/// The verified decoder: the bytes whose base64url encoding this is, or
/// nothing for a text that encodes nothing.
fn base64url_decode(text: &str) -> Option<Vec<u8>> { gateway_core::base64url::decode(text.as_bytes()) }

#[cfg(test)]
pub(crate) fn base64url_decode_for_test(text: &str) -> Option<Vec<u8>> { base64url_decode(text) }

#[cfg(test)]
pub(crate) fn base64url_encode(bytes: &[u8]) -> String {
    String::from_utf8(gateway_core::base64url::encode(bytes)).unwrap_or_default()
}
