//! Shipper state on disk: the enrollment identity and the progress checkpoint.
//! Both are small JSON documents written to a private temporary file and
//! renamed into place, mode 0600 on Unix. The identity file holds the server's
//! gateway credential and a fingerprint of the operator token, never the token.
use gateway_core::json::{self, Value};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{fs, io::{self, Write}, path::Path};

pub const IDENTITY_FILE: &str = "identity.json";
pub const CHECKPOINT_FILE: &str = "checkpoint.json";
const MAX_STATE_BYTES: u64 = 64 * 1024;

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub jwt: String,
    pub expires_at: u64,
    pub gateway_id: String,
    pub server: String,
    pub token_fingerprint: String,
}

/// Progress is a count of emitted exchanges resolved on the server, plus the
/// assembler limits that make exchange numbering reproducible from the file.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub session: String,
    pub resolved: u64,
    pub poisoned: u64,
    pub max_open_exchanges: usize,
    pub max_exchange_bytes: usize,
}

/// Lowercase hex from the verified encoder; every byte it returns is ASCII.
pub fn hex(bytes: &[u8]) -> String { gateway_core::shipping_identity::hex(bytes).into_iter().map(char::from).collect() }
pub fn fingerprint(token: &[u8]) -> String { hex(&Sha256::digest(token)) }

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
    write_private(&dir.join(IDENTITY_FILE), &serde_json::to_vec(identity)?)
}
pub fn load_checkpoint(dir: &Path) -> Option<Checkpoint> {
    let value = read_bounded(&dir.join(CHECKPOINT_FILE))?;
    Some(Checkpoint { session: text(&value, "session")?, resolved: number(&value, "resolved")?, poisoned: number(&value, "poisoned")?,
        max_open_exchanges: usize::try_from(number(&value, "max_open_exchanges")?).ok()?,
        max_exchange_bytes: usize::try_from(number(&value, "max_exchange_bytes")?).ok()? })
}
pub fn save_checkpoint(dir: &Path, checkpoint: &Checkpoint) -> io::Result<()> {
    write_private(&dir.join(CHECKPOINT_FILE), &serde_json::to_vec(checkpoint)?)
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

fn base64url_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len().saturating_mul(3) / 4);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte.wrapping_sub(b'A'),
            b'a'..=b'z' => byte.wrapping_sub(b'a').wrapping_add(26),
            b'0'..=b'9' => byte.wrapping_sub(b'0').wrapping_add(52),
            b'-' => 62, b'_' => 63, b'=' => continue, _ => return None,
        } as u32;
        buffer = (buffer << 6) | value; bits = bits.wrapping_add(6);
        if bits >= 8 { bits = bits.wrapping_sub(8); out.push((buffer >> bits) as u8); buffer &= (1u32 << bits).wrapping_sub(1); }
    }
    Some(out)
}

#[cfg(test)]
pub(crate) fn base64url_decode_for_test(text: &str) -> Option<Vec<u8>> { base64url_decode(text) }

pub fn base64url_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let mut word = 0u32;
        for (b, shift) in chunk.iter().zip([16u32, 8, 0]) { word |= (*b as u32) << shift; }
        for shift in [18u32, 12, 6, 0].into_iter().take(chunk.len().saturating_add(1)) {
            out.push(TABLE.get(((word >> shift) & 63) as usize).copied().unwrap_or(b'A') as char);
        }
    }
    out
}
