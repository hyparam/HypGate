//! Shipper state on disk: the enrollment identity, one progress checkpoint
//! per session, and one claim per session not yet fully shipped. The identity
//! and checkpoints are small JSON documents, written by the verified writer to
//! a private temporary file and renamed into place, mode 0600 on Unix. The
//! identity file holds the server's gateway credential and a fingerprint of
//! the operator token, never the token.
//!
//! A claim, `pending-<session>.json`, names a session's log and is held under
//! an exclusive file lock by the process shipping it. It is written when a
//! shipper starts on a session and removed only once that session is drained.
//! A claim whose lock is free belongs to a process that ended (the kernel
//! drops the lock with the process), so the next shipper to start adopts it
//! and drains that log before following its own. A claim whose lock is held
//! belongs to a live process and is left alone, so shippers sharing a state
//! directory never ship one session twice at once.
use gateway_core::json::{self, Value};
use crate::json_build::{self, object, write};
use std::{fs, io::{self, Seek, Write}, path::{Path, PathBuf}};

pub const IDENTITY_FILE: &str = "identity.json";
/// The single checkpoint of earlier versions, read when a session has no file of its own.
pub const LEGACY_CHECKPOINT_FILE: &str = "checkpoint.json";
const CLAIM_PREFIX: &str = "pending-";
const CLAIM_SUFFIX: &str = ".json";
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

// Effect site: the shipper's identity and checkpoint files, under the configured state directory.
#[allow(clippy::disallowed_methods)]
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    // Per process, so a live shipper and `hypgate ship` never share a temporary.
    let mut temporary = path.as_os_str().to_owned(); temporary.push(format!(".tmp.{}", std::process::id()));
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
/// The checkpoint file of one session.
pub fn checkpoint_path(dir: &Path, session: &[u8; 16]) -> PathBuf { dir.join(format!("checkpoint-{}.json", hex(session))) }
/// The session's own checkpoint, or else the legacy single checkpoint. The
/// verified `shipping_checkpoint::select` uses either only when its identity
/// names this session, server, and token.
pub fn load_checkpoint(dir: &Path, session: &[u8; 16]) -> Option<Checkpoint> {
    let value = read_bounded(&checkpoint_path(dir, session)).or_else(|| read_bounded(&dir.join(LEGACY_CHECKPOINT_FILE)))?;
    gateway_core::shipping_checkpoint::parse(&value)
}
pub fn save_checkpoint(dir: &Path, session: &[u8; 16], checkpoint: &Checkpoint) -> io::Result<()> {
    let value = gateway_core::shipping_checkpoint::value(checkpoint);
    write_private(&checkpoint_path(dir, session), &write(&value))
}

/// A held claim on one session: the open, locked claim file.
pub struct Claim { file: fs::File, path: PathBuf }
#[derive(Debug)]
pub enum ClaimError { Busy, Io(io::Error) }

fn claim_path(dir: &Path, session: &[u8; 16]) -> PathBuf { dir.join(format!("{CLAIM_PREFIX}{}{CLAIM_SUFFIX}", hex(session))) }

// Effect site: a session claim file under the configured state directory,
// created when `create` (never truncated by opening) and locked by the caller.
#[allow(clippy::disallowed_methods)]
fn open_claim(path: &Path, create: bool) -> io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create(create);
    #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
    options.open(path)
}
// Effect site: removes a drained session's claim file, the one deletion the shipper makes.
#[allow(clippy::disallowed_methods)]
fn remove_claim(path: &Path) -> io::Result<()> { fs::remove_file(path) }

fn lock(file: &fs::File) -> Result<(), ClaimError> {
    match file.try_lock() {
        Ok(()) => Ok(()),
        Err(fs::TryLockError::WouldBlock) => Err(ClaimError::Busy),
        Err(fs::TryLockError::Error(e)) => Err(ClaimError::Io(e)),
    }
}

/// Claim `session`, whose log is at `log`: lock its claim file, then record
/// the log path in it. `Busy` when another live process holds the claim.
pub fn claim(dir: &Path, session: &[u8; 16], log: &Path) -> Result<Claim, ClaimError> {
    let path = claim_path(dir, session);
    let mut file = open_claim(&path, true).map_err(ClaimError::Io)?;
    // Locked before written: a scanner that sees the contents also sees the lock.
    lock(&file)?;
    let text = log.to_str().ok_or_else(|| ClaimError::Io(io::ErrorKind::InvalidData.into()))?;
    let body = write(&object(vec![("log", json_build::text(text))]));
    let written = (|| {
        file.set_len(0)?; file.rewind()?; file.write_all(&body)?; file.sync_all()?;
        fs::File::open(dir)?.sync_all()
    })();
    written.map_err(ClaimError::Io)?;
    Ok(Claim { file, path })
}

impl Claim {
    /// The session is drained: empty the claim, so a scanner that opened it
    /// before the removal finds nothing to adopt, then remove it.
    pub fn release(self) -> io::Result<()> {
        self.file.set_len(0)?;
        self.file.sync_all()?;
        remove_claim(&self.path)
    }
}

fn session_of(name: &str) -> Option<[u8; 16]> {
    let digits = name.strip_prefix(CLAIM_PREFIX)?.strip_suffix(CLAIM_SUFFIX)?.as_bytes();
    if digits.len() != 32 { return None; }
    let mut session = [0u8; 16];
    for (byte, pair) in session.iter_mut().zip(digits.as_chunks::<2>().0) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    (hex(&session).as_bytes() == digits).then_some(session)
}

/// Claims left by processes that ended: each is returned locked, with its
/// session and log path. A claim held by a live process, or one without a
/// readable log path (being written, or released), is skipped.
pub fn abandoned(dir: &Path) -> Vec<(Claim, [u8; 16], PathBuf)> {
    let Ok(entries) = fs::read_dir(dir) else { return Vec::new(); };
    let mut found = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(session) = name.to_str().and_then(session_of) else { continue; };
        let path = dir.join(&name);
        let Ok(file) = open_claim(&path, false) else { continue; };
        if lock(&file).is_err() { continue; }
        let Some(log) = read_bounded(&path).and_then(|v| text(&v, "log")) else { continue; };
        found.push((Claim { file, path }, session, PathBuf::from(log)));
    }
    found.sort_by(|a, b| a.2.cmp(&b.2));
    found
}

#[cfg(test)]
pub(crate) fn base64url_encode(bytes: &[u8]) -> String {
    String::from_utf8(gateway_core::base64url::encode(bytes)).unwrap_or_default()
}
