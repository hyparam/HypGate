//! Fixtures shared by the integration tests; each test binary compiles its own copy.
#![allow(dead_code)]
use std::{fs, path::PathBuf, process::Child};

/// Kills and reaps the child process on drop.
pub struct Process(pub Child);
impl Drop for Process { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }

/// A fresh directory, removed on drop. `SOUNDGATE_STORAGE_TEST_DIR` relocates it
/// onto the private storage fixture.
pub struct TempDir(pub PathBuf);
impl TempDir {
    pub fn new(prefix: &str) -> Self {
        let mut nonce = [0; 16]; getrandom::fill(&mut nonce).unwrap();
        let name: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
        let root = std::env::var_os("SOUNDGATE_STORAGE_TEST_DIR")
            .map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
        let path = root.join(format!("{prefix}-{name}"));
        fs::create_dir(&path).unwrap(); Self(path)
    }
}
impl Drop for TempDir { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }
