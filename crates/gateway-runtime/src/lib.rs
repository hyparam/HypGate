#![forbid(unsafe_code)]
//! Trusted runtime ownership around the verified synchronous core.
pub mod admission;
pub mod budget;
pub mod config;
pub mod http_boundary;
pub mod transfer;
pub mod disk_log;
pub mod transport;
mod http_body;
mod http_io;
pub mod server;
