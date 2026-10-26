#![forbid(unsafe_code)]
#![deny(clippy::disallowed_methods)]
//! Trusted runtime ownership around the verified synchronous core. Blocking
//! sockets and threads only; no executor is linked.
pub mod admission;
pub mod budget;
pub mod config;
pub mod http_boundary;
mod http1;
mod net;
pub mod transfer;
pub mod disk_log;
pub mod transport;
mod http_body;
mod credited_job;
#[cfg(test)]
mod test_support;
pub mod server;
pub mod shipping;
