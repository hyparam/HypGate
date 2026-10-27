#![forbid(unsafe_code)]
#![deny(clippy::disallowed_methods)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::unreachable, clippy::todo,
    clippy::unimplemented, clippy::indexing_slicing, clippy::arithmetic_side_effects))]
//! Trusted runtime ownership around the verified synchronous core. Blocking
//! sockets and threads only; no executor is linked.
// Policy binding and request ownership.
pub mod admission;
pub mod budget;
pub mod config;
pub mod http_boundary;
pub mod transfer;

// External effects and their workers.
pub mod disk_log;
pub mod server;
pub mod shipping;
pub mod transport;

// Adapter implementation details and JSON construction.
mod credited_job;
mod http1;
mod http_body;
pub mod json_build;
mod net;

#[cfg(test)]
mod test_support;
