#![forbid(unsafe_code)]
//! Synchronous verified policy and streaming operations; no network or disk I/O.
#[allow(unused_imports)]
use vstd::prelude::*;

pub mod resource;
pub mod stream;
pub mod policy;
pub mod journal;
pub mod framing;

pub mod recovery;
pub mod audit_journal;

pub mod owned_stream;

pub mod buffer_accounting;

pub mod owned_accounting;
pub mod mailbox;
pub mod fixed_queue;
pub mod frame_queue;

#[cfg(test)]
#[path = "tests/streaming.rs"]
mod streaming_tests;
#[cfg(test)]
#[path = "tests/composition.rs"]
mod composition_tests;
