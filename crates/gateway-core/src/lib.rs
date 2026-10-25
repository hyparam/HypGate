#![forbid(unsafe_code)]
//! Synchronous verified policy and streaming operations; no network or disk I/O.
#[allow(unused_imports)]
use vstd::prelude::*;

pub mod policy;
pub mod resolved_route;
pub mod resource;
pub mod stream;
pub mod owned_stream;
pub mod submission;
pub mod journal;
pub mod journal_binding;
pub mod audit_journal;
pub mod framing;
pub mod metadata;
pub mod recovery;
pub mod fixed_queue;
pub mod frame_queue;
pub mod disk_worker;
pub mod drain;
pub mod task_credit;
pub mod mailbox;
pub mod read_buffer;
pub mod output_frame;
pub mod http_message;
pub mod http_connection;
pub mod http_worker;
pub mod http_accounting;
pub mod lifecycle_composition;
pub mod buffer_accounting;
pub mod owned_accounting;
pub mod exchange_assembler;
pub mod shipping_identity;
pub mod batch_builder;
pub mod upload_cursor;
pub mod enrollment;

#[cfg(test)]
#[path = "tests/streaming.rs"]
mod streaming_tests;
#[cfg(test)]
#[path = "tests/composition.rs"]
mod composition_tests;
#[cfg(test)]
#[path = "tests/metadata.rs"]
mod metadata_tests;
