#![forbid(unsafe_code)]
//! Synchronous verified policy and streaming operations; no network or disk I/O.
#[allow(unused_imports)]
use vstd::prelude::*;

pub mod policy;
pub mod resolved_route;
pub mod egress;
pub mod http1_head;
pub mod http1_write;
pub mod http1_framing;
pub mod http1_chunked;
pub mod http1_exchange;
pub mod http1_body;
pub mod resource;
pub mod stream;
pub mod owned_stream;
pub mod submission;
pub mod body_copy;
pub mod exchange_lifecycle;
pub mod headers;
pub mod health;
pub mod inbound;
pub mod destination;
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
pub mod shipper;
pub mod shipping_driver;
pub mod exchange_driver;
pub mod serve_driver;
pub mod json;
pub mod utf8;
pub mod projection;
pub mod config_schema;
pub mod config_values;
pub mod calendar;

#[cfg(test)]
#[path = "tests/streaming.rs"]
mod streaming_tests;
#[cfg(test)]
#[path = "tests/composition.rs"]
mod composition_tests;
#[cfg(test)]
#[path = "tests/metadata.rs"]
mod metadata_tests;
#[cfg(test)]
#[path = "tests/http1_head.rs"]
mod http1_head_tests;
#[cfg(test)]
#[path = "tests/http1_write.rs"]
mod http1_write_tests;
#[cfg(test)]
#[path = "tests/http1_framing.rs"]
mod http1_framing_tests;
#[cfg(test)]
#[path = "tests/http1_chunked.rs"]
mod http1_chunked_tests;
#[cfg(test)]
#[path = "tests/http1_exchange.rs"]
mod http1_exchange_tests;
#[cfg(test)]
#[path = "tests/http1_body.rs"]
mod http1_body_tests;
#[cfg(test)]
#[path = "tests/exchange_driver.rs"]
mod exchange_driver_tests;
#[cfg(test)]
#[path = "tests/serve_driver.rs"]
mod serve_driver_tests;
#[cfg(test)]
#[path = "tests/json.rs"]
mod json_tests;
#[cfg(test)]
#[path = "tests/utf8.rs"]
mod utf8_tests;
#[cfg(test)]
#[path = "tests/projection.rs"]
mod projection_tests;
#[cfg(test)]
#[path = "tests/config_values.rs"]
mod config_values_tests;
#[cfg(test)]
#[path = "tests/calendar.rs"]
mod calendar_tests;
