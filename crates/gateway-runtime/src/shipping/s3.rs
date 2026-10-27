//! S3 effects only. Backend choice, credentials, dates, headers, replies and checkpoints are core decisions.
use super::{Engine, now_ms, state};
use gateway_core::{s3_delivery::{Put, Response, Transport}, s3_driver::Store, shipping_checkpoint::Checkpoint};

impl Transport for Engine {
    fn milliseconds(&mut self) -> u64 { now_ms() }
    fn put(&mut self, request: Put) -> Response {
        let failed = Response { status: 0, retry_after: None };
        let Some(client) = self.client.as_ref() else { return failed; };
        match client.put(request) {
            Ok(reply) => Response { status: reply.status, retry_after: reply.retry_after },
            Err(_) => failed,
        }
    }
}
impl Store for Engine {
    fn load(&mut self) -> Option<Checkpoint> { state::load_checkpoint(&self.config.state_dir) }
    fn save(&mut self, value: Checkpoint) -> bool { state::save_checkpoint(&self.config.state_dir, &value).is_ok() }
}
