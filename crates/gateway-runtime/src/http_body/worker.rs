//! Private binding of HTTP permits to their worker registry and payload owners.
use gateway_core::http_worker::{HttpPermit, WorkerIssuer, WorkerRegistry};
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};

#[derive(Clone)]
pub(crate) struct WorkerHttp(Arc<Source>);
struct Source { registry: Arc<Mutex<WorkerRegistry>>, issuer: WorkerIssuer }
pub(super) struct Charge { registry: Arc<Mutex<WorkerRegistry>>, permit: HttpPermit }
// Both upload endpoints retain this charge, including receiver cleanup outside
// the mailbox mutex. A panic never reports completion while unwinding.
pub(super) struct UploadCharge { charge: Option<Charge>, failed: AtomicBool }
pub(super) struct UploadCleanup<'a>(&'a Option<Arc<UploadCharge>>);
impl<'a> UploadCleanup<'a> {
    pub(super) fn new(charge: &'a Option<Arc<UploadCharge>>) -> Self { Self(charge) }
}
impl Drop for UploadCleanup<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            if let Some(charge) = self.0 { charge.failed.store(true, Ordering::SeqCst); }
        }
    }
}
impl Drop for UploadCharge {
    fn drop(&mut self) {
        if !std::thread::panicking() && !self.failed.load(Ordering::SeqCst) {
            if let Some(charge) = self.charge.take() { charge.finish(); }
        }
    }
}
impl WorkerHttp {
    pub(crate) fn new(registry: Arc<Mutex<WorkerRegistry>>, issuer: WorkerIssuer) -> Self {
        Self(Arc::new(Source { registry, issuer }))
    }
    fn issue(&self, role: usize) -> Option<Charge> {
        let permit = self.0.registry.lock().ok()?.issue(&self.0.issuer, role)?;
        Some(Charge { registry: self.0.registry.clone(), permit })
    }
    pub(crate) fn input<B>(&self, body: B) -> Option<super::Reader<B>> {
        self.reader(body, gateway_core::http_worker::INPUT_READER)
    }
    pub(crate) fn output<B>(&self, body: B) -> Option<super::Reader<B>> {
        self.reader(body, gateway_core::http_worker::OUTPUT_READER)
    }
    fn reader<B>(&self, body: B, role: usize) -> Option<super::Reader<B>> {
        let charge = self.issue(role)?;
        let mut reader = super::Reader::new(body);
        reader.charge = Some(charge);
        Some(reader)
    }
    pub(crate) fn response_writer(&self, mut writer: super::Writer) -> Option<super::Writer> {
        writer.charge = Some(self.issue(gateway_core::http_worker::RESPONSE_WRITER)?);
        Some(writer)
    }
    pub(crate) fn upload(&self, max_frame: usize) -> Option<(super::Writer, super::ChannelBody)> {
        let charge = self.issue(gateway_core::http_worker::UPLOAD_CHANNEL)?;
        let charge = Arc::new(UploadCharge { charge: Some(charge), failed: AtomicBool::new(false) });
        let (mut writer, mut body) = super::channel(max_frame);
        writer.upload = Some(charge.clone());
        body.upload = Some(charge);
        Some((writer, body))
    }
}
impl Charge {
    // No automatic Drop: only an explicit normal-return boundary may finish.
    pub(super) fn finish(self) {
        if let Ok(mut registry) = self.registry.lock() {
            assert!(registry.finish(self.permit), "HTTP resource belongs to worker");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gateway_core::http_worker::{INPUT_READER, OUTPUT_READER, UPLOAD_CHANNEL};
    use bytes::Bytes;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use http_body_util::{Full, BodyExt};
    fn worker() -> (Arc<Mutex<WorkerRegistry>>, gateway_core::task_credit::TaskCredit, WorkerHttp) {
        let registry = Arc::new(Mutex::new(WorkerRegistry::new(1)));
        let (task, issuer) = registry.lock().unwrap().acquire().unwrap();
        let http = WorkerHttp::new(registry.clone(), issuer);
        (registry, task, http)
    }
    #[tokio::test]
    async fn both_reader_roles_retain_partial_frames_until_destruction() {
        for role in [INPUT_READER, OUTPUT_READER] {
            let (registry, task, http) = worker();
            let body = Full::new(Bytes::from_static(b"data"));
            let mut reader = if role == INPUT_READER { http.input(body) } else { http.output(body) }.unwrap();
            let mut byte = [0];
            reader.read_exact(&mut byte).await.unwrap();
            assert_eq!(reader.buffered.retained_bytes(), 4);
            assert_eq!(reader.buffered.len(), 3);
            assert_eq!(registry.lock().unwrap().role_usage(role), 1);
            drop(reader);
            assert_eq!(registry.lock().unwrap().role_usage(role), 0);
            assert!(registry.lock().unwrap().release_task(task));
            assert_eq!(registry.lock().unwrap().usage(), (0, 1));
        }
    }
    #[tokio::test]
    async fn upload_charge_survives_either_endpoint_and_covers_payload_destruction() {
        struct Payload(Arc<Mutex<WorkerRegistry>>);
        impl AsRef<[u8]> for Payload { fn as_ref(&self) -> &[u8] { b"data" } }
        impl Drop for Payload {
            fn drop(&mut self) { assert_eq!(self.0.lock().unwrap().role_usage(UPLOAD_CHANNEL), 1); }
        }
        for sender_first in [false, true] {
            let (registry, task, http) = worker();
            let (mut writer, mut body) = http.upload(4).unwrap();
            let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
            assert!(writer.sender.as_mut().unwrap().poll_send_with(&mut cx,
                || super::super::Message::Probe(Bytes::from_owner(Payload(registry.clone())))).is_ready());
            assert!(http.upload(4).is_none());
            if sender_first {
                drop(writer);
                assert_eq!(registry.lock().unwrap().role_usage(UPLOAD_CHANNEL), 1);
                drop(body.frame().await.unwrap().unwrap());
                drop(body);
            } else {
                drop(body);
                assert_eq!(registry.lock().unwrap().role_usage(UPLOAD_CHANNEL), 1);
                assert!(writer.write_all(b"late").await.is_err());
                drop(writer);
            }
            assert_eq!(registry.lock().unwrap().role_usage(UPLOAD_CHANNEL), 0);
            assert!(registry.lock().unwrap().release_task(task));
        }
    }
    #[test]
    fn upload_cleanup_panic_cannot_be_hidden_by_later_sender_destruction() {
        struct Panics;
        impl AsRef<[u8]> for Panics { fn as_ref(&self) -> &[u8] { b"data" } }
        impl Drop for Panics { fn drop(&mut self) { panic!("injected upload cleanup panic"); } }
        let (registry, task, http) = worker();
        let (mut writer, body) = http.upload(4).unwrap();
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(writer.sender.as_mut().unwrap().poll_send_with(&mut cx,
            || super::super::Message::Probe(Bytes::from_owner(Panics))).is_ready());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(body))).is_err());
        drop(writer);
        assert_eq!(registry.lock().unwrap().role_usage(UPLOAD_CHANNEL), 1);
        assert!(!registry.lock().unwrap().release_task(task));
        assert_eq!(registry.lock().unwrap().usage(), (1, 1));
    }
}
