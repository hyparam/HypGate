//! Private binding of HTTP permits to their worker registry and payload owners.
use gateway_core::http_worker::{HttpPermit, WorkerIssuer, WorkerRegistry};
use std::{io::{self, Write}, sync::{Arc, Mutex}};

#[derive(Clone)]
pub(crate) struct WorkerHttp(Arc<Source>);
struct Source { registry: Arc<Mutex<WorkerRegistry>>, issuer: WorkerIssuer }
pub(super) struct Charge { registry: Arc<Mutex<WorkerRegistry>>, permit: HttpPermit }
impl WorkerHttp {
    pub(crate) fn new(registry: Arc<Mutex<WorkerRegistry>>, issuer: WorkerIssuer) -> Self {
        Self(Arc::new(Source { registry, issuer }))
    }
    fn issue(&self, role: usize) -> Option<Charge> {
        let permit = self.0.registry.lock().ok()?.issue(&self.0.issuer, role)?;
        Some(Charge { registry: self.0.registry.clone(), permit })
    }
    /// The request body, read from the client.
    pub(crate) fn input<B>(&self, body: B) -> Option<super::Reader<B>> {
        self.reader(body, gateway_core::http_worker::INPUT_READER)
    }
    /// The response body, read from the provider.
    pub(crate) fn output<B>(&self, body: B) -> Option<super::Reader<B>> {
        self.reader(body, gateway_core::http_worker::OUTPUT_READER)
    }
    fn reader<B>(&self, body: B, role: usize) -> Option<super::Reader<B>> {
        let charge = self.issue(role)?;
        let mut reader = super::Reader::new(body);
        reader.charge = Some(charge);
        Some(reader)
    }
    /// The writer that frames the request body onto the upstream connection;
    /// the writer comes back when the role is unavailable.
    pub(crate) fn upload_writer<W>(&self, writer: W) -> Result<Charged<W>, W> {
        match self.issue(gateway_core::http_worker::UPLOAD_CHANNEL) {
            Some(charge) => Ok(Charged { inner: Some(writer), charge: Some(charge) }),
            None => Err(writer),
        }
    }
    /// The writer that frames the response body onto the client connection.
    pub(crate) fn response_writer<W>(&self, writer: W) -> Result<Charged<W>, W> {
        match self.issue(gateway_core::http_worker::RESPONSE_WRITER) {
            Some(charge) => Ok(Charged { inner: Some(writer), charge: Some(charge) }),
            None => Err(writer),
        }
    }
}
/// A writer holding one worker HTTP role for its lifetime.
pub(crate) struct Charged<W> { inner: Option<W>, charge: Option<Charge> }
impl<W> Charged<W> {
    /// The wrapped writer; the role is released here.
    pub(crate) fn into_inner(mut self) -> W {
        if let Some(charge) = self.charge.take() { charge.finish(); }
        self.inner.take().expect("live charged writer")
    }
}
impl<W> Drop for Charged<W> {
    fn drop(&mut self) {
        drop(self.inner.take());
        if let Some(charge) = self.charge.take() { charge.finish(); }
    }
}
impl<W: Write> Write for Charged<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> { self.inner.as_mut().expect("live charged writer").write(bytes) }
    fn flush(&mut self) -> io::Result<()> { self.inner.as_mut().expect("live charged writer").flush() }
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
    use gateway_core::http_worker::{INPUT_READER, OUTPUT_READER, RESPONSE_WRITER, UPLOAD_CHANNEL};
    use std::io::Read;
    fn worker() -> (Arc<Mutex<WorkerRegistry>>, gateway_core::task_credit::TaskCredit, WorkerHttp) {
        let registry = Arc::new(Mutex::new(WorkerRegistry::new(1)));
        let (task, issuer) = registry.lock().unwrap().acquire().unwrap();
        let http = WorkerHttp::new(registry.clone(), issuer);
        (registry, task, http)
    }
    #[test]
    fn both_reader_roles_hold_their_role_until_destruction() {
        for role in [INPUT_READER, OUTPUT_READER] {
            let (registry, task, http) = worker();
            let body = &b"data"[..];
            let mut reader = if role == INPUT_READER { http.input(body) } else { http.output(body) }.unwrap();
            let mut byte = [0];
            reader.read_exact(&mut byte).unwrap();
            assert_eq!(registry.lock().unwrap().role_usage(role), 1);
            assert!(registry.lock().unwrap().release_task(task).not(), "a live role blocks release");
            let (_, task, _) = (0, registry.lock().unwrap().acquire(), 0);
            assert!(task.is_none(), "the slot is still occupied");
            drop(reader);
            assert_eq!(registry.lock().unwrap().role_usage(role), 0);
        }
    }
    trait Not { fn not(self) -> bool; }
    impl Not for bool { fn not(self) -> bool { !self } }
    #[test]
    fn writer_roles_are_issued_once_and_released_on_drop_or_into_inner() {
        let (registry, task, http) = worker();
        let upload = http.upload_writer(Vec::<u8>::new()).ok().unwrap();
        assert!(http.upload_writer(Vec::<u8>::new()).is_err(), "one upload writer per worker");
        let mut response = http.response_writer(Vec::<u8>::new()).ok().unwrap();
        assert_eq!(registry.lock().unwrap().role_usage(UPLOAD_CHANNEL), 1);
        assert_eq!(registry.lock().unwrap().role_usage(RESPONSE_WRITER), 1);
        response.write_all(b"data").unwrap();
        assert_eq!(upload.into_inner(), Vec::<u8>::new());
        assert_eq!(registry.lock().unwrap().role_usage(UPLOAD_CHANNEL), 0);
        drop(response);
        assert_eq!(registry.lock().unwrap().role_usage(RESPONSE_WRITER), 0);
        assert!(registry.lock().unwrap().release_task(task));
        assert_eq!(registry.lock().unwrap().usage(), (0, 1));
    }
}
