//! HTTP metadata boundary. Header projection is the verified
//! `gateway_core::headers`; the heads themselves come from the verified
//! `http1_head` parser as byte fields, so this module only parses the route
//! selector and bearer token with the verified `inbound` functions and binds
//! the admitted route. No networking or body processing occurs here.
use crate::admission::AdmissionError;
use crate::config::{GatewayConfig, RoutedRequest};
use gateway_core::headers::{self, Field, Rejection};
use gateway_core::http1_head::{RequestHead, StatusHead};

#[cfg(test)]
pub(crate) const MAX_HEADER_BYTES: usize = headers::MAX_BYTES;
#[cfg(test)]
pub(crate) const MAX_HEADER_VALUES: usize = headers::MAX_FIELDS;

#[derive(Debug, PartialEq, Eq)]
pub enum HttpError { BadRequest, Unauthorized, MethodNotAllowed, HeadersTooLarge, Unavailable }
impl HttpError {
    /// Close the worker for a request refused before admission. No exchange
    /// and no record exist for it anywhere, so there is no lifecycle to
    /// finish. This is the only call to `Closed::without_request` in the
    /// runtime; clippy denies it everywhere else and
    /// `scripts/check_effect_sites.sh` pins this site.
    // Escape hatch: the one worker exit without a lifecycle.
    #[allow(clippy::disallowed_methods)]
    pub(crate) fn close(self) -> gateway_core::exchange_lifecycle::Closed {
        gateway_core::exchange_lifecycle::Closed::without_request()
    }
    pub fn status(&self) -> u16 {
        match self {
            Self::BadRequest => 400,
            Self::Unauthorized => 401,
            Self::MethodNotAllowed => 405,
            Self::HeadersTooLarge => 431,
            Self::Unavailable => 503,
        }
    }
}

/// The head the transport writes upstream: the resolved destination's
/// origin-form path and the verified projection's fields.
pub struct UpstreamHead { pub path: Vec<u8>, pub fields: Vec<Field> }

/// Owns admission until the transport is finished, including response streaming.
/// No public constructor, cloning, mutable headers, or raw-request extraction.
pub struct PreparedRequest<'a> {
    routed: RoutedRequest<'a>,
    upstream: Option<UpstreamHead>,
}
impl<'a> PreparedRequest<'a> {
    pub(crate) async fn copy_body<R, W, L>(&mut self, reader: &mut R, writer: &mut W, log: &mut L,
        direction: crate::transfer::Direction) -> Result<gateway_core::body_copy::BodyCopy, crate::transfer::TransferError>
    where R: tokio::io::AsyncRead + Unpin, W: tokio::io::AsyncWrite + Unpin, L: crate::transfer::AuditLog {
        self.routed.copy_body(reader, writer, log, direction).await
    }
    /// The configured destination string exactly as the operator wrote it.
    pub fn destination_text(&self) -> &str { self.routed.destination_text() }
    pub(crate) fn egress(&self) -> gateway_core::egress::Egress<'_, gateway_core::destination::Parts> { self.routed.egress() }
    pub(crate) fn stream(&mut self) -> &mut crate::admission::Request<'a> { self.routed.stream() }
    #[cfg(test)]
    pub(crate) fn upstream_fields(&self) -> &[Field] { &self.upstream.as_ref().expect("upstream head present").fields }
    #[cfg(test)]
    pub(crate) fn upstream_path(&self) -> &[u8] { &self.upstream.as_ref().expect("upstream head present").path }

    /// Kind 2: the wall clock, the authorized route selector, and the configured
    /// text of the destination this request resolved to, built by the verified
    /// `exchange_lifecycle::start_record`. Appended before any DNS, TCP, or TLS
    /// effect.
    pub(crate) async fn audit_request_start<L: crate::transfer::AuditLog>(&mut self, log: &mut L)
        -> Result<(), crate::transfer::TransferError>
    {
        let payload = self.routed.start_record(unix_ms()).ok_or(crate::transfer::TransferError::InvalidState)?;
        self.routed.stream().audit_metadata(log, crate::transfer::RecordKind::RequestStart, &payload).await
    }
    /// Kind 3: wall clock and the upstream HTTP status, appended after the
    /// response head passed the boundary checks and before it reaches the client.
    pub(crate) async fn audit_response_head<L: crate::transfer::AuditLog>(&mut self, log: &mut L, status: u16)
        -> Result<(), crate::transfer::TransferError>
    {
        let payload = gateway_core::metadata::encode_response_head(unix_ms(), status)
            .ok_or(crate::transfer::TransferError::InvalidState)?;
        self.routed.stream().audit_metadata(log, crate::transfer::RecordKind::ResponseHead, &payload).await
    }
    /// Kind 4: the completion payload the verified lifecycle produced.
    pub(crate) async fn audit_completion<L: crate::transfer::AuditLog>(&mut self, log: &mut L, payload: &[u8])
        -> Result<(), crate::transfer::TransferError>
    {
        self.routed.stream().audit_metadata(log, crate::transfer::RecordKind::Completion, payload).await
    }
    // Validate the configured binding before any DNS/TCP/TLS effect, then move
    // the only upstream head into the transport. It can be taken once.
    pub(crate) fn take_upstream(&mut self) -> Result<UpstreamHead, HttpError> {
        let head = self.upstream.take().ok_or(HttpError::BadRequest)?;
        let destination = self.routed.destination();
        let (name, credential) = self.routed.credential_header();
        let value_of = |wanted: &[u8]| head.fields.iter().find(|f| f.name == wanted).map(|f| f.value.as_slice());
        if head.path != destination.path || value_of(name) != Some(credential)
            || value_of(b"host") != Some(destination.authority.as_slice()) {
            return Err(HttpError::BadRequest);
        }
        Ok(head)
    }
}

/// Milliseconds since the Unix epoch, clamped to `u64`; a clock before the
/// epoch records zero rather than failing the request.
pub(crate) fn unix_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)).unwrap_or(0)
}

fn rejected(rejection: Rejection) -> HttpError {
    match rejection { Rejection::TooLarge => HttpError::HeadersTooLarge, Rejection::BadRequest => HttpError::BadRequest }
}

/// The gateway token: exactly one Authorization field holding a well-formed
/// bearer, parsed by the verified `inbound::bearer`.
fn bearer(fields: &Vec<Field>) -> Result<Vec<u8>, HttpError> {
    gateway_core::inbound::bearer(fields).ok_or(HttpError::Unauthorized)
}

/// Prepare a POST request after authenticating gateway Authorization. The head
/// came from the verified parser, so its limits already hold; the body stays
/// opaque. Client credential, Host, framing and proxy headers are discarded.
pub fn prepare<'a>(config: &'a GatewayConfig, head: &RequestHead) -> Result<PreparedRequest<'a>, HttpError> {
    if head.method != b"POST" { return Err(HttpError::MethodNotAllowed); }
    let fields = &head.fields;
    if !headers::fits(fields) { return Err(HttpError::HeadersTooLarge); }
    // Origin form only, and the path itself is parsed by the verified
    // `inbound::route_selector`, which accepts exactly `/routes/<canonical decimal u64>`.
    let route = gateway_core::inbound::route_selector(&head.target).ok_or(HttpError::BadRequest)?;
    let token = bearer(fields)?;
    // Every verified header rule runs before a request slot is taken, so a
    // rejected head never consumes capacity.
    headers::check_request(fields).map_err(rejected)?;
    let routed = config.admit(&token, route).map_err(|error| match error {
        AdmissionError::Unauthorized => HttpError::Unauthorized,
        AdmissionError::AtCapacity | AdmissionError::Unavailable => HttpError::Unavailable,
    })?;
    // The verified projection: allowlisted client headers, Host from the
    // resolved destination, the resolved credential exactly once, and
    // `Accept-Encoding: identity` so the provider sends opaque bytes.
    let (name, value) = routed.credential_header();
    let outgoing = headers::forward_request(fields, &routed.destination().authority, name, value).map_err(rejected)?;
    let path = routed.destination().path.clone();
    Ok(PreparedRequest { routed, upstream: Some(UpstreamHead { path, fields: outgoing }) })
}

/// Consume an upstream status head: the status to preserve and the filtered
/// fields to forward. A 1xx never reaches here; the adapter skips them and
/// refuses 101, since this gateway has no tunnel path.
pub(crate) fn prepare_response_head(head: StatusHead) -> Result<(u16, Vec<Field>), HttpError> {
    if head.status < 200 { return Err(HttpError::BadRequest); }
    Ok((head.status, response_fields(&head.fields)?))
}

/// Preserve upstream status separately. A 3xx is returned to the client, never
/// followed by the gateway; Location and cookies are not forwarded.
pub fn response_fields(fields: &Vec<Field>) -> Result<Vec<Field>, HttpError> {
    // The verified projection also rejects a response whose Connection header
    // nominates its own Content-Encoding: dropping that header while keeping
    // the encoded bytes would change their meaning.
    headers::forward_response(fields).map_err(rejected)
}

#[cfg(test)]
mod tests;
