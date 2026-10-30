//! HTTP metadata boundary. Header projection is the verified
//! `gateway_core::headers`; the heads themselves come from the verified
//! `http1_head` parser as byte fields, so this module only parses the route
//! selector and bearer token with the verified `inbound` functions and binds
//! the admitted route. No networking or body processing occurs here.
use crate::admission::AdmissionError;
use crate::config::{GatewayConfig, RoutedRequest};
use gateway_core::headers::{self, Field, Rejection};
use gateway_core::http1_exchange::{Refusal, refusal_status};
use gateway_core::http1_head::RequestHead;

#[cfg(test)]
pub(crate) const MAX_HEADER_BYTES: usize = headers::MAX_BYTES;
#[cfg(test)]
pub(crate) const MAX_HEADER_VALUES: usize = headers::MAX_FIELDS;

#[derive(Debug, PartialEq, Eq)]
pub enum HttpError { BadRequest, Unauthorized, MethodNotAllowed, HeadersTooLarge, Unavailable }
impl HttpError {
    /// The refusal the verified exchange machine answers for this error.
    pub fn refusal(&self) -> Refusal {
        match self {
            Self::BadRequest => Refusal::Malformed,
            Self::Unauthorized => Refusal::Unauthorized,
            Self::MethodNotAllowed => Refusal::MethodNotAllowed,
            Self::HeadersTooLarge => Refusal::HeadTooLarge,
            Self::Unavailable => Refusal::Unavailable,
        }
    }
    pub fn status(&self) -> u16 { refusal_status(self.refusal()) }
}

impl From<Refusal> for HttpError {
    fn from(value: Refusal) -> Self {
        match value {
            Refusal::Malformed => Self::BadRequest, Refusal::Unauthorized => Self::Unauthorized,
            Refusal::MethodNotAllowed => Self::MethodNotAllowed, Refusal::HeadTooLarge => Self::HeadersTooLarge,
            Refusal::Unavailable => Self::Unavailable,
        }
    }
}

/// The head the transport writes upstream: the resolved destination's
/// origin-form path and the verified projection's fields.
pub type UpstreamHead = gateway_core::request_context::ProviderHead;

/// Owns admission until the transport is finished, including response streaming.
/// No public constructor, cloning, mutable headers, or raw-request extraction.
pub struct PreparedRequest<'a> {
    routed: RoutedRequest<'a>,
    upstream: Option<UpstreamHead>,
}
impl<'a> PreparedRequest<'a> {
    pub(crate) fn copy_body<R, W, L>(&mut self, reader: &mut R, writer: &mut W, log: &mut L,
        direction: crate::transfer::Direction) -> Result<gateway_core::body_copy::BodyCopy, crate::transfer::TransferError>
    where R: std::io::Read, W: std::io::Write, L: crate::transfer::AuditLog {
        self.routed.copy_body(reader, writer, log, direction)
    }
    /// The configured destination string exactly as the operator wrote it.
    #[cfg(test)]
    pub fn destination_text(&self) -> &str { self.routed.destination_text() }
    pub(crate) fn egress(&self) -> Option<&gateway_core::egress::Egress<'_, gateway_core::destination::Parts>> { self.routed.egress() }
    pub(crate) fn stream(&mut self) -> &mut crate::admission::Request<'a> { self.routed.stream() }
    #[cfg(test)]
    pub(crate) fn upstream_fields(&self) -> &[Field] { self.upstream.as_ref().expect("upstream head present").fields_ref().as_slice() }

    /// Kind 2: the wall clock, the authorized route selector, and the configured
    /// text of the destination this request resolved to, built by the verified
    /// `exchange_lifecycle::start_record`. Appended before any DNS, TCP, or TLS
    /// effect.
    pub(crate) fn audit_request_start<L: crate::transfer::AuditLog>(&mut self, log: &mut L)
        -> Result<(), crate::transfer::TransferError>
    {
        let payload = self.routed.start_record(unix_ms()).ok_or(crate::transfer::TransferError::InvalidState)?;
        self.routed.stream().audit_metadata(log, crate::transfer::RecordKind::RequestStart, &payload)
    }
    /// Kind 3: wall clock and the upstream HTTP status, appended after the
    /// response head passed the boundary checks and before it reaches the client.
    pub(crate) fn audit_response_head<L: crate::transfer::AuditLog>(&mut self, log: &mut L, status: u16)
        -> Result<(), crate::transfer::TransferError>
    {
        let payload = gateway_core::metadata::encode_response_head(unix_ms(), status)
            .ok_or(crate::transfer::TransferError::InvalidState)?;
        self.routed.stream().audit_metadata(log, crate::transfer::RecordKind::ResponseHead, &payload)
    }
    /// Kind 4: the completion payload the verified lifecycle produced.
    pub(crate) fn audit_completion<L: crate::transfer::AuditLog>(&mut self, log: &mut L, payload: &[u8])
        -> Result<(), crate::transfer::TransferError>
    {
        self.routed.stream().audit_metadata(log, crate::transfer::RecordKind::Completion, payload)
    }
    // Validate the configured binding before any DNS/TCP/TLS effect, then move
    // the only upstream head into the transport. It can be taken once.
    pub(crate) fn take_upstream(&mut self) -> Result<UpstreamHead, HttpError> {
        self.upstream.take().ok_or(HttpError::BadRequest)
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

/// Prepare a POST request after authenticating gateway Authorization. The head
/// came from the verified parser, so its limits already hold; the body stays
/// opaque. Client credential, Host, framing and proxy headers are discarded.
pub fn prepare<'a>(config: &'a GatewayConfig, head: &RequestHead) -> Result<PreparedRequest<'a>, HttpError> {
    let checked = gateway_core::request_context::CheckedHead::parse(head).map_err(HttpError::from)?;
    let routed = config.admit_checked(&checked).map_err(|error| match error {
        AdmissionError::Unauthorized => HttpError::Unauthorized,
        AdmissionError::AtCapacity | AdmissionError::Unavailable => HttpError::Unavailable,
    })?;
    let upstream = routed.prepare_head(&checked).map_err(HttpError::from)?;
    Ok(PreparedRequest { routed, upstream: Some(upstream) })
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
