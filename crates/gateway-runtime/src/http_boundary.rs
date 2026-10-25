//! HTTP metadata boundary. Header projection is the verified
//! `gateway_core::headers`: this module converts Hyper's header map to byte
//! fields and back, parses the route selector and bearer token, and binds the
//! admitted route. No networking or body processing occurs here.
use crate::admission::AdmissionError;
use crate::config::{GatewayConfig, RoutedRequest};
use gateway_core::headers::{self, Field, Rejection};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, Uri};

pub(crate) const MAX_HEADER_BYTES: usize = headers::MAX_BYTES;
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
    pub fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest => StatusCode::BAD_REQUEST,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            Self::HeadersTooLarge => StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

/// Owns admission until the transport is finished, including response streaming.
/// No public constructor, cloning, mutable headers, or raw-request extraction.
pub struct PreparedRequest<'a> {
    routed: RoutedRequest<'a>,
    upstream: Request<()>,
}
impl<'a> PreparedRequest<'a> {
    pub(crate) async fn copy_body<R, W, L>(&mut self, reader: &mut R, writer: &mut W, log: &mut L,
        direction: crate::transfer::Direction) -> Result<gateway_core::body_copy::BodyCopy, crate::transfer::TransferError>
    where R: tokio::io::AsyncRead + Unpin, W: tokio::io::AsyncWrite + Unpin, L: crate::transfer::AuditLog {
        self.routed.copy_body(reader, writer, log, direction).await
    }
    pub fn destination(&self) -> &Uri { self.routed.destination() }
    pub(crate) fn egress(&self) -> gateway_core::egress::Egress<'_, crate::config::Destination> { self.routed.egress() }
    pub(crate) fn stream(&mut self) -> &mut crate::admission::Request<'a> { self.routed.stream() }

    /// Kind 2: wall clock, the authorized route selector, and the configured
    /// destination text this request was resolved to. Appended before any
    /// DNS, TCP, or TLS effect.
    pub(crate) async fn audit_request_start<L: crate::transfer::AuditLog>(&mut self, log: &mut L)
        -> Result<(), crate::transfer::TransferError>
    {
        let destination = self.routed.destination_text().as_bytes().to_vec();
        let selector = self.routed.stream().selector();
        let payload = gateway_core::metadata::encode_request_start(unix_ms(), selector, &destination)
            .ok_or(crate::transfer::TransferError::InvalidState)?;
        self.routed.stream().audit_metadata(log, crate::transfer::RecordKind::RequestStart, &payload).await
    }
    /// Kind 3: wall clock and the upstream HTTP status, appended after the
    /// response head passed the boundary checks and before it reaches the client.
    pub(crate) async fn audit_response_head<L: crate::transfer::AuditLog>(&mut self, log: &mut L, status: StatusCode)
        -> Result<(), crate::transfer::TransferError>
    {
        let payload = gateway_core::metadata::encode_response_head(unix_ms(), status.as_u16())
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
    // the only request into the direct HTTP/1 transport in origin form.
    pub(crate) fn take_upstream(&mut self) -> Result<Request<()>, HttpError> {
        let destination = self.routed.destination();
        let authority = destination.authority().ok_or(HttpError::BadRequest)?;
        let (name, credential) = self.routed.credential_header();
        if self.upstream.uri() != destination || self.upstream.method() != Method::POST
            || self.upstream.headers().get(name) != Some(credential)
            || self.upstream.headers().get("host").map(|h| h.as_bytes()) != Some(authority.as_str().as_bytes()) {
            return Err(HttpError::BadRequest);
        }
        let path = destination.path_and_query().ok_or(HttpError::BadRequest)?.clone();
        let uri = Uri::builder().path_and_query(path).build().map_err(|_| HttpError::BadRequest)?;
        let mut request = std::mem::take(&mut self.upstream);
        *request.uri_mut() = uri;
        Ok(request)
    }
}

/// Milliseconds since the Unix epoch, clamped to `u64`; a clock before the
/// epoch records zero rather than failing the request.
pub(crate) fn unix_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)).unwrap_or(0)
}

/// Hyper's header map as the verified core's byte fields, in map order,
/// names lowercase as Hyper stores them.
fn fields_of(headers: &HeaderMap) -> Vec<Field> {
    headers.iter().map(|(name, value)| Field {
        name: name.as_str().as_bytes().to_vec(), value: value.as_bytes().to_vec(), sensitive: value.is_sensitive(),
    }).collect()
}

/// The verified head as a Hyper header map. Names come from the allowlist or
/// the input map and values are copies of validated values, so conversion
/// cannot fail for a head the core produced.
fn header_map(fields: Vec<Field>) -> Result<HeaderMap, HttpError> {
    let mut out = HeaderMap::with_capacity(fields.len());
    for field in fields {
        let name = HeaderName::from_bytes(&field.name).map_err(|_| HttpError::BadRequest)?;
        let mut value = HeaderValue::from_bytes(&field.value).map_err(|_| HttpError::BadRequest)?;
        value.set_sensitive(field.sensitive);
        out.append(name, value);
    }
    Ok(out)
}

fn rejected(rejection: Rejection) -> HttpError {
    match rejection { Rejection::TooLarge => HttpError::HeadersTooLarge, Rejection::BadRequest => HttpError::BadRequest }
}

fn selector(uri: &Uri) -> Result<u64, HttpError> {
    // Origin form only: never route from a caller URL, authority, or query.
    // The path itself is parsed by the verified `inbound::route_selector`,
    // which accepts exactly `/routes/<canonical decimal u64>`.
    if uri.scheme().is_some() || uri.authority().is_some() || uri.query().is_some() {
        return Err(HttpError::BadRequest);
    }
    gateway_core::inbound::route_selector(uri.path().as_bytes()).ok_or(HttpError::BadRequest)
}

/// The gateway token: exactly one Authorization field holding a well-formed
/// bearer, parsed by the verified `inbound::bearer`.
fn bearer(fields: &Vec<Field>) -> Result<Vec<u8>, HttpError> {
    gateway_core::inbound::bearer(fields).ok_or(HttpError::Unauthorized)
}

/// Prepare a POST request after authenticating gateway Authorization. The caller
/// must enforce parser limits before allocating these headers and must keep the
/// body opaque. Client credential, Host, framing and proxy headers are discarded.
pub fn prepare<'a>(config: &'a GatewayConfig, method: &Method, uri: &Uri, headers: &HeaderMap)
    -> Result<PreparedRequest<'a>, HttpError>
{
    if method != Method::POST { return Err(HttpError::MethodNotAllowed); }
    let fields = fields_of(headers);
    if !headers::fits(&fields) { return Err(HttpError::HeadersTooLarge); }
    let route = selector(uri)?;
    let token = bearer(&fields)?;
    // Every verified header rule runs before a request slot is taken, so a
    // rejected head never consumes capacity.
    headers::check_request(&fields).map_err(rejected)?;
    let routed = config.admit(&token, route).map_err(|error| match error {
        AdmissionError::Unauthorized => HttpError::Unauthorized,
        AdmissionError::AtCapacity | AdmissionError::Unavailable => HttpError::Unavailable,
    })?;
    // The verified projection: allowlisted client headers, Host from the
    // resolved destination, the resolved credential exactly once, and
    // `Accept-Encoding: identity` so the provider sends opaque bytes.
    let (name, value) = routed.credential_header();
    let head = headers::forward_request(&fields, routed.authority().as_bytes(), name.as_bytes(), value.as_bytes()).map_err(rejected)?;
    let outgoing = header_map(head)?;
    let mut upstream = Request::new(());
    *upstream.method_mut() = Method::POST;
    *upstream.uri_mut() = routed.destination().clone();
    *upstream.headers_mut() = outgoing;
    Ok(PreparedRequest { routed, upstream })
}

/// Consume inbound metadata so its storage is gone before the worker awaits I/O.
pub(crate) fn prepare_request_parts(config: &GatewayConfig, parts: http::request::Parts)
    -> Result<PreparedRequest<'_>, HttpError>
{
    prepare(config, &parts.method, &parts.uri, &parts.headers)
}

/// Consume upstream metadata before returning detached headers for streaming.
pub(crate) fn prepare_response_parts(parts: http::response::Parts)
    -> Result<(StatusCode, HeaderMap), HttpError>
{
    // Hyper exposes 101 as an upgrade; this gateway has no tunnel path.
    if parts.status.is_informational() { return Err(HttpError::BadRequest); }
    Ok((parts.status, response_headers(&parts.headers)?))
}

/// Preserve upstream status separately. A 3xx is returned to the client, never
/// followed by the gateway; Location and cookies are not forwarded.
pub fn response_headers(headers: &HeaderMap) -> Result<HeaderMap, HttpError> {
    // The verified projection also rejects a response whose Connection header
    // nominates its own Content-Encoding: dropping that header while keeping
    // the encoded bytes would change their meaning.
    header_map(headers::forward_response(&fields_of(headers)).map_err(rejected)?)
}

#[cfg(test)]
mod tests;
