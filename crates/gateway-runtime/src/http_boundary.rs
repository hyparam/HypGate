//! Trusted HTTP metadata boundary. No networking or body processing occurs here.
use crate::admission::AdmissionError;
use crate::config::{GatewayConfig, RoutedRequest};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, Uri};

const MAX_HEADER_BYTES: usize = 32 * 1024;
const MAX_HEADER_VALUES: usize = 100;
const FORWARDED_REQUEST_HEADERS: &[&str] = &[
    "content-type", "accept", "anthropic-version", "anthropic-beta", "openai-beta",
];
const FORWARDED_RESPONSE_HEADERS: &[&str] = &[
    "content-type", "content-encoding", "cache-control", "retry-after", "request-id", "x-request-id",
];

#[derive(Debug, PartialEq, Eq)]
pub enum HttpError { BadRequest, Unauthorized, MethodNotAllowed, HeadersTooLarge, Unavailable }
impl HttpError {
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
    pub(crate) routed: RoutedRequest<'a>,
    pub(crate) upstream: Request<()>,
}
impl PreparedRequest<'_> {
    pub fn request_id(&self) -> u64 { self.routed.request_id() }
    pub fn tenant_id(&self) -> u64 { self.routed.tenant_id() }
    pub fn destination(&self) -> &Uri { self.upstream.uri() }
}

fn check_size(headers: &HeaderMap) -> Result<(), HttpError> {
    let mut size = 0usize;
    if headers.len() > MAX_HEADER_VALUES { return Err(HttpError::HeadersTooLarge); }
    for (name, value) in headers {
        size = size.checked_add(name.as_str().len() + value.as_bytes().len())
            .ok_or(HttpError::HeadersTooLarge)?;
        if size > MAX_HEADER_BYTES { return Err(HttpError::HeadersTooLarge); }
    }
    Ok(())
}

fn connection_options(headers: &HeaderMap, relevant: &[&str]) -> Result<Vec<HeaderName>, HttpError> {
    let mut options = Vec::new();
    for value in headers.get_all("connection") {
        let value = value.to_str().map_err(|_| HttpError::BadRequest)?;
        for part in value.split(',') {
            let part = part.trim_matches([' ', '\t']);
            if part.is_empty() { return Err(HttpError::BadRequest); }
            let name = HeaderName::from_bytes(part.as_bytes()).map_err(|_| HttpError::BadRequest)?;
            // Validate every token, but retain only distinct names that can
            // affect this forwarding allowlist (at most five/six entries).
            if relevant.iter().any(|candidate| name == *candidate) && !options.contains(&name) {
                options.push(name);
            }
        }
    }
    Ok(options)
}

fn filtered(headers: &HeaderMap, allowed: &[&'static str]) -> Result<HeaderMap, HttpError> {
    check_size(headers)?;
    let hop = connection_options(headers, allowed)?;
    let mut out = HeaderMap::new();
    for &name in allowed {
        if hop.iter().any(|h| h == name) { continue; }
        for value in headers.get_all(name) {
            // A small HeaderValue can share a much larger parser allocation.
            // Detach only its validated visible bytes, retaining redaction intent.
            let mut copied = HeaderValue::from_bytes(value.as_bytes()).map_err(|_| HttpError::BadRequest)?;
            copied.set_sensitive(value.is_sensitive());
            out.append(HeaderName::from_static(name), copied);
        }
    }
    Ok(out)
}

fn selector(uri: &Uri) -> Result<u64, HttpError> {
    // Accept only origin-form /routes/<decimal>. Never route from a caller URL,
    // authority, query, percent escape, or path suffix.
    if uri.scheme().is_some() || uri.authority().is_some() || uri.query().is_some() {
        return Err(HttpError::BadRequest);
    }
    let id = uri.path().strip_prefix("/routes/").ok_or(HttpError::BadRequest)?;
    if id.is_empty() || id.len() > 20 || !id.bytes().all(|b| b.is_ascii_digit())
        || (id.len() > 1 && id.starts_with('0')) {
        return Err(HttpError::BadRequest);
    }
    id.parse().map_err(|_| HttpError::BadRequest)
}

fn bearer(headers: &HeaderMap) -> Result<&[u8], HttpError> {
    let mut values = headers.get_all("authorization").iter();
    let value = values.next().ok_or(HttpError::Unauthorized)?.as_bytes();
    if values.next().is_some() { return Err(HttpError::Unauthorized); }
    let separator = value.iter().position(|b| *b == b' ').ok_or(HttpError::Unauthorized)?;
    let (scheme, rest) = value.split_at(separator);
    let token = &rest[1..];
    if !scheme.eq_ignore_ascii_case(b"bearer") || token.is_empty() || token.len() > 512
        || !token.iter().all(|b| b.is_ascii_alphanumeric() || b"-._~+/=".contains(b)) {
        return Err(HttpError::Unauthorized);
    }
    Ok(token)
}

/// Prepare a POST request after authenticating gateway Authorization. The caller
/// must enforce parser limits before allocating these headers and must keep the
/// body opaque. Client credential, Host, framing and proxy headers are discarded.
pub fn prepare<'a>(config: &'a GatewayConfig, method: &Method, uri: &Uri, headers: &HeaderMap)
    -> Result<PreparedRequest<'a>, HttpError>
{
    if method != Method::POST { return Err(HttpError::MethodNotAllowed); }
    check_size(headers)?;
    let route = selector(uri)?;
    let token = bearer(headers)?;
    // Validate every header rule before allocating a request slot.
    let mut outgoing = filtered(headers, FORWARDED_REQUEST_HEADERS)?;
    // Compression is deliberately unsupported on uploads; dropping its header
    // while forwarding compressed bytes would change the request's meaning.
    if headers.contains_key("content-encoding") || headers.contains_key("upgrade")
        || headers.contains_key("trailer") { return Err(HttpError::BadRequest); }
    for name in ["content-type", "anthropic-version"] {
        if headers.get_all(name).iter().count() > 1 { return Err(HttpError::BadRequest); }
    }
    let routed = config.admit(token, route).map_err(|error| match error {
        AdmissionError::Unauthorized => HttpError::Unauthorized,
        AdmissionError::AtCapacity | AdmissionError::Unavailable => HttpError::Unavailable,
    })?;
    let authority = routed.destination().authority().ok_or(HttpError::BadRequest)?;
    outgoing.insert("host", HeaderValue::from_str(authority.as_str()).map_err(|_| HttpError::BadRequest)?);
    let (name, value) = routed.credential_header();
    outgoing.insert(HeaderName::from_static(name), value.clone());
    // Ask for opaque, uncompressed response bytes. Transport must not silently
    // decode a provider that ignores this preference.
    outgoing.insert("accept-encoding", HeaderValue::from_static("identity"));
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
    check_size(headers)?;
    // Removing a nominated encoding while preserving encoded bytes changes
    // their meaning. Reject that upstream response instead.
    if connection_options(headers, FORWARDED_RESPONSE_HEADERS)?.iter().any(|h| h == "content-encoding") {
        return Err(HttpError::BadRequest);
    }
    filtered(headers, FORWARDED_RESPONSE_HEADERS)
}

#[cfg(test)]
mod tests;
