//! Minimal projection of one exchange into HypAware `ai_gateway_messages` rows:
//! one user part with the request text, one assistant part with the response
//! text and token usage. Provider bodies are parsed best effort for Anthropic
//! Messages and OpenAI Responses; anything else ships as raw text. Headers and
//! raw frames are never included. Provider bodies are read by the verified
//! JSON reader; the projection itself is trusted, tested code.
use gateway_core::exchange_assembler::Exchange;
use gateway_core::json::{self, Value as Json};
use gateway_core::shipping_identity::{exchange_key, message_key, part_key};
use serde_json::{json, Map, Value};
use super::state::hex;

pub const SCHEMA_VERSION: u32 = 7;
const MAX_SESSION_HINT: usize = 256;

#[derive(Default, Debug, PartialEq, Eq, Clone)]
pub struct Usage { pub input: u64, pub cache_read: u64, pub cache_write: u64, pub output: u64 }
impl Usage {
    fn json(&self) -> Value {
        json!({"input_tokens": self.input, "cache_read_tokens": self.cache_read, "cache_write_tokens": self.cache_write,
            "output_tokens": self.output,
            "total_tokens": self.input.saturating_add(self.cache_read).saturating_add(self.cache_write).saturating_add(self.output)})
    }
}

#[derive(Default, Debug)]
struct ParsedRequest { model: Option<String>, session_hint: Option<String>, user_text: Option<String> }
#[derive(Default, Debug)]
struct ParsedResponse { text: String, usage: Option<Usage>, model: Option<String> }

pub fn provider(host: &str) -> &str {
    match host { "api.anthropic.com" => "anthropic", "api.openai.com" => "openai", other => other }
}

fn destination_parts(exchange: &Exchange) -> (String, String) {
    // The record holds the configured destination text, which the verified
    // parser accepted at startup; its host and path are that parser's.
    let text = exchange.start.as_ref().map(|s| s.destination.as_slice()).unwrap_or(b"");
    match gateway_core::destination::parse(text) {
        Some(parts) => (String::from_utf8_lossy(&parts.host).into_owned(), String::from_utf8_lossy(&parts.path).into_owned()),
        None => (String::new(), String::new()),
    }
}

/// A string's bytes as text; provider strings are UTF-8 but the reader
/// passes raw bytes through, so this is lossy by design.
fn str_of(value: &Json) -> Option<String> { value.as_str().map(|b| String::from_utf8_lossy(b).into_owned()) }
/// The value at a key path.
fn at<'a>(value: &'a Json, path: &[&str]) -> Option<&'a Json> { path.iter().try_fold(value, |v, key| v.get(key.as_bytes())) }

fn text_of_content(content: &Json) -> Option<String> {
    match content {
        Json::Str(s) => Some(String::from_utf8_lossy(s).into_owned()),
        Json::Array(blocks) => {
            let parts: Vec<String> = blocks.iter().filter_map(|b| {
                let kind = at(b, &["type"]).and_then(str_of).unwrap_or_else(|| "text".to_owned());
                if matches!(kind.as_str(), "text" | "input_text" | "output_text") { at(b, &["text"]).and_then(str_of) } else { None }
            }).collect();
            if parts.is_empty() { None } else { Some(parts.join("\n")) }
        }
        _ => None,
    }
}

fn parse_request(bytes: &[u8]) -> ParsedRequest {
    let Some(value) = json::parse(bytes) else { return ParsedRequest::default(); };
    let model = at(&value, &["model"]).and_then(str_of);
    let hint = at(&value, &["metadata", "user_id"]).or_else(|| at(&value, &["user"])).and_then(str_of)
        .filter(|s| !s.is_empty() && s.len() <= MAX_SESSION_HINT);
    let messages = at(&value, &["messages"]).or_else(|| at(&value, &["input"]));
    let user_text = match messages {
        Some(Json::Str(s)) => Some(String::from_utf8_lossy(s).into_owned()),
        Some(Json::Array(items)) => items.iter().rev()
            .find(|m| at(m, &["role"]).and_then(str_of).as_deref() == Some("user"))
            .and_then(|m| at(m, &["content"])).and_then(text_of_content),
        _ => None,
    };
    ParsedRequest { model, session_hint: hint, user_text }
}

fn usage_of(value: &Json) -> Option<Usage> {
    let usage = at(value, &["usage"])?;
    let n = |paths: &[&[&str]]| paths.iter().find_map(|path| at(usage, path).and_then(Json::as_u64)).unwrap_or(0);
    let cache_read = n(&[&["cache_read_input_tokens"], &["input_tokens_details", "cached_tokens"], &["prompt_tokens_details", "cached_tokens"]]);
    let total_input = n(&[&["input_tokens"], &["prompt_tokens"]]);
    let output = n(&[&["output_tokens"], &["completion_tokens"]]);
    // Anthropic reports input net of cache; OpenAI reports cached tokens inside input.
    let input = if at(usage, &["cache_read_input_tokens"]).is_some() || at(usage, &["cache_creation_input_tokens"]).is_some() { total_input }
        else { total_input.saturating_sub(cache_read) };
    Some(Usage { input, cache_read, cache_write: n(&[&["cache_creation_input_tokens"]]), output })
}

fn parse_json_response(value: &Json) -> ParsedResponse {
    let mut out = ParsedResponse { model: at(value, &["model"]).and_then(str_of), ..Default::default() };
    if let Some(content) = at(value, &["content"]) { out.text = text_of_content(content).unwrap_or_default(); }
    else if let Some(Json::Array(items)) = at(value, &["output"]) {
        out.text = items.iter().filter_map(|i| at(i, &["content"]).and_then(text_of_content)).collect::<Vec<_>>().join("\n");
    } else if let Some(Json::Array(choices)) = at(value, &["choices"]) {
        out.text = choices.iter().filter_map(|c| at(c, &["message", "content"]).and_then(text_of_content)).collect::<Vec<_>>().join("\n");
    }
    out.usage = usage_of(value);
    out
}

pub fn is_sse(bytes: &[u8]) -> bool {
    let trimmed = bytes.iter().position(|b| !b.is_ascii_whitespace()).and_then(|i| bytes.get(i..)).unwrap_or(b"");
    trimmed.starts_with(b"event:") || trimmed.starts_with(b"data:") || trimmed.starts_with(b":")
}

fn parse_sse(bytes: &[u8]) -> ParsedResponse {
    let mut out = ParsedResponse::default();
    let mut usage = Usage::default(); let mut saw_usage = false;
    for line in bytes.split(|b| *b == b'\n') {
        let Some(data) = line.strip_prefix(b"data:") else { continue; };
        let Some(event) = json::parse(data) else { continue; };
        match at(&event, &["type"]).and_then(str_of).unwrap_or_default().as_str() {
            "message_start" => if let Some(message) = at(&event, &["message"]) {
                out.model = at(message, &["model"]).and_then(str_of);
                if let Some(u) = usage_of(message) { usage.input = u.input; usage.cache_read = u.cache_read; usage.cache_write = u.cache_write; saw_usage = true; }
            },
            "content_block_delta" => if let Some(text) = at(&event, &["delta", "text"]).and_then(str_of) { out.text.push_str(&text); },
            "message_delta" => if let Some(n) = at(&event, &["usage", "output_tokens"]).and_then(Json::as_u64) { usage.output = n; saw_usage = true; },
            "response.output_text.delta" => if let Some(text) = at(&event, &["delta"]).and_then(str_of) { out.text.push_str(&text); },
            "response.completed" => if let Some(response) = at(&event, &["response"]) {
                out.model = at(response, &["model"]).and_then(str_of);
                if let Some(u) = usage_of(response) { usage = u; saw_usage = true; }
            },
            _ => {
                // Chat-completions style chunks carry text in choices[].delta.content.
                if let Some(Json::Array(choices)) = at(&event, &["choices"]) {
                    for c in choices { if let Some(t) = at(c, &["delta", "content"]).and_then(str_of) { out.text.push_str(&t); } }
                }
                if let Some(u) = usage_of(&event) { usage = u; saw_usage = true; }
            }
        }
    }
    if saw_usage { out.usage = Some(usage); }
    out
}

fn parse_response(bytes: &[u8]) -> (ParsedResponse, bool) {
    if is_sse(bytes) { return (parse_sse(bytes), true); }
    match json::parse(bytes) {
        Some(value) => (parse_json_response(&value), false),
        None => (ParsedResponse::default(), false),
    }
}

fn truncated_utf8(bytes: &[u8], limit: usize) -> String { cap(String::from_utf8_lossy(bytes).into_owned(), limit) }
fn cap(text: String, limit: usize) -> String {
    if text.len() <= limit { return text; }
    let mut end = limit; while !text.is_char_boundary(end) { end = end.saturating_sub(1); }
    text.get(..end).unwrap_or("").to_owned()
}

/// Civil date and RFC 3339 timestamp from Unix milliseconds (proleptic Gregorian, UTC).
// Bounded arithmetic: ms fits u64, so days is below 2^38 and every
// intermediate fits i64 with room to spare; the algorithm is Howard Hinnant's.
#[allow(clippy::arithmetic_side_effects)]
pub fn civil(ms: u64) -> (i64, u32, u32, u32, u32, u32, u32) {
    let seconds = (ms / 1000) as i64; let millis = (ms % 1000) as u32;
    let days = seconds.div_euclid(86_400); let rem = seconds.rem_euclid(86_400);
    let z = days + 719_468; let era = z.div_euclid(146_097); let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32; let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day, (rem / 3600) as u32, ((rem % 3600) / 60) as u32, (rem % 60) as u32, millis)
}
pub fn iso_date(ms: u64) -> String { let (y, m, d, ..) = civil(ms); format!("{y:04}-{m:02}-{d:02}") }
pub fn iso_timestamp(ms: u64) -> String {
    let (y, mo, d, h, mi, s, ms) = civil(ms); format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{ms:03}Z")
}

/// Two rows per exchange. `max_text` caps each `content_text`.
pub fn rows(session: &[u8; 16], exchange: &Exchange, max_text: usize) -> Vec<Value> {
    let (host, path) = destination_parts(exchange);
    let request = parse_request(&exchange.upload);
    let (response, sse) = parse_response(&exchange.download);
    let exchange_id = hex(&exchange_key(session, exchange.request));
    let started = exchange.start.as_ref().map(|s| s.time_ms)
        .or(exchange.head.as_ref().map(|h| h.time_ms)).or(exchange.completion.as_ref().map(|c| c.time_ms)).unwrap_or(0);
    let finished = exchange.completion.as_ref().map(|c| c.time_ms).or(exchange.head.as_ref().map(|h| h.time_ms)).unwrap_or(started);
    let status = exchange.head.as_ref().map(|h| h.status);
    let outcome = exchange.completion.as_ref().map(|c| c.outcome);
    let session_id = request.session_hint.clone().unwrap_or_else(|| exchange_id.clone());
    let model = request.model.clone().or(response.model.clone());
    let is_error = status.is_some_and(|s| s >= 400) || outcome.is_some_and(|o| o != 0) || exchange.incomplete;
    let gateway = json!({
        "exchange_id": exchange_id, "upstream": host, "method": "POST", "path": path,
        "status_code": status, "outcome": outcome.map(outcome_name), "outcome_code": outcome,
        "request_bytes": exchange.upload_total, "response_bytes": exchange.download_total,
        "truncated": exchange.truncated, "incomplete": exchange.incomplete, "orphan": exchange.orphan,
        "is_sse": sse, "tenant": exchange.tenant.to_string(),
    });
    let base = |index: u32| -> Map<String, Value> {
        let mut row = Map::new();
        row.insert("schema_version".into(), json!(SCHEMA_VERSION));
        row.insert("session_id".into(), json!(session_id));
        row.insert("conversation_id".into(), json!(session_id));
        row.insert("user_id".into(), json!(exchange.tenant.to_string()));
        row.insert("provider".into(), json!(provider(&host)));
        row.insert("model".into(), json!(model));
        row.insert("conversation_started_at".into(), json!(iso_timestamp(started)));
        row.insert("conversation_source".into(), json!("loggate"));
        row.insert("client_name".into(), json!("loggate"));
        row.insert("message_id".into(), json!(hex(&message_key(session, exchange.request, index))));
        row.insert("message_index".into(), json!(index));
        row.insert("part_id".into(), json!(hex(&part_key(session, exchange.request, index, 0))));
        row.insert("part_index".into(), json!(0));
        row.insert("part_type".into(), json!("text"));
        row.insert("date".into(), json!(iso_date(started)));
        row.insert("request_id".into(), json!(exchange_id));
        row.insert("is_error".into(), json!(is_error));
        row.insert("status".into(), json!({"code": status, "outcome": outcome}));
        row
    };
    let mut user = base(0);
    user.insert("role".into(), json!("user"));
    user.insert("message_created_at".into(), json!(iso_timestamp(started)));
    user.insert("content_text".into(), json!(match request.user_text {
        Some(text) => cap(text, max_text), None => truncated_utf8(&exchange.upload, max_text) }));
    user.insert("attributes".into(), json!({"gateway": gateway}));
    let mut assistant = base(1);
    assistant.insert("role".into(), json!("assistant"));
    assistant.insert("message_created_at".into(), json!(iso_timestamp(finished)));
    assistant.insert("previous_message_id".into(), json!([hex(&message_key(session, exchange.request, 0))]));
    // Nothing recognizable parsed: ship the raw response text instead of nothing.
    let unparsed = response.text.is_empty() && response.usage.is_none() && !exchange.download.is_empty();
    assistant.insert("content_text".into(), json!(if unparsed { truncated_utf8(&exchange.download, max_text) } else { cap(response.text, max_text) }));
    let mut attributes = Map::new();
    attributes.insert("gateway".into(), gateway);
    if let Some(usage) = response.usage { attributes.insert("usage".into(), usage.json()); }
    assistant.insert("attributes".into(), Value::Object(attributes));
    vec![Value::Object(user), Value::Object(assistant)]
}

pub fn outcome_name(code: u8) -> &'static str {
    match code {
        0 => "success", 1 => "upstream_failure", 2 => "upstream_timeout", 3 => "upload_failure",
        4 => "download_failure", 5 => "client_disconnect", 6 => "log_refusal", _ => "other",
    }
}
