//! Minimal projection of one exchange into HypAware `ai_gateway_messages` rows:
//! one user part with the request text, one assistant part with the response
//! text and token usage. Provider bodies are parsed best effort for Anthropic
//! Messages and OpenAI Responses; anything else ships as raw text. Headers and
//! raw frames are never included. This is trusted, tested code.
use gateway_core::exchange_assembler::Exchange;
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
    let text = exchange.start.as_ref().and_then(|s| std::str::from_utf8(&s.destination).ok()).unwrap_or("");
    match text.parse::<http::Uri>() {
        Ok(uri) => (uri.host().unwrap_or("").to_owned(), uri.path().to_owned()),
        Err(_) => (String::new(), String::new()),
    }
}

fn text_of_content(content: &Value) -> Option<String> {
    match content {
        Value::String(s) => Some(s.clone()),
        Value::Array(blocks) => {
            let parts: Vec<&str> = blocks.iter().filter_map(|b| {
                let kind = b.get("type").and_then(Value::as_str).unwrap_or("text");
                if matches!(kind, "text" | "input_text" | "output_text") { b.get("text").and_then(Value::as_str) } else { None }
            }).collect();
            if parts.is_empty() { None } else { Some(parts.join("\n")) }
        }
        _ => None,
    }
}

fn parse_request(bytes: &[u8]) -> ParsedRequest {
    let Ok(value) = serde_json::from_slice::<Value>(bytes) else { return ParsedRequest::default(); };
    let model = value.get("model").and_then(Value::as_str).map(str::to_owned);
    let hint = value.pointer("/metadata/user_id").or_else(|| value.get("user")).and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= MAX_SESSION_HINT).map(str::to_owned);
    let messages = value.get("messages").or_else(|| value.get("input"));
    let user_text = match messages {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Array(items)) => items.iter().rev()
            .find(|m| m.get("role").and_then(Value::as_str) == Some("user"))
            .and_then(|m| m.get("content")).and_then(text_of_content),
        _ => None,
    };
    ParsedRequest { model, session_hint: hint, user_text }
}

fn usage_of(value: &Value) -> Option<Usage> {
    let usage = value.get("usage")?;
    let n = |keys: &[&str]| keys.iter().find_map(|k| usage.pointer(&format!("/{}", k.replace('.', "/"))).and_then(Value::as_u64)).unwrap_or(0);
    let cache_read = n(&["cache_read_input_tokens", "input_tokens_details.cached_tokens", "prompt_tokens_details.cached_tokens"]);
    let total_input = n(&["input_tokens", "prompt_tokens"]);
    let output = n(&["output_tokens", "completion_tokens"]);
    // Anthropic reports input net of cache; OpenAI reports cached tokens inside input.
    let input = if usage.get("cache_read_input_tokens").is_some() || usage.get("cache_creation_input_tokens").is_some() { total_input }
        else { total_input.saturating_sub(cache_read) };
    Some(Usage { input, cache_read, cache_write: n(&["cache_creation_input_tokens"]), output })
}

fn parse_json_response(value: &Value) -> ParsedResponse {
    let mut out = ParsedResponse { model: value.get("model").and_then(Value::as_str).map(str::to_owned), ..Default::default() };
    if let Some(content) = value.get("content") { out.text = text_of_content(content).unwrap_or_default(); }
    else if let Some(Value::Array(items)) = value.get("output") {
        out.text = items.iter().filter_map(|i| i.get("content").and_then(text_of_content)).collect::<Vec<_>>().join("\n");
    } else if let Some(Value::Array(choices)) = value.get("choices") {
        out.text = choices.iter().filter_map(|c| c.pointer("/message/content").and_then(text_of_content)).collect::<Vec<_>>().join("\n");
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
        let Ok(event) = serde_json::from_slice::<Value>(data) else { continue; };
        match event.get("type").and_then(Value::as_str).unwrap_or("") {
            "message_start" => if let Some(message) = event.get("message") {
                out.model = message.get("model").and_then(Value::as_str).map(str::to_owned);
                if let Some(u) = usage_of(message) { usage.input = u.input; usage.cache_read = u.cache_read; usage.cache_write = u.cache_write; saw_usage = true; }
            },
            "content_block_delta" => if let Some(text) = event.pointer("/delta/text").and_then(Value::as_str) { out.text.push_str(text); },
            "message_delta" => if let Some(n) = event.pointer("/usage/output_tokens").and_then(Value::as_u64) { usage.output = n; saw_usage = true; },
            "response.output_text.delta" => if let Some(text) = event.get("delta").and_then(Value::as_str) { out.text.push_str(text); },
            "response.completed" => if let Some(response) = event.get("response") {
                out.model = response.get("model").and_then(Value::as_str).map(str::to_owned);
                if let Some(u) = usage_of(response) { usage = u; saw_usage = true; }
            },
            _ => {
                // Chat-completions style chunks carry text in choices[].delta.content.
                if let Some(Value::Array(choices)) = event.get("choices") {
                    for c in choices { if let Some(t) = c.pointer("/delta/content").and_then(Value::as_str) { out.text.push_str(t); } }
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
    match serde_json::from_slice::<Value>(bytes) {
        Ok(value) => (parse_json_response(&value), false),
        Err(_) => (ParsedResponse::default(), false),
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
        row.insert("conversation_source".into(), json!("soundgate"));
        row.insert("client_name".into(), json!("soundgate"));
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
