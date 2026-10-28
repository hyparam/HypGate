//! The projection of one exchange into HypAware `ai_gateway_messages` rows:
//! one user part with the request text, one assistant part with the response
//! text and token usage. Provider bodies are read by the verified JSON
//! reader best effort for Anthropic Messages and OpenAI Responses and chat
//! completions, as JSON or as SSE; anything else ships as raw text. Headers
//! and raw frames are never included.
//!
//! What is proved: `rows` returns exactly two objects with fixed key lists
//! (`user_keys`, `assistant_keys`); every row is well formed for the writer
//! and every string in it is well-formed UTF-8; each `content_text` is at
//! most `max_text` bytes and cut only at a character boundary; the message
//! and part ids are the hex of the verified keys and the request id is the
//! hex of the exchange key; the schema version and message indexes are
//! fixed; the timestamps are the verified calendar's text of the exchange's
//! start and completion times. Response error interpretation is composed from
//! the JSON/SSE grammars through every event into both rows (response_semantics).
//! Provider text/token field selection remains pinned by tests. SSE framing is
//! proved in `sse`; usage objects are distinguished from missing/null usage,
//! and unknown chat-chunk usage preserves the previous accounting state.
use vstd::prelude::*;
use vstd::slice::{slice_index_get, slice_subrange, slice_to_vec};
use crate::exchange_assembler::Exchange;
use crate::json::{Member, Value};
use crate::response_semantics as semantics;
use crate::shipping_identity::{exchange_key, message_key, part_key, hex};

verus! {

pub const SCHEMA_VERSION: u64 = 7;
pub const MAX_SESSION_HINT: usize = 256;
const LF: u8 = 10;

// ---- names ------------------------------------------------------------------------------

pub const K_SCHEMA_VERSION: [u8; 14] = *b"schema_version";
pub const K_SESSION_ID: [u8; 10] = *b"session_id";
pub const K_CONVERSATION_ID: [u8; 15] = *b"conversation_id";
pub const K_USER_ID: [u8; 7] = *b"user_id";
pub const K_PROVIDER: [u8; 8] = *b"provider";
pub const K_MODEL: [u8; 5] = *b"model";
pub const K_CONVERSATION_STARTED_AT: [u8; 23] = *b"conversation_started_at";
pub const K_CONVERSATION_SOURCE: [u8; 19] = *b"conversation_source";
pub const K_CLIENT_NAME: [u8; 11] = *b"client_name";
pub const K_MESSAGE_ID: [u8; 10] = *b"message_id";
pub const K_MESSAGE_INDEX: [u8; 13] = *b"message_index";
pub const K_PART_ID: [u8; 7] = *b"part_id";
pub const K_PART_INDEX: [u8; 10] = *b"part_index";
pub const K_PART_TYPE: [u8; 9] = *b"part_type";
pub const K_DATE: [u8; 4] = *b"date";
pub const K_REQUEST_ID: [u8; 10] = *b"request_id";
pub const K_IS_ERROR: [u8; 8] = *b"is_error";
pub const K_STATUS: [u8; 6] = *b"status";
pub const K_CODE: [u8; 4] = *b"code";
pub const K_OUTCOME: [u8; 7] = *b"outcome";
pub const K_ROLE: [u8; 4] = *b"role";
pub const K_MESSAGE_CREATED_AT: [u8; 18] = *b"message_created_at";
pub const K_CONTENT_TEXT: [u8; 12] = *b"content_text";
pub const K_ATTRIBUTES: [u8; 10] = *b"attributes";
pub const K_PREVIOUS_MESSAGE_ID: [u8; 19] = *b"previous_message_id";
pub const K_GATEWAY: [u8; 7] = *b"gateway";
pub const K_USAGE: [u8; 5] = *b"usage";
pub const K_EXCHANGE_ID: [u8; 11] = *b"exchange_id";
pub const K_UPSTREAM: [u8; 8] = *b"upstream";
pub const K_METHOD: [u8; 6] = *b"method";
pub const K_PATH: [u8; 4] = *b"path";
pub const K_STATUS_CODE: [u8; 11] = *b"status_code";
pub const K_OUTCOME_CODE: [u8; 12] = *b"outcome_code";
pub const K_REQUEST_BYTES: [u8; 13] = *b"request_bytes";
pub const K_RESPONSE_BYTES: [u8; 14] = *b"response_bytes";
pub const K_TRUNCATED: [u8; 9] = *b"truncated";
pub const K_INCOMPLETE: [u8; 10] = *b"incomplete";
pub const K_ORPHAN: [u8; 6] = *b"orphan";
pub const K_IS_SSE: [u8; 6] = *b"is_sse";
pub const K_TENANT: [u8; 6] = *b"tenant";
pub const K_INPUT_TOKENS: [u8; 12] = *b"input_tokens";
pub const K_CACHE_READ_TOKENS: [u8; 17] = *b"cache_read_tokens";
pub const K_CACHE_WRITE_TOKENS: [u8; 18] = *b"cache_write_tokens";
pub const K_OUTPUT_TOKENS: [u8; 13] = *b"output_tokens";
pub const K_TOTAL_TOKENS: [u8; 12] = *b"total_tokens";
pub const P_MODEL: [u8; 5] = *b"model";
pub const P_METADATA: [u8; 8] = *b"metadata";
pub const P_USER_ID: [u8; 7] = *b"user_id";
pub const P_USER: [u8; 4] = *b"user";
pub const P_MESSAGES: [u8; 8] = *b"messages";
pub const P_INPUT: [u8; 5] = *b"input";
pub const P_ROLE: [u8; 4] = *b"role";
pub const P_CONTENT: [u8; 7] = *b"content";
pub const P_TYPE: [u8; 4] = *b"type";
pub const P_TEXT: [u8; 4] = *b"text";
pub const P_INPUT_TEXT: [u8; 10] = *b"input_text";
pub const P_OUTPUT_TEXT: [u8; 11] = *b"output_text";
pub const P_USAGE: [u8; 5] = *b"usage";
pub const P_CACHE_READ_INPUT_TOKENS: [u8; 23] = *b"cache_read_input_tokens";
pub const P_INPUT_TOKENS_DETAILS: [u8; 20] = *b"input_tokens_details";
pub const P_CACHED_TOKENS: [u8; 13] = *b"cached_tokens";
pub const P_PROMPT_TOKENS_DETAILS: [u8; 21] = *b"prompt_tokens_details";
pub const P_INPUT_TOKENS: [u8; 12] = *b"input_tokens";
pub const P_PROMPT_TOKENS: [u8; 13] = *b"prompt_tokens";
pub const P_OUTPUT_TOKENS: [u8; 13] = *b"output_tokens";
pub const P_COMPLETION_TOKENS: [u8; 17] = *b"completion_tokens";
pub const P_CACHE_CREATION_INPUT_TOKENS: [u8; 27] = *b"cache_creation_input_tokens";
pub const P_OUTPUT: [u8; 6] = *b"output";
pub const P_CHOICES: [u8; 7] = *b"choices";
pub const P_MESSAGE: [u8; 7] = *b"message";
pub const P_DELTA: [u8; 5] = *b"delta";
pub const P_RESPONSE: [u8; 8] = *b"response";
pub const P_MESSAGE_START: [u8; 13] = *b"message_start";
pub const P_CONTENT_BLOCK_DELTA: [u8; 19] = *b"content_block_delta";
pub const P_MESSAGE_DELTA: [u8; 13] = *b"message_delta";
pub const P_OUTPUT_TEXT_DELTA: [u8; 26] = *b"response.output_text.delta";
pub const P_RESPONSE_COMPLETED: [u8; 18] = *b"response.completed";
pub const SSE_DATA: [u8; 5] = *b"data:";
pub const SSE_EVENT: [u8; 6] = *b"event:";
pub const HOST_ANTHROPIC: [u8; 17] = *b"api.anthropic.com";
pub const HOST_OPENAI: [u8; 14] = *b"api.openai.com";
pub const PROVIDER_ANTHROPIC: [u8; 9] = *b"anthropic";
pub const PROVIDER_OPENAI: [u8; 6] = *b"openai";
pub const V_POST: [u8; 4] = *b"POST";
pub const V_HYPGATE: [u8; 7] = *b"hypgate";
pub const V_USER: [u8; 4] = *b"user";
pub const V_ASSISTANT: [u8; 9] = *b"assistant";
pub const V_TEXT: [u8; 4] = *b"text";
pub const O_SUCCESS: [u8; 7] = *b"success";
pub const O_UPSTREAM_FAILURE: [u8; 16] = *b"upstream_failure";
pub const O_UPSTREAM_TIMEOUT: [u8; 16] = *b"upstream_timeout";
pub const O_UPLOAD_FAILURE: [u8; 14] = *b"upload_failure";
pub const O_DOWNLOAD_FAILURE: [u8; 16] = *b"download_failure";
pub const O_CLIENT_DISCONNECT: [u8; 17] = *b"client_disconnect";
pub const O_LOG_REFUSAL: [u8; 11] = *b"log_refusal";
pub const O_OTHER: [u8; 5] = *b"other";

#[derive(Debug, PartialEq, Eq)]
pub struct Usage { pub input: u64, pub cache_read: u64, pub cache_write: u64, pub output: u64 }
struct ParsedRequest { model: Option<Vec<u8>>, session_hint: Option<Vec<u8>>, user_text: Option<Vec<u8>> }
struct ParsedResponse { text: Vec<u8>, usage: Option<Usage>, model: Option<Vec<u8>>, failed: bool }

// ---- what the rows look like ------------------------------------------------------------

/// Every string value in `v` is well-formed UTF-8.
pub open spec fn values_valid(v: Value) -> bool
    decreases v, 0int,
{
    match v {
        Value::Str(t) => crate::utf8::valid(t@),
        Value::Array(items) => values_valid_items(items@),
        Value::Object(ms) => values_valid_members(ms@),
        _ => true,
    }
}
pub open spec fn values_valid_items(items: Seq<Value>) -> bool
    decreases items, 1int,
{
    items.len() == 0 || (values_valid(items.last()) && values_valid_items(items.drop_last()))
}
pub open spec fn values_valid_members(ms: Seq<Member>) -> bool
    decreases ms, 1int,
{
    ms.len() == 0 || (values_valid(ms.last().value) && values_valid_members(ms.drop_last()))
}
/// The keys of an object, in order.
pub open spec fn keys_of(v: Value) -> Seq<Seq<u8>> {
    Seq::new(crate::json::members_of(v).len(), |k: int| crate::json::members_of(v)[k].key@)
}
pub open spec fn base_keys() -> Seq<Seq<u8>> {
    seq![K_SCHEMA_VERSION@, K_SESSION_ID@, K_CONVERSATION_ID@, K_USER_ID@, K_PROVIDER@, K_MODEL@, K_CONVERSATION_STARTED_AT@,
        K_CONVERSATION_SOURCE@, K_CLIENT_NAME@, K_MESSAGE_ID@, K_MESSAGE_INDEX@, K_PART_ID@, K_PART_INDEX@, K_PART_TYPE@, K_DATE@,
        K_REQUEST_ID@, K_IS_ERROR@, K_STATUS@]
}
pub open spec fn user_keys() -> Seq<Seq<u8>> { base_keys() + seq![K_ROLE@, K_MESSAGE_CREATED_AT@, K_CONTENT_TEXT@, K_ATTRIBUTES@] }
pub open spec fn assistant_keys() -> Seq<Seq<u8>> {
    base_keys() + seq![K_ROLE@, K_MESSAGE_CREATED_AT@, K_PREVIOUS_MESSAGE_ID@, K_CONTENT_TEXT@, K_ATTRIBUTES@]
}
pub open spec fn gateway_keys() -> Seq<Seq<u8>> {
    seq![K_EXCHANGE_ID@, K_UPSTREAM@, K_METHOD@, K_PATH@, K_STATUS_CODE@, K_OUTCOME@, K_OUTCOME_CODE@, K_REQUEST_BYTES@, K_RESPONSE_BYTES@,
        K_TRUNCATED@, K_INCOMPLETE@, K_ORPHAN@, K_IS_SSE@, K_TENANT@]
}
/// The value at index `k` of an object.
pub open spec fn value_at(v: Value, k: int) -> Value { crate::json::members_of(v)[k].value }
/// A text value: a string, well formed, at most `max` bytes.
pub open spec fn is_text(v: Value, max: int) -> bool { v is Str && crate::utf8::valid(v->Str_0@) && v->Str_0@.len() <= max }
pub open spec fn is_hex_of(v: Value, bytes: Seq<u8>) -> bool { v is Str && v->Str_0@ == crate::shipping_identity::hex_encoding(bytes) }
pub open spec fn is_number(v: Value, n: nat) -> bool { v is Number && v->Number_0@ == crate::inbound::decimal(n) }
pub open spec fn is_timestamp(v: Value, ms: u64) -> bool { v is Str && v->Str_0@ == crate::calendar::iso_timestamp(crate::calendar::civil_of(ms)) }
pub open spec fn is_date(v: Value, ms: u64) -> bool { v is Str && v->Str_0@ == crate::calendar::iso_date(crate::calendar::civil_of(ms)) }
/// When the exchange started: its request start, else its response head, else its completion, else 0.
pub open spec fn started_ms(e: Exchange) -> u64 {
    match e.start { Some(s) => s.time_ms, None => match e.head { Some(h) => h.time_ms, None => match e.completion { Some(c) => c.time_ms, None => 0 } } }
}
/// When it finished: its completion, else its response head, else when it started.
pub open spec fn finished_ms(e: Exchange) -> u64 {
    match e.completion { Some(c) => c.time_ms, None => match e.head { Some(h) => h.time_ms, None => started_ms(e) } }
}

// ---- building values --------------------------------------------------------------------

fn bytes_eq(a: &[u8], b: &[u8]) -> (out: bool)
    ensures out == (a@ == b@),
{
    if a.len() != b.len() { return false; }
    let mut k: usize = 0;
    while k < a.len()
        invariant k <= a.len(), a.len() == b.len(), forall|j: int| 0 <= j < k ==> a@[j] == b@[j],
        decreases a.len() - k,
    {
        if a[k] != b[k] { return false; }
        k = k + 1;
    }
    proof { assert(a@ =~= b@); }
    true
}
/// A string value: the sanitized bytes.
fn text(bytes: &[u8]) -> (out: Value)
    ensures out is Str, out->Str_0@ == crate::utf8::sanitized(bytes@), is_text(out, out->Str_0@.len() as int), values_valid(out),
        crate::json::well_formed(out),
{
    Value::Str(crate::utf8::sanitize(bytes))
}
/// A string value cut to `max` bytes at a character boundary.
fn capped(bytes: &[u8], max: usize) -> (out: Value)
    requires crate::utf8::valid(bytes@),
    ensures is_text(out, max as int), values_valid(out), crate::json::well_formed(out),
{
    Value::Str(crate::utf8::cap(bytes, max))
}
fn number(n: u64) -> (out: Value)
    ensures is_number(out, n as nat), values_valid(out), crate::json::well_formed(out),
{
    Value::from_u64(n)
}
/// ASCII text is kept by the sanitizer.
proof fn lemma_ascii_text(s: Seq<u8>)
    requires crate::calendar::ascii(s),
    ensures crate::utf8::sanitized(s) == s,
{
    assert forall|k: int| 0 <= k < s.len() implies #[trigger] s[k] < 0x80 by {}
    crate::utf8::lemma_ascii_valid(s);
    crate::utf8::lemma_valid_fixed(s);
}
/// The verified calendar's timestamp as a text value.
fn time_text(ms: u64) -> (out: Value)
    ensures is_timestamp(out, ms), values_valid(out), crate::json::well_formed(out),
{
    let bytes = crate::calendar::timestamp(ms);
    proof { crate::calendar::lemma_iso_ascii(crate::calendar::civil_of(ms)); lemma_ascii_text(bytes@); }
    text(bytes.as_slice())
}
/// The verified calendar's date as a text value.
fn date_text(ms: u64) -> (out: Value)
    ensures is_date(out, ms), values_valid(out), crate::json::well_formed(out),
{
    let bytes = crate::calendar::date(ms);
    proof { crate::calendar::lemma_iso_ascii(crate::calendar::civil_of(ms)); lemma_ascii_text(bytes@); }
    text(bytes.as_slice())
}
fn boolean(b: bool) -> (out: Value)
    ensures out == Value::Bool(b), values_valid(out), crate::json::well_formed(out),
{
    Value::Bool(b)
}
fn null() -> (out: Value)
    ensures out == Value::Null, values_valid(out), crate::json::well_formed(out),
{
    Value::Null
}
/// Append a member. The object stays well formed and valid.
fn push_member(ms: &mut Vec<Member>, key: &[u8], value: Value)
    requires crate::json::well_formed_members(old(ms)@), values_valid_members(old(ms)@), crate::json::well_formed(value), values_valid(value),
    ensures final(ms)@.len() == old(ms)@.len() + 1, forall|k: int| 0 <= k < old(ms)@.len() ==> final(ms)@[k] == old(ms)@[k],
        final(ms)@.last().key@ == key@, final(ms)@.last().value == value,
        crate::json::well_formed_members(final(ms)@), values_valid_members(final(ms)@),
{
    let ghost before = ms@;
    ms.push(Member { key: slice_to_vec(key), value });
    proof {
        assert(ms@.drop_last() =~= before);
        assert(ms@.last().value == value);
    }
}
fn object(ms: Vec<Member>) -> (out: Value)
    requires crate::json::well_formed_members(ms@), values_valid_members(ms@),
    ensures out == Value::Object(ms), crate::json::well_formed(out), values_valid(out), crate::json::members_of(out) == ms@,
{
    Value::Object(ms)
}
fn single(item: Value) -> (out: Value)
    requires crate::json::well_formed(item), values_valid(item),
    ensures crate::json::well_formed(out), values_valid(out),
{
    let mut items: Vec<Value> = Vec::new();
    items.push(item);
    proof {
        assert(items@.last() == item);
        assert(items@.drop_last().len() == 0);
        assert(crate::json::well_formed_items(items@.drop_last()));
        assert(values_valid_items(items@.drop_last()));
        assert(crate::json::well_formed_items(items@));
        assert(values_valid_items(items@));
    }
    Value::Array(items)
}
fn option_text(value: &Option<Vec<u8>>) -> (out: Value)
    ensures values_valid(out), crate::json::well_formed(out),
{
    match value { Some(bytes) => text(bytes.as_slice()), None => null() }
}
fn option_number(value: Option<u64>) -> (out: Value)
    ensures values_valid(out), crate::json::well_formed(out),
{
    match value { Some(n) => number(n), None => null() }
}

/// A valid text followed by a line feed and another valid text.
fn append_line(out: &mut Vec<u8>, separate: bool, more: &[u8])
    requires crate::utf8::valid(old(out)@), crate::utf8::valid(more@),
    ensures crate::utf8::valid(final(out)@),
{
    if separate {
        proof {
            let lf = seq![LF];
            assert(crate::utf8::ascii(lf));
            crate::utf8::lemma_ascii_valid(lf);
            crate::utf8::lemma_valid_append(out@, lf);
            assert(out@.push(LF) =~= out@ + lf);
        }
        out.push(LF);
    }
    proof { crate::utf8::lemma_valid_append(out@, more@); }
    crate::framing::append(out, more);
}

// ---- reading provider bodies ------------------------------------------------------------

/// The sanitized bytes of a string value.
fn str_of(value: &Value) -> (out: Option<Vec<u8>>)
    ensures match out { Some(t) => crate::utf8::valid(t@), None => true },
{
    match value { Value::Str(s) => Some(crate::utf8::sanitize(s.as_slice())), _ => None }
}
fn get2<'a>(value: &'a Value, a: &[u8], b: &[u8]) -> Option<&'a Value> {
    match value.get(a) { Some(inner) => inner.get(b), None => None }
}
fn u64_at(value: &Value, key: &[u8]) -> Option<u64> {
    match value.get(key) { Some(v) => v.as_u64(), None => None }
}
fn u64_at2(value: &Value, a: &[u8], b: &[u8]) -> Option<u64> {
    match get2(value, a, b) { Some(v) => v.as_u64(), None => None }
}
pub open spec fn has_field(value: Value, key: Seq<u8>) -> bool {
    exists|i: int| 0 <= i < crate::json::members_of(value).len()
        && crate::json::members_of(value)[i].key@ == key
}
fn str_at(value: &Value, key: &[u8]) -> (out: Option<Vec<u8>>)
    ensures match out { Some(t) => crate::utf8::valid(t@), None => true },
        !has_field(*value, key@) ==> out.is_none(),
{
    match value.get(key) { Some(v) => str_of(v), None => None }
}
fn str_at2(value: &Value, a: &[u8], b: &[u8]) -> (out: Option<Vec<u8>>)
    ensures match out { Some(t) => crate::utf8::valid(t@), None => true },
{
    match get2(value, a, b) { Some(v) => str_of(v), None => None }
}
fn is_text_kind(kind: &[u8]) -> bool {
    bytes_eq(kind, P_TEXT.as_slice()) || bytes_eq(kind, P_INPUT_TEXT.as_slice()) || bytes_eq(kind, P_OUTPUT_TEXT.as_slice())
}

/// The text of a message content: a string, or the text blocks of an array
/// joined by line feeds.
#[verifier::loop_isolation(false)]
fn text_of_content(content: &Value) -> (out: Option<Vec<u8>>)
    ensures match out { Some(t) => crate::utf8::valid(t@), None => true },
{
    match content {
        Value::Str(s) => Some(crate::utf8::sanitize(s.as_slice())),
        Value::Array(blocks) => {
            let mut joined: Vec<u8> = Vec::new();
            let mut any = false;
            let mut k: usize = 0;
            proof { assert(crate::utf8::valid(joined@)); }
            while k < blocks.len()
                invariant crate::utf8::valid(joined@),
                decreases blocks.len() - k,
            {
                let block = slice_index_get(blocks.as_slice(), k);
                let is_text = match block.get(P_TYPE.as_slice()) {
                    Some(kind) => match kind { Value::Str(s) => is_text_kind(s.as_slice()), _ => false },
                    None => true,
                };
                if is_text {
                    if let Some(t) = str_at(block, P_TEXT.as_slice()) {
                        append_line(&mut joined, any, t.as_slice());
                        any = true;
                    }
                }
                k = k + 1;
            }
            if any { Some(joined) } else { None }
        }
        _ => None,
    }
}

#[verifier::loop_isolation(false)]
fn parse_request(bytes: &[u8]) -> (out: ParsedRequest)
    ensures match out.model { Some(t) => crate::utf8::valid(t@), None => true },
        match out.session_hint { Some(t) => crate::utf8::valid(t@), None => true },
        match out.user_text { Some(t) => crate::utf8::valid(t@), None => true },
{
    let value = match crate::json::parse(bytes) {
        Some(v) => v,
        None => return ParsedRequest { model: None, session_hint: None, user_text: None },
    };
    let model = str_at(&value, P_MODEL.as_slice());
    let hint = match str_at2(&value, P_METADATA.as_slice(), P_USER_ID.as_slice()) {
        Some(h) => Some(h),
        None => str_at(&value, P_USER.as_slice()),
    };
    let session_hint = match hint {
        Some(h) => if h.len() == 0 || h.len() > MAX_SESSION_HINT { None } else { Some(h) },
        None => None,
    };
    let messages = match value.get(P_MESSAGES.as_slice()) { Some(m) => Some(m), None => value.get(P_INPUT.as_slice()) };
    let user_text = match messages {
        Some(Value::Str(s)) => Some(crate::utf8::sanitize(s.as_slice())),
        Some(Value::Array(items)) => {
            let mut found: Option<Vec<u8>> = None;
            let mut k: usize = items.len();
            while k > 0
                invariant k <= items.len(), match found { Some(t) => crate::utf8::valid(t@), None => true },
                decreases k,
            {
                k = k - 1;
                let item = slice_index_get(items.as_slice(), k);
                let is_user = match item.get(P_ROLE.as_slice()) {
                    Some(Value::Str(role)) => bytes_eq(role.as_slice(), V_USER.as_slice()),
                    _ => false,
                };
                if is_user {
                    found = match item.get(P_CONTENT.as_slice()) { Some(content) => text_of_content(content), None => None };
                    break;
                }
            }
            found
        }
        _ => None,
    };
    ParsedRequest { model, session_hint, user_text }
}

fn first_u64(a: Option<u64>, b: Option<u64>, c: Option<u64>) -> u64 {
    match a { Some(n) => n, None => match b { Some(n) => n, None => match c { Some(n) => n, None => 0 } } }
}
/// Usage is known only when the first usage field is an object; null is unknown.
pub open spec fn has_usage_object(value: Value) -> bool {
    let ms = crate::json::members_of(value);
    exists|i: int| 0 <= i < ms.len() && ms[i].key@ == P_USAGE@
        && (forall|j: int| 0 <= j < i ==> ms[j].key@ != P_USAGE@)
        && ms[i].value is Object
}
fn usage_of(value: &Value) -> (out: Option<Usage>)
    ensures out.is_some() == has_usage_object(*value),
{
    let usage = match value.get(P_USAGE.as_slice()) { Some(u) => u, None => return None };
    if !matches!(usage, Value::Object(_)) { return None; }
    let cache_read = first_u64(u64_at(usage, P_CACHE_READ_INPUT_TOKENS.as_slice()),
        u64_at2(usage, P_INPUT_TOKENS_DETAILS.as_slice(), P_CACHED_TOKENS.as_slice()),
        u64_at2(usage, P_PROMPT_TOKENS_DETAILS.as_slice(), P_CACHED_TOKENS.as_slice()));
    let total_input = first_u64(u64_at(usage, P_INPUT_TOKENS.as_slice()), u64_at(usage, P_PROMPT_TOKENS.as_slice()), None);
    let output = first_u64(u64_at(usage, P_OUTPUT_TOKENS.as_slice()), u64_at(usage, P_COMPLETION_TOKENS.as_slice()), None);
    // Anthropic reports input net of cache; OpenAI reports cached tokens inside input.
    let anthropic = usage.get(P_CACHE_READ_INPUT_TOKENS.as_slice()).is_some() || usage.get(P_CACHE_CREATION_INPUT_TOKENS.as_slice()).is_some();
    let input = if anthropic { total_input } else if total_input >= cache_read { total_input - cache_read } else { 0 };
    let cache_write = first_u64(u64_at(usage, P_CACHE_CREATION_INPUT_TOKENS.as_slice()), None, None);
    Some(Usage { input, cache_read, cache_write, output })
}

/// The texts of `items[k].path` joined by line feeds.
#[verifier::loop_isolation(false)]
fn join_contents(items: &Vec<Value>, inner: bool) -> (out: Vec<u8>)
    ensures crate::utf8::valid(out@),
{
    let mut joined: Vec<u8> = Vec::new();
    let mut any = false;
    let mut k: usize = 0;
    proof { assert(crate::utf8::valid(joined@)); }
    while k < items.len()
        invariant crate::utf8::valid(joined@),
        decreases items.len() - k,
    {
        let item = slice_index_get(items.as_slice(), k);
        let content = if inner { get2(item, P_MESSAGE.as_slice(), P_CONTENT.as_slice()) } else { item.get(P_CONTENT.as_slice()) };
        if let Some(c) = content {
            if let Some(t) = text_of_content(c) {
                append_line(&mut joined, any, t.as_slice());
                any = true;
            }
        }
        k = k + 1;
    }
    joined
}
fn parse_json_response(value: &Value) -> (out: ParsedResponse)
    ensures crate::utf8::valid(out.text@), match out.model { Some(t) => crate::utf8::valid(t@), None => true },
        out.usage.is_some() == has_usage_object(*value), out.failed == semantics::failure(*value),
{
    let model = str_at(value, P_MODEL.as_slice());
    let text: Vec<u8> = if let Some(content) = value.get(P_CONTENT.as_slice()) {
        match text_of_content(content) { Some(t) => t, None => Vec::new() }
    } else if let Some(Value::Array(items)) = value.get(P_OUTPUT.as_slice()) {
        join_contents(items, false)
    } else if let Some(Value::Array(choices)) = value.get(P_CHOICES.as_slice()) {
        join_contents(choices, true)
    } else {
        Vec::new()
    };
    proof { assert(crate::utf8::valid(Seq::<u8>::empty())); }
    ParsedResponse { text, usage: usage_of(value), model, failed: semantics::failed(value) }
}

/// Whether the SSE grammar dispatches at least one complete data event.
/// This is descriptive metadata, never a gate on response parsing.
pub fn is_sse(bytes: &[u8]) -> (out: bool)
    ensures out == (crate::sse::event_data(bytes@).len() > 0),
{
    crate::sse::Reader::new(bytes).next().is_some()
}

/// One `data:` event of a stream.
#[verifier::loop_isolation(false)]
fn sse_event(event: &Value, out: &mut ParsedResponse, usage: &mut Usage, saw_usage: &mut bool)
    requires crate::utf8::valid(old(out).text@), match old(out).model { Some(t) => crate::utf8::valid(t@), None => true },
    ensures crate::utf8::valid(final(out).text@), match final(out).model { Some(t) => crate::utf8::valid(t@), None => true },
        final(out).failed == (old(out).failed || semantics::failure(*event)),
        !has_field(*event, P_TYPE@) && !has_usage_object(*event) ==>
            *final(usage) == *old(usage) && *final(saw_usage) == *old(saw_usage),
{
    out.failed = out.failed || semantics::failed(event);
    let kind: Vec<u8> = match str_at(event, P_TYPE.as_slice()) { Some(k) => k, None => Vec::new() };
    proof { assert(!has_field(*event, P_TYPE@) ==> kind@.len() == 0); }
    if bytes_eq(kind.as_slice(), P_MESSAGE_START.as_slice()) {
        if let Some(message) = event.get(P_MESSAGE.as_slice()) {
            out.model = str_at(message, P_MODEL.as_slice());
            if let Some(u) = usage_of(message) {
                usage.input = u.input; usage.cache_read = u.cache_read; usage.cache_write = u.cache_write; *saw_usage = true;
            }
        }
    } else if bytes_eq(kind.as_slice(), P_CONTENT_BLOCK_DELTA.as_slice()) {
        if let Some(t) = str_at2(event, P_DELTA.as_slice(), P_TEXT.as_slice()) { append_line(&mut out.text, false, t.as_slice()); }
    } else if bytes_eq(kind.as_slice(), P_MESSAGE_DELTA.as_slice()) {
        if let Some(n) = u64_at2(event, P_USAGE.as_slice(), P_OUTPUT_TOKENS.as_slice()) { usage.output = n; *saw_usage = true; }
    } else if bytes_eq(kind.as_slice(), P_OUTPUT_TEXT_DELTA.as_slice()) {
        if let Some(t) = str_at(event, P_DELTA.as_slice()) { append_line(&mut out.text, false, t.as_slice()); }
    } else if bytes_eq(kind.as_slice(), P_RESPONSE_COMPLETED.as_slice())
        || bytes_eq(kind.as_slice(), semantics::RESPONSE_FAILED.as_slice())
        || bytes_eq(kind.as_slice(), semantics::RESPONSE_INCOMPLETE.as_slice()) {
        if let Some(response) = event.get(P_RESPONSE.as_slice()) {
            out.model = str_at(response, P_MODEL.as_slice());
            if let Some(u) = usage_of(response) { *usage = u; *saw_usage = true; }
        }
    } else {
        // Chat-completions style chunks carry text in choices[].delta.content.
        if let Some(Value::Array(choices)) = event.get(P_CHOICES.as_slice()) {
            let mut k: usize = 0;
            while k < choices.len()
                invariant crate::utf8::valid(out.text@), match out.model { Some(t) => crate::utf8::valid(t@), None => true },
                    *usage == *old(usage), *saw_usage == *old(saw_usage),
                decreases choices.len() - k,
            {
                let c = slice_index_get(choices.as_slice(), k);
                if let Some(t) = str_at2(c, P_DELTA.as_slice(), P_CONTENT.as_slice()) { append_line(&mut out.text, false, t.as_slice()); }
                k = k + 1;
            }
        }
        if let Some(u) = usage_of(event) { *usage = u; *saw_usage = true; }
        proof { assert(!has_usage_object(*event) ==> *usage == *old(usage) && *saw_usage == *old(saw_usage)); }
    }
}
/// The stream's text and usage, from complete, joined SSE event payloads.
#[verifier::loop_isolation(false)]
fn parse_sse(bytes: &[u8]) -> (out: ParsedResponse)
    ensures crate::utf8::valid(out.text@), match out.model { Some(t) => crate::utf8::valid(t@), None => true },
        semantics::stream(crate::sse::event_data(bytes@), out.failed),
{
    let mut out = ParsedResponse { text: Vec::new(), usage: None, model: None, failed: false };
    let mut usage = Usage { input: 0, cache_read: 0, cache_write: 0, output: 0 };
    let mut saw_usage = false;
    proof { assert(crate::utf8::valid(out.text@)); }
    let mut events = crate::sse::Reader::new(bytes);
    loop
        invariant events.valid(), crate::utf8::valid(out.text@), match out.model { Some(t) => crate::utf8::valid(t@), None => true },
            forall|tail: bool| semantics::stream(events.remaining(), tail) ==>
                semantics::stream(crate::sse::event_data(bytes@), out.failed || tail),
        decreases events.left() + 1,
    {
        let ghost before = events.remaining();
        let event = events.next_json();
        match event {
            Some(Some(value)) => sse_event(&value, &mut out, &mut usage, &mut saw_usage),
            Some(None) => {},
            None => {
                proof { semantics::empty_stream(); assert(before =~= Seq::<Seq<u8>>::empty()); }
                break;
            }
        }
        proof {
            let value = event.unwrap();
            assert(semantics::parsed(before[0], value));
            assert(events.remaining() =~= before.drop_first());
            assert forall|tail: bool| semantics::stream(events.remaining(), tail) implies
                semantics::stream(crate::sse::event_data(bytes@), out.failed || tail) by {
                semantics::prepend(before, value, tail);
                assert(semantics::stream(before, semantics::optional_failure(value) || tail));
            }
        }
    }
    if saw_usage { out.usage = Some(usage); }
    out
}
fn parse_response(bytes: &[u8]) -> (out: (ParsedResponse, bool))
    ensures crate::utf8::valid(out.0.text@), match out.0.model { Some(t) => crate::utf8::valid(t@), None => true },
        semantics::interpretation(bytes@, out.0.failed),
{
    match crate::json::parse(bytes) {
        Some(value) => {
            let response = parse_json_response(&value);
            proof { assert(semantics::parsed(bytes@, Some(value))); }
            (response, false)
        }
        None => (parse_sse(bytes), is_sse(bytes)),
    }
}

// ---- the rows ---------------------------------------------------------------------------

pub fn provider(host: &[u8]) -> (out: Value)
    ensures values_valid(out), crate::json::well_formed(out),
{
    if bytes_eq(host, HOST_ANTHROPIC.as_slice()) { text(PROVIDER_ANTHROPIC.as_slice()) }
    else if bytes_eq(host, HOST_OPENAI.as_slice()) { text(PROVIDER_OPENAI.as_slice()) }
    else { text(host) }
}
pub fn outcome_name(code: u8) -> (out: Value)
    ensures values_valid(out), crate::json::well_formed(out),
{
    if code == 0 { text(O_SUCCESS.as_slice()) } else if code == 1 { text(O_UPSTREAM_FAILURE.as_slice()) }
    else if code == 2 { text(O_UPSTREAM_TIMEOUT.as_slice()) } else if code == 3 { text(O_UPLOAD_FAILURE.as_slice()) }
    else if code == 4 { text(O_DOWNLOAD_FAILURE.as_slice()) } else if code == 5 { text(O_CLIENT_DISCONNECT.as_slice()) }
    else if code == 6 { text(O_LOG_REFUSAL.as_slice()) } else { text(O_OTHER.as_slice()) }
}
/// The host and path of the exchange's configured destination, which the
/// verified parser accepted at startup; empty when the record has none.
fn destination_parts(exchange: &Exchange) -> (Vec<u8>, Vec<u8>) {
    let empty: &[u8] = &[];
    let dest: &[u8] = match &exchange.start { Some(s) => s.destination.as_slice(), None => empty };
    match crate::destination::parse(dest) {
        Some(parts) => (parts.host, parts.path),
        None => (Vec::new(), Vec::new()),
    }
}
/// A string of the sanitized `bytes` cut to `max`.
fn truncated_text(bytes: &[u8], max: usize) -> (out: Value)
    ensures is_text(out, max as int), values_valid(out), crate::json::well_formed(out),
{
    let clean = crate::utf8::sanitize(bytes);
    capped(clean.as_slice(), max)
}

#[verifier::rlimit(100)]
fn gateway_object(exchange: &Exchange, exchange_id: &[u8], host: &[u8], path: &[u8], status: Option<u16>, outcome: Option<u8>, sse: bool) -> (out: Value)
    ensures crate::json::well_formed(out), values_valid(out), keys_of(out) == gateway_keys(),
{
    let mut ms: Vec<Member> = Vec::new();
    push_member(&mut ms, K_EXCHANGE_ID.as_slice(), text(exchange_id));
    push_member(&mut ms, K_UPSTREAM.as_slice(), text(host));
    push_member(&mut ms, K_METHOD.as_slice(), text(V_POST.as_slice()));
    push_member(&mut ms, K_PATH.as_slice(), text(path));
    push_member(&mut ms, K_STATUS_CODE.as_slice(), match status { Some(s) => number(s as u64), None => null() });
    push_member(&mut ms, K_OUTCOME.as_slice(), match outcome { Some(o) => outcome_name(o), None => null() });
    push_member(&mut ms, K_OUTCOME_CODE.as_slice(), match outcome { Some(o) => number(o as u64), None => null() });
    push_member(&mut ms, K_REQUEST_BYTES.as_slice(), number(exchange.upload_total));
    push_member(&mut ms, K_RESPONSE_BYTES.as_slice(), number(exchange.download_total));
    push_member(&mut ms, K_TRUNCATED.as_slice(), boolean(exchange.truncated));
    push_member(&mut ms, K_INCOMPLETE.as_slice(), boolean(exchange.incomplete));
    push_member(&mut ms, K_ORPHAN.as_slice(), boolean(exchange.orphan));
    push_member(&mut ms, K_IS_SSE.as_slice(), boolean(sse));
    let tenant = crate::http1_exchange::decimal_bytes(exchange.tenant);
    push_member(&mut ms, K_TENANT.as_slice(), text(tenant.as_slice()));
    let out = object(ms);
    proof { assert(keys_of(out) =~= gateway_keys()); }
    out
}
fn usage_object(usage: &Usage) -> (out: Value)
    ensures crate::json::well_formed(out), values_valid(out),
{
    let mut ms: Vec<Member> = Vec::new();
    push_member(&mut ms, K_INPUT_TOKENS.as_slice(), number(usage.input));
    push_member(&mut ms, K_CACHE_READ_TOKENS.as_slice(), number(usage.cache_read));
    push_member(&mut ms, K_CACHE_WRITE_TOKENS.as_slice(), number(usage.cache_write));
    push_member(&mut ms, K_OUTPUT_TOKENS.as_slice(), number(usage.output));
    let total = saturating_add(saturating_add(saturating_add(usage.input, usage.cache_read), usage.cache_write), usage.output);
    push_member(&mut ms, K_TOTAL_TOKENS.as_slice(), number(total));
    object(ms)
}
fn saturating_add(a: u64, b: u64) -> (out: u64)
    ensures out == if a + b <= u64::MAX { a + b } else { u64::MAX as int },
{
    if u64::MAX - a >= b { a + b } else { u64::MAX }
}

/// What both rows share.
struct Shared<'a> {
    session: &'a [u8; 16],
    exchange: &'a Exchange,
    exchange_id: Vec<u8>,
    session_id: Vec<u8>,
    host: Vec<u8>,
    path: Vec<u8>,
    model: Option<Vec<u8>>,
    started: u64,
    status: Option<u16>,
    outcome: Option<u8>,
    is_error: bool,
}

/// The eighteen members both rows begin with.
#[verifier::rlimit(100)]
fn base_members(shared: &Shared<'_>, index: u32) -> (ms: Vec<Member>)
    requires shared.started == started_ms(*shared.exchange),
    ensures crate::json::well_formed_members(ms@), values_valid_members(ms@), ms@.len() == 18,
        is_timestamp(ms@[6].value, started_ms(*shared.exchange)), is_date(ms@[14].value, started_ms(*shared.exchange)),
        forall|k: int| 0 <= k < 18 ==> #[trigger] ms@[k].key@ == base_keys()[k],
        is_number(ms@[0].value, SCHEMA_VERSION as nat), ms@[16].value == Value::Bool(shared.is_error),
        is_hex_of(ms@[9].value, crate::shipping_identity::message_key_encoding(shared.session@, shared.exchange.request, index)),
        is_number(ms@[10].value, index as nat),
        is_hex_of(ms@[11].value, crate::shipping_identity::part_key_encoding(shared.session@, shared.exchange.request, index, 0)),
        is_hex_of(ms@[15].value, crate::shipping_identity::exchange_key_encoding(shared.session@, shared.exchange.request)),
{
    let mut ms: Vec<Member> = Vec::new();
    push_member(&mut ms, K_SCHEMA_VERSION.as_slice(), number(SCHEMA_VERSION));
    push_member(&mut ms, K_SESSION_ID.as_slice(), text(shared.session_id.as_slice()));
    push_member(&mut ms, K_CONVERSATION_ID.as_slice(), text(shared.session_id.as_slice()));
    let tenant = crate::http1_exchange::decimal_bytes(shared.exchange.tenant);
    push_member(&mut ms, K_USER_ID.as_slice(), text(tenant.as_slice()));
    push_member(&mut ms, K_PROVIDER.as_slice(), provider(shared.host.as_slice()));
    push_member(&mut ms, K_MODEL.as_slice(), option_text(&shared.model));
    push_member(&mut ms, K_CONVERSATION_STARTED_AT.as_slice(), time_text(shared.started));
    push_member(&mut ms, K_CONVERSATION_SOURCE.as_slice(), text(V_HYPGATE.as_slice()));
    push_member(&mut ms, K_CLIENT_NAME.as_slice(), text(V_HYPGATE.as_slice()));
    let message = hex_text(message_key(shared.session, shared.exchange.request, index).as_slice());
    push_member(&mut ms, K_MESSAGE_ID.as_slice(), message);
    push_member(&mut ms, K_MESSAGE_INDEX.as_slice(), number(index as u64));
    let part = hex_text(part_key(shared.session, shared.exchange.request, index, 0).as_slice());
    push_member(&mut ms, K_PART_ID.as_slice(), part);
    push_member(&mut ms, K_PART_INDEX.as_slice(), number(0));
    push_member(&mut ms, K_PART_TYPE.as_slice(), text(V_TEXT.as_slice()));
    push_member(&mut ms, K_DATE.as_slice(), date_text(shared.started));
    push_member(&mut ms, K_REQUEST_ID.as_slice(), hex_text(exchange_key(shared.session, shared.exchange.request).as_slice()));
    push_member(&mut ms, K_IS_ERROR.as_slice(), boolean(shared.is_error));
    let mut status: Vec<Member> = Vec::new();
    push_member(&mut status, K_CODE.as_slice(), match shared.status { Some(s) => number(s as u64), None => null() });
    push_member(&mut status, K_OUTCOME.as_slice(), option_number(match shared.outcome { Some(o) => Some(o as u64), None => None }));
    push_member(&mut ms, K_STATUS.as_slice(), object(status));
    proof {
        assert forall|k: int| 0 <= k < 18 implies #[trigger] ms@[k].key@ == base_keys()[k] by {}
    }
    ms
}
/// The lowercase hex of `bytes` as a text value: ASCII, so sanitizing keeps it.
fn hex_text(key: &[u8]) -> (out: Value)
    ensures is_hex_of(out, key@), values_valid(out), crate::json::well_formed(out),
{
    let encoded = hex(key);
    proof {
        crate::shipping_identity::hex_is_ascii(key@);
        assert forall|k: int| 0 <= k < encoded@.len() implies #[trigger] encoded@[k] < 0x80 by {
            assert(crate::shipping_identity::is_hex_digit(encoded@[k]));
        }
        crate::utf8::lemma_ascii_valid(encoded@);
        crate::utf8::lemma_valid_fixed(encoded@);
    }
    text(encoded.as_slice())
}

/// Two rows per exchange. `max_text` caps each `content_text`.
#[verifier::rlimit(100)]
pub fn rows(session: &[u8; 16], exchange: &Exchange, max_text: usize) -> (out: Vec<Value>)
    ensures out@.len() == 2,
        exists|failed: bool| semantics::interpretation(exchange.download@, failed)
            && value_at(out@[0], 16) == Value::Bool(semantics::exchange_error(*exchange, failed))
            && value_at(out@[1], 16) == Value::Bool(semantics::exchange_error(*exchange, failed)),
        is_timestamp(value_at(out@[0], 6), started_ms(*exchange)), is_timestamp(value_at(out@[1], 6), started_ms(*exchange)),
        is_date(value_at(out@[0], 14), started_ms(*exchange)), is_date(value_at(out@[1], 14), started_ms(*exchange)),
        is_timestamp(value_at(out@[0], 19), started_ms(*exchange)), is_timestamp(value_at(out@[1], 19), finished_ms(*exchange)),
        crate::json::well_formed(out@[0]) && crate::json::well_formed(out@[1]),
        values_valid(out@[0]) && values_valid(out@[1]),
        keys_of(out@[0]) == user_keys(), keys_of(out@[1]) == assistant_keys(),
        is_text(value_at(out@[0], 20), max_text as int), is_text(value_at(out@[1], 21), max_text as int),
        is_number(value_at(out@[0], 0), SCHEMA_VERSION as nat), is_number(value_at(out@[1], 0), SCHEMA_VERSION as nat),
        is_number(value_at(out@[0], 10), 0), is_number(value_at(out@[1], 10), 1),
        is_hex_of(value_at(out@[0], 9), crate::shipping_identity::message_key_encoding(session@, exchange.request, 0)),
        is_hex_of(value_at(out@[1], 9), crate::shipping_identity::message_key_encoding(session@, exchange.request, 1)),
        is_hex_of(value_at(out@[0], 11), crate::shipping_identity::part_key_encoding(session@, exchange.request, 0, 0)),
        is_hex_of(value_at(out@[1], 11), crate::shipping_identity::part_key_encoding(session@, exchange.request, 1, 0)),
        is_hex_of(value_at(out@[0], 15), crate::shipping_identity::exchange_key_encoding(session@, exchange.request)),
        is_hex_of(value_at(out@[1], 15), crate::shipping_identity::exchange_key_encoding(session@, exchange.request)),
{
    let (host, path) = destination_parts(exchange);
    let request = parse_request(exchange.upload.as_slice());
    let (response, sse) = parse_response(exchange.download.as_slice());
    let exchange_id = hex(exchange_key(session, exchange.request).as_slice());
    let started = match &exchange.start { Some(s) => s.time_ms, None => match &exchange.head { Some(h) => h.time_ms, None => match &exchange.completion { Some(c) => c.time_ms, None => 0 } } };
    let finished = match &exchange.completion { Some(c) => c.time_ms, None => match &exchange.head { Some(h) => h.time_ms, None => started } };
    let status = match &exchange.head { Some(h) => Some(h.status), None => None };
    let outcome = match &exchange.completion { Some(c) => Some(c.outcome), None => None };
    let session_id = match &request.session_hint { Some(h) => slice_to_vec(h.as_slice()), None => slice_to_vec(exchange_id.as_slice()) };
    let model = match &request.model { Some(m) => Some(slice_to_vec(m.as_slice())), None => match &response.model { Some(m) => Some(slice_to_vec(m.as_slice())), None => None } };
    let is_error = response.failed || (match status { Some(s) => s >= 400, None => false }) || (match outcome { Some(o) => o != 0, None => false }) || exchange.incomplete;
    proof { assert(started == started_ms(*exchange)); assert(finished == finished_ms(*exchange)); }
    let shared = Shared { session, exchange, exchange_id, session_id, host, path, model, started, status, outcome, is_error };

    let mut user = base_members(&shared, 0);
    push_member(&mut user, K_ROLE.as_slice(), text(V_USER.as_slice()));
    push_member(&mut user, K_MESSAGE_CREATED_AT.as_slice(), time_text(started));
    let user_text = match &request.user_text { Some(t) => capped(t.as_slice(), max_text), None => truncated_text(exchange.upload.as_slice(), max_text) };
    push_member(&mut user, K_CONTENT_TEXT.as_slice(), user_text);
    let mut user_attributes: Vec<Member> = Vec::new();
    push_member(&mut user_attributes, K_GATEWAY.as_slice(), gateway_object(exchange, shared.exchange_id.as_slice(), shared.host.as_slice(), shared.path.as_slice(), status, outcome, sse));
    push_member(&mut user, K_ATTRIBUTES.as_slice(), object(user_attributes));
    let user_row = object(user);

    let mut assistant = base_members(&shared, 1);
    push_member(&mut assistant, K_ROLE.as_slice(), text(V_ASSISTANT.as_slice()));
    push_member(&mut assistant, K_MESSAGE_CREATED_AT.as_slice(), time_text(finished));
    push_member(&mut assistant, K_PREVIOUS_MESSAGE_ID.as_slice(), single(hex_text(message_key(session, exchange.request, 0).as_slice())));
    // Nothing recognizable parsed: ship the raw response text instead of nothing.
    let unparsed = response.text.len() == 0 && response.usage.is_none() && exchange.download.len() > 0;
    let assistant_text = if unparsed { truncated_text(exchange.download.as_slice(), max_text) } else { capped(response.text.as_slice(), max_text) };
    push_member(&mut assistant, K_CONTENT_TEXT.as_slice(), assistant_text);
    let mut assistant_attributes: Vec<Member> = Vec::new();
    push_member(&mut assistant_attributes, K_GATEWAY.as_slice(), gateway_object(exchange, shared.exchange_id.as_slice(), shared.host.as_slice(), shared.path.as_slice(), status, outcome, sse));
    if let Some(usage) = &response.usage { push_member(&mut assistant_attributes, K_USAGE.as_slice(), usage_object(usage)); }
    push_member(&mut assistant, K_ATTRIBUTES.as_slice(), object(assistant_attributes));
    let assistant_row = object(assistant);

    proof {
        assert(keys_of(user_row) =~= user_keys());
        assert(keys_of(assistant_row) =~= assistant_keys());
    }
    let mut out: Vec<Value> = Vec::new();
    out.push(user_row);
    out.push(assistant_row);
    out
}

} // verus!
