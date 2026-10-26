//! Builders over the verified JSON value, for the rows and files the gateway
//! writes. The writer in `gateway_core::json` is proved to emit exactly the
//! value it is given; these only arrange values, and every number they make
//! is a canonical decimal, which the writer is proved to accept.
use gateway_core::json::{self, Member, Value};

pub fn text(s: impl AsRef<str>) -> Value { Value::Str(s.as_ref().as_bytes().to_vec()) }
pub fn number(n: u64) -> Value { Value::from_u64(n) }
pub fn size(n: usize) -> Value { Value::from_u64(u64::try_from(n).unwrap_or(u64::MAX)) }
pub fn boolean(b: bool) -> Value { Value::Bool(b) }
pub fn option<T>(value: Option<T>, build: impl FnOnce(T) -> Value) -> Value { value.map_or(Value::Null, build) }
pub fn array(items: Vec<Value>) -> Value { Value::Array(items) }
pub fn object(members: Vec<(&str, Value)>) -> Value {
    Value::Object(members.into_iter().map(|(key, value)| Member { key: key.as_bytes().to_vec(), value }).collect())
}
/// The document's bytes: compact, escaped, no raw newline anywhere. The
/// writer refuses only a number whose lexeme is not a number, which these
/// builders never produce; a refused value writes as nothing.
pub fn write(value: &Value) -> Vec<u8> { json::write(value).unwrap_or_default() }
