//! The calendar for the verified projection (`gateway_core::projection`),
//! which builds the HypAware rows from an exchange: this module only turns
//! Unix milliseconds into RFC 3339 text, a trusted, tested computation, and
//! hands the exchange to the core.
use gateway_core::exchange_assembler::Exchange;
use gateway_core::json::Value;
use gateway_core::projection::Calendar;

/// Proleptic Gregorian UTC.
pub struct Utc;
impl Calendar for Utc {
    fn timestamp(&self, ms: u64) -> Vec<u8> { iso_timestamp(ms).into_bytes() }
    fn date(&self, ms: u64) -> Vec<u8> { iso_date(ms).into_bytes() }
}

/// Two rows per exchange, from the verified projection. `max_text` caps each `content_text`.
pub fn rows(session: &[u8; 16], exchange: &Exchange, max_text: usize) -> Vec<Value> {
    gateway_core::projection::rows(session, exchange, max_text, &Utc)
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
