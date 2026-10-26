//! The proleptic Gregorian calendar in UTC, for the timestamps the shipper
//! writes. The specification is the calendar itself: leap years, the days
//! in each month, and the day number of a date counted from 1970-01-01.
//! `civil` is proved to return the one date whose day number is the day of
//! the given Unix milliseconds, with the time of day decomposed exactly, and
//! the formatters are proved to print RFC 3339 text of exactly those fields.
use vstd::prelude::*;

verus! {

pub const EPOCH_YEAR: u64 = 1970;
pub const DAYS_PER_CYCLE: u64 = 146_097;
pub const MS_PER_DAY: u64 = 86_400_000;

pub open spec fn is_leap(y: int) -> bool { y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) }
pub open spec fn days_in_year(y: int) -> int { if is_leap(y) { 366 } else { 365 } }
pub open spec fn days_in_month(y: int, m: int) -> int {
    if m == 2 { if is_leap(y) { 29 } else { 28 } } else if m == 4 || m == 6 || m == 9 || m == 11 { 30 } else { 31 }
}
/// Days from January 1 of `y` to the first of month `m`.
pub open spec fn days_before_month(y: int, m: int) -> int
    decreases m,
{
    if m <= 1 { 0 } else { days_before_month(y, m - 1) + days_in_month(y, m - 1) }
}
/// Days from 1970-01-01 to January 1 of `y`, for `y >= 1970`.
pub open spec fn days_to_year(y: int) -> int
    decreases y - 1970,
{
    if y <= 1970 { 0 } else { days_to_year(y - 1) + days_in_year(y - 1) }
}
/// The day number of a date: days since 1970-01-01.
pub open spec fn day_number(y: int, m: int, d: int) -> int { days_to_year(y) + days_before_month(y, m) + d - 1 }
pub open spec fn date_ok(y: int, m: int, d: int) -> bool { y >= 1970 && 1 <= m <= 12 && 1 <= d <= days_in_month(y, m) }

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Civil { pub year: u64, pub month: u8, pub day: u8, pub hour: u8, pub minute: u8, pub second: u8, pub millisecond: u16 }

/// `c` is the civil time of `ms`.
pub open spec fn civil_ok(ms: u64, c: Civil) -> bool {
    date_ok(c.year as int, c.month as int, c.day as int) && day_number(c.year as int, c.month as int, c.day as int) == ms / MS_PER_DAY
        && c.hour < 24 && c.minute < 60 && c.second < 60 && c.millisecond < 1000
        && (c.hour as int) * 3600 + (c.minute as int) * 60 + c.second as int == (ms / 1000) % 86400
        && c.millisecond == ms % 1000
}
/// The civil time of `ms`: unique by `lemma_civil_unique`.
pub open spec fn civil_of(ms: u64) -> Civil { choose|c: Civil| civil_ok(ms, c) }

// ---- the calendar's arithmetic -------------------------------------------------------------

/// The months of a year add up to the year.
proof fn lemma_months_total(y: int)
    ensures days_before_month(y, 13) == days_in_year(y),
{
    assert(days_before_month(y, 1) == 0);
    assert(days_before_month(y, 2) == 31);
    assert(days_before_month(y, 3) == 31 + days_in_month(y, 2));
    assert(days_before_month(y, 4) == 62 + days_in_month(y, 2));
    assert(days_before_month(y, 5) == 92 + days_in_month(y, 2));
    assert(days_before_month(y, 6) == 123 + days_in_month(y, 2));
    assert(days_before_month(y, 7) == 153 + days_in_month(y, 2));
    assert(days_before_month(y, 8) == 184 + days_in_month(y, 2));
    assert(days_before_month(y, 9) == 215 + days_in_month(y, 2));
    assert(days_before_month(y, 10) == 245 + days_in_month(y, 2));
    assert(days_before_month(y, 11) == 276 + days_in_month(y, 2));
    assert(days_before_month(y, 12) == 306 + days_in_month(y, 2));
    assert(days_before_month(y, 13) == 337 + days_in_month(y, 2));
}
/// Later months start later.
proof fn lemma_months_monotone(y: int, a: int, b: int)
    requires 1 <= a <= b <= 13,
    ensures days_before_month(y, a) <= days_before_month(y, b), a < b ==> days_before_month(y, a) + days_in_month(y, a) <= days_before_month(y, b),
    decreases b - a,
{
    if a < b { lemma_months_monotone(y, a + 1, b); }
}
/// Later years start later.
proof fn lemma_years_monotone(a: int, b: int)
    requires 1970 <= a <= b,
    ensures days_to_year(a) <= days_to_year(b), a < b ==> days_to_year(a) + days_in_year(a) <= days_to_year(b),
    decreases b - a,
{
    if a < b { lemma_years_monotone(a + 1, b); }
}
/// Any 400 consecutive years hold 146,097 days.
proof fn lemma_year_cycle(y: int)
    requires y >= 1970,
    ensures days_to_year(y + 400) == days_to_year(y) + 146_097,
    decreases y - 1970,
{
    if y == 1970 {
        assert(days_to_year(2370) == 146_097) by (compute_only);
    } else {
        lemma_year_cycle(y - 1);
        assert(is_leap(y - 1 + 400) == is_leap(y - 1));
    }
}
proof fn lemma_eras(era: int)
    requires era >= 0,
    ensures days_to_year(1970 + 400 * era) == 146_097 * era,
    decreases era,
{
    if era > 0 {
        lemma_eras(era - 1);
        lemma_year_cycle(1970 + 400 * (era - 1));
    }
}
/// A day number names one date, and a time of day one triple.
pub proof fn lemma_civil_unique(ms: u64, a: Civil, b: Civil)
    requires civil_ok(ms, a), civil_ok(ms, b),
    ensures a == b,
{
    let (ya, ma, da) = (a.year as int, a.month as int, a.day as int);
    let (yb, mb, db) = (b.year as int, b.month as int, b.day as int);
    lemma_months_total(ya);
    lemma_months_total(yb);
    lemma_months_monotone(ya, ma, 13);
    lemma_months_monotone(yb, mb, 13);
    assert(days_before_month(ya, 1) == 0);
    assert(days_before_month(yb, 1) == 0);
    lemma_months_monotone(ya, 1, ma);
    lemma_months_monotone(yb, 1, mb);
    if ya < yb { lemma_years_monotone(ya, yb); assert(false); }
    if yb < ya { lemma_years_monotone(yb, ya); assert(false); }
    if ma < mb { lemma_months_monotone(ya, ma, mb); assert(false); }
    if mb < ma { lemma_months_monotone(ya, mb, ma); assert(false); }
}

// ---- computing the date --------------------------------------------------------------------

fn is_leap_exec(y: u64) -> (out: bool) ensures out == is_leap(y as int) { y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) }
fn days_in_year_exec(y: u64) -> (out: u64) ensures out == days_in_year(y as int) { if is_leap_exec(y) { 366 } else { 365 } }
fn days_in_month_exec(y: u64, m: u8) -> (out: u64)
    ensures out == days_in_month(y as int, m as int),
{
    if m == 2 { if is_leap_exec(y) { 29 } else { 28 } } else if m == 4 || m == 6 || m == 9 || m == 11 { 30 } else { 31 }
}

/// The civil time of Unix milliseconds.
pub fn civil(ms: u64) -> (out: Civil)
    ensures civil_ok(ms, out), out == civil_of(ms),
{
    let days = ms / MS_PER_DAY;
    let era = days / DAYS_PER_CYCLE;
    let ghost initial = days % DAYS_PER_CYCLE;
    let mut rem = days % DAYS_PER_CYCLE;
    let base: u64 = EPOCH_YEAR + 400 * era;
    let mut year: u64 = base;
    proof { lemma_eras(era as int); }
    while rem >= days_in_year_exec(year)
        invariant year >= base, days_to_year(year as int) + rem == days, 365 * (year - base) + rem <= initial, initial < DAYS_PER_CYCLE,
            base == EPOCH_YEAR + 400 * era, era <= u64::MAX / MS_PER_DAY / DAYS_PER_CYCLE,
        decreases rem,
    {
        rem = rem - days_in_year_exec(year);
        year = year + 1;
    }
    let ghost year_rem = rem as int;
    proof { lemma_months_total(year as int); }
    let mut month: u8 = 1;
    while rem >= days_in_month_exec(year, month)
        invariant 1 <= month <= 12, days_before_month(year as int, month as int) + rem == year_rem, year_rem < days_in_year(year as int),
            days_before_month(year as int, 13) == days_in_year(year as int),
        decreases 12 - month,
    {
        proof { lemma_months_monotone(year as int, month as int, 13); }
        rem = rem - days_in_month_exec(year, month);
        month = month + 1;
    }
    let day = (rem + 1) as u8;
    let seconds = (ms / 1000) % 86_400;
    let out = Civil { year, month, day, hour: (seconds / 3600) as u8, minute: ((seconds % 3600) / 60) as u8, second: (seconds % 60) as u8,
        millisecond: (ms % 1000) as u16 };
    proof {
        assert(civil_ok(ms, out));
        lemma_civil_unique(ms, out, civil_of(ms));
    }
    out
}

// ---- RFC 3339 text -------------------------------------------------------------------------

pub open spec fn zeros(k: nat) -> Seq<u8> { Seq::new(k, |i: int| 48u8) }
/// The decimal of `n`, left-padded with zeros to at least `width` digits.
pub open spec fn padded(n: nat, width: nat) -> Seq<u8> {
    let digits = crate::inbound::decimal(n);
    if digits.len() >= width { digits } else { zeros((width - digits.len()) as nat) + digits }
}
pub open spec fn iso_date(c: Civil) -> Seq<u8> {
    padded(c.year as nat, 4) + seq![45u8] + padded(c.month as nat, 2) + seq![45u8] + padded(c.day as nat, 2)
}
pub open spec fn iso_timestamp(c: Civil) -> Seq<u8> {
    iso_date(c) + seq![84u8] + padded(c.hour as nat, 2) + seq![58u8] + padded(c.minute as nat, 2) + seq![58u8] + padded(c.second as nat, 2)
        + seq![46u8] + padded(c.millisecond as nat, 3) + seq![90u8]
}
pub open spec fn ascii(s: Seq<u8>) -> bool { forall|k: int| 0 <= k < s.len() ==> #[trigger] s[k] < 0x80 }
pub proof fn lemma_padded_ascii(n: nat, width: nat)
    ensures ascii(padded(n, width)),
{
    crate::inbound::lemma_decimal_shape(n);
    let digits = crate::inbound::decimal(n);
    assert forall|k: int| 0 <= k < padded(n, width).len() implies #[trigger] padded(n, width)[k] < 0x80 by {
        if digits.len() >= width { assert(crate::inbound::is_digit(digits[k])); }
        else {
            let z = (width - digits.len()) as nat;
            if k < z { assert(padded(n, width)[k] == zeros(z)[k]); } else { assert(padded(n, width)[k] == digits[k - z]); assert(crate::inbound::is_digit(digits[k - z])); }
        }
    }
}
proof fn lemma_ascii_append(a: Seq<u8>, b: Seq<u8>)
    requires ascii(a), ascii(b),
    ensures ascii(a + b),
{
    assert forall|k: int| 0 <= k < (a + b).len() implies #[trigger] (a + b)[k] < 0x80 by {
        if k < a.len() { assert((a + b)[k] == a[k]); } else { assert((a + b)[k] == b[k - a.len()]); }
    }
}
/// Timestamps and dates are ASCII.
pub proof fn lemma_iso_ascii(c: Civil)
    ensures ascii(iso_date(c)), ascii(iso_timestamp(c)),
{
    lemma_padded_ascii(c.year as nat, 4); lemma_padded_ascii(c.month as nat, 2); lemma_padded_ascii(c.day as nat, 2);
    lemma_padded_ascii(c.hour as nat, 2); lemma_padded_ascii(c.minute as nat, 2); lemma_padded_ascii(c.second as nat, 2);
    lemma_padded_ascii(c.millisecond as nat, 3);
    let dash = seq![45u8]; let t = seq![84u8]; let colon = seq![58u8]; let dot = seq![46u8]; let z = seq![90u8];
    assert(ascii(dash) && ascii(t) && ascii(colon) && ascii(dot) && ascii(z));
    let d1 = padded(c.year as nat, 4) + dash; lemma_ascii_append(padded(c.year as nat, 4), dash);
    let d2 = d1 + padded(c.month as nat, 2); lemma_ascii_append(d1, padded(c.month as nat, 2));
    let d3 = d2 + dash; lemma_ascii_append(d2, dash);
    let d4 = d3 + padded(c.day as nat, 2); lemma_ascii_append(d3, padded(c.day as nat, 2));
    assert(iso_date(c) == d4);
    let s1 = d4 + t; lemma_ascii_append(d4, t);
    let s2 = s1 + padded(c.hour as nat, 2); lemma_ascii_append(s1, padded(c.hour as nat, 2));
    let s3 = s2 + colon; lemma_ascii_append(s2, colon);
    let s4 = s3 + padded(c.minute as nat, 2); lemma_ascii_append(s3, padded(c.minute as nat, 2));
    let s5 = s4 + colon; lemma_ascii_append(s4, colon);
    let s6 = s5 + padded(c.second as nat, 2); lemma_ascii_append(s5, padded(c.second as nat, 2));
    let s7 = s6 + dot; lemma_ascii_append(s6, dot);
    let s8 = s7 + padded(c.millisecond as nat, 3); lemma_ascii_append(s7, padded(c.millisecond as nat, 3));
    let s9 = s8 + z; lemma_ascii_append(s8, z);
    assert(iso_timestamp(c) == s9);
}

/// Append the decimal of `n` padded to `width`.
fn push_padded(out: &mut Vec<u8>, n: u64, width: usize)
    ensures final(out)@ == old(out)@ + padded(n as nat, width as nat),
{
    let digits = crate::http1_exchange::decimal_bytes(n);
    let ghost before = out@;
    let mut k: usize = digits.len();
    while k < width
        invariant k >= digits.len(), k <= width || k == digits.len(), out@ == before + zeros((k - digits.len()) as nat),
        decreases width - k,
    {
        out.push(48);
        proof { assert(before + zeros((k - digits.len()) as nat) + seq![48u8] =~= before + zeros((k + 1 - digits.len()) as nat)); }
        k = k + 1;
    }
    proof {
        if digits.len() >= width { assert(zeros(0) =~= Seq::<u8>::empty()); assert(out@ =~= before); }
    }
    crate::framing::append(out, digits.as_slice());
    proof {
        if digits.len() >= width { assert(out@ =~= before + padded(n as nat, width as nat)); }
        else { assert(out@ =~= before + (zeros((width - digits.len()) as nat) + digits@)); }
    }
}
/// `YYYY-MM-DD`.
pub fn format_date(c: &Civil) -> (out: Vec<u8>)
    ensures out@ == iso_date(*c),
{
    let mut out: Vec<u8> = Vec::new();
    push_padded(&mut out, c.year, 4);
    out.push(45);
    push_padded(&mut out, c.month as u64, 2);
    out.push(45);
    push_padded(&mut out, c.day as u64, 2);
    proof { assert(out@ =~= iso_date(*c)); }
    out
}
/// `YYYY-MM-DDTHH:MM:SS.mmmZ`.
pub fn format_timestamp(c: &Civil) -> (out: Vec<u8>)
    ensures out@ == iso_timestamp(*c),
{
    let mut out = format_date(c);
    out.push(84);
    push_padded(&mut out, c.hour as u64, 2);
    out.push(58);
    push_padded(&mut out, c.minute as u64, 2);
    out.push(58);
    push_padded(&mut out, c.second as u64, 2);
    out.push(46);
    push_padded(&mut out, c.millisecond as u64, 3);
    out.push(90);
    proof { assert(out@ =~= iso_timestamp(*c)); }
    out
}
/// The RFC 3339 timestamp of Unix milliseconds.
pub fn timestamp(ms: u64) -> (out: Vec<u8>)
    ensures out@ == iso_timestamp(civil_of(ms)),
{
    let c = civil(ms);
    format_timestamp(&c)
}
/// The civil date of Unix milliseconds.
pub fn date(ms: u64) -> (out: Vec<u8>)
    ensures out@ == iso_date(civil_of(ms)),
{
    let c = civil(ms);
    format_date(&c)
}

} // verus!
