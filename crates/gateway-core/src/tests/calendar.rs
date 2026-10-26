//! Executable checks of the calendar: known dates, and a sweep against an
//! independent closed-form algorithm (Howard Hinnant's) over the whole range.
use crate::calendar::*;

fn ts(ms: u64) -> String { String::from_utf8(timestamp(ms)).unwrap() }
fn day(ms: u64) -> String { String::from_utf8(date(ms)).unwrap() }

/// The closed form used before the calendar was verified, kept as an oracle.
fn hinnant(ms: u64) -> (i64, u32, u32, u32, u32, u32, u32) {
    let seconds = (ms / 1000) as i64; let millis = (ms % 1000) as u32;
    let days = seconds.div_euclid(86_400); let rem = seconds.rem_euclid(86_400);
    let z = days + 719_468; let era = z.div_euclid(146_097); let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d, (rem / 3600) as u32, ((rem % 3600) / 60) as u32, (rem % 60) as u32, millis)
}

#[test]
fn dates_and_timestamps_follow_the_proleptic_gregorian_calendar() {
    assert_eq!(civil(0), Civil { year: 1970, month: 1, day: 1, hour: 0, minute: 0, second: 0, millisecond: 0 });
    assert_eq!(ts(0), "1970-01-01T00:00:00.000Z");
    assert_eq!(day(951_782_400_000), "2000-02-29");
    assert_eq!(day(951_868_799_999), "2000-02-29");
    assert_eq!(ts(951_868_800_000), "2000-03-01T00:00:00.000Z");
    assert_eq!(day(4_107_542_400_000), "2100-03-01"); // 2100 is not a leap year
    assert_eq!(ts(1_700_000_000_123), "2023-11-14T22:13:20.123Z");
    assert_eq!(day(253_402_300_799_000), "9999-12-31");
    assert_eq!(ts(253_402_300_800_000), "10000-01-01T00:00:00.000Z");
}

#[test]
fn agrees_with_the_closed_form_across_the_range() {
    let mut samples: Vec<u64> = vec![0, 1, 999, 1000, 86_399_999, 86_400_000, u64::MAX, u64::MAX - 1, 951_782_400_000, 4_107_542_400_000];
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    for i in 0..200_000u64 {
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        samples.push(if i % 2 == 0 { x } else { x % 4_102_444_800_000 });
    }
    for ms in samples {
        let c = civil(ms);
        let (y, m, d, h, mi, s, millis) = hinnant(ms);
        assert_eq!((c.year as i64, c.month as u32, c.day as u32, c.hour as u32, c.minute as u32, c.second as u32, c.millisecond as u32), (y, m, d, h, mi, s, millis), "{ms}");
        assert_eq!(ts(ms), format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{millis:03}Z"));
        assert_eq!(day(ms), format!("{y:04}-{m:02}-{d:02}"));
    }
}
