//! Executable checks of the IPv6 literal grammar against the standard
//! library's parser, which the configuration loader used before.
use crate::ipv6::literal_ok;
use std::net::Ipv6Addr;

fn agrees(text: &str) {
    assert_eq!(literal_ok(text.as_bytes()), text.parse::<Ipv6Addr>().is_ok(), "{text:?}");
}

#[test]
fn accepts_and_rejects_as_the_standard_library_does() {
    for text in ["::", "::1", "1::", "1:2:3:4:5:6:7:8", "1::8", "1:2:3:4:5:6:7::", "::ffff:1.2.3.4", "64:ff9b::1.2.3.4", "1:2:3:4:5:6:1.2.3.4",
        "fe80::1", "FE80::ABCD:ef01", "0:0:0:0:0:0:0:0", "1:2:3:4:5:6:7:1.2.3.4", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7", ":1:2:3:4:5:6:7:8",
        "1:2:3:4:5:6:7:8:", "1:::2", "1::2::3", "12345::", "1:2:3:4:5:6::7:8", "::1.2.3.4.5", "::01.2.3.4", "::1.2.3.256", "::1.2.3",
        ":1.2.3.4", "1.2.3.4::", "::g", "", ":", "1:2:3:4:5:6:7:8::", "::ffff:1.2.3.04", "::1.2.3.4:5", "1::1.2.3.4", "::ffff:255.255.255.255",
        "::ffff:1.2.3.4x", "1 ::", " ::1", "::1%eth0", "[::1]", "::ff.ff.ff.ff", "::1.2.3.0", "::0.0.0.0", "1:2::3.4.5.6"] {
        agrees(text);
    }
}

#[test]
fn agrees_with_the_standard_library_on_random_texts() {
    let alphabet = b"0123456789abcdefABCDEF:.g ";
    let mut x: u64 = 0x2545_F491_4F6C_DD1D;
    for _ in 0..200_000 {
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        let len = (x % 24) as usize;
        let mut text = Vec::with_capacity(len);
        let mut y = x;
        for _ in 0..len {
            y = y.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            // Bias toward colons and digits so that valid addresses occur.
            let pick = (y >> 33) % 100;
            let b = if pick < 35 { b':' } else if pick < 75 { alphabet[((y >> 20) % 10) as usize] } else if pick < 85 { b'.' }
                else { alphabet[((y >> 20) % alphabet.len() as u64) as usize] };
            text.push(b);
        }
        let s = String::from_utf8(text).unwrap();
        agrees(&s);
    }
}
