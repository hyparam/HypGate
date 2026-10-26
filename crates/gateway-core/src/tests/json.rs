//! Executable checks of the JSON reader. The proof covers every input it
//! accepts; these pin concrete documents, decodings, and refusals.
use crate::json::*;

fn num(lexeme: &str) -> Value { Value::Number(lexeme.as_bytes().to_vec()) }
fn text(s: &str) -> Value { Value::Str(s.as_bytes().to_vec()) }
fn member(key: &str, value: Value) -> Member { Member { key: key.as_bytes().to_vec(), value } }
/// A `\u` escape, built from bytes so the source holds no escape itself.
fn esc(hex: &str) -> Vec<u8> { let mut v = vec![92u8, b'u']; v.extend_from_slice(hex.as_bytes()); v }
fn quoted(inside: &[u8]) -> Vec<u8> { let mut v = vec![34u8]; v.extend_from_slice(inside); v.push(34); v }

#[test]
fn reads_the_rfc_example() {
    let doc = br#" {
        "Image": {
            "Width":  800,
            "Height": 600,
            "Title":  "View from 15th Floor",
            "Thumbnail": { "Url": "http://www.example.com/image/481989943", "Height": 125, "Width": 100 },
            "Animated" : false,
            "IDs": [116, 943, 234, 38793]
        }
    } "#;
    let value = parse(doc).unwrap();
    let image = value.get(b"Image").unwrap();
    assert_eq!(image.get(b"Width").unwrap().as_u64(), Some(800));
    assert_eq!(image.get(b"Title").unwrap().as_str().map(Vec::as_slice), Some(&b"View from 15th Floor"[..]));
    assert_eq!(image.get(b"Thumbnail").unwrap().get(b"Height").unwrap().as_u64(), Some(125));
    assert_eq!(image.get(b"Animated").unwrap().as_bool(), Some(false));
    let ids: Vec<u64> = image.get(b"IDs").unwrap().as_array().unwrap().iter().map(|v| v.as_u64().unwrap()).collect();
    assert_eq!(ids, [116, 943, 234, 38793]);
    assert!(image.get(b"Missing").is_none());
    assert!(value.get(b"Width").is_none());
}

#[test]
fn reads_every_value_kind_with_whitespace_anywhere() {
    assert_eq!(parse(b"null"), Some(Value::Null));
    assert_eq!(parse(b" \t\r\ntrue \n"), Some(Value::Bool(true)));
    assert_eq!(parse(b"false"), Some(Value::Bool(false)));
    assert_eq!(parse(b"[]"), Some(Value::Array(vec![])));
    assert_eq!(parse(b"[ ]"), Some(Value::Array(vec![])));
    assert_eq!(parse(b"{}"), Some(Value::Object(vec![])));
    assert_eq!(parse(b"{ }"), Some(Value::Object(vec![])));
    assert_eq!(parse(b"[ 1 , [ 2 , [ ] ] , { \"a\" : null } ]"),
        Some(Value::Array(vec![num("1"), Value::Array(vec![num("2"), Value::Array(vec![])]), Value::Object(vec![member("a", Value::Null)])])));
    assert_eq!(parse(b"{\"a\":1,\"b\":[true],\"a\":2}"),
        Some(Value::Object(vec![member("a", num("1")), member("b", Value::Array(vec![Value::Bool(true)])), member("a", num("2"))])));
    assert_eq!(parse(b"{\"a\":1,\"a\":2}").unwrap().get(b"a"), Some(&num("1")), "the first duplicate wins");
}

#[test]
fn numbers_keep_their_lexeme_and_canonical_decimals_read_as_u64() {
    for lexeme in ["0", "-0", "7", "-7", "18446744073709551615", "18446744073709551616", "1.5", "-0.25", "1e3", "1E+3", "2.5e-10", "0.0"] {
        assert_eq!(parse(lexeme.as_bytes()), Some(num(lexeme)), "{lexeme}");
    }
    assert_eq!(num("0").as_u64(), Some(0));
    assert_eq!(num("18446744073709551615").as_u64(), Some(u64::MAX));
    for not_u64 in ["-0", "-7", "18446744073709551616", "1.5", "1e3", "0.0"] { assert_eq!(num(not_u64).as_u64(), None, "{not_u64}"); }
    assert_eq!(parse(b"[1,2]"), Some(Value::Array(vec![num("1"), num("2")])));
}

#[test]
fn refuses_malformed_numbers() {
    for bad in ["01", "-", "--1", "+1", "1.", ".5", "1e", "1e+", "1.e5", "0x10", "1_000", "NaN", "Infinity", "-01", "1 2"] {
        assert_eq!(parse(bad.as_bytes()), None, "{bad}");
    }
}

#[test]
fn decodes_string_escapes_to_utf8() {
    assert_eq!(parse(br#""plain text""#), Some(text("plain text")));
    assert_eq!(parse(br#""\" \\ \/ \b \f \n \r \t""#), Some(Value::Str(b"\" \\ / \x08 \x0c \n \r \t".to_vec())));
    assert_eq!(parse(&quoted(&[esc("0041"), esc("00e9"), esc("20ac")].concat())), Some(text("Aé€")));
    assert_eq!(parse(&quoted(&[esc("D83D"), esc("DE00")].concat())), Some(text("😀")));
    assert_eq!(parse(br#""\u0000""#), Some(Value::Str(vec![0])));
    assert_eq!(parse("\"raw é and 😀 pass through\"".as_bytes()), Some(text("raw é and 😀 pass through")));
    assert_eq!(parse(br#""""#), Some(text("")));
}

#[test]
fn refuses_malformed_strings() {
    for bad in [&br#""unterminated"#[..], br#""bad \x escape""#, br#""\u12"#, br#""\u12G4""#, br#""\uD83D""#, &quoted(&[esc("D83D"), esc("0041")].concat())[..],
        br#""\uDE00""#, b"\"control \x01 byte\"", b"\"tab\tinside\"", b"\"newline\ninside\"", b"'single'"] {
        assert_eq!(parse(bad), None, "{}", String::from_utf8_lossy(bad));
    }
}

#[test]
fn refuses_malformed_structure_and_trailing_bytes() {
    for bad in ["", " ", "[", "]", "[1,]", "[,1]", "[1 2]", "{", "{\"a\"}", "{\"a\":}", "{\"a\":1,}", "{a:1}", "{\"a\" 1}",
        "{1:2}", "nul", "tru", "falsey", "nulll", "[1]]", "[1] x", "1 2", "{} {}", "[1}", "{\"a\":1]"] {
        assert_eq!(parse(bad.as_bytes()), None, "{bad:?}");
    }
}

#[test]
fn nesting_is_bounded() {
    let deep = |n: usize| { let mut s = "[".repeat(n); s.push_str(&"]".repeat(n)); s };
    assert!(parse(deep(MAX_DEPTH as usize).as_bytes()).is_some());
    assert!(parse(deep(MAX_DEPTH as usize + 1).as_bytes()).is_none());
    let objects = |n: usize| { let mut s = "{\"k\":".repeat(n); s.push_str("1"); s.push_str(&"}".repeat(n)); s };
    assert!(parse(objects(MAX_DEPTH as usize).as_bytes()).is_some());
    assert!(parse(objects(MAX_DEPTH as usize + 1).as_bytes()).is_none());
}

#[test]
fn accessors_answer_only_for_their_kind() {
    let value = parse(br#"{"s":"x","n":5,"b":true,"z":null,"a":[],"o":{}}"#).unwrap();
    assert!(value.as_object().is_some() && value.as_array().is_none() && value.as_str().is_none());
    assert!(value.get(b"s").unwrap().as_str().is_some() && value.get(b"s").unwrap().as_u64().is_none());
    assert!(value.get(b"n").unwrap().as_u64() == Some(5) && value.get(b"n").unwrap().as_bool().is_none());
    assert!(value.get(b"b").unwrap().as_bool() == Some(true) && value.get(b"b").unwrap().as_array().is_none());
    assert!(value.get(b"z").unwrap().is_null() && !value.get(b"b").unwrap().is_null());
    assert!(value.get(b"a").unwrap().as_array().is_some_and(Vec::is_empty));
    assert!(value.get(b"o").unwrap().as_object().is_some_and(Vec::is_empty));
    assert!(Value::Null.get(b"x").is_none());
}

#[test]
fn writes_compact_documents_the_reader_reads_back() {
    let value = parse(br#" { "Image" : { "Width" : 800 , "Title" : "View" , "Animated" : false , "IDs" : [ 116 , 943 ] , "Thumb" : { } , "None" : null , "Empty" : [ ] } } "#).unwrap();
    let bytes = write(&value).unwrap();
    assert_eq!(bytes, br#"{"Image":{"Width":800,"Title":"View","Animated":false,"IDs":[116,943],"Thumb":{},"None":null,"Empty":[]}}"#);
    assert_eq!(parse(&bytes), Some(parse(&bytes).unwrap()));
    assert_eq!(round_trip(&value), Some(value));
    assert_eq!(write(&Value::Null), Some(b"null".to_vec()));
    assert_eq!(write(&Value::Bool(true)), Some(b"true".to_vec()));
    assert_eq!(write(&Value::Array(vec![Value::Array(vec![]), Value::Object(vec![member("a", Value::Array(vec![Value::Null, Value::Bool(true), Value::Bool(false)]))])])),
        Some(br#"[[],{"a":[null,true,false]}]"#.to_vec()));
    assert_eq!(write(&Value::Object(vec![member("a", num("1")), member("a", num("2"))])), Some(br#"{"a":1,"a":2}"#.to_vec()), "duplicate keys are written in order");
}

#[test]
fn escapes_strings_when_writing() {
    let value = Value::Str(b"\" \\ / \x08 \x0c \n \r \t \x01 \x1f raw \xc3\xa9 \xf0\x9f\x98\x80 \x7f".to_vec());
    let expected = [&b"\"\\\" \\\\ / \\b \\f \\n \\r \\t "[..], &esc("0001"), b" ", &esc("001f"), " raw é 😀 \x7f\"".as_bytes()].concat();
    assert_eq!(write(&value), Some(expected));
    assert_eq!(round_trip(&value), Some(value));
    let key = Value::Object(vec![member("line\nbreak \"q\"", Value::Null)]);
    assert_eq!(write(&key), Some(br#"{"line\nbreak \"q\"":null}"#.to_vec()));
    assert!(!write(&Value::Str(b"a\nb".to_vec())).unwrap().contains(&b'\n'), "no raw newline survives, so a row is one line");
}

#[test]
fn from_u64_round_trips_and_malformed_numbers_are_refused() {
    for n in [0u64, 7, 10, 1_000_000, u64::MAX] {
        let value = Value::from_u64(n);
        assert_eq!(value.as_u64(), Some(n));
        assert_eq!(write(&value), Some(n.to_string().into_bytes()));
    }
    for lexeme in ["-0", "1.5", "-2.5e-10", "1E+3", "18446744073709551616"] {
        assert_eq!(write(&num(lexeme)), Some(lexeme.as_bytes().to_vec()), "{lexeme}");
    }
    for bad in ["", "01", "-", "1.", ".5", "1e", "abc", "1 ", " 1"] {
        assert_eq!(write(&num(bad)), None, "{bad:?}");
        assert_eq!(write(&Value::Array(vec![num("1"), num(bad)])), None, "{bad:?}");
        assert_eq!(write(&Value::Object(vec![member("k", num(bad))])), None, "{bad:?}");
    }
}
