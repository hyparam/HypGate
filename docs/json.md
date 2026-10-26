# Verified JSON reader

`gateway_core::json` reads a byte string into a `Value` tree or refuses it.
It is what the gateway reads its root policy, its routes, the shipper's
state files, the HypAware server's replies, and provider bodies with. It
depends only on `vstd` and two small helpers in this crate (the hex digit
specification from the chunked decoder and the canonical decimal parser), so
it can be lifted out on its own.

## What is proved

The specification is the RFC 8259 grammar written as predicates over byte
positions:

- `document(s, v)`: `s` is whitespace, one value `v`, whitespace.
- `encodes(s, i, j, v)`: `s[i..j)` is exactly `v`: `null`, `true`, `false`,
  a number lexeme satisfying `number_ok`, a quoted string whose inside
  decodes to the string's bytes (`string_body`), an array whose inside is
  `elements`, or an object whose inside is `members`.
- `number_ok`: `-? (0 | [1-9][0-9]*) (\.[0-9]+)? ([eE][+-]?[0-9]+)?`.
- `string_body`: each byte stands for itself if it is at least 0x20 and not a
  quote or backslash, or is one escape sequence (`escape`): the eight
  two-character escapes, `\uXXXX` outside the surrogate range decoding to
  the code point's UTF-8, or a high surrogate followed by a low one decoding
  to the pair's code point. A lone surrogate matches nothing.
- `elements` and `members`: whitespace, or comma-separated items with
  whitespace around each; a member is a quoted key, a colon, and a value.

The theorem on `parse` is soundness: `parse(bytes) == Some(v)` implies
`document(bytes@, v)`. So a value the reader returns is encoded by exactly
the bytes it was handed, nothing was skipped or invented, every number
lexeme satisfies the number grammar, and every string is the decoding of its
escapes. `Value::get` returns the first member with the key and `None` only
when no member has it; `as_u64` returns `n` only for the lexeme that is the
canonical decimal of `n`; the other accessors answer only for their kind.

Executable tests pin the RFC example, every value kind, escapes and
surrogate pairs, number forms, the depth limit, and a table of malformed
inputs. Seven deliberate defects (a leading zero, a control byte, a lone low
surrogate, trailing bytes, a misread literal, a dropped escape byte, a
trailing comma) fail their proof obligations.

## What is not proved, and other limits

- **Completeness.** That every document of the grammar is accepted is not
  proved; it is tested. The parser is a deterministic recursive descent over
  an LL(1) grammar, so a refusal of a well-formed document would be a bug,
  not a design limit. Proving it is the natural next step, as it was for the
  chunked decoder.
- **UTF-8.** Raw bytes in strings at or above 0x20 pass through unchecked;
  the reader does not validate that a string is UTF-8. `\u` escapes produce
  well-formed UTF-8. Consumers that need text use `String::from_utf8` or a
  lossy conversion.
- **Duplicate keys** are kept in order and `get` finds the first. The
  configuration loader refuses duplicates and unknown keys itself.
- **Depth** is limited to `MAX_DEPTH` (64) nested arrays and objects; the
  limit is a refusal, not part of the grammar predicate.
- **Numbers** are kept as their lexeme. Only canonical `u64` decimals read as
  integers; fractions, exponents, and negatives are preserved but not
  evaluated. There is no floating-point conversion.

## Where it is used

`config.rs` reads the root policy and routes through it and walks the
schema (allowed keys, once each, required kinds); `shipping/config.rs` reads
the `shipping` section; `shipping/state.rs` reads the identity and
checkpoint files and the claims of the gateway credential;
`shipping/client.rs` reads error replies; `shipping/projection.rs` reads
provider request and response bodies and SSE events. Writing JSON still goes
through `serde_json`.
