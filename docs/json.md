# Verified JSON reader and writer

`gateway_core::json` reads a byte string into a `Value` tree or refuses it,
and writes a `Value` tree back out as one compact document. It is what the
gateway reads its root policy, its routes, the shipper's state files, the
HypAware server's replies, and provider bodies with, and what it writes the
state files, the shipped rows, and the scan output with. It depends only on
`vstd` and three small helpers in this crate (the hex digit specification
from the chunked decoder and the canonical decimal parser and encoder), so
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

`parse` is proved sound and complete against it. Soundness:
`parse(bytes) == Some(v)` implies `document(bytes@, v)`, so a value the
reader returns is encoded by exactly the bytes it was handed, nothing was
skipped or invented, every number lexeme satisfies the number grammar, and
every string is the decoding of its escapes. Completeness: for every `v`
with `document(bytes@, v)` and `depth(v) <= MAX_DEPTH`, `parse(bytes)` is
`Some(w)` with `same(w, v)`, structural equality of the two trees. So the
reader accepts exactly the grammar within the depth limit, and returns its
value; the grammar's determinism (that a document denotes one value) is a
corollary. The proof follows the reader: every scanner carries, besides its
soundness, a postcondition that for every encoding at its position the scan
ends where the encoding ends with the same bytes, established through a
loop invariant quantified over all such encodings (`string_progress`,
`stop`, `mstop`), with `boundary` naming what may follow a value so that a
number's maximal munch is the only reading. `Value::get` returns the first
member with the key and `None` only when no member has it; `as_u64` returns
`n` only for the lexeme that is the canonical decimal of `n`; the other
accessors answer only for their kind.

`write` is proved against the same grammar. A value is well formed
(`well_formed`) when every number lexeme in it satisfies `number_ok`; values
the reader returns are, by soundness, and so is `Value::from_u64`, whose
lexeme is the canonical decimal (`lemma_decimal_number_ok`). `write(v)` is
`Some(bytes)` exactly when `v` is well formed, and then
`encodes(bytes, 0, bytes.len(), v)`: the bytes are `v` and nothing else, no
whitespace, strings escaped. Composed with the reader's completeness this
gives `round_trip`: for a well-formed `v` within the depth limit,
`parse(write(v))` is `Some` of a value the same as `v`. The writer appends
to one buffer; the proof rests on `extends`, which says that what the
grammar establishes about a span is kept when bytes are appended after it,
proved for every predicate of the grammar by one induction over the value.
Strings are written with the quote, the backslash, and the five named
controls as two-character escapes and every other control byte as `\u00XX`;
every other byte stands for itself, so a row never contains a raw newline.

Executable tests pin the RFC example, every value kind, escapes and
surrogate pairs, number forms, the depth limit, a table of malformed
inputs, and the writer's output, escapes, round trips, and refusals.
Sixteen deliberate defects fail their proof obligations: seven in the
reader (a leading zero, a control byte, a lone low surrogate, trailing
bytes, a misread literal, a dropped escape byte, a trailing comma), six in
the writer (a raw quote, a raw control byte, a wrong hex digit, an unchecked
number, a missing comma, a missing colon), and three in the specification
that completeness catches (a grammar admitting control bytes, leading
zeros, or lone low surrogates would make the reader incomplete).

## What is not proved, and other limits

- **UTF-8.** Raw bytes in strings at or above 0x20 pass through unchecked;
  the reader does not validate that a string is UTF-8. `\u` escapes produce
  well-formed UTF-8. Consumers that need text use `String::from_utf8` or a
  lossy conversion.
- **Duplicate keys** are kept in order and `get` finds the first. The
  configuration loader refuses duplicates and unknown keys itself.
- **Depth** is limited to `MAX_DEPTH` (64) nested arrays and objects; the
  limit is a refusal, not part of the grammar predicate, and completeness
  is stated for documents within it.
- **Numbers** are kept as their lexeme. Only canonical `u64` decimals read as
  integers; fractions, exponents, and negatives are preserved but not
  evaluated. There is no floating-point conversion.

## Where it is used

`config.rs` reads the root policy and routes through it and walks the
schema (allowed keys, once each, required kinds); `shipping/config.rs` reads
the `shipping` section; `shipping/state.rs` reads and writes the identity
and checkpoint files and reads the claims of the gateway credential;
`shipping/client.rs` reads error replies; `shipping/projection.rs` reads
provider request and response bodies and SSE events and builds the rows the
shipper writes; `main.rs` writes the scan output. The runtime's `json_build`
module arranges values for the writer (text, numbers from `u64`, objects
from key-value lists); it holds no logic of its own. `serde_json` is no
longer a dependency of the gateway binary; the tests still use it to read
back what the writer emits.
