# HTTP/1.1 codec

The gateway speaks HTTP/1.1 through its own codec in `gateway-core`; no HTTP
library is linked. The codec is four verified modules and one thin adapter.
This page states the profile, what each module proves, and what stays
trusted.

## Profile

HTTP/1.1 only, one exchange per connection, closed after the response.
Inbound requests use origin-form targets. Bodies are delimited by
Content-Length, by chunked transfer coding, or, for upstream responses only,
by the close of the connection. Interim 1xx responses from upstream are
skipped, except 101, which is refused. Not supported, and refused when seen:
HTTP/1.0, pipelining, Upgrade, trailers, any transfer coding other than
`chunked` alone, obsolete line folding, and bare CR or LF. A request that
carries both Content-Length and Transfer-Encoding is refused.

## What is proved

| Module | Statement | Where |
| --- | --- | --- |
| `http1_head` | A request or status head is accepted exactly when it satisfies the relational grammar (`request_head_ok`, `status_head_ok`): the parser is sound (a returned head satisfies the grammar for exactly the bytes consumed) and complete (when none is returned, no prefix of the buffer satisfies it). Heads are bounded to 32 KiB and 100 fields. Names come out lowercased and values trimmed of surrounding blanks. | `parse_request`, `parse_status` |
| `http1_write` | A written head is the bytes the specification names, and those bytes satisfy the parser's grammar for the same start line and fields (`lemma_request_roundtrip`, `lemma_status_roundtrip`). The wire conditions on names and values exclude line-break injection by construction; `wire_ok` checks them at run time. | `write_request_head`, `write_status_head`, `wire_ok` |
| `http1_framing` | A head selects exactly one framing. Both Content-Length and Transfer-Encoding present, repeated fields, and any coding but `chunked` alone are refused. A Content-Length is accepted exactly when it is the canonical decimal of a `u64`. | `framing`, `parse_decimal` |
| `http1_chunked` | The decoder's invariant ties the bytes it consumed to complete chunks of exactly the body it emitted, so a finished body is one well-formed chunked encoding (`chunked_ok`) of the emitted bytes: nothing added, dropped, or reordered. Sizes have at most sixteen hex digits, so the count cannot overflow. Trailers and malformed delimiters are refused. Each chunk the encoder writes is a chunk of that grammar, and its last chunk is the grammar's last chunk. | `ChunkDecoder::feed`, `lemma_done_is_chunked`, `write_chunk_header`, `lemma_chunk_bytes_ok` |

Mutation guards for all four modules are in `scripts/check_mutations.py`.
Executable tests pin a corpus of valid and malformed heads, framing edge
cases, and chunked bodies split at every byte boundary.

## The adapter

`gateway-runtime/src/http1.rs` moves bytes between sockets and the codec and
decides nothing about what a byte means:

- `read_request_head` and `read_status_head` read into a buffer of at most
  32 KiB and call the parser after each read; a head that has not completed
  by the limit is too large, not incomplete.
- `BodyReader` yields only body bytes, delimited as the selected framing
  says; the end of the body is a clean EOF, and a body that stops early, a
  chunk coding fault, or data missing after a fixed length is an error.
- `ChunkedWriter` frames each write as one chunk and writes the last chunk on
  shutdown; it never closes the stream, the caller decides that.

The server (`server.rs`) reads the head under a ten-second deadline, answers
`431` or `400` for a head that is too large or malformed, sends `100
Continue` when asked, and writes every response with `Connection: close` and
either a Content-Length or chunked framing. The transport (`transport.rs`)
writes the upstream head from the verified projection's fields plus
`Transfer-Encoding: chunked` and `Connection: close`, streams the upload as
chunks, reads the status head, selects the response framing, and feeds the
body to the verified copy. The shipping client does the same with a fixed
Content-Length body.

## Trusted

- The adapter's byte movement: that a socket read lands in the buffer the
  parser is handed, that the bytes the encoders produce are the bytes
  written, and the plumbing of leftover bytes from the head read into the
  body reader.
- The sequencing decisions in the server and transport named above (which
  status to answer, when to send `100 Continue`, treating 204 and 304 as
  bodiless), which are tested, not proved. Lifting them into a verified
  exchange machine is the natural next step.
- Completeness of the chunked decoder against arbitrary peers is tested
  (every split of a valid body, size-line variants, extensions), not proved;
  its soundness is proved.
- Tokio, rustls, the OS, DNS, and TLS certificates, as before. Hyper,
  hyper-util, http, http-body, http-body-util, and bytes are no longer
  dependencies.

## Why this matters

The HTTP parser is the code that reads untrusted input first. The previous
parser was a dependency audited by inspection; this one is proved against
a grammar small enough to read in a sitting, and the properties that matter
for a gateway are theorems: no head is misread, a message can never be
delimited two ways, and a body arrives at the copy exactly as framed.
