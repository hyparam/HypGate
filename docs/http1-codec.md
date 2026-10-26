# HTTP/1.1 codec

The gateway speaks HTTP/1.1 through its own codec in `gateway-core`; no HTTP
library is linked. The codec is five verified modules and one thin adapter.
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
| `http1_exchange` | The gateway's own exchange decisions. Statuses come from total tables (`refusal_status`: 431, 400, 401, 405, 503; `failure_status`: 504 for a passed deadline, 502 otherwise); `wants_continue` and `upstream_status` (interim, refused 101, bodiless 204 and 304, or framed by the fields) are total. A `Connection` writes at most one response head, only while open, always with `Connection: close` and a framing field that matches the body (`Content-Length` of the fixed body, or chunked), never a body after 204 or 304, and its head parses back as the status and fields it meant (`lemma_head_well_formed`). An `Upstream` writes one `POST` head with the projection's fields plus chunked framing and `Connection: close`, likewise well formed. A `ChunkStream` yields bytes that are one well-formed chunked encoding of exactly the frames given; a stream ends cleanly only through its last chunk, and an aborted connection adds nothing. | `Connection::{interim_continue,respond_fixed,respond_stream,finish,abort}`, `Upstream::{request,finish}`, `ChunkStream::{frame,end}` |
| `http1_chunked` | The decoder accepts exactly the grammar. Soundness: its invariant ties the bytes it consumed to complete chunks of exactly the body it emitted, so a finished body is one well-formed chunked encoding (`chunked_ok`) of the emitted bytes: nothing added, dropped, or reordered. Completeness: when the bytes still to come complete a well-formed chunked body, a step never rejects, consumes no more than those bytes, is done exactly when it has consumed them all, and has then emitted exactly the body the encoding carries (`lemma_complete`); the proof rests on chunk boundaries being determined by the bytes, since a size line ends at the first CRLF and its digits at the first non-hex byte. Sizes have at most sixteen hex digits, so the count cannot overflow. Trailers and malformed delimiters are refused. Each chunk the encoder writes is a chunk of that grammar, and its last chunk is the grammar's last chunk. | `ChunkDecoder::feed`, `lemma_done_is_chunked`, `ChunkDecoder::lemma_complete`, `write_chunk_header`, `lemma_chunk_bytes_ok` |

Mutation guards for all five modules are in `scripts/check_mutations.py`.
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
- `ChunkedWriter` writes the bytes a verified `ChunkStream` yields for each
  write and for shutdown; it never closes the stream, the caller decides that.

The server (`server.rs`) reads the head under a ten-second deadline and then
asks the `Connection` machine for every byte it writes: the refusal for a head
that is too large or malformed, the `100 Continue`, the response head, the
chunks, and the last chunk. The transport (`transport.rs`) asks the `Upstream`
machine for the request head and the upload chunks, and classifies each
status head it reads with `upstream_status` until a final one. The shipping
client reuses `upstream_status` with a fixed Content-Length request.

## Trusted

- The adapter's byte movement: that a socket read lands in the buffer the
  parser is handed, that the bytes the encoders produce are the bytes
  written, and the plumbing of leftover bytes from the head read into the
  body reader.
- That the server and transport call the machines at the moments they do
  (after the head read, before the body, on a fault), and the reason phrases
  the server passes, which the machine checks for value bytes but does not
  choose.
- Tokio, rustls, the OS, DNS, and TLS certificates, as before. Hyper,
  hyper-util, http, http-body, http-body-util, and bytes are no longer
  dependencies.

## Why this matters

The HTTP parser is the code that reads untrusted input first. The previous
parser was a dependency audited by inspection; this one is proved against
a grammar small enough to read in a sitting, and the properties that matter
for a gateway are theorems: no head is misread, a message can never be
delimited two ways, a body arrives at the copy exactly as framed, and a
well-formed chunked body is never refused.
