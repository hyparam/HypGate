#!/usr/bin/env python3
"""Pin the runtime's blocking sites.

The verified core proves every loop terminates, given that each effect call
returns. Whether a blocking call returns is a property of the kernel, so it
cannot be proved; what can be checked is that every such call is known and
has a stated unblock mechanism. This script scans gateway-runtime's
production code (test modules, test files, and test support excluded) for
calls that can block the calling thread, names each by file, enclosing
function, and kind, and fails when that set differs from the list below or
when docs/blocking-sites.md does not name a site's function. A new blocking
call cannot appear without a row saying what unblocks it.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "crates" / "gateway-runtime" / "src"
DOC = ROOT / "docs" / "blocking-sites.md"

# What blocks, by the call that does it. Raw socket reads and writes all pass
# through `SocketIo::perform` (the one place a timeout is armed), so the
# generic read/write methods are not listed; the sites that reach a file
# descriptor some other way are.
KINDS = [
    ("accept", r"\.accept\(\)"),
    ("connect", r"connect_timeout\("),
    ("resolve", r"to_socket_addrs\(\)"),
    ("socket-op", r"\(self\.operation\)\(self\.socket\)"),
    ("handshake", r"complete_io\("),
    ("peek", r"\.peek\("),
    ("signal-read", r"reader\.read\(&mut byte\)"),
    ("file-read", r"read_to_end\(|fs::read\(|self\.reader\.read\(room\)"),
    ("fsync", r"sync_all\(\)"),
    ("condvar-wait", r"\.wait\(state\)|wait_timeout\("),
    ("channel-recv", r"\.recv\(\)|recv_timeout\("),
    ("join", r"\.join\(\)"),
    ("sleep", r"thread::sleep\("),
]

EXPECTED = """\
credited_job.rs:JobPool::new:channel-recv
credited_job.rs:Pending::wait:channel-recv
disk_log.rs:DiskLog::shutdown:join
disk_log.rs:DiskLog::shutdown:sleep
disk_log.rs:DurableWrite::sync:fsync
disk_log.rs:AuditLog::append:channel-recv
disk_log.rs:Source::read_exact:file-read
disk_log/queue.rs:Queue::enqueue:condvar-wait
disk_log/queue.rs:Queue::recv:condvar-wait
disk_log/rotation.rs:create_segment:fsync
disk_log/rotation.rs:SegmentIo::seal:fsync
disk_log/rotation.rs:SegmentIo::sync:fsync
main.rs:bounded_file:file-read
net.rs:Io::perform:socket-op
net.rs:Tls::handshake:handshake
server.rs:ClientWatch::finish:join
server.rs:ClientWatch::start:peek
server.rs:ClientWatch::start:sleep
server.rs:Effects::accept:accept
server.rs:wake_accept:connect
server/connections.rs:ConnectionSlots::wait_drained:condvar-wait
server/workers.rs:WorkerSlots::wait_drained:condvar-wait
shipping.rs:Engine::wait:sleep
shipping.rs:Shipper::shutdown:channel-recv
shipping.rs:Shipper::shutdown:join
shipping/client.rs:open_socket:connect
shipping/lookup.rs:Lookup::new:resolve
shipping/lookup.rs:Lookup::resolve:channel-recv
shipping/lookup.rs:Lookup::with:channel-recv
shipping/state.rs:read_bounded:file-read
shipping/state.rs:write_private:fsync
signal.rs:on_termination:signal-read
transport.rs:open_socket:connect
transport/resolver.rs:Resolver::resolve:resolve
"""

FN = re.compile(r"\bfn\s+([A-Za-z_0-9]+)\s*[<(]")
ATTR = re.compile(r"^\s*#\[")


def strip_generics(text):
    """Remove balanced `<...>` groups so `impl<T: Io<X>> A for B<C>` reads `impl A for B`."""
    out, depth = [], 0
    for ch in text.replace("->", ""):
        if ch == "<":
            depth += 1
        elif ch == ">" and depth:
            depth -= 1
        elif depth == 0:
            out.append(ch)
    return "".join(out)


IMPL = re.compile(r"^impl\s+(?:([A-Za-z_0-9:]+)\s+for\s+)?([A-Za-z_0-9:]+)")


def enclosing(lines, index):
    """The `Impl::fn` or `fn` name of the function containing `index`."""
    fn_at, name = None, None
    for k in range(index, -1, -1):
        m = FN.search(lines[k][1].split("//", 1)[0])
        if m:
            fn_at, name = k, m.group(1)
            break
    if name is None:
        return "?"
    for k in range(fn_at, -1, -1):
        line = lines[k][1]
        if line.startswith("impl"):
            m = IMPL.match(strip_generics(line))
            if m:
                return f"{(m.group(1) or m.group(2)).split('::')[-1]}::{name}"
            break
        if k != fn_at and re.match(r"^(pub(\([^)]*\))?\s+)?fn\s", line):
            break
        if k != fn_at and line.startswith("}"):
            break
    return name


def production_lines(text):
    """Yield (line_number, line) for lines outside `#[cfg(test)]` items."""
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.strip() == "#[cfg(test)]":
            # Skip attributes, then the item: a one-liner or a braced block.
            j = i + 1
            while j < len(lines) and ATTR.match(lines[j]):
                j += 1
            depth = 0
            seen_brace = False
            while j < len(lines):
                depth += lines[j].count("{") - lines[j].count("}")
                seen_brace = seen_brace or "{" in lines[j]
                j += 1
                if seen_brace and depth <= 0:
                    break
                if not seen_brace and lines[j - 1].rstrip().endswith(";"):
                    break
            i = j
            continue
        yield i + 1, line
        i += 1


def scan():
    found = set()
    for path in sorted(SRC.rglob("*.rs")):
        rel = path.relative_to(SRC).as_posix()
        if rel.endswith("/tests.rs") or "/tests/" in rel or rel.startswith("test_support"):
            continue
        lines = list(production_lines(path.read_text()))
        for index, (_, line) in enumerate(lines):
            code = line.split("//", 1)[0]
            for kind, pattern in KINDS:
                if re.search(pattern, code):
                    found.add(f"{rel}:{enclosing(lines, index)}:{kind}")
    return found


def main():
    actual = scan()
    expected = set(EXPECTED.split())
    if actual != expected:
        print("blocking sites changed; update scripts/check_blocking_sites.py and docs/blocking-sites.md", file=sys.stderr)
        for site in sorted(expected - actual):
            print(f"- {site}", file=sys.stderr)
        for site in sorted(actual - expected):
            print(f"+ {site}", file=sys.stderr)
        return 1
    doc = DOC.read_text()
    functions = {site.split(":", 1)[1].rsplit(":", 1)[0] for site in expected}
    missing = sorted(name for name in functions if f"`{name}`" not in doc)
    if missing:
        print(f"docs/blocking-sites.md has no row naming: {', '.join(missing)}", file=sys.stderr)
        return 1
    print(f"blocking sites: {len(expected)} pinned, each with a documented unblock mechanism")
    return 0


if __name__ == "__main__":
    sys.exit(main())
