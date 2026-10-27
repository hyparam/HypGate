# Audit log retention

HypGate starts a new audit session per process start and automatically splits it
into numbered files at the configured size or age threshold. It never truncates or reuses
a log. Retention is a separate operator action, after a log has been closed and
any required shipping has completed; it is not part of the durability proof.

## Archive closed logs

Keep an archive directory separate from the directory used by running gateways.
It must be owned by your user and private (mode 700). Only move a session there once
its gateway has stopped and any shipper reading it has finished. Keep its original
file and every numbered segment together, with their names unchanged until all
shipping or replay is complete. A successful
`hypgate ship ROOT.json LOG` can finish uploading an old log before archival.
Do not place shipper identity or checkpoint files in the archive.

Archive filenames must use `session-<name>.log`, where the name contains ASCII
letters, numbers, hyphens, or underscores and begins with a letter or number.
Numbered segments may additionally end in a dot followed by 6 to 20 digits.
Moving a closed file into the archive preserves its last-modified time.

## Preview and apply

The installer provides `hypgate-retain`; it requires Python 3. From a checkout,
use `python3 scripts/hypgate-retain` instead.

```sh
hypgate-retain /private/archive --days 30
hypgate-retain /private/archive --days 30 --apply
```

The first command prints JSON lines naming expired files and their sizes without
deleting them. The second deletes eligible files. An empty result means nothing
was eligible. Invalid log headers are reported as skipped. Errors give a nonzero
exit; deletions already completed are not rolled back.

A file expires only when its last modification is strictly older than the
specified number of 24-hour days. The tool checks the HypGate session header and
its checksum, ignores unrelated names, directories, symlinks, and hard links,
and refuses a symlink archive root or a non-private archive directory. It does
not inspect record bodies or require a complete final exchange: a closed log
from a crashed process can still be archived and eventually expire.

Only run maintenance while nothing writes to or moves files in the archive.
The tool cannot determine whether another process still has a log open or
whether a remote server has acknowledged its contents. Placement in the archive
is the operator's assertion that the file is ready for retention. Deleting a
log deliberately removes local audit evidence; keep backups if required.

A scheduler can run the explicit `--apply` command against this archive. The
serving process rotates files but never deletes them. Rotation alone does not
bound total disk usage; deletion remains this separate operator action. See
[automatic rotation](disk-logging.md#automatic-rotation).
