//! Read-only audit inspection. Body payloads are never printed.
use gateway_core::json::Value;
use gateway_runtime::{
    disk_log::{LogReader, Metadata, ScanError, StoredRecord},
    json_build::{number, object, size, text, write},
};
use std::io::{self, Write};

pub(crate) fn run(path: &str) -> Result<(), &'static str> {
    let file = std::fs::File::open(path).map_err(|_| "cannot open audit log")?;
    let mut reader = LogReader::new(file).map_err(|_| "invalid or incomplete audit header")?;
    let session: String = reader
        .session()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let mut output = io::stdout().lock();
    let mut records = 0u64;
    let error = loop {
        match reader.next_record() {
            Ok(Some(record)) => {
                records = records.checked_add(1).ok_or("record count exhausted")?;
                write_line(
                    &mut output,
                    &scan_row(&session, &record, reader.valid_end()),
                )?;
            }
            Ok(None) => break None,
            Err(error) => break Some(error),
        }
    };
    let status = match error {
        None => "complete",
        Some(ScanError::Incomplete) => "incomplete",
        Some(ScanError::Corrupt) => "corrupt",
        Some(ScanError::Io) => "io_error",
    };
    let summary = object(vec![
        ("type", text("summary")),
        ("session", text(&session)),
        ("records", number(records)),
        ("valid_end", number(reader.valid_end())),
        ("status", text(status)),
    ]);
    write_line(&mut output, &summary)?;
    if error.is_some() {
        Err("scan stopped at invalid tail; file unchanged")
    } else {
        Ok(())
    }
}

fn write_line(output: &mut impl Write, row: &Value) -> Result<(), &'static str> {
    output
        .write_all(&write(row))
        .and_then(|()| output.write_all(b"\n"))
        .map_err(|_| "cannot write scan output")
}

// Body payloads are never printed; metadata fields are decoded with the
// verified codecs, and a metadata payload that does not decode is reported as such.
fn scan_row(session: &str, record: &StoredRecord, valid_end: u64) -> Value {
    let mut row = vec![
        ("type", text("record")),
        ("session", text(session)),
        ("tenant", number(record.tenant)),
        ("request", number(record.request)),
        ("chunk", number(record.chunk)),
        ("kind", text(record.kind.name())),
        ("payload_bytes", size(record.bytes.len())),
        ("valid_end", number(valid_end)),
    ];
    if let Some(direction) = record.direction() {
        row.push((
            "direction",
            text(match direction {
                gateway_runtime::transfer::Direction::Upload => "upload",
                gateway_runtime::transfer::Direction::Download => "download",
            }),
        ));
        return object(row);
    }
    match record.metadata() {
        Some(Metadata::RequestStart(start)) => {
            row.push(("time_ms", number(start.time_ms)));
            row.push(("selector", number(start.selector)));
            row.push((
                "destination",
                text(String::from_utf8_lossy(&start.destination)),
            ));
        }
        Some(Metadata::ResponseHead(head)) => {
            row.push(("time_ms", number(head.time_ms)));
            row.push(("status", number(u64::from(head.status))));
        }
        Some(Metadata::Completion(done)) => {
            row.push(("time_ms", number(done.time_ms)));
            row.push(("outcome", number(u64::from(done.outcome))));
            row.push(("upload_bytes", number(done.upload_bytes)));
            row.push(("download_bytes", number(done.download_bytes)));
        }
        None => {
            row.push(("metadata", text("invalid")));
        }
    }
    object(row)
}
