use crate::db;
use crate::error::{AppError, Result};
use crate::models::{CsvMapping, CsvPreview, FlowRecord, ImportProgress, ImportResult};
use csv::{Reader, ReaderBuilder, StringRecord};
use rusqlite::Connection;
use std::fs::File;
use std::io::{BufReader, Read};
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};

const BATCH_SIZE: usize = 1_000;
const PREVIEW_ROWS: usize = 20;

pub fn preview(path: &Path) -> Result<CsvPreview> {
    let mut reader = csv_reader(path)?;
    let headers = reader
        .headers()?
        .iter()
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    let (detected_format, suggested_mapping) = detect_mapping(&headers)
        .map(|(format, mapping)| (Some(format), Some(mapping)))
        .unwrap_or((None, None));
    let rows = reader
        .records()
        .take(PREVIEW_ROWS)
        .map(|record| record.map(|row| row.iter().map(ToOwned::to_owned).collect()))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(CsvPreview {
        headers,
        detected_format,
        suggested_mapping,
        rows,
    })
}

pub fn import<F>(
    connection: &mut Connection,
    path: &Path,
    import_id: &str,
    explicit_mapping: Option<CsvMapping>,
    cancelled: &AtomicBool,
    mut report: F,
) -> Result<ImportResult>
where
    F: FnMut(ImportProgress),
{
    let total_bytes = path.metadata().ok().map(|metadata| metadata.len());
    let source_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("capture.csv");
    db::start_import(connection, import_id, "csv", source_name)?;
    let outcome = import_inner(
        connection,
        path,
        import_id,
        explicit_mapping,
        cancelled,
        total_bytes,
        &mut report,
    );
    match outcome {
        Ok(result) => {
            let status = if result.cancelled {
                "cancelled"
            } else {
                "complete"
            };
            db::finish_import(
                connection,
                import_id,
                result.accepted,
                result.skipped,
                status,
                None,
            )?;
            report(ImportProgress {
                import_id: import_id.into(),
                phase: status.into(),
                processed: result.accepted + result.skipped,
                accepted: result.accepted,
                skipped: result.skipped,
                total_bytes,
                completed: true,
                cancelled: result.cancelled,
                message: None,
            });
            Ok(result)
        }
        Err(error) => {
            let _ = db::finish_import(
                connection,
                import_id,
                0,
                0,
                "failed",
                Some(&error.to_string()),
            );
            Err(error)
        }
    }
}

fn import_inner<F>(
    connection: &mut Connection,
    path: &Path,
    import_id: &str,
    explicit_mapping: Option<CsvMapping>,
    cancelled: &AtomicBool,
    total_bytes: Option<u64>,
    report: &mut F,
) -> Result<ImportResult>
where
    F: FnMut(ImportProgress),
{
    let mut reader = csv_reader(path)?;
    let headers = reader.headers()?.clone();
    let mapping = match explicit_mapping {
        Some(mapping) => mapping,
        None => detect_mapping(&headers.iter().map(ToOwned::to_owned).collect::<Vec<_>>())
            .map(|(_, mapping)| mapping)
            .ok_or_else(|| {
                AppError::Invalid(
                    "could not detect source/destination fields; provide an explicit mapping"
                        .into(),
                )
            })?,
    };
    let indexes = MappingIndexes::new(&headers, &mapping)?;
    let mut batch = Vec::with_capacity(BATCH_SIZE);
    let mut accepted = 0_u64;
    let mut skipped = 0_u64;
    let mut warnings = Vec::new();

    while let Some(record) = next_record(&mut reader)? {
        if cancelled.load(Ordering::Relaxed) {
            if !batch.is_empty() {
                db::insert_batch(connection, import_id, &batch)?;
            }
            return Ok(ImportResult {
                import_id: import_id.into(),
                accepted,
                skipped,
                cancelled: true,
                warnings,
            });
        }
        match indexes.parse(&record) {
            Ok(flow) => {
                batch.push(flow);
                accepted += 1;
            }
            Err(reason) => {
                skipped += 1;
                if warnings.len() < 20 {
                    warnings.push(format!("row {}: {reason}", accepted + skipped + 1));
                }
            }
        }
        if batch.len() >= BATCH_SIZE {
            db::insert_batch(connection, import_id, &batch)?;
            batch.clear();
            report(ImportProgress {
                import_id: import_id.into(),
                phase: "parsing".into(),
                processed: accepted + skipped,
                accepted,
                skipped,
                total_bytes,
                completed: false,
                cancelled: false,
                message: None,
            });
        }
    }
    if !batch.is_empty() {
        db::insert_batch(connection, import_id, &batch)?;
    }
    Ok(ImportResult {
        import_id: import_id.into(),
        accepted,
        skipped,
        cancelled: false,
        warnings,
    })
}

fn csv_reader(path: &Path) -> Result<Reader<BufReader<File>>> {
    let delimiter = detect_delimiter(path)?;
    Ok(ReaderBuilder::new()
        .delimiter(delimiter)
        .flexible(true)
        .trim(csv::Trim::All)
        .from_reader(BufReader::with_capacity(256 * 1024, File::open(path)?)))
}

fn detect_delimiter(path: &Path) -> Result<u8> {
    let mut file = File::open(path)?;
    let mut sample = [0_u8; 8 * 1024];
    let count = file.read(&mut sample)?;
    let sample = &sample[..count];
    let tabs = sample.iter().filter(|byte| **byte == b'\t').count();
    let commas = sample.iter().filter(|byte| **byte == b',').count();
    Ok(if tabs > commas { b'\t' } else { b',' })
}

fn next_record<R: Read>(reader: &mut Reader<R>) -> Result<Option<StringRecord>> {
    let mut record = StringRecord::new();
    Ok(reader.read_record(&mut record)?.then_some(record))
}

fn detect_mapping(headers: &[String]) -> Option<(String, CsvMapping)> {
    let normalized = headers
        .iter()
        .map(|header| header.trim().to_ascii_lowercase())
        .collect::<Vec<_>>();
    let has = |name: &str| normalized.iter().any(|header| header == name);
    let original = |name: &str| {
        normalized
            .iter()
            .position(|header| header == name)
            .map(|index| headers[index].clone())
    };
    if has("source.ip") && has("destination.ip") {
        return Some((
            "ECS / Security Onion".into(),
            CsvMapping {
                source_ip: original("source.ip")?,
                destination_ip: original("destination.ip")?,
                source_port: original("source.port"),
                destination_port: original("destination.port"),
                protocol: original("network.transport").or_else(|| original("network.protocol")),
                timestamp: original("@timestamp"),
                bytes: original("network.bytes").or_else(|| original("source.bytes")),
                packets: original("network.packets"),
            },
        ));
    }
    if has("id.orig_h") && has("id.resp_h") {
        return Some((
            "Zeek".into(),
            CsvMapping {
                source_ip: original("id.orig_h")?,
                destination_ip: original("id.resp_h")?,
                source_port: original("id.orig_p"),
                destination_port: original("id.resp_p"),
                protocol: original("proto"),
                timestamp: original("ts"),
                bytes: original("orig_bytes").or_else(|| original("resp_bytes")),
                packets: original("orig_pkts").or_else(|| original("resp_pkts")),
            },
        ));
    }
    let source = ["src_ip", "source_ip", "src", "source"]
        .iter()
        .find_map(|name| original(name));
    let destination = ["dst_ip", "destination_ip", "dest_ip", "dst", "destination"]
        .iter()
        .find_map(|name| original(name));
    source.zip(destination).map(|(source_ip, destination_ip)| {
        (
            "Generic flow CSV".into(),
            CsvMapping {
                source_ip,
                destination_ip,
                source_port: ["src_port", "source_port", "sport"]
                    .iter()
                    .find_map(|name| original(name)),
                destination_port: ["dst_port", "destination_port", "dport"]
                    .iter()
                    .find_map(|name| original(name)),
                protocol: ["protocol", "proto"].iter().find_map(|name| original(name)),
                timestamp: ["timestamp", "time", "ts"]
                    .iter()
                    .find_map(|name| original(name)),
                bytes: ["bytes", "total_bytes"]
                    .iter()
                    .find_map(|name| original(name)),
                packets: ["packets", "total_packets"]
                    .iter()
                    .find_map(|name| original(name)),
            },
        )
    })
}

struct MappingIndexes {
    source_ip: usize,
    destination_ip: usize,
    source_port: Option<usize>,
    destination_port: Option<usize>,
    protocol: Option<usize>,
    timestamp: Option<usize>,
    bytes: Option<usize>,
    packets: Option<usize>,
}

impl MappingIndexes {
    fn new(headers: &StringRecord, mapping: &CsvMapping) -> Result<Self> {
        let required = |name: &str| {
            header_index(headers, name)
                .ok_or_else(|| AppError::Invalid(format!("mapped column not found: {name}")))
        };
        let optional =
            |name: &Option<String>| name.as_ref().map(|value| required(value)).transpose();
        Ok(Self {
            source_ip: required(&mapping.source_ip)?,
            destination_ip: required(&mapping.destination_ip)?,
            source_port: optional(&mapping.source_port)?,
            destination_port: optional(&mapping.destination_port)?,
            protocol: optional(&mapping.protocol)?,
            timestamp: optional(&mapping.timestamp)?,
            bytes: optional(&mapping.bytes)?,
            packets: optional(&mapping.packets)?,
        })
    }

    fn parse(&self, row: &StringRecord) -> std::result::Result<FlowRecord, String> {
        let source = parse_ip(row.get(self.source_ip).unwrap_or_default())?;
        let destination = parse_ip(row.get(self.destination_ip).unwrap_or_default())?;
        Ok(FlowRecord {
            source_ip: source.to_string(),
            destination_ip: destination.to_string(),
            source_port: parse_optional(row, self.source_port, "source port")?,
            destination_port: parse_optional(row, self.destination_port, "destination port")?,
            protocol: self
                .protocol
                .and_then(|index| row.get(index))
                .filter(|value| !value.is_empty() && *value != "-")
                .unwrap_or("OTHER")
                .to_ascii_uppercase(),
            timestamp: parse_timestamp(row, self.timestamp)?,
            bytes: parse_optional::<u64>(row, self.bytes, "bytes")?.unwrap_or(0),
            packets: parse_optional::<u64>(row, self.packets, "packets")?.unwrap_or(1),
        })
    }
}

fn header_index(headers: &StringRecord, name: &str) -> Option<usize> {
    headers
        .iter()
        .position(|header| header.eq_ignore_ascii_case(name.trim()))
}

fn parse_ip(value: &str) -> std::result::Result<IpAddr, String> {
    IpAddr::from_str(value.trim()).map_err(|_| format!("invalid IP address: {value}"))
}

fn parse_optional<T: FromStr>(
    row: &StringRecord,
    index: Option<usize>,
    label: &str,
) -> std::result::Result<Option<T>, String> {
    let Some(value) = index.and_then(|index| row.get(index)) else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() || value == "-" {
        return Ok(None);
    }
    value
        .parse()
        .map(Some)
        .map_err(|_| format!("invalid {label}: {value}"))
}

fn parse_timestamp(
    row: &StringRecord,
    index: Option<usize>,
) -> std::result::Result<Option<i64>, String> {
    let Some(value) = index.and_then(|index| row.get(index)) else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() || value == "-" {
        return Ok(None);
    }
    if let Ok(seconds) = value.parse::<f64>() {
        return Ok(Some((seconds * 1_000.0) as i64));
    }
    time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .map(|timestamp| Some((timestamp.unix_timestamp_nanos() / 1_000_000) as i64))
        .map_err(|_| format!("unsupported timestamp: {value}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufWriter, Write};

    #[test]
    fn detects_zeek_mapping_case_insensitively() {
        let headers = vec![
            "TS".into(),
            "id.orig_h".into(),
            "id.resp_h".into(),
            "proto".into(),
        ];
        let (format, mapping) = detect_mapping(&headers).unwrap();
        assert_eq!(format, "Zeek");
        assert_eq!(mapping.source_ip, "id.orig_h");
    }

    #[test]
    fn validates_ip_addresses() {
        assert!(parse_ip("2001:db8::1").is_ok());
        assert!(parse_ip("999.2.3.4").is_err());
    }

    #[test]
    fn parses_unix_and_ecs_timestamps() {
        let unix = StringRecord::from(vec!["1710000000.250"]);
        let ecs = StringRecord::from(vec!["2024-03-09T16:00:00.250Z"]);
        assert_eq!(
            parse_timestamp(&unix, Some(0)).unwrap(),
            Some(1_710_000_000_250)
        );
        assert!(parse_timestamp(&ecs, Some(0)).unwrap().is_some());
    }

    #[test]
    #[ignore = "run explicitly with NETMAP_PERF_ROWS to exercise large streaming imports"]
    fn streaming_csv_performance_fixture() {
        let rows = std::env::var("NETMAP_PERF_ROWS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(100_000);
        let id = uuid::Uuid::new_v4();
        let csv_path = std::env::temp_dir().join(format!("netmap-perf-{id}.csv"));
        let database = std::env::temp_dir().join(format!("netmap-perf-{id}.sqlite3"));
        let mut writer = BufWriter::new(File::create(&csv_path).unwrap());
        writeln!(
            writer,
            "@timestamp,source.ip,destination.ip,source.port,destination.port,network.transport,network.bytes,network.packets"
        )
        .unwrap();
        for index in 0..rows {
            writeln!(
                writer,
                "2026-08-03T12:00:00Z,10.0.{}.1,10.1.{}.2,{},443,tcp,1500,1",
                index % 250,
                (index / 250) % 250,
                10_000 + (index % 50_000)
            )
            .unwrap();
        }
        writer.flush().unwrap();

        let mut connection = crate::db::open(&database).unwrap();
        let started = std::time::Instant::now();
        let result = import(
            &mut connection,
            &csv_path,
            "performance",
            None,
            &AtomicBool::new(false),
            |_| {},
        )
        .unwrap();
        let elapsed = started.elapsed();
        eprintln!(
            "imported {} rows in {:.2?} ({:.0} rows/sec)",
            result.accepted,
            elapsed,
            result.accepted as f64 / elapsed.as_secs_f64()
        );
        assert_eq!(result.accepted, rows);
        assert_eq!(result.skipped, 0);
        drop(connection);
        let _ = std::fs::remove_file(csv_path);
        let _ = std::fs::remove_file(&database);
        let _ = std::fs::remove_file(database.with_extension("sqlite3-wal"));
        let _ = std::fs::remove_file(database.with_extension("sqlite3-shm"));
    }
}
