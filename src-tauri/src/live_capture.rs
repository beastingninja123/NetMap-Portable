use crate::db;
use crate::error::{AppError, Result};
use crate::models::{
    CaptureInterface, FlowRecord, GraphFilters, LiveCaptureUpdate, TsharkInfo,
};
use crate::pcap_import::decode_packet_with_hostnames;
use pcap_parser::{create_reader, Block, Linktype, PcapBlockOwned, PcapError};
use rusqlite::Connection;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const READER_BUFFER: usize = 2 * 1024 * 1024;
const FLUSH_PACKET_THRESHOLD: usize = 500;
const FLUSH_INTERVAL: Duration = Duration::from_millis(500);
const MAX_BPF_LEN: usize = 200;
const GRAPH_LIMIT: u32 = 2_500;

#[derive(Debug)]
pub struct LiveSession {
    pub session_id: String,
    pub import_id: String,
    pub interface_id: String,
    pub interface_name: String,
    pub cancel: Arc<AtomicBool>,
    pub child: Arc<Mutex<Option<Child>>>,
}

pub fn resolve_tshark() -> TsharkInfo {
    if let Some(path) = find_tshark() {
        TsharkInfo {
            available: true,
            path: Some(path.display().to_string()),
            message: "tshark found".into(),
        }
    } else {
        TsharkInfo {
            available: false,
            path: None,
            message: "tshark not found. Install Wireshark (includes tshark) and Npcap, then restart NetMap.".into(),
        }
    }
}

pub fn find_tshark() -> Option<PathBuf> {
    if let Ok(path) = which("tshark") {
        return Some(path);
    }
    let candidates = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
    ];
    candidates
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
}

fn which(command: &str) -> std::io::Result<PathBuf> {
    let output = Command::new("where").arg(command).output()?;
    if !output.status.success() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "command not found",
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let first = text
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "empty where output"))?;
    Ok(PathBuf::from(first))
}

pub fn list_interfaces() -> Result<crate::models::CaptureInterfacesResponse> {
    let info = resolve_tshark();
    let Some(tshark) = info.path.as_ref().map(PathBuf::from) else {
        return Ok(crate::models::CaptureInterfacesResponse {
            tshark: info,
            interfaces: Vec::new(),
        });
    };
    let output = Command::new(&tshark)
        .arg("-D")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| AppError::Invalid(format!("failed to run tshark -D: {error}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(AppError::Invalid(if stderr.is_empty() {
            "tshark -D failed. Capture may require Administrator rights and Npcap.".into()
        } else {
            stderr
        }));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(crate::models::CaptureInterfacesResponse {
        tshark: info,
        interfaces: parse_interface_list(&stdout),
    })
}

pub fn parse_interface_list(stdout: &str) -> Vec<CaptureInterface> {
    stdout
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let (index, rest) = line.split_once('.')?;
            let id = index.trim();
            if id.is_empty() || !id.chars().all(|c| c.is_ascii_digit()) {
                return None;
            }
            let name = rest.trim();
            if name.is_empty() {
                return None;
            }
            Some(CaptureInterface {
                id: id.to_string(),
                name: name.to_string(),
            })
        })
        .collect()
}

pub fn validate_bpf(filter: &str) -> Result<Option<String>> {
    let trimmed = filter.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.len() > MAX_BPF_LEN {
        return Err(AppError::Invalid(format!(
            "BPF filter must be {MAX_BPF_LEN} characters or fewer"
        )));
    }
    if trimmed.chars().any(|c| ";|&`$<>\"'\\!\n\r".contains(c)) {
        return Err(AppError::Invalid(
            "BPF filter contains unsupported characters".into(),
        ));
    }
    Ok(Some(trimmed.to_string()))
}

pub fn validate_interface_id(id: &str, interfaces: &[CaptureInterface]) -> Result<CaptureInterface> {
    interfaces
        .iter()
        .find(|iface| iface.id == id)
        .cloned()
        .ok_or_else(|| AppError::Invalid(format!("unknown capture interface: {id}")))
}

pub fn spawn_tshark(tshark: &Path, interface_id: &str, bpf: Option<&str>) -> Result<Child> {
    let mut command = Command::new(tshark);
    command
        .args(["-i", interface_id, "-n", "-w", "-"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    if let Some(filter) = bpf {
        command.args(["-f", filter]);
    }
    command
        .spawn()
        .map_err(|error| AppError::Invalid(format!("failed to start tshark: {error}")))
}

pub fn run_capture_loop<F>(
    connection: &mut Connection,
    import_id: &str,
    session_id: &str,
    mut stdout: impl Read + Send,
    cancelled: &AtomicBool,
    child: Arc<Mutex<Option<Child>>>,
    mut emit: F,
) -> Result<()>
where
    F: FnMut(LiveCaptureUpdate),
{
    let mut reader = create_reader(READER_BUFFER, &mut stdout)
        .map_err(|error| AppError::Pcap(error.to_string()))?;
    let mut batch: Vec<FlowRecord> = Vec::with_capacity(FLUSH_PACKET_THRESHOLD);
    let mut hostname_batch = Vec::new();
    let mut accepted = 0_u64;
    let mut skipped = 0_u64;
    let mut legacy_ethernet = false;
    let mut legacy_fraction_divisor = 1_000_u64;
    let mut interfaces: Vec<(Linktype, u64, u64)> = Vec::new();
    let mut last_flush = Instant::now();

    let flush = |connection: &mut Connection,
                 batch: &mut Vec<FlowRecord>,
                 hostname_batch: &mut Vec<(String, String, Option<i64>)>,
                 accepted: u64,
                 skipped: u64,
                 status: &str,
                 message: Option<String>,
                 emit: &mut F|
     -> Result<()> {
        if !batch.is_empty() {
            db::insert_batch(connection, import_id, batch)?;
            batch.clear();
        }
        if !hostname_batch.is_empty() {
            db::upsert_hostnames(connection, hostname_batch)?;
            hostname_batch.clear();
        }
        db::rebuild_node_totals(connection)?;
        let dataset = db::query_graph(
            connection,
            &GraphFilters {
                import_ids: Some(vec![import_id.to_string()]),
                limit: Some(GRAPH_LIMIT),
                ..GraphFilters::default()
            },
        )?;
        emit(LiveCaptureUpdate {
            session_id: session_id.into(),
            import_id: import_id.into(),
            status: status.into(),
            packets: accepted + skipped,
            accepted,
            skipped,
            message,
            dataset: Some(dataset),
        });
        Ok(())
    };

    loop {
        if cancelled.load(Ordering::Relaxed) {
            let _ = flush(
                connection,
                &mut batch,
                &mut hostname_batch,
                accepted,
                skipped,
                "stopping",
                None,
                &mut emit,
            );
            break;
        }

        match reader.next() {
            Ok((offset, block)) => {
                let (packet_seen, decoded) = match block {
                    PcapBlockOwned::LegacyHeader(header) => {
                        legacy_ethernet = header.network == Linktype::ETHERNET;
                        legacy_fraction_divisor =
                            if matches!(header.magic_number, 0xa1b2_3c4d | 0x4d3c_b2a1) {
                                1_000_000
                            } else {
                                1_000
                            };
                        (false, None)
                    }
                    PcapBlockOwned::Legacy(packet) if legacy_ethernet => {
                        let timestamp = i64::from(packet.ts_sec) * 1_000
                            + (u64::from(packet.ts_usec) / legacy_fraction_divisor) as i64;
                        (
                            true,
                            decode_packet_with_hostnames(packet.data, Some(timestamp)),
                        )
                    }
                    PcapBlockOwned::Legacy(_) => (true, None),
                    PcapBlockOwned::NG(Block::SectionHeader(_)) => {
                        interfaces.clear();
                        (false, None)
                    }
                    PcapBlockOwned::NG(Block::InterfaceDescription(interface)) => {
                        interfaces.push((
                            interface.linktype,
                            interface.ts_resolution().unwrap_or(1_000_000),
                            interface.ts_offset().max(0) as u64,
                        ));
                        (false, None)
                    }
                    PcapBlockOwned::NG(Block::EnhancedPacket(packet)) => {
                        let decoded = interfaces
                            .get(packet.if_id as usize)
                            .filter(|(linktype, _, _)| *linktype == Linktype::ETHERNET)
                            .and_then(|(_, resolution, offset)| {
                                let timestamp =
                                    (packet.decode_ts_f64(*offset, *resolution) * 1_000.0) as i64;
                                decode_packet_with_hostnames(packet.data, Some(timestamp))
                            });
                        (true, decoded)
                    }
                    PcapBlockOwned::NG(Block::SimplePacket(packet))
                        if interfaces
                            .first()
                            .is_some_and(|(linktype, _, _)| *linktype == Linktype::ETHERNET) =>
                    {
                        (true, decode_packet_with_hostnames(packet.data, None))
                    }
                    PcapBlockOwned::NG(Block::SimplePacket(_)) => (true, None),
                    _ => (false, None),
                };
                reader.consume(offset);
                match decoded {
                    Some(decoded) => {
                        batch.push(decoded.flow);
                        hostname_batch.extend(decoded.hostnames);
                        accepted += 1;
                    }
                    None if packet_seen => skipped += 1,
                    None => {}
                }
                if batch.len() >= FLUSH_PACKET_THRESHOLD || last_flush.elapsed() >= FLUSH_INTERVAL {
                    flush(
                        connection,
                        &mut batch,
                        &mut hostname_batch,
                        accepted,
                        skipped,
                        "capturing",
                        None,
                        &mut emit,
                    )?;
                    last_flush = Instant::now();
                }
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                if cancelled.load(Ordering::Relaxed) {
                    break;
                }
                match reader.refill() {
                    Ok(()) => {}
                    Err(PcapError::Eof) => break,
                    Err(PcapError::Incomplete(_)) => {
                        std::thread::sleep(Duration::from_millis(40));
                    }
                    Err(error) => return Err(AppError::Pcap(error.to_string())),
                }
            }
            Err(error) => return Err(AppError::Pcap(error.to_string())),
        }
    }

    if let Ok(mut guard) = child.lock() {
        if let Some(mut process) = guard.take() {
            let _ = process.kill();
            let _ = process.wait();
        }
    }

    let status = if cancelled.load(Ordering::Relaxed) {
        "cancelled"
    } else {
        "complete"
    };
    flush(
        connection,
        &mut batch,
        &mut hostname_batch,
        accepted,
        skipped,
        status,
        None,
        &mut emit,
    )?;
    db::finish_import(connection, import_id, accepted, skipped, status, None)?;
    emit(LiveCaptureUpdate {
        session_id: session_id.into(),
        import_id: import_id.into(),
        status: status.into(),
        packets: accepted + skipped,
        accepted,
        skipped,
        message: None,
        dataset: db::query_graph(
            connection,
            &GraphFilters {
                import_ids: Some(vec![import_id.to_string()]),
                limit: Some(GRAPH_LIMIT),
                ..GraphFilters::default()
            },
        )
        .ok(),
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tshark_interface_list() {
        let sample = r#"
1. \Device\NPF_{ABC} (Ethernet)
2. \Device\NPF_{DEF} (Wi-Fi)
3. Adapter for loopback traffic capture (Loopback)
"#;
        let interfaces = parse_interface_list(sample);
        assert_eq!(interfaces.len(), 3);
        assert_eq!(interfaces[0].id, "1");
        assert!(interfaces[0].name.contains("Ethernet"));
        assert_eq!(interfaces[2].id, "3");
    }

    #[test]
    fn rejects_dangerous_bpf() {
        assert!(validate_bpf("host 10.0.0.1").unwrap().is_some());
        assert!(validate_bpf("").unwrap().is_none());
        assert!(validate_bpf("tcp; calc").is_err());
        assert!(validate_bpf(&"a".repeat(201)).is_err());
    }

    #[test]
    fn validates_known_interface_ids() {
        let interfaces = parse_interface_list("1. eth0\n2. wlan0\n");
        assert_eq!(validate_interface_id("2", &interfaces).unwrap().name, "wlan0");
        assert!(validate_interface_id("9", &interfaces).is_err());
    }
}
