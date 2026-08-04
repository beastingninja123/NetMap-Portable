use crate::db;
use crate::error::{AppError, Result};
use crate::models::{FlowRecord, ImportProgress, ImportResult};
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use pcap_parser::{create_reader, Block, Linktype, PcapBlockOwned, PcapError};
use rusqlite::Connection;
use std::fs::File;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

const READER_BUFFER: usize = 2 * 1024 * 1024;
const BATCH_SIZE: usize = 2_000;

pub fn import<F>(
    connection: &mut Connection,
    path: &Path,
    import_id: &str,
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
        .unwrap_or("capture.pcap");
    db::start_import(connection, import_id, "pcap", source_name)?;
    let outcome = import_inner(
        connection,
        path,
        import_id,
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
    cancelled: &AtomicBool,
    total_bytes: Option<u64>,
    report: &mut F,
) -> Result<ImportResult>
where
    F: FnMut(ImportProgress),
{
    let file = File::open(path)?;
    let mut reader =
        create_reader(READER_BUFFER, file).map_err(|error| AppError::Pcap(error.to_string()))?;
    let mut batch = Vec::with_capacity(BATCH_SIZE);
    let mut accepted = 0_u64;
    let mut skipped = 0_u64;
    let mut consumed = 0_u64;
    let mut legacy_ethernet = false;
    let mut legacy_fraction_divisor = 1_000_u64;
    let mut interfaces: Vec<(Linktype, u64, u64)> = Vec::new();

    loop {
        if cancelled.load(Ordering::Relaxed) {
            if !batch.is_empty() {
                db::insert_batch(connection, import_id, &batch)?;
            }
            return Ok(ImportResult {
                import_id: import_id.into(),
                accepted,
                skipped,
                cancelled: true,
                warnings: Vec::new(),
            });
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
                        (true, decode_packet(packet.data, Some(timestamp)))
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
                                decode_packet(packet.data, Some(timestamp))
                            });
                        (true, decoded)
                    }
                    PcapBlockOwned::NG(Block::SimplePacket(packet))
                        if interfaces
                            .first()
                            .is_some_and(|(linktype, _, _)| *linktype == Linktype::ETHERNET) =>
                    {
                        (true, decode_packet(packet.data, None))
                    }
                    PcapBlockOwned::NG(Block::SimplePacket(_)) => (true, None),
                    _ => (false, None),
                };
                consumed = consumed.saturating_add(offset as u64);
                reader.consume(offset);
                match decoded {
                    Some(flow) => {
                        batch.push(flow);
                        accepted += 1;
                    }
                    None if packet_seen => skipped += 1,
                    None => {}
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
                        message: Some(format!("{consumed} capture bytes consumed")),
                    });
                }
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => reader
                .refill()
                .map_err(|error| AppError::Pcap(error.to_string()))?,
            Err(error) => return Err(AppError::Pcap(error.to_string())),
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
        warnings: Vec::new(),
    })
}

fn decode_packet(packet: &[u8], timestamp: Option<i64>) -> Option<FlowRecord> {
    let sliced = SlicedPacket::from_ethernet(packet).ok()?;
    let (source_ip, destination_ip, network_protocol) = match sliced.net? {
        NetSlice::Ipv4(ipv4) => (
            ipv4.header().source_addr().to_string(),
            ipv4.header().destination_addr().to_string(),
            "IP",
        ),
        NetSlice::Ipv6(ipv6) => (
            ipv6.header().source_addr().to_string(),
            ipv6.header().destination_addr().to_string(),
            "IPV6",
        ),
        NetSlice::Arp(_) => return None,
    };
    let (source_port, destination_port, protocol) = match sliced.transport {
        Some(TransportSlice::Tcp(tcp)) => {
            (Some(tcp.source_port()), Some(tcp.destination_port()), "TCP")
        }
        Some(TransportSlice::Udp(udp)) => {
            (Some(udp.source_port()), Some(udp.destination_port()), "UDP")
        }
        Some(TransportSlice::Icmpv4(_)) => (None, None, "ICMP"),
        Some(TransportSlice::Icmpv6(_)) => (None, None, "ICMPV6"),
        _ => (None, None, network_protocol),
    };
    Some(FlowRecord {
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        protocol: protocol.into(),
        bytes: packet.len() as u64,
        packets: 1,
        timestamp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    fn ipv4_udp_packet() -> Vec<u8> {
        vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, // Ethernet
            0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2, // IPv4
            0x1f, 0x90, 0, 53, 0, 8, 0, 0, // UDP
        ]
    }

    fn temporary_legacy_pcap() -> std::path::PathBuf {
        let packet = ipv4_udp_packet();
        let mut capture = vec![
            0xd4, 0xc3, 0xb2, 0xa1, // little-endian microsecond magic
            2, 0, 4, 0, // version 2.4
            0, 0, 0, 0, 0, 0, 0, 0, // timezone + accuracy
            0xff, 0xff, 0, 0, // snap length
            1, 0, 0, 0, // Ethernet
            1, 0, 0, 0, // timestamp seconds
            0x20, 0xa1, 0x07, 0, // 500000 microseconds
        ];
        capture.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        capture.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        capture.extend_from_slice(&packet);
        let path = std::env::temp_dir().join(format!("netmap-{}.pcap", uuid::Uuid::new_v4()));
        std::fs::write(&path, capture).unwrap();
        path
    }

    #[test]
    fn decodes_ethernet_ipv4_udp_without_fixture() {
        let flow = decode_packet(&ipv4_udp_packet(), Some(42)).unwrap();
        assert_eq!(flow.source_ip, "10.0.0.1");
        assert_eq!(flow.destination_port, Some(53));
        assert_eq!(flow.protocol, "UDP");
        assert_eq!(flow.timestamp, Some(42));
    }

    #[test]
    fn decodes_vlan_ipv6_tcp_metadata() {
        let mut packet = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x81, 0x00, // Ethernet + VLAN type
            0, 7, 0x86, 0xdd, // VLAN 7 + IPv6 type
            0x60, 0, 0, 0, 0, 20, 6, 64, // IPv6 fixed header
        ];
        packet.extend_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        packet.extend_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        packet.extend_from_slice(&[
            0xc3, 0x50, 0x01, 0xbb, // 50000 -> 443
            0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x02, 0x20, 0, 0, 0, 0, 0,
        ]);

        let flow = decode_packet(&packet, None).unwrap();
        assert_eq!(flow.source_ip, "fd00::1");
        assert_eq!(flow.destination_ip, "fd00::2");
        assert_eq!(flow.destination_port, Some(443));
        assert_eq!(flow.protocol, "TCP");
    }

    #[test]
    fn rejects_truncated_or_non_ip_frames() {
        assert!(decode_packet(&[0; 8], None).is_none());
        let arp = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x06, 0, 1, 8, 0, 6, 4, 0, 1, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];
        assert!(decode_packet(&arp, None).is_none());
    }

    #[test]
    fn imports_legacy_pcap_without_counting_headers_as_skipped() {
        let path = temporary_legacy_pcap();
        let database =
            std::env::temp_dir().join(format!("netmap-{}.sqlite3", uuid::Uuid::new_v4()));
        let mut connection = crate::db::open(&database).unwrap();
        let result = import(
            &mut connection,
            &path,
            "pcap-test",
            &AtomicBool::new(false),
            |_| {},
        )
        .unwrap();
        let _ = std::fs::remove_file(path);
        drop(connection);
        let _ = std::fs::remove_file(database);
        assert_eq!(result.accepted, 1);
        assert_eq!(result.skipped, 0);
    }

    #[test]
    fn cancellation_stops_before_parsing_packets() {
        let path = temporary_legacy_pcap();
        let database =
            std::env::temp_dir().join(format!("netmap-{}.sqlite3", uuid::Uuid::new_v4()));
        let mut connection = crate::db::open(&database).unwrap();
        let result = import(
            &mut connection,
            &path,
            "cancel-test",
            &AtomicBool::new(true),
            |_| {},
        )
        .unwrap();
        let _ = std::fs::remove_file(path);
        drop(connection);
        let _ = std::fs::remove_file(database);
        assert!(result.cancelled);
        assert_eq!(result.accepted, 0);
    }
}
