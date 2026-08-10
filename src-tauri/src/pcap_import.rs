use crate::db;
use crate::error::{AppError, Result};
use crate::models::{FlowRecord, ImportProgress, ImportResult, PacketRecord, PcapImportOptions};
use etherparse::{LinkSlice, NetSlice, SlicedPacket, TransportSlice};
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
    options: &PcapImportOptions,
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
        options,
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
    options: &PcapImportOptions,
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
    let mut hostname_batch = Vec::new();
    let mut accepted = 0_u64;
    let mut skipped = 0_u64;
    let mut consumed = 0_u64;
    let mut legacy_linktype = None;
    let mut legacy_fraction_divisor = 1_000_u64;
    let mut interfaces: Vec<(Linktype, u64, u64)> = Vec::new();

    loop {
        if cancelled.load(Ordering::Relaxed) {
            if !batch.is_empty() {
                db::insert_batch(connection, import_id, &batch)?;
            }
            if !hostname_batch.is_empty() {
                db::upsert_hostnames(connection, &hostname_batch)?;
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
                        legacy_linktype =
                            supported_linktype(header.network).then_some(header.network);
                        legacy_fraction_divisor =
                            if matches!(header.magic_number, 0xa1b2_3c4d | 0x4d3c_b2a1) {
                                1_000_000
                            } else {
                                1_000
                            };
                        (false, None)
                    }
                    PcapBlockOwned::Legacy(packet) if legacy_linktype.is_some() => {
                        let timestamp = i64::from(packet.ts_sec) * 1_000
                            + (u64::from(packet.ts_usec) / legacy_fraction_divisor) as i64;
                        (
                            true,
                            decode_packet_with_linktype(
                                packet.data,
                                Some(timestamp),
                                legacy_linktype.unwrap(),
                                options,
                            ),
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
                            .filter(|(linktype, _, _)| supported_linktype(*linktype))
                            .and_then(|(linktype, resolution, offset)| {
                                let timestamp =
                                    (packet.decode_ts_f64(*offset, *resolution) * 1_000.0) as i64;
                                decode_packet_with_linktype(packet.data, Some(timestamp), *linktype, options)
                            });
                        (true, decoded)
                    }
                    PcapBlockOwned::NG(Block::SimplePacket(packet))
                        if interfaces
                            .first()
                            .is_some_and(|(linktype, _, _)| supported_linktype(*linktype)) =>
                    {
                        let linktype = interfaces.first().unwrap().0;
                        (
                            true,
                            decode_packet_with_linktype(packet.data, None, linktype, options),
                        )
                    }
                    PcapBlockOwned::NG(Block::SimplePacket(_)) => (true, None),
                    _ => (false, None),
                };
                consumed = consumed.saturating_add(offset as u64);
                reader.consume(offset);
                match decoded {
                    Some(mut decoded) => {
                        if let Some(packet) = decoded.flow.packet.as_mut() {
                            packet.packet_number = accepted + skipped + 1;
                        }
                        batch.push(decoded.flow);
                        if options.dns_hostnames {
                            hostname_batch.extend(decoded.hostnames);
                        }
                        accepted += 1;
                    }
                    None if packet_seen => skipped += 1,
                    None => {}
                }
                if batch.len() >= BATCH_SIZE {
                    db::insert_batch(connection, import_id, &batch)?;
                    batch.clear();
                    if !hostname_batch.is_empty() {
                        db::upsert_hostnames(connection, &hostname_batch)?;
                        hostname_batch.clear();
                    }
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
    if !hostname_batch.is_empty() {
        db::upsert_hostnames(connection, &hostname_batch)?;
    }
    Ok(ImportResult {
        import_id: import_id.into(),
        accepted,
        skipped,
        cancelled: false,
        warnings: Vec::new(),
    })
}

pub struct DecodedPacket {
    pub flow: FlowRecord,
    pub hostnames: Vec<(String, String, Option<i64>)>,
}

#[cfg(test)]
fn decode_packet(packet: &[u8], timestamp: Option<i64>) -> Option<FlowRecord> {
    decode_packet_with_hostnames(packet, timestamp).map(|decoded| decoded.flow)
}

pub fn decode_packet_with_hostnames(
    packet: &[u8],
    timestamp: Option<i64>,
) -> Option<DecodedPacket> {
    decode_packet_with_linktype(packet, timestamp, Linktype::ETHERNET, &PcapImportOptions::default())
}

fn supported_linktype(linktype: Linktype) -> bool {
    matches!(linktype, Linktype::ETHERNET | Linktype::LINUX_SLL)
}

fn decode_packet_with_linktype(
    packet: &[u8],
    timestamp: Option<i64>,
    linktype: Linktype,
    options: &PcapImportOptions,
) -> Option<DecodedPacket> {
    let sliced = match linktype {
        Linktype::ETHERNET => SlicedPacket::from_ethernet(packet).ok()?,
        Linktype::LINUX_SLL => SlicedPacket::from_linux_sll(packet).ok()?,
        _ => return None,
    };
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
    let (frame_source_mac, frame_destination_mac) = match sliced.link.as_ref() {
        Some(LinkSlice::Ethernet2(ethernet)) => (
            crate::vendor::normalize_mac(ethernet.source()),
            crate::vendor::normalize_mac(ethernet.destination()),
        ),
        _ => (None, None),
    };
    let source_mac = match sliced.link.as_ref() {
        Some(LinkSlice::Ethernet2(ethernet)) if options.mac_addresses && is_local_address(&source_ip) => {
            crate::vendor::normalize_mac(ethernet.source())
        }
        _ => None,
    };
    let mut hostnames = Vec::new();
    let mut tcp_flags = None;
    let (source_port, destination_port, protocol) = match sliced.transport {
        Some(TransportSlice::Tcp(tcp)) => {
            if options.tcp_flags {
                let flags = [(tcp.syn(), "SYN"), (tcp.ack(), "ACK"), (tcp.fin(), "FIN"), (tcp.rst(), "RST"), (tcp.psh(), "PSH"), (tcp.urg(), "URG")]
                    .into_iter().filter_map(|(set, name)| set.then_some(name)).collect::<Vec<_>>().join(" ");
                tcp_flags = (!flags.is_empty()).then_some(flags);
            }
            (Some(tcp.source_port()), Some(tcp.destination_port()), "TCP")
        }
        Some(TransportSlice::Udp(udp)) => {
            if matches!(udp.source_port(), 53 | 5353) || matches!(udp.destination_port(), 53 | 5353)
            {
                hostnames.extend(
                    parse_dns_hostnames(udp.payload())
                        .into_iter()
                        .map(|(ip, hostname)| (ip, hostname, timestamp)),
                );
            }
            (Some(udp.source_port()), Some(udp.destination_port()), "UDP")
        }
        Some(TransportSlice::Icmpv4(_)) => (None, None, "ICMP"),
        Some(TransportSlice::Icmpv6(_)) => (None, None, "ICMPV6"),
        _ => (None, None, network_protocol),
    };
    let packet_record = options.packet_indexing.then(|| PacketRecord {
        packet_number: 0,
        timestamp,
        source_ip: source_ip.clone(),
        destination_ip: destination_ip.clone(),
        source_mac: options.mac_addresses.then_some(frame_source_mac).flatten(),
        destination_mac: options.mac_addresses.then_some(frame_destination_mac).flatten(),
        source_port,
        destination_port,
        protocol: protocol.into(),
        length: packet.len() as u64,
        tcp_flags,
        payload_preview: (options.payload_preview_bytes > 0).then(|| {
            packet.iter().take(options.payload_preview_bytes.min(256) as usize)
                .map(|byte| format!("{byte:02X}")).collect::<Vec<_>>().join(" ")
        }),
    });
    Some(DecodedPacket {
        flow: FlowRecord {
            source_ip,
            destination_ip,
            source_mac,
            source_port,
            destination_port,
            protocol: protocol.into(),
            bytes: packet.len() as u64,
            packets: 1,
            timestamp,
            packet: packet_record,
        },
        hostnames,
    })
}

fn is_local_address(value: &str) -> bool {
    value.parse::<std::net::IpAddr>().is_ok_and(|address| match address {
        std::net::IpAddr::V4(ip) => ip.is_private() || ip.is_link_local() || ip.is_loopback(),
        std::net::IpAddr::V6(ip) => ip.is_unique_local() || ip.is_unicast_link_local() || ip.is_loopback(),
    })
}

fn parse_dns_hostnames(packet: &[u8]) -> Vec<(String, String)> {
    if packet.len() < 12 || u16::from_be_bytes([packet[2], packet[3]]) & 0x8000 == 0 {
        return Vec::new();
    }
    let questions = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let answers = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let mut offset = 12;
    for _ in 0..questions {
        let Some((_, next)) = parse_dns_name(packet, offset) else {
            return Vec::new();
        };
        offset = next;
        if offset + 4 > packet.len() {
            return Vec::new();
        }
        offset += 4;
    }

    let mut observations = Vec::new();
    for _ in 0..answers {
        let Some((hostname, next)) = parse_dns_name(packet, offset) else {
            break;
        };
        offset = next;
        if offset + 10 > packet.len() {
            break;
        }
        let record_type = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let data_length = u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]) as usize;
        offset += 10;
        if offset + data_length > packet.len() {
            break;
        }
        let address = match (record_type, data_length) {
            (1, 4) => Some(
                std::net::Ipv4Addr::new(
                    packet[offset],
                    packet[offset + 1],
                    packet[offset + 2],
                    packet[offset + 3],
                )
                .to_string(),
            ),
            (28, 16) => <[u8; 16]>::try_from(&packet[offset..offset + 16])
                .ok()
                .map(std::net::Ipv6Addr::from)
                .map(|address| address.to_string()),
            _ => None,
        };
        if let Some(address) = address {
            observations.push((address, hostname));
        }
        offset += data_length;
    }
    observations
}

fn parse_dns_name(packet: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut cursor = start;
    let mut consumed = None;
    let mut jumps = 0;
    loop {
        let length = *packet.get(cursor)?;
        if length & 0xc0 == 0xc0 {
            let low = *packet.get(cursor + 1)? as usize;
            let pointer = (((length & 0x3f) as usize) << 8) | low;
            consumed.get_or_insert(cursor + 2);
            cursor = pointer;
            jumps += 1;
            if jumps > 16 {
                return None;
            }
            continue;
        }
        if length == 0 {
            let end = consumed.unwrap_or(cursor + 1);
            let name = labels.join(".").to_ascii_lowercase();
            if name.is_empty() || name.len() > 253 {
                return None;
            }
            return Some((name, end));
        }
        if length > 63 {
            return None;
        }
        let label_start = cursor + 1;
        let label_end = label_start + length as usize;
        let label = std::str::from_utf8(packet.get(label_start..label_end)?).ok()?;
        if label.is_empty()
            || label
                .chars()
                .any(|character| character.is_control() || character.is_whitespace())
        {
            return None;
        }
        labels.push(label);
        cursor = label_end;
        if labels.len() > 32 {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    fn ipv4_udp_packet() -> Vec<u8> {
        vec![
            0, 1, 2, 3, 4, 5, 0x00, 0x1b, 0x44, 0x11, 0x3a, 0xb7, 0x08, 0x00, // Ethernet
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
        assert_eq!(flow.source_mac.as_deref(), Some("00:1B:44:11:3A:B7"));
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
    fn extracts_passive_dns_a_record_hostname() {
        let response = [
            0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, // header
            4, b'h', b'o', b's', b't', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o',
            b'm', 0, 0, 1, 0, 1, // question
            0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 10, // answer
        ];
        assert_eq!(
            parse_dns_hostnames(&response),
            vec![("192.0.2.10".into(), "host.example.com".into())]
        );
    }

    #[test]
    fn imports_legacy_pcap_without_counting_headers_as_skipped() {
        let path = temporary_legacy_pcap();
        let database =
            std::env::temp_dir().join(format!("netmap-{}.sqlite3", uuid::Uuid::new_v4()));
        let mut connection = crate::db::open(&database).unwrap();
        let deep_options = PcapImportOptions {
            packet_indexing: true,
            tcp_flags: true,
            payload_preview_bytes: 32,
            ..PcapImportOptions::default()
        };
        let result = import(
            &mut connection,
            &path,
            "pcap-test",
            &AtomicBool::new(false),
            &deep_options,
            |_| {},
        )
        .unwrap();
        let packet_page = crate::db::query_packets(&connection, 10, 0, None).unwrap();
        assert_eq!(packet_page.total, 1);
        assert_eq!(packet_page.packets[0].source_mac.as_deref(), Some("00:1B:44:11:3A:B7"));
        assert!(packet_page.packets[0].payload_preview.is_some());
        let _ = std::fs::remove_file(path);
        drop(connection);
        let _ = std::fs::remove_file(database);
        assert_eq!(result.accepted, 1);
        assert_eq!(result.skipped, 0);
    }

    #[test]
    fn imports_real_bundled_ot_captures() {
        let capture_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("test-pcaps");
        for (file_name, expected_service_port, expected_minimum_nodes) in [
            ("wireshark-modbus-tcp-float.pcap", 502, 1),
            ("wireshark-s7comm-plc-status.pcap", 102, 1),
            ("wireshark-dnp3-select-operate.pcap", 20_000, 1),
            ("wireshark-iec104.pcap", 2_404, 1),
            ("wireshark-hart-ip.pcap", 5_094, 1),
            ("netresec-4sics-geek-lounge-2015-10-20.pcap", 102, 10),
            ("netresec-s4x15-bacnet-fiu.pcap", 47_808, 10),
        ] {
            let database = std::env::temp_dir().join(format!(
                "netmap-ot-{}-{}.sqlite3",
                file_name,
                uuid::Uuid::new_v4()
            ));
            let mut connection = crate::db::open(&database).unwrap();
            let result = import(
                &mut connection,
                &capture_root.join(file_name),
                &format!("real-{file_name}"),
                &AtomicBool::new(false),
                &PcapImportOptions::default(),
                |_| {},
            )
            .unwrap();
            assert!(
                result.accepted > 0,
                "expected at least one supported IP flow in {file_name}"
            );
            let graph =
                crate::db::query_graph(&connection, &crate::models::GraphFilters::default())
                    .unwrap();
            assert!(
                graph.nodes.len() >= expected_minimum_nodes,
                "expected at least {expected_minimum_nodes} IP nodes in {file_name}, got {}",
                graph.nodes.len()
            );
            assert!(
                graph.edges.iter().any(|edge| {
                    edge.source_port == Some(expected_service_port)
                        || edge.destination_port == Some(expected_service_port)
                }),
                "expected service port {expected_service_port} in {file_name}"
            );
            drop(connection);
            let _ = std::fs::remove_file(database);
        }
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
            &PcapImportOptions::default(),
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
