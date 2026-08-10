# Changelog

All notable changes to NetMap Portable are documented in this file.

## 0.5.0 — 2026-08-10

### Added
- Fast topology and opt-in deep-inspection profiles for PCAP imports
- Dedicated Packet inspection workspace with search, pagination, endpoint and
  port metadata, frame lengths, timestamps, and optional hexadecimal previews
- Individually configurable MAC collection, passive DNS naming, TCP flags, and
  bounded frame previews; sensitive byte previews remain disabled by default
- Ethernet MAC extraction and offline vendor identification using bundled
  IEEE MA-L, MA-M, and MA-S assignment data
- MAC and vendor display in device details and topology labels, plus MAC/vendor
  search and CSV export fields
- Inferred Purdue Model levels with an optional Purdue-organized topology

### Changed
- PCAP imports can retain per-packet metadata when deep inspection is enabled,
  while the default fast profile keeps the existing low-overhead flow path
- Import controls now explain the performance, storage, and privacy tradeoffs
  of every inspection option before processing begins
- Device inspection surfaces hardware identity and Purdue placement alongside
  the existing OT role and IEC 62443 zone information

### Security and privacy
- Locally administered, multicast, broadcast, and invalid MAC addresses do not
  receive speculative vendor assignments
- Frame previews are capped at 256 bytes by the backend and imported content is
  treated only as data; it is never executed

### Validation
- Added backend coverage for vendor matching, MAC normalization, deep packet
  persistence, packet queries, and bounded frame previews

## 0.4.0 — 2026-08-07

### Added
- OT / ICS protocol filtering and well-known-port inference for Modbus, DNP3,
  EtherNet/IP, BACnet, OPC UA, S7comm, IEC 104, FINS, and HART-IP
- Inferred and manually assignable OT asset roles and IEC 62443-style security
  zones, with optional zone grouping and cross-zone conduit highlighting
- Baseline anomaly detection for new host pairs, protocols, ports, and traffic
  spikes, plus first-seen timeline playback
- Direction-aware two-hop hover tracing for inbound, outbound, or bidirectional
  communication paths
- Adjustable host spacing, persistent drag positions, adaptive labels, and
  plain-language help throughout the analysis controls
- Offline **Test PCAP** chooser with seven bundled Wireshark and Netresec OT
  training captures, source attribution, and SHA-256 verification details
- Import mode control to replace the current map safely or merge new captures
  into it

### Fixed
- Clearing a protocol filter no longer makes restored hosts disappear or lose
  their saved positions
- Initial maps now run a real layout instead of stacking every host at one point
- Failed, cancelled, and zero-flow imports leave the current map unchanged
- Linux cooked-capture packets in bundled PCAPs are now decoded alongside
  Ethernet packets

### Changed
- Graph updates synchronize elements incrementally and preserve positions across
  filtering and timeline changes
- Portable builds copy the complete offline PCAP catalog beside the executable
  and include it in the generated checksum manifest

## 0.3.0 — 2026-08-04

### Added
- Investigation / Live workspace tabs
- Live NIC capture via tshark (Wireshark CLI) with Start/Stop, adapter picker, and optional BPF filter
- Real-time map updates from live capture batches (throttled, positions preserved)
- Demo live stream when running in the browser without Tauri

### Changed
- Network map refreshes elements incrementally instead of remounting on every dataset change

## 0.2.0 — 2026-08-04

### Added
- One-line-per-host-pair connection mode with expandable port details
- Hide / show connection lines toolbar control
- Internal-only and external-only host scope filters
- Renamable project title (persisted locally)
- Passiveable pair/flow cap and connection label toggle for dense maps

### Fixed
- Host click no longer clears the details pane
- Hosts can be dragged more than once (no longer freeze after move)
- Dense-map drag responsiveness (fade edges while moving, haystack edges)

### Changed
- Default connection mode is aggregate (one link per host pair)
- Connection labels off by default

## 0.1.0 — 2026-08-03

- Initial portable Tauri + React network map
- CSV / PCAP import, filters, saved views, diagnostics, offline storage
