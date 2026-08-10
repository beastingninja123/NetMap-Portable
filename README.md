# NetMap Portable

NetMap Portable is an offline Windows desktop application for turning packet
captures and Security Onion exports into an explorable network map. It is
designed to run from a USB drive without admin rights, an internet connection,
Npcap, or a system-wide database.

## Supported input

- Legacy PCAP and PCAPNG captures
- Ethernet and VLAN traffic
- IPv4 and IPv6 metadata
- TCP, UDP, ICMP, and other IP protocol metadata
- OT / ICS protocol names from analyzer exports, plus well-known-port inference
  for Modbus, DNP3, EtherNet/IP, BACnet, OPC UA, S7comm, IEC 104, FINS, and
  HART-IP when a capture only identifies TCP or UDP
- Security Onion / ECS CSV (`source.ip`, `destination.ip`, ports, protocol,
  timestamps, bytes, and packets)
- Zeek-style CSV (`id.orig_h`, `id.resp_h`, `id.orig_p`, `id.resp_p`)
- Arbitrary connection CSV through the column-mapping wizard

PCAP imports offer two local processing profiles. **Fast topology** retains
only aggregated connection metadata for large captures. **Deep inspection**
also indexes supported IP packets for the Packet inspection tab. MAC
addresses, passive DNS names, TCP flags, and a bounded hexadecimal frame
preview can be enabled or disabled independently. Frame previews are off by
default because captured bytes can contain sensitive content; imported bytes
are displayed only as data and are never executed.

## Map interaction

- Hover a host to keep its direct peers and second-hop paths prominent while
  unrelated hosts and links fade.
- Hostname and IP labels remain visible at low zoom with adaptive label sizing.
- Use **Host spacing** to compact or spread the selected layout, then drag any
  host to fine-tune its position.
- Standard and OT / ICS protocols can be filtered independently or combined.
- OT roles and IEC 62443-style security zones are inferred locally and can be
  overridden per host. Cross-zone links can be highlighted as conduits.
- Ethernet captures associate locally sourced IPs with observed MAC addresses
  and identify globally assigned vendors from a bundled offline IEEE registry
  snapshot. Private and multicast MACs do not receive speculative vendor names.
- Organize the topology by subnet, IEC 62443-style zone, or inferred Purdue
  Model level.
- Baseline analysis flags later host pairs, protocols, ports, and traffic
  spikes; timeline playback reveals flows by their first-seen timestamp.
- Hover tracing can follow both directions, outbound traffic, or inbound
  traffic for two hops.

## Offline OT lab captures

Use **Test PCAP** in the Project panel to choose from two multi-host ICS lab
captures (12 and 15 IP hosts) plus five focused protocol captures for
Modbus/TCP, Siemens S7comm, DNP3, IEC 104, and HART-IP. The unmodified files
live in `test-pcaps/` beside the portable executable and are copied into every
USB build, so the chooser works offline.
See `test-pcaps/SOURCES.md` for source links and SHA-256 verification guidance.

## Development

Prerequisites:

- Node.js 20 or newer
- Rust stable with the MSVC target
- Visual Studio 2022 C++ Build Tools
- WebView2 for development

```powershell
npm install
npm run test
npm run build
npm run desktop:dev
```

Rust tests can be run with:

```powershell
cargo test --manifest-path src-tauri/Cargo.toml
```

## Build the USB folder

```powershell
npm run portable
```

The script creates `portable/NetMap-Portable/`, copies the release executable
and fixed WebView2 runtime, copies the offline `test-pcaps/` catalog, creates an empty portable `data/projects/`
directory, and writes SHA-256 checksums. Copy the whole `NetMap-Portable`
folder to the USB drive and launch `NetMap Portable.exe`.

The fixed WebView2 runtime must exist in
`src-tauri/WebView2.FixedVersionRuntime/` before packaging. Obtain the
Microsoft Evergreen Standalone Fixed Version x64 runtime on a connected build
machine, extract it there, and retain its license files. The target air-gapped
machine does not need WebView2 installed.

For Windows 10 machines that do not already have WebView2, format the USB drive
as NTFS. Fixed WebView2 v120 and newer uses an AppContainer renderer and needs
the NTFS read/execute permissions applied by the portable build script. Windows
11 and Windows 10 machines with the Evergreen runtime can also launch from
exFAT, but NTFS is the dependable fully self-contained option.

## Security and portability

- The app makes no network requests and contains no update client.
- Capture parsing is streaming and never executes imported content.
- Project databases and settings live below `data/` beside the executable.
- CSV exported by the app escapes values that spreadsheet applications could
  interpret as formulas.
- The Tauri command surface and content security policy are intentionally
  narrow.

For very dense datasets, use time, protocol, CIDR, or traffic thresholds and
subnet grouping before rendering. Source records are aggregated into flows so
multi-million-row imports remain queryable.
# React + TypeScript + Vite

This template provides a minimal setup to get React working in Vite with HMR and some Oxlint rules.

Currently, two official plugins are available:

- [@vitejs/plugin-react](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react) uses [Oxc](https://oxc.rs)
- [@vitejs/plugin-react-swc](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react-swc) uses [SWC](https://swc.rs/)

## React Compiler

The React Compiler is not enabled on this template because of its impact on dev & build performances. To add it, see [this documentation](https://react.dev/learn/react-compiler/installation).

## Expanding the Oxlint configuration

If you are developing a production application, we recommend enabling type-aware lint rules by installing `oxlint-tsgolint` and editing `.oxlintrc.json`:

```json
{
  "$schema": "./node_modules/oxlint/configuration_schema.json",
  "plugins": ["react", "typescript", "oxc"],
  "options": {
    "typeAware": true
  },
  "rules": {
    "react/rules-of-hooks": "error",
    "react/only-export-components": ["warn", { "allowConstantExport": true }]
  }
}
```

See the [Oxlint rules documentation](https://oxc.rs/docs/guide/usage/linter/rules) for the full list of rules and categories.
