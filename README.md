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
- Security Onion / ECS CSV (`source.ip`, `destination.ip`, ports, protocol,
  timestamps, bytes, and packets)
- Zeek-style CSV (`id.orig_h`, `id.resp_h`, `id.orig_p`, `id.resp_p`)
- Arbitrary connection CSV through the column-mapping wizard

Only connection metadata is retained. Packet payloads are not stored or
displayed.

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
and fixed WebView2 runtime, creates an empty portable `data/projects/`
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
