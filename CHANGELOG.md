# Changelog

All notable changes to NetMap Portable are documented in this file.

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
