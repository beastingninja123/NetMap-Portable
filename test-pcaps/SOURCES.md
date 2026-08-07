# Bundled OT test captures

These are unmodified, real protocol captures published by Wireshark and
Netresec for protocol education and ICS/SCADA security training. NetMap never
executes capture content and retains only connection metadata when a capture is
imported.

| Local file | Protocol | Original source |
| --- | --- | --- |
| `netresec-4sics-geek-lounge-2015-10-20.pcap` | Multi-host ICS lab / S7comm | [Netresec 4SICS Geek Lounge](https://www.netresec.com/?page=PCAP4SICS) |
| `netresec-s4x15-bacnet-fiu.pcap` | Multi-host BACnet ICS Village | [Netresec S4x15 ICS Village](https://www.netresec.com/?page=DigitalBond_S4) |
| `wireshark-modbus-tcp-float.pcap` | Modbus/TCP | [Wireshark issue 7902 attachment](https://gitlab.com/wireshark/wireshark/-/work_items/7902) |
| `wireshark-s7comm-plc-status.pcap` | Siemens S7comm | [Wireshark SampleCaptures](https://gitlab.com/wireshark/wireshark/-/wikis/SampleCaptures) |
| `wireshark-dnp3-select-operate.pcap` | DNP3 select/operate | [Wireshark SampleCaptures](https://gitlab.com/wireshark/wireshark/-/wikis/SampleCaptures) |
| `wireshark-iec104.pcap` | IEC 60870-5-104 | [Wireshark SampleCaptures](https://gitlab.com/wireshark/wireshark/-/wikis/SampleCaptures) |
| `wireshark-hart-ip.pcap` | HART-IP TCP and UDP | [Wireshark SampleCaptures](https://gitlab.com/wireshark/wireshark/-/wikis/SampleCaptures) |

The portable build copies this directory beside `NetMap Portable.exe`. The
in-app **Test PCAP** chooser only lists captures from that local directory, so
the feature remains available on an offline or air-gapped USB system.

## SHA-256

| Local file | SHA-256 |
| --- | --- |
| `netresec-4sics-geek-lounge-2015-10-20.pcap` | `8c6ee02dc26b1b5298a7c9b4dc83cc779bd2a3219d5c5cbc51e3d4d325763bc2` |
| `netresec-s4x15-bacnet-fiu.pcap` | `c9209c33b4d2c3b3ae279d543a8bdddbe978bff43a12f4695a8542df60879bfb` |
| `wireshark-modbus-tcp-float.pcap` | `2302cf9c4f83fa7bc4d8c8006f5565dec50d9c5eb7f9eee3de8755b37bfe7908` |
| `wireshark-s7comm-plc-status.pcap` | `e71f81b471bd67da2fd6e40dc69a7179574ba66771c6150cd7bfe232cc07b8a9` |
| `wireshark-dnp3-select-operate.pcap` | `9cc5c193218d78afba25fec251c4e91f682066f076225c6eaa642e8b32d34b7e` |
| `wireshark-iec104.pcap` | `a78aa971adc51e54413a865937f1799ef57118d397cef57ccd93a358ed5b85d6` |
| `wireshark-hart-ip.pcap` | `dda914bff86358caf5bc6e3ed06814124104ecb0eff71e5c7e806fe1b24a09a6` |
