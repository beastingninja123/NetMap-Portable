import { normalizeProtocol } from './protocols'
import type { NetworkDataset } from './types'

const hosts = [
  ['gateway', '10.20.0.1', 'internal'],
  ['sensor', '10.20.0.12', 'internal'],
  ['analyst', '10.20.0.24', 'internal'],
  ['fileserver', '10.20.1.8', 'internal'],
  ['database', '10.20.1.21', 'internal'],
  ['workstation-07', '10.20.2.47', 'internal'],
  ['workstation-14', '10.20.2.93', 'internal'],
  ['dns-resolver', '10.20.0.53', 'internal'],
  ['cdn-edge', '104.18.32.120', 'external'],
  ['cloud-api', '52.85.132.19', 'external'],
  ['suspicious-host', '185.220.101.42', 'external'],
  ['update-service', '151.101.2.217', 'external'],
  ['plc-line-1', '10.20.3.10', 'internal'],
  ['hmi-line-1', '10.20.3.20', 'internal'],
  ['opc-gateway', '10.20.3.30', 'internal'],
  ['building-controller', '10.20.4.10', 'internal'],
  ['substation-rtu', '10.20.5.10', 'internal'],
] as const

export const demoDataset: NetworkDataset = {
  nodes: hosts.map(([label, ip, kind], index) => ({
    id: `n${index}`,
    label,
    ip,
    hostname: label,
    subnet: ip.startsWith('10.') ? `${ip.split('.').slice(0, 3).join('.')}.0/24` : 'External',
    kind,
    bytes: 84_000 + index * 137_000,
    packets: 120 + index * 73,
    firstSeen: '2026-08-03T12:08:00Z',
    lastSeen: `2026-08-03T15:${String(10 + index * 3).padStart(2, '0')}:00Z`,
    imports: ['sensor-east-2026-08-03.csv'],
    tags: index === 10 ? ['watchlist'] : index === 3 ? ['critical'] : [],
    notes: index === 10 ? 'Tor exit observed in threat feed.' : undefined,
  })),
  edges: [
    [1, 0, 'DNS', 53, 38400, 224], [2, 0, 'TLS', 443, 618000, 802],
    [2, 3, 'SMB', 445, 2280000, 1804], [3, 4, 'TCP', 5432, 4710000, 3312],
    [5, 7, 'DNS', 53, 48200, 302], [5, 8, 'TLS', 443, 930000, 978],
    [6, 7, 'DNS', 53, 34600, 198], [6, 10, 'SSH', 22, 182000, 384],
    [7, 8, 'UDP', 53, 74500, 440], [2, 9, 'HTTPS', 443, 1220000, 1119],
    [5, 11, 'HTTP', 80, 382000, 590], [0, 9, 'TLS', 443, 510000, 635],
    [1, 3, 'TCP', 9200, 880000, 742], [6, 3, 'TCP', 445, 668000, 521],
    [10, 6, 'TCP', 49172, 94000, 166], [4, 9, 'TLS', 443, 210000, 290],
    [13, 12, 'MODBUS', 502, 740000, 1210], [13, 14, 'OPC UA', 4840, 630000, 842],
    [14, 4, 'ETHERNET/IP', 44818, 490000, 618], [15, 0, 'BACNET', 47808, 210000, 402],
    [16, 0, 'DNP3', 20000, 375000, 537],
  ].map(([source, target, protocol, port, bytes, packets], index) => ({
    id: `e${index}`,
    source: `n${source}`,
    target: `n${target}`,
    protocol: normalizeProtocol(String(protocol), undefined, Number(port)),
    port: Number(port),
    bytes: Number(bytes),
    packets: Number(packets),
    firstSeen: `2026-08-03T1${2 + (index % 4)}:${String(index * 3).padStart(2, '0')}:00Z`,
    lastSeen: `2026-08-03T15:${String(20 + index).padStart(2, '0')}:00Z`,
    imports: ['sensor-east-2026-08-03.csv'],
  })),
}

export const sampleCsvRows: Record<string, string>[] = [
  { '@timestamp': '2026-08-03T15:32:14Z', 'source.ip': '10.20.2.93', 'destination.ip': '185.220.101.42', 'source.port': '53122', 'destination.port': '22', 'network.transport': 'tcp', 'network.bytes': '48120', 'network.packets': '84' },
  { '@timestamp': '2026-08-03T15:32:16Z', 'source.ip': '10.20.2.47', 'destination.ip': '104.18.32.120', 'source.port': '49214', 'destination.port': '443', 'network.transport': 'tcp', 'network.bytes': '120840', 'network.packets': '112' },
  { '@timestamp': '2026-08-03T15:32:19Z', 'source.ip': '10.20.0.24', 'destination.ip': '10.20.1.8', 'source.port': '51882', 'destination.port': '445', 'network.transport': 'tcp', 'network.bytes': '382104', 'network.packets': '308' },
]
