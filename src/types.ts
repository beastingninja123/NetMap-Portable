export type Protocol =
  | 'TCP'
  | 'UDP'
  | 'ICMP'
  | 'DNS'
  | 'HTTP'
  | 'TLS'
  | 'SSH'
  | 'MODBUS'
  | 'DNP3'
  | 'ETHERNET/IP'
  | 'BACNET'
  | 'OPC UA'
  | 'S7COMM'
  | 'PROFINET'
  | 'IEC 104'
  | 'FINS'
  | 'HART-IP'
  | 'MMS'
  | 'GOOSE'
  | 'ETHERCAT'
  | 'OTHER'

export interface NetworkNode {
  id: string
  label: string
  ip: string
  hostname?: string
  mac?: string
  vendor?: string
  subnet: string
  kind: 'internal' | 'external'
  bytes: number
  packets: number
  firstSeen: string
  lastSeen: string
  imports: string[]
  tags: string[]
  notes?: string
  assetRole?: AssetRole
  assetRoleSource?: 'inferred' | 'manual'
  securityZone?: SecurityZone
  securityZoneSource?: 'inferred' | 'manual'
  purdueLevel?: PurdueLevel
  anomalyCount?: number
}

export interface NetworkEdge {
  id: string
  source: string
  target: string
  protocol: Protocol
  port: number
  bytes: number
  packets: number
  firstSeen: string
  lastSeen: string
  imports: string[]
  anomalies?: AnomalyKind[]
}

export interface AggregatedEdge {
  id: string
  source: string
  target: string
  bytes: number
  packets: number
  firstSeen: string
  lastSeen: string
  flowCount: number
  ports: Array<{ protocol: Protocol; port: number; bytes: number; packets: number }>
  protocols: Protocol[]
  imports: string[]
  flows: NetworkEdge[]
}

export type EdgeDisplayMode = 'hidden' | 'aggregate' | 'per-port'
export type HostScope = 'all' | 'internal' | 'external'
export type PathDirection = 'both' | 'outbound' | 'inbound'
export type AssetRole =
  | 'PLC'
  | 'HMI'
  | 'RTU'
  | 'Historian'
  | 'Engineering Workstation'
  | 'OPC Gateway'
  | 'Building Controller'
  | 'Safety System'
  | 'Field Device'
  | 'Server'
  | 'Workstation'
  | 'Network Infrastructure'
  | 'External Endpoint'
  | 'Unknown'
export type SecurityZone =
  | 'Enterprise'
  | 'DMZ'
  | 'Operations'
  | 'Supervisory'
  | 'Control'
  | 'Safety'
  | 'Field'
  | 'External'
  | 'Unassigned'
export type PurdueLevel = 'Level 5 · Enterprise' | 'Level 4 · Site business' | 'Level 3.5 · Industrial DMZ' | 'Level 3 · Operations' | 'Level 2 · Supervisory' | 'Level 1 · Control' | 'Level 0 · Process' | 'External / unassigned'
export type AnomalyKind = 'new-pair' | 'new-protocol' | 'new-port' | 'traffic-spike'

export interface NetworkDataset {
  nodes: NetworkNode[]
  edges: NetworkEdge[]
}

export interface TestCapture {
  id: string
  name: string
  description: string
  protocols: Protocol[]
  path: string
}

export interface ImportMapping {
  timestamp: string
  sourceIp: string
  destinationIp: string
  sourcePort: string
  destinationPort: string
  protocol: string
  bytes: string
  packets: string
}

export type MappingField = keyof ImportMapping
export type DetectedSchema = 'Security Onion / ECS' | 'Zeek' | 'Generic CSV'

export interface CsvPreview {
  name: string
  headers: string[]
  rows: Record<string, string>[]
  schema: DetectedSchema
  mapping: ImportMapping
}

export interface ImportResult {
  importedRows: number
  skippedRows: number
  warnings: string[]
  dataset: NetworkDataset
}

export interface ImportProgress {
  phase: string
  percent: number
  processed: number
  total: number
}

export interface PcapImportOptions {
  packetIndexing: boolean
  macAddresses: boolean
  dnsHostnames: boolean
  tcpFlags: boolean
  payloadPreviewBytes: number
}

export interface PacketRecord {
  packetNumber: number
  timestamp?: number
  sourceIp: string
  destinationIp: string
  sourceMac?: string
  destinationMac?: string
  sourcePort?: number
  destinationPort?: number
  protocol: string
  length: number
  tcpFlags?: string
  payloadPreview?: string
}

export interface PacketPage {
  packets: PacketRecord[]
  total: number
}

export interface FilterState {
  query: string
  startTime: string
  endTime: string
  port: string
  protocols: Protocol[]
  minBytes: number
  minPackets: number
  direction: 'all' | 'internal' | 'external' | 'cross-boundary'
  hostScope: HostScope
  neighborhood: number
  hideIsolates: boolean
  hideNoise: boolean
  groupSubnets: boolean
  complexityCap: number
  edgeMode: EdgeDisplayMode
  showEdgeLabels: boolean
}

export interface SavedView {
  id: string
  name: string
  filters: FilterState
  layout: string
}

export interface Diagnostics {
  mode: 'Tauri native' | 'Browser demo'
  version: string
  platform: string
  nodeCount: number
  edgeCount: number
}
