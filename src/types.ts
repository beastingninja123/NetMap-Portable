export type Protocol = 'TCP' | 'UDP' | 'ICMP' | 'DNS' | 'HTTP' | 'TLS' | 'SSH' | 'OTHER'

export interface NetworkNode {
  id: string
  label: string
  ip: string
  subnet: string
  kind: 'internal' | 'external'
  bytes: number
  packets: number
  firstSeen: string
  lastSeen: string
  imports: string[]
  tags: string[]
  notes?: string
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
}

export interface NetworkDataset {
  nodes: NetworkNode[]
  edges: NetworkEdge[]
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

export interface FilterState {
  query: string
  startTime: string
  endTime: string
  port: string
  protocols: Protocol[]
  minBytes: number
  minPackets: number
  direction: 'all' | 'internal' | 'external' | 'cross-boundary'
  neighborhood: number
  hideIsolates: boolean
  hideNoise: boolean
  groupSubnets: boolean
  complexityCap: number
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
