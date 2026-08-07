import type {
  AnomalyKind,
  AssetRole,
  NetworkDataset,
  NetworkEdge,
  NetworkNode,
  PathDirection,
  SecurityZone,
} from './types'

export const ASSET_ROLES: AssetRole[] = [
  'PLC',
  'HMI',
  'RTU',
  'Historian',
  'Engineering Workstation',
  'OPC Gateway',
  'Building Controller',
  'Safety System',
  'Field Device',
  'Server',
  'Workstation',
  'Network Infrastructure',
  'External Endpoint',
  'Unknown',
]

export const SECURITY_ZONES: SecurityZone[] = [
  'Enterprise',
  'DMZ',
  'Operations',
  'Supervisory',
  'Control',
  'Safety',
  'Field',
  'External',
  'Unassigned',
]

export const ZONE_COLORS: Record<SecurityZone, string> = {
  Enterprise: '#60a5fa',
  DMZ: '#c084fc',
  Operations: '#22d3ee',
  Supervisory: '#34d399',
  Control: '#f59e0b',
  Safety: '#ef4444',
  Field: '#a3e635',
  External: '#f472b6',
  Unassigned: '#64748b',
}

export const ANOMALY_LABELS: Record<AnomalyKind, string> = {
  'new-pair': 'New host pair',
  'new-protocol': 'New protocol for pair',
  'new-port': 'New port for pair',
  'traffic-spike': 'Traffic spike',
}

function hostnameText(node: NetworkNode): string {
  return `${node.hostname ?? ''} ${node.label}`.toLowerCase()
}

function relatedEdges(node: NetworkNode, edges: NetworkEdge[]): NetworkEdge[] {
  return edges.filter((edge) => edge.source === node.id || edge.target === node.id)
}

export function inferAssetRole(node: NetworkNode, edges: NetworkEdge[]): AssetRole {
  if (node.kind === 'external') return 'External Endpoint'
  const name = hostnameText(node)
  if (/\bplc\b|controller/.test(name) && !/building/.test(name)) return 'PLC'
  if (/\bhmi\b|operator/.test(name)) return 'HMI'
  if (/\brtu\b|remote.?terminal/.test(name)) return 'RTU'
  if (/historian/.test(name)) return 'Historian'
  if (/opc/.test(name)) return 'OPC Gateway'
  if (/engineering|eng-?station/.test(name)) return 'Engineering Workstation'
  if (/building|bacnet|bms/.test(name)) return 'Building Controller'
  if (/safety|\bsis\b/.test(name)) return 'Safety System'
  if (/gateway|router|firewall|switch|dns|resolver/.test(name)) return 'Network Infrastructure'
  if (/database|server|api/.test(name)) return 'Server'
  if (/workstation|analyst|laptop|desktop/.test(name)) return 'Workstation'
  if (/sensor|meter|drive|relay|actuator/.test(name)) return 'Field Device'

  const traffic = relatedEdges(node, edges)
  if (traffic.some((edge) => edge.target === node.id && edge.protocol === 'DNP3')) return 'RTU'
  if (traffic.some((edge) => edge.target === node.id && ['MODBUS', 'ETHERNET/IP', 'S7COMM', 'IEC 104'].includes(edge.protocol))) return 'PLC'
  if (traffic.some((edge) => edge.protocol === 'BACNET')) return 'Building Controller'
  if (traffic.some((edge) => edge.target === node.id && edge.protocol === 'OPC UA')) return 'OPC Gateway'
  if (traffic.some((edge) => edge.source === node.id && ['MODBUS', 'ETHERNET/IP', 'S7COMM', 'DNP3'].includes(edge.protocol))) return 'HMI'
  return 'Unknown'
}

export function inferSecurityZone(node: NetworkNode, role: AssetRole): SecurityZone {
  if (node.kind === 'external' || role === 'External Endpoint') return 'External'
  if (role === 'Safety System') return 'Safety'
  if (role === 'RTU' || role === 'Field Device') return 'Field'
  if (role === 'PLC' || role === 'Building Controller') return 'Control'
  if (role === 'HMI' || role === 'Engineering Workstation') return 'Supervisory'
  if (role === 'Historian' || role === 'OPC Gateway' || role === 'Server') return 'Operations'
  if (role === 'Workstation') return 'Enterprise'
  if (role === 'Network Infrastructure') return 'DMZ'
  return 'Unassigned'
}

export function enrichAssetMetadata(dataset: NetworkDataset): NetworkDataset {
  const nodes = dataset.nodes.map((node) => {
    const inferredRole = inferAssetRole(node, dataset.edges)
    const assetRole = node.assetRoleSource === 'manual' && node.assetRole ? node.assetRole : inferredRole
    const inferredZone = inferSecurityZone(node, assetRole)
    const securityZone = node.securityZoneSource === 'manual' && node.securityZone
      ? node.securityZone
      : inferredZone
    return {
      ...node,
      assetRole,
      assetRoleSource: node.assetRoleSource === 'manual' ? 'manual' as const : 'inferred' as const,
      securityZone,
      securityZoneSource: node.securityZoneSource === 'manual' ? 'manual' as const : 'inferred' as const,
    }
  })
  return { ...dataset, nodes }
}

export interface TimeBounds {
  start: number
  end: number
}

export function datasetTimeBounds(dataset: NetworkDataset): TimeBounds | null {
  if (dataset.edges.length === 0) return null
  const timestamps = dataset.edges.flatMap((edge) => [Date.parse(edge.firstSeen), Date.parse(edge.lastSeen)])
    .filter(Number.isFinite)
  if (timestamps.length === 0) return null
  return { start: Math.min(...timestamps), end: Math.max(...timestamps) }
}

function pairKey(edge: NetworkEdge): string {
  return [edge.source, edge.target].sort().join('<->')
}

function median(values: number[]): number {
  if (values.length === 0) return 0
  const sorted = [...values].sort((left, right) => left - right)
  const middle = Math.floor(sorted.length / 2)
  return sorted.length % 2 === 0 ? (sorted[middle - 1] + sorted[middle]) / 2 : sorted[middle]
}

export function analyzeBaseline(dataset: NetworkDataset, baselinePercent: number): NetworkDataset {
  const bounds = datasetTimeBounds(dataset)
  if (!bounds || bounds.start === bounds.end) return dataset
  const cutoff = bounds.start + (bounds.end - bounds.start) * Math.max(0.05, Math.min(0.8, baselinePercent / 100))
  const baseline = dataset.edges.filter((edge) => Date.parse(edge.firstSeen) <= cutoff)
  const pairs = new Set(baseline.map(pairKey))
  const protocols = new Set(baseline.map((edge) => `${pairKey(edge)}|${edge.protocol}`))
  const ports = new Set(baseline.map((edge) => `${pairKey(edge)}|${edge.port}`))
  const spikeThreshold = Math.max(1, median(baseline.map((edge) => edge.bytes)) * 4)

  const edges = dataset.edges.map((edge) => {
    const anomalies: AnomalyKind[] = []
    const isLater = Date.parse(edge.firstSeen) > cutoff
    const pair = pairKey(edge)
    if (isLater && !pairs.has(pair)) anomalies.push('new-pair')
    if (isLater && pairs.has(pair) && !protocols.has(`${pair}|${edge.protocol}`)) anomalies.push('new-protocol')
    if (isLater && pairs.has(pair) && !ports.has(`${pair}|${edge.port}`)) anomalies.push('new-port')
    if (isLater && edge.bytes > spikeThreshold) anomalies.push('traffic-spike')
    return { ...edge, anomalies }
  })
  const counts = new Map<string, number>()
  edges.forEach((edge) => {
    if (!edge.anomalies?.length) return
    counts.set(edge.source, (counts.get(edge.source) ?? 0) + edge.anomalies.length)
    counts.set(edge.target, (counts.get(edge.target) ?? 0) + edge.anomalies.length)
  })
  const nodes = dataset.nodes.map((node) => ({ ...node, anomalyCount: counts.get(node.id) ?? 0 }))
  return { nodes, edges }
}

export function datasetAtPercent(dataset: NetworkDataset, percent: number): NetworkDataset {
  const bounds = datasetTimeBounds(dataset)
  if (!bounds || percent >= 100) return dataset
  const cursor = bounds.start + (bounds.end - bounds.start) * Math.max(0, percent / 100)
  const edges = dataset.edges.filter((edge) => Date.parse(edge.firstSeen) <= cursor)
  const visibleNodeIds = new Set(edges.flatMap((edge) => [edge.source, edge.target]))
  const nodes = dataset.nodes.filter((node) => visibleNodeIds.has(node.id))
  return { nodes, edges }
}

export function timeAtPercent(bounds: TimeBounds | null, percent: number): number | null {
  if (!bounds) return null
  return bounds.start + (bounds.end - bounds.start) * Math.max(0, Math.min(1, percent / 100))
}

export interface TracedNeighborhood {
  distances: Map<string, number>
  edgeIds: Map<string, number>
}

export function traceNeighborhood(
  rootId: string,
  edges: Array<Pick<NetworkEdge, 'id' | 'source' | 'target'>>,
  direction: PathDirection,
  maxDepth = 2,
): TracedNeighborhood {
  const distances = new Map<string, number>([[rootId, 0]])
  const edgeIds = new Map<string, number>()
  let frontier = new Set([rootId])
  for (let depth = 1; depth <= maxDepth; depth += 1) {
    const next = new Set<string>()
    edges.forEach((edge) => {
      const forward = direction !== 'inbound' && frontier.has(edge.source) && !distances.has(edge.target)
      const reverse = direction !== 'outbound' && frontier.has(edge.target) && !distances.has(edge.source)
      if (forward) {
        next.add(edge.target)
        edgeIds.set(edge.id, depth)
      }
      if (reverse) {
        next.add(edge.source)
        edgeIds.set(edge.id, depth)
      }
    })
    next.forEach((id) => distances.set(id, depth))
    frontier = next
  }
  return { distances, edgeIds }
}
