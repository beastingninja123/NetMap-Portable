import type {
  CsvPreview,
  DetectedSchema,
  FilterState,
  ImportMapping,
  NetworkDataset,
  NetworkEdge,
  NetworkNode,
} from './types'

const FIELD_ALIASES: Record<keyof ImportMapping, string[]> = {
  timestamp: ['@timestamp', 'timestamp', 'ts', '_time'],
  sourceIp: ['source.ip', 'src_ip', 'id.orig_h', 'src', 'source_ip'],
  destinationIp: ['destination.ip', 'dest_ip', 'dst_ip', 'id.resp_h', 'dst', 'destination_ip'],
  sourcePort: ['source.port', 'src_port', 'id.orig_p', 'source_port'],
  destinationPort: ['destination.port', 'dest_port', 'dst_port', 'id.resp_p', 'destination_port'],
  protocol: ['network.transport', 'network.protocol', 'proto', 'protocol', 'service'],
  bytes: ['network.bytes', 'bytes', 'orig_bytes', 'resp_bytes'],
  packets: ['network.packets', 'packets', 'orig_pkts', 'resp_pkts'],
}

export function detectCsvColumns(headers: string[]): {
  schema: DetectedSchema
  mapping: ImportMapping
} {
  const normalized = new Map(headers.map((header) => [header.toLowerCase().trim(), header]))
  const mapping = Object.fromEntries(
    Object.entries(FIELD_ALIASES).map(([field, aliases]) => [
      field,
      aliases.map((alias) => normalized.get(alias)).find(Boolean) ?? '',
    ]),
  ) as unknown as ImportMapping

  const names = new Set([...normalized.keys()])
  const schema: DetectedSchema = names.has('id.orig_h') || names.has('id.resp_h')
    ? 'Zeek'
    : names.has('source.ip') || names.has('destination.ip') || names.has('@timestamp')
      ? 'Security Onion / ECS'
      : 'Generic CSV'
  return { schema, mapping }
}

export function createCsvPreview(
  name: string,
  rows: Record<string, string>[],
  headers: string[],
): CsvPreview {
  const detected = detectCsvColumns(headers)
  return { name, rows: rows.slice(0, 8), headers, ...detected }
}

function ipToNumber(ip: string): number | null {
  const parts = ip.split('.').map(Number)
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return null
  return parts.reduce((sum, part) => (sum * 256) + part, 0) >>> 0
}

export function matchesIpOrCidr(ip: string, term: string): boolean {
  if (!term.includes('/')) return ip.toLowerCase().includes(term.toLowerCase())
  const [network, prefixText] = term.split('/')
  const value = ipToNumber(ip)
  const base = ipToNumber(network)
  const prefix = Number(prefixText)
  if (value === null || base === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return false
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0
  return (value & mask) === (base & mask)
}

function inTimeRange(edge: NetworkEdge, filters: FilterState): boolean {
  const afterStart = !filters.startTime || new Date(edge.lastSeen) >= new Date(filters.startTime)
  const beforeEnd = !filters.endTime || new Date(edge.firstSeen) <= new Date(filters.endTime)
  return afterStart && beforeEnd
}

export function filterDataset(dataset: NetworkDataset, filters: FilterState): NetworkDataset {
  const nodeById = new Map(dataset.nodes.map((node) => [node.id, node]))
  let edges = dataset.edges.filter((edge) => {
    const source = nodeById.get(edge.source)
    const target = nodeById.get(edge.target)
    if (!source || !target || !inTimeRange(edge, filters)) return false
    const queryMatch = !filters.query
      || matchesIpOrCidr(source.ip, filters.query)
      || matchesIpOrCidr(target.ip, filters.query)
      || edge.protocol.toLowerCase().includes(filters.query.toLowerCase())
    const portMatch = !filters.port || String(edge.port) === filters.port
    const protocolMatch = filters.protocols.length === 0 || filters.protocols.includes(edge.protocol)
    const directionMatch = filters.direction === 'all'
      || (filters.direction === 'cross-boundary' && source.kind !== target.kind)
      || (filters.direction !== 'cross-boundary'
        && (source.kind === filters.direction || target.kind === filters.direction))
    return queryMatch && portMatch && protocolMatch && directionMatch
      && edge.bytes >= filters.minBytes && edge.packets >= filters.minPackets
      && (!filters.hideNoise || edge.bytes >= 1_000 || edge.packets >= 5)
  })

  edges = [...edges].sort((a, b) => b.bytes - a.bytes).slice(0, filters.complexityCap)
  let visibleIds = new Set(edges.flatMap((edge) => [edge.source, edge.target]))

  if (filters.query && filters.neighborhood > 0) {
    const seeds = dataset.nodes.filter((node) => matchesIpOrCidr(node.ip, filters.query)).map((node) => node.id)
    let frontier = new Set(seeds)
    visibleIds = new Set(seeds)
    for (let depth = 0; depth < filters.neighborhood; depth += 1) {
      const next = new Set<string>()
      dataset.edges.forEach((edge) => {
        if (frontier.has(edge.source)) next.add(edge.target)
        if (frontier.has(edge.target)) next.add(edge.source)
      })
      next.forEach((id) => visibleIds.add(id))
      frontier = next
    }
    edges = edges.filter((edge) => visibleIds.has(edge.source) && visibleIds.has(edge.target))
  }

  const nodes = dataset.nodes.filter((node) => !filters.hideIsolates || visibleIds.has(node.id))
  return { nodes, edges }
}

export function sanitizeCsvCell(value: unknown): string {
  const text = String(value ?? '')
  return /^[=+\-@\t\r]/.test(text) ? `'${text}` : text
}

function quoteCsv(value: unknown): string {
  return `"${sanitizeCsvCell(value).replaceAll('"', '""')}"`
}

export function exportDatasetCsv(dataset: NetworkDataset): string {
  const header = ['source_ip', 'destination_ip', 'protocol', 'port', 'bytes', 'packets', 'first_seen', 'last_seen']
  const nodes = new Map(dataset.nodes.map((node) => [node.id, node]))
  const lines = dataset.edges.map((edge) => [
    nodes.get(edge.source)?.ip ?? edge.source,
    nodes.get(edge.target)?.ip ?? edge.target,
    edge.protocol,
    edge.port,
    edge.bytes,
    edge.packets,
    edge.firstSeen,
    edge.lastSeen,
  ].map(quoteCsv).join(','))
  return [header.join(','), ...lines].join('\r\n')
}

export function downloadText(filename: string, content: string, type: string): void {
  const url = URL.createObjectURL(new Blob([content], { type }))
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  anchor.click()
  URL.revokeObjectURL(url)
}

export function summarizeNode(node: NetworkNode, dataset: NetworkDataset): NetworkEdge[] {
  return dataset.edges
    .filter((edge) => edge.source === node.id || edge.target === node.id)
    .sort((a, b) => b.bytes - a.bytes)
}
