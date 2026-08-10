import type {
  AggregatedEdge,
  CsvPreview,
  DetectedSchema,
  FilterState,
  ImportMapping,
  NetworkDataset,
  NetworkEdge,
  NetworkNode,
  Protocol,
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
  if (!term.includes('/')) return ip.toLowerCase().startsWith(term.toLowerCase())
  const [network, prefixText] = term.split('/')
  const value = ipToNumber(ip)
  const base = ipToNumber(network)
  const prefix = Number(prefixText)
  if (value === null || base === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return false
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0
  return (value & mask) === (base & mask)
}

export function parseSearchTerms(query: string): string[] {
  return [...new Set(
    query
      .split(/[\s,;]+/)
      .map((term) => term.trim().toLowerCase())
      .filter(Boolean),
  )]
}

function nodeMatchesTerms(node: NetworkNode, terms: string[]): boolean {
  return terms.some((term) =>
    matchesIpOrCidr(node.ip, term)
    || node.hostname?.toLowerCase().startsWith(term)
    || node.mac?.toLowerCase().includes(term)
    || node.vendor?.toLowerCase().includes(term)
    || node.label.toLowerCase().startsWith(term),
  )
}

function inTimeRange(edge: NetworkEdge, filters: FilterState): boolean {
  const afterStart = !filters.startTime || new Date(edge.lastSeen) >= new Date(filters.startTime)
  const beforeEnd = !filters.endTime || new Date(edge.firstSeen) <= new Date(filters.endTime)
  return afterStart && beforeEnd
}

function earlier(left: string, right: string): string {
  return new Date(left) <= new Date(right) ? left : right
}

function later(left: string, right: string): string {
  return new Date(left) >= new Date(right) ? left : right
}

/** Collapse many port/protocol flows between the same host pair into one map edge. */
export function aggregatePairEdges(edges: NetworkEdge[]): AggregatedEdge[] {
  const groups = new Map<string, NetworkEdge[]>()
  for (const edge of edges) {
    const key = `${edge.source}->${edge.target}`
    const bucket = groups.get(key)
    if (bucket) bucket.push(edge)
    else groups.set(key, [edge])
  }

  return [...groups.entries()]
    .map(([key, flows]) => {
      const sorted = [...flows].sort((a, b) => b.bytes - a.bytes)
      const ports = sorted.map((flow) => ({
        protocol: flow.protocol,
        port: flow.port,
        bytes: flow.bytes,
        packets: flow.packets,
      }))
      const protocols = [...new Set(sorted.map((flow) => flow.protocol))] as Protocol[]
      const imports = [...new Set(sorted.flatMap((flow) => flow.imports))]
      return {
        id: `pair-${key}`,
        source: sorted[0].source,
        target: sorted[0].target,
        bytes: sorted.reduce((sum, flow) => sum + flow.bytes, 0),
        packets: sorted.reduce((sum, flow) => sum + flow.packets, 0),
        firstSeen: sorted.reduce((min, flow) => earlier(min, flow.firstSeen), sorted[0].firstSeen),
        lastSeen: sorted.reduce((max, flow) => later(max, flow.lastSeen), sorted[0].lastSeen),
        flowCount: sorted.length,
        ports,
        protocols,
        imports,
        flows: sorted,
      }
    })
    .sort((a, b) => b.bytes - a.bytes)
}

export function filterDataset(dataset: NetworkDataset, filters: FilterState): NetworkDataset {
  const nodeById = new Map(dataset.nodes.map((node) => [node.id, node]))
  const terms = parseSearchTerms(filters.query)
  let edges = dataset.edges.filter((edge) => {
    const source = nodeById.get(edge.source)
    const target = nodeById.get(edge.target)
    if (!source || !target || !inTimeRange(edge, filters)) return false
    const portMatch = !filters.port || String(edge.port) === filters.port
    const protocolMatch = filters.protocols.length === 0 || filters.protocols.includes(edge.protocol)
    const directionMatch = filters.direction === 'all'
      || (filters.direction === 'cross-boundary' && source.kind !== target.kind)
      || (filters.direction !== 'cross-boundary'
        && (source.kind === filters.direction || target.kind === filters.direction))
    return portMatch && protocolMatch && directionMatch
      && edge.bytes >= filters.minBytes && edge.packets >= filters.minPackets
      && (!filters.hideNoise || edge.bytes >= 1_000 || edge.packets >= 5)
  })

  // Hosts of the selected scope that appear in any matching flow (even cross-boundary).
  const scopedParticipants = new Set<string>()
  if (filters.hostScope !== 'all') {
    for (const edge of edges) {
      const source = nodeById.get(edge.source)
      const target = nodeById.get(edge.target)
      if (source?.kind === filters.hostScope) scopedParticipants.add(source.id)
      if (target?.kind === filters.hostScope) scopedParticipants.add(target.id)
    }
    // Map lines only between hosts inside the selected scope.
    edges = edges.filter((edge) => {
      const source = nodeById.get(edge.source)
      const target = nodeById.get(edge.target)
      return source?.kind === filters.hostScope && target?.kind === filters.hostScope
    })
  }

  // Cap by host-pair in aggregate/hidden modes so one chatty pair does not burn the budget.
  edges = [...edges].sort((a, b) => b.bytes - a.bytes)
  if (filters.edgeMode === 'per-port') {
    edges = edges.slice(0, filters.complexityCap)
  } else {
    const topPairs = aggregatePairEdges(edges).slice(0, filters.complexityCap)
    edges = topPairs.flatMap((pair) => pair.flows)
  }
  let visibleIds: Set<string>

  if (terms.length > 0) {
    const scopedNodes = dataset.nodes.filter((node) =>
      filters.hostScope === 'all' || node.kind === filters.hostScope,
    )
    const seeds = scopedNodes.filter((node) => nodeMatchesTerms(node, terms)).map((node) => node.id)
    let frontier = new Set(seeds)
    visibleIds = new Set(seeds)
    for (let depth = 0; depth < filters.neighborhood; depth += 1) {
      const next = new Set<string>()
      edges.forEach((edge) => {
        if (frontier.has(edge.source)) next.add(edge.target)
        if (frontier.has(edge.target)) next.add(edge.source)
      })
      next.forEach((id) => visibleIds.add(id))
      frontier = next
    }
    edges = edges.filter((edge) => visibleIds.has(edge.source) && visibleIds.has(edge.target))
  } else {
    visibleIds = new Set(edges.flatMap((edge) => [edge.source, edge.target]))
  }

  const nodes = dataset.nodes.filter((node) => {
    if (filters.hostScope !== 'all' && node.kind !== filters.hostScope) return false
    if (terms.length > 0) return visibleIds.has(node.id)
    if (!filters.hideIsolates) return true
    // Keep scoped hosts that had traffic even when their only peers were outside the scope.
    return visibleIds.has(node.id) || scopedParticipants.has(node.id)
  })
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
  const header = ['source_ip', 'source_mac', 'source_vendor', 'destination_ip', 'destination_mac', 'destination_vendor', 'protocol', 'port', 'bytes', 'packets', 'first_seen', 'last_seen']
  const nodes = new Map(dataset.nodes.map((node) => [node.id, node]))
  const lines = dataset.edges.map((edge) => [
    nodes.get(edge.source)?.ip ?? edge.source,
    nodes.get(edge.source)?.mac ?? '',
    nodes.get(edge.source)?.vendor ?? '',
    nodes.get(edge.target)?.ip ?? edge.target,
    nodes.get(edge.target)?.mac ?? '',
    nodes.get(edge.target)?.vendor ?? '',
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
