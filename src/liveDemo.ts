import type { NetworkDataset, Protocol } from './types'

/** Synthetic live flows for browser demo mode (no tshark). */
export function injectDemoLiveFlow(current: NetworkDataset, tick: number): NetworkDataset {
  const peers = [
    ['10.20.0.50', 'internal'],
    ['10.20.0.51', 'internal'],
    ['104.18.32.120', 'external'],
    ['8.8.8.8', 'external'],
  ] as const
  const [ip, kind] = peers[tick % peers.length]
  const now = new Date().toISOString()
  const hubId = 'live-hub'
  const peerId = `live-${ip}`
  const nodes = [...current.nodes]
  if (!nodes.some((node) => node.id === hubId)) {
    nodes.push({
      id: hubId, label: 'live-sensor', ip: '10.20.0.12', hostname: 'live-sensor',
      subnet: '10.20.0.0/24', kind: 'internal', bytes: 0, packets: 0,
      firstSeen: now, lastSeen: now, imports: ['live:demo'], tags: [],
    })
  }
  if (!nodes.some((node) => node.id === peerId)) {
    nodes.push({
      id: peerId, label: ip, ip, hostname: undefined,
      subnet: kind === 'internal' ? '10.20.0.0/24' : 'External', kind,
      bytes: 0, packets: 0, firstSeen: now, lastSeen: now, imports: ['live:demo'], tags: [],
    })
  }
  const edgeId = `live-e-${tick}`
  const edges = [
    ...current.edges,
    {
      id: edgeId, source: hubId, target: peerId,
      protocol: (['DNS', 'TLS', 'HTTP', 'UDP'] as Protocol[])[tick % 4],
      port: [53, 443, 80, 123][tick % 4],
      bytes: 1200 + tick * 350, packets: 4 + tick,
      firstSeen: now, lastSeen: now, imports: ['live:demo'],
    },
  ].slice(-80)
  return {
    nodes: nodes.map((node) => {
      const related = edges.filter((edge) => edge.source === node.id || edge.target === node.id)
      return {
        ...node,
        bytes: related.reduce((sum, edge) => sum + edge.bytes, 0),
        packets: related.reduce((sum, edge) => sum + edge.packets, 0),
        lastSeen: now,
      }
    }),
    edges,
  }
}
