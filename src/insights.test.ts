import { describe, expect, it } from 'vitest'
import { analyzeBaseline, datasetAtPercent, enrichAssetMetadata, traceNeighborhood } from './insights'
import type { NetworkDataset } from './types'

const dataset: NetworkDataset = {
  nodes: [
    { id: 'hmi', label: 'line-hmi', hostname: 'line-hmi', ip: '10.0.0.2', subnet: '10.0.0.0/24', kind: 'internal', bytes: 10, packets: 1, firstSeen: '2026-01-01T00:00:00Z', lastSeen: '2026-01-01T00:10:00Z', imports: [], tags: [] },
    { id: 'plc', label: 'plc-1', hostname: 'plc-1', ip: '10.0.0.3', subnet: '10.0.0.0/24', kind: 'internal', bytes: 10, packets: 1, firstSeen: '2026-01-01T00:00:00Z', lastSeen: '2026-01-01T00:10:00Z', imports: [], tags: [] },
    { id: 'new', label: 'new-host', ip: '10.0.0.4', subnet: '10.0.0.0/24', kind: 'internal', bytes: 10, packets: 1, firstSeen: '2026-01-01T00:09:00Z', lastSeen: '2026-01-01T00:10:00Z', imports: [], tags: [] },
  ],
  edges: [
    { id: 'base', source: 'hmi', target: 'plc', protocol: 'MODBUS', port: 502, bytes: 100, packets: 2, firstSeen: '2026-01-01T00:00:00Z', lastSeen: '2026-01-01T00:01:00Z', imports: [] },
    { id: 'port', source: 'hmi', target: 'plc', protocol: 'TCP', port: 1234, bytes: 200, packets: 3, firstSeen: '2026-01-01T00:09:00Z', lastSeen: '2026-01-01T00:09:10Z', imports: [] },
    { id: 'new-pair', source: 'new', target: 'plc', protocol: 'MODBUS', port: 502, bytes: 2000, packets: 20, firstSeen: '2026-01-01T00:09:00Z', lastSeen: '2026-01-01T00:10:00Z', imports: [] },
  ],
}

describe('OT insights', () => {
  it('infers OT roles and IEC 62443-style zones', () => {
    const enriched = enrichAssetMetadata(dataset)
    expect(enriched.nodes.find((node) => node.id === 'hmi')?.assetRole).toBe('HMI')
    expect(enriched.nodes.find((node) => node.id === 'hmi')?.securityZone).toBe('Supervisory')
    expect(enriched.nodes.find((node) => node.id === 'plc')?.assetRole).toBe('PLC')
    expect(enriched.nodes.find((node) => node.id === 'plc')?.securityZone).toBe('Control')
  })

  it('flags later pairs, ports, protocols, and spikes against the baseline', () => {
    const analyzed = analyzeBaseline(dataset, 30)
    expect(analyzed.edges.find((edge) => edge.id === 'port')?.anomalies).toEqual(['new-protocol', 'new-port'])
    expect(analyzed.edges.find((edge) => edge.id === 'new-pair')?.anomalies).toEqual(['new-pair', 'traffic-spike'])
  })

  it('filters timeline playback by first-seen time', () => {
    expect(datasetAtPercent(dataset, 20).edges.map((edge) => edge.id)).toEqual(['base'])
    expect(datasetAtPercent(dataset, 100).edges).toHaveLength(3)
  })

  it('traces inbound and outbound paths independently', () => {
    const edges = [
      { id: 'one', source: 'a', target: 'b' },
      { id: 'two', source: 'b', target: 'c' },
      { id: 'reverse', source: 'd', target: 'a' },
    ]
    expect([...traceNeighborhood('a', edges, 'outbound').distances.keys()]).toEqual(['a', 'b', 'c'])
    expect([...traceNeighborhood('a', edges, 'inbound').distances.keys()]).toEqual(['a', 'd'])
    expect(traceNeighborhood('a', edges, 'both').edgeIds.size).toBe(3)
  })
})
