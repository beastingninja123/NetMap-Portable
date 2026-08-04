import { describe, expect, it } from 'vitest'
import { demoDataset } from './demoData'
import type { FilterState } from './types'
import {
  aggregatePairEdges,
  detectCsvColumns,
  filterDataset,
  matchesIpOrCidr,
  parseSearchTerms,
  sanitizeCsvCell,
} from './utils'

const filters: FilterState = {
  query: '',
  startTime: '',
  endTime: '',
  port: '',
  protocols: [],
  minBytes: 0,
  minPackets: 0,
  direction: 'all',
  hostScope: 'all',
  neighborhood: 0,
  hideIsolates: true,
  hideNoise: false,
  groupSubnets: false,
  complexityCap: 500,
  edgeMode: 'aggregate',
  showEdgeLabels: false,
}

describe('CSV field detection', () => {
  it('detects Security Onion / ECS fields', () => {
    const result = detectCsvColumns(['@timestamp', 'source.ip', 'destination.ip', 'destination.port', 'network.transport'])
    expect(result.schema).toBe('Security Onion / ECS')
    expect(result.mapping.sourceIp).toBe('source.ip')
    expect(result.mapping.destinationPort).toBe('destination.port')
  })

  it('detects Zeek fields', () => {
    const result = detectCsvColumns(['ts', 'id.orig_h', 'id.resp_h', 'id.orig_p', 'id.resp_p', 'proto'])
    expect(result.schema).toBe('Zeek')
    expect(result.mapping.sourceIp).toBe('id.orig_h')
    expect(result.mapping.destinationIp).toBe('id.resp_h')
  })
})

describe('network filters', () => {
  it('matches IP prefixes and CIDR ranges without substring false positives', () => {
    expect(matchesIpOrCidr('10.20.2.47', '10.20.2.0/24')).toBe(true)
    expect(matchesIpOrCidr('10.20.3.47', '10.20.2.0/24')).toBe(false)
    expect(matchesIpOrCidr('185.220.101.42', '185.220')).toBe(true)
    expect(matchesIpOrCidr('185.220.101.42', '220.101')).toBe(false)
  })

  it('parses several comma or space-separated IP prefixes', () => {
    expect(parseSearchTerms('172., 192.  120.;10.')).toEqual(['172.', '192.', '120.', '10.'])
  })

  it('keeps strict search results at neighborhood depth zero', () => {
    const result = filterDataset(demoDataset, {
      ...filters,
      query: '10.20.2.47',
      neighborhood: 0,
    })
    expect(result.nodes.map((node) => node.ip)).toEqual(['10.20.2.47'])
    expect(result.edges).toHaveLength(0)
  })

  it('combines multiple prefix searches without unrelated hosts', () => {
    const result = filterDataset(demoDataset, {
      ...filters,
      query: '10.20.2., 104.',
      neighborhood: 0,
    })
    expect(result.nodes.length).toBeGreaterThan(1)
    expect(result.nodes.every((node) => node.ip.startsWith('10.20.2.') || node.ip.startsWith('104.'))).toBe(true)
  })

  it('adds direct peers only when neighborhood depth is increased', () => {
    const strict = filterDataset(demoDataset, {
      ...filters,
      query: '10.20.2.47',
      neighborhood: 0,
    })
    const expanded = filterDataset(demoDataset, {
      ...filters,
      query: '10.20.2.47',
      neighborhood: 1,
    })
    expect(strict.nodes).toHaveLength(1)
    expect(expanded.nodes.length).toBeGreaterThan(strict.nodes.length)
    expect(expanded.edges.length).toBeGreaterThan(0)
  })

  it('filters by protocol, port, volume, and boundary', () => {
    const result = filterDataset(demoDataset, {
      ...filters,
      port: '443',
      protocols: ['TLS'],
      minBytes: 500_000,
      direction: 'cross-boundary',
    })
    expect(result.edges.length).toBeGreaterThan(0)
    expect(result.edges.every((edge) => edge.port === 443 && edge.protocol === 'TLS' && edge.bytes >= 500_000)).toBe(true)
  })

  it('filters to internal or external hosts only', () => {
    const internal = filterDataset(demoDataset, { ...filters, hostScope: 'internal' })
    const external = filterDataset(demoDataset, { ...filters, hostScope: 'external' })
    expect(internal.nodes.length).toBeGreaterThan(0)
    expect(external.nodes.length).toBeGreaterThan(0)
    expect(internal.nodes.every((node) => node.kind === 'internal')).toBe(true)
    expect(external.nodes.every((node) => node.kind === 'external')).toBe(true)
    expect(internal.edges.every((edge) => {
      const source = internal.nodes.find((node) => node.id === edge.source)
      const target = internal.nodes.find((node) => node.id === edge.target)
      return source?.kind === 'internal' && target?.kind === 'internal'
    })).toBe(true)
  })
})

describe('edge aggregation', () => {
  it('collapses multiple flows between the same hosts into one pair edge', () => {
    const multiFlow: typeof demoDataset = {
      nodes: demoDataset.nodes,
      edges: [
        { ...demoDataset.edges[0], id: 'a1', source: 'n5', target: 'n8', protocol: 'TLS', port: 443, bytes: 1000 },
        { ...demoDataset.edges[0], id: 'a2', source: 'n5', target: 'n8', protocol: 'HTTP', port: 80, bytes: 500 },
        { ...demoDataset.edges[0], id: 'a3', source: 'n5', target: 'n8', protocol: 'DNS', port: 53, bytes: 100 },
      ],
    }
    const pairs = aggregatePairEdges(multiFlow.edges)
    expect(pairs).toHaveLength(1)
    expect(pairs[0].flowCount).toBe(3)
    expect(pairs[0].bytes).toBe(1600)
    expect(pairs[0].ports.map((port) => port.port)).toEqual([443, 80, 53])
  })
})

describe('CSV export sanitization', () => {
  it.each(['=SUM(A1:A2)', '+cmd', '-2+3', '@payload', '\tformula'])('neutralizes formula-like cell %s', (value) => {
    expect(sanitizeCsvCell(value)).toBe(`'${value}`)
  })

  it('leaves ordinary values untouched', () => {
    expect(sanitizeCsvCell('10.20.0.1')).toBe('10.20.0.1')
  })
})
