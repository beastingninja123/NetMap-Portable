import { describe, expect, it } from 'vitest'
import { demoDataset } from './demoData'
import type { FilterState } from './types'
import { detectCsvColumns, filterDataset, matchesIpOrCidr, sanitizeCsvCell } from './utils'

const filters: FilterState = {
  query: '',
  startTime: '',
  endTime: '',
  port: '',
  protocols: [],
  minBytes: 0,
  minPackets: 0,
  direction: 'all',
  neighborhood: 1,
  hideIsolates: true,
  hideNoise: false,
  groupSubnets: false,
  complexityCap: 500,
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
  it('matches exact IP fragments and CIDR ranges', () => {
    expect(matchesIpOrCidr('10.20.2.47', '10.20.2.0/24')).toBe(true)
    expect(matchesIpOrCidr('10.20.3.47', '10.20.2.0/24')).toBe(false)
    expect(matchesIpOrCidr('185.220.101.42', '220.101')).toBe(true)
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
})

describe('CSV export sanitization', () => {
  it.each(['=SUM(A1:A2)', '+cmd', '-2+3', '@payload', '\tformula'])('neutralizes formula-like cell %s', (value) => {
    expect(sanitizeCsvCell(value)).toBe(`'${value}`)
  })

  it('leaves ordinary values untouched', () => {
    expect(sanitizeCsvCell('10.20.0.1')).toBe('10.20.0.1')
  })
})
