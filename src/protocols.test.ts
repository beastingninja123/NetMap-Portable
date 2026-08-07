import { describe, expect, it } from 'vitest'
import { displayPort, normalizeProtocol } from './protocols'

describe('protocol normalization', () => {
  it.each([
    ['tcp', 55000, 502, 'MODBUS'],
    ['tcp', 20000, 55000, 'DNP3'],
    ['udp', 55000, 47808, 'BACNET'],
    ['tcp', 55000, 44818, 'ETHERNET/IP'],
    ['tcp', 55000, 4840, 'OPC UA'],
    ['tcp', 55000, 102, 'S7COMM'],
    ['tcp', 55000, 2404, 'IEC 104'],
    ['udp', 9600, 55000, 'FINS'],
    ['tcp', 55000, 5094, 'HART-IP'],
  ])('infers %s port %s/%s as %s', (transport, sourcePort, destinationPort, expected) => {
    expect(normalizeProtocol(transport, Number(sourcePort), Number(destinationPort))).toBe(expected)
  })

  it('prefers explicit analyzer protocol names over their transport ports', () => {
    expect(normalizeProtocol('opcua', 443, 55000)).toBe('OPC UA')
    expect(normalizeProtocol('IEC 61850 GOOSE')).toBe('GOOSE')
    expect(normalizeProtocol('enip')).toBe('ETHERNET/IP')
  })

  it('keeps standard protocol inference working in both directions', () => {
    expect(normalizeProtocol('tcp', 443, 55000)).toBe('TLS')
    expect(normalizeProtocol('udp', 55000, 53)).toBe('DNS')
    expect(normalizeProtocol('icmpv6')).toBe('ICMP')
  })

  it('falls back safely for unknown analyzer values', () => {
    expect(normalizeProtocol('unrecognized-service')).toBe('OTHER')
  })

  it('uses the service port in either flow direction', () => {
    expect(displayPort('MODBUS', 55000, 502)).toBe(502)
    expect(displayPort('MODBUS', 502, 55000)).toBe(502)
    expect(displayPort('TCP', 55000, 5432)).toBe(5432)
  })
})
