import type { Protocol } from './types'

export const STANDARD_PROTOCOLS: Protocol[] = ['TCP', 'UDP', 'ICMP', 'DNS', 'HTTP', 'TLS', 'SSH']

export const OT_PROTOCOLS: Protocol[] = [
  'MODBUS',
  'DNP3',
  'ETHERNET/IP',
  'BACNET',
  'OPC UA',
  'S7COMM',
  'PROFINET',
  'IEC 104',
  'FINS',
  'HART-IP',
  'MMS',
  'GOOSE',
  'ETHERCAT',
]

export const PROTOCOL_COLORS: Record<Protocol, string> = {
  TCP: '#38bdf8',
  UDP: '#a78bfa',
  ICMP: '#fbbf24',
  DNS: '#34d399',
  HTTP: '#fb923c',
  TLS: '#22d3ee',
  SSH: '#f472b6',
  MODBUS: '#f97316',
  DNP3: '#ef4444',
  'ETHERNET/IP': '#eab308',
  BACNET: '#84cc16',
  'OPC UA': '#14b8a6',
  S7COMM: '#06b6d4',
  PROFINET: '#3b82f6',
  'IEC 104': '#8b5cf6',
  FINS: '#d946ef',
  'HART-IP': '#ec4899',
  MMS: '#f43f5e',
  GOOSE: '#f59e0b',
  ETHERCAT: '#10b981',
  OTHER: '#94a3b8',
}

const EXPLICIT_PROTOCOLS = new Map<string, Protocol>([
  ['TCP', 'TCP'],
  ['UDP', 'UDP'],
  ['ICMP', 'ICMP'],
  ['ICMPV4', 'ICMP'],
  ['ICMPV6', 'ICMP'],
  ['DNS', 'DNS'],
  ['MDNS', 'DNS'],
  ['HTTP', 'HTTP'],
  ['HTTPS', 'TLS'],
  ['TLS', 'TLS'],
  ['SSL', 'TLS'],
  ['SSH', 'SSH'],
  ['MODBUS', 'MODBUS'],
  ['MODBUSTCP', 'MODBUS'],
  ['DNP3', 'DNP3'],
  ['ETHERNETIP', 'ETHERNET/IP'],
  ['ENIP', 'ETHERNET/IP'],
  ['CIP', 'ETHERNET/IP'],
  ['BACNET', 'BACNET'],
  ['BACNETIP', 'BACNET'],
  ['OPCUA', 'OPC UA'],
  ['S7COMM', 'S7COMM'],
  ['S7COMMPLUS', 'S7COMM'],
  ['PROFINET', 'PROFINET'],
  ['PNIO', 'PROFINET'],
  ['IEC104', 'IEC 104'],
  ['IEC608705104', 'IEC 104'],
  ['FINS', 'FINS'],
  ['OMRONFINS', 'FINS'],
  ['HARTIP', 'HART-IP'],
  ['MMS', 'MMS'],
  ['IEC61850MMS', 'MMS'],
  ['GOOSE', 'GOOSE'],
  ['IEC61850GOOSE', 'GOOSE'],
  ['ETHERCAT', 'ETHERCAT'],
])

const WELL_KNOWN_PORTS: Partial<Record<Protocol, number[]>> = {
  DNS: [53, 5353],
  HTTP: [80],
  TLS: [443],
  SSH: [22],
  MODBUS: [502],
  DNP3: [20000],
  'ETHERNET/IP': [2222, 44818],
  BACNET: [47808],
  'OPC UA': [4840],
  S7COMM: [102],
  'IEC 104': [2404],
  FINS: [9600],
  'HART-IP': [5094],
}

function protocolKey(value: string): string {
  return value.trim().toUpperCase().replace(/[^A-Z0-9]/g, '')
}

function hasPort(ports: Array<number | undefined>, ...matches: number[]): boolean {
  return ports.some((port) => port !== undefined && matches.includes(port))
}

/**
 * Normalizes explicit application names and infers common services from both
 * ends of a TCP/UDP flow. Port inference is intentionally limited to stable,
 * well-known assignments; explicit analyzer output always takes precedence.
 */
export function normalizeProtocol(
  value: string,
  sourcePort?: number,
  destinationPort?: number,
): Protocol {
  const key = protocolKey(value)
  const explicit = EXPLICIT_PROTOCOLS.get(key)
  if (explicit && explicit !== 'TCP' && explicit !== 'UDP') return explicit

  const transport = explicit ?? (key === 'IP' || key === 'IPV6' ? 'OTHER' : undefined)
  const ports = [sourcePort, destinationPort]

  if (transport === 'TCP' || transport === 'UDP') {
    if (hasPort(ports, 44818, 2222)) return 'ETHERNET/IP'
    if (hasPort(ports, 20000)) return 'DNP3'
    if (hasPort(ports, 47808)) return 'BACNET'
    if (hasPort(ports, 9600)) return 'FINS'
    if (hasPort(ports, 5094)) return 'HART-IP'
  }

  if (transport === 'TCP') {
    if (hasPort(ports, 502)) return 'MODBUS'
    if (hasPort(ports, 4840)) return 'OPC UA'
    if (hasPort(ports, 102)) return 'S7COMM'
    if (hasPort(ports, 2404)) return 'IEC 104'
    if (hasPort(ports, 53)) return 'DNS'
    if (hasPort(ports, 80)) return 'HTTP'
    if (hasPort(ports, 443)) return 'TLS'
    if (hasPort(ports, 22)) return 'SSH'
  }

  if (transport === 'UDP' && hasPort(ports, 53, 5353)) return 'DNS'
  return transport ?? 'OTHER'
}

/** Chooses the recognizable service port even when the packet is server-to-client. */
export function displayPort(
  protocol: Protocol,
  sourcePort?: number,
  destinationPort?: number,
): number {
  const known = WELL_KNOWN_PORTS[protocol] ?? []
  if (destinationPort !== undefined && known.includes(destinationPort)) return destinationPort
  if (sourcePort !== undefined && known.includes(sourcePort)) return sourcePort
  return destinationPort ?? sourcePort ?? 0
}
