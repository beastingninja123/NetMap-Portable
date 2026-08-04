import { invoke } from '@tauri-apps/api/core'
import { listen } from '@tauri-apps/api/event'
import { open } from '@tauri-apps/plugin-dialog'
import Papa from 'papaparse'
import { demoDataset, sampleCsvRows } from './demoData'
import type {
  CsvPreview,
  Diagnostics,
  ImportMapping,
  ImportProgress,
  ImportResult,
  NetworkDataset,
  NetworkNode,
  Protocol,
  SavedView,
} from './types'
import { createCsvPreview } from './utils'

declare global {
  interface Window {
    __TAURI_INTERNALS__?: unknown
  }
}

export const isTauri = (): boolean => Boolean(window.__TAURI_INTERNALS__)

interface NativeProject {
  id: string
  name: string
  path: string
}

interface NativeMapping {
  sourceIp: string
  destinationIp: string
  sourcePort?: string
  destinationPort?: string
  protocol?: string
  timestamp?: string
  bytes?: string
  packets?: string
}

interface NativePreview {
  headers: string[]
  detectedFormat?: string
  suggestedMapping?: NativeMapping
  rows: string[][]
}

interface NativeImportResult {
  importId: string
  accepted: number
  skipped: number
  cancelled: boolean
  warnings: string[]
}

interface NativeProgress {
  importId: string
  phase: string
  processed: number
  accepted: number
  skipped: number
  completed: boolean
  cancelled: boolean
  message?: string
}

interface NativeGraph {
  nodes: Array<{
    id: number
    ip: string
    hostname?: string
    totalBytes: number
    totalPackets: number
    firstSeen?: number
    lastSeen?: number
    imports: string[]
    tags: string[]
    notes?: string
  }>
  edges: Array<{
    id: number
    source: number
    target: number
    sourcePort?: number
    destinationPort?: number
    protocol: string
    bytes: number
    packets: number
    firstSeen?: number
    lastSeen?: number
  }>
  truncated: boolean
}

interface NativeDiagnostics {
  version: string
  dataRoot: string
  portableMode: boolean
  sqliteVersion: string
}

interface NativeSavedView {
  id: string
  name: string
  state: { filters?: SavedView['filters']; layout?: string } | null
}

let activeProject: NativeProject | null = null

async function ensureProject(): Promise<NativeProject> {
  if (activeProject) return activeProject
  const projects = await invoke<NativeProject[]>('list_projects')
  activeProject = projects[0] ?? await invoke<NativeProject>('create_project', { name: 'Branch Office Investigation' })
  return activeProject
}

export async function getActiveProject(): Promise<{ id: string; name: string }> {
  if (!isTauri()) {
    const name = localStorage.getItem('netmap-project-name') ?? 'Branch Office Investigation'
    return { id: 'demo', name }
  }
  const project = await ensureProject()
  return { id: project.id, name: project.name }
}

export async function renameProject(name: string): Promise<{ id: string; name: string }> {
  const trimmed = name.trim()
  if (!trimmed) throw new Error('Project name cannot be empty')
  if (trimmed.length > 120) throw new Error('Project name must be 120 characters or fewer')
  if (!isTauri()) {
    localStorage.setItem('netmap-project-name', trimmed)
    return { id: 'demo', name: trimmed }
  }
  const project = await ensureProject()
  const updated = await invoke<NativeProject>('rename_project', {
    projectId: project.id,
    name: trimmed,
  })
  activeProject = updated
  return { id: updated.id, name: updated.name }
}

function optional(value: string): string | undefined {
  return value.trim() || undefined
}

function nativeMapping(mapping: ImportMapping): NativeMapping {
  return {
    sourceIp: mapping.sourceIp.trim(),
    destinationIp: mapping.destinationIp.trim(),
    sourcePort: optional(mapping.sourcePort),
    destinationPort: optional(mapping.destinationPort),
    protocol: optional(mapping.protocol),
    timestamp: optional(mapping.timestamp),
    bytes: optional(mapping.bytes),
    packets: optional(mapping.packets),
  }
}

function frontendMapping(mapping: NativeMapping | undefined): ImportMapping {
  return {
    timestamp: mapping?.timestamp ?? '',
    sourceIp: mapping?.sourceIp ?? '',
    destinationIp: mapping?.destinationIp ?? '',
    sourcePort: mapping?.sourcePort ?? '',
    destinationPort: mapping?.destinationPort ?? '',
    protocol: mapping?.protocol ?? '',
    bytes: mapping?.bytes ?? '',
    packets: mapping?.packets ?? '',
  }
}

function normalizeProtocol(value: string): Protocol {
  const protocol = value.toUpperCase()
  if (['TCP', 'UDP', 'ICMP', 'DNS', 'HTTP', 'TLS', 'SSH'].includes(protocol)) return protocol as Protocol
  return 'OTHER'
}

function isInternal(ip: string): boolean {
  if (ip.startsWith('10.') || ip.startsWith('192.168.')) return true
  const match = /^172\.(\d+)\./.exec(ip)
  if (match && Number(match[1]) >= 16 && Number(match[1]) <= 31) return true
  const lowered = ip.toLowerCase()
  return lowered.startsWith('fc') || lowered.startsWith('fd') || lowered.startsWith('fe80:')
}

function subnetFor(ip: string): string {
  if (ip.includes(':')) return `${ip.split(':').slice(0, 4).join(':')}::/64`
  return `${ip.split('.').slice(0, 3).join('.')}.0/24`
}

function isoTime(milliseconds: number | undefined): string {
  return milliseconds === undefined ? new Date(0).toISOString() : new Date(milliseconds).toISOString()
}

function graphToDataset(graph: NativeGraph): NetworkDataset {
  return {
    nodes: graph.nodes.map((node) => ({
      id: String(node.id),
      label: node.hostname ?? node.ip,
      ip: node.ip,
      hostname: node.hostname,
      subnet: subnetFor(node.ip),
      kind: isInternal(node.ip) ? 'internal' : 'external',
      bytes: node.totalBytes,
      packets: node.totalPackets,
      firstSeen: isoTime(node.firstSeen),
      lastSeen: isoTime(node.lastSeen),
      imports: node.imports,
      tags: node.tags,
      notes: node.notes,
    })),
    edges: graph.edges.map((edge) => ({
      id: String(edge.id),
      source: String(edge.source),
      target: String(edge.target),
      protocol: normalizeProtocol(edge.protocol),
      port: edge.destinationPort ?? edge.sourcePort ?? 0,
      bytes: edge.bytes,
      packets: edge.packets,
      firstSeen: isoTime(edge.firstSeen),
      lastSeen: isoTime(edge.lastSeen),
      imports: [],
    })),
  }
}

export interface CaptureInterface {
  id: string
  name: string
}

export interface TsharkInfo {
  available: boolean
  path?: string
  message: string
}

export interface LiveCaptureSession {
  sessionId: string
  importId: string
  interfaceId: string
  interfaceName: string
  status: string
}

export interface LiveCaptureUpdate {
  sessionId: string
  importId: string
  status: string
  packets: number
  accepted: number
  skipped: number
  message?: string
  dataset?: NetworkDataset
}

interface NativeLiveUpdate {
  sessionId: string
  importId: string
  status: string
  packets: number
  accepted: number
  skipped: number
  message?: string
  dataset?: NativeGraph
}

export async function listCaptureInterfaces(): Promise<{ tshark: TsharkInfo; interfaces: CaptureInterface[] }> {
  if (!isTauri()) {
    return {
      tshark: { available: true, path: 'demo-tshark', message: 'Browser demo capture' },
      interfaces: [
        { id: '1', name: 'Demo Ethernet' },
        { id: '2', name: 'Demo Wi-Fi' },
      ],
    }
  }
  return invoke<{ tshark: TsharkInfo; interfaces: CaptureInterface[] }>('list_capture_interfaces')
}

export async function startLiveCapture(interfaceId: string, bpfFilter = ''): Promise<LiveCaptureSession> {
  if (!isTauri()) {
    return {
      sessionId: 'demo-live',
      importId: 'demo-live',
      interfaceId,
      interfaceName: interfaceId === '2' ? 'Demo Wi-Fi' : 'Demo Ethernet',
      status: 'capturing',
    }
  }
  const project = await ensureProject()
  return invoke<LiveCaptureSession>('start_live_capture', {
    projectId: project.id,
    interfaceId,
    bpfFilter: bpfFilter.trim() || null,
  })
}

export async function stopLiveCapture(): Promise<boolean> {
  if (!isTauri()) return true
  return invoke<boolean>('stop_live_capture')
}

export async function liveCaptureStatus(): Promise<LiveCaptureSession | null> {
  if (!isTauri()) return null
  return invoke<LiveCaptureSession | null>('live_capture_status')
}

export async function listenLiveCapture(
  onUpdate: (update: LiveCaptureUpdate) => void,
): Promise<() => void> {
  if (!isTauri()) {
    return () => undefined
  }
  return listen<NativeLiveUpdate>('live-capture-update', ({ payload }) => {
    onUpdate({
      sessionId: payload.sessionId,
      importId: payload.importId,
      status: payload.status,
      packets: payload.packets,
      accepted: payload.accepted,
      skipped: payload.skipped,
      message: payload.message,
      dataset: payload.dataset ? graphToDataset(payload.dataset) : undefined,
    })
  })
}

export async function loadProjectDataset(): Promise<NetworkDataset | null> {
  if (!isTauri()) return null
  const project = await ensureProject()
  const graph = await invoke<NativeGraph>('query_graph', {
    projectId: project.id,
    filters: { limit: 5000 },
  })
  return graphToDataset(graph)
}

export async function loadSavedViews(): Promise<SavedView[] | null> {
  if (!isTauri()) return null
  const project = await ensureProject()
  const records = await invoke<NativeSavedView[]>('list_views', { projectId: project.id })
  return records.flatMap((record) => record.state?.filters && record.state.layout
    ? [{ id: record.id, name: record.name, filters: record.state.filters, layout: record.state.layout }]
    : [])
}

export async function persistSavedView(view: SavedView): Promise<void> {
  if (!isTauri()) return
  const project = await ensureProject()
  await invoke('save_view', {
    projectId: project.id,
    viewId: view.id,
    name: view.name,
    stateJson: { filters: view.filters, layout: view.layout },
  })
}

export async function persistNodeMetadata(node: NetworkNode): Promise<void> {
  if (!isTauri()) return
  const project = await ensureProject()
  await invoke('set_node_metadata', {
    projectId: project.id,
    nodeId: Number(node.id),
    tags: node.tags,
    notes: node.notes ?? null,
  })
}

export async function chooseFiles(kind: 'csv' | 'pcap'): Promise<string[]> {
  if (!isTauri()) return kind === 'csv' ? ['sensor-east-2026-08-03.csv'] : ['branch-office-capture.pcap']
  const extensions = kind === 'csv' ? ['csv', 'tsv', 'log'] : ['pcap', 'pcapng', 'cap']
  const result = await open({ multiple: true, filters: [{ name: kind.toUpperCase(), extensions }] })
  return typeof result === 'string' ? [result] : result ?? []
}

export async function previewCsv(path: string, browserFile?: File): Promise<CsvPreview> {
  if (isTauri()) {
    const preview = await invoke<NativePreview>('preview_csv', { path })
    const rows = preview.rows.map((values) => Object.fromEntries(
      preview.headers.map((header, index) => [header, values[index] ?? '']),
    ))
    const fallback = createCsvPreview(path.split(/[\\/]/).at(-1) ?? path, rows, preview.headers)
    return {
      ...fallback,
      schema: preview.detectedFormat?.includes('Zeek')
        ? 'Zeek'
        : preview.detectedFormat
          ? 'Security Onion / ECS'
          : fallback.schema,
      mapping: preview.suggestedMapping ? frontendMapping(preview.suggestedMapping) : fallback.mapping,
    }
  }
  if (browserFile) {
    const text = await browserFile.text()
    const parsed = Papa.parse<Record<string, string>>(text, { header: true, skipEmptyLines: true })
    return createCsvPreview(browserFile.name, parsed.data, parsed.meta.fields ?? [])
  }
  return createCsvPreview(path, sampleCsvRows, Object.keys(sampleCsvRows[0] ?? {}))
}

export async function importCapture(
  paths: string[],
  mapping: ImportMapping | null,
  onProgress: (progress: ImportProgress) => void,
  signal: AbortSignal,
): Promise<ImportResult> {
  if (isTauri()) {
    const project = await ensureProject()
    let currentImportId = ''
    let accepted = 0
    let skipped = 0
    const warnings: string[] = []
    const unlisten = await listen<NativeProgress>('import-progress', ({ payload }) => {
      currentImportId = payload.importId
      onProgress({
        phase: payload.phase,
        percent: payload.completed ? 100 : Math.round(Math.min(95, 5 + Math.log10(payload.processed + 1) * 18)),
        processed: payload.processed,
        total: 0,
      })
    })
    const cancel = () => {
      if (currentImportId) void invoke('cancel_import', { importId: currentImportId })
    }
    signal.addEventListener('abort', cancel)
    try {
      for (const path of paths) {
        if (signal.aborted) throw new DOMException('Import cancelled', 'AbortError')
        const command = path.toLowerCase().endsWith('.csv') || path.toLowerCase().endsWith('.tsv')
          ? 'import_csv'
          : 'import_pcap'
        const result = await invoke<NativeImportResult>(command, {
          projectId: project.id,
          path,
          ...(command === 'import_csv' && mapping ? { mapping: nativeMapping(mapping) } : {}),
        })
        accepted += result.accepted
        skipped += result.skipped
        warnings.push(...result.warnings)
        if (result.cancelled || signal.aborted) throw new DOMException('Import cancelled', 'AbortError')
      }
      const graph = await invoke<NativeGraph>('query_graph', {
        projectId: project.id,
        filters: { limit: 5000 },
      })
      return {
        importedRows: accepted,
        skippedRows: skipped,
        warnings: graph.truncated ? [...warnings, 'The map was limited to the 5,000 busiest flows.'] : warnings,
        dataset: graphToDataset(graph),
      }
    } finally {
      signal.removeEventListener('abort', cancel)
      unlisten()
    }
  }
  const phases = ['Reading capture', 'Normalizing fields', 'Building flow index', 'Calculating topology']
  for (let step = 1; step <= 20; step += 1) {
    if (signal.aborted) throw new DOMException('Import cancelled', 'AbortError')
    await new Promise((resolve) => window.setTimeout(resolve, 90))
    onProgress({
      phase: phases[Math.min(phases.length - 1, Math.floor((step - 1) / 5))],
      percent: step * 5,
      processed: step * 924,
      total: 18_480,
    })
  }
  return { importedRows: 18_436, skippedRows: 44, warnings: ['44 incomplete flows were skipped.'], dataset: demoDataset }
}

export async function getDiagnostics(dataset: NetworkDataset): Promise<Diagnostics> {
  if (isTauri()) {
    const diagnostics = await invoke<NativeDiagnostics>('diagnostics')
    return {
      mode: 'Tauri native',
      version: diagnostics.version,
      platform: `Windows · SQLite ${diagnostics.sqliteVersion}${diagnostics.portableMode ? ' · Portable' : ' · Development'}`,
      nodeCount: dataset.nodes.length,
      edgeCount: dataset.edges.length,
    }
  }
  return {
    mode: 'Browser demo',
    version: '0.3.0',
    platform: navigator.platform || 'Browser',
    nodeCount: dataset.nodes.length,
    edgeCount: dataset.edges.length,
  }
}
