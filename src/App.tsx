import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import './App.css'
import {
  chooseFiles,
  getActiveProject,
  getDiagnostics,
  importCapture,
  isTauri,
  listTestCaptures,
  listCaptureInterfaces,
  listenLiveCapture,
  loadProjectDataset,
  loadSavedViews,
  persistNodeMetadata,
  persistSavedView,
  previewCsv,
  queryPackets,
  renameProject,
  startLiveCapture,
  stopLiveCapture,
  type CaptureInterface,
  type LiveCaptureUpdate,
  type TsharkInfo,
} from './api'
import { demoDataset } from './demoData'
import {
  analyzeBaseline,
  ANOMALY_LABELS,
  ASSET_ROLES,
  datasetAtPercent,
  datasetTimeBounds,
  enrichAssetMetadata,
  SECURITY_ZONES,
  timeAtPercent,
} from './insights'
import { injectDemoLiveFlow } from './liveDemo'
import NetworkMap, { type NetworkMapHandle } from './NetworkMap'
import { ASSET_ROLE_HELP, CONTROL_HELP, PROTOCOL_HELP, ZONE_HELP } from './plainLanguageHelp'
import { OT_PROTOCOLS, STANDARD_PROTOCOLS } from './protocols'
import type {
  AggregatedEdge,
  CsvPreview,
  Diagnostics,
  EdgeDisplayMode,
  FilterState,
  HostScope,
  ImportMapping,
  ImportProgress,
  PacketPage,
  PacketRecord,
  PcapImportOptions,
  NetworkDataset,
  NetworkEdge,
  NetworkNode,
  PathDirection,
  SavedView,
  TestCapture,
} from './types'
import { aggregatePairEdges, downloadText, exportDatasetCsv, filterDataset, summarizeNode } from './utils'
import { APP_VERSION } from './version'

const defaultFilters: FilterState = {
  query: '', startTime: '', endTime: '', port: '', protocols: [], minBytes: 0, minPackets: 0,
  direction: 'all', hostScope: 'all', neighborhood: 0, hideIsolates: true, hideNoise: false,
  groupSubnets: false, complexityCap: 250, edgeMode: 'aggregate', showEdgeLabels: false,
}

type ImportStage = 'source' | 'mapping' | 'progress' | 'complete'
type WorkspaceTab = 'investigation' | 'packets' | 'live'

const defaultPcapOptions: PcapImportOptions = {
  packetIndexing: false,
  macAddresses: true,
  dnsHostnames: true,
  tcpFlags: false,
  payloadPreviewBytes: 0,
}

function formatBytes(bytes: number): string {
  if (bytes >= 1_000_000) return `${(bytes / 1_000_000).toFixed(1)} MB`
  if (bytes >= 1_000) return `${(bytes / 1_000).toFixed(1)} KB`
  return `${bytes} B`
}

function formatTime(value: string): string {
  return new Date(value).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' })
}

function Icon({ name }: { name: string }) {
  const paths: Record<string, string> = {
    map: 'M3 6l5-3 8 3 5-3v15l-5 3-8-3-5 3V6zm5-3v15m8-12v15',
    import: 'M12 3v12m-4-4 4 4 4-4M4 17v4h16v-4',
    search: 'M11 4a7 7 0 100 14 7 7 0 000-14zm5 12 5 5',
    fit: 'M8 3H3v5m13-5h5v5M8 21H3v-5m13 5h5v-5',
    export: 'M12 15V3m-4 4 4-4 4 4M4 13v8h16v-8',
    info: 'M12 22a10 10 0 100-20 10 10 0 000 20zm0-11v6m0-10v.01',
    help: 'M12 22a10 10 0 100-20 10 10 0 000 20zm-3-13a3 3 0 116 0c0 2-3 2-3 5m0 3v.01',
    close: 'M5 5l14 14M19 5L5 19',
  }
  return <svg viewBox="0 0 24 24" aria-hidden="true"><path d={paths[name]} /></svg>
}

function HelpHint({ text }: { text: string }) {
  return <abbr className="help-hint" title={text} aria-label={`Plain-language help: ${text}`} tabIndex={0}>?</abbr>
}

function App() {
  const [dataset, setDataset] = useState<NetworkDataset>(demoDataset)
  const [filters, setFilters] = useState(defaultFilters)
  const [layout, setLayout] = useState('cose')
  const [selectedNode, setSelectedNode] = useState<NetworkNode | null>(demoDataset.nodes[6] ?? null)
  const [selectedEdge, setSelectedEdge] = useState<NetworkEdge | null>(null)
  const [selectedAggregate, setSelectedAggregate] = useState<AggregatedEdge | null>(null)
  const [expandedPairId, setExpandedPairId] = useState<string | null>(null)
  const [theme, setTheme] = useState<'dark' | 'light'>('dark')
  const [importOpen, setImportOpen] = useState(false)
  const [importStage, setImportStage] = useState<ImportStage>('source')
  const [importKind, setImportKind] = useState<'csv' | 'pcap'>('csv')
  const [importPaths, setImportPaths] = useState<string[]>([])
  const [preview, setPreview] = useState<CsvPreview | null>(null)
  const [mapping, setMapping] = useState<ImportMapping | null>(null)
  const [progress, setProgress] = useState<ImportProgress | null>(null)
  const [importError, setImportError] = useState('')
  const [importSummary, setImportSummary] = useState('')
  const [mergeWithExisting, setMergeWithExisting] = useState(false)
  const [pcapOptions, setPcapOptions] = useState<PcapImportOptions>(defaultPcapOptions)
  const [savedViews, setSavedViews] = useState<SavedView[]>([
    { id: 'cross', name: 'Boundary traffic', filters: { ...defaultFilters, direction: 'cross-boundary' }, layout: 'cose' },
    { id: 'watch', name: 'Suspicious host ±1', filters: { ...defaultFilters, query: '185.220.101.42', neighborhood: 1 }, layout: 'breadthfirst' },
  ])
  const [diagnostics, setDiagnostics] = useState<Diagnostics | null>(null)
  const [diagnosticsOpen, setDiagnosticsOpen] = useState(false)
  const [helpOpen, setHelpOpen] = useState(false)
  const [showHostnames, setShowHostnames] = useState(true)
  const [nodeSpacing, setNodeSpacing] = useState(70)
  const [groupZones, setGroupZones] = useState(false)
  const [groupPurdue, setGroupPurdue] = useState(false)
  const [showConduits, setShowConduits] = useState(false)
  const [showAnomalies, setShowAnomalies] = useState(false)
  const [baselinePercent, setBaselinePercent] = useState(30)
  const [pathDirection, setPathDirection] = useState<PathDirection>('both')
  const [timelineEnabled, setTimelineEnabled] = useState(false)
  const [timelinePercent, setTimelinePercent] = useState(100)
  const [timelinePlaying, setTimelinePlaying] = useState(false)
  const [testCaptureOpen, setTestCaptureOpen] = useState(false)
  const [testCaptures, setTestCaptures] = useState<TestCapture[]>([])
  const [testCaptureError, setTestCaptureError] = useState('')
  const [zoomPercent, setZoomPercent] = useState(100)
  const [projectName, setProjectName] = useState('Branch Office Investigation')
  const [editingProjectName, setEditingProjectName] = useState(false)
  const [projectNameDraft, setProjectNameDraft] = useState('Branch Office Investigation')
  const [workspaceTab, setWorkspaceTab] = useState<WorkspaceTab>('investigation')
  const [liveDataset, setLiveDataset] = useState<NetworkDataset>({ nodes: [], edges: [] })
  const [mapLiveDataset, setMapLiveDataset] = useState<NetworkDataset>({ nodes: [], edges: [] })
  const [captureInterfaces, setCaptureInterfaces] = useState<CaptureInterface[]>([])
  const [tsharkInfo, setTsharkInfo] = useState<TsharkInfo | null>(null)
  const [selectedInterfaceId, setSelectedInterfaceId] = useState('')
  const [bpfFilter, setBpfFilter] = useState('')
  const [liveStatus, setLiveStatus] = useState('idle')
  const [livePackets, setLivePackets] = useState(0)
  const [liveAccepted, setLiveAccepted] = useState(0)
  const [liveSkipped, setLiveSkipped] = useState(0)
  const [liveMessage, setLiveMessage] = useState('')
  const [liveCapturing, setLiveCapturing] = useState(false)
  const [liveStartedAt, setLiveStartedAt] = useState<number | null>(null)
  const [liveClock, setLiveClock] = useState(0)
  const abortRef = useRef<AbortController | null>(null)
  const mapRef = useRef<NetworkMapHandle>(null)
  const metadataTimerRef = useRef<number | null>(null)
  const projectNameInputRef = useRef<HTMLInputElement>(null)
  const liveThrottleRef = useRef<number | null>(null)
  const demoLiveTimerRef = useRef<number | null>(null)

  useEffect(() => {
    void getActiveProject()
      .then((project) => {
        setProjectName(project.name)
        setProjectNameDraft(project.name)
      })
      .catch((error) => setImportError(error instanceof Error ? error.message : String(error)))
    void loadProjectDataset()
      .then((stored) => {
        if (stored) {
          setDataset(stored)
          setSelectedNode(stored.nodes[0] ?? null)
        }
      })
      .catch((error) => setImportError(error instanceof Error ? error.message : String(error)))
    void loadSavedViews()
      .then((stored) => {
        if (stored) setSavedViews(stored)
      })
      .catch((error) => setImportError(error instanceof Error ? error.message : String(error)))
    return () => {
      if (metadataTimerRef.current !== null) window.clearTimeout(metadataTimerRef.current)
    }
  }, [])

  useEffect(() => {
    if (editingProjectName) projectNameInputRef.current?.focus()
  }, [editingProjectName])

  useEffect(() => {
    if (!liveCapturing || liveStartedAt === null) return undefined
    const timer = window.setInterval(() => setLiveClock(Date.now()), 1000)
    return () => window.clearInterval(timer)
  }, [liveCapturing, liveStartedAt])

  useEffect(() => {
    if (!timelinePlaying) return undefined
    const timer = window.setInterval(() => {
      setTimelinePercent((current) => {
        if (current >= 99) {
          setTimelinePlaying(false)
          return 100
        }
        return current + 1
      })
    }, 160)
    return () => window.clearInterval(timer)
  }, [timelinePlaying])

  useEffect(() => {
    let cancelled = false
    void listCaptureInterfaces()
      .then((result) => {
        if (cancelled) return
        setTsharkInfo(result.tshark)
        setCaptureInterfaces(result.interfaces)
        setSelectedInterfaceId((current) => current || result.interfaces[0]?.id || '')
      })
      .catch((error) => {
        if (!cancelled) setLiveMessage(error instanceof Error ? error.message : String(error))
      })
    return () => { cancelled = true }
  }, [])

  useEffect(() => {
    let unlisten: (() => void) | undefined
    void listenLiveCapture((update: LiveCaptureUpdate) => {
      setLiveStatus(update.status)
      setLivePackets(update.packets)
      setLiveAccepted(update.accepted)
      setLiveSkipped(update.skipped)
      if (update.message) setLiveMessage(update.message)
      const active = update.status === 'capturing' || update.status === 'starting' || update.status === 'stopping'
      setLiveCapturing(active)
      if (update.dataset) {
        setLiveDataset(update.dataset)
        if (liveThrottleRef.current !== null) window.clearTimeout(liveThrottleRef.current)
        liveThrottleRef.current = window.setTimeout(() => {
          setMapLiveDataset(update.dataset!)
          liveThrottleRef.current = null
        }, 1000)
      }
      if (update.status === 'complete' || update.status === 'cancelled' || update.status === 'failed') {
        if (update.dataset) setMapLiveDataset(update.dataset)
        void loadProjectDataset()
          .then((stored) => { if (stored) setDataset(stored) })
          .catch(() => undefined)
      }
    }).then((stop) => { unlisten = stop })
    return () => {
      unlisten?.()
      if (liveThrottleRef.current !== null) window.clearTimeout(liveThrottleRef.current)
      if (demoLiveTimerRef.current !== null) window.clearInterval(demoLiveTimerRef.current)
    }
  }, [])

  const rawActiveDataset = workspaceTab === 'live' ? liveDataset : dataset
  const rawMapDataset = workspaceTab === 'live' ? mapLiveDataset : dataset
  const activeDataset = useMemo(
    () => analyzeBaseline(enrichAssetMetadata(rawActiveDataset), baselinePercent),
    [baselinePercent, rawActiveDataset],
  )
  const analyzedMapDataset = useMemo(
    () => analyzeBaseline(enrichAssetMetadata(rawMapDataset), baselinePercent),
    [baselinePercent, rawMapDataset],
  )
  const timelineBounds = useMemo(() => datasetTimeBounds(analyzedMapDataset), [analyzedMapDataset])
  const mapDataset = useMemo(
    () => timelineEnabled ? datasetAtPercent(analyzedMapDataset, timelinePercent) : analyzedMapDataset,
    [analyzedMapDataset, timelineEnabled, timelinePercent],
  )
  const visible = useMemo(() => filterDataset(mapDataset, filters), [filters, mapDataset])
  const aggregatedEdges = useMemo(() => aggregatePairEdges(visible.edges), [visible.edges])
  const resolvedSelectedNode = selectedNode
    ? activeDataset.nodes.find((node) => node.id === selectedNode.id) ?? selectedNode
    : null
  const anomalousEdges = useMemo(
    () => visible.edges.filter((edge) => edge.anomalies?.length),
    [visible.edges],
  )
  useEffect(() => {
    if (selectedNode && !visible.nodes.some((node) => node.id === selectedNode.id)) {
      setSelectedNode(null)
    }
    if (selectedEdge && !visible.edges.some((edge) => edge.id === selectedEdge.id)) {
      setSelectedEdge(null)
    }
    if (selectedAggregate && !aggregatedEdges.some((edge) => edge.id === selectedAggregate.id)) {
      setSelectedAggregate(null)
      if (expandedPairId === selectedAggregate.id) setExpandedPairId(null)
    }
  }, [aggregatedEdges, expandedPairId, selectedAggregate, selectedEdge, selectedNode, visible])
  const nodeEdges = useMemo(
    () => resolvedSelectedNode ? summarizeNode(resolvedSelectedNode, activeDataset) : [],
    [activeDataset, resolvedSelectedNode],
  )
  const connectionCount = filters.edgeMode === 'hidden'
    ? 0
    : filters.edgeMode === 'aggregate'
      ? aggregatedEdges.length
      : visible.edges.length

  const updateFilter = <K extends keyof FilterState>(key: K, value: FilterState[K]) => {
    setFilters((current) => ({ ...current, [key]: value }))
    if (key === 'edgeMode') {
      setExpandedPairId(null)
      setSelectedAggregate(null)
      setSelectedEdge(null)
    }
  }
  const onSelectNode = useCallback((node: NetworkNode | null) => {
    setSelectedNode(node)
    if (node) {
      setSelectedEdge(null)
      setSelectedAggregate(null)
    }
  }, [])
  const onSelectEdge = useCallback((edge: NetworkEdge | null) => {
    setSelectedEdge(edge)
    if (edge) {
      setSelectedNode(null)
      setSelectedAggregate(null)
    }
  }, [])
  const onSelectAggregatedEdge = useCallback((edge: AggregatedEdge | null) => {
    setSelectedAggregate(edge)
    if (edge) {
      setSelectedEdge(null)
      setSelectedNode(null)
    }
  }, [])
  const onZoomChange = useCallback((zoom: number) => setZoomPercent(Math.round(zoom * 100)), [])

  const beginDemoLiveStream = (interfaceId: string) => {
    if (demoLiveTimerRef.current !== null) window.clearInterval(demoLiveTimerRef.current)
    setLiveStartedAt(Date.now())
    setLiveCapturing(true)
    setLiveStatus('capturing')
    setLiveMessage(`Demo capture on ${interfaceId === '2' ? 'Demo Wi-Fi' : 'Demo Ethernet'}`)
    let tick = 0
    demoLiveTimerRef.current = window.setInterval(() => {
      tick += 1
      setLiveDataset((current) => {
        const next = injectDemoLiveFlow(current, tick)
        if (tick % 2 === 0) setMapLiveDataset(next)
        setLivePackets(tick * 12)
        setLiveAccepted(next.edges.length)
        setLiveSkipped(0)
        return next
      })
    }, 700)
  }

  const handleStartLive = async () => {
    setLiveMessage('')
    setLivePackets(0)
    setLiveAccepted(0)
    setLiveSkipped(0)
    setLiveDataset({ nodes: [], edges: [] })
    setMapLiveDataset({ nodes: [], edges: [] })
    try {
      if (!isTauri()) {
        beginDemoLiveStream(selectedInterfaceId || '1')
        return
      }
      const session = await startLiveCapture(selectedInterfaceId, bpfFilter)
      setLiveStartedAt(Date.now())
      setLiveCapturing(true)
      setLiveStatus(session.status)
      setLiveMessage(`Capturing on ${session.interfaceName}`)
    } catch (error) {
      setLiveCapturing(false)
      setLiveStatus('failed')
      setLiveMessage(error instanceof Error ? error.message : String(error))
    }
  }

  const handleStopLive = async () => {
    if (demoLiveTimerRef.current !== null) {
      window.clearInterval(demoLiveTimerRef.current)
      demoLiveTimerRef.current = null
    }
    try {
      await stopLiveCapture()
    } catch (error) {
      setLiveMessage(error instanceof Error ? error.message : String(error))
    }
    setLiveCapturing(false)
    setLiveStatus('stopped')
    setLiveStartedAt(null)
  }

  const openImporter = (kind: 'csv' | 'pcap') => {
    setImportKind(kind)
    setImportPaths([])
    setPreview(null)
    setMapping(null)
    setImportError('')
    setImportSummary('')
    setMergeWithExisting(false)
    setImportStage('source')
    setImportOpen(true)
  }

  const openTestCaptureChooser = async () => {
    setTestCaptureError('')
    setTestCaptureOpen(true)
    try {
      setTestCaptures(await listTestCaptures())
    } catch (error) {
      setTestCaptureError(error instanceof Error ? error.message : String(error))
    }
  }

  const chooseTestCapture = (capture: TestCapture) => {
    setTestCaptureOpen(false)
    setImportKind('pcap')
    setImportPaths([capture.path])
    setPreview(null)
    setMapping(null)
    setImportError('')
    setImportSummary('')
    setMergeWithExisting(false)
    setImportStage('source')
    setShowAnomalies(false)
    setShowConduits(false)
    setImportOpen(true)
  }

  const selectNativeFiles = async () => {
    try {
      const paths = await chooseFiles(importKind)
      if (!paths.length) return
      setImportPaths(paths)
      if (importKind === 'csv') {
        const result = await previewCsv(paths[0])
        setPreview(result)
        setMapping(result.mapping)
      }
    } catch (error) {
      setImportError(error instanceof Error ? error.message : String(error))
    }
  }

  const selectBrowserFile = async (file: File | undefined) => {
    if (!file) return
    try {
      setImportPaths([file.name])
      if (importKind === 'csv') {
        const result = await previewCsv(file.name, file)
        setPreview(result)
        setMapping(result.mapping)
      }
    } catch (error) {
      setImportError(error instanceof Error ? error.message : String(error))
    }
  }

  const runImport = async () => {
    const controller = new AbortController()
    abortRef.current = controller
    setImportStage('progress')
    setImportError('')
    try {
      const result = await importCapture(importPaths, mapping, mergeWithExisting, setProgress, controller.signal, pcapOptions)
      setDataset(result.dataset)
      setFilters(defaultFilters)
      setTimelinePercent(100)
      setTimelinePlaying(false)
      setImportSummary(`${result.importedRows.toLocaleString()} rows imported · ${result.skippedRows} skipped · ${mergeWithExisting ? 'merged with existing map' : 'replaced previous map'}${result.warnings.length ? ` · ${result.warnings[0]}` : ''}`)
      setImportStage('complete')
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') {
        setImportError('Import cancelled. No project data was changed.')
      } else {
        setImportError(error instanceof Error ? error.message : String(error))
      }
      setImportStage('source')
    } finally {
      abortRef.current = null
    }
  }

  const showDiagnostics = async () => {
    setDiagnosticsOpen(true)
    try {
      setDiagnostics(await getDiagnostics(dataset))
    } catch {
      setDiagnostics({
        mode: isTauri() ? 'Tauri native' : 'Browser demo',
        version: APP_VERSION,
        platform: navigator.platform,
        nodeCount: dataset.nodes.length,
        edgeCount: dataset.edges.length,
      })
    }
  }

  const saveView = () => {
    const name = window.prompt('Name this view', `Investigation ${savedViews.length + 1}`)
    if (!name?.trim()) return
    const view = { id: crypto.randomUUID(), name: name.trim(), filters, layout }
    setSavedViews((views) => [...views, view])
    void persistSavedView(view).catch((error) => setImportError(error instanceof Error ? error.message : String(error)))
  }

  const updateNodeMetadata = (changed: NetworkNode) => {
    const patch = (current: NetworkDataset): NetworkDataset => ({
      ...current,
      nodes: current.nodes.map((node) => node.id === changed.id ? changed : node),
    })
    setDataset(patch)
    setLiveDataset(patch)
    setMapLiveDataset(patch)
    setSelectedNode(changed)
    if (metadataTimerRef.current !== null) window.clearTimeout(metadataTimerRef.current)
    metadataTimerRef.current = window.setTimeout(() => {
      void persistNodeMetadata(changed)
        .catch((error) => setImportError(error instanceof Error ? error.message : String(error)))
    }, 400)
  }

  const edgePeer = (edge: NetworkEdge, node: NetworkNode): NetworkNode | undefined => {
    const peerId = edge.source === node.id ? edge.target : edge.source
    return activeDataset.nodes.find((item) => item.id === peerId)
  }

  const liveElapsed = liveStartedAt
    ? Math.max(0, Math.floor(((liveClock || Date.now()) - liveStartedAt) / 1000))
    : 0
  const timelineTimestamp = timeAtPercent(timelineBounds, timelinePercent)

  const beginRenameProject = () => {
    setProjectNameDraft(projectName)
    setEditingProjectName(true)
  }

  const commitProjectName = async () => {
    const next = projectNameDraft.trim()
    setEditingProjectName(false)
    if (!next || next === projectName) {
      setProjectNameDraft(projectName)
      return
    }
    try {
      const updated = await renameProject(next)
      setProjectName(updated.name)
      setProjectNameDraft(updated.name)
    } catch (error) {
      setProjectNameDraft(projectName)
      setImportError(error instanceof Error ? error.message : String(error))
    }
  }

  return (
    <div className="app" data-theme={theme}>
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark"><Icon name="map" /></span>
          <div><strong>NetMap</strong><small>PORTABLE</small></div>
        </div>
        <div className="project-title">
          <span className="status-dot" />
          {editingProjectName ? (
            <input
              ref={projectNameInputRef}
              className="project-name-input"
              value={projectNameDraft}
              maxLength={120}
              aria-label="Project name"
              onChange={(event) => setProjectNameDraft(event.target.value)}
              onBlur={() => { void commitProjectName() }}
              onKeyDown={(event) => {
                if (event.key === 'Enter') {
                  event.preventDefault()
                  void commitProjectName()
                }
                if (event.key === 'Escape') {
                  setProjectNameDraft(projectName)
                  setEditingProjectName(false)
                }
              }}
            />
          ) : (
            <button type="button" className="project-name-button" onClick={beginRenameProject} title="Rename project">
              {projectName}
            </button>
          )}
          <span className="muted">/ {dataset.nodes.length} hosts</span>
        </div>
        <div className="top-actions">
          <span className="mode-badge">{isTauri() ? 'LOCAL' : 'DEMO'} · v{APP_VERSION} · OFFLINE</span>
          <button className="icon-button" onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')} aria-label="Toggle color theme">
            {theme === 'dark' ? '☼' : '☾'}
          </button>
          <button className="icon-button" onClick={() => setHelpOpen(true)} aria-label="Open documentation"><Icon name="help" /></button>
          <button className="icon-button" onClick={showDiagnostics} aria-label="Open diagnostics"><Icon name="info" /></button>
        </div>
      </header>

      <div className="workspace-tabs" role="tablist" aria-label="Workspace">
        <button
          type="button"
          role="tab"
          aria-selected={workspaceTab === 'investigation'}
          className={workspaceTab === 'investigation' ? 'active' : ''}
          onClick={() => setWorkspaceTab('investigation')}
        >
          Investigation
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={workspaceTab === 'packets'}
          className={workspaceTab === 'packets' ? 'active' : ''}
          onClick={() => setWorkspaceTab('packets')}
        >
          Packet inspection
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={workspaceTab === 'live'}
          className={workspaceTab === 'live' ? 'active' : ''}
          onClick={() => setWorkspaceTab('live')}
        >
          Live{liveCapturing ? ' · REC' : ''}
        </button>
      </div>

      {workspaceTab === 'packets' ? <PacketInspector /> : <div className="workspace">
        <aside className="sidebar" aria-label="Project and filters">
          <div className="side-scroll">
            {workspaceTab === 'live' ? (
              <section className="side-section">
                <div className="section-heading"><span>LIVE CAPTURE</span></div>
                <p className={`live-tshark ${tsharkInfo?.available ? 'ok' : 'missing'}`}>
                  {tsharkInfo?.message ?? 'Checking for tshark…'}
                </p>
                {tsharkInfo?.path && <p className="filter-help">{tsharkInfo.path}</p>}
                <label>Interface <HelpHint text={CONTROL_HELP.interface} />
                  <select
                    value={selectedInterfaceId}
                    disabled={liveCapturing}
                    onChange={(event) => setSelectedInterfaceId(event.target.value)}
                  >
                    {captureInterfaces.length === 0 && <option value="">No adapters found</option>}
                    {captureInterfaces.map((iface) => (
                      <option key={iface.id} value={iface.id}>{iface.id}. {iface.name}</option>
                    ))}
                  </select>
                </label>
                <label>BPF filter (optional) <HelpHint text={CONTROL_HELP.bpf} />
                  <input
                    value={bpfFilter}
                    disabled={liveCapturing}
                    onChange={(event) => setBpfFilter(event.target.value)}
                    placeholder="host 10.0.0.1 or port 53"
                  />
                </label>
                <div className="import-buttons">
                  {!liveCapturing ? (
                    <button className="primary-live" disabled={!selectedInterfaceId || (isTauri() && !tsharkInfo?.available)} onClick={() => { void handleStartLive() }}>
                      Start capture
                    </button>
                  ) : (
                    <button className="danger-live" onClick={() => { void handleStopLive() }}>Stop capture</button>
                  )}
                </div>
                <dl className="live-stats">
                  <div><dt>Status</dt><dd>{liveStatus}</dd></div>
                  <div><dt>Packets</dt><dd>{livePackets.toLocaleString()}</dd></div>
                  <div><dt>Flows</dt><dd>{liveAccepted.toLocaleString()}</dd></div>
                  <div><dt>Skipped</dt><dd>{liveSkipped.toLocaleString()}</dd></div>
                  <div><dt>Elapsed</dt><dd>{liveCapturing ? `${liveElapsed}s` : '—'}</dd></div>
                </dl>
                {liveMessage && <p className="filter-help">{liveMessage}</p>}
                <p className="filter-help">Requires Wireshark/tshark and Npcap. Run as Administrator if the adapter list is empty.</p>
              </section>
            ) : null}
            {workspaceTab === 'investigation' ? (
            <section className="side-section">
              <div className="section-heading"><span>PROJECT</span><button className="text-button" onClick={() => openImporter('csv')}>＋ New</button></div>
              <div className="project-card">
                <div className="project-icon"><Icon name="map" /></div>
                <div className="project-card-copy">
                  {editingProjectName ? (
                    <input
                      className="project-name-input"
                      value={projectNameDraft}
                      maxLength={120}
                      aria-label="Project name"
                      onChange={(event) => setProjectNameDraft(event.target.value)}
                      onBlur={() => { void commitProjectName() }}
                      onKeyDown={(event) => {
                        if (event.key === 'Enter') {
                          event.preventDefault()
                          void commitProjectName()
                        }
                        if (event.key === 'Escape') {
                          setProjectNameDraft(projectName)
                          setEditingProjectName(false)
                        }
                      }}
                    />
                  ) : (
                    <button type="button" className="project-name-button" onClick={beginRenameProject} title="Rename project">
                      <strong>{projectName}</strong>
                    </button>
                  )}
                  <small>{dataset.nodes.length} hosts · {dataset.edges.length} flows</small>
                </div>
                <button type="button" className="text-button project-rename" onClick={beginRenameProject} title="Rename project">Rename</button>
              </div>
              <div className="import-buttons">
                <button onClick={() => openImporter('csv')}><Icon name="import" /> Import CSV</button>
                <button onClick={() => openImporter('pcap')}><Icon name="import" /> Select PCAP</button>
                <button className="test-pcap-button" onClick={() => { void openTestCaptureChooser() }}><Icon name="map" /> Test PCAP</button>
              </div>
            </section>
            ) : null}

            <section className="side-section filters">
              <div className="section-heading">
                <span>FILTERS</span>
                <div className="section-actions">
                  <button className="text-button" onClick={() => setHelpOpen(true)}>Plain guide</button>
                  <button className="text-button" onClick={() => { setFilters(defaultFilters); setExpandedPairId(null); setSelectedAggregate(null) }}>Reset</button>
                </div>
              </div>
              <label className="search-field">
                <span className="sr-only">Search IPs, hostnames, MAC addresses, vendors, or CIDR ranges</span>
                <Icon name="search" />
                <input title={CONTROL_HELP.search} value={filters.query} onChange={(event) => updateFilter('query', event.target.value)} placeholder="IP, name, MAC, vendor, or CIDR" />
                <kbd>⌘ K</kbd>
              </label>
              <p className="filter-help">Search IPs, names, MACs, vendors, or CIDR ranges. Comma-separate several values. <HelpHint text={CONTROL_HELP.search} /></p>
              <div className="field-grid">
                <label>From <HelpHint text={CONTROL_HELP.time} /><input type="datetime-local" value={filters.startTime} onChange={(event) => updateFilter('startTime', event.target.value)} /></label>
                <label>To <HelpHint text={CONTROL_HELP.time} /><input type="datetime-local" value={filters.endTime} onChange={(event) => updateFilter('endTime', event.target.value)} /></label>
              </div>
              <label>Port <HelpHint text={CONTROL_HELP.port} /><input value={filters.port} inputMode="numeric" onChange={(event) => updateFilter('port', event.target.value.replace(/\D/g, ''))} placeholder="Any port" /></label>
              <fieldset>
                <legend>Protocol <HelpHint text={CONTROL_HELP.protocol} /></legend>
                <div className="protocol-chips">
                  {STANDARD_PROTOCOLS.map((protocol) => (
                    <button
                      type="button"
                      key={protocol}
                      title={PROTOCOL_HELP[protocol]}
                      aria-label={`${protocol}: ${PROTOCOL_HELP[protocol]}`}
                      className={filters.protocols.includes(protocol) ? 'active' : ''}
                      onClick={() => updateFilter('protocols', filters.protocols.includes(protocol)
                        ? filters.protocols.filter((item) => item !== protocol)
                        : [...filters.protocols, protocol])}
                    >{protocol}</button>
                  ))}
                </div>
              </fieldset>
              <fieldset>
                <legend>OT / ICS protocol <HelpHint text={CONTROL_HELP.otProtocol} /></legend>
                <div className="protocol-chips ot-protocol-chips">
                  {OT_PROTOCOLS.map((protocol) => (
                    <button
                      type="button"
                      key={protocol}
                      title={PROTOCOL_HELP[protocol]}
                      aria-label={`${protocol}: ${PROTOCOL_HELP[protocol]}`}
                      className={filters.protocols.includes(protocol) ? 'active' : ''}
                      onClick={() => updateFilter('protocols', filters.protocols.includes(protocol)
                        ? filters.protocols.filter((item) => item !== protocol)
                        : [...filters.protocols, protocol])}
                    >{protocol}</button>
                  ))}
                </div>
                <p className="filter-help">OT controls physical equipment; ICS means industrial control system. Hover a protocol for a plain-language definition.</p>
              </fieldset>
              <div className="field-grid">
                <label>Min bytes <HelpHint text={CONTROL_HELP.minBytes} /><input type="number" min="0" value={filters.minBytes} onChange={(event) => updateFilter('minBytes', Number(event.target.value))} /></label>
                <label>Min packets <HelpHint text={CONTROL_HELP.minPackets} /><input type="number" min="0" value={filters.minPackets} onChange={(event) => updateFilter('minPackets', Number(event.target.value))} /></label>
              </div>
              <label>Host scope <HelpHint text={CONTROL_HELP.hostScope} />
                <select value={filters.hostScope} onChange={(event) => updateFilter('hostScope', event.target.value as HostScope)}>
                  <option value="all">All hosts</option>
                  <option value="internal">Internal / private IPs only</option>
                  <option value="external">External / public IPs only</option>
                </select>
              </label>
              <label>Traffic boundary <HelpHint text={CONTROL_HELP.boundary} />
                <select value={filters.direction} onChange={(event) => updateFilter('direction', event.target.value as FilterState['direction'])}>
                  <option value="all">All traffic</option><option value="internal">Touches internal / private</option>
                  <option value="external">Touches external / public</option><option value="cross-boundary">Internal ↔ external only</option>
                </select>
              </label>
              <label>Connections <HelpHint text={CONTROL_HELP.connections} />
                <select value={filters.edgeMode} onChange={(event) => updateFilter('edgeMode', event.target.value as EdgeDisplayMode)}>
                  <option value="aggregate">One line per host pair</option>
                  <option value="per-port">Every port / flow</option>
                  <option value="hidden">Hide connections</option>
                </select>
              </label>
              <p className="filter-help">
                {filters.edgeMode === 'aggregate'
                  ? 'Default: one line between hosts. Click a line to list ports; expand to draw them.'
                  : filters.edgeMode === 'per-port'
                    ? 'Draws every port separately — can lag on large captures.'
                    : 'Hosts stay visible; connection lines are hidden for faster dragging.'}
              </p>
              <label>Host spacing <HelpHint text={CONTROL_HELP.spacing} /> <output>{nodeSpacing}</output>
                <input
                  type="range"
                  min="35"
                  max="180"
                  step="5"
                  value={nodeSpacing}
                  onChange={(event) => setNodeSpacing(Number(event.target.value))}
                />
              </label>
              <p className="filter-help">Lower values pull the map together. Drag any host to fine-tune its position.</p>
              <label>Include connected peers <HelpHint text={CONTROL_HELP.neighborhood} /> <output>depth {filters.neighborhood}</output>
                <input type="range" min="0" max="3" value={filters.neighborhood} onChange={(event) => updateFilter('neighborhood', Number(event.target.value))} />
              </label>
              <label>
                {filters.edgeMode === 'per-port' ? 'Visible flow cap' : 'Visible pair cap'} <HelpHint text={CONTROL_HELP.cap} />
                <output>{filters.complexityCap}</output>
                <input type="range" min="25" max="1000" step="25" value={filters.complexityCap} onChange={(event) => updateFilter('complexityCap', Number(event.target.value))} />
              </label>
              <label className="check"><input type="checkbox" checked={filters.showEdgeLabels} onChange={(event) => updateFilter('showEdgeLabels', event.target.checked)} /> <span>Show connection labels <HelpHint text={CONTROL_HELP.edgeLabels} /></span></label>
              <label className="check"><input type="checkbox" checked={filters.groupSubnets} onChange={(event) => { updateFilter('groupSubnets', event.target.checked); if (event.target.checked) { setGroupZones(false); setGroupPurdue(false) } }} /> <span>Group by subnet <HelpHint text={CONTROL_HELP.subnet} /></span></label>
              <label className="check"><input type="checkbox" checked={filters.hideIsolates} onChange={(event) => updateFilter('hideIsolates', event.target.checked)} /> <span>Hide isolated hosts <HelpHint text={CONTROL_HELP.isolates} /></span></label>
              <label className="check"><input type="checkbox" checked={filters.hideNoise} onChange={(event) => updateFilter('hideNoise', event.target.checked)} /> <span>Hide low-volume noise <HelpHint text={CONTROL_HELP.noise} /></span></label>
            </section>

            <section className="side-section filters analysis-controls">
              <div className="section-heading"><span>OT ANALYSIS</span><small>{anomalousEdges.length} flagged flows</small></div>
              <p className="filter-help standards-explainer"><strong>IEC 62443</strong> is industrial cybersecurity guidance. A <strong>zone</strong> groups equipment needing similar protection; a <strong>conduit</strong> is a controlled path between zones. NetMap's assignments are suggestions, not a compliance assessment.</p>
              <label>Hover path direction <HelpHint text={CONTROL_HELP.pathDirection} />
                <select value={pathDirection} onChange={(event) => setPathDirection(event.target.value as PathDirection)}>
                  <option value="both">Both directions</option>
                  <option value="outbound">Outbound only</option>
                  <option value="inbound">Inbound only</option>
                </select>
              </label>
              <label className="check"><input type="checkbox" checked={groupZones} onChange={(event) => { setGroupZones(event.target.checked); if (event.target.checked) { updateFilter('groupSubnets', false); setGroupPurdue(false) } }} /> <span>Group by IEC 62443 zone <HelpHint text={`${CONTROL_HELP.iec62443} ${CONTROL_HELP.zone}`} /></span></label>
              <label className="check"><input type="checkbox" checked={groupPurdue} onChange={(event) => { setGroupPurdue(event.target.checked); if (event.target.checked) { updateFilter('groupSubnets', false); setGroupZones(false) } }} /> <span>Organize by Purdue Model level</span></label>
              <label className="check"><input type="checkbox" checked={showConduits} onChange={(event) => setShowConduits(event.target.checked)} /> <span>Highlight cross-zone conduits <HelpHint text={CONTROL_HELP.conduit} /></span></label>
              <label className="check"><input type="checkbox" checked={showAnomalies} onChange={(event) => setShowAnomalies(event.target.checked)} /> <span>Highlight baseline anomalies <HelpHint text={CONTROL_HELP.anomalies} /></span></label>
              <label>Baseline learning window <HelpHint text={CONTROL_HELP.baseline} /> <output>{baselinePercent}%</output>
                <input type="range" min="10" max="60" step="5" value={baselinePercent} onChange={(event) => setBaselinePercent(Number(event.target.value))} />
              </label>
              <p className="filter-help">Learns early traffic, then flags new pairs, protocols, ports, and large volume changes.</p>
              <label className="check"><input type="checkbox" checked={timelineEnabled} onChange={(event) => { setTimelineEnabled(event.target.checked); setTimelinePlaying(false); setTimelinePercent(event.target.checked ? 0 : 100) }} /> <span>Timeline playback by first seen <HelpHint text={CONTROL_HELP.timeline} /></span></label>
            </section>

            {workspaceTab === 'investigation' ? (
            <section className="side-section">
              <div className="section-heading"><span>SAVED VIEWS <HelpHint text={CONTROL_HELP.savedViews} /></span><button className="text-button" onClick={saveView}>＋ Save</button></div>
              <div className="saved-list">
                {savedViews.map((view) => (
                  <button
                    key={view.id}
                    onClick={() => {
                      setFilters({ ...defaultFilters, ...view.filters })
                      setLayout(view.layout)
                      setExpandedPairId(null)
                    }}
                  >
                    <span>◇</span>{view.name}<small>›</small>
                  </button>
                ))}
              </div>
            </section>
            ) : null}
          </div>
        </aside>

        <main className={`main-panel ${timelineEnabled ? 'timeline-open' : ''}`}>
          <div className="map-toolbar">
            <div>
              <strong>{workspaceTab === 'live' ? 'Live topology' : 'Network topology'}</strong>
              <span>
                {visible.nodes.length} nodes · {connectionCount}{' '}
                {filters.edgeMode === 'aggregate' ? 'links' : 'connections'}
                {filters.edgeMode === 'aggregate' && visible.edges.length !== connectionCount
                  ? ` · ${visible.edges.length} flows`
                  : ''}
                {workspaceTab === 'live' && liveCapturing ? ' · live' : ''}
              </span>
            </div>
            <div className="toolbar-actions">
              <label>Layout <HelpHint text={CONTROL_HELP.layout} />
                <select value={layout} onChange={(event) => setLayout(event.target.value)}>
                  <option value="cose">Force directed</option><option value="breadthfirst">Hierarchical</option>
                  <option value="circle">Circle</option><option value="grid">Grid</option>
                </select>
              </label>
              <button onClick={() => mapRef.current?.zoomOut()} aria-label="Zoom out">−</button>
              <output className="zoom-level" aria-label="Current zoom">{zoomPercent}%</output>
              <button onClick={() => mapRef.current?.zoomIn()} aria-label="Zoom in">＋</button>
              <button title={CONTROL_HELP.fit} onClick={() => mapRef.current?.fit()}><Icon name="fit" /> Fit</button>
              <button title={CONTROL_HELP.resetLayout} onClick={() => mapRef.current?.reset()}>↻ Reset</button>
              <button
                className={filters.edgeMode !== 'hidden' ? 'active' : ''}
                onClick={() => updateFilter('edgeMode', filters.edgeMode === 'hidden' ? 'aggregate' : 'hidden')}
                title={CONTROL_HELP.links}
              >
                {filters.edgeMode === 'hidden' ? 'Links off' : 'Links on'}
              </button>
              <button
                className={showHostnames ? 'active' : ''}
                onClick={() => setShowHostnames((current) => !current)}
                title={CONTROL_HELP.names}
              >
                {showHostnames ? 'Names on' : 'Names off'}
              </button>
              <div className="export-menu">
                <button title={CONTROL_HELP.png} onClick={() => mapRef.current?.exportPng()}><Icon name="export" /> PNG</button>
                <button title={CONTROL_HELP.csv} onClick={() => downloadText('netmap-flows.csv', exportDatasetCsv(visible), 'text/csv;charset=utf-8')}>CSV</button>
              </div>
            </div>
          </div>
          <NetworkMap
            ref={mapRef}
            dataset={visible}
            layout={layout}
            nodeSpacing={nodeSpacing}
            groupSubnets={filters.groupSubnets}
            groupZones={groupZones}
            groupPurdue={groupPurdue}
            showConduits={showConduits}
            showAnomalies={showAnomalies}
            pathDirection={pathDirection}
            showHostnames={showHostnames}
            edgeMode={filters.edgeMode}
            showEdgeLabels={filters.showEdgeLabels}
            aggregatedEdges={aggregatedEdges}
            expandedPairId={expandedPairId}
            onZoomChange={onZoomChange}
            onSelectNode={onSelectNode}
            onSelectEdge={onSelectEdge}
            onSelectAggregatedEdge={onSelectAggregatedEdge}
          />
          {timelineEnabled && (
            <div className="timeline-bar" aria-label="Timeline playback controls">
              <button
                type="button"
                onClick={() => {
                  if (timelinePercent >= 100) setTimelinePercent(0)
                  setTimelinePlaying((playing) => !playing)
                }}
              >{timelinePlaying ? 'Pause' : 'Play'}</button>
              <button type="button" onClick={() => { setTimelinePlaying(false); setTimelinePercent(0) }}>Restart</button>
              <input aria-label="Timeline position" type="range" min="0" max="100" value={timelinePercent} onChange={(event) => { setTimelinePlaying(false); setTimelinePercent(Number(event.target.value)) }} />
              <output>{timelineTimestamp === null ? 'No timestamps' : new Date(timelineTimestamp).toLocaleString()} · {timelinePercent}%</output>
            </div>
          )}
          <div className="map-status">
            <span><i className="internal-dot" /> Internal host</span><span><i className="external-dot" /> External host</span>
            <span className="map-hint">
              {workspaceTab === 'live'
                ? 'Live updates ~1/s · Hover a host to trace 2 hops · Drag hosts to rearrange'
                : 'Hover a host to trace 2 hops · Scroll to zoom · Drag hosts to rearrange'}
            </span>
          </div>
        </main>

        <aside className="details-pane" aria-label="Selection details">
          {resolvedSelectedNode ? (
            <NodeDetails
              node={resolvedSelectedNode}
              edges={nodeEdges}
              peerFor={(edge) => edgePeer(edge, resolvedSelectedNode)}
              onChange={updateNodeMetadata}
            />
          ) : selectedAggregate ? (
            <AggregatedEdgeDetails
              edge={selectedAggregate}
              nodes={activeDataset.nodes}
              expanded={expandedPairId === selectedAggregate.id}
              onToggleExpand={() => setExpandedPairId((current) => (
                current === selectedAggregate.id ? null : selectedAggregate.id
              ))}
              onSelectFlow={(flow) => {
                setSelectedEdge(flow)
                setSelectedAggregate(null)
                setSelectedNode(null)
              }}
            />
          ) : selectedEdge ? (
            <EdgeDetails edge={selectedEdge} nodes={activeDataset.nodes} />
          ) : (
            <div className="empty-details">
              <span>◎</span>
              <h2>{workspaceTab === 'live' ? 'Live capture' : 'Inspect the map'}</h2>
              <p>
                {workspaceTab === 'live'
                  ? 'Start a capture to watch hosts and flows appear in real time.'
                  : 'Select a host or connection to review its activity.'}
              </p>
            </div>
          )}
        </aside>
      </div>}

      {testCaptureOpen && (
        <TestCaptureDialog
          captures={testCaptures}
          error={testCaptureError}
          onChoose={chooseTestCapture}
          onClose={() => setTestCaptureOpen(false)}
        />
      )}

      {importOpen && (
        <ImportDialog
          stage={importStage}
          kind={importKind}
          paths={importPaths}
          preview={preview}
          mapping={mapping}
          progress={progress}
          error={importError}
          summary={importSummary}
          mergeWithExisting={mergeWithExisting}
          pcapOptions={pcapOptions}
          onClose={() => setImportOpen(false)}
          onSelect={selectNativeFiles}
          onBrowserFile={selectBrowserFile}
          onMapping={setMapping}
          onMergeWithExisting={setMergeWithExisting}
          onPcapOptions={setPcapOptions}
          onNext={() => setImportStage('mapping')}
          onImport={runImport}
          onCancel={() => abortRef.current?.abort()}
        />
      )}

      {helpOpen && (
        <div className="modal-backdrop" role="presentation" onMouseDown={() => setHelpOpen(false)}>
          <section className="modal help-modal" role="dialog" aria-modal="true" aria-labelledby="help-title" onMouseDown={(event) => event.stopPropagation()}>
            <header><div><span className="eyebrow">DOCUMENTATION</span><h2 id="help-title">Using NetMap Portable</h2></div><button className="icon-button" onClick={() => setHelpOpen(false)} aria-label="Close"><Icon name="close" /></button></header>
            <div className="help-content">
              <section>
                <h3>Search IPs and hostnames</h3>
                <p>Searches are prefix-based. Enter <code>172.</code> to show addresses beginning with 172. Enter several values separated by commas, spaces, or semicolons, such as <code>172., 192., 120.</code>. Full IPv4 CIDR ranges such as <code>10.20.0.0/16</code> are also supported.</p>
                <p>Connected-peer depth defaults to 0, so unrelated hosts stay hidden. Increase it only when you want to add one or more hops around the matching hosts.</p>
              </section>
              <section>
                <h3>Navigate the map</h3>
                <p>Use the mouse wheel or trackpad to zoom toward the pointer. Labels scale up automatically as you zoom out. Fit centers everything currently visible; Reset reruns the selected layout. Use Host spacing to pull hosts together or spread them out, then drag any host to fine-tune its position.</p>
                <p>Hover a host to emphasize its direct peers and their peers. Unrelated hosts and links fade so two-hop communication paths remain readable.</p>
              </section>
              <section>
                <h3>Connection density</h3>
                <p>By default NetMap draws <strong>one line per host pair</strong> instead of a line per port. Click a link to list every protocol/port in the details pane, then choose Expand ports on map when you need the fan-out. Switch Connections to Every port / flow only for small filtered sets. Use Links off or Hide connections when rearranging hubs.</p>
                <p>Host scope can show internal IPs only or external IPs only. Pair that with traffic boundary filters and the visible pair/flow cap to keep large captures workable.</p>
              </section>
              <section>
                <h3>Live capture</h3>
                <p>Open the <strong>Live</strong> tab to capture from a NIC with Wireshark’s <code>tshark</code>. Choose an adapter, optionally add a BPF filter (for example <code>port 53</code> or <code>host 10.0.0.1</code>), then Start. Flows appear on the map about once per second and are saved into the current project.</p>
                <p>Install Wireshark (includes tshark) and Npcap first. If no adapters appear, run NetMap as Administrator. Stop the capture before unplugging the interface. NetMap does not bundle Wireshark.</p>
              </section>
              <section>
                <h3>Hostnames from captures</h3>
                <p>PCAP imports passively read DNS and mDNS A/AAAA answers. When a response maps a name to an IP, the map can display both. Use Names on/off in the toolbar to switch between hostname labels and IP-only labels.</p>
                <p>Names are best-effort: encrypted DNS, missing DNS responses, static hosts, and captures taken after name resolution may provide no hostname. NetMap never performs live DNS lookups.</p>
              </section>
              <section>
                <h3>Filters and privacy</h3>
                <p>Protocol, port, time, host scope, traffic direction, connection mode, and volume filters combine with the search. OT / ICS filters recognize explicit analyzer names and infer common protocols from well-known ports when only TCP or UDP is available.</p>
                <p>All parsing and project storage remain local beside the portable application.</p>
              </section>
              <section>
                <h3>Replace or merge imports</h3>
                <p>New imports replace the current map by default, and the existing map is kept if parsing fails. Enable <strong>Merge with current map</strong> in the import dialog only when you want to combine multiple captures in one project.</p>
              </section>
              <section>
                <h3>OT roles, zones, and conduits</h3>
                <p>NetMap infers PLC, HMI, RTU, historian, gateway, controller, and workstation roles from hostnames and observed traffic. Select a host to override its role or IEC 62443-style zone. Group by zone and enable conduits to review cross-zone paths.</p>
              </section>
              <section>
                <h3>Baseline and timeline</h3>
                <p>The baseline window learns the early portion of the capture and flags later host pairs, protocols, ports, and traffic spikes. Timeline playback reveals flows according to their first-seen timestamp. Use Test PCAP to load an offline exercise designed for these controls.</p>
              </section>
            </div>
          </section>
        </div>
      )}

      {diagnosticsOpen && (
        <div className="modal-backdrop" role="presentation" onMouseDown={() => setDiagnosticsOpen(false)}>
          <section className="modal diagnostics-modal" role="dialog" aria-modal="true" aria-labelledby="diagnostics-title" onMouseDown={(event) => event.stopPropagation()}>
            <header><div><span className="eyebrow">SYSTEM</span><h2 id="diagnostics-title">Diagnostics</h2></div><button className="icon-button" onClick={() => setDiagnosticsOpen(false)} aria-label="Close"><Icon name="close" /></button></header>
            {diagnostics ? <dl className="diagnostics-grid">
              <div><dt>Runtime</dt><dd>{diagnostics.mode}</dd></div><div><dt>Version</dt><dd>{diagnostics.version}</dd></div>
              <div><dt>Platform</dt><dd>{diagnostics.platform}</dd></div><div><dt>Storage</dt><dd>Local only</dd></div>
              <div><dt>Nodes loaded</dt><dd>{diagnostics.nodeCount}</dd></div><div><dt>Edges loaded</dt><dd>{diagnostics.edgeCount}</dd></div>
            </dl> : <p>Collecting diagnostics…</p>}
            <div className="notice">✓ No internet access required. Capture data remains on this device.</div>
          </section>
        </div>
      )}
    </div>
  )
}

function NodeDetails({ node, edges, peerFor, onChange }: {
  node: NetworkNode
  edges: NetworkEdge[]
  peerFor: (edge: NetworkEdge) => NetworkNode | undefined
  onChange: (node: NetworkNode) => void
}) {
  const [tagDraft, setTagDraft] = useState('')
  const protocolsUsed = [...new Set(edges.map((edge) => edge.protocol))]
  const ports = [...new Set(edges.map((edge) => edge.port))].slice(0, 6)
  const anomalyKinds = [...new Set(edges.flatMap((edge) => edge.anomalies ?? []))]
  return (
    <>
      <div className="details-header">
        <span className={`host-avatar ${node.kind}`}>⌁</span>
        <div><span className="eyebrow">{node.kind} HOST</span><h2>{node.ip}</h2><p>{node.hostname ?? node.vendor ?? 'No hostname observed'}</p></div>
      </div>
      <div className="risk-banner"><span>Shielded</span><strong>{node.kind === 'internal' ? 'Internal asset' : 'External endpoint'}</strong></div>
      <section className="detail-section inline-facts">
        <div><h3>MAC ADDRESS</h3><p>{node.mac ?? 'Not observed'}</p></div>
        <div><h3>VENDOR</h3><p>{node.vendor ?? (node.mac ? 'Unknown or private MAC' : 'Not available')}</p></div>
      </section>
      <section className="detail-section"><h3>PURDUE MODEL</h3><p>{node.purdueLevel ?? 'External / unassigned'}</p></section>
      <section className="detail-section asset-classification">
        <h3>OT ASSET CLASSIFICATION</h3>
        <label>Asset role <HelpHint text={`${CONTROL_HELP.assetRole} ${ASSET_ROLE_HELP[node.assetRole ?? 'Unknown']}`} />
          <select
            value={node.assetRoleSource === 'manual' ? node.assetRole : ''}
            onChange={(event) => onChange(event.target.value
              ? { ...node, assetRole: event.target.value as NetworkNode['assetRole'], assetRoleSource: 'manual' }
              : { ...node, assetRole: undefined, assetRoleSource: undefined })}
          >
            <option value="">Auto-detect ({node.assetRole ?? 'Unknown'})</option>
            {ASSET_ROLES.map((role) => <option key={role} value={role}>{role}</option>)}
          </select>
        </label>
        <label>IEC 62443 zone <HelpHint text={`${CONTROL_HELP.zone} ${ZONE_HELP[node.securityZone ?? 'Unassigned']}`} />
          <select
            value={node.securityZoneSource === 'manual' ? node.securityZone : ''}
            onChange={(event) => onChange(event.target.value
              ? { ...node, securityZone: event.target.value as NetworkNode['securityZone'], securityZoneSource: 'manual' }
              : { ...node, securityZone: undefined, securityZoneSource: undefined })}
          >
            <option value="">Auto-assign ({node.securityZone ?? 'Unassigned'})</option>
            {SECURITY_ZONES.map((zone) => <option key={zone} value={zone}>{zone}</option>)}
          </select>
        </label>
      </section>
      {anomalyKinds.length > 0 && (
        <section className="detail-section anomaly-summary">
          <h3>BASELINE FINDINGS</h3>
          <div>{anomalyKinds.map((kind) => <span key={kind}>{ANOMALY_LABELS[kind]}</span>)}</div>
        </section>
      )}
      <section className="detail-section">
        <h3>TRAFFIC SUMMARY</h3>
        <div className="metric-grid">
          <div><span>Total bytes</span><strong>{formatBytes(edges.reduce((sum, edge) => sum + edge.bytes, 0))}</strong></div>
          <div><span>Packets</span><strong>{edges.reduce((sum, edge) => sum + edge.packets, 0).toLocaleString()}</strong></div>
          <div><span>First seen</span><strong>{formatTime(node.firstSeen)}</strong></div>
          <div><span>Last seen</span><strong>{formatTime(node.lastSeen)}</strong></div>
        </div>
      </section>
      <section className="detail-section">
        <h3>TOP PEERS</h3>
        <div className="peer-list">
          {edges.slice(0, 5).map((edge) => {
            const peer = peerFor(edge)
            return <div key={edge.id}><span className={`peer-dot ${peer?.kind ?? 'external'}`} /><div><strong>{peer?.ip ?? 'Unknown'}</strong><small>{edge.protocol}:{edge.port}</small></div><b>{formatBytes(edge.bytes)}</b></div>
          })}
        </div>
      </section>
      <section className="detail-section inline-facts">
        <div><h3>PROTOCOLS</h3><p>{protocolsUsed.join(' · ') || '—'}</p></div>
        <div><h3>TOP PORTS</h3><p>{ports.join(' · ') || '—'}</p></div>
      </section>
      <section className="detail-section">
        <h3>TAGS & NOTES</h3>
        <div className="tags">{node.tags.map((tag) => <button key={tag} onClick={() => onChange({ ...node, tags: node.tags.filter((item) => item !== tag) })}>#{tag} ×</button>)}</div>
        <form className="tag-form" onSubmit={(event) => { event.preventDefault(); if (tagDraft.trim()) onChange({ ...node, tags: [...new Set([...node.tags, tagDraft.trim()])] }); setTagDraft('') }}>
          <input aria-label="New tag" value={tagDraft} onChange={(event) => setTagDraft(event.target.value)} placeholder="Add tag…" /><button>Add</button>
        </form>
        <textarea aria-label="Host notes" value={node.notes ?? ''} onChange={(event) => onChange({ ...node, notes: event.target.value })} placeholder="Add investigation notes…" />
      </section>
      <section className="detail-section source-list"><h3>SOURCE IMPORTS</h3>{node.imports.map((source) => <p key={source}>▤ {source}</p>)}</section>
    </>
  )
}

function TestCaptureDialog({ captures, error, onChoose, onClose }: {
  captures: TestCapture[]
  error: string
  onChoose: (capture: TestCapture) => void
  onClose: () => void
}) {
  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={onClose}>
      <section className="modal test-capture-modal" role="dialog" aria-modal="true" aria-labelledby="test-capture-title" onMouseDown={(event) => event.stopPropagation()}>
        <header>
          <div><span className="eyebrow">OFFLINE LAB DATA</span><h2 id="test-capture-title">Choose a recommended OT capture</h2></div>
          <button className="icon-button" onClick={onClose} aria-label="Close"><Icon name="close" /></button>
        </header>
        <p className="test-capture-intro">These are real, unmodified Wireshark and Netresec training captures. The multi-host labs appear first. Every file ships beside the app for offline USB use.</p>
        {error && <div className="error-box">{error}</div>}
        <div className="test-capture-list">
          {captures.map((capture) => (
            <button type="button" key={capture.id} onClick={() => onChoose(capture)}>
              <span className="test-capture-icon"><Icon name="map" /></span>
              <span><strong>{capture.name}</strong><small>{capture.description}</small><em>{capture.protocols.join(' · ')}</em></span>
              <b>Use capture ›</b>
            </button>
          ))}
          {!error && captures.length === 0 && <p>Loading bundled captures…</p>}
        </div>
      </section>
    </div>
  )
}

function EdgeDetails({ edge, nodes }: { edge: NetworkEdge; nodes: NetworkNode[] }) {
  const source = nodes.find((node) => node.id === edge.source)
  const target = nodes.find((node) => node.id === edge.target)
  return <div className="edge-details">
    <span className="eyebrow">DIRECTIONAL FLOW</span><h2>{edge.protocol}:{edge.port}</h2>
    <div className="flow-route"><strong>{source?.ip}</strong><span>→</span><strong>{target?.ip}</strong></div>
    {edge.anomalies?.length ? <div className="edge-anomalies">{edge.anomalies.map((kind) => <span key={kind}>{ANOMALY_LABELS[kind]}</span>)}</div> : null}
    <dl><div><dt>Bytes</dt><dd>{formatBytes(edge.bytes)}</dd></div><div><dt>Packets</dt><dd>{edge.packets.toLocaleString()}</dd></div><div><dt>First seen</dt><dd>{formatTime(edge.firstSeen)}</dd></div><div><dt>Last seen</dt><dd>{formatTime(edge.lastSeen)}</dd></div></dl>
    <section className="detail-section source-list"><h3>SOURCE IMPORTS</h3>{edge.imports.map((sourceName) => <p key={sourceName}>▤ {sourceName}</p>)}</section>
  </div>
}

function AggregatedEdgeDetails({ edge, nodes, expanded, onToggleExpand, onSelectFlow }: {
  edge: AggregatedEdge
  nodes: NetworkNode[]
  expanded: boolean
  onToggleExpand: () => void
  onSelectFlow: (flow: NetworkEdge) => void
}) {
  const source = nodes.find((node) => node.id === edge.source)
  const target = nodes.find((node) => node.id === edge.target)
  const anomalies = [...new Set(edge.flows.flatMap((flow) => flow.anomalies ?? []))]
  return (
    <div className="edge-details">
      <span className="eyebrow">HOST PAIR LINK</span>
      <h2>{edge.flowCount} port{edge.flowCount === 1 ? '' : 's'}</h2>
      <div className="flow-route"><strong>{source?.ip}</strong><span>→</span><strong>{target?.ip}</strong></div>
      {anomalies.length ? <div className="edge-anomalies">{anomalies.map((kind) => <span key={kind}>{ANOMALY_LABELS[kind]}</span>)}</div> : null}
      <dl>
        <div><dt>Total bytes</dt><dd>{formatBytes(edge.bytes)}</dd></div>
        <div><dt>Packets</dt><dd>{edge.packets.toLocaleString()}</dd></div>
        <div><dt>Protocols</dt><dd>{edge.protocols.join(' · ')}</dd></div>
        <div><dt>Last seen</dt><dd>{formatTime(edge.lastSeen)}</dd></div>
      </dl>
      <section className="detail-section">
        <div className="section-heading">
          <h3>PORTS IN USE</h3>
          <button type="button" className="text-button" onClick={onToggleExpand}>
            {expanded ? 'Collapse on map' : 'Expand ports on map'}
          </button>
        </div>
        <div className="peer-list port-list">
          {edge.ports.map((port) => {
            const flow = edge.flows.find((item) => item.protocol === port.protocol && item.port === port.port)
            return (
              <button
                key={`${port.protocol}-${port.port}`}
                type="button"
                className="port-row"
                onClick={() => flow && onSelectFlow(flow)}
              >
                <div><strong>{port.protocol}:{port.port}</strong><small>{port.packets.toLocaleString()} packets</small></div>
                <b>{formatBytes(port.bytes)}</b>
              </button>
            )
          })}
        </div>
      </section>
      <section className="detail-section source-list">
        <h3>SOURCE IMPORTS</h3>
        {edge.imports.map((sourceName) => <p key={sourceName}>▤ {sourceName}</p>)}
      </section>
    </div>
  )
}

function PacketInspector() {
  const [page, setPage] = useState<PacketPage>({ packets: [], total: 0 })
  const [offset, setOffset] = useState(0)
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<PacketRecord | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    void queryPackets(offset, search).then((result) => {
      if (!cancelled) {
        setPage(result)
        setSelected((current) => result.packets.find((packet) => packet.packetNumber === current?.packetNumber) ?? result.packets[0] ?? null)
        setError('')
      }
    }).catch((reason) => {
      if (!cancelled) setError(reason instanceof Error ? reason.message : String(reason))
    }).finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [offset, search])

  return (
    <div className="packet-workspace">
      <header className="packet-header">
        <div><span className="eyebrow">DEEP PACKET INSPECTION</span><h2>Packet index</h2><p>{page.total.toLocaleString()} retained packets · offline metadata inspection</p></div>
        <label className="packet-search"><span>Filter packets</span><input value={search} onChange={(event) => { setOffset(0); setSearch(event.target.value) }} placeholder="IP, MAC, or protocol" /></label>
      </header>
      {error && <div className="error-box">{error}</div>}
      {!loading && page.total === 0 ? (
        <div className="packet-empty"><h3>No packet index is available</h3><p>Import a PCAP using the <strong>Deep inspection</strong> profile. Fast topology imports intentionally retain only aggregated flows.</p></div>
      ) : (
        <div className="packet-grid">
          <section className="packet-table-wrap">
            <table className="packet-table"><thead><tr><th>#</th><th>Time</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Length</th></tr></thead><tbody>
              {page.packets.map((packet) => <tr key={packet.packetNumber} className={selected?.packetNumber === packet.packetNumber ? 'selected' : ''} onClick={() => setSelected(packet)}>
                <td>{packet.packetNumber}</td><td>{packet.timestamp ? new Date(packet.timestamp).toLocaleTimeString() : '—'}</td>
                <td>{packet.sourceIp}{packet.sourcePort !== undefined ? `:${packet.sourcePort}` : ''}</td><td>{packet.destinationIp}{packet.destinationPort !== undefined ? `:${packet.destinationPort}` : ''}</td>
                <td><span className="protocol-pill">{packet.protocol}</span></td><td>{packet.length} B</td>
              </tr>)}
            </tbody></table>
            <footer className="packet-pagination"><button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 250))}>Previous</button><span>{page.total ? `${offset + 1}–${Math.min(offset + page.packets.length, page.total)} of ${page.total}` : '0 packets'}</span><button disabled={offset + page.packets.length >= page.total} onClick={() => setOffset(offset + 250)}>Next</button></footer>
          </section>
          <aside className="packet-details">
            {selected ? <>
              <span className="eyebrow">PACKET {selected.packetNumber}</span><h2>{selected.protocol}</h2>
              <dl><div><dt>Timestamp</dt><dd>{selected.timestamp ? new Date(selected.timestamp).toLocaleString() : 'Not recorded'}</dd></div><div><dt>Frame length</dt><dd>{selected.length} bytes</dd></div><div><dt>Source IP</dt><dd>{selected.sourceIp}{selected.sourcePort !== undefined ? `:${selected.sourcePort}` : ''}</dd></div><div><dt>Destination IP</dt><dd>{selected.destinationIp}{selected.destinationPort !== undefined ? `:${selected.destinationPort}` : ''}</dd></div><div><dt>Source MAC</dt><dd>{selected.sourceMac ?? 'Not retained'}</dd></div><div><dt>Destination MAC</dt><dd>{selected.destinationMac ?? 'Not retained'}</dd></div><div><dt>TCP flags</dt><dd>{selected.tcpFlags ?? 'Not retained / not TCP'}</dd></div></dl>
              <h3>HEX PREVIEW</h3><pre>{selected.payloadPreview ?? 'Payload preview was disabled for this import.'}</pre>
            </> : <p>Select a packet to inspect it.</p>}
          </aside>
        </div>
      )}
    </div>
  )
}

function ImportDialog(props: {
  stage: ImportStage
  kind: 'csv' | 'pcap'
  paths: string[]
  preview: CsvPreview | null
  mapping: ImportMapping | null
  progress: ImportProgress | null
  error: string
  summary: string
  mergeWithExisting: boolean
  pcapOptions: PcapImportOptions
  onClose: () => void
  onSelect: () => void
  onBrowserFile: (file: File | undefined) => void
  onMapping: (mapping: ImportMapping) => void
  onMergeWithExisting: (merge: boolean) => void
  onPcapOptions: (options: PcapImportOptions) => void
  onNext: () => void
  onImport: () => void
  onCancel: () => void
}) {
  const fields: Array<[keyof ImportMapping, string]> = [
    ['timestamp', 'Timestamp'], ['sourceIp', 'Source IP'], ['destinationIp', 'Destination IP'],
    ['sourcePort', 'Source port'], ['destinationPort', 'Destination port'], ['protocol', 'Protocol'],
    ['bytes', 'Bytes'], ['packets', 'Packets'],
  ]
  const step = props.stage === 'source' ? 1 : props.stage === 'mapping' ? 2 : 3
  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={props.stage === 'progress' ? undefined : props.onClose}>
      <section className="modal import-modal" role="dialog" aria-modal="true" aria-labelledby="import-title" onMouseDown={(event) => event.stopPropagation()}>
        <header><div><span className="eyebrow">ADD DATA</span><h2 id="import-title">Import {props.kind === 'csv' ? 'flow records' : 'packet capture'}</h2></div><button className="icon-button" disabled={props.stage === 'progress'} onClick={props.onClose} aria-label="Close"><Icon name="close" /></button></header>
        <ol className="steps"><li className={step >= 1 ? 'active' : ''}><b>1</b>Source</li><li className={step >= 2 ? 'active' : ''}><b>2</b>{props.kind === 'csv' ? 'Map fields' : 'Options'}</li><li className={step >= 3 ? 'active' : ''}><b>3</b>Import</li></ol>

        {props.stage === 'source' && <>
          <div className="drop-zone">
            <span className="drop-icon"><Icon name="import" /></span>
            <h3>Select {props.kind.toUpperCase()} files</h3>
            <p>{props.kind === 'csv' ? 'Security Onion, ECS, Zeek, or custom delimited flow records' : 'PCAP, PCAPNG, or CAP · processed locally'}</p>
            {isTauri()
              ? <button className="primary" onClick={props.onSelect}>Browse files</button>
              : <label className="primary file-button">Browse files<input type="file" accept={props.kind === 'csv' ? '.csv,.tsv,.log' : '.pcap,.pcapng,.cap'} onChange={(event) => props.onBrowserFile(event.target.files?.[0])} /></label>}
          </div>
          {props.paths.length > 0 && <div className="selected-file"><span>▤</span><div><strong>{props.paths[0].split(/[\\/]/).at(-1)}</strong><small>{props.preview ? `${props.preview.rows.length}+ preview rows · ${props.preview.schema} detected` : 'Ready for local analysis'}</small></div><b>✓</b></div>}
          <div className={`import-behavior ${props.mergeWithExisting ? 'merge' : 'replace'}`}>
            <label className="check">
              <input type="checkbox" checked={props.mergeWithExisting} onChange={(event) => props.onMergeWithExisting(event.target.checked)} />
              Merge with current map
            </label>
            <p>{props.mergeWithExisting
              ? 'Enabled: add these files to the hosts and flows already in this project.'
              : 'Replace mode (default): after a successful import, only these selected files remain on the map.'}</p>
          </div>
          {props.preview && <div className="preview-wrap"><div className="preview-heading"><strong>Data preview</strong><span>{props.preview.headers.length} columns</span></div><table><thead><tr>{props.preview.headers.slice(0, 5).map((header) => <th key={header}>{header}</th>)}</tr></thead><tbody>{props.preview.rows.slice(0, 3).map((row, index) => <tr key={index}>{props.preview?.headers.slice(0, 5).map((header) => <td key={header}>{row[header]}</td>)}</tr>)}</tbody></table></div>}
          {props.error && <div className="error-box">{props.error}</div>}
          <footer><button onClick={props.onClose}>Cancel</button><button className="primary" disabled={!props.paths.length} onClick={props.onNext}>Continue</button></footer>
        </>}

        {props.stage === 'mapping' && props.preview && props.mapping && <>
          <div className="detected-banner"><span>✓</span><div><strong>{props.preview.schema} fields detected</strong><p>Review auto-mapped columns before importing.</p></div></div>
          <div className="mapping-grid">
            {fields.map(([field, label]) => <label key={field}>{label}{field === 'sourceIp' || field === 'destinationIp' ? <em>required</em> : null}
              <select value={props.mapping?.[field]} onChange={(event) => props.onMapping({ ...props.mapping!, [field]: event.target.value })}>
                <option value="">Not mapped</option>{props.preview?.headers.map((header) => <option key={header}>{header}</option>)}
              </select>
            </label>)}
          </div>
          <div className="mapping-note">Custom mappings apply to this import only. Raw files are never modified.</div>
          <footer><button onClick={props.onClose}>Cancel</button><button className="primary" disabled={!props.mapping.sourceIp || !props.mapping.destinationIp} onClick={props.onImport}>Import records</button></footer>
        </>}

        {props.stage === 'mapping' && props.kind === 'pcap' && <>
          <div className="inspection-profile">
            <button type="button" className={!props.pcapOptions.packetIndexing ? 'active' : ''} onClick={() => props.onPcapOptions({ ...defaultPcapOptions })}>
              <strong>Fast topology</strong><span>Best for large captures</span><small>Streams packets directly into aggregated flows. No per-packet database.</small>
            </button>
            <button type="button" className={props.pcapOptions.packetIndexing ? 'active' : ''} onClick={() => props.onPcapOptions({ ...props.pcapOptions, packetIndexing: true, tcpFlags: true })}>
              <strong>Deep inspection</strong><span>Packet-by-packet index</span><small>Uses more time and disk space. Enables the Packet inspection tab.</small>
            </button>
          </div>
          <div className="inspection-options">
            <h3>Inspection options</h3>
            <label className="check"><input type="checkbox" checked={props.pcapOptions.macAddresses} onChange={(event) => props.onPcapOptions({ ...props.pcapOptions, macAddresses: event.target.checked })} /> MAC addresses and offline vendor lookup</label>
            <label className="check"><input type="checkbox" checked={props.pcapOptions.dnsHostnames} onChange={(event) => props.onPcapOptions({ ...props.pcapOptions, dnsHostnames: event.target.checked })} /> Passive DNS/mDNS hostname extraction</label>
            <label className="check"><input type="checkbox" disabled={!props.pcapOptions.packetIndexing} checked={props.pcapOptions.packetIndexing && props.pcapOptions.tcpFlags} onChange={(event) => props.onPcapOptions({ ...props.pcapOptions, tcpFlags: event.target.checked })} /> TCP flags (SYN, ACK, FIN, RST, PSH, URG)</label>
            <label className="check"><input type="checkbox" disabled={!props.pcapOptions.packetIndexing} checked={props.pcapOptions.payloadPreviewBytes > 0} onChange={(event) => props.onPcapOptions({ ...props.pcapOptions, payloadPreviewBytes: event.target.checked ? 96 : 0 })} /> Retain first 96 frame bytes as hexadecimal preview</label>
            <p className="mapping-note">Payload preview is disabled by default because it can retain sensitive content. Imported bytes are displayed as data and are never executed.</p>
          </div>
          <footer><button onClick={() => props.onClose()}>Cancel</button><button className="primary" onClick={props.onImport}>Import capture</button></footer>
        </>}

        {props.stage === 'progress' && <>
          <div className="progress-view"><span className="progress-ring">{props.progress?.percent ?? 0}%</span><h3>{props.progress?.phase ?? 'Preparing import'}</h3><p>{props.progress?.total ? `${props.progress.processed.toLocaleString()} of ${props.progress.total.toLocaleString()} records` : `${(props.progress?.processed ?? 0).toLocaleString()} records processed`}</p><progress max="100" value={props.progress?.percent ?? 0} /></div>
          <footer><button className="danger" onClick={props.onCancel}>Cancel import</button></footer>
        </>}

        {props.stage === 'complete' && <>
          <div className="complete-view"><span>✓</span><h3>Import complete</h3><p>{props.summary}</p><div className="notice">Topology, filters, and peer summaries are ready.</div></div>
          <footer><button className="primary" onClick={props.onClose}>View topology</button></footer>
        </>}
      </section>
    </div>
  )
}

export default App
