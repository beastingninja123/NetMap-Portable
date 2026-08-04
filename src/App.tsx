import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import './App.css'
import {
  chooseFiles,
  getDiagnostics,
  importCapture,
  isTauri,
  loadProjectDataset,
  loadSavedViews,
  persistNodeMetadata,
  persistSavedView,
  previewCsv,
} from './api'
import { demoDataset } from './demoData'
import NetworkMap, { type NetworkMapHandle } from './NetworkMap'
import type {
  CsvPreview,
  Diagnostics,
  FilterState,
  ImportMapping,
  ImportProgress,
  NetworkDataset,
  NetworkEdge,
  NetworkNode,
  Protocol,
  SavedView,
} from './types'
import { downloadText, exportDatasetCsv, filterDataset, summarizeNode } from './utils'

const protocols: Protocol[] = ['TCP', 'UDP', 'ICMP', 'DNS', 'HTTP', 'TLS', 'SSH']

const defaultFilters: FilterState = {
  query: '', startTime: '', endTime: '', port: '', protocols: [], minBytes: 0, minPackets: 0,
  direction: 'all', neighborhood: 1, hideIsolates: true, hideNoise: false,
  groupSubnets: false, complexityCap: 500,
}

type ImportStage = 'source' | 'mapping' | 'progress' | 'complete'

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
    close: 'M5 5l14 14M19 5L5 19',
  }
  return <svg viewBox="0 0 24 24" aria-hidden="true"><path d={paths[name]} /></svg>
}

function App() {
  const [dataset, setDataset] = useState<NetworkDataset>(demoDataset)
  const [filters, setFilters] = useState(defaultFilters)
  const [layout, setLayout] = useState('cose')
  const [selectedNode, setSelectedNode] = useState<NetworkNode | null>(demoDataset.nodes[6] ?? null)
  const [selectedEdge, setSelectedEdge] = useState<NetworkEdge | null>(null)
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
  const [savedViews, setSavedViews] = useState<SavedView[]>([
    { id: 'cross', name: 'Boundary traffic', filters: { ...defaultFilters, direction: 'cross-boundary' }, layout: 'cose' },
    { id: 'watch', name: 'Suspicious host ±1', filters: { ...defaultFilters, query: '185.220.101.42', neighborhood: 1 }, layout: 'breadthfirst' },
  ])
  const [diagnostics, setDiagnostics] = useState<Diagnostics | null>(null)
  const [diagnosticsOpen, setDiagnosticsOpen] = useState(false)
  const abortRef = useRef<AbortController | null>(null)
  const mapRef = useRef<NetworkMapHandle>(null)
  const metadataTimerRef = useRef<number | null>(null)

  useEffect(() => {
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

  const visible = useMemo(() => filterDataset(dataset, filters), [dataset, filters])
  const nodeEdges = useMemo(
    () => selectedNode ? summarizeNode(selectedNode, dataset) : [],
    [dataset, selectedNode],
  )

  const updateFilter = <K extends keyof FilterState>(key: K, value: FilterState[K]) => {
    setFilters((current) => ({ ...current, [key]: value }))
  }
  const onSelectNode = useCallback((node: NetworkNode | null) => setSelectedNode(node), [])
  const onSelectEdge = useCallback((edge: NetworkEdge | null) => setSelectedEdge(edge), [])

  const openImporter = (kind: 'csv' | 'pcap') => {
    setImportKind(kind)
    setImportPaths([])
    setPreview(null)
    setMapping(null)
    setImportError('')
    setImportSummary('')
    setImportStage('source')
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
      const result = await importCapture(importPaths, mapping, setProgress, controller.signal)
      setDataset(result.dataset)
      setImportSummary(`${result.importedRows.toLocaleString()} rows imported · ${result.skippedRows} skipped${result.warnings.length ? ` · ${result.warnings[0]}` : ''}`)
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
        version: 'Unavailable',
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
    setDataset((current) => ({
      ...current,
      nodes: current.nodes.map((node) => node.id === changed.id ? changed : node),
    }))
    setSelectedNode(changed)
    if (metadataTimerRef.current !== null) window.clearTimeout(metadataTimerRef.current)
    metadataTimerRef.current = window.setTimeout(() => {
      void persistNodeMetadata(changed)
        .catch((error) => setImportError(error instanceof Error ? error.message : String(error)))
    }, 400)
  }

  const edgePeer = (edge: NetworkEdge, node: NetworkNode): NetworkNode | undefined => {
    const peerId = edge.source === node.id ? edge.target : edge.source
    return dataset.nodes.find((item) => item.id === peerId)
  }

  return (
    <div className="app" data-theme={theme}>
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark"><Icon name="map" /></span>
          <div><strong>NetMap</strong><small>PORTABLE</small></div>
        </div>
        <div className="project-title">
          <span className="status-dot" /> Branch Office Investigation
          <span className="muted">/ sensor-east-2026-08-03.csv</span>
        </div>
        <div className="top-actions">
          <span className="mode-badge">{isTauri() ? 'LOCAL' : 'DEMO'} · OFFLINE</span>
          <button className="icon-button" onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')} aria-label="Toggle color theme">
            {theme === 'dark' ? '☼' : '☾'}
          </button>
          <button className="icon-button" onClick={showDiagnostics} aria-label="Open diagnostics"><Icon name="info" /></button>
        </div>
      </header>

      <div className="workspace">
        <aside className="sidebar" aria-label="Project and filters">
          <div className="side-scroll">
            <section className="side-section">
              <div className="section-heading"><span>PROJECT</span><button className="text-button" onClick={() => openImporter('csv')}>＋ New</button></div>
              <div className="project-card">
                <div className="project-icon"><Icon name="map" /></div>
                <div><strong>Branch Office</strong><small>12 hosts · 16 flows</small></div>
                <span>•••</span>
              </div>
              <div className="import-buttons">
                <button onClick={() => openImporter('csv')}><Icon name="import" /> Import CSV</button>
                <button onClick={() => openImporter('pcap')}><Icon name="import" /> Select PCAP</button>
              </div>
            </section>

            <section className="side-section filters">
              <div className="section-heading"><span>FILTERS</span><button className="text-button" onClick={() => setFilters(defaultFilters)}>Reset</button></div>
              <label className="search-field">
                <span className="sr-only">Search IP, CIDR, or protocol</span>
                <Icon name="search" />
                <input value={filters.query} onChange={(event) => updateFilter('query', event.target.value)} placeholder="IP, CIDR, protocol…" />
                <kbd>⌘ K</kbd>
              </label>
              <div className="field-grid">
                <label>From<input type="datetime-local" value={filters.startTime} onChange={(event) => updateFilter('startTime', event.target.value)} /></label>
                <label>To<input type="datetime-local" value={filters.endTime} onChange={(event) => updateFilter('endTime', event.target.value)} /></label>
              </div>
              <label>Port<input value={filters.port} inputMode="numeric" onChange={(event) => updateFilter('port', event.target.value.replace(/\D/g, ''))} placeholder="Any port" /></label>
              <fieldset>
                <legend>Protocol</legend>
                <div className="protocol-chips">
                  {protocols.map((protocol) => (
                    <button
                      type="button"
                      key={protocol}
                      className={filters.protocols.includes(protocol) ? 'active' : ''}
                      onClick={() => updateFilter('protocols', filters.protocols.includes(protocol)
                        ? filters.protocols.filter((item) => item !== protocol)
                        : [...filters.protocols, protocol])}
                    >{protocol}</button>
                  ))}
                </div>
              </fieldset>
              <div className="field-grid">
                <label>Min bytes<input type="number" min="0" value={filters.minBytes} onChange={(event) => updateFilter('minBytes', Number(event.target.value))} /></label>
                <label>Min packets<input type="number" min="0" value={filters.minPackets} onChange={(event) => updateFilter('minPackets', Number(event.target.value))} /></label>
              </div>
              <label>Traffic boundary
                <select value={filters.direction} onChange={(event) => updateFilter('direction', event.target.value as FilterState['direction'])}>
                  <option value="all">All traffic</option><option value="internal">Touches internal</option>
                  <option value="external">Touches external</option><option value="cross-boundary">Cross-boundary only</option>
                </select>
              </label>
              <label>Neighborhood depth <output>{filters.neighborhood}</output>
                <input type="range" min="0" max="3" value={filters.neighborhood} onChange={(event) => updateFilter('neighborhood', Number(event.target.value))} />
              </label>
              <label>Visible edge cap <output>{filters.complexityCap}</output>
                <input type="range" min="25" max="1000" step="25" value={filters.complexityCap} onChange={(event) => updateFilter('complexityCap', Number(event.target.value))} />
              </label>
              <label className="check"><input type="checkbox" checked={filters.groupSubnets} onChange={(event) => updateFilter('groupSubnets', event.target.checked)} /> Group by subnet</label>
              <label className="check"><input type="checkbox" checked={filters.hideIsolates} onChange={(event) => updateFilter('hideIsolates', event.target.checked)} /> Hide isolated hosts</label>
              <label className="check"><input type="checkbox" checked={filters.hideNoise} onChange={(event) => updateFilter('hideNoise', event.target.checked)} /> Hide low-volume noise</label>
            </section>

            <section className="side-section">
              <div className="section-heading"><span>SAVED VIEWS</span><button className="text-button" onClick={saveView}>＋ Save</button></div>
              <div className="saved-list">
                {savedViews.map((view) => (
                  <button key={view.id} onClick={() => { setFilters(view.filters); setLayout(view.layout) }}>
                    <span>◇</span>{view.name}<small>›</small>
                  </button>
                ))}
              </div>
            </section>
          </div>
        </aside>

        <main className="main-panel">
          <div className="map-toolbar">
            <div>
              <strong>Network topology</strong>
              <span>{visible.nodes.length} nodes · {visible.edges.length} connections</span>
            </div>
            <div className="toolbar-actions">
              <label>Layout
                <select value={layout} onChange={(event) => setLayout(event.target.value)}>
                  <option value="cose">Force directed</option><option value="breadthfirst">Hierarchical</option>
                  <option value="circle">Circle</option><option value="grid">Grid</option>
                </select>
              </label>
              <button onClick={() => mapRef.current?.fit()}><Icon name="fit" /> Fit</button>
              <button onClick={() => mapRef.current?.reset()}>↻ Reset</button>
              <div className="export-menu">
                <button onClick={() => mapRef.current?.exportPng()}><Icon name="export" /> PNG</button>
                <button onClick={() => downloadText('netmap-flows.csv', exportDatasetCsv(visible), 'text/csv;charset=utf-8')}>CSV</button>
              </div>
            </div>
          </div>
          <NetworkMap
            ref={mapRef}
            dataset={visible}
            layout={layout}
            groupSubnets={filters.groupSubnets}
            onSelectNode={onSelectNode}
            onSelectEdge={onSelectEdge}
          />
          <div className="map-status">
            <span><i className="internal-dot" /> Internal host</span><span><i className="external-dot" /> External host</span>
            <span className="map-hint">Scroll to zoom · Drag hosts to pin · Click for details</span>
          </div>
        </main>

        <aside className="details-pane" aria-label="Selection details">
          {selectedNode ? (
            <NodeDetails
              node={selectedNode}
              edges={nodeEdges}
              peerFor={(edge) => edgePeer(edge, selectedNode)}
              onChange={updateNodeMetadata}
            />
          ) : selectedEdge ? (
            <EdgeDetails edge={selectedEdge} nodes={dataset.nodes} />
          ) : (
            <div className="empty-details"><span>◎</span><h2>Inspect the map</h2><p>Select a host or connection to review its activity.</p></div>
          )}
        </aside>
      </div>

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
          onClose={() => setImportOpen(false)}
          onSelect={selectNativeFiles}
          onBrowserFile={selectBrowserFile}
          onMapping={setMapping}
          onNext={() => setImportStage(importKind === 'csv' ? 'mapping' : 'progress')}
          onImport={runImport}
          onCancel={() => abortRef.current?.abort()}
        />
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
  return (
    <>
      <div className="details-header">
        <span className={`host-avatar ${node.kind}`}>⌁</span>
        <div><span className="eyebrow">{node.kind} HOST</span><h2>{node.ip}</h2><p>{node.label}</p></div>
      </div>
      <div className="risk-banner"><span>Shielded</span><strong>{node.kind === 'internal' ? 'Internal asset' : 'External endpoint'}</strong></div>
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

function EdgeDetails({ edge, nodes }: { edge: NetworkEdge; nodes: NetworkNode[] }) {
  const source = nodes.find((node) => node.id === edge.source)
  const target = nodes.find((node) => node.id === edge.target)
  return <div className="edge-details">
    <span className="eyebrow">DIRECTIONAL FLOW</span><h2>{edge.protocol}:{edge.port}</h2>
    <div className="flow-route"><strong>{source?.ip}</strong><span>→</span><strong>{target?.ip}</strong></div>
    <dl><div><dt>Bytes</dt><dd>{formatBytes(edge.bytes)}</dd></div><div><dt>Packets</dt><dd>{edge.packets.toLocaleString()}</dd></div><div><dt>First seen</dt><dd>{formatTime(edge.firstSeen)}</dd></div><div><dt>Last seen</dt><dd>{formatTime(edge.lastSeen)}</dd></div></dl>
    <section className="detail-section source-list"><h3>SOURCE IMPORTS</h3>{edge.imports.map((sourceName) => <p key={sourceName}>▤ {sourceName}</p>)}</section>
  </div>
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
  onClose: () => void
  onSelect: () => void
  onBrowserFile: (file: File | undefined) => void
  onMapping: (mapping: ImportMapping) => void
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
          {props.preview && <div className="preview-wrap"><div className="preview-heading"><strong>Data preview</strong><span>{props.preview.headers.length} columns</span></div><table><thead><tr>{props.preview.headers.slice(0, 5).map((header) => <th key={header}>{header}</th>)}</tr></thead><tbody>{props.preview.rows.slice(0, 3).map((row, index) => <tr key={index}>{props.preview?.headers.slice(0, 5).map((header) => <td key={header}>{row[header]}</td>)}</tr>)}</tbody></table></div>}
          {props.error && <div className="error-box">{props.error}</div>}
          <footer><button onClick={props.onClose}>Cancel</button><button className="primary" disabled={!props.paths.length} onClick={props.kind === 'csv' ? props.onNext : props.onImport}>Continue</button></footer>
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
