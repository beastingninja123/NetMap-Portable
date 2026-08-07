import cytoscape, {
  type Core,
  type ElementDefinition,
  type EventObject,
  type LayoutOptions,
  type StylesheetStyle,
} from 'cytoscape'
import { forwardRef, useEffect, useImperativeHandle, useRef } from 'react'
import { rememberPositions, syncGraphElements } from './graphSync'
import { traceNeighborhood, ZONE_COLORS } from './insights'
import { PROTOCOL_COLORS } from './protocols'
import type {
  AggregatedEdge,
  EdgeDisplayMode,
  NetworkDataset,
  NetworkEdge,
  NetworkNode,
  PathDirection,
  Protocol,
  SecurityZone,
} from './types'

export interface NetworkMapHandle {
  fit: () => void
  reset: () => void
  zoomIn: () => void
  zoomOut: () => void
  exportPng: () => void
}

interface Props {
  dataset: NetworkDataset
  layout: string
  nodeSpacing: number
  groupSubnets: boolean
  groupZones: boolean
  showConduits: boolean
  showAnomalies: boolean
  pathDirection: PathDirection
  showHostnames: boolean
  edgeMode: EdgeDisplayMode
  showEdgeLabels: boolean
  aggregatedEdges: AggregatedEdge[]
  expandedPairId: string | null
  onZoomChange: (zoom: number) => void
  onSelectNode: (node: NetworkNode | null) => void
  onSelectEdge: (edge: NetworkEdge | null) => void
  onSelectAggregatedEdge: (edge: AggregatedEdge | null) => void
}

function protocolColor(protocols: Protocol[]): string {
  if (protocols.length === 1) return PROTOCOL_COLORS[protocols[0]]
  return '#7dd3fc'
}

function classSlug(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, '-')
}

function compoundPositions(
  dataset: NetworkDataset,
  groupMode: 'zone' | 'subnet',
  nodeSpacing: number,
): Map<string, { x: number; y: number }> {
  const valueFor = (node: NetworkNode) => groupMode === 'zone'
    ? node.securityZone ?? 'Unassigned'
    : node.subnet
  const values = [...new Set(dataset.nodes.map(valueFor))].sort()
  const groupColumns = Math.max(1, Math.ceil(Math.sqrt(values.length)))
  const groupStride = Math.max(210, nodeSpacing * 3)
  const positions = new Map<string, { x: number; y: number }>()

  values.forEach((value, groupIndex) => {
    const members = dataset.nodes.filter((node) => valueFor(node) === value)
    const columns = Math.max(1, Math.ceil(Math.sqrt(members.length)))
    const groupX = (groupIndex % groupColumns) * groupStride
    const groupY = Math.floor(groupIndex / groupColumns) * groupStride
    members.forEach((node, memberIndex) => {
      const column = memberIndex % columns
      const row = Math.floor(memberIndex / columns)
      positions.set(node.id, {
        x: groupX + (column - (columns - 1) / 2) * nodeSpacing,
        y: groupY + (row - (Math.ceil(members.length / columns) - 1) / 2) * nodeSpacing,
      })
    })
  })
  return positions
}

function elementsFor(
  dataset: NetworkDataset,
  grouped: boolean,
  groupZones: boolean,
  nodeSpacing: number,
  showConduits: boolean,
  showAnomalies: boolean,
  showHostnames: boolean,
  edgeMode: EdgeDisplayMode,
  showEdgeLabels: boolean,
  aggregatedEdges: AggregatedEdge[],
  expandedPairId: string | null,
): ElementDefinition[] {
  const nodeById = new Map(dataset.nodes.map((node) => [node.id, node]))
  const groupMode = groupZones ? 'zone' : grouped ? 'subnet' : null
  const presetPositions = groupMode ? compoundPositions(dataset, groupMode, nodeSpacing) : null
  const groupValues = groupMode === 'zone'
    ? [...new Set(dataset.nodes.map((node) => node.securityZone ?? 'Unassigned'))]
    : groupMode === 'subnet'
      ? [...new Set(dataset.nodes.map((node) => node.subnet))]
      : []
  const groups = groupValues.map((value) => ({
      data: {
        id: `group-${groupMode}-${classSlug(value)}`,
        label: value,
        group: true,
        groupKind: groupMode,
        zoneColor: groupMode === 'zone' ? ZONE_COLORS[value as SecurityZone] : '#31516e',
      },
      classes: `subnet ${groupMode === 'zone' ? 'zone-group' : 'subnet-group'}`,
    }))
  const nodes = dataset.nodes.map((node) => ({
    data: {
      ...node,
      parent: groupMode === 'zone'
        ? `group-zone-${classSlug(node.securityZone ?? 'Unassigned')}`
        : groupMode === 'subnet'
          ? `group-subnet-${classSlug(node.subnet)}`
          : undefined,
      displayLabel: showHostnames && node.hostname ? `${node.hostname}\n${node.ip}` : node.ip,
      zoneColor: ZONE_COLORS[node.securityZone ?? 'Unassigned'],
    },
    classes: [
      node.kind,
      `role-${classSlug(node.assetRole ?? 'Unknown')}`,
      'zone-assigned',
      showAnomalies && node.anomalyCount ? 'anomalous' : '',
    ].filter(Boolean).join(' '),
    position: presetPositions?.get(node.id),
  }))

  const edgeClasses = (edge: Pick<NetworkEdge, 'source' | 'target' | 'anomalies'>, base: string): string => {
    const sourceZone = nodeById.get(edge.source)?.securityZone
    const targetZone = nodeById.get(edge.target)?.securityZone
    const conduit = showConduits && sourceZone && targetZone && sourceZone !== targetZone
    const anomalous = showAnomalies && Boolean(edge.anomalies?.length)
    return [base, conduit ? 'conduit' : '', anomalous ? 'anomaly-edge' : ''].filter(Boolean).join(' ')
  }

  if (edgeMode === 'hidden') return [...groups, ...nodes]

  if (edgeMode === 'aggregate') {
    const edges = aggregatedEdges.flatMap<ElementDefinition>((edge) => {
      if (expandedPairId === edge.id) {
        return edge.flows.map((flow) => ({
          data: {
            ...flow,
            label: showEdgeLabels ? `${flow.protocol} · ${flow.port}` : '',
            weight: Math.max(1.2, Math.min(6, Math.log10(flow.bytes + 1) - 2)),
            color: PROTOCOL_COLORS[flow.protocol] ?? PROTOCOL_COLORS.OTHER,
            kind: 'flow',
            tip: `${flow.protocol}:${flow.port} · ${flow.bytes.toLocaleString()} bytes`,
          },
          classes: edgeClasses(flow, 'flow-edge'),
        }))
      }
      const top = edge.ports[0]
      const anomalies = [...new Set(edge.flows.flatMap((flow) => flow.anomalies ?? []))]
      const label = showEdgeLabels
        ? (edge.flowCount === 1 && top
          ? `${top.protocol} · ${top.port}`
          : `${edge.flowCount} ports`)
        : ''
      return [{
        data: {
          id: edge.id,
          source: edge.source,
          target: edge.target,
          bytes: edge.bytes,
          packets: edge.packets,
          flowCount: edge.flowCount,
          label,
          weight: Math.max(2, Math.min(8, Math.log10(edge.bytes + 1) - 1.5)),
          color: protocolColor(edge.protocols),
          kind: 'aggregate',
          anomalies,
          tip: edge.flowCount === 1 && top
            ? `${top.protocol}:${top.port} · ${edge.bytes.toLocaleString()} bytes`
            : `${edge.flowCount} ports · ${edge.bytes.toLocaleString()} bytes · click for details`,
        },
        classes: edgeClasses({ ...edge, anomalies }, 'aggregate-edge'),
      }]
    })
    return [...groups, ...nodes, ...edges]
  }

  const edges = dataset.edges.map((edge) => ({
    data: {
      ...edge,
      label: showEdgeLabels ? `${edge.protocol} · ${edge.port}` : '',
      weight: Math.max(1.5, Math.min(7, Math.log10(edge.bytes + 1) - 2)),
      color: PROTOCOL_COLORS[edge.protocol] ?? PROTOCOL_COLORS.OTHER,
      kind: 'flow',
      tip: `${edge.protocol}:${edge.port} · ${edge.bytes.toLocaleString()} bytes`,
    },
    classes: edgeClasses(edge, 'flow-edge'),
  }))
  return [...groups, ...nodes, ...edges]
}

function layoutOptions(name: string, nodeSpacing: number, randomize = true): LayoutOptions {
  const spacingFactor = Math.max(0.5, Math.min(2.25, nodeSpacing / 80))
  if (name === 'grid') return { name: 'grid', animate: false, padding: 36, spacingFactor }
  if (name === 'circle') return { name: 'circle', animate: false, padding: 36, spacingFactor }
  if (name === 'breadthfirst') {
    return { name: 'breadthfirst', directed: true, animate: false, padding: 36, spacingFactor }
  }
  return {
    name: 'cose',
    animate: false,
    randomize,
    padding: 36,
    idealEdgeLength: nodeSpacing,
    nodeRepulsion: Math.round(1_800 + nodeSpacing * 45),
    componentSpacing: Math.max(30, Math.round(nodeSpacing * 0.8)),
    gravity: 1.2,
    numIter: 800,
  }
}

const HOVER_CLASSES = 'hover-dim hover-root hover-hop-1 hover-hop-2 hover-path-1 hover-path-2'

function clearNeighborhoodHighlight(cy: Core): void {
  cy.elements().removeClass(HOVER_CLASSES)
}

function highlightNeighborhood(cy: Core, rootId: string, direction: PathDirection): void {
  clearNeighborhoodHighlight(cy)
  const traced = traceNeighborhood(rootId, cy.edges().map((edge) => ({
    id: edge.id(),
    source: edge.source().id(),
    target: edge.target().id(),
  })), direction)

  cy.nodes().not('.subnet').addClass('hover-dim')
  cy.edges().addClass('hover-dim')
  traced.distances.forEach((depth, id) => {
    const node = cy.getElementById(id)
    node.removeClass('hover-dim')
    node.addClass(depth === 0 ? 'hover-root' : depth === 1 ? 'hover-hop-1' : 'hover-hop-2')
  })

  traced.edgeIds.forEach((depth, id) => {
    const edge = cy.getElementById(id)
    edge.removeClass('hover-dim')
    edge.addClass(depth === 1 ? 'hover-path-1' : 'hover-path-2')
  })
}

function applyAdaptiveLabelScale(cy: Core, force = false): void {
  const zoom = Math.max(0.1, cy.zoom())
  const fontSize = Math.min(80, Math.max(10, 10 / zoom))
  const nodeSize = Math.min(70, Math.max(26, 26 / Math.sqrt(zoom)))
  const scaleKey = `${Math.round(fontSize)}-${Math.round(nodeSize)}`
  if (!force && cy.scratch('_adaptiveLabelScale') === scaleKey) return
  cy.scratch('_adaptiveLabelScale', scaleKey)
  cy.nodes().not('.subnet').style({
    'font-size': fontSize,
    width: nodeSize,
    height: nodeSize,
    'text-background-opacity': zoom < 0.85 ? 0.9 : 0.42,
    'text-outline-width': zoom < 0.85 ? 1.5 : 1,
  })
}

const NetworkMap = forwardRef<NetworkMapHandle, Props>(function NetworkMap(
  {
    dataset,
    layout,
    nodeSpacing,
    groupSubnets,
    groupZones,
    showConduits,
    showAnomalies,
    pathDirection,
    showHostnames,
    edgeMode,
    showEdgeLabels,
    aggregatedEdges,
    expandedPairId,
    onSelectNode,
    onSelectEdge,
    onSelectAggregatedEdge,
    onZoomChange,
  },
  ref,
) {
  const hostRef = useRef<HTMLDivElement>(null)
  const cyRef = useRef<Core | null>(null)
  const tooltipRef = useRef<HTMLDivElement>(null)
  const datasetRef = useRef(dataset)
  const aggregatedRef = useRef(aggregatedEdges)
  const onSelectNodeRef = useRef(onSelectNode)
  const onSelectEdgeRef = useRef(onSelectEdge)
  const onSelectAggregatedEdgeRef = useRef(onSelectAggregatedEdge)
  const onZoomChangeRef = useRef(onZoomChange)
  const readyRef = useRef(false)
  const nodeSpacingRef = useRef(nodeSpacing)
  const lastAppliedSpacingRef = useRef(nodeSpacing)
  const positionCacheRef = useRef(new Map<string, { x: number; y: number }>())
  const skipNextElementSyncRef = useRef(false)
  const pathDirectionRef = useRef(pathDirection)

  datasetRef.current = dataset
  aggregatedRef.current = aggregatedEdges
  onSelectNodeRef.current = onSelectNode
  onSelectEdgeRef.current = onSelectEdge
  onSelectAggregatedEdgeRef.current = onSelectAggregatedEdge
  onZoomChangeRef.current = onZoomChange
  nodeSpacingRef.current = nodeSpacing
  pathDirectionRef.current = pathDirection

  useImperativeHandle(ref, () => ({
    fit: () => cyRef.current?.fit(undefined, 40),
    zoomIn: () => {
      const cy = cyRef.current
      if (cy) {
        cy.zoom({
          level: Math.min(cy.maxZoom(), cy.zoom() * 1.5),
          renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 },
        })
      }
    },
    zoomOut: () => {
      const cy = cyRef.current
      if (cy) {
        cy.zoom({
          level: Math.max(cy.minZoom(), cy.zoom() / 1.5),
          renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 },
        })
      }
    },
    reset: () => {
      const cy = cyRef.current
      if (!cy) return
      cy.nodes().unselect()
      clearNeighborhoodHighlight(cy)
      if (groupZones || groupSubnets) {
        const groupMode = groupZones ? 'zone' : 'subnet'
        const positions = compoundPositions(datasetRef.current, groupMode, nodeSpacingRef.current)
        cy.nodes().not('.subnet').forEach((node) => {
          const position = positions.get(node.id())
          if (position) node.position(position)
        })
        cy.fit(undefined, 48)
      } else {
        cy.layout(layoutOptions(layout, nodeSpacingRef.current)).run()
      }
      rememberPositions(cy, positionCacheRef.current)
      applyAdaptiveLabelScale(cy, true)
    },
    exportPng: () => {
      const data = cyRef.current?.png({ full: true, scale: 2, bg: '#08111f' })
      if (!data) return
      const anchor = document.createElement('a')
      anchor.href = data
      anchor.download = 'netmap-topology.png'
      anchor.click()
    },
  }), [groupSubnets, groupZones, layout])

  // Remount only when layout/grouping changes (structural).
  useEffect(() => {
    if (!hostRef.current) return
    readyRef.current = false
    const dense = dataset.edges.length > 80 || aggregatedEdges.length > 80
    const curveStyle = edgeMode === 'per-port' || dense ? 'haystack' : 'bezier'
    const cy = cytoscape({
      container: hostRef.current,
      elements: elementsFor(
        dataset,
        groupSubnets,
        groupZones,
        nodeSpacingRef.current,
        showConduits,
        showAnomalies,
        showHostnames,
        edgeMode,
        showEdgeLabels,
        aggregatedEdges,
        expandedPairId,
      ),
      layout: groupSubnets || groupZones
        ? { name: 'preset', animate: false, fit: true, padding: 36 }
        : layoutOptions(layout, nodeSpacingRef.current),
      minZoom: 0.1,
      maxZoom: 10,
      hideEdgesOnViewport: dense,
      textureOnViewport: dense,
      pixelRatio: dense ? 1 : 'auto',
      style: [
        {
          selector: 'node',
          style: {
            'background-color': '#19324b',
            'border-color': '#4dd8ff',
            'border-width': 2,
            label: 'data(displayLabel)',
            color: '#cbd5e1',
            'font-size': 10,
            'font-weight': 600,
            'text-wrap': 'wrap',
            'text-valign': 'bottom',
            'text-margin-y': 8,
            'text-background-color': '#08111f',
            'text-background-padding': '2px',
            'text-background-shape': 'roundrectangle',
            'text-outline-color': '#08111f',
            width: 26,
            height: 26,
            'min-zoomed-font-size': 0,
          },
        },
        { selector: 'node.external', style: { 'background-color': '#35233e', 'border-color': '#f472b6', shape: 'diamond' } },
        { selector: 'node.zone-assigned', style: { 'border-color': 'data(zoneColor)' } },
        { selector: 'node.role-plc', style: { shape: 'roundrectangle' } },
        { selector: 'node.role-hmi', style: { shape: 'hexagon' } },
        { selector: 'node.role-rtu', style: { shape: 'rectangle' } },
        { selector: 'node.role-historian, node.role-server', style: { shape: 'barrel' } },
        { selector: 'node.role-opc-gateway, node.role-network-infrastructure', style: { shape: 'octagon' } },
        { selector: 'node.role-safety-system', style: { shape: 'triangle' } },
        {
          selector: 'node.anomalous',
          style: { 'underlay-color': '#ef4444', 'underlay-opacity': 0.32, 'underlay-padding': 6 },
        },
        { selector: 'node:selected', style: { 'border-width': 4, 'border-color': '#f8fafc', 'overlay-color': '#38bdf8', 'overlay-opacity': 0.14 } },
        {
          selector: 'node.subnet',
          style: {
            'background-color': '#0c2033',
            'background-opacity': 0.48,
            'border-color': '#31516e',
            'border-style': 'dashed',
            'border-width': 1,
            label: 'data(label)',
            color: '#7f9bb5',
            'font-size': 10,
            'text-valign': 'top',
            'text-halign': 'center',
            padding: '22px',
          },
        },
        {
          selector: 'node.zone-group',
          style: {
            'background-color': 'data(zoneColor)',
            'background-opacity': 0.08,
            'border-color': 'data(zoneColor)',
            'border-width': 2,
          },
        },
        {
          selector: 'edge',
          style: {
            width: 'data(weight)',
            'line-color': 'data(color)',
            'target-arrow-color': 'data(color)',
            'target-arrow-shape': curveStyle === 'haystack' ? 'none' : 'triangle',
            'curve-style': curveStyle,
            'haystack-radius': 0.45,
            opacity: 0.7,
            label: 'data(label)',
            color: '#91a5b9',
            'font-size': 7,
            'text-background-color': '#08111f',
            'text-background-opacity': 0.8,
            'text-background-padding': '2px',
            'min-zoomed-font-size': 0,
          },
        },
        { selector: 'edge.aggregate-edge', style: { opacity: 0.85 } },
        { selector: 'edge.conduit', style: { 'line-style': 'dashed', opacity: 0.95 } },
        {
          selector: 'edge.anomaly-edge',
          style: { 'line-color': '#ef4444', 'target-arrow-color': '#ef4444', opacity: 1, 'line-style': 'dotted' },
        },
        { selector: 'edge:selected', style: { opacity: 1, 'line-color': '#f8fafc', 'target-arrow-color': '#f8fafc', width: 4 } },
        { selector: 'node.hover-dim', style: { opacity: 0.08, 'text-opacity': 0.04 } },
        { selector: 'edge.hover-dim', style: { opacity: 0.035, 'text-opacity': 0 } },
        {
          selector: 'node.hover-root',
          style: { opacity: 1, 'text-opacity': 1, 'border-width': 5, 'border-color': '#f8fafc', 'z-index': 30 },
        },
        {
          selector: 'node.hover-hop-1',
          style: { opacity: 1, 'text-opacity': 1, 'border-width': 3, 'border-color': '#7dd3fc', 'z-index': 20 },
        },
        {
          selector: 'node.hover-hop-2',
          style: { opacity: 0.78, 'text-opacity': 0.9, 'border-width': 2, 'z-index': 10 },
        },
        { selector: 'edge.hover-path-1', style: { opacity: 1, 'text-opacity': 1, width: 4, 'z-index': 20 } },
        { selector: 'edge.hover-path-2', style: { opacity: 0.72, 'text-opacity': 0.8, width: 2.5, 'z-index': 10 } },
        { selector: 'core', style: { 'active-bg-opacity': 0 } },
      ] as StylesheetStyle[],
    })
    cyRef.current = cy
    readyRef.current = true
    skipNextElementSyncRef.current = true
    lastAppliedSpacingRef.current = nodeSpacingRef.current
    rememberPositions(cy, positionCacheRef.current)
    applyAdaptiveLabelScale(cy, true)

    let zoomAnimationFrame: number | null = null
    cy.on('zoom', () => {
      onZoomChangeRef.current(cy.zoom())
      if (zoomAnimationFrame !== null) return
      zoomAnimationFrame = window.requestAnimationFrame(() => {
        applyAdaptiveLabelScale(cy)
        zoomAnimationFrame = null
      })
    })
    onZoomChangeRef.current(cy.zoom())
    cy.on('tap', 'node', (event: EventObject) => {
      if (event.target.hasClass('subnet')) return
      const node = datasetRef.current.nodes.find((item) => item.id === event.target.id()) ?? null
      onSelectNodeRef.current(node)
    })
    cy.on('tap', 'edge', (event: EventObject) => {
      const data = event.target.data()
      if (data.kind === 'aggregate') {
        const aggregate = aggregatedRef.current.find((item) => item.id === data.id) ?? null
        onSelectAggregatedEdgeRef.current(aggregate)
        return
      }
      const edge = datasetRef.current.edges.find((item) => item.id === data.id)
        ?? aggregatedRef.current.flatMap((item) => item.flows).find((item) => item.id === data.id)
        ?? null
      onSelectEdgeRef.current(edge)
    })
    cy.on('tap', (event: EventObject) => {
      if (event.target === cy) {
        onSelectNodeRef.current(null)
        onSelectEdgeRef.current(null)
        onSelectAggregatedEdgeRef.current(null)
      }
    })
    cy.on('grab', 'node', (event: EventObject) => {
      event.target.unlock()
      clearNeighborhoodHighlight(cy)
      cy.edges().style('opacity', 0.15)
      cy.edges().style('label', '')
    })
    cy.on('free', 'node', () => {
      cy.edges().removeStyle('opacity')
      cy.edges().removeStyle('label')
      rememberPositions(cy, positionCacheRef.current)
    })
    cy.on('mouseover', 'node', (event: EventObject) => {
      if (!event.target.hasClass('subnet')) {
        highlightNeighborhood(cy, event.target.id(), pathDirectionRef.current)
      }
    })
    cy.on('mouseout', 'node', () => clearNeighborhoodHighlight(cy))
    cy.on('mouseover', 'node, edge', (event: EventObject) => {
      const tooltip = tooltipRef.current
      if (!tooltip) return
      const item = event.target.data()
      tooltip.textContent = event.target.isNode()
        ? `${item.hostname ? `${item.hostname} · ` : ''}${item.ip ?? item.subnet}`
        : String(item.tip ?? item.label ?? '')
      tooltip.hidden = false
    })
    cy.on('mousemove', 'node, edge', (event: EventObject) => {
      const tooltip = tooltipRef.current
      if (!tooltip) return
      tooltip.style.left = `${event.renderedPosition.x + 16}px`
      tooltip.style.top = `${event.renderedPosition.y + 12}px`
    })
    cy.on('mouseout', 'node, edge', () => {
      if (tooltipRef.current) tooltipRef.current.hidden = true
    })

    return () => {
      readyRef.current = false
      if (zoomAnimationFrame !== null) window.cancelAnimationFrame(zoomAnimationFrame)
      cy.destroy()
      cyRef.current = null
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- remount only for layout / compound grouping
  }, [groupSubnets, groupZones, layout])

  // Reflow after the spacing slider settles; keep the current orientation and fit the result.
  useEffect(() => {
    const cy = cyRef.current
    if (!cy || !readyRef.current || lastAppliedSpacingRef.current === nodeSpacing) return
    const timeout = window.setTimeout(() => {
      if (!cyRef.current || cyRef.current !== cy) return
      lastAppliedSpacingRef.current = nodeSpacing
      if (groupZones || groupSubnets) {
        const groupMode = groupZones ? 'zone' : 'subnet'
        const positions = compoundPositions(datasetRef.current, groupMode, nodeSpacing)
        cy.nodes().not('.subnet').forEach((node) => {
          const position = positions.get(node.id())
          if (position) node.position(position)
        })
      } else {
        cy.layout(layoutOptions(layout, nodeSpacing, false)).run()
      }
      cy.fit(undefined, 48)
      rememberPositions(cy, positionCacheRef.current)
      applyAdaptiveLabelScale(cy, true)
    }, 120)
    return () => window.clearTimeout(timeout)
  }, [groupSubnets, groupZones, layout, nodeSpacing])

  // Incremental element refresh — preserves pinned positions during live capture.
  useEffect(() => {
    const cy = cyRef.current
    if (!cy || !readyRef.current) return
    if (skipNextElementSyncRef.current) {
      skipNextElementSyncRef.current = false
      return
    }
    const elements = elementsFor(
      dataset,
      groupSubnets,
      groupZones,
      nodeSpacingRef.current,
      showConduits,
      showAnomalies,
      showHostnames,
      edgeMode,
      showEdgeLabels,
      aggregatedEdges,
      expandedPairId,
    )
    const synced = syncGraphElements(cy, elements, positionCacheRef.current)
    if (synced.brandNewCount >= 3 && !groupSubnets && !groupZones) {
      cy.layout(layoutOptions(layout, nodeSpacingRef.current, synced.retainedNodeCount === 0)).run()
      cy.fit(undefined, 48)
      rememberPositions(cy, positionCacheRef.current)
    }
    applyAdaptiveLabelScale(cy, true)
  }, [
    aggregatedEdges,
    dataset,
    edgeMode,
    expandedPairId,
    groupSubnets,
    groupZones,
    layout,
    showAnomalies,
    showConduits,
    showEdgeLabels,
    showHostnames,
  ])

  const legendProtocols = [...new Set(dataset.edges.map((edge) => edge.protocol))]

  return (
    <div className="map-host">
      <div ref={hostRef} className="cytoscape-canvas" aria-label="Interactive network topology" />
      <div ref={tooltipRef} className="map-tooltip" hidden />
      <div className="map-legend" aria-label="Protocol color legend">
        {legendProtocols.map((protocol) => (
          <span key={protocol}><i style={{ background: PROTOCOL_COLORS[protocol] }} />{protocol}</span>
        ))}
      </div>
    </div>
  )
})

export default NetworkMap
