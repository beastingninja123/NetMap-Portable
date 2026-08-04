import cytoscape, { type Core, type ElementDefinition, type EventObject, type LayoutOptions } from 'cytoscape'
import { forwardRef, useEffect, useImperativeHandle, useRef } from 'react'
import type { AggregatedEdge, EdgeDisplayMode, NetworkDataset, NetworkEdge, NetworkNode } from './types'

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
  groupSubnets: boolean
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

const colors: Record<string, string> = {
  TCP: '#38bdf8', UDP: '#a78bfa', ICMP: '#fbbf24', DNS: '#34d399',
  HTTP: '#fb923c', TLS: '#22d3ee', SSH: '#f472b6', OTHER: '#94a3b8',
}

function protocolColor(protocols: string[]): string {
  if (protocols.length === 1) return colors[protocols[0]] ?? colors.OTHER
  return '#7dd3fc'
}

function elementsFor(
  dataset: NetworkDataset,
  grouped: boolean,
  showHostnames: boolean,
  edgeMode: EdgeDisplayMode,
  showEdgeLabels: boolean,
  aggregatedEdges: AggregatedEdge[],
  expandedPairId: string | null,
): ElementDefinition[] {
  const groups = grouped
    ? [...new Set(dataset.nodes.map((node) => node.subnet))].map((subnet) => ({
      data: { id: `group-${subnet}`, label: subnet, group: true },
      classes: 'subnet',
    }))
    : []
  const nodes = dataset.nodes.map((node) => ({
    data: {
      ...node,
      parent: grouped ? `group-${node.subnet}` : undefined,
      displayLabel: showHostnames && node.hostname ? `${node.hostname}\n${node.ip}` : node.ip,
    },
    classes: node.kind,
  }))

  if (edgeMode === 'hidden') return [...groups, ...nodes]

  if (edgeMode === 'aggregate') {
    const edges = aggregatedEdges.flatMap((edge) => {
      if (expandedPairId === edge.id) {
        return edge.flows.map((flow) => ({
          data: {
            ...flow,
            label: showEdgeLabels ? `${flow.protocol} · ${flow.port}` : '',
            weight: Math.max(1.2, Math.min(6, Math.log10(flow.bytes + 1) - 2)),
            color: colors[flow.protocol] ?? colors.OTHER,
            kind: 'flow',
            tip: `${flow.protocol}:${flow.port} · ${flow.bytes.toLocaleString()} bytes`,
          },
          classes: 'flow-edge',
        }))
      }
      const top = edge.ports[0]
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
          tip: edge.flowCount === 1 && top
            ? `${top.protocol}:${top.port} · ${edge.bytes.toLocaleString()} bytes`
            : `${edge.flowCount} ports · ${edge.bytes.toLocaleString()} bytes · click for details`,
        },
        classes: 'aggregate-edge',
      }]
    })
    return [...groups, ...nodes, ...edges]
  }

  const edges = dataset.edges.map((edge) => ({
    data: {
      ...edge,
      label: showEdgeLabels ? `${edge.protocol} · ${edge.port}` : '',
      weight: Math.max(1.5, Math.min(7, Math.log10(edge.bytes + 1) - 2)),
      color: colors[edge.protocol] ?? colors.OTHER,
      kind: 'flow',
      tip: `${edge.protocol}:${edge.port} · ${edge.bytes.toLocaleString()} bytes`,
    },
    classes: 'flow-edge',
  }))
  return [...groups, ...nodes, ...edges]
}

function layoutOptions(name: string): LayoutOptions {
  if (name === 'grid') return { name: 'grid', animate: false, padding: 36 }
  if (name === 'circle') return { name: 'circle', animate: false, padding: 36 }
  if (name === 'breadthfirst') return { name: 'breadthfirst', directed: true, animate: false, padding: 36 }
  return {
    name: 'cose',
    animate: false,
    randomize: true,
    padding: 36,
    idealEdgeLength: 120,
    nodeRepulsion: 9000,
    numIter: 800,
  }
}

const NetworkMap = forwardRef<NetworkMapHandle, Props>(function NetworkMap(
  {
    dataset,
    layout,
    groupSubnets,
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
  datasetRef.current = dataset
  aggregatedRef.current = aggregatedEdges

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
      cy.layout(layoutOptions(layout)).run()
    },
    exportPng: () => {
      const data = cyRef.current?.png({ full: true, scale: 2, bg: '#08111f' })
      if (!data) return
      const anchor = document.createElement('a')
      anchor.href = data
      anchor.download = 'netmap-topology.png'
      anchor.click()
    },
  }), [layout])

  useEffect(() => {
    if (!hostRef.current) return
    const dense = dataset.edges.length > 80 || aggregatedEdges.length > 80
    const curveStyle = edgeMode === 'per-port' || dense ? 'haystack' : 'bezier'
    const cy = cytoscape({
      container: hostRef.current,
      elements: elementsFor(
        dataset,
        groupSubnets,
        showHostnames,
        edgeMode,
        showEdgeLabels,
        aggregatedEdges,
        expandedPairId,
      ),
      layout: layoutOptions(layout),
      minZoom: 0.05,
      maxZoom: 10,
      wheelSensitivity: 0.35,
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
            'font-size': 9,
            'text-wrap': 'wrap',
            'text-valign': 'bottom',
            'text-margin-y': 8,
            width: 24,
            height: 24,
            'min-zoomed-font-size': 8,
          },
        },
        { selector: 'node.external', style: { 'background-color': '#35233e', 'border-color': '#f472b6', shape: 'diamond' } },
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
            'min-zoomed-font-size': 10,
          },
        },
        { selector: 'edge.aggregate-edge', style: { opacity: 0.85 } },
        { selector: 'edge:selected', style: { opacity: 1, 'line-color': '#f8fafc', 'target-arrow-color': '#f8fafc', width: 4 } },
        { selector: 'core', style: { 'active-bg-opacity': 0 } },
      ],
    })
    cyRef.current = cy

    cy.on('zoom', () => onZoomChange(cy.zoom()))
    onZoomChange(cy.zoom())
    cy.on('tap', 'node', (event: EventObject) => {
      if (event.target.hasClass('subnet')) return
      const node = datasetRef.current.nodes.find((item) => item.id === event.target.id()) ?? null
      onSelectNode(node)
    })
    cy.on('tap', 'edge', (event: EventObject) => {
      const data = event.target.data()
      if (data.kind === 'aggregate') {
        const aggregate = aggregatedRef.current.find((item) => item.id === data.id) ?? null
        onSelectAggregatedEdge(aggregate)
        return
      }
      const edge = datasetRef.current.edges.find((item) => item.id === data.id)
        ?? aggregatedRef.current.flatMap((item) => item.flows).find((item) => item.id === data.id)
        ?? null
      onSelectEdge(edge)
    })
    cy.on('tap', (event: EventObject) => {
      if (event.target === cy) {
        onSelectNode(null)
        onSelectEdge(null)
        onSelectAggregatedEdge(null)
      }
    })
    cy.on('grab', 'node', (event: EventObject) => {
      event.target.unlock()
      cy.edges().style('opacity', 0.15)
      cy.edges().style('label', '')
    })
    cy.on('free', 'node', () => {
      cy.edges().removeStyle('opacity')
      cy.edges().removeStyle('label')
    })
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
      cy.destroy()
      cyRef.current = null
    }
  }, [
    aggregatedEdges,
    dataset,
    edgeMode,
    expandedPairId,
    groupSubnets,
    layout,
    onSelectAggregatedEdge,
    onSelectEdge,
    onSelectNode,
    onZoomChange,
    showEdgeLabels,
    showHostnames,
  ])

  return (
    <div className="map-host">
      <div ref={hostRef} className="cytoscape-canvas" aria-label="Interactive network topology" />
      <div ref={tooltipRef} className="map-tooltip" hidden />
      <div className="map-legend" aria-label="Protocol color legend">
        {Object.entries(colors).slice(0, 6).map(([name, color]) => (
          <span key={name}><i style={{ background: color }} />{name}</span>
        ))}
      </div>
    </div>
  )
})

export default NetworkMap
