import cytoscape, { type Core, type ElementDefinition, type EventObject, type LayoutOptions } from 'cytoscape'
import { forwardRef, useEffect, useImperativeHandle, useRef } from 'react'
import type { NetworkDataset, NetworkEdge, NetworkNode } from './types'

export interface NetworkMapHandle {
  fit: () => void
  reset: () => void
  exportPng: () => void
}

interface Props {
  dataset: NetworkDataset
  layout: string
  groupSubnets: boolean
  onSelectNode: (node: NetworkNode | null) => void
  onSelectEdge: (edge: NetworkEdge | null) => void
}

const colors: Record<string, string> = {
  TCP: '#38bdf8', UDP: '#a78bfa', ICMP: '#fbbf24', DNS: '#34d399',
  HTTP: '#fb923c', TLS: '#22d3ee', SSH: '#f472b6', OTHER: '#94a3b8',
}

function elementsFor(dataset: NetworkDataset, grouped: boolean): ElementDefinition[] {
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
      displayLabel: `${node.label}\n${node.ip}`,
    },
    classes: node.kind,
  }))
  const edges = dataset.edges.map((edge) => ({
    data: {
      ...edge,
      label: `${edge.protocol} · ${edge.port}`,
      weight: Math.max(1.5, Math.min(7, Math.log10(edge.bytes + 1) - 2)),
      color: colors[edge.protocol] ?? colors.OTHER,
    },
  }))
  return [...groups, ...nodes, ...edges]
}

function layoutOptions(name: string): LayoutOptions {
  if (name === 'grid') return { name: 'grid', animate: true, padding: 36 }
  if (name === 'circle') return { name: 'circle', animate: true, padding: 36 }
  if (name === 'breadthfirst') return { name: 'breadthfirst', directed: true, animate: true, padding: 36 }
  return { name: 'cose', animate: true, randomize: true, padding: 36, idealEdgeLength: 100, nodeRepulsion: 7000 }
}

const NetworkMap = forwardRef<NetworkMapHandle, Props>(function NetworkMap(
  { dataset, layout, groupSubnets, onSelectNode, onSelectEdge },
  ref,
) {
  const hostRef = useRef<HTMLDivElement>(null)
  const cyRef = useRef<Core | null>(null)
  const tooltipRef = useRef<HTMLDivElement>(null)

  useImperativeHandle(ref, () => ({
    fit: () => cyRef.current?.fit(undefined, 40),
    reset: () => {
      const cy = cyRef.current
      if (!cy) return
      cy.nodes().unselect()
      cy.nodes().unlock()
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
    const cy = cytoscape({
      container: hostRef.current,
      elements: elementsFor(dataset, groupSubnets),
      layout: layoutOptions(layout),
      minZoom: 0.18,
      maxZoom: 3.5,
      wheelSensitivity: 0.22,
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
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            opacity: 0.72,
            label: 'data(label)',
            color: '#91a5b9',
            'font-size': 7,
            'text-background-color': '#08111f',
            'text-background-opacity': 0.8,
            'text-background-padding': '2px',
          },
        },
        { selector: 'edge:selected', style: { opacity: 1, 'line-color': '#f8fafc', 'target-arrow-color': '#f8fafc' } },
      ],
    })
    cyRef.current = cy

    cy.on('tap', 'node:not(.subnet)', (event: EventObject) => {
      const node = dataset.nodes.find((item) => item.id === event.target.id()) ?? null
      onSelectNode(node)
      onSelectEdge(null)
    })
    cy.on('tap', 'edge', (event: EventObject) => {
      const edge = dataset.edges.find((item) => item.id === event.target.id()) ?? null
      onSelectEdge(edge)
      onSelectNode(null)
    })
    cy.on('tap', (event: EventObject) => {
      if (event.target === cy) {
        onSelectNode(null)
        onSelectEdge(null)
      }
    })
    cy.on('dragfree', 'node', (event: EventObject) => event.target.lock())
    cy.on('mouseover', 'node, edge', (event: EventObject) => {
      const tooltip = tooltipRef.current
      if (!tooltip) return
      const item = event.target.data()
      tooltip.textContent = event.target.isNode()
        ? `${item.label} · ${item.ip ?? item.subnet}`
        : `${item.protocol}:${item.port} · ${Number(item.bytes).toLocaleString()} bytes`
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
  }, [dataset, groupSubnets, layout, onSelectEdge, onSelectNode])

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
