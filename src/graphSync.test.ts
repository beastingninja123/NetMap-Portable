import cytoscape, { type ElementDefinition } from 'cytoscape'
import { describe, expect, it } from 'vitest'
import { syncGraphElements } from './graphSync'

const full: ElementDefinition[] = [
  { data: { id: 'a', label: 'A' }, position: { x: 20, y: 30 } },
  { data: { id: 'b', label: 'B' }, position: { x: 160, y: 90 } },
  { data: { id: 'a-b', source: 'a', target: 'b' } },
]

describe('graph element synchronization', () => {
  it('restores node positions after a filter removes and returns them', () => {
    const cy = cytoscape({ headless: true, elements: full, layout: { name: 'preset' } })
    const positions = new Map<string, { x: number; y: number }>()
    syncGraphElements(cy, [full[0]], positions)
    expect(cy.getElementById('b').empty()).toBe(true)
    const result = syncGraphElements(cy, full, positions)
    expect(result.brandNewCount).toBe(0)
    expect(cy.getElementById('b').position()).toEqual({ x: 160, y: 90 })
    expect(cy.edges()).toHaveLength(1)
    cy.destroy()
  })

  it('identifies genuinely new nodes so the map can re-run a layout', () => {
    const cy = cytoscape({ headless: true, elements: [], layout: { name: 'preset' } })
    const result = syncGraphElements(cy, full, new Map())
    expect(result.brandNewCount).toBe(2)
    expect(cy.nodes()).toHaveLength(2)
    cy.destroy()
  })
})
