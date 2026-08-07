import type { Core, ElementDefinition } from 'cytoscape'

export type PositionCache = Map<string, { x: number; y: number }>

export function rememberPositions(cy: Core, positions: PositionCache): void {
  cy.nodes().forEach((node) => {
    if (!node.hasClass('subnet')) positions.set(node.id(), { ...node.position() })
  })
}

function stableAngle(id: string): number {
  const hash = [...id].reduce((value, character) => ((value * 31) + character.charCodeAt(0)) >>> 0, 7)
  return (hash % 360) * Math.PI / 180
}

export function syncGraphElements(
  cy: Core,
  elements: ElementDefinition[],
  positions: PositionCache,
): { brandNewCount: number; retainedNodeCount: number } {
  rememberPositions(cy, positions)
  const desiredIds = new Set(elements.map((element) => String(element.data.id)))
  const newNodeIds: string[] = []
  const retainedNodeCount = cy.nodes().not('.subnet').filter((node) => desiredIds.has(node.id())).length
  cy.batch(() => {
    cy.elements().filter((element) => !desiredIds.has(element.id())).remove()
    elements.forEach((definition) => {
      const id = String(definition.data.id)
      const existing = cy.getElementById(id)
      if (existing.nonempty()) {
        existing.data(definition.data)
        existing.classes(definition.classes ?? '')
        return
      }
      const added = cy.add(definition)
      if (added.isNode() && !added.hasClass('subnet')) newNodeIds.push(id)
    })
  })

  let brandNewCount = 0
  newNodeIds.forEach((id) => {
    const node = cy.getElementById(id)
    const prior = positions.get(id)
    if (prior) {
      node.position(prior)
      return
    }
    brandNewCount += 1
    const neighbors = node.neighborhood('node').nodes().not('.subnet')
    const anchor = neighbors.nonempty()
      ? neighbors.position()
      : { x: (cy.width() / 2 - cy.pan().x) / cy.zoom(), y: (cy.height() / 2 - cy.pan().y) / cy.zoom() }
    const angle = stableAngle(id)
    node.position({ x: anchor.x + Math.cos(angle) * 65, y: anchor.y + Math.sin(angle) * 65 })
    positions.set(id, { ...node.position() })
  })
  return { brandNewCount, retainedNodeCount }
}
