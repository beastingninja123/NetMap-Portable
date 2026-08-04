import { describe, expect, it } from 'vitest'
import { injectDemoLiveFlow } from './liveDemo'

describe('demo live stream', () => {
  it('grows the live dataset with hosts and flows', () => {
    let dataset = { nodes: [], edges: [] }
    dataset = injectDemoLiveFlow(dataset, 1)
    dataset = injectDemoLiveFlow(dataset, 2)
    dataset = injectDemoLiveFlow(dataset, 3)
    expect(dataset.nodes.length).toBeGreaterThan(1)
    expect(dataset.edges).toHaveLength(3)
    expect(dataset.nodes.some((node) => node.ip === '10.20.0.12')).toBe(true)
  })
})
