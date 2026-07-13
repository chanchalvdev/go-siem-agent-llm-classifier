import { describe, it, expect, vi, beforeEach } from 'vitest'
import { act, renderHook } from '@testing-library/react'
import { apply, useAlertStream, type AgentEvent, type Incident } from '../hooks/useAlertStream'

const seq: AgentEvent[] = [
  { incident_id: 'abc', event_id: 'e1', type: 'tool_call', data: '{"name":"check_abuseipdb","input":"{\\"ip\\":\\"8.8.8.8\\"}"}' },
  { incident_id: 'abc', event_id: 'e1', type: 'tool_result', data: '{"abuse_score":90}' },
  { incident_id: 'abc', event_id: 'e1', type: 'chunk', data: '## Sum' },
  { incident_id: 'abc', event_id: 'e1', type: 'chunk', data: 'mary' },
  { incident_id: 'abc', event_id: 'e1', type: 'done', data: '' },
]

function fold(events: AgentEvent[]): Incident {
  let map = new Map<string, Incident>()
  for (const ev of events) map = apply(map, ev)
  return map.get('abc')!
}

describe('apply reducer', () => {
  it('folds a full event sequence into one incident', () => {
    const inc = fold(seq)
    expect(inc.status).toBe('complete')
    expect(inc.tools).toHaveLength(1)
    expect(inc.tools[0].name).toBe('check_abuseipdb')
    expect(inc.tools[0].result).toContain('abuse_score')
    expect(inc.playbook).toBe('## Summary')
  })

  it('marks failed on an error event', () => {
    const inc = fold([{ incident_id: 'abc', event_id: 'e1', type: 'error', data: 'boom' }])
    expect(inc.status).toBe('failed')
  })
})

// --- Hook test with a mock WebSocket ---

class MockWebSocket {
  static last: MockWebSocket | null = null
  url: string
  onopen: (() => void) | null = null
  onmessage: ((e: { data: string }) => void) | null = null
  onclose: (() => void) | null = null
  constructor(url: string) {
    this.url = url
    MockWebSocket.last = this
  }
  close() {
    this.onclose?.()
  }
}

describe('useAlertStream', () => {
  beforeEach(() => {
    vi.stubGlobal('WebSocket', MockWebSocket as unknown as typeof WebSocket)
  })

  it('connects and accumulates incidents from messages', () => {
    const { result } = renderHook(() => useAlertStream('ws://test/ws'))
    act(() => MockWebSocket.last!.onopen?.())
    expect(result.current.connected).toBe(true)

    for (const ev of seq) {
      act(() => MockWebSocket.last!.onmessage?.({ data: JSON.stringify(ev) }))
    }
    const inc = result.current.incidents.get('abc')!
    expect(inc.status).toBe('complete')
    expect(inc.playbook).toBe('## Summary')

    act(() => result.current.clearIncident('abc'))
    expect(result.current.incidents.has('abc')).toBe(false)
  })
})
