import { useCallback, useEffect, useRef, useState } from 'react'

// AgentEvent mirrors the Go api broadcast payload.
export interface AgentEvent {
  incident_id: string
  event_id: string
  type: 'tool_call' | 'tool_result' | 'chunk' | 'done' | 'error'
  data: string
}

export interface ToolInvocation {
  name: string
  input: string
  result?: string
}

export type IncidentStatus = 'investigating' | 'complete' | 'failed'

export interface Incident {
  id: string
  eventId: string
  status: IncidentStatus
  tools: ToolInvocation[]
  playbook: string
}

const MAX_BACKOFF = 30_000

function defaultURL(): string {
  const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
  return `${proto}://${window.location.host}/ws/alerts`
}

// apply folds one AgentEvent into the incident map, returning a new map.
// Must stay pure: never mutate objects from the previous map — React StrictMode
// double-invokes state updaters, so any mutation is applied twice.
export function apply(map: Map<string, Incident>, ev: AgentEvent): Map<string, Incident> {
  const next = new Map(map)
  const prev: Incident = next.get(ev.incident_id) ?? {
    id: ev.incident_id, eventId: ev.event_id, status: 'investigating', tools: [], playbook: '',
  }
  const inc: Incident = { ...prev, tools: [...prev.tools] }
  switch (ev.type) {
    case 'tool_call': {
      const parsed = safeParse(ev.data)
      inc.tools.push({ name: parsed.name ?? 'tool', input: parsed.input ?? '' })
      break
    }
    case 'tool_result':
      if (inc.tools.length) inc.tools[inc.tools.length - 1] = { ...inc.tools[inc.tools.length - 1], result: ev.data }
      break
    case 'chunk':
      inc.playbook = prev.playbook + ev.data
      break
    case 'done':
      inc.status = 'complete'
      break
    case 'error':
      inc.status = 'failed'
      break
  }
  next.set(ev.incident_id, inc)
  return next
}

function safeParse(s: string): { name?: string; input?: string } {
  try {
    return JSON.parse(s)
  } catch {
    return {}
  }
}

export function useAlertStream(url: string = defaultURL()) {
  const [connected, setConnected] = useState(false)
  const [incidents, setIncidents] = useState<Map<string, Incident>>(new Map())
  const [latestEvent, setLatestEvent] = useState<AgentEvent | null>(null)
  const backoff = useRef(1000)
  const timer = useRef<ReturnType<typeof setTimeout>>(undefined)

  const clearIncident = useCallback((id: string) => {
    setIncidents((m) => {
      const next = new Map(m)
      next.delete(id)
      return next
    })
  }, [])

  useEffect(() => {
    let closed = false
    let ws: WebSocket

    const connect = () => {
      ws = new WebSocket(url)
      ws.onopen = () => {
        setConnected(true)
        backoff.current = 1000
      }
      ws.onmessage = (e) => {
        const ev = safeParse(e.data) as AgentEvent
        if (!ev.incident_id) return
        setLatestEvent(ev)
        setIncidents((m) => apply(m, ev))
      }
      ws.onclose = () => {
        setConnected(false)
        if (closed) return
        timer.current = setTimeout(connect, backoff.current)
        backoff.current = Math.min(backoff.current * 2, MAX_BACKOFF)
      }
    }
    connect()

    return () => {
      closed = true
      clearTimeout(timer.current)
      ws?.close()
    }
  }, [url])

  return { connected, incidents, latestEvent, clearIncident }
}
