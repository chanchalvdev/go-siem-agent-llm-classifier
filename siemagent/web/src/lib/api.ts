import axios from 'axios'
import type { Severity } from '../styles/tokens'

// ── Types mirroring Go structs ────────────────────────────────────────────────

export interface LogEvent {
  raw: string
  timestamp: string
  hostname?: string
  app_name?: string
  proc_id?: string
  message: string
  source: 'syslog' | 'json' | 'raw'
}

export interface MITREInfo {
  tactic: string
  technique_id: string
  technique: string
}

export interface Classification {
  severity: Severity
  attack_type: string
  confidence: number
  mitre: MITREInfo
  iocs: string[]
  remediation: string
  summary: string
}

export interface ClassifiedEvent extends Classification {
  event: LogEvent
  processed_at: string
}

export interface HealthStatus {
  status: string
}

// ── Auth ──────────────────────────────────────────────────────────────────────

// API key for servers started with SIEM_API_KEYS. Vite compiles it into the
// bundle, so anyone who can load the dashboard can read it: fine for local or
// single-team installs, not a substitute for SSO in front of a shared one.
const apiKey: string = import.meta.env.VITE_SIEM_API_KEY ?? ''

export function authHeaders(): Record<string, string> {
  return apiKey ? { 'X-API-Key': apiKey } : {}
}

// Browsers cannot set headers on a WebSocket handshake, so the server accepts
// the key as a query parameter on upgrade requests only.
export function withApiKey(url: string): string {
  if (!apiKey) return url
  return `${url}${url.includes('?') ? '&' : '?'}api_key=${encodeURIComponent(apiKey)}`
}

// ── Axios instance ────────────────────────────────────────────────────────────

const client = axios.create({
  baseURL: '/api',
  timeout: 30_000,
  headers: { 'Content-Type': 'application/json', ...authHeaders() },
})

// Log request duration in development
if (import.meta.env.DEV) {
  client.interceptors.request.use((config) => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    ;(config as any)._t = Date.now()
    return config
  })
  client.interceptors.response.use((response) => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const start = (response.config as any)._t as number
    if (start) {
      console.debug(`[api] ${response.config.method?.toUpperCase()} ${response.config.url} — ${Date.now() - start}ms`)
    }
    return response
  })
}

// ── API functions ─────────────────────────────────────────────────────────────

export async function classifyLog(log: string, format?: string): Promise<ClassifiedEvent> {
  const { data } = await client.post<ClassifiedEvent>('/classify', { log, format: format ?? 'auto' })
  return data
}

// Most recent stored events, newest first. With Postgres configured this
// includes history from before the last server restart.
export async function listEvents(limit = 100): Promise<ClassifiedEvent[]> {
  const { data } = await client.get<ClassifiedEvent[]>('/events', { params: { limit } })
  return data
}

export async function getHealth(): Promise<HealthStatus> {
  const { data } = await client.get<HealthStatus>('/health')
  return data
}

export interface SearchHit {
  event_id: string
  timestamp: string
  source: string
  attack_type: string
  severity: Severity
  summary: string
  mitre_tactic: string
  score: number
}

export interface AttackCount {
  count: number
  severity: string
}

export interface TimelineBucket {
  time: string
  counts: Record<string, number>
}

export interface AnalyticsSummary {
  total_events: number
  attack_type_counts: Record<string, AttackCount>
  timeline: TimelineBucket[]
  mitre_tactics: Record<string, number>
}

export async function searchEvents(query: string, severity?: Severity, limit = 20): Promise<SearchHit[]> {
  const params: Record<string, string | number> = { q: query, limit }
  if (severity) params.severity = severity
  const { data } = await client.get<SearchHit[]>('/search', { params })
  return data
}

export async function getAnalytics(): Promise<AnalyticsSummary> {
  const { data } = await client.get<AnalyticsSummary>('/analytics/summary')
  return data
}

export async function ingestLogs(logs: string[], format = 'auto') {
  const { data } = await client.post('/ingest', { logs, format })
  return data
}

// ── SSE streaming ─────────────────────────────────────────────────────────────

export function classifyLogStream(
  log: string,
  format: string,
  onChunk: (chunk: string) => void,
  onResult: (event: ClassifiedEvent) => void,
  onError: (err: string) => void,
): () => void {
  const controller = new AbortController()

  fetch('/api/classify/stream', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify({ log, format }),
    signal: controller.signal,
  })
    .then(async (res) => {
      if (!res.ok || !res.body) {
        onError(res.status === 401 ? 'Unauthorized: check VITE_SIEM_API_KEY' : `Request failed (${res.status})`)
        return
      }
      const reader = res.body.getReader()
      const decoder = new TextDecoder()
      let buf = ''

      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        buf += decoder.decode(value, { stream: true })
        const lines = buf.split('\n\n')
        buf = lines.pop() ?? ''
        for (const line of lines) {
          const text = line.replace(/^data: /, '').trim()
          if (!text) continue
          try {
            const msg = JSON.parse(text)
            if (msg.chunk) onChunk(msg.chunk)
            if (msg.done) onResult(msg.result)
            if (msg.error) onError(msg.error)
          } catch {
            // ignore parse errors on partial data
          }
        }
      }
    })
    .catch((err) => {
      if (err.name !== 'AbortError') onError(String(err))
    })

  return () => controller.abort()
}
