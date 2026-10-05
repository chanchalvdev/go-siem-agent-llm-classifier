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

export type DetectionLevel = 'informational' | 'low' | 'medium' | 'high' | 'critical'

export interface Detection {
  rule_id: string
  title: string
  level: DetectionLevel
  tags?: string[]
  /** Threshold rules: events that crossed the threshold. */
  count?: number
  /** Threshold rules: shared group-by value, e.g. "src_ip=203.0.113.7". */
  group?: string
  /** Threshold rules: e.g. "count() by src_ip >= 10 in 5m". */
  threshold?: string
}

export interface ClassifiedEvent extends Classification {
  event: LogEvent
  processed_at: string
  /** Detection rules that matched this event. */
  detections?: Detection[]
  /** What produced the verdict. Absent on events stored before rules existed. */
  classified_by?: 'rules' | 'llm' | 'llm+rules'
  /** Set when a suppression matched: stored, but kept out of incidents. */
  suppressed_by?: string
}

export interface DetectionRule {
  id: string
  title: string
  description?: string
  level: DetectionLevel
  status?: string
  tags?: string[]
  source: string
  hits: number
  enabled: boolean
  type: 'single' | 'threshold'
  threshold?: string
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

// State-changing requests authenticated by the session cookie must carry this
// header; other sites cannot add it, which blocks cross-site request forgery.
export const CSRF_HEADERS: Record<string, string> = { 'X-Requested-With': 'siemagent' }

// ── Axios instance ────────────────────────────────────────────────────────────

const client = axios.create({
  baseURL: '/api',
  timeout: 30_000,
  headers: { 'Content-Type': 'application/json', ...CSRF_HEADERS, ...authHeaders() },
})

// A 401 means the session ended (expired, logged out elsewhere, account
// disabled). Listeners (the auth gate) re-check and show the login screen.
export const SESSION_EXPIRED_EVENT = 'siem:session-expired'
client.interceptors.response.use(undefined, (error) => {
  if (axios.isAxiosError(error) && error.response?.status === 401 && !error.config?.url?.startsWith('/auth/')) {
    window.dispatchEvent(new Event(SESSION_EXPIRED_EVENT))
  }
  return Promise.reject(error)
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

export async function listDetectionRules(): Promise<DetectionRule[]> {
  const { data } = await client.get<DetectionRule[]>('/detections/rules')
  return data
}

export async function setDetectionRuleEnabled(id: string, enabled: boolean): Promise<DetectionRule> {
  const { data } = await client.patch<DetectionRule>(`/detections/rules/${encodeURIComponent(id)}`, { enabled })
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
    headers: { 'Content-Type': 'application/json', ...CSRF_HEADERS, ...authHeaders() },
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

// ── Incidents ─────────────────────────────────────────────────────────────────

export type IncidentStatus = 'new' | 'investigating' | 'resolved'
export type IncidentResolution = '' | 'true_positive' | 'false_positive' | 'benign' | 'duplicate'
export type EntityKind = 'ip' | 'user' | 'host' | 'signature'

export interface Entity {
  kind: EntityKind
  value: string
}

export interface Incident {
  id: string
  title: string
  severity: Severity
  status: IncidentStatus
  resolution?: IncidentResolution
  assignee?: string
  entities: Entity[]
  /** ATT&CK tactics reached, in matrix order. */
  tactics: string[]
  techniques: string[]
  alert_count: number
  first_seen: string
  last_seen: string
  created_at: string
  updated_at: string
  resolved_at?: string
}

export interface IncidentAlert {
  id: number
  incident_id: string
  at: string
  severity: Severity
  attack_type: string
  summary: string
  tactic?: string
  technique_id?: string
  rules?: string[]
  hostname?: string
  raw: string
  entities: Entity[]
}

export type ActivityKind =
  | 'created' | 'status' | 'assignee' | 'severity' | 'comment' | 'escalated' | 'resolution' | 'investigation' | 'feedback' | 'response'

export interface IncidentActivity {
  id: number
  incident_id: string
  at: string
  actor: string
  kind: ActivityKind
  body: string
}

export interface IncidentDetail extends Incident {
  alerts: IncidentAlert[]
  activity: IncidentActivity[]
}

export interface IncidentStats {
  open: number
  by_status: Partial<Record<IncidentStatus, number>>
  open_by_severity: Partial<Record<Severity, number>>
  resolved: number
  false_positive: number
  mttr_seconds: number
}

export interface IncidentFilter {
  status?: IncidentStatus
  severity?: Severity
  assignee?: string
  /** "ip:1.2.3.4", "user:alice" or "host:web01" */
  entity?: string
  limit?: number
}

export interface IncidentUpdate {
  status?: IncidentStatus
  resolution?: IncidentResolution
  assignee?: string
  severity?: Severity
}

export async function listIncidents(filter: IncidentFilter = {}): Promise<Incident[]> {
  const params = Object.fromEntries(Object.entries(filter).filter(([, v]) => v !== undefined && v !== ''))
  const { data } = await client.get<Incident[]>('/incidents', { params })
  return data
}

export async function getIncident(id: string): Promise<IncidentDetail> {
  const { data } = await client.get<IncidentDetail>(`/incidents/${encodeURIComponent(id)}`)
  return data
}

export async function getIncidentStats(): Promise<IncidentStats> {
  const { data } = await client.get<IncidentStats>('/incidents/stats')
  return data
}

export async function updateIncident(id: string, update: IncidentUpdate): Promise<Incident> {
  const { data } = await client.patch<Incident>(`/incidents/${encodeURIComponent(id)}`, update)
  return data
}

export async function addIncidentComment(id: string, body: string): Promise<IncidentActivity> {
  const { data } = await client.post<IncidentActivity>(`/incidents/${encodeURIComponent(id)}/comments`, { body })
  return data
}

// apiError extracts the server's error message from a failed request.
export function apiError(err: unknown): string {
  if (axios.isAxiosError(err)) {
    const msg = (err.response?.data as { error?: string } | undefined)?.error
    if (msg) return msg
  }
  return err instanceof Error ? err.message : String(err)
}

// Starts an AI investigation of the whole incident; the write-up streams over
// the live alert socket and is saved to the incident timeline.
export async function investigateIncident(id: string): Promise<void> {
  await client.post(`/incidents/${encodeURIComponent(id)}/investigate`)
}

export async function getIncidentReport(id: string): Promise<string> {
  const { data } = await client.get<string>(`/incidents/${encodeURIComponent(id)}/report`, {
    responseType: 'text',
    transformResponse: (d) => d,
  })
  return data
}

export async function rateInvestigation(id: string, helpful: boolean, note = ''): Promise<IncidentActivity> {
  const { data } = await client.post<IncidentActivity>(`/incidents/${encodeURIComponent(id)}/feedback`, { helpful, note })
  return data
}

// ── Response ──────────────────────────────────────────────────────────────────

export type ActionStatus = 'pending' | 'dry_run' | 'running' | 'succeeded' | 'failed' | 'rejected'
export type ActionType = 'block_ip' | 'disable_user' | 'isolate_host' | 'notify' | 'webhook'
export type PlaybookMode = 'approval' | 'dry_run' | 'auto'

export interface ResponseAction {
  id: string
  incident_id: string
  playbook_id: string
  playbook_name: string
  type: ActionType
  target?: string
  message?: string
  step: number
  status: ActionStatus
  reason: string
  result?: string
  proposed_at: string
  decided_by?: string
  decided_at?: string
  executed_at?: string
}

export interface Playbook {
  id: string
  name: string
  description?: string
  mode: PlaybookMode
  enabled: boolean
  source: string
  trigger: {
    min_severity?: Severity
    tactics?: string[]
    techniques?: string[]
    attack_types?: string[]
  }
  actions: { type: ActionType; message?: string }[]
}

export async function listPlaybooks(): Promise<Playbook[]> {
  const { data } = await client.get<Playbook[]>('/playbooks')
  return data
}

export async function listActions(filter: { status?: ActionStatus; incident?: string; limit?: number } = {}): Promise<ResponseAction[]> {
  const params = Object.fromEntries(Object.entries(filter).filter(([, v]) => v !== undefined && v !== ''))
  const { data } = await client.get<ResponseAction[]>('/response/actions', { params })
  return data
}

export async function approveAction(id: string): Promise<ResponseAction> {
  const { data } = await client.post<ResponseAction>(`/response/actions/${encodeURIComponent(id)}/approve`)
  return data
}

export async function rejectAction(id: string, reason = ''): Promise<ResponseAction> {
  const { data } = await client.post<ResponseAction>(`/response/actions/${encodeURIComponent(id)}/reject`, { reason })
  return data
}

export async function runPlaybook(incidentId: string, playbookId: string): Promise<ResponseAction[]> {
  const { data } = await client.post<ResponseAction[]>(
    `/incidents/${encodeURIComponent(incidentId)}/playbooks/${encodeURIComponent(playbookId)}/run`,
  )
  return data
}

// ── Accounts ──────────────────────────────────────────────────────────────────

export type Role = 'viewer' | 'analyst' | 'admin'

export interface Me {
  username: string
  role: Role
  /** session: logged in · api_key: VITE_SIEM_API_KEY · open: no auth configured */
  auth: 'session' | 'api_key' | 'open'
  id?: string
  permissions: { read: boolean; write: boolean; admin: boolean }
}

export interface User {
  id: string
  username: string
  display_name?: string
  role: Role
  disabled: boolean
  created_at: string
  last_login_at?: string
}

export interface AuditEntry {
  id: number
  at: string
  actor: string
  action: string
  target?: string
  status?: number
  ip?: string
}

export async function getMe(): Promise<Me> {
  const { data } = await client.get<Me>('/auth/me')
  return data
}

export async function login(username: string, password: string): Promise<void> {
  await client.post('/auth/login', { username, password })
}

export async function logout(): Promise<void> {
  await client.post('/auth/logout')
}

export async function changePassword(currentPassword: string, newPassword: string): Promise<void> {
  await client.post('/auth/password', { current_password: currentPassword, new_password: newPassword })
}

export async function listUsers(): Promise<User[]> {
  const { data } = await client.get<User[]>('/users')
  return data
}

export async function createUser(u: { username: string; display_name?: string; password: string; role: Role }): Promise<User> {
  const { data } = await client.post<User>('/users', u)
  return data
}

export async function updateUser(id: string, u: { role?: Role; disabled?: boolean; password?: string; display_name?: string }): Promise<User> {
  const { data } = await client.patch<User>(`/users/${encodeURIComponent(id)}`, u)
  return data
}

export async function listAudit(filter: { actor?: string; limit?: number } = {}): Promise<AuditEntry[]> {
  const params = Object.fromEntries(Object.entries(filter).filter(([, v]) => v !== undefined && v !== ''))
  const { data } = await client.get<AuditEntry[]>('/audit', { params })
  return data
}

export type RetentionKind = 'events' | 'incidents' | 'audit' | 'sessions'

export interface RetentionRun {
  at: string
  deleted: Partial<Record<RetentionKind, number>>
  errors?: Partial<Record<RetentionKind, string>>
}

export interface RetentionStatus {
  /** false without Postgres: nothing durable to purge. */
  active: boolean
  /** 0 keeps the data forever. */
  events_days: number
  incidents_days: number
  audit_days: number
  interval_seconds?: number
  last_run: RetentionRun | null
}

export async function getRetention(): Promise<RetentionStatus> {
  const { data } = await client.get<RetentionStatus>('/retention')
  return data
}

export interface Suppression {
  id: string
  entity?: { kind: 'ip' | 'user' | 'host'; value: string }
  rule_id?: string
  attack_type?: string
  reason: string
  created_by: string
  created_at: string
  /** Absent for a suppression that lasts until it is lifted. */
  expires_at?: string
  /** Matches since the server started. */
  hits: number
  last_hit?: string
}

export interface NewSuppression {
  /** "ip:1.2.3.4", "user:alice" or "host:web01" */
  entity?: string
  rule_id?: string
  attack_type?: string
  reason: string
  /** Go duration such as "24h"; empty lasts until lifted. */
  duration?: string
  /** Records the snooze on this incident's timeline. */
  incident_id?: string
}

export async function listSuppressions(): Promise<Suppression[]> {
  const { data } = await client.get<Suppression[]>('/suppressions')
  return data
}

export async function createSuppression(req: NewSuppression): Promise<Suppression> {
  const { data } = await client.post<Suppression>('/suppressions', req)
  return data
}

export async function liftSuppression(id: string): Promise<void> {
  await client.delete(`/suppressions/${encodeURIComponent(id)}`)
}

export type IndicatorType = 'ip' | 'cidr' | 'domain' | 'hash'
export type WatchlistSource = 'manual' | 'feed' | 'file'

export interface Watchlist {
  id: string
  name: string
  description?: string
  source: WatchlistSource
  url?: string
  severity: Severity
  enabled: boolean
  refresh_seconds?: number
  created_by?: string
  created_at: string
  /** Indicators loaded right now. */
  count: number
  /** Feed or file lines that were not indicators. */
  skipped?: number
  last_fetched?: string
  /** Last download error; the previous indicators stay in use. */
  error?: string
  /** Matches since the server started. */
  hits: number
  last_hit?: string
}

export interface Indicator {
  value: string
  type: IndicatorType
  note?: string
  added_by?: string
}

export interface NewWatchlist {
  name: string
  description?: string
  source: 'manual' | 'feed'
  url?: string
  severity: Severity
  refresh_seconds?: number
}

export interface IOCLookupResult {
  watchlist_id: string
  watchlist: string
  indicator: string
  severity: Severity
}

export async function listWatchlists(): Promise<Watchlist[]> {
  const { data } = await client.get<Watchlist[]>('/watchlists')
  return data
}

export async function createWatchlist(req: NewWatchlist): Promise<Watchlist> {
  const { data } = await client.post<Watchlist>('/watchlists', req)
  return data
}

export async function updateWatchlist(id: string, u: { name?: string; enabled?: boolean; severity?: Severity }): Promise<Watchlist> {
  const { data } = await client.patch<Watchlist>(`/watchlists/${encodeURIComponent(id)}`, u)
  return data
}

export async function deleteWatchlist(id: string): Promise<void> {
  await client.delete(`/watchlists/${encodeURIComponent(id)}`)
}

export async function refreshWatchlist(id: string): Promise<Watchlist> {
  const { data } = await client.post<Watchlist>(`/watchlists/${encodeURIComponent(id)}/refresh`)
  return data
}

export async function listIndicators(id: string, limit = 200): Promise<{ total: number; indicators: Indicator[] }> {
  const { data } = await client.get<{ total: number; indicators: Indicator[] }>(`/watchlists/${encodeURIComponent(id)}/indicators`, { params: { limit } })
  return data
}

export async function addIndicators(id: string, values: string[], note?: string): Promise<{ added: Indicator[]; rejected: string[] }> {
  const { data } = await client.post<{ added: Indicator[]; rejected: string[] }>(`/watchlists/${encodeURIComponent(id)}/indicators`, { values, note })
  return data
}

export async function removeIndicator(id: string, value: string): Promise<void> {
  await client.delete(`/watchlists/${encodeURIComponent(id)}/indicators`, { params: { value } })
}

export async function lookupIOC(value: string): Promise<IOCLookupResult[]> {
  const { data } = await client.get<IOCLookupResult[]>('/ioc/lookup', { params: { value } })
  return data
}
