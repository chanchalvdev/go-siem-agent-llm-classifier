import { useState, useRef } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Shield, ShieldCheck, AlertTriangle, RefreshCw, Menu, X, BarChart2, Activity, ChevronDown, BookOpen, Siren, Workflow, Users as UsersIcon, ScrollText, LogOut, BellOff, Radar, Gauge } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { classifyLog, listEvents } from '../lib/api'
import type { ClassifiedEvent } from '../lib/api'
import type { Severity } from '../styles/tokens'
import { EventCard } from '../components/EventCard'
import { SeverityBadge } from '../components/SeverityBadge'
import { MITREBadge } from '../components/MITREBadge'
import { IOCList } from '../components/IOCList'
import { DropZone } from '../components/DropZone'
import { SimilarEvents } from '../components/SimilarEvents'
import { AnalyticsPanel } from '../components/AnalyticsPanel'
import { MITREHeatmap } from '../components/MITREHeatmap'
import { Docs } from './Docs'
import { Rules } from './Rules'
import { Incidents } from './Incidents'
import { Response } from './Response'
import { Users } from './Users'
import { Audit } from './Audit'
import { Suppressions } from './Suppressions'
import { Watchlists } from './Watchlists'
import { Metrics } from './Metrics'
import { useAuth } from '../auth/auth'
import { ThemeToggle } from '../components/ThemeToggle'
import { DetectionList } from '../components/DetectionList'

const ALL_SEVERITIES: Severity[] = ['P1', 'P2', 'P3', 'P4', 'P5']
const EVENTS_KEY = 'classified-events'

function useEventStore() {
  const qc = useQueryClient()
  const { data: events = [] } = useQuery<ClassifiedEvent[]>({
    queryKey: [EVENTS_KEY],
    // Load stored history once; new classifications are prepended locally.
    queryFn: () => listEvents(100),
    staleTime: Infinity,
  })
  function addEvent(ev: ClassifiedEvent) {
    qc.setQueryData<ClassifiedEvent[]>([EVENTS_KEY], (prev = []) => [ev, ...prev])
    qc.invalidateQueries({ queryKey: ['analytics'] })
  }
  function addEvents(evs: ClassifiedEvent[]) {
    qc.setQueryData<ClassifiedEvent[]>([EVENTS_KEY], (prev = []) => [...[...evs].reverse(), ...prev])
    qc.invalidateQueries({ queryKey: ['analytics'] })
  }
  function clear() {
    qc.setQueryData<ClassifiedEvent[]>([EVENTS_KEY], [])
  }
  return { events, addEvent, addEvents, clear }
}

type Tab = 'events' | 'incidents' | 'response' | 'analytics' | 'metrics' | 'rules' | 'watchlists' | 'suppressions' | 'users' | 'audit' | 'docs'

const NAV: { tab: Tab; label: string; Icon: LucideIcon; admin?: boolean }[] = [
  { tab: 'events', label: 'Events', Icon: AlertTriangle },
  { tab: 'incidents', label: 'Incidents', Icon: Siren },
  { tab: 'response', label: 'Response', Icon: Workflow },
  { tab: 'analytics', label: 'Analytics', Icon: BarChart2 },
  { tab: 'metrics', label: 'SOC metrics', Icon: Gauge },
  { tab: 'rules', label: 'Rules', Icon: ShieldCheck },
  { tab: 'watchlists', label: 'Watchlists', Icon: Radar },
  { tab: 'suppressions', label: 'Suppressions', Icon: BellOff },
  { tab: 'users', label: 'Users', Icon: UsersIcon, admin: true },
  { tab: 'audit', label: 'Audit', Icon: ScrollText, admin: true },
  { tab: 'docs', label: 'Docs', Icon: BookOpen },
]

// Full-page tabs replace the events/analytics split view.
const PAGE_TABS: Partial<Record<Tab, () => React.ReactElement>> = {
  incidents: Incidents,
  response: Response,
  rules: Rules,
  watchlists: Watchlists,
  metrics: Metrics,
  suppressions: Suppressions,
  users: Users,
  audit: Audit,
  docs: Docs,
}

export function Dashboard() {
  const { events, addEvent, addEvents, clear } = useEventStore()
  const [selected, setSelected] = useState<ClassifiedEvent | null>(null)
  const [logInput, setLogInput] = useState('')
  const [classifying, setClassifying] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [severityFilter, setSeverityFilter] = useState<Set<Severity>>(new Set(ALL_SEVERITIES))
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [detailOpen, setDetailOpen] = useState(false)
  const [activeTab, setActiveTab] = useState<Tab>('events')
  const inputRef = useRef<HTMLInputElement>(null)

  const { me, can, signOut } = useAuth()
  const nav = NAV.filter((n) => !n.admin || can('admin'))
  const Page = PAGE_TABS[activeTab]
  const filtered = events.filter((e) => severityFilter.has(e.severity as Severity))

  const severityCounts = ALL_SEVERITIES.reduce((acc, s) => {
    acc[s] = events.filter(e => e.severity === s).length
    return acc
  }, {} as Record<Severity, number>)

  async function handleClassify(e: React.FormEvent) {
    e.preventDefault()
    if (!logInput.trim() || classifying) return
    setError(null)
    setClassifying(true)
    try {
      const ev = await classifyLog(logInput.trim())
      addEvent(ev)
      setSelected(ev)
      setDetailOpen(true)
      setLogInput('')
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      setError(msg)
    } finally {
      setClassifying(false)
    }
  }

  function toggleSeverity(s: Severity) {
    setSeverityFilter((prev) => {
      const next = new Set(prev)
      if (next.has(s)) next.delete(s)
      else next.add(s)
      return next
    })
  }

  function handleSelectEvent(ev: ClassifiedEvent) {
    setSelected(ev === selected ? null : ev)
    setDetailOpen(ev !== selected)
  }

  return (
    <div className="flex h-screen bg-canvas text-fg overflow-hidden">

      {/* ── Sidebar overlay (mobile) ── */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 z-40 bg-overlay/50 backdrop-blur-sm lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* ── Sidebar ── */}
      <aside className={`
        fixed top-0 left-0 h-full z-50 w-64 bg-surface border-r border-line
        flex flex-col transition-transform duration-300 ease-in-out
        lg:static lg:translate-x-0 lg:z-auto
        ${sidebarOpen ? 'translate-x-0' : '-translate-x-full'}
      `}>
        {/* Logo */}
        <div className="px-5 py-5 border-b border-line flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-accent flex items-center justify-center shrink-0">
              <Shield size={16} className="text-on-accent" />
            </div>
            <div>
              <p className="font-semibold text-fg text-sm leading-tight">SIEMAgent</p>
              <p className="text-[10px] text-fg-subtle leading-tight">AI Security Classifier</p>
            </div>
          </div>
          <button onClick={() => setSidebarOpen(false)} className="lg:hidden text-fg-subtle hover:text-fg-muted">
            <X size={18} />
          </button>
        </div>

        {/* Nav */}
        <nav className="px-3 py-4 space-y-1">
          {nav.map(({ tab, label, Icon }) => (
            <button
              key={tab}
              onClick={() => { setActiveTab(tab); setSidebarOpen(false) }}
              aria-current={activeTab === tab ? 'page' : undefined}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-colors ${
                activeTab === tab
                  ? 'bg-accent/15 text-accent-text font-medium'
                  : 'text-fg-muted hover:text-fg hover:bg-fg/4'
              }`}
            >
              <Icon size={16} />
              {label}
              {tab === 'events' && events.length > 0 && (
                <span className="ml-auto text-xs bg-accent/15 text-accent-text px-1.5 py-0.5 rounded-full">
                  {events.length}
                </span>
              )}
            </button>
          ))}
        </nav>

        {/* Signed-in user */}
        <div className="mx-3 mb-3 rounded-lg border border-line px-3 py-2 text-xs">
          {me.auth === 'open' ? (
            <p className="text-warning" title="Set SIEM_ADMIN_USER and SIEM_ADMIN_PASSWORD to require logins">
              Open access: no login configured
            </p>
          ) : (
            <div className="flex items-center gap-2">
              <div className="min-w-0 flex-1">
                <p className="truncate font-medium text-fg">{me.username}</p>
                <p className="text-fg-subtle">{me.role}{me.auth === 'api_key' ? ' · API key' : ''}</p>
              </div>
              {me.auth === 'session' && (
                <button onClick={signOut} aria-label="Sign out" title="Sign out" className="rounded-md p-1.5 text-fg-subtle hover:bg-fg/4 hover:text-fg">
                  <LogOut size={14} />
                </button>
              )}
            </div>
          )}
        </div>

        {/* Theme (header has it on md+; small screens reach it here) */}
        <div className="px-4 pb-3 md:hidden">
          <p className="text-[10px] text-fg-subtle uppercase tracking-widest mb-2">Theme</p>
          <ThemeToggle />
        </div>

        {/* Severity filter */}
        <div className="px-4 py-4 border-t border-line mt-auto">
          <p className="text-[10px] text-fg-subtle uppercase tracking-widest mb-3">Filter by Severity</p>
          <div className="space-y-2">
            {ALL_SEVERITIES.map((s) => (
              <label key={s} className="flex items-center gap-2 cursor-pointer group">
                <div className={`w-4 h-4 rounded border flex items-center justify-center transition-colors ${
                  severityFilter.has(s)
                    ? 'bg-accent border-accent'
                    : 'border-line-strong bg-transparent'
                }`} onClick={() => toggleSeverity(s)}>
                  {severityFilter.has(s) && (
                    <svg width="10" height="8" viewBox="0 0 10 8" fill="none">
                      <path d="M1 4L3.5 6.5L9 1" stroke="currentColor" className="text-on-accent" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
                    </svg>
                  )}
                </div>
                <SeverityBadge severity={s} size="sm" />
                <span className="ml-auto text-xs text-fg-subtle">{severityCounts[s] || 0}</span>
              </label>
            ))}
          </div>
          {events.length > 0 && (
            <button
              onClick={clear}
              className="mt-4 w-full text-xs text-fg-subtle hover:text-danger flex items-center justify-center gap-1.5 py-1.5 rounded border border-line hover:border-danger/30 transition-colors"
            >
              <RefreshCw size={11} /> Clear all ({events.length})
            </button>
          )}
        </div>
      </aside>

      {/* ── Main content ── */}
      <div className="flex flex-col flex-1 min-w-0 overflow-hidden">

        {/* ── Top navbar ── */}
        <header className="shrink-0 bg-surface/80 backdrop-blur border-b border-line px-4 py-3">
          <div className="flex items-center gap-3">
            <button
              onClick={() => setSidebarOpen(true)}
              aria-label="Open navigation"
              className="lg:hidden text-fg-muted hover:text-fg p-1"
            >
              <Menu size={20} />
            </button>

            <div className="flex-1 flex items-center gap-2 min-w-0">
              {!can('write') && (
                <p className="flex-1 text-xs text-fg-subtle">Read-only access: viewers can't classify or upload logs.</p>
              )}
              {can('write') && <DropZone onResults={addEvents} />}
              {can('write') && <form onSubmit={handleClassify} className="flex-1 flex gap-2 min-w-0">
                <input
                  ref={inputRef}
                  value={logInput}
                  onChange={(e) => setLogInput(e.target.value)}
                  placeholder="Paste a log line and press Enter to classify…"
                  aria-label="Log line to classify"
                  className="flex-1 min-w-0 bg-surface-2 border border-line-strong rounded-lg px-3 py-2 text-sm text-fg placeholder-fg-subtle focus:outline-none focus:border-accent focus:ring-2 focus:ring-accent/20 transition-colors"
                />
                <button
                  type="submit"
                  disabled={classifying || !logInput.trim()}
                  className="shrink-0 px-4 py-2 rounded-lg bg-accent text-on-accent hover:bg-accent-strong shadow-card disabled:opacity-40 disabled:cursor-not-allowed text-sm font-medium transition-colors flex items-center gap-2"
                >
                  {classifying ? (
                    <>
                      <Activity size={14} className="animate-pulse" />
                      <span className="hidden sm:inline">Classifying…</span>
                    </>
                  ) : (
                    <>
                      <Shield size={14} />
                      <span className="hidden sm:inline">Classify</span>
                    </>
                  )}
                </button>
              </form>}
            </div>

            <div className="shrink-0 hidden md:block">
              <ThemeToggle compact />
            </div>
          </div>

          {error && (
            <div className="mt-2 text-xs text-danger bg-danger/10 border border-danger/30 rounded-lg px-3 py-2 flex items-center gap-2">
              <AlertTriangle size={12} />
              {error}
            </div>
          )}
        </header>

        {/* ── Mobile tab bar ── */}
        <div className="lg:hidden flex border-b border-line bg-surface/60 shrink-0">
          {nav.map(({ tab }) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`flex-1 py-2.5 text-xs font-medium capitalize transition-colors ${
                activeTab === tab
                  ? 'text-accent-text border-b-2 border-accent'
                  : 'text-fg-subtle hover:text-fg-muted'
              }`}
            >
              {tab}
            </button>
          ))}
        </div>

        {/* ── Body ── */}
        {Page ? (
          <Page />
        ) : (
        <div className="flex flex-1 min-h-0 overflow-hidden">

          {/* Events list */}
          <div className={`
            flex flex-col flex-1 min-w-0 overflow-hidden
            ${activeTab !== 'events' ? 'hidden lg:flex' : 'flex'}
          `}>
            {/* Stats bar */}
            {events.length > 0 && (
              <div className="shrink-0 flex items-center gap-3 px-4 py-2 border-b border-line bg-surface/40 overflow-x-auto">
                <span className="text-xs text-fg-subtle shrink-0">{filtered.length} events</span>
                <div className="flex items-center gap-2">
                  {ALL_SEVERITIES.filter(s => severityCounts[s] > 0).map(s => (
                    <div key={s} className="flex items-center gap-1 shrink-0">
                      <SeverityBadge severity={s} size="sm" />
                      <span className="text-xs text-fg-subtle">{severityCounts[s]}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Event cards */}
            <div className="flex-1 overflow-y-auto px-3 py-3 space-y-2">
              {filtered.length === 0 ? (
                <div className="flex flex-col items-center justify-center h-full text-center py-20 px-6">
                  <div className="w-16 h-16 rounded-2xl bg-fg/4 flex items-center justify-center mb-4">
                    <Shield size={28} className="text-fg-subtle" />
                  </div>
                  <p className="text-sm text-fg-muted font-medium">No events yet</p>
                  <p className="text-xs text-fg-subtle mt-1 max-w-xs">
                    Paste a log line in the input above or upload a .log file to start classifying
                  </p>
                </div>
              ) : (
                filtered.map((ev, i) => (
                  <EventCard
                    key={`${ev.processed_at}-${i}`}
                    event={ev}
                    onClick={() => handleSelectEvent(ev)}
                    selected={ev === selected}
                  />
                ))
              )}
            </div>
          </div>

          {/* Analytics tab (mobile) / always visible on desktop */}
          <div className={`
            ${activeTab !== 'analytics' ? 'hidden lg:block' : 'flex flex-col flex-1'}
            lg:w-80 lg:shrink-0 lg:border-l lg:border-line lg:overflow-y-auto
            ${selected ? 'lg:hidden xl:block' : ''}
          `}>
            <AnalyticsPanel />
            <div className="p-3">
              <h3 className="mb-2 text-xs uppercase tracking-wide text-fg-subtle">MITRE ATT&CK Heatmap</h3>
              <MITREHeatmap events={events} />
            </div>
          </div>

          {/* Detail panel — slides in on mobile, static on desktop */}
          {selected && (
            <>
              {/* Mobile overlay */}
              <div
                className="fixed inset-0 z-30 bg-overlay/50 backdrop-blur-sm xl:hidden"
                onClick={() => { setSelected(null); setDetailOpen(false) }}
              />
              <div className={`
                fixed bottom-0 left-0 right-0 z-40 max-h-[85vh] overflow-y-auto
                bg-surface border-t border-line-strong rounded-t-2xl
                xl:static xl:max-h-none xl:rounded-none xl:border-t-0 xl:border-l xl:border-line
                xl:w-96 xl:shrink-0 xl:overflow-y-auto
                ${detailOpen ? 'translate-y-0' : 'translate-y-full'}
                transition-transform duration-300 xl:translate-y-0
              `}>
                {/* Mobile drag handle */}
                <div className="xl:hidden flex justify-center pt-3 pb-1">
                  <div className="w-10 h-1 rounded-full bg-fg/20" />
                </div>

                <DetailPanel
                  event={selected}
                  onClose={() => { setSelected(null); setDetailOpen(false) }}
                />
              </div>
            </>
          )}
        </div>
        )}
      </div>
    </div>
  )
}

function DetailPanel({ event, onClose }: { event: ClassifiedEvent; onClose: () => void }) {
  const [remOpen, setRemOpen] = useState(true)
  const sev = event.severity as Severity
  const confidence = Math.round((event.confidence ?? 0) * 100)

  return (
    <div className="p-4 space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-2 flex-wrap">
          <SeverityBadge severity={sev} size="md" />
        </div>
        <button
          onClick={onClose}
          className="shrink-0 p-1.5 rounded-lg text-fg-subtle hover:text-fg hover:bg-fg/10 transition-colors"
        >
          <X size={16} />
        </button>
      </div>

      {/* Title + summary */}
      <div>
        <h2 className="text-base font-semibold text-fg leading-snug">{event.attack_type}</h2>
        <p className="text-sm text-fg-muted mt-1.5 leading-relaxed">{event.summary}</p>
      </div>

      {/* Confidence */}
      <div>
        <div className="flex items-center justify-between mb-1.5">
          <p className="text-[10px] text-fg-subtle uppercase tracking-widest">Confidence</p>
          <span className="text-xs font-mono text-fg-muted">{confidence}%</span>
        </div>
        <div className="h-1.5 bg-fg/10 rounded-full overflow-hidden">
          <div
            className="h-full rounded-full transition-all"
            style={{
              width: `${confidence}%`,
              background: confidence >= 80 ? 'rgb(var(--accent))' : confidence >= 60 ? 'rgb(var(--warning))' : 'rgb(var(--fg-subtle))'
            }}
          />
        </div>
      </div>

      {/* Detection rules */}
      {event.detections && event.detections.length > 0 && (
        <div>
          <p className="text-[10px] text-fg-subtle uppercase tracking-widest mb-2">
            Detection rules{event.classified_by === 'rules' ? ' · classified without AI' : ''}
          </p>
          <DetectionList detections={event.detections} />
        </div>
      )}

      {/* MITRE */}
      {event.mitre && event.mitre.tactic !== 'N/A' && (
        <div>
          <p className="text-[10px] text-fg-subtle uppercase tracking-widest mb-2">MITRE ATT&CK</p>
          <div className="bg-fg/4 rounded-xl p-3 space-y-2 border border-line">
            <div className="flex items-center justify-between gap-2 flex-wrap">
              <span className="text-xs text-fg-muted">{event.mitre.tactic}</span>
              <MITREBadge tactic="" technique={event.mitre.technique_id} />
            </div>
            {event.mitre.technique && (
              <p className="text-xs text-fg-subtle">{event.mitre.technique}</p>
            )}
          </div>
        </div>
      )}

      {/* IOCs */}
      {event.iocs?.length > 0 && (
        <div>
          <p className="text-[10px] text-fg-subtle uppercase tracking-widest mb-2">Indicators of Compromise</p>
          <IOCList iocs={event.iocs} />
        </div>
      )}

      {/* Remediation collapsible */}
      {event.remediation && (
        <div className="border border-line rounded-xl overflow-hidden">
          <button
            onClick={() => setRemOpen(o => !o)}
            className="w-full flex items-center justify-between px-3 py-2.5 text-left bg-fg/4 hover:bg-fg/8 transition-colors"
          >
            <p className="text-[10px] text-fg-subtle uppercase tracking-widest">Recommended Action</p>
            <ChevronDown size={14} className={`text-fg-subtle transition-transform ${remOpen ? 'rotate-180' : ''}`} />
          </button>
          {remOpen && (
            <div className="px-3 py-3">
              <p className="text-xs text-fg-muted leading-relaxed">{event.remediation}</p>
            </div>
          )}
        </div>
      )}

      {/* Raw log */}
      <div>
        <p className="text-[10px] text-fg-subtle uppercase tracking-widest mb-2">Raw Log</p>
        <pre className="text-xs font-mono text-fg-muted bg-surface-2 rounded-xl p-3 overflow-x-auto whitespace-pre-wrap break-all border border-line">
          {event.event.raw}
        </pre>
      </div>

      {/* Meta */}
      <div className="flex flex-wrap gap-2 text-[10px] text-fg-subtle">
        <span className="bg-fg/4 rounded px-2 py-1">Source: {event.event.source}</span>
        {event.event.hostname && <span className="bg-fg/4 rounded px-2 py-1">{event.event.hostname}</span>}
        {event.event.app_name && <span className="bg-fg/4 rounded px-2 py-1">{event.event.app_name}</span>}
      </div>

      {/* Similar events */}
      {event.summary && (
        <div className="border-t border-line pt-4">
          <SimilarEvents summary={event.summary} />
        </div>
      )}
    </div>
  )
}
