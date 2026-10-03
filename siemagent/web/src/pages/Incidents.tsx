import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Siren, X } from 'lucide-react'
import { getIncidentStats, listIncidents } from '../lib/api'
import type { Incident, IncidentStatus } from '../lib/api'
import { STATUS_LABELS, STATUS_STYLES } from '../lib/incidents'
import { formatDuration, timeAgo } from '../lib/time'
import { SeverityBadge } from '../components/SeverityBadge'
import { IncidentDetail } from '../components/IncidentDetail'
import { SEVERITY_BORDER } from '../styles/tokens'

type View = 'open' | IncidentStatus | 'all'

const VIEWS: { value: View; label: string }[] = [
  { value: 'open', label: 'Open' },
  { value: 'new', label: 'New' },
  { value: 'investigating', label: 'Investigating' },
  { value: 'resolved', label: 'Resolved' },
  { value: 'all', label: 'All' },
]

function StatusPill({ status }: { status: IncidentStatus }) {
  return (
    <span className={`rounded-full border px-2 py-0.5 text-[10px] font-medium ${STATUS_STYLES[status]}`}>
      {STATUS_LABELS[status]}
    </span>
  )
}

function IncidentRow({ inc, selected, onSelect }: { inc: Incident; selected: boolean; onSelect: () => void }) {
  return (
    <li>
      <button
        onClick={onSelect}
        aria-current={selected ? 'true' : undefined}
        className={`w-full text-left rounded-xl border border-l-4 ${SEVERITY_BORDER[inc.severity]} p-3 shadow-card transition-colors ${
          selected ? 'border-line bg-accent/10 ring-2 ring-accent/40' : 'border-line bg-surface hover:bg-fg/3'
        }`}
      >
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={inc.severity} size="sm" />
          <StatusPill status={inc.status} />
          <span className="ml-auto text-[11px] text-fg-subtle">{timeAgo(inc.last_seen)}</span>
        </div>
        <p className="mt-1.5 text-sm font-medium text-fg break-words">{inc.title}</p>
        <p className="mt-1 text-[11px] text-fg-muted">
          <span className="font-mono">{inc.id}</span> · {inc.alert_count} alert{inc.alert_count === 1 ? '' : 's'}
          {inc.tactics.length > 0 && <> · {inc.tactics.length} tactic{inc.tactics.length === 1 ? '' : 's'}</>}
          {inc.assignee ? <> · {inc.assignee}</> : <> · <span className="text-fg-subtle">unassigned</span></>}
        </p>
      </button>
    </li>
  )
}

export function Incidents() {
  const [view, setView] = useState<View>('open')
  const [entity, setEntity] = useState<string | null>(null)
  const [selected, setSelected] = useState<string | null>(null)

  const { data: stats } = useQuery({ queryKey: ['incident-stats'], queryFn: getIncidentStats, refetchInterval: 15_000 })
  const { data: incidents = [], isLoading, isError } = useQuery({
    queryKey: ['incidents', view, entity],
    queryFn: () => listIncidents({
      status: view === 'open' || view === 'all' ? undefined : view,
      entity: entity ?? undefined,
      limit: 200,
    }),
    refetchInterval: 10_000,
  })
  const visible = view === 'open' ? incidents.filter((i) => i.status !== 'resolved') : incidents
  const critical = (stats?.open_by_severity.P1 ?? 0) + (stats?.open_by_severity.P2 ?? 0)

  const tiles: [string, string | number, string?][] = [
    ['Open incidents', stats?.open ?? '—'],
    ['Open P1 / P2', stats ? critical : '—', critical > 0 ? 'text-danger' : undefined],
    ['Resolved', stats?.resolved ?? '—'],
    ['Mean time to resolve', stats && stats.resolved > 0 ? formatDuration(stats.mttr_seconds) : '—'],
  ]

  return (
    <div className="flex flex-1 min-h-0 overflow-hidden">
      <div className={`flex flex-col min-w-0 overflow-y-auto border-r border-line ${selected ? 'hidden lg:flex lg:w-[26rem] xl:w-[30rem]' : 'flex-1'}`}>
        <div className="p-4 sm:p-6 space-y-4">
          <header>
            <h1 className="text-lg font-semibold text-fg flex items-center gap-2">
              <Siren size={18} className="text-accent-text" aria-hidden="true" />
              Incidents
            </h1>
            <p className="mt-1 text-sm text-fg-muted">
              Alerts that share an IP, user or host are grouped into one incident you can assign, track and resolve.
            </p>
          </header>

          <dl className={`grid gap-3 ${selected ? 'grid-cols-2' : 'grid-cols-2 sm:grid-cols-4'}`}>
            {tiles.map(([label, value, tone]) => (
              <div key={label} className="rounded-xl border border-line bg-surface p-3 shadow-card">
                <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">{label}</dt>
                <dd className={`mt-1 text-xl font-semibold tabular-nums ${tone ?? 'text-fg'}`}>{value}</dd>
              </div>
            ))}
          </dl>

          <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Filter incidents by status">
            {VIEWS.map((v) => (
              <button
                key={v.value}
                aria-pressed={view === v.value}
                onClick={() => setView(v.value)}
                className={`rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors ${
                  view === v.value
                    ? 'border-accent bg-accent/15 text-accent-text'
                    : 'border-line text-fg-muted hover:text-fg hover:bg-fg/4'
                }`}
              >
                {v.label}
              </button>
            ))}
            {entity && (
              <span className="inline-flex items-center gap-1 rounded-lg border border-accent/40 bg-accent/10 px-2 py-1 font-mono text-xs text-accent-text">
                {entity}
                <button onClick={() => setEntity(null)} aria-label={`Clear filter ${entity}`} className="hover:text-fg">
                  <X size={12} />
                </button>
              </span>
            )}
          </div>

          {isLoading ? (
            <p className="text-sm text-fg-subtle">Loading incidents…</p>
          ) : isError ? (
            <p className="text-sm text-danger">Could not load incidents.</p>
          ) : visible.length === 0 ? (
            <div className="rounded-xl border border-dashed border-line-strong p-8 text-center">
              <p className="text-sm font-medium text-fg">No incidents here</p>
              <p className="mt-1 text-xs text-fg-muted">
                P1–P3 alerts open incidents automatically. Classify or upload logs to see them.
              </p>
            </div>
          ) : (
            <ul className="space-y-2" aria-label="Incidents">
              {visible.map((inc) => (
                <IncidentRow key={inc.id} inc={inc} selected={inc.id === selected} onSelect={() => setSelected(inc.id)} />
              ))}
            </ul>
          )}
        </div>
      </div>

      {selected && (
        <div className="flex-1 min-w-0 overflow-y-auto">
          <IncidentDetail
            key={selected}
            id={selected}
            onClose={() => setSelected(null)}
            onEntity={(e) => { setEntity(e); setView('all'); setSelected(null) }}
          />
        </div>
      )}
    </div>
  )
}
