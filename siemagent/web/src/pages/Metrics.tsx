import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Bar, BarChart, CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { Gauge } from 'lucide-react'
import { getSOCMetrics } from '../lib/api'
import type { DurationStats, SOCMetrics } from '../lib/api'
import { formatDuration } from '../lib/time'
import { useChartColors } from '../theme/chartColors'

const WINDOWS = [7, 30, 90]
const CARD = 'rounded-xl border border-line bg-surface p-4 shadow-card'
const RESOLUTION_LABELS: Record<string, string> = {
  true_positive: 'True positive', false_positive: 'False positive', benign: 'Benign', duplicate: 'Duplicate', unspecified: 'No resolution set',
}

function dur(d: DurationStats, key: 'median_seconds' | 'mean_seconds' | 'p90_seconds' = 'median_seconds'): string {
  const v = d[key]
  return v === null ? '—' : formatDuration(v)
}

function shortDay(iso: string): string {
  const [, m, d] = iso.split('-')
  return `${Number(d)}/${Number(m)}`
}

// TimeTile shows a median with the mean and p90 underneath.
function TimeTile({ label, help, d }: { label: string; help: string; d: DurationStats }) {
  return (
    <div className={CARD}>
      <dt className="text-[11px] uppercase tracking-wide text-fg-subtle" title={help}>{label}</dt>
      <dd className="mt-1">
        <span className="text-2xl font-semibold tabular-nums text-fg">{dur(d)}</span>
        {d.samples > 0 && <span className="ml-1 text-xs text-fg-subtle">median</span>}
        <p className="mt-1 text-[11px] text-fg-muted">
          {d.samples === 0 ? 'No data in this window' : `mean ${dur(d, 'mean_seconds')} · p90 ${dur(d, 'p90_seconds')} · ${d.samples} incident${d.samples === 1 ? '' : 's'}`}
        </p>
      </dd>
    </div>
  )
}

function CountTile({ label, value, note, tone }: { label: string; value: string | number; note?: string; tone?: string }) {
  return (
    <div className={CARD}>
      <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">{label}</dt>
      <dd className="mt-1">
        <span className={`text-2xl font-semibold tabular-nums ${tone ?? 'text-fg'}`}>{value}</span>
        {note && <p className="mt-1 text-[11px] text-fg-muted">{note}</p>}
      </dd>
    </div>
  )
}

function Charts({ m }: { m: SOCMetrics }) {
  const c = useChartColors()
  const tooltip = {
    contentStyle: { background: c.tooltipBg, border: `1px solid ${c.tooltipBorder}`, borderRadius: 8, color: c.tooltipText, fontSize: 11 },
    labelStyle: { color: c.tooltipText },
  }
  const tick = { fill: c.text, fontSize: 10 }
  const data = m.daily.map((d) => ({ ...d, label: shortDay(d.day) }))
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <figure className={CARD}>
        <figcaption className="text-sm font-semibold text-fg">Alerts per day</figcaption>
        <p className="text-[11px] text-fg-muted">P1–P3 events; {m.event_totals.events.toLocaleString()} events in total, {m.event_totals.suppressed} suppressed</p>
        <div className="mt-3 h-48">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
              <CartesianGrid stroke={c.grid} vertical={false} />
              <XAxis dataKey="label" tick={tick} axisLine={{ stroke: c.axis }} tickLine={false} minTickGap={12} />
              <YAxis tick={tick} axisLine={false} tickLine={false} allowDecimals={false} />
              <Tooltip {...tooltip} cursor={{ fill: c.grid }} />
              <Bar dataKey="alerts" name="Alerts" fill={c.pair[0]} radius={[4, 4, 0, 0]} maxBarSize={18} isAnimationActive={false} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </figure>
      <figure className={CARD}>
        <figcaption className="text-sm font-semibold text-fg">Incidents opened and resolved</figcaption>
        <p className="text-[11px] text-fg-muted">{m.incidents_opened} opened, {m.incidents_resolved} resolved</p>
        <div className="mt-3 h-48">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={data} margin={{ top: 4, right: 8, bottom: 0, left: -20 }}>
              <CartesianGrid stroke={c.grid} vertical={false} />
              <XAxis dataKey="label" tick={tick} axisLine={{ stroke: c.axis }} tickLine={false} minTickGap={12} />
              <YAxis tick={tick} axisLine={false} tickLine={false} allowDecimals={false} />
              <Tooltip {...tooltip} cursor={{ stroke: c.axis }} />
              <Legend wrapperStyle={{ fontSize: 11, color: c.text }} iconType="plainline" />
              <Line type="linear" dataKey="incidents_opened" name="Opened" stroke={c.pair[0]} strokeWidth={2} dot={false} activeDot={{ r: 4 }} isAnimationActive={false} />
              <Line type="linear" dataKey="incidents_resolved" name="Resolved" stroke={c.pair[1]} strokeWidth={2} strokeDasharray="6 3" dot={false} activeDot={{ r: 4 }} isAnimationActive={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </figure>
    </div>
  )
}

function TopAttackTypes({ m }: { m: SOCMetrics }) {
  const c = useChartColors()
  const top = m.top_attack_types[0]?.count ?? 0
  return (
    <section aria-labelledby="types-title" className={CARD}>
      <h2 id="types-title" className="text-sm font-semibold text-fg">Top attack types</h2>
      <p className="text-[11px] text-fg-muted">Incidents opened in this window</p>
      {m.top_attack_types.length === 0 ? (
        <p className="mt-3 text-xs text-fg-subtle">No incidents.</p>
      ) : (
        <ul className="mt-3 space-y-2">
          {m.top_attack_types.map((t) => (
            <li key={t.name} className="text-xs">
              <div className="flex justify-between gap-2">
                <span className="truncate text-fg">{t.name}</span>
                <span className="tabular-nums text-fg-muted">{t.count}</span>
              </div>
              <div className="mt-1 h-1.5 rounded-full bg-fg/5" aria-hidden="true">
                <div className="h-1.5 rounded-full" style={{ width: `${(t.count / top) * 100}%`, background: c.pair[0] }} />
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}

function Workload({ m }: { m: SOCMetrics }) {
  return (
    <section aria-labelledby="workload-title" className={CARD}>
      <h2 id="workload-title" className="text-sm font-semibold text-fg">Analyst workload</h2>
      <p className="text-[11px] text-fg-muted">
        Open incidents now; resolved and time to resolve in this window. {m.unassigned_open} open incident{m.unassigned_open === 1 ? ' is' : 's are'} unassigned.
      </p>
      {m.workload.length === 0 ? (
        <p className="mt-3 text-xs text-fg-subtle">No incidents are assigned yet.</p>
      ) : (
        <table className="mt-3 w-full text-left text-xs">
          <caption className="sr-only">Analyst workload</caption>
          <thead className="text-[11px] uppercase tracking-wide text-fg-subtle">
            <tr>
              <th scope="col" className="py-1 font-medium">Analyst</th>
              <th scope="col" className="py-1 text-right font-medium">Open</th>
              <th scope="col" className="py-1 text-right font-medium">Resolved</th>
              <th scope="col" className="py-1 text-right font-medium">Median MTTR</th>
            </tr>
          </thead>
          <tbody>
            {m.workload.map((a) => (
              <tr key={a.name} className="border-t border-line">
                <td className="py-1.5 font-medium text-fg">{a.name}</td>
                <td className="py-1.5 text-right tabular-nums text-fg">{a.open}</td>
                <td className="py-1.5 text-right tabular-nums text-fg">{a.resolved}</td>
                <td className="py-1.5 text-right tabular-nums text-fg-muted">{dur(a.mttr)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  )
}

function Resolutions({ m }: { m: SOCMetrics }) {
  const entries = Object.entries(m.by_resolution).sort((a, b) => b[1] - a[1])
  return (
    <section aria-labelledby="res-title" className={CARD}>
      <h2 id="res-title" className="text-sm font-semibold text-fg">How incidents were resolved</h2>
      {entries.length === 0 ? (
        <p className="mt-3 text-xs text-fg-subtle">Nothing resolved in this window.</p>
      ) : (
        <dl className="mt-3 space-y-1.5 text-xs">
          {entries.map(([k, v]) => (
            <div key={k} className="flex justify-between">
              <dt className="text-fg-muted">{RESOLUTION_LABELS[k] ?? k}</dt>
              <dd className="tabular-nums text-fg">{v}</dd>
            </div>
          ))}
        </dl>
      )}
    </section>
  )
}

function DailyTable({ m }: { m: SOCMetrics }) {
  return (
    <details className={CARD}>
      <summary className="cursor-pointer text-sm font-semibold text-fg">Daily numbers</summary>
      <div className="mt-3 max-h-80 overflow-auto">
        <table className="w-full text-left text-xs">
          <caption className="sr-only">Events, alerts and incidents per day</caption>
          <thead className="sticky top-0 bg-surface text-[11px] uppercase tracking-wide text-fg-subtle">
            <tr>
              {['Day', 'Events', 'Alerts', 'Suppressed', 'Opened', 'Resolved'].map((h, i) => (
                <th key={h} scope="col" className={`py-1 font-medium ${i ? 'text-right' : ''}`}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {[...m.daily].reverse().map((d) => (
              <tr key={d.day} className="border-t border-line tabular-nums">
                <td className="py-1 text-fg">{d.day}</td>
                <td className="py-1 text-right text-fg">{d.events}</td>
                <td className="py-1 text-right text-fg">{d.alerts}</td>
                <td className="py-1 text-right text-fg-muted">{d.suppressed}</td>
                <td className="py-1 text-right text-fg">{d.incidents_opened}</td>
                <td className="py-1 text-right text-fg">{d.incidents_resolved}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </details>
  )
}

export function Metrics() {
  const [days, setDays] = useState(30)
  const { data: m, isLoading, isError } = useQuery({
    queryKey: ['soc-metrics', days],
    queryFn: () => getSOCMetrics(days),
    refetchInterval: 60_000,
  })

  return (
    <div className="flex-1 overflow-y-auto">
      <div className="mx-auto max-w-6xl space-y-5 p-4 sm:p-6">
        <header className="flex flex-wrap items-end gap-3">
          <div className="flex-1">
            <h1 className="flex items-center gap-2 text-lg font-semibold text-fg">
              <Gauge size={18} className="text-accent-text" aria-hidden="true" /> SOC metrics
            </h1>
            <p className="mt-1 text-sm text-fg-muted">How fast threats are detected, picked up and resolved, and how the work is spread.</p>
          </div>
          <div className="flex gap-1.5" role="group" aria-label="Time window">
            {WINDOWS.map((w) => (
              <button
                key={w}
                type="button"
                aria-pressed={days === w}
                onClick={() => setDays(w)}
                className={`rounded-lg border px-3 py-1.5 text-xs font-medium ${
                  days === w ? 'border-accent bg-accent/15 text-accent-text' : 'border-line text-fg-muted hover:bg-fg/4 hover:text-fg'
                }`}
              >
                {w} days
              </button>
            ))}
          </div>
        </header>

        {isLoading ? (
          <p className="text-sm text-fg-subtle">Loading metrics…</p>
        ) : isError || !m ? (
          <p className="text-sm text-danger">Could not load SOC metrics.</p>
        ) : (
          <>
            <dl className="grid grid-cols-1 gap-3 sm:grid-cols-3">
              <TimeTile label="Time to detect (MTTD)" help="From the log time of the alert that opened an incident to the incident opening" d={m.mttd} />
              <TimeTile label="Time to acknowledge (MTTA)" help="From an incident opening to an analyst assigning it or changing its status" d={m.mtta} />
              <TimeTile label="Time to resolve (MTTR)" help="From an incident opening to it being resolved" d={m.mttr} />
            </dl>
            <dl className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <CountTile label="Open now" value={m.open_now} note={`${m.unassigned_open} unassigned`} />
              <CountTile label="Open over 24 h" value={m.open_over_24h} tone={m.open_over_24h > 0 ? 'text-warning' : undefined} note="Backlog ageing" />
              <CountTile label="Opened / resolved" value={`${m.incidents_opened} / ${m.incidents_resolved}`} note={`in ${m.days} days`} />
              <CountTile
                label="False-positive rate"
                value={m.false_positive_rate === null ? '—' : `${Math.round(m.false_positive_rate * 100)}%`}
                note="of incidents resolved"
              />
            </dl>
            <Charts m={m} />
            <div className="grid gap-4 lg:grid-cols-3">
              <TopAttackTypes m={m} />
              <Workload m={m} />
              <Resolutions m={m} />
            </div>
            <DailyTable m={m} />
          </>
        )}
      </div>
    </div>
  )
}
