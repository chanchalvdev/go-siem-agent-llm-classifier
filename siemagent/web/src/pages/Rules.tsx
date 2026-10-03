import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Search, ShieldCheck, Timer } from 'lucide-react'
import { listDetectionRules, setDetectionRuleEnabled } from '../lib/api'
import type { DetectionRule } from '../lib/api'
import { LEVEL_STYLES } from '../lib/levels'

const RULES_KEY = ['detection-rules']

type TypeFilter = 'all' | 'single' | 'threshold' | 'disabled'

const FILTERS: { value: TypeFilter; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'threshold', label: 'Threshold' },
  { value: 'single', label: 'Single event' },
  { value: 'disabled', label: 'Disabled' },
]

function matchesFilter(r: DetectionRule, filter: TypeFilter, query: string): boolean {
  if (filter === 'disabled' && r.enabled) return false
  if ((filter === 'single' || filter === 'threshold') && r.type !== filter) return false
  if (!query) return true
  const q = query.toLowerCase()
  return (
    r.title.toLowerCase().includes(q) ||
    r.id.toLowerCase().includes(q) ||
    (r.tags ?? []).some((t) => t.includes(q))
  )
}

// Toggle is an accessible on/off switch.
function Toggle({ checked, label, disabled, onChange }: {
  checked: boolean
  label: string
  disabled?: boolean
  onChange: (next: boolean) => void
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={`relative inline-flex h-5 w-9 shrink-0 items-center rounded-full border transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/40 disabled:opacity-50 ${
        checked ? 'bg-accent border-accent' : 'bg-surface-2 border-line-strong'
      }`}
    >
      <span
        className={`inline-block h-3.5 w-3.5 rounded-full bg-surface shadow-card transition-transform ${
          checked ? 'translate-x-[18px]' : 'translate-x-[2px]'
        }`}
      />
    </button>
  )
}

export function Rules() {
  const qc = useQueryClient()
  const [filter, setFilter] = useState<TypeFilter>('all')
  const [query, setQuery] = useState('')
  const { data: rules = [], isLoading, isError } = useQuery({
    queryKey: RULES_KEY,
    queryFn: listDetectionRules,
    refetchInterval: 15_000, // hit counts move as events arrive
  })

  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => setDetectionRuleEnabled(id, enabled),
    onSuccess: (updated) => {
      qc.setQueryData<DetectionRule[]>(RULES_KEY, (prev = []) => prev.map((r) => (r.id === updated.id ? updated : r)))
    },
  })

  const visible = useMemo(() => rules.filter((r) => matchesFilter(r, filter, query.trim())), [rules, filter, query])
  const enabledCount = rules.filter((r) => r.enabled).length
  const thresholdCount = rules.filter((r) => r.type === 'threshold').length
  const totalHits = rules.reduce((n, r) => n + r.hits, 0)

  return (
    <div className="flex-1 overflow-y-auto">
      <div className="mx-auto max-w-5xl p-4 sm:p-6 space-y-5">
        <header>
          <h1 className="text-lg font-semibold text-fg flex items-center gap-2">
            <ShieldCheck size={18} className="text-accent-text" aria-hidden="true" />
            Detection rules
          </h1>
          <p className="mt-1 text-sm text-fg-muted">
            Sigma rules evaluated on every event. Turning a rule off takes effect immediately and is saved.
          </p>
        </header>

        <dl className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            ['Rules', rules.length],
            ['Enabled', enabledCount],
            ['Threshold rules', thresholdCount],
            ['Hits since start', totalHits],
          ].map(([label, value]) => (
            <div key={label} className="rounded-xl border border-line bg-surface p-3 shadow-card">
              <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">{label}</dt>
              <dd className="mt-1 text-xl font-semibold text-fg tabular-nums">{value}</dd>
            </div>
          ))}
        </dl>

        <div className="flex flex-col sm:flex-row gap-3 sm:items-center">
          <div className="flex flex-wrap gap-1.5" role="group" aria-label="Filter rules">
            {FILTERS.map((f) => (
              <button
                key={f.value}
                type="button"
                aria-pressed={filter === f.value}
                onClick={() => setFilter(f.value)}
                className={`rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors ${
                  filter === f.value
                    ? 'border-accent bg-accent/15 text-accent-text'
                    : 'border-line text-fg-muted hover:text-fg hover:bg-fg/4'
                }`}
              >
                {f.label}
              </button>
            ))}
          </div>
          <label className="relative sm:ml-auto sm:w-64">
            <span className="sr-only">Search rules</span>
            <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-fg-subtle" aria-hidden="true" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search title, id or tag"
              className="w-full rounded-lg border border-line-strong bg-surface-2 py-1.5 pl-8 pr-3 text-sm text-fg placeholder-fg-subtle focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/20"
            />
          </label>
        </div>

        {toggle.isError && (
          <p role="alert" className="rounded-lg border border-danger/30 bg-danger/10 px-3 py-2 text-xs text-danger">
            Could not update the rule. Check the server is reachable and try again.
          </p>
        )}

        {isLoading ? (
          <p className="text-sm text-fg-subtle">Loading rules…</p>
        ) : isError ? (
          <p className="text-sm text-danger">Could not load detection rules.</p>
        ) : visible.length === 0 ? (
          <p className="text-sm text-fg-subtle">No rules match.</p>
        ) : (
          <ul className="space-y-2" aria-label="Detection rules">
            {visible.map((r) => (
              <li
                key={r.id}
                className={`rounded-xl border border-line bg-surface p-3 shadow-card flex items-start gap-3 ${r.enabled ? '' : 'opacity-60'}`}
              >
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-sm font-medium text-fg">{r.title}</span>
                    <span className={`rounded border px-1.5 py-0.5 font-mono text-[10px] font-semibold uppercase ${LEVEL_STYLES[r.level] ?? LEVEL_STYLES.medium}`}>
                      {r.level}
                    </span>
                    {r.type === 'threshold' && (
                      <span className="inline-flex items-center gap-1 rounded-full border border-info/30 bg-info/10 px-1.5 py-0.5 text-[10px] font-medium text-info">
                        <Timer size={10} aria-hidden="true" /> Threshold
                      </span>
                    )}
                  </div>
                  {r.description && <p className="mt-1 text-xs text-fg-muted">{r.description}</p>}
                  {r.threshold && <p className="mt-1 font-mono text-[11px] text-fg-muted">{r.threshold}</p>}
                  <p className="mt-1 truncate font-mono text-[10px] text-fg-subtle" title={r.id}>
                    {r.id} · {r.source}
                  </p>
                </div>
                <div className="flex flex-col items-end gap-2 shrink-0">
                  <Toggle
                    checked={r.enabled}
                    label={`${r.enabled ? 'Disable' : 'Enable'} ${r.title}`}
                    disabled={toggle.isPending && toggle.variables?.id === r.id}
                    onChange={(enabled) => toggle.mutate({ id: r.id, enabled })}
                  />
                  <span className="text-[11px] text-fg-subtle tabular-nums">{r.hits} hits</span>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  )
}
