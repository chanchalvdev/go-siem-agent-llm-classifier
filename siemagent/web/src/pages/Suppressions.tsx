import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { BellOff } from 'lucide-react'
import { apiError, liftSuppression, listSuppressions } from '../lib/api'
import type { Suppression } from '../lib/api'
import { timeAgo } from '../lib/time'
import { useAuth } from '../auth/auth'
import { SuppressionForm } from '../components/SuppressionForm'

function isActive(s: Suppression, now: number): boolean {
  return !s.expires_at || new Date(s.expires_at).getTime() > now
}

function matcher(s: Suppression): string {
  const parts: string[] = []
  if (s.entity) parts.push(`${s.entity.kind}:${s.entity.value}`)
  if (s.rule_id) parts.push(`rule ${s.rule_id}`)
  if (s.attack_type) parts.push(s.attack_type)
  return parts.join(' + ')
}

function until(s: Suppression, now: number): string {
  if (!s.expires_at) return 'until lifted'
  const t = new Date(s.expires_at)
  return t.getTime() > now ? `until ${t.toLocaleString()}` : `expired ${timeAgo(s.expires_at)}`
}

export function Suppressions() {
  const qc = useQueryClient()
  const writable = useAuth().can('write')
  const { data = [], isLoading, isError } = useQuery({ queryKey: ['suppressions'], queryFn: listSuppressions, refetchInterval: 15_000 })
  const lift = useMutation({
    mutationFn: liftSuppression,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['suppressions'] }),
  })

  const now = Date.now()
  const active = data.filter((s) => isActive(s, now))
  const expired = data.filter((s) => !isActive(s, now))
  const absorbed = data.reduce((n, s) => n + s.hits, 0)
  const tiles: [string, number][] = [
    ['Active', active.length],
    ['Suppressed events since start', absorbed],
    ['Expired', expired.length],
  ]

  const row = (s: Suppression) => (
    <li key={s.id} className={`flex items-start gap-3 rounded-xl border border-line bg-surface p-3 shadow-card ${isActive(s, now) ? '' : 'opacity-60'}`}>
      <div className="min-w-0 flex-1">
        <p className="break-words font-mono text-sm text-fg">{matcher(s)}</p>
        <p className="mt-1 text-xs text-fg-muted">{s.reason}</p>
        <p className="mt-1 text-[11px] text-fg-subtle">
          <span className="font-mono">{s.id}</span> · by {s.created_by} {timeAgo(s.created_at)} · {until(s, now)}
        </p>
      </div>
      <div className="flex shrink-0 flex-col items-end gap-2">
        <span className="text-[11px] tabular-nums text-fg-subtle">
          {s.hits} hit{s.hits === 1 ? '' : 's'}{s.last_hit ? ` · last ${timeAgo(s.last_hit)}` : ''}
        </span>
        {writable && (
          <button
            type="button"
            onClick={() => lift.mutate(s.id)}
            disabled={lift.isPending && lift.variables === s.id}
            aria-label={`${isActive(s, now) ? 'Lift' : 'Remove'} ${s.id}`}
            className="rounded-lg border border-line px-2.5 py-1 text-xs text-fg-muted hover:bg-fg/4 hover:text-fg disabled:opacity-40"
          >
            {isActive(s, now) ? 'Lift' : 'Remove'}
          </button>
        )}
      </div>
    </li>
  )

  return (
    <div className="flex-1 overflow-y-auto">
      <div className="mx-auto max-w-5xl space-y-5 p-4 sm:p-6">
        <header>
          <h1 className="flex items-center gap-2 text-lg font-semibold text-fg">
            <BellOff size={18} className="text-accent-text" aria-hidden="true" /> Suppressions
          </h1>
          <p className="mt-1 text-sm text-fg-muted">
            Snooze known noise, such as a scanner you run or an authorised pentest, so it stops opening incidents.
            {!writable && ' Only analysts and admins can add or lift suppressions.'}
          </p>
        </header>

        <dl className="grid grid-cols-3 gap-3">
          {tiles.map(([label, value]) => (
            <div key={label} className="rounded-xl border border-line bg-surface p-3 shadow-card">
              <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">{label}</dt>
              <dd className="mt-1 text-xl font-semibold tabular-nums text-fg">{value}</dd>
            </div>
          ))}
        </dl>

        {writable && <SuppressionForm />}

        {lift.error && (
          <p role="alert" className="rounded-lg border border-danger/30 bg-danger/10 px-3 py-2 text-xs text-danger">{apiError(lift.error)}</p>
        )}

        {isLoading ? (
          <p className="text-sm text-fg-subtle">Loading suppressions…</p>
        ) : isError ? (
          <p className="text-sm text-danger">Could not load suppressions.</p>
        ) : data.length === 0 ? (
          <p className="text-sm text-fg-subtle">Nothing is suppressed.</p>
        ) : (
          <>
            {active.length > 0 && <ul aria-label="Active suppressions" className="space-y-2">{active.map(row)}</ul>}
            {expired.length > 0 && (
              <section aria-labelledby="expired-title" className="space-y-2">
                <h2 id="expired-title" className="text-xs font-semibold uppercase tracking-wide text-fg-subtle">Expired</h2>
                <ul aria-label="Expired suppressions" className="space-y-2">{expired.map(row)}</ul>
              </section>
            )}
          </>
        )}
      </div>
    </div>
  )
}
