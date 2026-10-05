import { useQuery } from '@tanstack/react-query'
import { Archive } from 'lucide-react'
import { getRetention } from '../lib/api'
import type { RetentionStatus } from '../lib/api'
import { timeAgo } from '../lib/time'

function keep(days: number): string {
  if (days <= 0) return 'Forever'
  if (days % 365 === 0) return `${days / 365} year${days === 365 ? '' : 's'}`
  return `${days} day${days === 1 ? '' : 's'}`
}

function lastRunText(s: RetentionStatus): string {
  const run = s.last_run
  if (!run) return 'Not run yet.'
  const d = run.deleted
  const removed = (d.events ?? 0) + (d.incidents ?? 0) + (d.audit ?? 0)
  return `Last run ${timeAgo(run.at)}: removed ${removed} record${removed === 1 ? '' : 's'} and ${d.sessions ?? 0} expired session${d.sessions === 1 ? '' : 's'}.`
}

// RetentionPanel shows how long the platform keeps data, set with the
// RETENTION_*_DAYS environment variables.
export function RetentionPanel() {
  const { data, isError } = useQuery({ queryKey: ['retention'], queryFn: getRetention, refetchInterval: 60_000 })
  if (isError) return null
  const errors = Object.entries(data?.last_run?.errors ?? {})

  return (
    <section aria-labelledby="retention-title" className="rounded-xl border border-line bg-surface p-4 shadow-card">
      <h2 id="retention-title" className="flex items-center gap-2 text-sm font-semibold text-fg">
        <Archive size={15} className="text-accent-text" aria-hidden="true" /> Data retention
      </h2>
      {!data ? (
        <p className="mt-2 text-xs text-fg-subtle">Loading…</p>
      ) : !data.active ? (
        <p className="mt-2 text-xs text-fg-muted">
          Data is kept in memory and cleared on restart. Set <code className="font-mono">POSTGRES_DSN</code> to keep it,
          and <code className="font-mono">RETENTION_*_DAYS</code> to limit how long.
        </p>
      ) : (
        <>
          <dl className="mt-3 grid grid-cols-3 gap-3 text-xs">
            {[
              ['Events', data.events_days],
              ['Resolved incidents', data.incidents_days],
              ['Audit log', data.audit_days],
            ].map(([label, days]) => (
              <div key={label}>
                <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">{label}</dt>
                <dd className="mt-0.5 font-medium text-fg">{keep(Number(days))}</dd>
              </div>
            ))}
          </dl>
          <p className="mt-3 text-xs text-fg-muted">{lastRunText(data)}</p>
          {errors.length > 0 && (
            <p role="alert" className="mt-2 rounded-lg border border-danger/30 bg-danger/10 px-2.5 py-1.5 text-xs text-danger">
              Purge failed for {errors.map(([k]) => k).join(', ')}. Check the server log.
            </p>
          )}
        </>
      )}
    </section>
  )
}
