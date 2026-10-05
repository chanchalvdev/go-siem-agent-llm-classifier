import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ScrollText } from 'lucide-react'
import { listAudit } from '../lib/api'
import { RetentionPanel } from '../components/RetentionPanel'

function statusTone(status?: number): string {
  if (!status) return 'text-fg-subtle'
  if (status >= 500) return 'text-danger'
  if (status >= 400) return 'text-warning'
  return 'text-success'
}

export function Audit() {
  const [actor, setActor] = useState('')
  const audit = useQuery({
    queryKey: ['audit', actor],
    queryFn: () => listAudit({ actor: actor.trim() || undefined, limit: 300 }),
    refetchInterval: 15_000,
  })
  return (
    <div className="flex-1 overflow-y-auto">
      <div className="mx-auto max-w-6xl space-y-4 p-4 sm:p-6">
        <header className="flex flex-wrap items-end gap-3">
          <div className="flex-1">
            <h1 className="flex items-center gap-2 text-lg font-semibold text-fg">
              <ScrollText size={18} className="text-accent-text" aria-hidden="true" /> Audit log
            </h1>
            <p className="mt-1 text-sm text-fg-muted">Every login and every change made through the API, newest first.</p>
          </div>
          <label className="flex flex-col gap-1 text-xs text-fg-muted">
            Filter by user
            <input
              value={actor}
              onChange={(e) => setActor(e.target.value)}
              placeholder="username"
              className="rounded-lg border border-line-strong bg-surface-2 px-2.5 py-1.5 text-sm text-fg focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/20"
            />
          </label>
        </header>
        <RetentionPanel />
        <div className="overflow-x-auto rounded-xl border border-line bg-surface shadow-card">
          <table className="w-full text-left text-xs">
            <caption className="sr-only">Audit log entries</caption>
            <thead className="border-b border-line text-[11px] uppercase tracking-wide text-fg-subtle">
              <tr>
                <th scope="col" className="px-3 py-2 font-medium">Time</th>
                <th scope="col" className="px-3 py-2 font-medium">User</th>
                <th scope="col" className="px-3 py-2 font-medium">Action</th>
                <th scope="col" className="px-3 py-2 font-medium">Target</th>
                <th scope="col" className="px-3 py-2 font-medium">Result</th>
                <th scope="col" className="px-3 py-2 font-medium">IP</th>
              </tr>
            </thead>
            <tbody>
              {(audit.data ?? []).map((e) => (
                <tr key={e.id} className="border-b border-line last:border-0">
                  <td className="whitespace-nowrap px-3 py-2 text-fg-muted"><time dateTime={e.at}>{new Date(e.at).toLocaleString()}</time></td>
                  <td className="px-3 py-2 font-medium text-fg">{e.actor}</td>
                  <td className="px-3 py-2 font-mono text-fg">{e.action}</td>
                  <td className="max-w-xs truncate px-3 py-2 font-mono text-fg-muted" title={e.target}>{e.target}</td>
                  <td className={`px-3 py-2 font-mono ${statusTone(e.status)}`}>{e.status || '—'}</td>
                  <td className="px-3 py-2 font-mono text-fg-subtle">{e.ip}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {audit.data?.length === 0 && <p className="p-4 text-sm text-fg-subtle">No entries.</p>}
        </div>
      </div>
    </div>
  )
}
