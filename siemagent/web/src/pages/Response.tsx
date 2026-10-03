import { useQuery } from '@tanstack/react-query'
import { Workflow } from 'lucide-react'
import { apiError, listActions, listPlaybooks } from '../lib/api'
import type { Playbook } from '../lib/api'
import { ACTION_LABELS, MODE_LABELS } from '../lib/response'
import { ActionCard } from '../components/ActionCard'
import { useActionDecisions } from '../hooks/useActionDecisions'

function triggerSummary(p: Playbook): string {
  const t = p.trigger
  const parts: string[] = []
  if (t.min_severity) parts.push(`${t.min_severity} or worse`)
  if (t.tactics?.length) parts.push(`tactic ${t.tactics.join(' / ')}`)
  if (t.techniques?.length) parts.push(`technique ${t.techniques.join(' / ')}`)
  if (t.attack_types?.length) parts.push(`attack “${t.attack_types.join('” / “')}”`)
  return parts.length ? parts.join(', ') : 'every incident'
}

const MODE_STYLES = {
  approval: 'border-warning/30 bg-warning/10 text-warning',
  dry_run: 'border-line-strong bg-fg/4 text-fg-muted',
  auto: 'border-danger/30 bg-danger/10 text-danger',
} as const

export function Response() {
  const pending = useQuery({ queryKey: ['actions', 'pending'], queryFn: () => listActions({ status: 'pending' }), refetchInterval: 10_000 })
  const recent = useQuery({ queryKey: ['actions', 'recent'], queryFn: () => listActions({ limit: 50 }), refetchInterval: 15_000 })
  const playbooks = useQuery({ queryKey: ['playbooks'], queryFn: listPlaybooks })
  const decisions = useActionDecisions()
  const history = (recent.data ?? []).filter((a) => a.status !== 'pending')

  return (
    <div className="flex-1 overflow-y-auto">
      <div className="mx-auto max-w-5xl space-y-6 p-4 sm:p-6">
        <header>
          <h1 className="flex items-center gap-2 text-lg font-semibold text-fg">
            <Workflow size={18} className="text-accent-text" aria-hidden="true" />
            Response
          </h1>
          <p className="mt-1 text-sm text-fg-muted">
            Playbooks propose actions when incidents match. Nothing runs until you approve it, unless a playbook is set to automatic.
          </p>
        </header>

        {decisions.error && (
          <p role="alert" className="rounded-lg border border-danger/30 bg-danger/10 px-3 py-2 text-xs text-danger">
            {apiError(decisions.error)}
          </p>
        )}

        <section aria-labelledby="pending-title">
          <h2 id="pending-title" className="mb-2 text-xs font-semibold uppercase tracking-wide text-fg-subtle">
            Awaiting approval ({pending.data?.length ?? 0})
          </h2>
          {pending.isError ? (
            <p className="text-sm text-danger">Could not load actions.</p>
          ) : (pending.data ?? []).length === 0 ? (
            <p className="rounded-xl border border-dashed border-line-strong p-6 text-center text-sm text-fg-muted">
              Nothing waiting for approval.
            </p>
          ) : (
            <ul className="space-y-2" aria-label="Actions awaiting approval">
              {pending.data!.map((a) => (
                <ActionCard key={a.id} action={a} showIncident busy={decisions.busy} onApprove={decisions.approve} onReject={decisions.reject} />
              ))}
            </ul>
          )}
        </section>

        <section aria-labelledby="history-title">
          <h2 id="history-title" className="mb-2 text-xs font-semibold uppercase tracking-wide text-fg-subtle">Recent actions</h2>
          {history.length === 0 ? (
            <p className="text-sm text-fg-subtle">No actions yet.</p>
          ) : (
            <ul className="space-y-2" aria-label="Recent actions">
              {history.map((a) => <ActionCard key={a.id} action={a} showIncident />)}
            </ul>
          )}
        </section>

        <section aria-labelledby="playbooks-title">
          <h2 id="playbooks-title" className="mb-2 text-xs font-semibold uppercase tracking-wide text-fg-subtle">Playbooks</h2>
          <ul className="grid gap-2 sm:grid-cols-2" aria-label="Playbooks">
            {(playbooks.data ?? []).map((p) => (
              <li key={p.id} className={`rounded-xl border border-line bg-surface p-3 shadow-card ${p.enabled ? '' : 'opacity-60'}`}>
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-sm font-medium text-fg">{p.name}</span>
                  <span className={`rounded-full border px-2 py-0.5 text-[10px] font-medium ${MODE_STYLES[p.mode]}`}>{MODE_LABELS[p.mode]}</span>
                  {!p.enabled && <span className="text-[10px] text-fg-subtle">disabled</span>}
                </div>
                {p.description && <p className="mt-1 text-xs text-fg-muted">{p.description}</p>}
                <p className="mt-1.5 text-[11px] text-fg-muted"><span className="text-fg-subtle">When:</span> {triggerSummary(p)}</p>
                <p className="text-[11px] text-fg-muted">
                  <span className="text-fg-subtle">Then:</span> {p.actions.map((a) => ACTION_LABELS[a.type] ?? a.type).join(' → ')}
                </p>
                <p className="mt-1 font-mono text-[10px] text-fg-subtle">{p.id} · {p.source}</p>
              </li>
            ))}
          </ul>
        </section>
      </div>
    </div>
  )
}
