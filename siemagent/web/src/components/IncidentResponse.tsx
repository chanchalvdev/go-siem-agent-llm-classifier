import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiError, listActions, listPlaybooks, runPlaybook } from '../lib/api'
import { ActionCard } from './ActionCard'
import { useActionDecisions } from '../hooks/useActionDecisions'

// IncidentResponse lists an incident's response actions and lets an analyst
// run any playbook against it.
export function IncidentResponse({ incidentId }: { incidentId: string }) {
  const qc = useQueryClient()
  const actions = useQuery({
    queryKey: ['actions', 'incident', incidentId],
    queryFn: () => listActions({ incident: incidentId }),
    refetchInterval: 10_000,
  })
  const playbooks = useQuery({ queryKey: ['playbooks'], queryFn: listPlaybooks })
  const [playbook, setPlaybook] = useState('')
  const decisions = useActionDecisions()
  const run = useMutation({
    mutationFn: (pb: string) => runPlaybook(incidentId, pb),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['actions'] })
      qc.invalidateQueries({ queryKey: ['incident', incidentId] })
    },
  })
  const error = decisions.error ?? run.error

  return (
    <section aria-labelledby="response-title">
      <h3 id="response-title" className="mb-2 text-xs font-semibold uppercase tracking-wide text-fg-subtle">Response</h3>
      <form
        className="mb-3 flex flex-wrap gap-2"
        onSubmit={(e) => { e.preventDefault(); if (playbook) run.mutate(playbook) }}
      >
        <label className="sr-only" htmlFor={`playbook-${incidentId}`}>Playbook to run</label>
        <select
          id={`playbook-${incidentId}`}
          value={playbook}
          onChange={(e) => setPlaybook(e.target.value)}
          className="min-w-0 flex-1 rounded-lg border border-line-strong bg-surface-2 px-2.5 py-1.5 text-sm text-fg focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/20"
        >
          <option value="">Choose a playbook…</option>
          {(playbooks.data ?? []).map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
        </select>
        <button
          type="submit"
          disabled={!playbook || run.isPending}
          className="rounded-lg border border-line-strong px-3 py-1.5 text-sm text-fg hover:bg-fg/4 disabled:opacity-40"
        >
          Run playbook
        </button>
      </form>
      {run.isSuccess && run.data.length === 0 && (
        <p role="status" className="mb-2 text-xs text-fg-muted">
          Nothing new to propose: the actions already exist or no entity fits them.
        </p>
      )}
      {error && (
        <p role="alert" className="mb-2 rounded-lg border border-danger/30 bg-danger/10 px-3 py-2 text-xs text-danger">
          {apiError(error)}
        </p>
      )}
      {(actions.data ?? []).length === 0 ? (
        <p className="text-xs text-fg-subtle">No response actions for this incident.</p>
      ) : (
        <ul className="space-y-2" aria-label="Response actions">
          {actions.data!.map((a) => (
            <ActionCard key={a.id} action={a} busy={decisions.busy} onApprove={decisions.approve} onReject={decisions.reject} />
          ))}
        </ul>
      )}
    </section>
  )
}
