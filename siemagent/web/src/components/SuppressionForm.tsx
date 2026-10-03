import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { BellOff } from 'lucide-react'
import { apiError, createSuppression } from '../lib/api'
import type { Suppression } from '../lib/api'

const field =
  'rounded-lg border border-line-strong bg-surface-2 px-2.5 py-1.5 text-sm text-fg focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/20'

const DURATIONS: { value: string; label: string }[] = [
  { value: '1h', label: '1 hour' },
  { value: '24h', label: '24 hours' },
  { value: '168h', label: '7 days' },
  { value: '720h', label: '30 days' },
  { value: '', label: 'Until lifted' },
]

interface Props {
  /** Pick from these entities ("ip:1.2.3.4") instead of typing matchers. */
  entities?: string[]
  /** Note the snooze on this incident's timeline. */
  incidentId?: string
  onDone?: (s: Suppression) => void
}

// SuppressionForm snoozes alerts by entity, detection rule and/or attack type.
export function SuppressionForm({ entities, incidentId, onDone }: Props) {
  const qc = useQueryClient()
  const [entity, setEntity] = useState(entities?.[0] ?? '')
  const [ruleId, setRuleId] = useState('')
  const [attackType, setAttackType] = useState('')
  const [reason, setReason] = useState('')
  const [duration, setDuration] = useState('24h')

  const create = useMutation({
    mutationFn: () => createSuppression({
      entity: entity.trim() || undefined,
      rule_id: ruleId.trim() || undefined,
      attack_type: attackType.trim() || undefined,
      reason: reason.trim(),
      duration,
      incident_id: incidentId,
    }),
    onSuccess: (s) => {
      setReason('')
      if (!entities) { setEntity(''); setRuleId(''); setAttackType('') }
      qc.invalidateQueries({ queryKey: ['suppressions'] })
      if (incidentId) qc.invalidateQueries({ queryKey: ['incident', incidentId] })
      onDone?.(s)
    },
  })

  return (
    <form
      aria-label="Snooze alerts"
      onSubmit={(e) => { e.preventDefault(); create.mutate() }}
      className="grid gap-3 rounded-xl border border-line bg-surface p-4 shadow-card sm:grid-cols-2"
    >
      {entities ? (
        <label className="flex flex-col gap-1 text-xs text-fg-muted">Entity
          <select className={`${field} font-mono`} value={entity} onChange={(e) => setEntity(e.target.value)}>
            {entities.map((e) => <option key={e} value={e}>{e}</option>)}
          </select>
        </label>
      ) : (
        <>
          <label className="flex flex-col gap-1 text-xs text-fg-muted">Entity
            <input className={`${field} font-mono`} value={entity} onChange={(e) => setEntity(e.target.value)} placeholder="ip:203.0.113.9, user:svc-backup or host:web01" />
          </label>
          <label className="flex flex-col gap-1 text-xs text-fg-muted">Detection rule ID
            <input className={`${field} font-mono`} value={ruleId} onChange={(e) => setRuleId(e.target.value)} placeholder="any rule" />
          </label>
          <label className="flex flex-col gap-1 text-xs text-fg-muted">Attack type
            <input className={field} value={attackType} onChange={(e) => setAttackType(e.target.value)} placeholder="any attack type, e.g. Port Scan" />
          </label>
        </>
      )}
      <label className="flex flex-col gap-1 text-xs text-fg-muted">For
        <select className={field} value={duration} onChange={(e) => setDuration(e.target.value)}>
          {DURATIONS.map((d) => <option key={d.label} value={d.value}>{d.label}</option>)}
        </select>
      </label>
      <label className="flex flex-col gap-1 text-xs text-fg-muted sm:col-span-2">Reason
        <input className={field} value={reason} onChange={(e) => setReason(e.target.value)} required maxLength={500} placeholder="e.g. authorised pentest from this IP until Friday" />
      </label>
      {create.error && (
        <p role="alert" className="sm:col-span-2 rounded-lg border border-danger/30 bg-danger/10 px-3 py-2 text-xs text-danger">{apiError(create.error)}</p>
      )}
      <p className="sm:col-span-2 text-[11px] text-fg-subtle">
        Matching events are still stored, but open no incident, run no playbook and start no AI investigation.
        {!entities && ' Every field you fill in must match.'}
      </p>
      <div className="sm:col-span-2">
        <button type="submit" disabled={create.isPending} className="inline-flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1.5 text-sm font-medium text-on-accent hover:bg-accent-strong disabled:opacity-40">
          <BellOff size={14} aria-hidden="true" /> Snooze
        </button>
      </div>
    </form>
  )
}
