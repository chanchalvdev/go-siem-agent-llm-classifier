import { useState } from 'react'
import { Ban, Bell, Check, Lock, MonitorX, Webhook, X } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import type { ActionType, ResponseAction } from '../lib/api'
import { ACTION_LABELS, ACTION_STATUS_LABELS, ACTION_STATUS_STYLES } from '../lib/response'
import { timeAgo } from '../lib/time'

const ICONS: Record<ActionType, LucideIcon> = {
  block_ip: Ban,
  disable_user: Lock,
  isolate_host: MonitorX,
  notify: Bell,
  webhook: Webhook,
}

interface Props {
  action: ResponseAction
  busy?: boolean
  onApprove?: (id: string) => void
  onReject?: (id: string, reason: string) => void
  /** Show which incident the action belongs to (on the cross-incident queue). */
  showIncident?: boolean
}

// ActionCard shows one response action and, while pending, approve/reject.
export function ActionCard({ action: a, busy, onApprove, onReject, showIncident }: Props) {
  const [rejecting, setRejecting] = useState(false)
  const [reason, setReason] = useState('')
  const Icon = ICONS[a.type] ?? Webhook
  const label = `${ACTION_LABELS[a.type] ?? a.type}${a.target ? ` ${a.target}` : ''}`

  return (
    <li className="rounded-xl border border-line bg-surface p-3 shadow-card">
      <div className="flex flex-wrap items-center gap-2">
        <Icon size={15} className="text-fg-muted" aria-hidden="true" />
        <span className="text-sm font-medium text-fg">
          {ACTION_LABELS[a.type] ?? a.type}
          {a.target && <span className="ml-1 font-mono">{a.target}</span>}
        </span>
        <span className={`rounded-full border px-2 py-0.5 text-[10px] font-medium ${ACTION_STATUS_STYLES[a.status]}`}>
          {ACTION_STATUS_LABELS[a.status]}
        </span>
        <time className="ml-auto text-[11px] text-fg-subtle" dateTime={a.proposed_at}>{timeAgo(a.proposed_at)}</time>
      </div>
      <p className="mt-1 text-xs text-fg-muted">
        {a.playbook_name} · {a.reason}
        {showIncident && <> · <span className="font-mono">{a.incident_id}</span></>}
      </p>
      {a.message && <p className="mt-1 rounded-md bg-fg/4 px-2 py-1 text-xs text-fg">{a.message}</p>}
      {a.result && <p className="mt-1 break-words text-xs text-fg-subtle">{a.result}</p>}
      {a.decided_by && a.status !== 'pending' && (
        <p className="mt-1 text-[11px] text-fg-subtle">Decided by {a.decided_by}</p>
      )}

      {a.status === 'pending' && onApprove && onReject && (
        rejecting ? (
          <form
            className="mt-2 flex flex-wrap gap-2"
            onSubmit={(e) => { e.preventDefault(); onReject(a.id, reason.trim()); setRejecting(false) }}
          >
            <label className="sr-only" htmlFor={`reason-${a.id}`}>Reason for rejecting</label>
            <input
              id={`reason-${a.id}`}
              value={reason}
              maxLength={1000}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Why not? (optional)"
              className="min-w-0 flex-1 rounded-lg border border-line-strong bg-surface-2 px-2.5 py-1.5 text-xs text-fg focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/20"
            />
            <button type="submit" disabled={busy} className="rounded-lg border border-danger/40 px-2.5 py-1.5 text-xs font-medium text-danger hover:bg-danger/10 disabled:opacity-40">
              Confirm reject
            </button>
            <button type="button" onClick={() => setRejecting(false)} className="rounded-lg px-2 py-1.5 text-xs text-fg-muted hover:text-fg">
              Cancel
            </button>
          </form>
        ) : (
          <div className="mt-2 flex gap-2">
            <button
              onClick={() => onApprove(a.id)}
              disabled={busy}
              aria-label={`Approve ${label}`}
              className="inline-flex items-center gap-1 rounded-lg bg-accent px-2.5 py-1.5 text-xs font-medium text-on-accent hover:bg-accent-strong disabled:opacity-40"
            >
              <Check size={13} aria-hidden="true" /> Approve and run
            </button>
            <button
              onClick={() => setRejecting(true)}
              disabled={busy}
              aria-label={`Reject ${label}`}
              className="inline-flex items-center gap-1 rounded-lg border border-line-strong px-2.5 py-1.5 text-xs text-fg-muted hover:text-fg hover:bg-fg/4 disabled:opacity-40"
            >
              <X size={13} aria-hidden="true" /> Reject
            </button>
          </div>
        )
      )}
    </li>
  )
}
