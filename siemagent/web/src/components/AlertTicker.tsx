import type { Incident } from '../hooks/useAlertStream'
import { CheckCircle2, Loader2, AlertTriangle } from 'lucide-react'

interface Props {
  incidents: Incident[]
  onSelect: (id: string) => void
}

const STATUS_TEXT: Record<Incident['status'], string> = {
  investigating: 'Investigating…',
  complete: 'Playbook ready',
  failed: 'Investigation failed',
}

function StatusIcon({ status }: { status: Incident['status'] }) {
  if (status === 'complete') return <CheckCircle2 size={14} className="text-success" />
  if (status === 'failed') return <AlertTriangle size={14} className="text-danger" />
  return <Loader2 size={14} className="animate-spin text-warning" />
}

// AlertTicker shows a slide-in banner per active incident. It is intentionally
// presentational: the parent owns the incident list and selection.
export function AlertTicker({ incidents, onSelect }: Props) {
  if (incidents.length === 0) return null

  return (
    <div className="fixed inset-x-0 top-0 z-50 flex flex-col gap-1 p-2">
      {incidents.map((inc) => (
        <button
          key={inc.id}
          onClick={() => onSelect(inc.id)}
          className="ticker-in flex items-center gap-2 rounded-lg border border-line-strong
            bg-surface/95 px-3 py-2 text-left text-sm shadow-lg backdrop-blur
            hover:border-fg/20"
        >
          <span className="rounded bg-danger/10 px-1.5 py-0.5 font-mono text-[10px]
            font-semibold text-danger severity-pulse">
            INCIDENT
          </span>
          <span className="font-mono text-xs text-fg-muted">{inc.id}</span>
          <span className="ml-auto flex items-center gap-1 text-xs text-fg-muted">
            <StatusIcon status={inc.status} />
            {STATUS_TEXT[inc.status]}
          </span>
        </button>
      ))}
    </div>
  )
}
