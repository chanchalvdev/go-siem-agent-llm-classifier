import type { ClassifiedEvent } from '../lib/api'
import { SEVERITY_COLORS } from '../styles/tokens'
import { SeverityBadge } from './SeverityBadge'
import { MITREBadge } from './MITREBadge'
import type { Severity } from '../styles/tokens'

interface Props {
  event: ClassifiedEvent
  onClick: () => void
  selected: boolean
  score?: number
}

function timeAgo(iso: string): string {
  const diff = (Date.now() - new Date(iso).getTime()) / 1000
  if (diff < 60)    return `${Math.round(diff)}s ago`
  if (diff < 3600)  return `${Math.round(diff / 60)}m ago`
  if (diff < 86400) return `${Math.round(diff / 3600)}h ago`
  return `${Math.round(diff / 86400)}d ago`
}

export function EventCard({ event, onClick, selected, score }: Props) {
  const sev = event.severity as Severity
  const borderColor = SEVERITY_COLORS[sev]
  const summary = event.summary?.length > 90
    ? event.summary.slice(0, 90) + '…'
    : event.summary
  const confidence = Math.round((event.confidence ?? 0) * 100)

  return (
    <button
      onClick={onClick}
      className={`
        w-full text-left rounded-xl border transition-all duration-150
        focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent
        ${selected
          ? 'bg-accent/10 border-accent/50 shadow-pop'
          : 'bg-surface border-line shadow-card hover:border-line-strong hover:bg-surface-2'
        }
      `}
      style={{ borderLeft: `3px solid ${borderColor}` }}
    >
      <div className="p-3">
        {/* Row 1: severity + attack type + time */}
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2 min-w-0 flex-wrap">
            <SeverityBadge severity={sev} size="sm" />
            <span className="text-sm font-semibold text-fg truncate">{event.attack_type}</span>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            {score !== undefined && (
              <span className="text-[10px] text-accent-text bg-accent/10 px-1.5 py-0.5 rounded-full border border-accent/30">
                {score}% match
              </span>
            )}
            <span className="text-[10px] text-fg-subtle">
              {timeAgo(event.processed_at || event.event.timestamp)}
            </span>
          </div>
        </div>

        {/* Row 2: host / app */}
        {(event.event.hostname || event.event.app_name) && (
          <div className="mt-1 flex items-center gap-1.5 text-[11px] text-fg-subtle">
            {event.event.hostname && <span>{event.event.hostname}</span>}
            {event.event.hostname && event.event.app_name && <span>·</span>}
            {event.event.app_name && <span>{event.event.app_name}</span>}
          </div>
        )}

        {/* Row 3: summary */}
        {summary && (
          <p className="mt-1.5 text-xs text-fg-muted leading-relaxed">{summary}</p>
        )}

        {/* Row 4: MITRE + confidence */}
        <div className="mt-2.5 flex items-center justify-between gap-2">
          <MITREBadge tactic={event.mitre?.tactic ?? ''} technique={event.mitre?.technique_id ?? ''} />
          <div className="flex items-center gap-1.5 shrink-0">
            <div className="h-1 w-14 bg-fg/10 rounded-full overflow-hidden">
              <div
                className="h-full rounded-full"
                style={{
                  width: `${confidence}%`,
                  background: confidence >= 80 ? 'rgb(var(--accent))' : confidence >= 60 ? 'rgb(var(--warning))' : 'rgb(var(--fg-subtle))'
                }}
              />
            </div>
            <span className="text-[10px] text-fg-subtle">{confidence}%</span>
          </div>
        </div>
      </div>
    </button>
  )
}
