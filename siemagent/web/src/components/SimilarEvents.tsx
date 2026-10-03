import { useQuery } from '@tanstack/react-query'
import { searchEvents } from '../lib/api'
import { SeverityBadge } from './SeverityBadge'
import type { Severity } from '../styles/tokens'

interface Props {
  summary: string
}

function timeAgo(iso: string) {
  const diff = (Date.now() - new Date(iso).getTime()) / 1000
  if (diff < 3600) return `${Math.round(diff / 60)}m ago`
  if (diff < 86400) return `${Math.round(diff / 3600)}h ago`
  return `${Math.round(diff / 86400)}d ago`
}

export function SimilarEvents({ summary }: Props) {
  const { data: hits = [], isLoading, isError } = useQuery({
    queryKey: ['similar', summary],
    queryFn: () => searchEvents(summary, undefined, 5),
    enabled: summary.length > 10,
    staleTime: 60_000,
  })

  if (isError) return null // silently skip if Qdrant unavailable

  return (
    <div>
      <p className="text-xs text-fg-subtle uppercase tracking-wider mb-2">Similar past events</p>

      {isLoading && (
        <div className="space-y-2">
          {[1, 2, 3].map(i => (
            <div key={i} className="h-12 bg-surface-2 rounded animate-pulse" />
          ))}
        </div>
      )}

      {!isLoading && hits.length === 0 && (
        <p className="text-xs text-fg-subtle">No similar events found.</p>
      )}

      <div className="space-y-1.5">
        {hits.map((hit, i) => (
          <div
            key={`${hit.event_id}-${i}`}
            className="bg-fg/4 rounded px-3 py-2 flex items-center justify-between gap-2"
          >
            <div className="flex items-center gap-2 min-w-0">
              <SeverityBadge severity={hit.severity as Severity} size="sm" />
              <span className="text-xs text-fg-muted truncate">{hit.attack_type}</span>
              {hit.source && (
                <span className="text-xs text-fg-subtle shrink-0">{hit.source}</span>
              )}
            </div>
            <span className="text-xs text-fg-subtle shrink-0">{timeAgo(hit.timestamp)}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
