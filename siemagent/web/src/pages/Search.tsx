import { useState, useCallback } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Search as SearchIcon, AlertCircle } from 'lucide-react'
import { searchEvents } from '../lib/api'
import type { Severity } from '../styles/tokens'
import { SeverityBadge, SEVERITY_LABELS } from '../components/SeverityBadge'
import { MITREBadge } from '../components/MITREBadge'

const ALL_SEVERITIES: Severity[] = ['P1', 'P2', 'P3', 'P4', 'P5']

function useDebounce<T>(value: T, delay: number): T {
  const [debounced, setDebounced] = useState(value)
  useState(() => {
    const t = setTimeout(() => setDebounced(value), delay)
    return () => clearTimeout(t)
  })
  return debounced
}

export function SearchPage() {
  const [query, setQuery] = useState('')
  const [severityFilter, setSeverityFilter] = useState<Severity | ''>('')
  const debouncedQuery = useDebounce(query, 300)

  const { data: results = [], isFetching, isError } = useQuery({
    queryKey: ['search', debouncedQuery, severityFilter],
    queryFn: () => searchEvents(debouncedQuery, severityFilter || undefined, 20),
    enabled: debouncedQuery.length > 2,
    staleTime: 30_000,
  })

  const handleSubmit = useCallback((e: React.FormEvent) => {
    e.preventDefault()
  }, [])

  function timeAgo(iso: string) {
    const diff = (Date.now() - new Date(iso).getTime()) / 1000
    if (diff < 60) return `${Math.round(diff)}s ago`
    if (diff < 3600) return `${Math.round(diff / 60)}m ago`
    return `${Math.round(diff / 3600)}h ago`
  }

  return (
    <div className="flex flex-col h-screen bg-canvas text-fg">
      {/* Header */}
      <header className="sticky top-0 z-10 bg-canvas/90 backdrop-blur border-b border-line px-6 py-4">
        <form onSubmit={handleSubmit} className="flex gap-3 max-w-3xl">
          <div className="relative flex-1">
            <SearchIcon size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-fg-subtle" />
            <input
              autoFocus
              value={query}
              onChange={e => setQuery(e.target.value)}
              placeholder="Search events by description, host, attack type…"
              className="w-full bg-surface border border-line-strong rounded-lg pl-9 pr-4 py-2.5 text-sm text-fg placeholder-fg-subtle focus:outline-none focus:border-accent"
            />
          </div>
          <select
            value={severityFilter}
            onChange={e => setSeverityFilter(e.target.value as Severity | '')}
            className="bg-surface border border-line-strong rounded-lg px-3 py-2.5 text-sm text-fg-muted focus:outline-none focus:border-accent"
          >
            <option value="">All severities</option>
            {ALL_SEVERITIES.map(s => (
              <option key={s} value={s}>{s} · {SEVERITY_LABELS[s]}</option>
            ))}
          </select>
        </form>
      </header>

      <div className="flex-1 overflow-y-auto px-6 py-4">
        {/* States */}
        {query.length <= 2 && (
          <div className="flex flex-col items-center justify-center h-full text-fg-subtle text-center">
            <SearchIcon size={48} className="mb-4 opacity-20" />
            <p className="text-sm">Type at least 3 characters to search</p>
            <p className="text-xs mt-1">Searches by semantic similarity across all indexed events</p>
          </div>
        )}

        {query.length > 2 && isFetching && (
          <div className="flex items-center justify-center h-32 text-fg-subtle text-sm">
            Searching…
          </div>
        )}

        {isError && (
          <div className="flex items-center gap-2 text-danger bg-danger/10 border border-danger/40 rounded px-4 py-3 text-sm">
            <AlertCircle size={16} />
            Search unavailable — Qdrant may not be running.
          </div>
        )}

        {!isFetching && query.length > 2 && results.length === 0 && !isError && (
          <div className="flex flex-col items-center justify-center h-64 text-fg-subtle text-center">
            <SearchIcon size={48} className="mb-4 opacity-20" />
            <p className="text-sm">No results for "{query}"</p>
          </div>
        )}

        {/* Results */}
        <div className="space-y-2 max-w-3xl">
          {results.map((hit, i) => (
            <div
              key={`${hit.event_id}-${i}`}
              className="bg-surface border border-line rounded-lg p-4 hover:border-line-strong transition-colors"
            >
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-center gap-2 flex-wrap">
                  <SeverityBadge severity={hit.severity} size="sm" />
                  <span className="text-sm font-medium text-fg">{hit.attack_type}</span>
                  <span className="text-xs text-accent-text bg-accent/10 px-1.5 py-0.5 rounded font-mono">
                    {Math.round(hit.score * 100)}% match
                  </span>
                </div>
                <span className="text-xs text-fg-subtle shrink-0">{timeAgo(hit.timestamp)}</span>
              </div>

              {hit.summary && (
                <p className="mt-2 text-sm text-fg-muted font-log leading-relaxed">{hit.summary}</p>
              )}

              <div className="mt-2 flex items-center gap-2">
                <span className="text-xs text-fg-subtle">{hit.source}</span>
                {hit.mitre_tactic && hit.mitre_tactic !== 'N/A' && (
                  <MITREBadge tactic={hit.mitre_tactic} technique="" />
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
