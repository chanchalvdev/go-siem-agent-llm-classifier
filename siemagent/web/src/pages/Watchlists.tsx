import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, ChevronDown, ChevronRight, Radar, RefreshCw, Search, Trash2 } from 'lucide-react'
import {
  addIndicators, apiError, createWatchlist, deleteWatchlist, listIndicators, listWatchlists, lookupIOC,
  refreshWatchlist, removeIndicator, updateWatchlist,
} from '../lib/api'
import type { IOCLookupResult, NewWatchlist, Watchlist } from '../lib/api'
import type { Severity } from '../styles/tokens'
import { SeverityBadge } from '../components/SeverityBadge'
import { timeAgo } from '../lib/time'
import { useAuth } from '../auth/auth'

const KEY = ['watchlists']
const field =
  'rounded-lg border border-line-strong bg-surface-2 px-2.5 py-1.5 text-sm text-fg focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/20'
const SOURCE_LABEL: Record<Watchlist['source'], string> = { manual: 'Manual', feed: 'Feed', file: 'File' }
const SEVERITIES: Severity[] = ['P1', 'P2', 'P3', 'P4']

function ErrorNote({ error }: { error: unknown }) {
  if (!error) return null
  return <p role="alert" className="rounded-lg border border-danger/30 bg-danger/10 px-3 py-2 text-xs text-danger">{apiError(error)}</p>
}

function Lookup() {
  const [value, setValue] = useState('')
  const lookup = useMutation({ mutationFn: lookupIOC })
  const results: IOCLookupResult[] | undefined = lookup.data
  return (
    <section aria-labelledby="lookup-title" className="rounded-xl border border-line bg-surface p-4 shadow-card">
      <h2 id="lookup-title" className="text-sm font-semibold text-fg">Check an indicator</h2>
      <form
        className="mt-2 flex gap-2"
        onSubmit={(e) => { e.preventDefault(); if (value.trim()) lookup.mutate(value.trim()) }}
      >
        <label className="sr-only" htmlFor="ioc-lookup">IP, domain, hash or URL</label>
        <input id="ioc-lookup" className={`${field} flex-1 font-mono`} value={value} onChange={(e) => setValue(e.target.value)} placeholder="IP, domain, hash or URL" />
        <button type="submit" className="inline-flex items-center gap-1.5 rounded-lg border border-line px-3 py-1.5 text-sm text-fg hover:bg-fg/4">
          <Search size={14} aria-hidden="true" /> Check
        </button>
      </form>
      <ErrorNote error={lookup.error} />
      {results && (
        <p className="mt-2 text-xs" role="status">
          {results.length === 0 ? (
            <span className="text-fg-muted">Not on any enabled watchlist.</span>
          ) : (
            <span className="text-danger">
              Listed on {results.map((r) => `${r.watchlist} (${r.severity}${r.indicator !== value.trim().toLowerCase() ? `, via ${r.indicator}` : ''})`).join(', ')}
            </span>
          )}
        </p>
      )}
    </section>
  )
}

function CreateForm({ onDone }: { onDone: () => void }) {
  const [name, setName] = useState('')
  const [source, setSource] = useState<'manual' | 'feed'>('manual')
  const [url, setUrl] = useState('')
  const [severity, setSeverity] = useState<Severity>('P2')
  const [hours, setHours] = useState(6)
  const create = useMutation({
    mutationFn: () => {
      const req: NewWatchlist = { name: name.trim(), source, severity }
      if (source === 'feed') {
        req.url = url.trim()
        req.refresh_seconds = Math.round(hours * 3600)
      }
      return createWatchlist(req)
    },
    onSuccess: () => { setName(''); setUrl(''); onDone() },
  })
  return (
    <form
      aria-label="Add a watchlist"
      onSubmit={(e) => { e.preventDefault(); create.mutate() }}
      className="grid gap-3 rounded-xl border border-line bg-surface p-4 shadow-card sm:grid-cols-2"
    >
      <label className="flex flex-col gap-1 text-xs text-fg-muted">Name
        <input className={field} value={name} onChange={(e) => setName(e.target.value)} required maxLength={100} />
      </label>
      <label className="flex flex-col gap-1 text-xs text-fg-muted">Source
        <select className={field} value={source} onChange={(e) => setSource(e.target.value as 'manual' | 'feed')}>
          <option value="manual">Manual: analysts add indicators</option>
          <option value="feed">Feed: download from a URL</option>
        </select>
      </label>
      {source === 'feed' && (
        <>
          <label className="flex flex-col gap-1 text-xs text-fg-muted sm:col-span-2">Feed URL (one indicator per line, hosts or CSV)
            <input className={`${field} font-mono`} value={url} onChange={(e) => setUrl(e.target.value)} required placeholder="https://feodotracker.abuse.ch/downloads/ipblocklist.txt" />
          </label>
          <label className="flex flex-col gap-1 text-xs text-fg-muted">Refresh every (hours)
            <input className={field} type="number" min={0.25} step={0.25} value={hours} onChange={(e) => setHours(Number(e.target.value))} />
          </label>
        </>
      )}
      <label className="flex flex-col gap-1 text-xs text-fg-muted">Severity of a match
        <select className={field} value={severity} onChange={(e) => setSeverity(e.target.value as Severity)}>
          {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
      </label>
      <div className="sm:col-span-2"><ErrorNote error={create.error} /></div>
      <div className="sm:col-span-2">
        <button type="submit" disabled={create.isPending} className="rounded-lg bg-accent px-3 py-1.5 text-sm font-medium text-on-accent hover:bg-accent-strong disabled:opacity-40">
          Add watchlist
        </button>
      </div>
    </form>
  )
}

function Indicators({ list, writable }: { list: Watchlist; writable: boolean }) {
  const qc = useQueryClient()
  const key = ['watchlist-indicators', list.id]
  const { data, isLoading } = useQuery({ queryKey: key, queryFn: () => listIndicators(list.id, 200) })
  const [values, setValues] = useState('')
  const [note, setNote] = useState('')
  const [rejected, setRejected] = useState<string[]>([])
  const refresh = () => { qc.invalidateQueries({ queryKey: key }); qc.invalidateQueries({ queryKey: KEY }) }
  const add = useMutation({
    mutationFn: () => addIndicators(list.id, values.split(/[\s,]+/).filter(Boolean), note.trim() || undefined),
    onSuccess: (res) => { setValues(''); setRejected(res.rejected); refresh() },
  })
  const remove = useMutation({ mutationFn: (value: string) => removeIndicator(list.id, value), onSuccess: refresh })
  const editable = writable && list.source === 'manual'

  return (
    <div className="mt-3 space-y-3 border-t border-line pt-3">
      {editable && (
        <form
          aria-label={`Add indicators to ${list.name}`}
          onSubmit={(e) => { e.preventDefault(); if (values.trim()) add.mutate() }}
          className="grid gap-2 sm:grid-cols-[1fr_auto]"
        >
          <label className="flex flex-col gap-1 text-xs text-fg-muted sm:col-span-2">Indicators (one per line: IP, range, domain, hash or URL)
            <textarea className={`${field} min-h-20 font-mono`} value={values} onChange={(e) => setValues(e.target.value)} />
          </label>
          <label className="flex flex-col gap-1 text-xs text-fg-muted">Note
            <input className={field} value={note} onChange={(e) => setNote(e.target.value)} maxLength={200} placeholder="e.g. INC-2EA4C98D phishing" />
          </label>
          <button type="submit" disabled={add.isPending} className="self-end rounded-lg bg-accent px-3 py-1.5 text-sm font-medium text-on-accent disabled:opacity-40">Add</button>
          <div className="sm:col-span-2"><ErrorNote error={add.error ?? remove.error} /></div>
          {rejected.length > 0 && (
            <p className="sm:col-span-2 text-xs text-warning">Not indicators, skipped: <span className="font-mono">{rejected.join(', ')}</span></p>
          )}
        </form>
      )}
      {isLoading ? (
        <p className="text-xs text-fg-subtle">Loading indicators…</p>
      ) : !data || data.total === 0 ? (
        <p className="text-xs text-fg-subtle">No indicators yet.</p>
      ) : (
        <>
          <ul aria-label={`Indicators of ${list.name}`} className="max-h-72 divide-y divide-line overflow-y-auto rounded-lg border border-line">
            {data.indicators.map((ind) => (
              <li key={ind.value} className="flex items-center gap-2 px-2.5 py-1.5 text-xs">
                <span className="w-12 shrink-0 text-[10px] uppercase text-fg-subtle">{ind.type}</span>
                <span className="min-w-0 flex-1 truncate font-mono text-fg" title={ind.value}>{ind.value}</span>
                {ind.note && <span className="hidden truncate text-fg-muted sm:inline">{ind.note}</span>}
                {editable && (
                  <button type="button" aria-label={`Remove ${ind.value}`} onClick={() => remove.mutate(ind.value)} className="text-fg-subtle hover:text-danger">
                    <Trash2 size={13} aria-hidden="true" />
                  </button>
                )}
              </li>
            ))}
          </ul>
          {data.total > data.indicators.length && (
            <p className="text-[11px] text-fg-subtle">Showing {data.indicators.length} of {data.total}.</p>
          )}
        </>
      )}
    </div>
  )
}

function WatchlistCard({ list, isAdmin, writable }: { list: Watchlist; isAdmin: boolean; writable: boolean }) {
  const qc = useQueryClient()
  const [open, setOpen] = useState(false)
  const invalidate = () => qc.invalidateQueries({ queryKey: KEY })
  const update = useMutation({ mutationFn: (u: { enabled?: boolean; severity?: Severity }) => updateWatchlist(list.id, u), onSuccess: invalidate })
  const refresh = useMutation({ mutationFn: () => refreshWatchlist(list.id), onSuccess: invalidate })
  const remove = useMutation({ mutationFn: () => deleteWatchlist(list.id), onSuccess: invalidate })

  return (
    <li className={`rounded-xl border border-line bg-surface p-3 shadow-card ${list.enabled ? '' : 'opacity-60'}`}>
      <div className="flex flex-wrap items-start gap-3">
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          aria-expanded={open}
          className="flex min-w-0 flex-1 items-start gap-2 text-left"
        >
          {open ? <ChevronDown size={16} className="mt-0.5 shrink-0 text-fg-subtle" aria-hidden="true" /> : <ChevronRight size={16} className="mt-0.5 shrink-0 text-fg-subtle" aria-hidden="true" />}
          <span className="min-w-0">
            <span className="flex flex-wrap items-center gap-2">
              <span className="text-sm font-medium text-fg">{list.name}</span>
              <SeverityBadge severity={list.severity} size="sm" />
              <span className="rounded-full border border-line px-1.5 py-0.5 text-[10px] text-fg-muted">{SOURCE_LABEL[list.source]}</span>
              {!list.enabled && <span className="text-[10px] text-fg-subtle">Disabled</span>}
            </span>
            <span className="mt-1 block text-[11px] text-fg-muted">
              {list.count.toLocaleString()} indicator{list.count === 1 ? '' : 's'} · {list.hits} match{list.hits === 1 ? '' : 'es'}
              {list.last_hit && <> · last {timeAgo(list.last_hit)}</>}
              {list.source === 'feed' && (list.last_fetched ? <> · fetched {timeAgo(list.last_fetched)}</> : <> · waiting for first download</>)}
            </span>
            {list.url && <span className="mt-0.5 block truncate font-mono text-[10px] text-fg-subtle" title={list.url}>{list.url}</span>}
          </span>
        </button>
        {isAdmin && (
          <div className="flex shrink-0 items-center gap-2">
            {list.source === 'feed' && (
              <button type="button" onClick={() => refresh.mutate()} disabled={refresh.isPending} aria-label={`Refresh ${list.name}`} className="rounded-lg border border-line p-1.5 text-fg-muted hover:text-fg disabled:opacity-40">
                <RefreshCw size={13} className={refresh.isPending ? 'animate-spin' : ''} aria-hidden="true" />
              </button>
            )}
            <label className="sr-only" htmlFor={`sev-${list.id}`}>Severity of {list.name}</label>
            <select id={`sev-${list.id}`} className={`${field} py-1 text-xs`} value={list.severity} onChange={(e) => update.mutate({ severity: e.target.value as Severity })}>
              {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
            <button type="button" onClick={() => update.mutate({ enabled: !list.enabled })} className="rounded-lg border border-line px-2.5 py-1 text-xs text-fg-muted hover:text-fg">
              {list.enabled ? 'Disable' : 'Enable'}
            </button>
            {list.source !== 'file' && (
              <button type="button" onClick={() => remove.mutate()} aria-label={`Delete ${list.name}`} className="rounded-lg border border-line p-1.5 text-fg-muted hover:text-danger">
                <Trash2 size={13} aria-hidden="true" />
              </button>
            )}
          </div>
        )}
      </div>
      {list.error && (
        <p className="mt-2 flex items-center gap-1.5 text-xs text-warning">
          <AlertTriangle size={12} aria-hidden="true" /> Last download failed: {list.error}. The previous indicators are still in use.
        </p>
      )}
      <ErrorNote error={update.error ?? refresh.error ?? remove.error} />
      {open && <Indicators list={list} writable={writable} />}
    </li>
  )
}

export function Watchlists() {
  const { can } = useAuth()
  const isAdmin = can('admin')
  const writable = can('write')
  const [adding, setAdding] = useState(false)
  const qc = useQueryClient()
  const { data = [], isLoading, isError } = useQuery({ queryKey: KEY, queryFn: listWatchlists, refetchInterval: 30_000 })
  const enabled = data.filter((w) => w.enabled)
  const tiles: [string, string | number][] = [
    ['Watchlists', data.length],
    ['Indicators in use', enabled.reduce((n, w) => n + w.count, 0).toLocaleString()],
    ['Matches since start', data.reduce((n, w) => n + w.hits, 0)],
  ]

  return (
    <div className="flex-1 overflow-y-auto">
      <div className="mx-auto max-w-5xl space-y-5 p-4 sm:p-6">
        <header className="flex flex-wrap items-end gap-3">
          <div className="flex-1">
            <h1 className="flex items-center gap-2 text-lg font-semibold text-fg">
              <Radar size={18} className="text-accent-text" aria-hidden="true" /> Watchlists
            </h1>
            <p className="mt-1 text-sm text-fg-muted">
              Known-bad IPs, ranges, domains and file hashes. Any event that mentions one is raised to the list's severity and can open an incident.
            </p>
          </div>
          {isAdmin && (
            <button type="button" onClick={() => setAdding((v) => !v)} aria-expanded={adding} className="rounded-lg border border-line px-3 py-1.5 text-sm text-fg hover:bg-fg/4">
              {adding ? 'Cancel' : 'Add watchlist'}
            </button>
          )}
        </header>

        <dl className="grid grid-cols-3 gap-3">
          {tiles.map(([label, value]) => (
            <div key={label} className="rounded-xl border border-line bg-surface p-3 shadow-card">
              <dt className="text-[11px] uppercase tracking-wide text-fg-subtle">{label}</dt>
              <dd className="mt-1 text-xl font-semibold tabular-nums text-fg">{value}</dd>
            </div>
          ))}
        </dl>

        {adding && <CreateForm onDone={() => { setAdding(false); qc.invalidateQueries({ queryKey: KEY }) }} />}
        <Lookup />

        {isLoading ? (
          <p className="text-sm text-fg-subtle">Loading watchlists…</p>
        ) : isError ? (
          <p className="text-sm text-danger">Could not load watchlists.</p>
        ) : data.length === 0 ? (
          <div className="rounded-xl border border-dashed border-line-strong p-8 text-center">
            <p className="text-sm font-medium text-fg">No watchlists yet</p>
            <p className="mt-1 text-xs text-fg-muted">
              {isAdmin ? 'Add a manual list or a threat feed URL, ' : 'An admin can add lists or threat feeds, '}
              or put list files in IOC_WATCHLIST_DIR.
            </p>
          </div>
        ) : (
          <ul aria-label="Watchlists" className="space-y-2">
            {data.map((w) => <WatchlistCard key={w.id} list={w} isAdmin={isAdmin} writable={writable} />)}
          </ul>
        )}
      </div>
    </div>
  )
}
