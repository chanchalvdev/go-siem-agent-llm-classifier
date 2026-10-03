import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  AlertTriangle, Bot, CheckCircle2, FileText, MessageSquare, PlusCircle, Sparkles, ThumbsDown, ThumbsUp,
  TrendingUp, UserRound, X,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import {
  addIncidentComment, apiError, getIncident, investigateIncident, rateInvestigation, updateIncident,
} from '../lib/api'
import type {
  IncidentActivity, IncidentAlert, IncidentDetail as Detail, IncidentResolution, IncidentStatus, IncidentUpdate,
} from '../lib/api'
import { timeAgo } from '../lib/time'
import { STATUS_LABELS, entityLabel } from '../lib/incidents'
import { SeverityBadge } from './SeverityBadge'
import { KillChain } from './KillChain'
import { IncidentReport } from './IncidentReport'

const RESOLUTION_LABELS: Record<Exclude<IncidentResolution, ''>, string> = {
  true_positive: 'True positive',
  false_positive: 'False positive',
  benign: 'Benign',
  duplicate: 'Duplicate',
}

const ACTIVITY_ICONS: Record<string, LucideIcon> = {
  created: PlusCircle,
  escalated: TrendingUp,
  comment: MessageSquare,
  investigation: Bot,
  assignee: UserRound,
  status: CheckCircle2,
  resolution: CheckCircle2,
  severity: AlertTriangle,
  feedback: ThumbsUp,
}

type TimelineItem =
  | { type: 'alert'; at: string; key: string; alert: IncidentAlert }
  | { type: 'activity'; at: string; key: string; activity: IncidentActivity }

// timeline merges alerts and history, newest first.
function timeline(d: Detail): TimelineItem[] {
  const items: TimelineItem[] = [
    ...d.alerts.map((a) => ({ type: 'alert' as const, at: a.at, key: `a${a.id}`, alert: a })),
    ...d.activity.map((a) => ({ type: 'activity' as const, at: a.at, key: `h${a.id}`, activity: a })),
  ]
  return items.sort((x, y) => new Date(y.at).getTime() - new Date(x.at).getTime() || y.key.localeCompare(x.key))
}

const fieldClass =
  'rounded-lg border border-line-strong bg-surface-2 px-2.5 py-1.5 text-sm text-fg focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/20'

interface Props {
  id: string
  onClose?: () => void
  onEntity?: (entity: string) => void
}

export function IncidentDetail({ id, onClose, onEntity }: Props) {
  const qc = useQueryClient()
  const key = ['incident', id]
  const { data, isLoading, isError } = useQuery({ queryKey: key, queryFn: () => getIncident(id), refetchInterval: 10_000 })
  const [comment, setComment] = useState('')
  const [assigneeDraft, setAssigneeDraft] = useState<string | null>(null)
  const [showReport, setShowReport] = useState(false)

  const refresh = () => {
    qc.invalidateQueries({ queryKey: key })
    qc.invalidateQueries({ queryKey: ['incidents'] })
    qc.invalidateQueries({ queryKey: ['incident-stats'] })
  }
  const update = useMutation({ mutationFn: (u: IncidentUpdate) => updateIncident(id, u), onSuccess: refresh })
  const investigate = useMutation({ mutationFn: () => investigateIncident(id) })
  const rate = useMutation({ mutationFn: (helpful: boolean) => rateInvestigation(id, helpful), onSuccess: refresh })
  const addComment = useMutation({
    mutationFn: (body: string) => addIncidentComment(id, body),
    onSuccess: () => { setComment(''); refresh() },
  })

  if (isLoading) return <p className="p-6 text-sm text-fg-subtle">Loading incident…</p>
  if (isError || !data) return <p className="p-6 text-sm text-danger">Could not load the incident.</p>

  const assignee = assigneeDraft ?? data.assignee ?? ''
  const saveAssignee = () => {
    if (assigneeDraft !== null && assigneeDraft.trim() !== (data.assignee ?? '')) {
      update.mutate({ assignee: assigneeDraft.trim() })
    }
    setAssigneeDraft(null)
  }
  const error = update.error ?? addComment.error ?? investigate.error ?? rate.error
  const latestInvestigation = [...data.activity].reverse().find((a) => a.kind === 'investigation')

  return (
    <article className="p-4 sm:p-6 space-y-5" aria-labelledby="incident-title">
      <header className="flex items-start gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={data.severity} />
            <span className="font-mono text-xs text-fg-subtle">{data.id}</span>
          </div>
          <h2 id="incident-title" className="mt-2 text-lg font-semibold text-fg break-words">{data.title}</h2>
          <p className="mt-1 text-xs text-fg-muted">
            {data.alert_count} alert{data.alert_count === 1 ? '' : 's'} · first seen {timeAgo(data.first_seen)} · last seen {timeAgo(data.last_seen)}
          </p>
        </div>
        {onClose && (
          <button onClick={onClose} aria-label="Close incident" className="rounded-lg p-1.5 text-fg-subtle hover:bg-fg/4 hover:text-fg">
            <X size={18} />
          </button>
        )}
      </header>

      <div className="flex flex-wrap gap-2">
        <button
          onClick={() => investigate.mutate()}
          disabled={investigate.isPending}
          className="inline-flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1.5 text-sm font-medium text-on-accent hover:bg-accent-strong disabled:opacity-40"
        >
          <Sparkles size={14} aria-hidden="true" /> Investigate with AI
        </button>
        <button
          onClick={() => setShowReport(true)}
          className="inline-flex items-center gap-1.5 rounded-lg border border-line-strong px-3 py-1.5 text-sm text-fg hover:bg-fg/4"
        >
          <FileText size={14} aria-hidden="true" /> Report
        </button>
        {investigate.isSuccess && (
          <p role="status" className="self-center text-xs text-fg-muted">
            Investigation started. The write-up appears in the timeline when it finishes.
          </p>
        )}
      </div>
      {showReport && <IncidentReport id={id} onClose={() => setShowReport(false)} />}

      <section aria-label="Case" className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <label className="flex flex-col gap-1 text-xs text-fg-muted">
          Status
          <select
            className={fieldClass}
            value={data.status}
            disabled={update.isPending}
            onChange={(e) => update.mutate({ status: e.target.value as IncidentStatus })}
          >
            {Object.entries(STATUS_LABELS).map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </select>
        </label>
        <label className="flex flex-col gap-1 text-xs text-fg-muted">
          Assignee
          <input
            className={fieldClass}
            value={assignee}
            placeholder="Unassigned"
            maxLength={100}
            onChange={(e) => setAssigneeDraft(e.target.value)}
            onBlur={saveAssignee}
            onKeyDown={(e) => { if (e.key === 'Enter') e.currentTarget.blur() }}
          />
        </label>
        <label className="flex flex-col gap-1 text-xs text-fg-muted">
          Resolution
          <select
            className={fieldClass}
            value={data.resolution ?? ''}
            disabled={data.status !== 'resolved' || update.isPending}
            title={data.status !== 'resolved' ? 'Resolve the incident to record a resolution' : undefined}
            onChange={(e) => update.mutate({ resolution: e.target.value as IncidentResolution })}
          >
            <option value="">—</option>
            {Object.entries(RESOLUTION_LABELS).map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </select>
        </label>
      </section>

      {error && (
        <p role="alert" className="rounded-lg border border-danger/30 bg-danger/10 px-3 py-2 text-xs text-danger">
          {apiError(error)}
        </p>
      )}

      <section aria-labelledby="kc-title">
        <h3 id="kc-title" className="mb-2 text-xs font-semibold uppercase tracking-wide text-fg-subtle">Kill chain</h3>
        <KillChain tactics={data.tactics} />
      </section>

      <section aria-labelledby="entities-title">
        <h3 id="entities-title" className="mb-2 text-xs font-semibold uppercase tracking-wide text-fg-subtle">Entities</h3>
        <ul className="flex flex-wrap gap-1.5">
          {data.entities.map((e) => (
            <li key={entityLabel(e)}>
              {onEntity && e.kind !== 'signature' ? (
                <button
                  onClick={() => onEntity(entityLabel(e))}
                  title="Show every incident involving this entity"
                  className="rounded-md border border-line bg-surface-2 px-2 py-1 font-mono text-xs text-fg hover:border-accent hover:text-accent-text"
                >
                  <span className="text-fg-subtle">{e.kind}:</span>{e.value}
                </button>
              ) : (
                <span className="rounded-md border border-line bg-surface-2 px-2 py-1 font-mono text-xs text-fg">
                  <span className="text-fg-subtle">{e.kind}:</span>{e.value}
                </span>
              )}
            </li>
          ))}
        </ul>
      </section>

      <section aria-labelledby="timeline-title">
        <h3 id="timeline-title" className="mb-2 text-xs font-semibold uppercase tracking-wide text-fg-subtle">Timeline</h3>
        <form
          className="mb-4 flex gap-2"
          onSubmit={(e) => { e.preventDefault(); if (comment.trim()) addComment.mutate(comment.trim()) }}
        >
          <label className="sr-only" htmlFor="incident-comment">Add a comment</label>
          <textarea
            id="incident-comment"
            rows={2}
            value={comment}
            onChange={(e) => setComment(e.target.value)}
            placeholder="Add a note: findings, actions taken, next steps…"
            className={`${fieldClass} flex-1 resize-y`}
          />
          <button
            type="submit"
            disabled={!comment.trim() || addComment.isPending}
            className="self-end rounded-lg bg-accent px-3 py-2 text-sm font-medium text-on-accent hover:bg-accent-strong disabled:opacity-40"
          >
            Comment
          </button>
        </form>
        <ol className="space-y-2" aria-label="Incident timeline">
          {timeline(data).map((item) => item.type === 'alert'
            ? <AlertItem key={item.key} alert={item.alert} />
            : (
              <ActivityItem
                key={item.key}
                activity={item.activity}
                onRate={item.activity.id === latestInvestigation?.id && !rate.isSuccess ? (h) => rate.mutate(h) : undefined}
              />
            ))}
        </ol>
      </section>
    </article>
  )
}

function AlertItem({ alert }: { alert: IncidentAlert }) {
  return (
    <li className="rounded-xl border border-line bg-surface p-3 shadow-card">
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={alert.severity} size="sm" />
        <span className="text-sm font-medium text-fg">{alert.attack_type}</span>
        {alert.tactic && alert.tactic !== 'N/A' && <span className="text-[11px] text-fg-muted">{alert.tactic}</span>}
        <time className="ml-auto text-[11px] text-fg-subtle" dateTime={alert.at}>{timeAgo(alert.at)}</time>
      </div>
      {alert.summary && <p className="mt-1 text-xs text-fg-muted">{alert.summary}</p>}
      <pre className="mt-2 overflow-x-auto whitespace-pre-wrap break-all rounded-md bg-fg/4 p-2 font-mono text-[11px] text-fg-muted">{alert.raw}</pre>
      {alert.rules && alert.rules.length > 0 && (
        <p className="mt-1 text-[11px] text-fg-subtle">Rules: {alert.rules.join(', ')}</p>
      )}
    </li>
  )
}

function ActivityItem({ activity, onRate }: { activity: IncidentActivity; onRate?: (helpful: boolean) => void }) {
  const Icon = ACTIVITY_ICONS[activity.kind] ?? MessageSquare
  const long = activity.kind === 'comment' || activity.kind === 'investigation'
  return (
    <li className={`flex gap-2.5 rounded-xl p-3 ${long ? 'border border-line bg-surface shadow-card' : ''}`}>
      <Icon size={15} className={`mt-0.5 shrink-0 ${activity.kind === 'investigation' ? 'text-info' : 'text-fg-subtle'}`} aria-hidden="true" />
      <div className="min-w-0 flex-1">
        <p className="text-xs text-fg-muted">
          <span className="font-medium text-fg">{activity.actor}</span>
          {activity.kind === 'investigation' ? ' completed an AI investigation' : activity.kind === 'comment' ? ' commented' : ''}
          {' · '}
          <time dateTime={activity.at}>{timeAgo(activity.at)}</time>
        </p>
        <p className={`mt-0.5 break-words text-sm ${long ? 'whitespace-pre-wrap text-fg' : 'text-fg-muted'}`}>{activity.body}</p>
        {onRate && (
          <div className="mt-2 flex items-center gap-2 text-xs text-fg-muted">
            Was this investigation helpful?
            <button onClick={() => onRate(true)} className="inline-flex items-center gap-1 rounded-md border border-line px-2 py-1 hover:border-success/40 hover:text-success">
              <ThumbsUp size={12} aria-hidden="true" /> Helpful
            </button>
            <button onClick={() => onRate(false)} className="inline-flex items-center gap-1 rounded-md border border-line px-2 py-1 hover:border-danger/40 hover:text-danger">
              <ThumbsDown size={12} aria-hidden="true" /> Not helpful
            </button>
          </div>
        )}
      </div>
    </li>
  )
}
