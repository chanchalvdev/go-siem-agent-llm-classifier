import type { ToolInvocation } from '../hooks/useAlertStream'

interface Props {
  tools: ToolInvocation[]
}

interface AbuseCard {
  ip: string
  abuse_score?: number
  country?: string
  isp?: string
  total_reports?: number
  note?: string
}

interface OTXCard {
  indicator: string
  pulse_count?: number
  threat_labels?: string[]
  note?: string
}

function parse<T>(raw?: string): T | null {
  if (!raw) return null
  try {
    return JSON.parse(raw) as T
  } catch {
    return null
  }
}

// scoreClass maps an abuse confidence score to a traffic-light badge that
// keeps readable contrast in both themes.
function scoreClass(score = 0): string {
  if (score >= 75) return 'bg-danger/10 text-danger border-danger/30'
  if (score >= 25) return 'bg-warning/10 text-warning border-warning/30'
  return 'bg-success/10 text-success border-success/30'
}

export function ThreatIntelPanel({ tools }: Props) {
  const abuse = tools.filter((t) => t.name === 'check_abuseipdb').map((t) => parse<AbuseCard>(t.result))
  const otx = tools.filter((t) => t.name === 'check_otx').map((t) => parse<OTXCard>(t.result))
  const cards = [...abuse, ...otx].filter(Boolean)

  if (cards.length === 0) {
    return <p className="text-sm text-fg-subtle italic">No external threat intel</p>
  }

  return (
    <div className="grid gap-3 sm:grid-cols-2">
      {abuse.map((c, i) =>
        c && (
          <div key={`a${i}`} className="rounded-lg border border-line-strong bg-fg/4 p-3">
            <div className="flex items-center justify-between">
              <span className="font-mono text-sm text-fg">{c.ip}</span>
              {c.note ? (
                <span className="text-xs text-fg-subtle">{c.note}</span>
              ) : (
                <span className={`rounded border px-2 py-0.5 text-xs font-semibold ${scoreClass(c.abuse_score)}`}>
                  {c.abuse_score ?? 0}% abuse
                </span>
              )}
            </div>
            {!c.note && (
              <p className="mt-1 text-xs text-fg-muted">
                {c.country} · {c.isp} · {c.total_reports ?? 0} reports
              </p>
            )}
          </div>
        ),
      )}
      {otx.map((c, i) =>
        c && (
          <div key={`o${i}`} className="rounded-lg border border-line-strong bg-fg/4 p-3">
            <div className="flex items-center justify-between">
              <span className="font-mono text-sm text-fg">{c.indicator}</span>
              <span className="text-xs text-fg-muted">{c.pulse_count ?? 0} pulses</span>
            </div>
            <div className="mt-1 flex flex-wrap gap-1">
              {(c.threat_labels ?? []).slice(0, 6).map((label) => (
                <span key={label} className="rounded bg-info/10 px-1.5 py-0.5 text-[10px] text-info">
                  {label}
                </span>
              ))}
            </div>
          </div>
        ),
      )}
    </div>
  )
}
