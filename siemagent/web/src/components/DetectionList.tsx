import { ShieldCheck } from 'lucide-react'
import type { Detection, DetectionLevel } from '../lib/api'

const LEVEL_STYLES: Record<DetectionLevel, string> = {
  critical: 'bg-sev-p1/10 text-sev-p1 border-sev-p1/30',
  high: 'bg-sev-p2/10 text-sev-p2 border-sev-p2/30',
  medium: 'bg-sev-p3/10 text-sev-p3 border-sev-p3/30',
  low: 'bg-sev-p4/10 text-sev-p4 border-sev-p4/30',
  informational: 'bg-sev-p5/10 text-sev-p5 border-sev-p5/30',
}

// ATT&CK tags ("attack.t1490", "attack.impact") are shown on the MITRE card;
// only other tags (e.g. CVEs) are listed here.
function extraTags(tags: string[] = []): string[] {
  return tags.filter((t) => !t.startsWith('attack.'))
}

export function DetectionList({ detections }: { detections: Detection[] }) {
  if (detections.length === 0) return null
  return (
    <ul className="space-y-2" aria-label="Matched detection rules">
      {detections.map((d) => (
        <li key={d.rule_id} className="flex items-start gap-2.5 rounded-xl border border-line bg-surface p-3 shadow-card">
          <ShieldCheck size={15} className="mt-0.5 shrink-0 text-accent-text" aria-hidden="true" />
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-sm font-medium text-fg">{d.title}</span>
              <span className={`rounded border px-1.5 py-0.5 font-mono text-[10px] font-semibold uppercase ${LEVEL_STYLES[d.level] ?? LEVEL_STYLES.medium}`}>
                {d.level}
              </span>
            </div>
            <p className="mt-0.5 truncate font-mono text-[10px] text-fg-subtle" title={d.rule_id}>{d.rule_id}</p>
            {extraTags(d.tags).length > 0 && (
              <p className="mt-1 text-[10px] text-fg-muted">{extraTags(d.tags).join(' · ')}</p>
            )}
          </div>
        </li>
      ))}
    </ul>
  )
}

// Compact marker for event cards: shows when a rule produced or confirmed the verdict.
export function RuleBadge({ classifiedBy }: { classifiedBy?: string }) {
  if (classifiedBy !== 'rules' && classifiedBy !== 'llm+rules') return null
  const label = classifiedBy === 'rules' ? 'Rule' : 'Rule + AI'
  return (
    <span
      className="inline-flex items-center gap-1 rounded-full border border-accent/30 bg-accent/10 px-1.5 py-0.5 text-[10px] font-medium text-accent-text"
      title={classifiedBy === 'rules' ? 'Classified by a detection rule (no AI call)' : 'AI verdict confirmed by a detection rule'}
    >
      <ShieldCheck size={10} aria-hidden="true" />
      {label}
    </span>
  )
}
