import type { Severity } from '../styles/tokens'
import { SEVERITY_BG, SEVERITY_LABELS } from '../styles/tokens'

// Re-exported so consumers (Search page, tests) can pull labels from the badge.
export { SEVERITY_LABELS } from '../styles/tokens'

const DOT_STYLES: Record<Severity, string> = {
  P1: 'bg-sev-p1',
  P2: 'bg-sev-p2',
  P3: 'bg-sev-p3',
  P4: 'bg-sev-p4',
  P5: 'bg-sev-p5',
}

interface Props {
  severity: Severity
  size?: 'sm' | 'md'
}

export function SeverityBadge({ severity, size = 'md' }: Props) {
  const sizeClass = size === 'sm'
    ? 'text-[10px] px-1.5 py-0.5 gap-1'
    : 'text-xs px-2 py-1 gap-1.5'

  return (
    <span className={`
      inline-flex items-center font-mono font-semibold rounded-md border
      ${sizeClass} ${SEVERITY_BG[severity]}
      ${severity === 'P1' ? 'severity-pulse' : ''}
    `}>
      <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${DOT_STYLES[severity]}`} />
      {severity} · {SEVERITY_LABELS[severity]}
    </span>
  )
}
