import type { Severity } from '../styles/tokens'
import { SEVERITY_LABELS } from '../styles/tokens'

// Re-exported so consumers (Search page, tests) can pull labels from the badge.
export { SEVERITY_LABELS } from '../styles/tokens'

const SEVERITY_STYLES: Record<Severity, string> = {
  P1: 'bg-red-500/15 text-red-400 border-red-500/30',
  P2: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  P3: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  P4: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  P5: 'bg-gray-500/15 text-gray-400 border-gray-500/30',
}

const DOT_STYLES: Record<Severity, string> = {
  P1: 'bg-red-400',
  P2: 'bg-orange-400',
  P3: 'bg-yellow-400',
  P4: 'bg-blue-400',
  P5: 'bg-gray-400',
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
      ${sizeClass} ${SEVERITY_STYLES[severity]}
      ${severity === 'P1' ? 'severity-pulse' : ''}
    `}>
      <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${DOT_STYLES[severity]}`} />
      {severity} · {SEVERITY_LABELS[severity]}
    </span>
  )
}
