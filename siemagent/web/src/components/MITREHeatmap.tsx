import { useMemo } from 'react'
import type { ClassifiedEvent } from '../lib/api'
import type { Severity } from '../styles/tokens'
import { SEVERITY_COLORS } from '../styles/tokens'

// Kill-chain order, Reconnaissance → Impact.
const TACTICS = [
  'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
  'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
  'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
  'Exfiltration', 'Impact',
] as const

const DAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'] as const
const SEV_RANK: Severity[] = ['P5', 'P4', 'P3', 'P2', 'P1']

interface Cell {
  count: number
  severity: Severity
}

interface Props {
  events: ClassifiedEvent[]
  onSelect?: (tactic: string, weekday: number) => void
}

// worse returns the higher-priority (more severe) of two severities.
function worse(a: Severity, b: Severity): Severity {
  return SEV_RANK.indexOf(a) >= SEV_RANK.indexOf(b) ? a : b
}

// buildGrid tallies events into a tactic × weekday matrix.
function buildGrid(events: ClassifiedEvent[]): Map<string, Cell> {
  const grid = new Map<string, Cell>()
  let max = 0
  for (const ev of events) {
    const tactic = ev.mitre?.tactic
    if (!tactic || !TACTICS.includes(tactic as (typeof TACTICS)[number])) continue
    const weekday = (new Date(ev.processed_at).getDay() + 6) % 7 // Mon=0
    const key = `${tactic}|${weekday}`
    const cell = grid.get(key) ?? { count: 0, severity: 'P5' as Severity }
    cell.count += 1
    cell.severity = worse(cell.severity, ev.severity)
    grid.set(key, cell)
    max = Math.max(max, cell.count)
  }
  grid.set('__max__', { count: max, severity: 'P5' })
  return grid
}

export function MITREHeatmap({ events, onSelect }: Props) {
  const grid = useMemo(() => buildGrid(events), [events])
  const max = grid.get('__max__')?.count ?? 0

  if (events.length === 0) {
    return <p className="text-sm text-gray-500 italic">No events to chart yet.</p>
  }

  return (
    <div className="overflow-x-auto">
      <div className="inline-grid gap-1" style={{ gridTemplateColumns: `minmax(9rem,auto) repeat(7,1.5rem)` }}>
        <div />
        {DAYS.map((d) => (
          <div key={d} className="text-center text-[10px] text-gray-500">{d}</div>
        ))}
        {TACTICS.map((tactic) => (
          <div key={tactic} className="contents">
            <div className="truncate pr-2 text-[11px] text-gray-400" title={tactic}>{tactic}</div>
            {DAYS.map((_, day) => {
              const cell = grid.get(`${tactic}|${day}`)
              const opacity = cell && max ? 0.15 + 0.85 * (cell.count / max) : 0
              return (
                <button
                  key={day}
                  onClick={() => cell && onSelect?.(tactic, day)}
                  title={cell ? `${tactic} · ${DAYS[day]}: ${cell.count} (${cell.severity})` : ''}
                  className="h-6 w-6 rounded-sm border border-white/5"
                  style={{ background: cell ? SEVERITY_COLORS[cell.severity] : 'transparent', opacity: opacity || 1 }}
                />
              )
            })}
          </div>
        ))}
      </div>
      <p className="mt-2 text-xs text-gray-500">{events.length} events · colour = highest severity, opacity = volume</p>
    </div>
  )
}
