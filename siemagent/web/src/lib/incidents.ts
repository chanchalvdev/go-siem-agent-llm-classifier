import type { Entity, IncidentStatus } from './api'

export const STATUS_LABELS: Record<IncidentStatus, string> = {
  new: 'New',
  investigating: 'Investigating',
  resolved: 'Resolved',
}

export const STATUS_STYLES: Record<IncidentStatus, string> = {
  new: 'border-info/30 bg-info/10 text-info',
  investigating: 'border-warning/30 bg-warning/10 text-warning',
  resolved: 'border-success/30 bg-success/10 text-success',
}

// ATT&CK enterprise tactics in matrix order (mirrors mitre.KillChain in Go).
export const KILL_CHAIN = [
  'Reconnaissance',
  'Resource Development',
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact',
]

export function entityLabel(e: Entity): string {
  return `${e.kind}:${e.value}`
}
