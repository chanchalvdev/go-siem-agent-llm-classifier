interface Props {
  tactic: string
  technique: string
}

// Top-20 most common ATT&CK technique names (ID → short name)
const TECHNIQUE_NAMES: Record<string, string> = {
  'T1059':     'Command and Scripting Interpreter',
  'T1059.001': 'PowerShell',
  'T1059.003': 'Windows Command Shell',
  'T1078':     'Valid Accounts',
  'T1110':     'Brute Force',
  'T1110.001': 'Password Guessing',
  'T1110.003': 'Password Spraying',
  'T1190':     'Exploit Public-Facing Application',
  'T1566':     'Phishing',
  'T1566.001': 'Spearphishing Attachment',
  'T1021':     'Remote Services',
  'T1021.001': 'Remote Desktop Protocol',
  'T1053':     'Scheduled Task/Job',
  'T1055':     'Process Injection',
  'T1082':     'System Information Discovery',
  'T1083':     'File and Directory Discovery',
  'T1105':     'Ingress Tool Transfer',
  'T1486':     'Data Encrypted for Impact',
  'T1548':     'Abuse Elevation Control Mechanism',
  'T1562':     'Impair Defenses',
}

function techniqueURL(id: string): string {
  // T1110.001 → https://attack.mitre.org/techniques/T1110/001/
  const [base, sub] = id.split('.')
  return sub
    ? `https://attack.mitre.org/techniques/${base}/${sub}/`
    : `https://attack.mitre.org/techniques/${id}/`
}

export function MITREBadge({ tactic, technique }: Props) {
  const noTactic = !tactic || tactic === 'none' || tactic === 'N/A'
  const noTechnique = !technique || technique === 'none' || technique === 'N/A'

  if (noTactic && noTechnique) return null

  const tooltipName = TECHNIQUE_NAMES[technique]

  return (
    <span className="inline-flex items-center gap-1.5 flex-wrap">
      {!noTactic && (
        <span className="text-xs bg-surface-2 text-fg-muted px-2 py-0.5 rounded border border-line-strong">
          {tactic}
        </span>
      )}
      {!noTechnique && (
        <a
          href={techniqueURL(technique)}
          target="_blank"
          rel="noopener noreferrer"
          title={tooltipName ?? technique}
          className="text-xs font-mono text-accent-text hover:text-accent-text bg-surface-2 px-2 py-0.5 rounded border border-line-strong hover:border-accent transition-colors"
        >
          {technique}
        </a>
      )}
    </span>
  )
}
