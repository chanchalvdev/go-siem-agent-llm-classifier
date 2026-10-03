import { useState } from 'react'
import type { Incident as IncidentData } from '../hooks/useAlertStream'
import { ThreatIntelPanel } from '../components/ThreatIntelPanel'

interface Props {
  incident?: IncidentData
  onClose?: () => void
}

const STATUS_CHIP: Record<IncidentData['status'], string> = {
  investigating: 'bg-warning/10 text-warning',
  complete: 'bg-success/10 text-success',
  failed: 'bg-danger/10 text-danger',
}

export function Incident({ incident, onClose }: Props) {
  const [copied, setCopied] = useState(false)

  if (!incident) {
    return <p className="p-6 text-sm text-fg-subtle">Select an incident to view its investigation.</p>
  }

  const copy = () => {
    navigator.clipboard?.writeText(incident.playbook)
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  return (
    <div className="flex flex-col gap-4 p-4 lg:flex-row">
      {/* Left: tool timeline + threat intel */}
      <aside className="lg:w-2/5">
        <div className="mb-2 flex items-center gap-2">
          <span className="font-mono text-sm text-fg">Incident {incident.id}</span>
          <span className={`rounded px-2 py-0.5 text-xs font-semibold ${STATUS_CHIP[incident.status]}`}>
            {incident.status}
          </span>
          {onClose && (
            <button onClick={onClose} className="ml-auto text-xs text-fg-subtle hover:text-fg-muted">
              close
            </button>
          )}
        </div>
        <h3 className="mb-1 text-xs uppercase tracking-wide text-fg-subtle">Investigation</h3>
        <ol className="mb-4 space-y-2">
          {incident.tools.map((t, i) => (
            <li key={i} className="rounded-lg border border-line-strong bg-fg/4 p-2">
              <details>
                <summary className="cursor-pointer font-mono text-xs text-accent-text">{t.name}</summary>
                <pre className="mt-1 whitespace-pre-wrap break-all text-[11px] text-fg-muted">
                  {t.input}
                  {t.result ? `\n→ ${t.result}` : ''}
                </pre>
              </details>
            </li>
          ))}
        </ol>
        <h3 className="mb-1 text-xs uppercase tracking-wide text-fg-subtle">Threat Intel</h3>
        <ThreatIntelPanel tools={incident.tools} />
      </aside>

      {/* Right: streaming playbook */}
      <section className="lg:w-3/5">
        <div className="mb-2 flex items-center">
          <h3 className="text-xs uppercase tracking-wide text-fg-subtle">Playbook</h3>
          <button onClick={copy} className="ml-auto rounded border border-line-strong px-2 py-1
            text-xs text-fg-muted hover:border-fg/20">
            {copied ? 'Copied' : 'Copy Playbook'}
          </button>
        </div>
        <pre className="whitespace-pre-wrap rounded-lg border border-line-strong bg-surface-2 p-3
          text-sm leading-relaxed text-fg">
          {incident.playbook || 'Synthesizing playbook…'}
        </pre>
      </section>
    </div>
  )
}
