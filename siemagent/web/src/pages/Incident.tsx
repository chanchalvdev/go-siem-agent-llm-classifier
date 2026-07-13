import { useState } from 'react'
import type { Incident as IncidentData } from '../hooks/useAlertStream'
import { ThreatIntelPanel } from '../components/ThreatIntelPanel'

interface Props {
  incident?: IncidentData
  onClose?: () => void
}

const STATUS_CHIP: Record<IncidentData['status'], string> = {
  investigating: 'bg-orange-500/15 text-orange-300',
  complete: 'bg-green-500/15 text-green-300',
  failed: 'bg-red-500/15 text-red-300',
}

export function Incident({ incident, onClose }: Props) {
  const [copied, setCopied] = useState(false)

  if (!incident) {
    return <p className="p-6 text-sm text-gray-500">Select an incident to view its investigation.</p>
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
          <span className="font-mono text-sm text-gray-200">Incident {incident.id}</span>
          <span className={`rounded px-2 py-0.5 text-xs font-semibold ${STATUS_CHIP[incident.status]}`}>
            {incident.status}
          </span>
          {onClose && (
            <button onClick={onClose} className="ml-auto text-xs text-gray-500 hover:text-gray-300">
              close
            </button>
          )}
        </div>
        <h3 className="mb-1 text-xs uppercase tracking-wide text-gray-500">Investigation</h3>
        <ol className="mb-4 space-y-2">
          {incident.tools.map((t, i) => (
            <li key={i} className="rounded-lg border border-white/10 bg-white/5 p-2">
              <details>
                <summary className="cursor-pointer font-mono text-xs text-blue-300">{t.name}</summary>
                <pre className="mt-1 whitespace-pre-wrap break-all text-[11px] text-gray-400">
                  {t.input}
                  {t.result ? `\n→ ${t.result}` : ''}
                </pre>
              </details>
            </li>
          ))}
        </ol>
        <h3 className="mb-1 text-xs uppercase tracking-wide text-gray-500">Threat Intel</h3>
        <ThreatIntelPanel tools={incident.tools} />
      </aside>

      {/* Right: streaming playbook */}
      <section className="lg:w-3/5">
        <div className="mb-2 flex items-center">
          <h3 className="text-xs uppercase tracking-wide text-gray-500">Playbook</h3>
          <button onClick={copy} className="ml-auto rounded border border-white/10 px-2 py-1
            text-xs text-gray-300 hover:border-white/20">
            {copied ? 'Copied' : 'Copy Playbook'}
          </button>
        </div>
        <pre className="whitespace-pre-wrap rounded-lg border border-white/10 bg-black/30 p-3
          text-sm leading-relaxed text-gray-200">
          {incident.playbook || 'Synthesizing playbook…'}
        </pre>
      </section>
    </div>
  )
}
