import { useQuery } from '@tanstack/react-query'
import { Check, Copy, Download, X } from 'lucide-react'
import { useState } from 'react'
import { getIncidentReport } from '../lib/api'

// IncidentReport previews the Markdown incident report with copy and download.
export function IncidentReport({ id, onClose }: { id: string; onClose: () => void }) {
  const { data, isLoading, isError } = useQuery({ queryKey: ['incident-report', id], queryFn: () => getIncidentReport(id) })
  const [copied, setCopied] = useState(false)

  function download() {
    if (!data) return
    const url = URL.createObjectURL(new Blob([data], { type: 'text/markdown' }))
    const a = document.createElement('a')
    a.href = url
    a.download = `${id}-report.md`
    a.click()
    URL.revokeObjectURL(url)
  }

  async function copy() {
    if (!data) return
    try {
      await navigator.clipboard.writeText(data)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      // Clipboard can be blocked; download still works.
    }
  }

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="report-title"
      className="fixed inset-0 z-50 flex items-start justify-center overflow-auto bg-overlay/50 p-4 backdrop-blur-sm"
      onKeyDown={(e) => { if (e.key === 'Escape') onClose() }}
    >
      <div className="w-full max-w-4xl rounded-xl border border-line-strong bg-surface shadow-pop">
        <header className="flex items-center gap-2 border-b border-line px-4 py-3">
          <h2 id="report-title" className="flex-1 text-sm font-semibold text-fg">Incident report · {id}</h2>
          <button
            onClick={copy}
            disabled={!data}
            className="inline-flex items-center gap-1.5 rounded-lg border border-line px-2.5 py-1.5 text-xs text-fg-muted hover:bg-fg/4 hover:text-fg disabled:opacity-40"
          >
            {copied ? <Check size={13} /> : <Copy size={13} />} {copied ? 'Copied' : 'Copy'}
          </button>
          <button
            onClick={download}
            disabled={!data}
            className="inline-flex items-center gap-1.5 rounded-lg bg-accent px-2.5 py-1.5 text-xs font-medium text-on-accent hover:bg-accent-strong disabled:opacity-40"
          >
            <Download size={13} /> Download .md
          </button>
          <button onClick={onClose} aria-label="Close report" autoFocus className="rounded-lg p-1.5 text-fg-subtle hover:bg-fg/4 hover:text-fg">
            <X size={16} />
          </button>
        </header>
        <div className="max-h-[75vh] overflow-auto p-4">
          {isLoading ? (
            <p className="text-sm text-fg-subtle">Building report…</p>
          ) : isError ? (
            <p className="text-sm text-danger">Could not build the report.</p>
          ) : (
            <pre className="whitespace-pre-wrap break-words font-mono text-xs leading-relaxed text-fg">{data}</pre>
          )}
        </div>
      </div>
    </div>
  )
}
