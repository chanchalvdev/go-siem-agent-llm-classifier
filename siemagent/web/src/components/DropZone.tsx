import { useRef, useState, useCallback } from 'react'
import { Upload, CheckCircle } from 'lucide-react'
import { classifyLog } from '../lib/api'
import type { ClassifiedEvent } from '../lib/api'

interface Props {
  onResults: (events: ClassifiedEvent[]) => void
}

export function DropZone({ onResults }: Props) {
  const inputRef = useRef<HTMLInputElement>(null)
  const [dragging, setDragging] = useState(false)
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null)
  const [toast, setToast] = useState<string | null>(null)

  const process = useCallback(async (file: File) => {
    const text = await file.text()
    const lines = text.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'))
    if (!lines.length) return

    const total = lines.length
    setProgress({ done: 0, total })
    const BATCH = 5
    const results: ClassifiedEvent[] = []

    for (let i = 0; i < lines.length; i += BATCH) {
      const batch = lines.slice(i, i + BATCH)
      const settled = await Promise.allSettled(batch.map(l => classifyLog(l)))
      for (const res of settled) {
        if (res.status === 'fulfilled') results.push(res.value)
      }
      setProgress({ done: Math.min(i + BATCH, total), total })
    }

    onResults(results)
    setProgress(null)
    const p1 = results.filter(r => r.severity === 'P1').length
    const p2 = results.filter(r => r.severity === 'P2').length
    setToast(`${results.length} classified — ${p1} Critical, ${p2} High`)
    setTimeout(() => setToast(null), 5000)
  }, [onResults])

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setDragging(false)
    const file = e.dataTransfer.files[0]
    if (file) process(file)
  }, [process])

  const handleChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) process(file)
    e.target.value = ''
  }, [process])

  return (
    <div className="relative shrink-0">
      <button
        type="button"
        onClick={() => inputRef.current?.click()}
        onDragOver={e => { e.preventDefault(); setDragging(true) }}
        onDragLeave={() => setDragging(false)}
        onDrop={handleDrop}
        className={`
          flex items-center gap-2 px-3 py-2 rounded-lg border border-dashed text-sm transition-all
          ${dragging
            ? 'border-accent bg-accent/10 text-accent-text'
            : 'border-line-strong hover:border-fg/25 text-fg-subtle hover:text-fg-muted'
          }
        `}
      >
        <Upload size={14} />
        {progress ? (
          <span className="text-xs text-accent-text">
            {progress.done}/{progress.total}
          </span>
        ) : (
          <span className="hidden sm:inline text-xs">Upload</span>
        )}
        {progress && (
          <div className="w-16 h-1 bg-fg/10 rounded-full overflow-hidden">
            <div
              className="h-full bg-accent-strong rounded-full transition-all"
              style={{ width: `${(progress.done / progress.total) * 100}%` }}
            />
          </div>
        )}
      </button>

      <input ref={inputRef} type="file" accept=".log,.txt" className="hidden" onChange={handleChange} />

      {toast && (
        <div className="absolute top-full mt-2 left-0 z-50 flex items-center gap-2 bg-surface border border-line-strong text-xs text-fg px-3 py-2 rounded-xl shadow-xl whitespace-nowrap">
          <CheckCircle size={12} className="text-success shrink-0" />
          {toast}
        </div>
      )}
    </div>
  )
}
