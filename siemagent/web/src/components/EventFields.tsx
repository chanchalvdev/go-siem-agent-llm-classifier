// EventFields lists an event's normalised fields (source.ip, user.name, …),
// grouped by their first segment so related values sit together.
export function EventFields({ fields }: { fields?: Record<string, string> }) {
  const entries = Object.entries(fields ?? {}).sort(([a], [b]) => a.localeCompare(b))
  if (entries.length === 0) return null
  return (
    <div>
      <p className="mb-2 text-[10px] uppercase tracking-widest text-fg-subtle">Fields</p>
      <dl aria-label="Normalised fields" className="grid grid-cols-[minmax(0,auto)_1fr] gap-x-3 gap-y-1 rounded-xl border border-line bg-surface-2 p-3 text-xs">
        {entries.map(([k, v]) => (
          <div key={k} className="contents">
            <dt className="font-mono text-fg-subtle">{k}</dt>
            <dd className="min-w-0 break-all font-mono text-fg">{v}</dd>
          </div>
        ))}
      </dl>
    </div>
  )
}
