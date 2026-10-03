import { KILL_CHAIN } from '../lib/incidents'

// KillChain shows how far an attack progressed: every ATT&CK tactic in order,
// with the ones this incident reached highlighted.
export function KillChain({ tactics }: { tactics: string[] }) {
  const reached = new Set(tactics.map((t) => t.toLowerCase()))
  const furthest = KILL_CHAIN.reduce((n, t, i) => (reached.has(t.toLowerCase()) ? i : n), -1)
  return (
    <div>
      <p className="mb-2 text-xs text-fg-muted">
        {reached.size === 0
          ? 'No ATT&CK tactics identified yet.'
          : `Reached ${reached.size} of ${KILL_CHAIN.length} tactics; furthest: ${KILL_CHAIN[furthest] ?? 'unknown'}.`}
      </p>
      <ol className="grid grid-cols-2 sm:grid-cols-7 gap-1" aria-label="MITRE ATT&CK kill chain">
        {KILL_CHAIN.map((t, i) => {
          const hit = reached.has(t.toLowerCase())
          return (
            <li
              key={t}
              aria-current={hit ? 'step' : undefined}
              title={t}
              className={`rounded-md border px-1.5 py-1 text-[10px] leading-tight ${
                hit
                  ? 'border-danger/40 bg-danger/10 font-semibold text-danger'
                  : i < furthest
                    ? 'border-line bg-fg/3 text-fg-muted'
                    : 'border-line text-fg-subtle'
              }`}
            >
              <span className="sr-only">{hit ? 'Reached: ' : 'Not reached: '}</span>
              {t}
            </li>
          )
        })}
      </ol>
    </div>
  )
}
