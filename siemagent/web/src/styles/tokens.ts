export type Severity = 'P1' | 'P2' | 'P3' | 'P4' | 'P5'

// Theme-aware severity colours for inline `style` on HTML elements. For SVG
// charts use useChartColors(), which resolves concrete values.
export const SEVERITY_COLORS: Record<Severity, string> = {
  P1: 'rgb(var(--sev-p1))',
  P2: 'rgb(var(--sev-p2))',
  P3: 'rgb(var(--sev-p3))',
  P4: 'rgb(var(--sev-p4))',
  P5: 'rgb(var(--sev-p5))',
}

export const SEVERITY_LABELS: Record<Severity, string> = {
  P1: 'Critical',
  P2: 'High',
  P3: 'Medium',
  P4: 'Low',
  P5: 'Info',
}

// Full class strings (not built dynamically) so Tailwind can see them.
export const SEVERITY_BG: Record<Severity, string> = {
  P1: 'bg-sev-p1/10 text-sev-p1 border-sev-p1/30',
  P2: 'bg-sev-p2/10 text-sev-p2 border-sev-p2/30',
  P3: 'bg-sev-p3/10 text-sev-p3 border-sev-p3/30',
  P4: 'bg-sev-p4/10 text-sev-p4 border-sev-p4/30',
  P5: 'bg-sev-p5/10 text-sev-p5 border-sev-p5/30',
}

export const SEVERITY_BORDER: Record<Severity, string> = {
  P1: 'border-l-sev-p1',
  P2: 'border-l-sev-p2',
  P3: 'border-l-sev-p3',
  P4: 'border-l-sev-p4',
  P5: 'border-l-sev-p5',
}
