import type { DetectionLevel } from './api'

// Sigma rule levels share the severity palette: critical ≈ P1 … informational ≈ P5.
export const LEVEL_STYLES: Record<DetectionLevel, string> = {
  critical: 'bg-sev-p1/10 text-sev-p1 border-sev-p1/30',
  high: 'bg-sev-p2/10 text-sev-p2 border-sev-p2/30',
  medium: 'bg-sev-p3/10 text-sev-p3 border-sev-p3/30',
  low: 'bg-sev-p4/10 text-sev-p4 border-sev-p4/30',
  informational: 'bg-sev-p5/10 text-sev-p5 border-sev-p5/30',
}
