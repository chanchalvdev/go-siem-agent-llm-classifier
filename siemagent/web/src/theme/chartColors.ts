import { useMemo } from 'react'
import { useTheme } from './theme'

// SVG presentation attributes (what Recharts writes) cannot read CSS
// variables, so charts get concrete colours resolved from the active theme.
// Recomputed whenever the theme changes so charts redraw in the new palette.

function token(name: string, fallback: string): string {
  if (typeof window === 'undefined') return fallback
  const raw = getComputedStyle(document.documentElement).getPropertyValue(`--${name}`).trim()
  return raw ? `rgb(${raw.split(/\s+/).join(', ')})` : fallback
}

export interface ChartColors {
  grid: string
  axis: string
  text: string
  tooltipBg: string
  tooltipBorder: string
  tooltipText: string
  severity: Record<'P1' | 'P2' | 'P3' | 'P4' | 'P5', string>
  series: string[]
}

export function useChartColors(): ChartColors {
  const { resolved } = useTheme()
  return useMemo(() => {
    const dark = resolved === 'dark'
    return {
      grid: token('line', dark ? '#202940' : '#e2e7ee'),
      axis: token('line-strong', dark ? '#2f3a56' : '#cbd3de'),
      text: token('fg-subtle', dark ? '#7c8ba3' : '#5c6a80'),
      tooltipBg: token('surface', dark ? '#0f1629' : '#ffffff'),
      tooltipBorder: token('line-strong', dark ? '#2f3a56' : '#cbd3de'),
      tooltipText: token('fg', dark ? '#f1f5f9' : '#0f172a'),
      severity: {
        P1: token('sev-p1', '#dc2626'),
        P2: token('sev-p2', '#c2410c'),
        P3: token('sev-p3', '#a16207'),
        P4: token('sev-p4', '#2563eb'),
        P5: token('sev-p5', '#64748b'),
      },
      // Categorical palette, tuned per theme for contrast against the surface.
      series: dark
        ? ['#60a5fa', '#a78bfa', '#f472b6', '#f87171', '#fb923c', '#facc15', '#34d399', '#22d3ee']
        : ['#2563eb', '#7c3aed', '#db2777', '#dc2626', '#ea580c', '#ca8a04', '#059669', '#0891b2'],
    }
    // `resolved` is the trigger: the class on <html> has already changed.
  }, [resolved])
}
