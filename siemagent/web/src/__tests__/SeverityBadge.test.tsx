import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { SeverityBadge, SEVERITY_LABELS } from '../components/SeverityBadge'

describe('SeverityBadge', () => {
  it('renders "Critical" text for P1', () => {
    render(<SeverityBadge severity="P1" />)
    expect(screen.getByText(/Critical/)).toBeInTheDocument()
  })

  it('renders correct label for each severity', () => {
    const severities = ['P1', 'P2', 'P3', 'P4', 'P5'] as const
    for (const sev of severities) {
      const { unmount } = render(<SeverityBadge severity={sev} />)
      expect(screen.getByText(new RegExp(SEVERITY_LABELS[sev]))).toBeInTheDocument()
      unmount()
    }
  })

  it('applies the P1 (critical red) severity colour token', () => {
    const { container } = render(<SeverityBadge severity="P1" />)
    const badge = container.firstChild as HTMLElement
    // Severity colours are theme tokens (red in both themes for P1).
    expect(badge.className).toMatch(/text-sev-p1/)
    const { container: low } = render(<SeverityBadge severity="P4" />)
    expect((low.firstChild as HTMLElement).className).not.toMatch(/sev-p1/)
  })

  it('applies pulse animation class for P1', () => {
    const { container } = render(<SeverityBadge severity="P1" />)
    const badge = container.firstChild as HTMLElement
    expect(badge.className).toContain('severity-pulse')
  })

  it('does NOT apply pulse animation for P3', () => {
    const { container } = render(<SeverityBadge severity="P3" />)
    const badge = container.firstChild as HTMLElement
    expect(badge.className).not.toContain('severity-pulse')
  })

  it('renders sm size with smaller padding classes', () => {
    const { container } = render(<SeverityBadge severity="P2" size="sm" />)
    const badge = container.firstChild as HTMLElement
    expect(badge.className).toContain('text-[10px]')
  })

  it('renders md size with larger padding classes', () => {
    const { container } = render(<SeverityBadge severity="P2" size="md" />)
    const badge = container.firstChild as HTMLElement
    expect(badge.className).toContain('text-xs')
  })
})
