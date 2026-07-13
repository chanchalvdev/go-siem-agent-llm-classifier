import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import { MITREHeatmap } from '../components/MITREHeatmap'
import type { ClassifiedEvent } from '../lib/api'
import type { Severity } from '../styles/tokens'

function evt(tactic: string, severity: Severity, iso: string): ClassifiedEvent {
  return {
    severity, attack_type: 'Brute Force', confidence: 0.9,
    mitre: { tactic, technique_id: 'T1110', technique: 'Brute Force' },
    iocs: [], remediation: '', summary: 's',
    event: { raw: '', timestamp: iso, message: '', source: 'syslog' },
    processed_at: iso,
  }
}

describe('MITREHeatmap', () => {
  it('shows a placeholder when there are no events', () => {
    render(<MITREHeatmap events={[]} />)
    expect(screen.getByText(/No events to chart/)).toBeInTheDocument()
  })

  it('renders the tactic rows and a total count', () => {
    const events = [
      evt('Credential Access', 'P1', '2026-07-06T10:00:00Z'),
      evt('Execution', 'P3', '2026-07-06T10:00:00Z'),
    ]
    render(<MITREHeatmap events={events} />)
    expect(screen.getByText('Credential Access')).toBeInTheDocument()
    expect(screen.getByText(/2 events/)).toBeInTheDocument()
  })

  it('fires onSelect when a populated cell is clicked', () => {
    const onSelect = vi.fn()
    const events = [evt('Impact', 'P2', '2026-07-06T10:00:00Z')]
    render(<MITREHeatmap events={events} onSelect={onSelect} />)
    // The populated cell carries a title with the tactic name.
    fireEvent.click(screen.getByTitle(/Impact ·/))
    expect(onSelect).toHaveBeenCalled()
  })
})
