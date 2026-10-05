import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, it, expect, vi } from 'vitest'
import { EventCard } from '../components/EventCard'
import type { ClassifiedEvent } from '../lib/api'

const mockEvent: ClassifiedEvent = {
  attack_type: 'Brute Force',
  severity: 'P2',
  confidence: 0.9,
  summary: 'Multiple failed SSH login attempts detected from 192.168.1.100.',
  remediation: 'Block the source IP.',
  iocs: ['192.168.1.100'],
  mitre: {
    tactic: 'Credential Access',
    technique_id: 'T1110.001',
    technique: 'Password Guessing',
  },
  event: {
    raw: '<165>1 2024-01-15T10:30:00Z webserver sshd 1 - msg',
    timestamp: '2024-01-15T10:30:00Z',
    hostname: 'webserver',
    app_name: 'sshd',
    message: 'Failed password for root',
    source: 'syslog',
  },
  processed_at: new Date().toISOString(),
}

describe('EventCard', () => {
  it('calls onClick when card is clicked', async () => {
    const onClick = vi.fn()
    render(<EventCard event={mockEvent} onClick={onClick} selected={false} />)
    await userEvent.click(screen.getByRole('button'))
    expect(onClick).toHaveBeenCalledOnce()
  })

  it('shows severity badge', () => {
    render(<EventCard event={mockEvent} onClick={() => {}} selected={false} />)
    expect(screen.getByText(/High/)).toBeInTheDocument()
  })

  it('shows attack type', () => {
    render(<EventCard event={mockEvent} onClick={() => {}} selected={false} />)
    expect(screen.getByText('Brute Force')).toBeInTheDocument()
  })

  it('shows truncated summary', () => {
    render(<EventCard event={mockEvent} onClick={() => {}} selected={false} />)
    // Summary is 56 chars so fits within 80 char limit — should appear as-is
    expect(screen.getByText(/Multiple failed SSH login attempts/)).toBeInTheDocument()
  })

  it('adds ring class when selected', () => {
    const { container } = render(<EventCard event={mockEvent} onClick={() => {}} selected={true} />)
    const card = container.firstChild as HTMLElement
    expect(card.className).toMatch(/ring/)
  })

  it('does not have ring class when not selected', () => {
    const { container } = render(<EventCard event={mockEvent} onClick={() => {}} selected={false} />)
    const card = container.firstChild as HTMLElement
    expect(card.className).not.toMatch(/ring-1/)
  })

  it('shows match score badge when score prop is provided', () => {
    render(<EventCard event={mockEvent} onClick={() => {}} selected={false} score={92} />)
    expect(screen.getByText(/92% match/)).toBeInTheDocument()
  })

  it('marks suppressed events', () => {
    render(<EventCard event={{ ...mockEvent, suppressed_by: 'SUP-1' }} onClick={() => {}} selected={false} />)
    expect(screen.getByText('Suppressed')).toHaveAttribute('title', expect.stringContaining('SUP-1'))
  })

  it('shows no suppressed badge on normal events', () => {
    render(<EventCard event={mockEvent} onClick={() => {}} selected={false} />)
    expect(screen.queryByText('Suppressed')).not.toBeInTheDocument()
  })

  it('does not show match score when score prop is absent', () => {
    render(<EventCard event={mockEvent} onClick={() => {}} selected={false} />)
    expect(screen.queryByText(/% match/)).not.toBeInTheDocument()
  })
})
