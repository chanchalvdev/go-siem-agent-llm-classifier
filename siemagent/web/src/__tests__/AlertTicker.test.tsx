import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import { AlertTicker } from '../components/AlertTicker'
import type { Incident } from '../hooks/useAlertStream'

const base: Incident = { id: 'abc', eventId: 'e1', status: 'investigating', tools: [], playbook: '' }

describe('AlertTicker', () => {
  it('renders nothing when there are no incidents', () => {
    const { container } = render(<AlertTicker incidents={[]} onSelect={() => {}} />)
    expect(container.firstChild).toBeNull()
  })

  it('shows Investigating for an in-progress incident', () => {
    render(<AlertTicker incidents={[base]} onSelect={() => {}} />)
    expect(screen.getByText(/Investigating/)).toBeInTheDocument()
  })

  it('shows Playbook ready and fires onSelect when complete incident clicked', () => {
    const onSelect = vi.fn()
    render(<AlertTicker incidents={[{ ...base, status: 'complete' }]} onSelect={onSelect} />)
    expect(screen.getByText(/Playbook ready/)).toBeInTheDocument()
    fireEvent.click(screen.getByText(/Playbook ready/))
    expect(onSelect).toHaveBeenCalledWith('abc')
  })
})
