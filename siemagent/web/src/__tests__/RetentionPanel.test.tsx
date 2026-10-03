import { beforeEach, describe, expect, it, vi } from 'vitest'
import { screen } from '@testing-library/react'
import type { RetentionStatus } from '../lib/api'
import { renderWithQuery } from '../test/render'

const api = vi.hoisted(() => ({ getRetention: vi.fn() }))
vi.mock('../lib/api', () => api)

const { RetentionPanel } = await import('../components/RetentionPanel')

beforeEach(() => vi.clearAllMocks())

describe('RetentionPanel', () => {
  it('explains that memory mode keeps nothing', async () => {
    api.getRetention.mockResolvedValue({ active: false, events_days: 0, incidents_days: 0, audit_days: 0, last_run: null })
    renderWithQuery(<RetentionPanel />)
    expect(await screen.findByText(/cleared on restart/)).toBeInTheDocument()
  })

  it('shows the policy and the last run', async () => {
    const status: RetentionStatus = {
      active: true,
      events_days: 30,
      incidents_days: 0,
      audit_days: 730,
      interval_seconds: 3600,
      last_run: { at: new Date().toISOString(), deleted: { events: 4, audit: 1, sessions: 1 } },
    }
    api.getRetention.mockResolvedValue(status)
    renderWithQuery(<RetentionPanel />)
    expect(await screen.findByText('30 days')).toBeInTheDocument()
    expect(screen.getByText('Forever')).toBeInTheDocument()
    expect(screen.getByText('2 years')).toBeInTheDocument()
    expect(screen.getByText(/removed 5 records and 1 expired session\./)).toBeInTheDocument()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('flags a failed purge', async () => {
    api.getRetention.mockResolvedValue({
      active: true, events_days: 30, incidents_days: 0, audit_days: 0,
      last_run: { at: new Date().toISOString(), deleted: {}, errors: { events: 'boom' } },
    })
    renderWithQuery(<RetentionPanel />)
    expect(await screen.findByRole('alert')).toHaveTextContent('Purge failed for events')
  })
})
