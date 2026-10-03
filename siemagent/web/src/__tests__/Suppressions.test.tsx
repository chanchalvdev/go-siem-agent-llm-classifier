import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import type { Suppression } from '../lib/api'
import { renderWithQuery } from '../test/render'
import { AuthContext } from '../auth/auth'

const now = Date.now()
const iso = (offsetMs: number) => new Date(now + offsetMs).toISOString()

const active: Suppression = {
  id: 'SUP-AAAA', entity: { kind: 'ip', value: '203.0.113.9' }, reason: 'authorised pentest',
  created_by: 'ana', created_at: iso(-3_600_000), expires_at: iso(86_400_000), hits: 42, last_hit: iso(-60_000),
}
const forever: Suppression = {
  id: 'SUP-BBBB', rule_id: 'port-scan', attack_type: 'Port Scan', reason: 'internal scanner',
  created_by: 'ada', created_at: iso(-7_200_000), hits: 1,
}
const expired: Suppression = {
  id: 'SUP-CCCC', entity: { kind: 'host', value: 'build01' }, reason: 'maintenance',
  created_by: 'ana', created_at: iso(-90_000_000), expires_at: iso(-3_600_000), hits: 0,
}

const api = vi.hoisted(() => ({
  listSuppressions: vi.fn(),
  createSuppression: vi.fn(),
  liftSuppression: vi.fn(),
  apiError: (e: unknown) => (e instanceof Error ? e.message : String(e)),
}))
vi.mock('../lib/api', () => api)

const { Suppressions } = await import('../pages/Suppressions')

const viewer = {
  me: { username: 'vic', role: 'viewer' as const, auth: 'session' as const, permissions: { read: true, write: false, admin: false } },
  can: (p: string) => p === 'read',
  signOut: () => {},
}

beforeEach(() => {
  vi.clearAllMocks()
  api.listSuppressions.mockResolvedValue([active, forever, expired])
  api.createSuppression.mockResolvedValue(active)
  api.liftSuppression.mockResolvedValue(undefined)
})

describe('Suppressions page', () => {
  it('splits active and expired and totals the hits', async () => {
    renderWithQuery(<Suppressions />)
    const activeList = await screen.findByRole('list', { name: 'Active suppressions' })
    expect(within(activeList).getByText('ip:203.0.113.9')).toBeInTheDocument()
    expect(within(activeList).getByText('rule port-scan + Port Scan')).toBeInTheDocument()
    expect(within(activeList).getByText(/until lifted/)).toBeInTheDocument()
    expect(within(activeList).getByText(/42 hits/)).toBeInTheDocument()
    const expiredList = screen.getByRole('list', { name: 'Expired suppressions' })
    expect(within(expiredList).getByText('host:build01')).toBeInTheDocument()
    expect(within(expiredList).getByText(/expired/)).toBeInTheDocument()
    expect(screen.getByText('Suppressed events since start').nextSibling).toHaveTextContent('43')
  })

  it('creates a suppression from the form', async () => {
    renderWithQuery(<Suppressions />)
    const form = await screen.findByRole('form', { name: 'Snooze alerts' })
    fireEvent.change(within(form).getByLabelText('Attack type'), { target: { value: 'Port Scan' } })
    fireEvent.change(within(form).getByLabelText('For'), { target: { value: '' } })
    fireEvent.change(within(form).getByLabelText('Reason'), { target: { value: 'our scanner' } })
    fireEvent.click(within(form).getByRole('button', { name: 'Snooze' }))
    await waitFor(() => expect(api.createSuppression).toHaveBeenCalledWith({
      entity: undefined, rule_id: undefined, attack_type: 'Port Scan', reason: 'our scanner', duration: '', incident_id: undefined,
    }))
  })

  it('shows the server error', async () => {
    api.createSuppression.mockRejectedValue(new Error('set at least one of entity, rule_id or attack_type'))
    renderWithQuery(<Suppressions />)
    const form = await screen.findByRole('form', { name: 'Snooze alerts' })
    fireEvent.change(within(form).getByLabelText('Reason'), { target: { value: 'x' } })
    fireEvent.click(within(form).getByRole('button', { name: 'Snooze' }))
    expect(await within(form).findByRole('alert')).toHaveTextContent('set at least one')
  })

  it('lifts a suppression', async () => {
    renderWithQuery(<Suppressions />)
    fireEvent.click(await screen.findByRole('button', { name: 'Lift SUP-AAAA' }))
    await waitFor(() => expect(api.liftSuppression).toHaveBeenCalledWith('SUP-AAAA', expect.anything()))
  })

  it('is read-only for viewers', async () => {
    renderWithQuery(<AuthContext.Provider value={viewer}><Suppressions /></AuthContext.Provider>)
    await screen.findByRole('list', { name: 'Active suppressions' })
    expect(screen.queryByRole('form', { name: 'Snooze alerts' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^Lift/ })).not.toBeInTheDocument()
  })
})
