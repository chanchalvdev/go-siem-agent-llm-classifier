import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import type { AuditEntry, User } from '../lib/api'
import { renderWithQuery } from '../test/render'
import { AuthContext } from '../auth/auth'

const now = new Date().toISOString()
const users: User[] = [
  { id: 'usr_ada', username: 'ada', role: 'admin', disabled: false, created_at: now, last_login_at: now },
  { id: 'usr_vic', username: 'vic', display_name: 'Victor', role: 'viewer', disabled: false, created_at: now },
]
const audit: AuditEntry[] = [
  { id: 2, at: now, actor: 'ada', action: 'PATCH /api/users/{id}', target: '/api/users/usr_vic', status: 200, ip: '10.0.0.1' },
  { id: 1, at: now, actor: 'vic', action: 'login.failed', ip: '10.0.0.2' },
]

const api = vi.hoisted(() => ({
  listUsers: vi.fn(),
  createUser: vi.fn(),
  updateUser: vi.fn(),
  listAudit: vi.fn(),
  getRetention: vi.fn(),
  apiError: (e: unknown) => (e instanceof Error ? e.message : String(e)),
}))
vi.mock('../lib/api', () => api)

const { Users } = await import('../pages/Users')
const { Audit } = await import('../pages/Audit')

const adminCtx = {
  me: { username: 'ada', role: 'admin' as const, auth: 'session' as const, id: 'usr_ada', permissions: { read: true, write: true, admin: true } },
  can: () => true,
  signOut: () => {},
}

beforeEach(() => {
  vi.clearAllMocks()
  api.listUsers.mockResolvedValue(users)
  api.createUser.mockResolvedValue(users[1])
  api.updateUser.mockResolvedValue(users[1])
  api.listAudit.mockResolvedValue(audit)
  api.getRetention.mockResolvedValue({ active: false, events_days: 0, incidents_days: 0, audit_days: 0, last_run: null })
})

describe('Users page', () => {
  it('lists users and protects your own account', async () => {
    renderWithQuery(<AuthContext.Provider value={adminCtx}><Users /></AuthContext.Provider>)
    expect(await screen.findByText('Victor')).toBeInTheDocument()
    const list = screen.getByRole('list', { name: 'Users' })
    expect(within(list).getByText('never logged in')).toBeInTheDocument()
    const rows = within(list).getAllByRole('listitem')
    expect(within(rows[0]).getByText('you')).toBeInTheDocument()
    expect(within(rows[0]).getByRole('button', { name: 'Disable' })).toBeDisabled()
  })

  it('adds a user', async () => {
    renderWithQuery(<AuthContext.Provider value={adminCtx}><Users /></AuthContext.Provider>)
    const form = await screen.findByRole('form', { name: 'Add a user' })
    fireEvent.change(within(form).getByLabelText('Username'), { target: { value: 'neo' } })
    fireEvent.change(within(form).getByLabelText(/Initial password/), { target: { value: 'a long enough password' } })
    fireEvent.change(within(form).getByLabelText('Role'), { target: { value: 'viewer' } })
    fireEvent.click(within(form).getByRole('button', { name: 'Add user' }))
    await waitFor(() => expect(api.createUser).toHaveBeenCalledWith({ username: 'neo', display_name: '', password: 'a long enough password', role: 'viewer' }))
  })

  it('changes a role, disables and resets a password', async () => {
    renderWithQuery(<AuthContext.Provider value={adminCtx}><Users /></AuthContext.Provider>)
    fireEvent.change(await screen.findByLabelText('Role of vic'), { target: { value: 'analyst' } })
    await waitFor(() => expect(api.updateUser).toHaveBeenCalledWith('usr_vic', { role: 'analyst' }))
    const rows = screen.getAllByRole('listitem')
    fireEvent.click(within(rows[1]).getByRole('button', { name: 'Disable' }))
    await waitFor(() => expect(api.updateUser).toHaveBeenCalledWith('usr_vic', { disabled: true }))
    fireEvent.click(within(rows[1]).getByRole('button', { name: 'Reset password' }))
    fireEvent.change(screen.getByLabelText('New password for vic'), { target: { value: 'reset to this one' } })
    fireEvent.click(screen.getByRole('button', { name: 'Set' }))
    await waitFor(() => expect(api.updateUser).toHaveBeenCalledWith('usr_vic', { password: 'reset to this one' }))
  })

  it('shows a refused change', async () => {
    api.updateUser.mockRejectedValueOnce(new Error('this is the last active admin; make another user admin first'))
    renderWithQuery(<AuthContext.Provider value={adminCtx}><Users /></AuthContext.Provider>)
    fireEvent.change(await screen.findByLabelText('Role of ada'), { target: { value: 'viewer' } })
    expect(await screen.findByRole('alert')).toHaveTextContent('last active admin')
  })
})

describe('Audit page', () => {
  it('lists entries and filters by user', async () => {
    renderWithQuery(<Audit />)
    const table = await screen.findByRole('table', { name: 'Audit log entries' })
    expect(await within(table).findByText('PATCH /api/users/{id}')).toBeInTheDocument()
    expect(within(table).getByText('login.failed')).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('Filter by user'), { target: { value: 'vic' } })
    await waitFor(() => expect(api.listAudit).toHaveBeenCalledWith({ actor: 'vic', limit: 300 }))
  })
})
