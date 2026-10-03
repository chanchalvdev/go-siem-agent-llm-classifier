import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, screen, waitFor } from '@testing-library/react'
import { AxiosError, AxiosHeaders } from 'axios'
import type { Me } from '../lib/api'
import { renderWithQuery } from '../test/render'

function unauthorized() {
  const headers = new AxiosHeaders()
  return new AxiosError('401', 'ERR_BAD_REQUEST', { headers }, null, {
    status: 401, statusText: 'Unauthorized', headers: {}, config: { headers }, data: { error: 'authentication required' },
  })
}

const ana: Me = { username: 'ana', role: 'analyst', auth: 'session', id: 'usr_1', permissions: { read: true, write: true, admin: false } }

const api = vi.hoisted(() => ({
  getMe: vi.fn(),
  login: vi.fn(),
  logout: vi.fn(),
  apiError: (e: unknown) => (e instanceof Error ? e.message : String(e)),
  SESSION_EXPIRED_EVENT: 'siem:session-expired',
}))
vi.mock('../lib/api', () => api)

const { AuthGate } = await import('../auth/AuthGate')
const { useAuth } = await import('../auth/auth')

function Who() {
  const { me, can, signOut } = useAuth()
  return (
    <div>
      <p>signed in as {me.username}</p>
      <p>{can('admin') ? 'admin' : 'not admin'}</p>
      <button onClick={signOut}>out</button>
    </div>
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  api.logout.mockResolvedValue(undefined)
})

describe('AuthGate', () => {
  it('asks for a login, then shows the app', async () => {
    api.getMe.mockRejectedValueOnce(unauthorized()).mockResolvedValue(ana)
    api.login.mockResolvedValue(undefined)
    renderWithQuery(<AuthGate><Who /></AuthGate>)

    expect(await screen.findByRole('heading', { name: 'Sign in to SIEMAgent' })).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'ana' } })
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'correct horse battery' } })
    fireEvent.click(screen.getByRole('button', { name: 'Sign in' }))

    await waitFor(() => expect(api.login).toHaveBeenCalledWith('ana', 'correct horse battery'))
    expect(await screen.findByText('signed in as ana')).toBeInTheDocument()
    expect(screen.getByText('not admin')).toBeInTheDocument()
  })

  it('shows a failed login', async () => {
    api.getMe.mockRejectedValue(unauthorized())
    api.login.mockRejectedValue(new Error('invalid username or password'))
    renderWithQuery(<AuthGate><Who /></AuthGate>)
    fireEvent.change(await screen.findByLabelText('Username'), { target: { value: 'ana' } })
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'nope' } })
    fireEvent.click(screen.getByRole('button', { name: 'Sign in' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('invalid username or password')
  })

  it('goes back to the login when the session expires', async () => {
    api.getMe.mockResolvedValueOnce(ana).mockRejectedValue(unauthorized())
    renderWithQuery(<AuthGate><Who /></AuthGate>)
    await screen.findByText('signed in as ana')
    window.dispatchEvent(new Event('siem:session-expired'))
    expect(await screen.findByRole('heading', { name: 'Sign in to SIEMAgent' })).toBeInTheDocument()
  })

  it('signs out', async () => {
    api.getMe.mockResolvedValueOnce(ana).mockRejectedValue(unauthorized())
    renderWithQuery(<AuthGate><Who /></AuthGate>)
    fireEvent.click(await screen.findByRole('button', { name: 'out' }))
    await waitFor(() => expect(api.logout).toHaveBeenCalled())
    expect(await screen.findByRole('heading', { name: 'Sign in to SIEMAgent' })).toBeInTheDocument()
  })
})

function serverError(status?: number) {
  const headers = new AxiosHeaders()
  const res = status ? { status, statusText: '', headers: {}, config: { headers }, data: {} } : undefined
  return new AxiosError('down', status ? 'ERR_BAD_RESPONSE' : 'ERR_NETWORK', { headers }, null, res)
}

describe('AuthGate when the backend is down', () => {
  it('explains instead of showing the login, and recovers on retry', async () => {
    api.getMe.mockRejectedValueOnce(serverError(502)).mockResolvedValue(ana)
    renderWithQuery(<AuthGate><Who /></AuthGate>)
    expect(await screen.findByRole('heading', { name: 'Cannot reach the SIEMAgent backend' })).toBeInTheDocument()
    expect(screen.queryByLabelText('Username')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Retry now' }))
    expect(await screen.findByText('signed in as ana')).toBeInTheDocument()
  })

  it('names an outdated backend', async () => {
    api.getMe.mockRejectedValue(serverError(404))
    renderWithQuery(<AuthGate><Who /></AuthGate>)
    expect(await screen.findByRole('heading', { name: 'The backend is running an older version' })).toBeInTheDocument()
  })
})
