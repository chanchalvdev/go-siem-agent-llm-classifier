import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import type { Watchlist } from '../lib/api'
import { renderWithQuery } from '../test/render'
import { AuthContext } from '../auth/auth'

const now = new Date().toISOString()
const manual: Watchlist = {
  id: 'WL-1', name: 'Case 42 C2', source: 'manual', severity: 'P1', enabled: true, created_at: now, count: 2, hits: 3, last_hit: now,
}
const feed: Watchlist = {
  id: 'WL-2', name: 'Feodo', source: 'feed', url: 'https://feeds.example/ip.txt', severity: 'P2', enabled: true,
  created_at: now, count: 500, hits: 0, last_fetched: now, error: 'feed answered HTTP 503',
}
const file: Watchlist = { id: 'file:tor.list', name: 'tor', source: 'file', severity: 'P3', enabled: false, created_at: now, count: 10, hits: 0 }

const api = vi.hoisted(() => ({
  listWatchlists: vi.fn(),
  createWatchlist: vi.fn(),
  updateWatchlist: vi.fn(),
  deleteWatchlist: vi.fn(),
  refreshWatchlist: vi.fn(),
  listIndicators: vi.fn(),
  addIndicators: vi.fn(),
  removeIndicator: vi.fn(),
  lookupIOC: vi.fn(),
  apiError: (e: unknown) => (e instanceof Error ? e.message : String(e)),
}))
vi.mock('../lib/api', () => api)

const { Watchlists } = await import('../pages/Watchlists')

const ctx = (role: 'admin' | 'analyst' | 'viewer') => ({
  me: { username: role, role, auth: 'session' as const, permissions: { read: true, write: role !== 'viewer', admin: role === 'admin' } },
  can: (p: string) => p === 'read' || (p === 'write' && role !== 'viewer') || (p === 'admin' && role === 'admin'),
  signOut: () => {},
})
const render = (role: 'admin' | 'analyst' | 'viewer') =>
  renderWithQuery(<AuthContext.Provider value={ctx(role)}><Watchlists /></AuthContext.Provider>)

beforeEach(() => {
  vi.clearAllMocks()
  api.listWatchlists.mockResolvedValue([manual, feed, file])
  api.listIndicators.mockResolvedValue({ total: 2, indicators: [
    { value: '203.0.113.9', type: 'ip', note: 'phishing', added_by: 'ana' },
    { value: '198.51.100.0/24', type: 'cidr' },
  ] })
  api.addIndicators.mockResolvedValue({ added: [], rejected: ['junk!'] })
  api.removeIndicator.mockResolvedValue(undefined)
  api.updateWatchlist.mockResolvedValue(manual)
  api.refreshWatchlist.mockResolvedValue(feed)
  api.createWatchlist.mockResolvedValue(feed)
  api.lookupIOC.mockResolvedValue([])
})

describe('Watchlists page', () => {
  it('summarises lists and shows feed errors', async () => {
    render('viewer')
    const lists = await screen.findByRole('list', { name: 'Watchlists' })
    expect(within(lists).getByText('Case 42 C2')).toBeInTheDocument()
    expect(within(lists).getByText(/500 indicators/)).toBeInTheDocument()
    expect(within(lists).getByText(/Last download failed: feed answered HTTP 503/)).toBeInTheDocument()
    // Disabled lists don't count towards indicators in use.
    expect(screen.getByText('Indicators in use').nextSibling).toHaveTextContent('502')
    expect(screen.getByText('Matches since start').nextSibling).toHaveTextContent('3')
  })

  it('viewers can browse but not change anything', async () => {
    render('viewer')
    await screen.findByRole('list', { name: 'Watchlists' })
    expect(screen.queryByRole('button', { name: 'Add watchlist' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Disable' })).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /Case 42 C2/ }))
    expect(await screen.findByRole('list', { name: 'Indicators of Case 42 C2' })).toBeInTheDocument()
    expect(screen.queryByRole('form', { name: 'Add indicators to Case 42 C2' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Remove 203.0.113.9' })).not.toBeInTheDocument()
  })

  it('analysts add and remove indicators on manual lists', async () => {
    render('analyst')
    fireEvent.click(await screen.findByRole('button', { name: /Case 42 C2/ }))
    const form = await screen.findByRole('form', { name: 'Add indicators to Case 42 C2' })
    fireEvent.change(within(form).getByLabelText(/Indicators/), { target: { value: 'evil.example\n203.0.113.10, junk!' } })
    fireEvent.change(within(form).getByLabelText('Note'), { target: { value: 'INC-1' } })
    fireEvent.click(within(form).getByRole('button', { name: 'Add' }))
    await waitFor(() => expect(api.addIndicators).toHaveBeenCalledWith('WL-1', ['evil.example', '203.0.113.10', 'junk!'], 'INC-1'))
    expect(await within(form).findByText('junk!')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Remove 198.51.100.0/24' }))
    await waitFor(() => expect(api.removeIndicator).toHaveBeenCalledWith('WL-1', '198.51.100.0/24'))

    // Feeds are read-only even for analysts.
    fireEvent.click(screen.getByRole('button', { name: /Feodo/ }))
    await waitFor(() => expect(api.listIndicators).toHaveBeenCalledWith('WL-2', 200))
    expect(screen.queryByRole('form', { name: 'Add indicators to Feodo' })).not.toBeInTheDocument()
  })

  it('admins add a feed, refresh, re-grade and disable lists', async () => {
    render('admin')
    fireEvent.click(await screen.findByRole('button', { name: 'Add watchlist' }))
    const form = screen.getByRole('form', { name: 'Add a watchlist' })
    fireEvent.change(within(form).getByLabelText('Name'), { target: { value: 'URLhaus' } })
    fireEvent.change(within(form).getByLabelText('Source'), { target: { value: 'feed' } })
    fireEvent.change(within(form).getByLabelText(/Feed URL/), { target: { value: 'https://urlhaus.example/hostfile' } })
    fireEvent.change(within(form).getByLabelText(/Refresh every/), { target: { value: '1' } })
    fireEvent.change(within(form).getByLabelText('Severity of a match'), { target: { value: 'P3' } })
    fireEvent.click(within(form).getByRole('button', { name: 'Add watchlist' }))
    await waitFor(() => expect(api.createWatchlist).toHaveBeenCalledWith({
      name: 'URLhaus', source: 'feed', severity: 'P3', url: 'https://urlhaus.example/hostfile', refresh_seconds: 3600,
    }))

    fireEvent.click(screen.getByRole('button', { name: 'Refresh Feodo' }))
    await waitFor(() => expect(api.refreshWatchlist).toHaveBeenCalledWith('WL-2'))
    fireEvent.change(screen.getByLabelText('Severity of Case 42 C2'), { target: { value: 'P2' } })
    await waitFor(() => expect(api.updateWatchlist).toHaveBeenCalledWith('WL-1', { severity: 'P2' }))
    // File lists can be disabled but not deleted (they live on disk).
    expect(screen.queryByRole('button', { name: 'Delete tor' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Delete Feodo' })).toBeInTheDocument()
  })

  it('checks a single indicator', async () => {
    api.lookupIOC.mockResolvedValue([{ watchlist_id: 'WL-1', watchlist: 'Case 42 C2', indicator: '198.51.100.0/24', severity: 'P1' }])
    render('viewer')
    fireEvent.change(await screen.findByLabelText('IP, domain, hash or URL'), { target: { value: '198.51.100.7' } })
    fireEvent.click(screen.getByRole('button', { name: 'Check' }))
    expect(await screen.findByRole('status')).toHaveTextContent('Listed on Case 42 C2 (P1, via 198.51.100.0/24)')
  })
})
