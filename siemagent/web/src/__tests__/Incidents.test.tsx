import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import type { Incident, IncidentDetail, IncidentStats } from '../lib/api'
import { renderWithQuery } from '../test/render'

const now = new Date().toISOString()

const open: Incident = {
  id: 'INC-AAAA0001', title: 'SSH Brute Force from 203.0.113.7', severity: 'P2', status: 'new',
  entities: [{ kind: 'ip', value: '203.0.113.7' }, { kind: 'host', value: 'web01' }],
  tactics: ['Credential Access'], techniques: ['T1110.001'], alert_count: 12,
  first_seen: now, last_seen: now, created_at: now, updated_at: now,
}
const resolved: Incident = { ...open, id: 'INC-BBBB0002', title: 'Port Scan from 198.51.100.4', status: 'resolved', severity: 'P3', assignee: 'alice' }

const detail: IncidentDetail = {
  ...open,
  alerts: [{
    id: 1, incident_id: open.id, at: now, severity: 'P2', attack_type: 'SSH Brute Force', summary: '10 failures',
    tactic: 'Credential Access', raw: 'sshd: Failed password for root from 203.0.113.7', entities: [], rules: ['SSH Brute Force'],
  }],
  activity: [
    { id: 2, incident_id: open.id, at: now, actor: 'system', kind: 'created', body: 'Opened from P2 alert: SSH Brute Force' },
    { id: 3, incident_id: open.id, at: now, actor: 'ai-agent', kind: 'investigation', body: '## Summary\nBlock the IP.' },
  ],
}

const stats: IncidentStats = {
  open: 1, by_status: { new: 1, resolved: 1 }, open_by_severity: { P2: 1 }, resolved: 1, false_positive: 0, mttr_seconds: 5400,
}

const api = vi.hoisted(() => ({
  listIncidents: vi.fn(),
  getIncidentStats: vi.fn(),
  getIncident: vi.fn(),
  updateIncident: vi.fn(),
  addIncidentComment: vi.fn(),
  investigateIncident: vi.fn(),
  getIncidentReport: vi.fn(),
  rateInvestigation: vi.fn(),
  listActions: vi.fn(),
  listPlaybooks: vi.fn(),
  runPlaybook: vi.fn(),
  approveAction: vi.fn(),
  rejectAction: vi.fn(),
  apiError: (e: unknown) => (e instanceof Error ? e.message : String(e)),
}))
vi.mock('../lib/api', () => api)

const { Incidents } = await import('../pages/Incidents')

beforeEach(() => {
  vi.clearAllMocks()
  api.listIncidents.mockImplementation(async (f: { status?: string; entity?: string }) => {
    if (f.status) return [open, resolved].filter((i) => i.status === f.status)
    return [open, resolved]
  })
  api.getIncidentStats.mockResolvedValue(stats)
  api.getIncident.mockResolvedValue(detail)
  api.updateIncident.mockResolvedValue({ ...open, status: 'investigating' })
  api.investigateIncident.mockResolvedValue(undefined)
  api.listActions.mockResolvedValue([])
  api.listPlaybooks.mockResolvedValue([])
  api.getIncidentReport.mockResolvedValue('# Incident report: SSH Brute Force\n\n## AI investigation')
  api.rateInvestigation.mockResolvedValue({ id: 10, incident_id: open.id, at: now, actor: 'analyst', kind: 'feedback', body: 'x' })
  api.addIncidentComment.mockResolvedValue({ id: 9, incident_id: open.id, at: now, actor: 'analyst', kind: 'comment', body: 'x' })
})

describe('Incidents page', () => {
  it('shows queue stats and only open incidents by default', async () => {
    renderWithQuery(<Incidents />)
    const list = await screen.findByRole('list', { name: 'Incidents' })
    expect(within(list).getAllByRole('listitem')).toHaveLength(1)
    expect(within(list).getByText(open.title)).toBeInTheDocument()
    expect(screen.getByText('Mean time to resolve').nextSibling).toHaveTextContent('1h 30m')
    expect(screen.getByText('Open P1 / P2').nextSibling).toHaveTextContent('1')

    fireEvent.click(screen.getByRole('button', { name: 'Resolved' }))
    await waitFor(() => expect(api.listIncidents).toHaveBeenCalledWith(expect.objectContaining({ status: 'resolved' })))
    expect(await screen.findByText(resolved.title)).toBeInTheDocument()
  })

  it('opens an incident with kill chain, timeline and AI investigation', async () => {
    renderWithQuery(<Incidents />)
    fireEvent.click(await screen.findByText(open.title))
    expect(await screen.findByRole('heading', { name: open.title })).toBeInTheDocument()
    expect(screen.getByText(/Reached 1 of 14 tactics/)).toBeInTheDocument()
    const timeline = screen.getByRole('list', { name: 'Incident timeline' })
    expect(within(timeline).getByText(/completed an AI investigation/)).toBeInTheDocument()
    expect(within(timeline).getByText('sshd: Failed password for root from 203.0.113.7')).toBeInTheDocument()
    expect(within(timeline).getByText('Rules: SSH Brute Force')).toBeInTheDocument()
  })

  it('changes status, assigns and comments', async () => {
    renderWithQuery(<Incidents />)
    fireEvent.click(await screen.findByText(open.title))
    await screen.findByRole('heading', { name: open.title })

    fireEvent.change(screen.getByLabelText('Status'), { target: { value: 'investigating' } })
    await waitFor(() => expect(api.updateIncident).toHaveBeenCalledWith(open.id, { status: 'investigating' }))

    const assignee = screen.getByLabelText('Assignee')
    fireEvent.change(assignee, { target: { value: '  bob ' } })
    fireEvent.blur(assignee)
    await waitFor(() => expect(api.updateIncident).toHaveBeenCalledWith(open.id, { assignee: 'bob' }))

    expect(screen.getByLabelText('Resolution')).toBeDisabled()

    fireEvent.change(screen.getByLabelText('Add a comment'), { target: { value: 'Blocked at firewall' } })
    fireEvent.click(screen.getByRole('button', { name: 'Comment' }))
    await waitFor(() => expect(api.addIncidentComment).toHaveBeenCalledWith(open.id, 'Blocked at firewall'))
  })

  it('shows the server error when an update is rejected', async () => {
    api.updateIncident.mockRejectedValueOnce(new Error('set status to resolved to record a resolution'))
    renderWithQuery(<Incidents />)
    fireEvent.click(await screen.findByText(open.title))
    await screen.findByRole('heading', { name: open.title })
    fireEvent.change(screen.getByLabelText('Status'), { target: { value: 'resolved' } })
    expect(await screen.findByRole('alert')).toHaveTextContent('set status to resolved')
  })

  it('filters by an entity from the detail view', async () => {
    renderWithQuery(<Incidents />)
    fireEvent.click(await screen.findByText(open.title))
    fireEvent.click(await screen.findByRole('button', { name: 'ip:203.0.113.7' }))
    await waitFor(() => expect(api.listIncidents).toHaveBeenCalledWith(expect.objectContaining({ entity: 'ip:203.0.113.7' })))
    expect(screen.getByRole('button', { name: 'Clear filter ip:203.0.113.7' })).toBeInTheDocument()
  })
})

describe('Incident AI actions', () => {
  it('starts an investigation on demand', async () => {
    renderWithQuery(<Incidents />)
    fireEvent.click(await screen.findByText(open.title))
    fireEvent.click(await screen.findByRole('button', { name: 'Investigate with AI' }))
    await waitFor(() => expect(api.investigateIncident).toHaveBeenCalledWith(open.id))
    expect(await screen.findByRole('status')).toHaveTextContent('Investigation started')
  })

  it('previews the report', async () => {
    renderWithQuery(<Incidents />)
    fireEvent.click(await screen.findByText(open.title))
    fireEvent.click(await screen.findByRole('button', { name: 'Report' }))
    const dialog = await screen.findByRole('dialog', { name: `Incident report · ${open.id}` })
    expect(await within(dialog).findByText(/# Incident report: SSH Brute Force/)).toBeInTheDocument()
    expect(within(dialog).getByRole('button', { name: 'Download .md' })).toBeEnabled()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Close report' }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('rates the latest AI investigation', async () => {
    renderWithQuery(<Incidents />)
    fireEvent.click(await screen.findByText(open.title))
    fireEvent.click(await screen.findByRole('button', { name: 'Not helpful' }))
    await waitFor(() => expect(api.rateInvestigation).toHaveBeenCalledWith(open.id, false))
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Not helpful' })).not.toBeInTheDocument())
  })
})

describe('Incident detail for viewers', () => {
  it('hides every write control', async () => {
    const { AuthContext } = await import('../auth/auth')
    const viewer = {
      me: { username: 'vic', role: 'viewer' as const, auth: 'session' as const, permissions: { read: true, write: false, admin: false } },
      can: (p: string) => p === 'read',
      signOut: () => {},
    }
    renderWithQuery(<AuthContext.Provider value={viewer}><Incidents /></AuthContext.Provider>)
    fireEvent.click(await screen.findByText(open.title))
    await screen.findByRole('heading', { name: open.title })
    expect(screen.queryByRole('button', { name: 'Investigate with AI' })).not.toBeInTheDocument()
    expect(screen.queryByLabelText('Add a comment')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Not helpful' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Run playbook' })).not.toBeInTheDocument()
    expect(screen.getByLabelText('Status')).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Report' })).toBeInTheDocument()
  })
})
