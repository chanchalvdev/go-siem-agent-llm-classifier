import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import type { Playbook, ResponseAction } from '../lib/api'
import { renderWithQuery } from '../test/render'

const now = new Date().toISOString()
const pending: ResponseAction = {
  id: 'ACT-1', incident_id: 'INC-1', playbook_id: 'contain-brute-force-source', playbook_name: 'Contain brute-force source',
  type: 'block_ip', target: '185.220.101.4', step: 0, status: 'pending', reason: 'matched trigger on SSH Brute Force', proposed_at: now,
}
const done: ResponseAction = {
  ...pending, id: 'ACT-2', type: 'notify', target: undefined, status: 'succeeded', message: 'P1 incident',
  result: 'hooks.slack.com answered HTTP 200', decided_by: 'alice',
}
const playbooks: Playbook[] = [{
  id: 'contain-brute-force-source', name: 'Contain brute-force source', mode: 'approval', enabled: true, source: 'builtin',
  trigger: { min_severity: 'P2', techniques: ['T1110'] }, actions: [{ type: 'block_ip' }],
}]

const api = vi.hoisted(() => ({
  listActions: vi.fn(),
  listPlaybooks: vi.fn(),
  approveAction: vi.fn(),
  rejectAction: vi.fn(),
  runPlaybook: vi.fn(),
  apiError: (e: unknown) => (e instanceof Error ? e.message : String(e)),
}))
vi.mock('../lib/api', () => api)

const { Response } = await import('../pages/Response')
const { IncidentResponse } = await import('../components/IncidentResponse')

beforeEach(() => {
  vi.clearAllMocks()
  api.listActions.mockImplementation(async (f: { status?: string }) => (f.status === 'pending' ? [pending] : [pending, done]))
  api.listPlaybooks.mockResolvedValue(playbooks)
  api.approveAction.mockResolvedValue({ ...pending, status: 'succeeded' })
  api.rejectAction.mockResolvedValue({ ...pending, status: 'rejected' })
  api.runPlaybook.mockResolvedValue([])
})

describe('Response page', () => {
  it('lists pending approvals, history and playbooks', async () => {
    renderWithQuery(<Response />)
    const queue = await screen.findByRole('list', { name: 'Actions awaiting approval' })
    expect(within(queue).getByText('185.220.101.4')).toBeInTheDocument()
    expect(within(queue).getByText('Awaiting approval')).toBeInTheDocument()
    const history = screen.getByRole('list', { name: 'Recent actions' })
    expect(within(history).getByText('hooks.slack.com answered HTTP 200')).toBeInTheDocument()
    expect(within(history).getByText('Decided by alice')).toBeInTheDocument()
    const pbs = await screen.findByRole('list', { name: 'Playbooks' })
    expect(within(pbs).getByText('P2 or worse, technique T1110')).toBeInTheDocument()
    expect(within(pbs).getByText('Needs approval')).toBeInTheDocument()
  })

  it('approves an action', async () => {
    renderWithQuery(<Response />)
    fireEvent.click(await screen.findByRole('button', { name: 'Approve Block IP 185.220.101.4' }))
    await waitFor(() => expect(api.approveAction).toHaveBeenCalledWith('ACT-1'))
  })

  it('rejects with a reason', async () => {
    renderWithQuery(<Response />)
    fireEvent.click(await screen.findByRole('button', { name: 'Reject Block IP 185.220.101.4' }))
    fireEvent.change(screen.getByLabelText('Reason for rejecting'), { target: { value: 'authorised pentest' } })
    fireEvent.click(screen.getByRole('button', { name: 'Confirm reject' }))
    await waitFor(() => expect(api.rejectAction).toHaveBeenCalledWith('ACT-1', 'authorised pentest'))
  })

  it('shows a failed decision', async () => {
    api.approveAction.mockRejectedValueOnce(new Error('action is succeeded; only pending actions can be decided'))
    renderWithQuery(<Response />)
    fireEvent.click(await screen.findByRole('button', { name: 'Approve Block IP 185.220.101.4' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('only pending actions can be decided')
  })
})

describe('IncidentResponse', () => {
  it('runs a playbook against the incident', async () => {
    renderWithQuery(<IncidentResponse incidentId="INC-1" />)
    await screen.findByRole('option', { name: 'Contain brute-force source' })
    fireEvent.change(screen.getByLabelText('Playbook to run'), { target: { value: 'contain-brute-force-source' } })
    fireEvent.click(screen.getByRole('button', { name: 'Run playbook' }))
    await waitFor(() => expect(api.runPlaybook).toHaveBeenCalledWith('INC-1', 'contain-brute-force-source'))
    expect(await screen.findByRole('status')).toHaveTextContent('Nothing new to propose')
    expect(api.listActions).toHaveBeenCalledWith({ incident: 'INC-1' })
  })
})
