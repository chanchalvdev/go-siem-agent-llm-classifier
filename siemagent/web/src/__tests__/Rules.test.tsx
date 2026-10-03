import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import type { DetectionRule } from '../lib/api'
import { renderWithQuery } from '../test/render'

const rules: DetectionRule[] = [
  {
    id: 'bf-1', title: 'SSH Brute Force', level: 'high', source: 'builtin', hits: 3,
    enabled: true, type: 'threshold', threshold: 'count() by src_ip >= 10 in 5m',
    tags: ['attack.t1110.001'],
  },
  { id: 'shadow-1', title: 'Shadow Copies Deleted', level: 'critical', source: 'builtin', hits: 0, enabled: true, type: 'single' },
  { id: 'old-1', title: 'Noisy Rule', level: 'low', source: '/rules/x.yml', hits: 99, enabled: false, type: 'single' },
]

const api = vi.hoisted(() => ({
  listDetectionRules: vi.fn(),
  setDetectionRuleEnabled: vi.fn(),
}))
vi.mock('../lib/api', () => api)

const { Rules } = await import('../pages/Rules')

beforeEach(() => {
  api.listDetectionRules.mockResolvedValue(rules)
  api.setDetectionRuleEnabled.mockImplementation(async (id: string, enabled: boolean) => ({
    ...rules.find((r) => r.id === id)!, enabled,
  }))
})

describe('Rules page', () => {
  it('lists rules with summary counts and threshold details', async () => {
    renderWithQuery(<Rules />)
    expect(await screen.findByText('SSH Brute Force')).toBeInTheDocument()
    expect(screen.getByText('count() by src_ip >= 10 in 5m')).toBeInTheDocument()
    expect(screen.getByText('Threshold rules').nextSibling).toHaveTextContent('1')
    expect(screen.getByText('Enabled').nextSibling).toHaveTextContent('2')
    expect(screen.getByText('Hits since start').nextSibling).toHaveTextContent('102')
  })

  it('filters by type and search text', async () => {
    renderWithQuery(<Rules />)
    await screen.findByText('SSH Brute Force')
    fireEvent.click(screen.getByRole('button', { name: 'Disabled' }))
    const list = screen.getByRole('list', { name: 'Detection rules' })
    expect(within(list).getAllByRole('listitem')).toHaveLength(1)
    expect(within(list).getByText('Noisy Rule')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'All' }))
    fireEvent.change(screen.getByPlaceholderText('Search title, id or tag'), { target: { value: 't1110' } })
    expect(within(screen.getByRole('list', { name: 'Detection rules' })).getAllByRole('listitem')).toHaveLength(1)
  })

  it('disables a rule through the API and shows the new state', async () => {
    renderWithQuery(<Rules />)
    const toggle = await screen.findByRole('switch', { name: 'Disable SSH Brute Force' })
    expect(toggle).toHaveAttribute('aria-checked', 'true')
    fireEvent.click(toggle)
    await waitFor(() => expect(api.setDetectionRuleEnabled).toHaveBeenCalledWith('bf-1', false))
    expect(await screen.findByRole('switch', { name: 'Enable SSH Brute Force' })).toHaveAttribute('aria-checked', 'false')
  })

  it('reports a failed update', async () => {
    api.setDetectionRuleEnabled.mockRejectedValueOnce(new Error('boom'))
    renderWithQuery(<Rules />)
    fireEvent.click(await screen.findByRole('switch', { name: 'Disable SSH Brute Force' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not update the rule')
  })
})
