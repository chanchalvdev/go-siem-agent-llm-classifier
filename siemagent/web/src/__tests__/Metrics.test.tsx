import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import type { SOCMetrics } from '../lib/api'
import { renderWithQuery } from '../test/render'
import { ThemeProvider } from '../theme/ThemeProvider'

const dur = (median: number | null, samples = 2) => ({
  samples: median === null ? 0 : samples, mean_seconds: median === null ? null : median * 1.5,
  median_seconds: median, p90_seconds: median === null ? null : median * 3,
})

const metrics: SOCMetrics = {
  days: 30, since: '2026-09-06T00:00:00Z', generated_at: '2026-10-05T12:00:00Z',
  incidents_opened: 12, incidents_resolved: 9, open_now: 4, unassigned_open: 1, open_over_24h: 2,
  mttd: dur(90), mtta: dur(600, 8), mttr: dur(7200, 9),
  false_positive_rate: 2 / 9,
  opened_by_severity: { P1: 2, P2: 6, P3: 4 },
  by_resolution: { true_positive: 6, false_positive: 2, benign: 1 },
  top_attack_types: [{ name: 'SSH Brute Force', count: 7 }, { name: 'Port Scan From One Source', count: 3 }],
  daily: [
    { day: '2026-10-04', events: 120, alerts: 9, suppressed: 3, incidents_opened: 4, incidents_resolved: 2 },
    { day: '2026-10-05', events: 40, alerts: 2, suppressed: 0, incidents_opened: 1, incidents_resolved: 3 },
  ],
  workload: [{ name: 'ana', open: 2, resolved: 5, mttr: dur(3600, 5) }, { name: 'bob', open: 1, resolved: 4, mttr: dur(null) }],
  event_totals: { events: 160, alerts: 11, suppressed: 3 },
}

const api = vi.hoisted(() => ({ getSOCMetrics: vi.fn() }))
vi.mock('../lib/api', () => api)

const { Metrics } = await import('../pages/Metrics')
const page = () => renderWithQuery(<ThemeProvider><Metrics /></ThemeProvider>)

beforeEach(() => {
  vi.clearAllMocks()
  api.getSOCMetrics.mockResolvedValue(metrics)
})

describe('SOC metrics page', () => {
  it('shows detect, acknowledge and resolve times', async () => {
    page()
    const mttd = (await screen.findByText('Time to detect (MTTD)')).parentElement!
    expect(within(mttd).getByText('2m')).toBeInTheDocument() // 90s median
    expect(within(mttd).getByText(/mean 2m · p90 5m · 2 incidents/)).toBeInTheDocument()
    expect(within(screen.getByText('Time to resolve (MTTR)').parentElement!).getByText('2h')).toBeInTheDocument()
  })

  it('shows queue, backlog and false-positive rate', async () => {
    page()
    expect((await screen.findByText('Open now')).nextSibling).toHaveTextContent('4')
    expect(screen.getByText('1 unassigned')).toBeInTheDocument()
    expect(screen.getByText('Open over 24 h').nextSibling).toHaveTextContent('2')
    expect(screen.getByText('False-positive rate').nextSibling).toHaveTextContent('22%')
    expect(screen.getByText(/160 events in total, 3 suppressed/)).toBeInTheDocument()
  })

  it('lists attack types, workload and resolutions', async () => {
    page()
    expect(await screen.findByText('SSH Brute Force')).toBeInTheDocument()
    const table = screen.getByRole('table', { name: 'Analyst workload' })
    const rows = within(table).getAllByRole('row')
    expect(rows[1]).toHaveTextContent('ana251h') // open, resolved, median MTTR
    expect(rows[2]).toHaveTextContent('bob14—')
    expect(screen.getByText('True positive').nextSibling).toHaveTextContent('6')
    expect(screen.getByText(/1 open incident is unassigned/)).toBeInTheDocument()
  })

  it('has a table view of the daily numbers', async () => {
    page()
    const table = await screen.findByRole('table', { name: 'Events, alerts and incidents per day' })
    const rows = within(table).getAllByRole('row')
    expect(rows[1]).toHaveTextContent('2026-10-05') // newest first
    expect(rows[2]).toHaveTextContent('2026-10-0412093 42'.replace(' ', ''))
  })

  it('switches the window', async () => {
    page()
    await screen.findByText('Open now')
    expect(api.getSOCMetrics).toHaveBeenCalledWith(30)
    fireEvent.click(screen.getByRole('button', { name: '7 days' }))
    await waitFor(() => expect(api.getSOCMetrics).toHaveBeenCalledWith(7))
    expect(screen.getByRole('button', { name: '7 days' })).toHaveAttribute('aria-pressed', 'true')
  })

  it('handles an empty window', async () => {
    api.getSOCMetrics.mockResolvedValue({
      ...metrics, incidents_opened: 0, incidents_resolved: 0, mttd: dur(null), mtta: dur(null), mttr: dur(null),
      false_positive_rate: null, top_attack_types: [], workload: [], by_resolution: {},
    })
    page()
    expect(await screen.findAllByText('No data in this window')).toHaveLength(3)
    expect(screen.getByText('False-positive rate').nextSibling).toHaveTextContent('—')
    expect(screen.getByText('No incidents are assigned yet.')).toBeInTheDocument()
  })
})
