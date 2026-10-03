import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { DetectionList, RuleBadge } from '../components/DetectionList'
import type { Detection } from '../lib/api'

const detections: Detection[] = [
  {
    rule_id: 'cd2cd99d-a2e1-4871-8eed-a9f2918b699a',
    title: 'Shadow Copies Deleted',
    level: 'critical',
    tags: ['attack.impact', 'attack.t1490', 'cve.2024.0001'],
  },
  { rule_id: 'a4d1327c', title: 'SSH Password Authentication Failure', level: 'low' },
]

describe('DetectionList', () => {
  it('lists each matched rule with its level', () => {
    render(<DetectionList detections={detections} />)
    expect(screen.getByRole('list', { name: 'Matched detection rules' })).toBeInTheDocument()
    expect(screen.getByText('Shadow Copies Deleted')).toBeInTheDocument()
    expect(screen.getByText('critical')).toHaveClass('text-sev-p1')
    expect(screen.getByText('low')).toHaveClass('text-sev-p4')
  })

  it('shows non-ATT&CK tags only (ATT&CK is on the MITRE card)', () => {
    render(<DetectionList detections={detections} />)
    expect(screen.getByText('cve.2024.0001')).toBeInTheDocument()
    expect(screen.queryByText(/attack\.t1490/)).not.toBeInTheDocument()
  })

  it('renders nothing without detections', () => {
    const { container } = render(<DetectionList detections={[]} />)
    expect(container).toBeEmptyDOMElement()
  })
})

describe('RuleBadge', () => {
  it('marks rule-only and rule-confirmed verdicts', () => {
    const { rerender } = render(<RuleBadge classifiedBy="rules" />)
    expect(screen.getByText('Rule')).toBeInTheDocument()
    rerender(<RuleBadge classifiedBy="llm+rules" />)
    expect(screen.getByText('Rule + AI')).toBeInTheDocument()
  })

  it('stays hidden for AI-only or legacy events', () => {
    const { container, rerender } = render(<RuleBadge classifiedBy="llm" />)
    expect(container).toBeEmptyDOMElement()
    rerender(<RuleBadge />)
    expect(container).toBeEmptyDOMElement()
  })
})
