import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { ThreatIntelPanel } from '../components/ThreatIntelPanel'
import type { ToolInvocation } from '../hooks/useAlertStream'

describe('ThreatIntelPanel', () => {
  it('shows a placeholder when there is no intel', () => {
    render(<ThreatIntelPanel tools={[]} />)
    expect(screen.getByText(/No external threat intel/)).toBeInTheDocument()
  })

  it('renders an AbuseIPDB card with score and reports', () => {
    const tools: ToolInvocation[] = [{
      name: 'check_abuseipdb',
      input: '{"ip":"8.8.8.8"}',
      result: '{"ip":"8.8.8.8","abuse_score":87,"country":"CN","isp":"Evil","total_reports":42}',
    }]
    render(<ThreatIntelPanel tools={tools} />)
    expect(screen.getByText('8.8.8.8')).toBeInTheDocument()
    expect(screen.getByText(/87% abuse/)).toBeInTheDocument()
    expect(screen.getByText(/42 reports/)).toBeInTheDocument()
  })

  it('renders OTX threat labels', () => {
    const tools: ToolInvocation[] = [{
      name: 'check_otx',
      input: '{"indicator":"evil.com","type":"domain"}',
      result: '{"indicator":"evil.com","pulse_count":3,"threat_labels":["apt","malware"]}',
    }]
    render(<ThreatIntelPanel tools={tools} />)
    expect(screen.getByText('apt')).toBeInTheDocument()
    expect(screen.getByText(/3 pulses/)).toBeInTheDocument()
  })
})
