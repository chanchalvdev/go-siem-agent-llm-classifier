import { describe, expect, it } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import { EventFields } from '../components/EventFields'

describe('EventFields', () => {
  it('lists fields sorted by name', () => {
    render(<EventFields fields={{ 'user.name': 'root', 'event.outcome': 'failure', 'source.ip': '203.0.113.7' }} />)
    const list = screen.getByLabelText('Normalised fields')
    const terms = within(list).getAllByRole('term').map((el) => el.textContent)
    expect(terms).toEqual(['event.outcome', 'source.ip', 'user.name'])
    expect(within(list).getByText('203.0.113.7')).toBeInTheDocument()
  })

  it('renders nothing without fields', () => {
    const { container } = render(<EventFields fields={{}} />)
    expect(container).toBeEmptyDOMElement()
    render(<EventFields />)
    expect(screen.queryByText('Fields')).not.toBeInTheDocument()
  })
})
