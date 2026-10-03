import { describe, expect, it } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import { KillChain } from '../components/KillChain'
import { KILL_CHAIN } from '../lib/incidents'

describe('KillChain', () => {
  it('marks reached tactics and names the furthest', () => {
    render(<KillChain tactics={['Credential Access', 'initial access']} />)
    const chain = screen.getByRole('list', { name: 'MITRE ATT&CK kill chain' })
    expect(within(chain).getAllByRole('listitem')).toHaveLength(KILL_CHAIN.length)
    expect(screen.getByText(/Reached 2 of 14 tactics; furthest: Credential Access/)).toBeInTheDocument()
    const reached = within(chain).getAllByRole('listitem').filter((li) => li.getAttribute('aria-current') === 'step')
    expect(reached.map((li) => li.textContent)).toEqual(['Reached: Initial Access', 'Reached: Credential Access'])
  })

  it('says when nothing is mapped yet', () => {
    render(<KillChain tactics={[]} />)
    expect(screen.getByText('No ATT&CK tactics identified yet.')).toBeInTheDocument()
  })
})
