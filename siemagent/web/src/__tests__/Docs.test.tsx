import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, beforeAll } from 'vitest'
import { Docs } from '../pages/Docs'

// jsdom does not implement scrollIntoView; stub it so TOC clicks don't throw.
beforeAll(() => {
  Element.prototype.scrollIntoView = () => {}
})

describe('Docs', () => {
  it('renders the user guide heading', () => {
    render(<Docs />)
    expect(screen.getByText('SIEMAgent User Guide')).toBeInTheDocument()
  })

  it('lists the severity reference rows', () => {
    render(<Docs />)
    expect(screen.getByText(/Active breach, ransomware/)).toBeInTheDocument()
    expect(screen.getByText(/Normal operations/)).toBeInTheDocument()
  })

  it('documents the developer API endpoints', () => {
    render(<Docs />)
    expect(screen.getByText('/api/classify')).toBeInTheDocument()
    expect(screen.getByText('/ws/alerts')).toBeInTheDocument()
  })

  it('navigates when a table-of-contents entry is clicked', () => {
    render(<Docs />)
    const tocButton = screen.getByRole('button', { name: /Classify your first log/ })
    fireEvent.click(tocButton)
    expect(tocButton).toHaveClass('text-blue-400')
  })
})
