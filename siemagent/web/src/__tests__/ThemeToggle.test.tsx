import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, fireEvent, render, screen } from '@testing-library/react'
import { ThemeToggle } from '../components/ThemeToggle'
import { ThemeProvider } from '../theme/ThemeProvider'
import { THEME_STORAGE_KEY } from '../theme/theme'

function mockSystemTheme(dark: boolean) {
  const listeners: Array<() => void> = []
  const mq = {
    matches: dark,
    addEventListener: (_: string, fn: () => void) => listeners.push(fn),
    removeEventListener: vi.fn(),
  }
  vi.stubGlobal('matchMedia', vi.fn(() => mq))
  return {
    change(next: boolean) {
      mq.matches = next
      listeners.forEach((fn) => fn())
    },
  }
}

function renderToggle() {
  return render(
    <ThemeProvider>
      <ThemeToggle />
    </ThemeProvider>,
  )
}

const isDark = () => document.documentElement.classList.contains('dark')

beforeEach(() => {
  localStorage.clear()
  document.documentElement.classList.remove('dark')
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('ThemeToggle', () => {
  it('follows the OS theme by default, including later changes', () => {
    const system = mockSystemTheme(true)
    renderToggle()
    expect(screen.getByRole('radio', { name: 'System' })).toHaveAttribute('aria-checked', 'true')
    expect(isDark()).toBe(true)

    act(() => system.change(false))
    expect(isDark()).toBe(false)
  })

  it('applies and remembers an explicit choice', () => {
    mockSystemTheme(true)
    renderToggle()

    fireEvent.click(screen.getByRole('radio', { name: 'Light' }))
    expect(isDark()).toBe(false)
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe('light')
    expect(screen.getByRole('radio', { name: 'Light' })).toHaveAttribute('aria-checked', 'true')

    fireEvent.click(screen.getByRole('radio', { name: 'Dark' }))
    expect(isDark()).toBe(true)
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe('dark')
  })

  it('restores a saved preference over the OS theme', () => {
    mockSystemTheme(false)
    localStorage.setItem(THEME_STORAGE_KEY, 'dark')
    renderToggle()
    expect(isDark()).toBe(true)
    expect(screen.getByRole('radio', { name: 'Dark' })).toHaveAttribute('aria-checked', 'true')
  })

  it('ignores an invalid stored value', () => {
    mockSystemTheme(false)
    localStorage.setItem(THEME_STORAGE_KEY, 'neon')
    renderToggle()
    expect(screen.getByRole('radio', { name: 'System' })).toHaveAttribute('aria-checked', 'true')
    expect(isDark()).toBe(false)
  })
})
