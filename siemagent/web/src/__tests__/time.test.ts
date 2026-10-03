import { describe, expect, it } from 'vitest'
import { formatDuration, timeAgo } from '../lib/time'

describe('time helpers', () => {
  it('formats relative times', () => {
    const now = Date.parse('2026-10-03T12:00:00Z')
    expect(timeAgo('2026-10-03T11:59:30Z', now)).toBe('30s ago')
    expect(timeAgo('2026-10-03T11:15:00Z', now)).toBe('45m ago')
    expect(timeAgo('2026-10-03T09:00:00Z', now)).toBe('3h ago')
    expect(timeAgo('2026-09-30T12:00:00Z', now)).toBe('3d ago')
    expect(timeAgo('2026-10-03T12:00:05Z', now)).toBe('0s ago') // clock skew
  })

  it('formats durations', () => {
    expect(formatDuration(42)).toBe('42s')
    expect(formatDuration(720)).toBe('12m')
    expect(formatDuration(3600)).toBe('1h')
    expect(formatDuration(12000)).toBe('3h 20m')
    expect(formatDuration(187200)).toBe('2d 4h')
  })
})
