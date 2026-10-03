/** @type {import('tailwindcss').Config} */

// Semantic colours resolve to CSS variables defined per theme in index.css,
// so one class (e.g. `bg-surface`, `text-fg-muted`) is correct in light and
// dark. Variables hold RGB channels so Tailwind opacity (`bg-fg/5`) works.
const v = (name) => `rgb(var(--${name}) / <alpha-value>)`

export default {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'Segoe UI', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
      colors: {
        canvas: v('canvas'),
        surface: { DEFAULT: v('surface'), 2: v('surface-2') },
        line: { DEFAULT: v('line'), strong: v('line-strong') },
        fg: { DEFAULT: v('fg'), muted: v('fg-muted'), subtle: v('fg-subtle') },
        accent: { DEFAULT: v('accent'), strong: v('accent-strong'), text: v('accent-text') },
        'on-accent': v('on-accent'),
        success: v('success'),
        warning: v('warning'),
        danger: v('danger'),
        info: v('info'),
        overlay: v('overlay'),
        sev: { p1: v('sev-p1'), p2: v('sev-p2'), p3: v('sev-p3'), p4: v('sev-p4'), p5: v('sev-p5') },
      },
      opacity: { 3: '0.03', 4: '0.04', 6: '0.06', 7: '0.07', 8: '0.08', 15: '0.15' },
      boxShadow: {
        card: '0 1px 2px rgb(var(--shadow) / 0.06), 0 1px 3px rgb(var(--shadow) / 0.08)',
        pop: '0 10px 30px -10px rgb(var(--shadow) / 0.35)',
      },
    },
  },
  plugins: [],
}
