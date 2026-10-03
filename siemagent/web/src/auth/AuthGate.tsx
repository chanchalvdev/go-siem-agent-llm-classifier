import { useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import axios from 'axios'
import { Shield } from 'lucide-react'
import { SESSION_EXPIRED_EVENT, apiError, getMe, login, logout } from '../lib/api'
import { AuthContext } from './auth'
import type { AuthContextValue, Permission } from './auth'

// AuthGate shows the login form until the server recognises the caller,
// then provides who they are and what they may do to the app.
export function AuthGate({ children }: { children: ReactNode }) {
  const qc = useQueryClient()
  const me = useQuery({ queryKey: ['me'], queryFn: getMe, retry: false, staleTime: 60_000 })

  useEffect(() => {
    const onExpired = () => { void qc.invalidateQueries({ queryKey: ['me'] }) }
    window.addEventListener(SESSION_EXPIRED_EVENT, onExpired)
    return () => window.removeEventListener(SESSION_EXPIRED_EVENT, onExpired)
  }, [qc])

  const value = useMemo<AuthContextValue | null>(() => {
    if (!me.data) return null
    return {
      me: me.data,
      can: (p: Permission) => me.data.permissions[p],
      signOut: () => {
        // Reset drops every cached response (nothing from the old session
        // stays on screen) and refetches "me", which now shows the login.
        void logout().finally(() => { void qc.resetQueries() })
      },
    }
  }, [me.data, qc])

  if (me.isLoading) {
    return <div className="flex h-screen items-center justify-center bg-canvas text-sm text-fg-subtle">Loading…</div>
  }
  const unauthorized = axios.isAxiosError(me.error) && me.error.response?.status === 401
  if (unauthorized || !value) {
    return (
      <LoginForm
        error={!unauthorized && me.error ? 'Cannot reach the SIEMAgent server.' : undefined}
        onSuccess={() => qc.invalidateQueries({ queryKey: ['me'] })}
      />
    )
  }
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

function LoginForm({ onSuccess, error }: { onSuccess: () => void; error?: string }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [failure, setFailure] = useState<string | null>(null)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setFailure(null)
    try {
      await login(username, password)
      setPassword('')
      onSuccess()
    } catch (err) {
      setFailure(apiError(err))
    } finally {
      setBusy(false)
    }
  }

  const field =
    'w-full rounded-lg border border-line-strong bg-surface-2 px-3 py-2 text-sm text-fg focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/20'
  return (
    <main className="flex min-h-screen items-center justify-center bg-canvas p-4">
      <form onSubmit={submit} className="w-full max-w-sm space-y-4 rounded-xl border border-line bg-surface p-6 shadow-pop" aria-labelledby="login-title">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-accent">
            <Shield size={18} className="text-on-accent" aria-hidden="true" />
          </div>
          <div>
            <h1 id="login-title" className="text-base font-semibold text-fg">Sign in to SIEMAgent</h1>
            <p className="text-xs text-fg-subtle">AI security operations</p>
          </div>
        </div>
        {(failure || error) && (
          <p role="alert" className="rounded-lg border border-danger/30 bg-danger/10 px-3 py-2 text-xs text-danger">{failure ?? error}</p>
        )}
        <label className="block space-y-1 text-xs text-fg-muted">
          Username
          <input className={field} value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" autoFocus required />
        </label>
        <label className="block space-y-1 text-xs text-fg-muted">
          Password
          <input className={field} type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required />
        </label>
        <button
          type="submit"
          disabled={busy || !username || !password}
          className="w-full rounded-lg bg-accent py-2 text-sm font-medium text-on-accent hover:bg-accent-strong disabled:opacity-40"
        >
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </main>
  )
}
