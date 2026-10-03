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
  const me = useQuery({
    queryKey: ['me'],
    queryFn: getMe,
    retry: false,
    staleTime: 60_000,
    // While the backend is down (still compiling, crashed, restarting), keep
    // checking so the app recovers by itself once it answers.
    refetchInterval: (q) => (q.state.error && !isUnauthorized(q.state.error) ? 3000 : false),
  })

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
  if (me.error && !isUnauthorized(me.error)) {
    return <ServerUnavailable error={me.error} onRetry={() => void me.refetch()} retrying={me.isFetching} />
  }
  // A 401 always means "log in", even though the previous user's data is
  // still cached from before the session expired.
  if (isUnauthorized(me.error) || !value) {
    return <LoginForm onSuccess={() => qc.invalidateQueries({ queryKey: ['me'] })} />
  }
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

function isUnauthorized(err: unknown): boolean {
  return axios.isAxiosError(err) && err.response?.status === 401
}

// describe explains why the backend didn't answer, in terms of what to check.
function describe(err: unknown): { title: string; detail: string } {
  const status = axios.isAxiosError(err) ? err.response?.status : undefined
  if (status === 404) {
    return {
      title: 'The backend is running an older version',
      detail: 'It does not know /api/auth/me. Stop the backend and start it again from the latest code (make dev).',
    }
  }
  if (status && status < 500) {
    return { title: `The backend answered ${status}`, detail: 'Check the backend terminal for the error.' }
  }
  return {
    title: 'Cannot reach the SIEMAgent backend',
    detail:
      'The dashboard is up but the Go server on port 8080 is not answering. It may still be starting, or it stopped with an error: check the terminal running make dev (look for a line starting with "error:").',
  }
}

function ServerUnavailable({ error, onRetry, retrying }: { error: unknown; onRetry: () => void; retrying: boolean }) {
  const { title, detail } = describe(error)
  return (
    <main className="flex min-h-screen items-center justify-center bg-canvas p-4">
      <section role="alert" aria-labelledby="down-title" className="w-full max-w-md space-y-3 rounded-xl border border-line bg-surface p-6 shadow-pop">
        <h1 id="down-title" className="text-base font-semibold text-fg">{title}</h1>
        <p className="text-sm text-fg-muted">{detail}</p>
        <p className="text-xs text-fg-subtle">Retrying automatically every few seconds.</p>
        <button
          onClick={onRetry}
          disabled={retrying}
          className="rounded-lg border border-line-strong px-3 py-1.5 text-sm text-fg hover:bg-fg/4 disabled:opacity-40"
        >
          {retrying ? 'Checking…' : 'Retry now'}
        </button>
      </section>
    </main>
  )
}

function LoginForm({ onSuccess }: { onSuccess: () => void }) {
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
        {failure && (
          <p role="alert" className="rounded-lg border border-danger/30 bg-danger/10 px-3 py-2 text-xs text-danger">{failure}</p>
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
