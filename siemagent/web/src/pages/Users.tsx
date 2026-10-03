import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { UserPlus, Users as UsersIcon } from 'lucide-react'
import { apiError, createUser, listUsers, updateUser } from '../lib/api'
import type { Role, User } from '../lib/api'
import { timeAgo } from '../lib/time'
import { useAuth } from '../auth/auth'

const ROLE_HELP: Record<Role, string> = {
  viewer: 'Read everything',
  analyst: 'Work incidents, classify logs, approve actions',
  admin: 'Everything, plus users, rules and the audit log',
}

const field =
  'rounded-lg border border-line-strong bg-surface-2 px-2.5 py-1.5 text-sm text-fg focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/20'

function NewUserForm({ onDone }: { onDone: () => void }) {
  const [username, setUsername] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState<Role>('analyst')
  const create = useMutation({
    mutationFn: () => createUser({ username, display_name: displayName, password, role }),
    onSuccess: () => { setUsername(''); setDisplayName(''); setPassword(''); onDone() },
  })
  return (
    <form
      onSubmit={(e) => { e.preventDefault(); create.mutate() }}
      className="grid gap-3 rounded-xl border border-line bg-surface p-4 shadow-card sm:grid-cols-2"
      aria-label="Add a user"
    >
      <label className="flex flex-col gap-1 text-xs text-fg-muted">Username
        <input className={field} value={username} onChange={(e) => setUsername(e.target.value)} required autoComplete="off" />
      </label>
      <label className="flex flex-col gap-1 text-xs text-fg-muted">Display name
        <input className={field} value={displayName} onChange={(e) => setDisplayName(e.target.value)} />
      </label>
      <label className="flex flex-col gap-1 text-xs text-fg-muted">Initial password (12+ characters)
        <input className={field} type="password" value={password} onChange={(e) => setPassword(e.target.value)} required minLength={12} autoComplete="new-password" />
      </label>
      <label className="flex flex-col gap-1 text-xs text-fg-muted">Role
        <select className={field} value={role} onChange={(e) => setRole(e.target.value as Role)}>
          {(Object.keys(ROLE_HELP) as Role[]).map((r) => <option key={r} value={r}>{r}: {ROLE_HELP[r]}</option>)}
        </select>
      </label>
      {create.error && (
        <p role="alert" className="sm:col-span-2 rounded-lg border border-danger/30 bg-danger/10 px-3 py-2 text-xs text-danger">{apiError(create.error)}</p>
      )}
      <div className="sm:col-span-2">
        <button type="submit" disabled={create.isPending} className="inline-flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1.5 text-sm font-medium text-on-accent hover:bg-accent-strong disabled:opacity-40">
          <UserPlus size={14} aria-hidden="true" /> Add user
        </button>
      </div>
    </form>
  )
}

function UserRow({ user, self, onChange }: { user: User; self: boolean; onChange: (u: Partial<Pick<User, 'role' | 'disabled'>> & { password?: string }) => void }) {
  const [resetting, setResetting] = useState(false)
  const [pw, setPw] = useState('')
  return (
    <li className={`rounded-xl border border-line bg-surface p-3 shadow-card ${user.disabled ? 'opacity-60' : ''}`}>
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-sm font-medium text-fg">{user.display_name || user.username}</span>
        <span className="font-mono text-xs text-fg-subtle">{user.username}</span>
        {self && <span className="rounded-full border border-accent/30 bg-accent/10 px-1.5 py-0.5 text-[10px] text-accent-text">you</span>}
        {user.disabled && <span className="rounded-full border border-line-strong px-1.5 py-0.5 text-[10px] text-fg-subtle">disabled</span>}
        <span className="ml-auto text-[11px] text-fg-subtle">
          {user.last_login_at ? `last login ${timeAgo(user.last_login_at)}` : 'never logged in'}
        </span>
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <label className="sr-only" htmlFor={`role-${user.id}`}>Role of {user.username}</label>
        <select id={`role-${user.id}`} className={field} value={user.role} onChange={(e) => onChange({ role: e.target.value as Role })}>
          {(Object.keys(ROLE_HELP) as Role[]).map((r) => <option key={r} value={r}>{r}</option>)}
        </select>
        <button
          onClick={() => onChange({ disabled: !user.disabled })}
          disabled={self}
          title={self ? 'You cannot disable your own account' : undefined}
          className="rounded-lg border border-line-strong px-2.5 py-1.5 text-xs text-fg-muted hover:bg-fg/4 hover:text-fg disabled:opacity-40"
        >
          {user.disabled ? 'Enable' : 'Disable'}
        </button>
        {resetting ? (
          <form className="flex gap-2" onSubmit={(e) => { e.preventDefault(); onChange({ password: pw }); setPw(''); setResetting(false) }}>
            <label className="sr-only" htmlFor={`pw-${user.id}`}>New password for {user.username}</label>
            <input id={`pw-${user.id}`} type="password" minLength={12} required value={pw} onChange={(e) => setPw(e.target.value)} className={field} autoComplete="new-password" placeholder="New password" />
            <button type="submit" className="rounded-lg bg-accent px-2.5 py-1.5 text-xs font-medium text-on-accent">Set</button>
          </form>
        ) : (
          <button onClick={() => setResetting(true)} className="rounded-lg border border-line-strong px-2.5 py-1.5 text-xs text-fg-muted hover:bg-fg/4 hover:text-fg">
            Reset password
          </button>
        )}
      </div>
    </li>
  )
}

export function Users() {
  const qc = useQueryClient()
  const { me } = useAuth()
  const users = useQuery({ queryKey: ['users'], queryFn: listUsers })
  const update = useMutation({
    mutationFn: ({ id, change }: { id: string; change: Parameters<typeof updateUser>[1] }) => updateUser(id, change),
    onSettled: () => qc.invalidateQueries({ queryKey: ['users'] }),
  })
  return (
    <div className="flex-1 overflow-y-auto">
      <div className="mx-auto max-w-4xl space-y-5 p-4 sm:p-6">
        <header>
          <h1 className="flex items-center gap-2 text-lg font-semibold text-fg">
            <UsersIcon size={18} className="text-accent-text" aria-hidden="true" /> Users
          </h1>
          <p className="mt-1 text-sm text-fg-muted">
            Viewers read everything; analysts also work incidents and approve response actions; admins also manage users, rules and the audit log.
          </p>
        </header>
        <NewUserForm onDone={() => qc.invalidateQueries({ queryKey: ['users'] })} />
        {update.error && (
          <p role="alert" className="rounded-lg border border-danger/30 bg-danger/10 px-3 py-2 text-xs text-danger">{apiError(update.error)}</p>
        )}
        <ul className="space-y-2" aria-label="Users">
          {(users.data ?? []).map((u) => (
            <UserRow key={u.id} user={u} self={u.id === me.id} onChange={(change) => update.mutate({ id: u.id, change })} />
          ))}
        </ul>
      </div>
    </div>
  )
}
