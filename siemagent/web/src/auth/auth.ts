import { createContext, useContext } from 'react'
import type { Me } from '../lib/api'

export type Permission = 'read' | 'write' | 'admin'

export interface AuthContextValue {
  me: Me
  can: (p: Permission) => boolean
  signOut: () => void
}

export const AuthContext = createContext<AuthContextValue | null>(null)

// Full access when rendered outside <AuthGate> (component tests, open installs).
const fallback: AuthContextValue = {
  me: { username: 'analyst', role: 'admin', auth: 'open', permissions: { read: true, write: true, admin: true } },
  can: () => true,
  signOut: () => {},
}

export function useAuth(): AuthContextValue {
  return useContext(AuthContext) ?? fallback
}
