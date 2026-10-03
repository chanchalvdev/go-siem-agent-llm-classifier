import { useState } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Dashboard } from './pages/Dashboard'
import { AlertTicker } from './components/AlertTicker'
import { Incident } from './pages/Incident'
import { useAlertStream } from './hooks/useAlertStream'
import { ThemeProvider } from './theme/ThemeProvider'
import { AuthGate } from './auth/AuthGate'

const queryClient = new QueryClient()

// LiveIncidents wires the WebSocket alert stream to the global ticker and an
// incident detail overlay. Kept out of Dashboard so it stays app-global.
function LiveIncidents() {
  const { incidents, clearIncident } = useAlertStream()
  const [selected, setSelected] = useState<string | null>(null)
  const active = [...incidents.values()]
  const current = selected ? incidents.get(selected) : undefined

  return (
    <>
      <AlertTicker incidents={active} onSelect={setSelected} />
      {current && (
        <div className="fixed inset-0 z-50 flex items-start justify-center bg-overlay/50 backdrop-blur-sm p-4 overflow-auto">
          <div className="w-full max-w-5xl rounded-xl border border-line-strong bg-surface shadow-pop">
            <Incident
              incident={current}
              onClose={() => {
                clearIncident(current.id)
                setSelected(null)
              }}
            />
          </div>
        </div>
      )}
    </>
  )
}

export default function App() {
  return (
    <ThemeProvider>
      <QueryClientProvider client={queryClient}>
        <AuthGate>
          <LiveIncidents />
          <Dashboard />
        </AuthGate>
      </QueryClientProvider>
    </ThemeProvider>
  )
}
