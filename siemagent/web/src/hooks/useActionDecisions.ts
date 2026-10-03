import { useMutation, useQueryClient } from '@tanstack/react-query'
import { approveAction, rejectAction } from '../lib/api'

// useActionDecisions approves or rejects response actions and refreshes
// every view that shows them (queues, incident timelines).
export function useActionDecisions() {
  const qc = useQueryClient()
  const refresh = () => {
    qc.invalidateQueries({ queryKey: ['actions'] })
    qc.invalidateQueries({ queryKey: ['incident'] })
  }
  const approve = useMutation({ mutationFn: (id: string) => approveAction(id), onSettled: refresh })
  const reject = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) => rejectAction(id, reason),
    onSettled: refresh,
  })
  return {
    approve: (id: string) => approve.mutate(id),
    reject: (id: string, reason: string) => reject.mutate({ id, reason }),
    busy: approve.isPending || reject.isPending,
    error: approve.error ?? reject.error,
  }
}
