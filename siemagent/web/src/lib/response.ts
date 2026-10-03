import type { ActionStatus, ActionType, PlaybookMode } from './api'

export const ACTION_LABELS: Record<ActionType, string> = {
  block_ip: 'Block IP',
  disable_user: 'Disable user',
  isolate_host: 'Isolate host',
  notify: 'Notify',
  webhook: 'Webhook',
}

export const ACTION_STATUS_LABELS: Record<ActionStatus, string> = {
  pending: 'Awaiting approval',
  dry_run: 'Dry run',
  running: 'Running',
  succeeded: 'Succeeded',
  failed: 'Failed',
  rejected: 'Rejected',
}

export const ACTION_STATUS_STYLES: Record<ActionStatus, string> = {
  pending: 'border-warning/30 bg-warning/10 text-warning',
  dry_run: 'border-line-strong bg-fg/4 text-fg-muted',
  running: 'border-info/30 bg-info/10 text-info',
  succeeded: 'border-success/30 bg-success/10 text-success',
  failed: 'border-danger/30 bg-danger/10 text-danger',
  rejected: 'border-line-strong bg-fg/4 text-fg-subtle',
}

export const MODE_LABELS: Record<PlaybookMode, string> = {
  approval: 'Needs approval',
  dry_run: 'Dry run',
  auto: 'Automatic',
}
