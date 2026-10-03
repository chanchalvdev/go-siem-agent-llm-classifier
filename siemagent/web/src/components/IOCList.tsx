import { Network, Hash, Globe } from 'lucide-react'

interface Props {
  iocs: string[]
}

const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/
const IPV6_RE = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/
const MD5_RE  = /^[0-9a-fA-F]{32}$/
const SHA1_RE = /^[0-9a-fA-F]{40}$/
const SHA256_RE = /^[0-9a-fA-F]{64}$/
const DOMAIN_RE = /^(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$/

function classify(ioc: string): 'ip' | 'hash' | 'domain' | 'unknown' {
  if (IPV4_RE.test(ioc) || IPV6_RE.test(ioc)) return 'ip'
  if (MD5_RE.test(ioc) || SHA1_RE.test(ioc) || SHA256_RE.test(ioc)) return 'hash'
  if (DOMAIN_RE.test(ioc)) return 'domain'
  return 'unknown'
}

function iocLink(ioc: string, type: string): string | undefined {
  if (type === 'ip')     return `https://www.abuseipdb.com/check/${ioc}`
  if (type === 'hash')   return `https://www.virustotal.com/gui/file/${ioc}`
  if (type === 'domain') return `https://www.virustotal.com/gui/domain/${ioc}`
  return undefined
}

export function IOCList({ iocs }: Props) {
  if (!iocs || iocs.length === 0) return null

  return (
    <div className="flex flex-wrap gap-1.5">
      {iocs.map((ioc) => {
        const type = classify(ioc)
        const href = iocLink(ioc, type)

        const Icon =
          type === 'ip'   ? Network :
          type === 'hash' ? Hash :
          Globe

        const chip = (
          <span className="inline-flex items-center gap-1 font-mono text-xs bg-surface-2 text-fg-muted px-2 py-1 rounded border border-line-strong hover:border-line-strong transition-colors">
            <Icon size={12} className="shrink-0 text-fg-subtle" />
            {ioc}
          </span>
        )

        if (href) {
          return (
            <a key={ioc} href={href} target="_blank" rel="noopener noreferrer">
              {chip}
            </a>
          )
        }
        return <span key={ioc}>{chip}</span>
      })}
    </div>
  )
}
