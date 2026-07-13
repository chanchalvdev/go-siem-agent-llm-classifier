import { useState } from 'react'
import {
  BookOpen, Zap, Upload, Radio, BarChart2, Search, Shield,
  FileText, HelpCircle, Terminal, ChevronRight,
} from 'lucide-react'
import { SeverityBadge } from '../components/SeverityBadge'
import type { Severity } from '../styles/tokens'

// Docs is the in-app user guide. It is intentionally self-contained (no data
// fetching) so it renders instantly and works offline.

interface Section {
  id: string
  title: string
  icon: typeof BookOpen
}

const SECTIONS: Section[] = [
  { id: 'overview', title: 'Overview', icon: BookOpen },
  { id: 'quickstart', title: 'Classify your first log', icon: Zap },
  { id: 'results', title: 'Reading a result', icon: FileText },
  { id: 'upload', title: 'Bulk upload', icon: Upload },
  { id: 'incidents', title: 'Live investigations', icon: Radio },
  { id: 'analytics', title: 'Analytics & MITRE', icon: BarChart2 },
  { id: 'search', title: 'Similar events', icon: Search },
  { id: 'severity', title: 'Severity reference', icon: Shield },
  { id: 'faq', title: 'Tips & FAQ', icon: HelpCircle },
  { id: 'api', title: 'For developers', icon: Terminal },
]

const ALL_SEV: { s: Severity; when: string }[] = [
  { s: 'P1', when: 'Active breach, ransomware, confirmed data exfiltration' },
  { s: 'P2', when: 'Successful intrusion or privilege escalation' },
  { s: 'P3', when: 'Failed attack attempt or notable anomaly' },
  { s: 'P4', when: 'Policy violation or reconnaissance' },
  { s: 'P5', when: 'Normal operations / benign noise' },
]

function H({ id, children }: { id: string; children: React.ReactNode }) {
  return (
    <h2 id={id} className="scroll-mt-4 text-lg font-semibold text-white mb-3 flex items-center gap-2">
      {children}
    </h2>
  )
}

function Card({ children }: { children: React.ReactNode }) {
  return (
    <div className="rounded-xl border border-white/5 bg-white/[0.03] p-4 text-sm leading-relaxed text-gray-300">
      {children}
    </div>
  )
}

function Step({ n, children }: { n: number; children: React.ReactNode }) {
  return (
    <li className="flex gap-3">
      <span className="shrink-0 w-6 h-6 rounded-full bg-blue-600/20 text-blue-400 text-xs font-semibold flex items-center justify-center">
        {n}
      </span>
      <span className="text-sm text-gray-300 leading-relaxed pt-0.5">{children}</span>
    </li>
  )
}

function Code({ children }: { children: React.ReactNode }) {
  return (
    <code className="font-mono text-[12px] bg-black/40 border border-white/5 rounded px-1.5 py-0.5 text-blue-300">
      {children}
    </code>
  )
}

export function Docs() {
  const [active, setActive] = useState('overview')

  function go(id: string) {
    setActive(id)
    document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }

  return (
    <div className="flex flex-1 min-h-0 overflow-hidden">
      {/* Table of contents */}
      <nav className="hidden lg:block w-60 shrink-0 border-r border-white/5 overflow-y-auto p-4">
        <p className="text-[10px] text-gray-500 uppercase tracking-widest mb-3">User Guide</p>
        <ul className="space-y-0.5">
          {SECTIONS.map((s) => {
            const Icon = s.icon
            return (
              <li key={s.id}>
                <button
                  onClick={() => go(s.id)}
                  className={`w-full flex items-center gap-2.5 px-2.5 py-2 rounded-lg text-sm text-left transition-colors ${
                    active === s.id
                      ? 'bg-blue-600/20 text-blue-400 font-medium'
                      : 'text-gray-400 hover:text-gray-200 hover:bg-white/5'
                  }`}
                >
                  <Icon size={14} className="shrink-0" />
                  {s.title}
                </button>
              </li>
            )
          })}
        </ul>
      </nav>

      {/* Content */}
      <div className="flex-1 overflow-y-auto">
        <div className="max-w-3xl mx-auto px-5 py-6 space-y-10">

          {/* Hero */}
          <header className="border-b border-white/5 pb-6">
            <div className="flex items-center gap-3 mb-2">
              <div className="w-9 h-9 rounded-lg bg-blue-600 flex items-center justify-center">
                <Shield size={18} className="text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-white">SIEMAgent User Guide</h1>
                <p className="text-xs text-gray-500">AI-powered security log classification & incident response</p>
              </div>
            </div>
            <p className="text-sm text-gray-400 leading-relaxed">
              SIEMAgent reads raw security logs, uses a large language model to classify each event,
              maps it to the MITRE ATT&CK framework, and — for critical events — automatically launches
              an AI agent that enriches the alert with threat intelligence and writes a response playbook.
            </p>
          </header>

          {/* Overview */}
          <section className="space-y-3">
            <H id="overview"><BookOpen size={18} className="text-blue-400" /> What SIEMAgent does</H>
            <Card>
              Paste or upload a log line and SIEMAgent tells you, in seconds: <strong className="text-gray-100">what
              kind of attack it is</strong>, <strong className="text-gray-100">how urgent it is</strong> (P1–P5),
              which <strong className="text-gray-100">MITRE ATT&CK</strong> tactic and technique it matches, the
              <strong className="text-gray-100"> indicators of compromise</strong> to block, and a
              <strong className="text-gray-100"> recommended remediation</strong>. Every event is also embedded into
              a vector database so you can later find similar past events.
            </Card>
            <div className="grid sm:grid-cols-3 gap-3">
              {[
                { t: 'Classify', d: 'LLM tags attack type, severity & MITRE mapping' },
                { t: 'Investigate', d: 'Agent auto-enriches P1/P2 alerts with threat intel' },
                { t: 'Correlate', d: 'Vector search surfaces similar historical events' },
              ].map((f) => (
                <div key={f.t} className="rounded-xl border border-white/5 bg-white/[0.03] p-3">
                  <p className="text-sm font-medium text-blue-400 mb-1">{f.t}</p>
                  <p className="text-xs text-gray-400 leading-relaxed">{f.d}</p>
                </div>
              ))}
            </div>
          </section>

          {/* Quickstart */}
          <section className="space-y-3">
            <H id="quickstart"><Zap size={18} className="text-blue-400" /> Classify your first log</H>
            <ol className="space-y-3">
              <Step n={1}>
                Paste a log line into the input at the top of the screen — for example a syslog line
                like <Code>{'<165>1 2024-01-15T10:30:00Z web sshd 1234 - Failed password for root from 192.168.1.100'}</Code>.
              </Step>
              <Step n={2}>Press <Code>Enter</Code> or click <strong className="text-gray-100">Classify</strong>.</Step>
              <Step n={3}>
                The event appears in the list on the left, and a detail panel slides in on the right with the full analysis.
              </Step>
              <Step n={4}>
                Don't have a log handy? SIEMAgent accepts RFC 5424 / RFC 3164 syslog, JSON logs, or plain text — format
                is auto-detected.
              </Step>
            </ol>
          </section>

          {/* Results */}
          <section className="space-y-3">
            <H id="results"><FileText size={18} className="text-blue-400" /> Reading a result</H>
            <div className="space-y-2">
              {[
                ['Severity badge', 'P1 (Critical) → P5 (Info). Drives colour-coding and whether an auto-investigation fires.'],
                ['Attack type', 'Human-readable category — Brute Force, SQL Injection, Data Destruction, Benign, etc.'],
                ['Confidence', 'The model\'s self-reported certainty (0–100%). Treat low-confidence P1s as "verify first".'],
                ['MITRE ATT&CK', 'Tactic + technique ID (e.g. T1110.001). Click through on the heatmap to see coverage.'],
                ['Indicators of Compromise', 'Concrete IPs, domains, hashes, usernames and paths pulled from the log — the things to block.'],
                ['Recommended action', 'A short, concrete remediation you can hand to an on-call responder.'],
              ].map(([t, d]) => (
                <div key={t} className="flex gap-3 rounded-lg border border-white/5 bg-white/[0.03] p-3">
                  <ChevronRight size={16} className="text-blue-400 shrink-0 mt-0.5" />
                  <div>
                    <p className="text-sm font-medium text-gray-100">{t}</p>
                    <p className="text-xs text-gray-400 leading-relaxed mt-0.5">{d}</p>
                  </div>
                </div>
              ))}
            </div>
          </section>

          {/* Upload */}
          <section className="space-y-3">
            <H id="upload"><Upload size={18} className="text-blue-400" /> Bulk upload a log file</H>
            <Card>
              Click <strong className="text-gray-100">Upload</strong> (top-left) or drag a <Code>.log</Code> /
              <Code>.txt</Code> file onto the window. SIEMAgent parses every line and classifies them in parallel
              through a worker pool — up to 500 lines per upload. Results stream into the event list as they complete,
              and the analytics panel updates live.
            </Card>
          </section>

          {/* Incidents */}
          <section className="space-y-3">
            <H id="incidents"><Radio size={18} className="text-blue-400" /> Live incident investigations</H>
            <Card>
              When a classification comes back <SeverityBadge severity="P1" size="sm" /> or
              {' '}<SeverityBadge severity="P2" size="sm" />, SIEMAgent automatically launches an autonomous agent.
              A banner appears at the top of the screen — click it to open the investigation.
            </Card>
            <p className="text-sm text-gray-400">Inside an investigation you'll see:</p>
            <ul className="space-y-2">
              <Step n={1}><strong className="text-gray-100">A tool timeline</strong> — every action the agent took: IP reputation lookups (AbuseIPDB), threat-intel pulses (AlienVault OTX), MITRE technique lookups, and searches over your own past events.</Step>
              <Step n={2}><strong className="text-gray-100">Threat-intel cards</strong> — the enriched verdict for each indicator.</Step>
              <Step n={3}><strong className="text-gray-100">A streaming playbook</strong> — a full markdown incident-response plan, written token-by-token. Use <strong className="text-gray-100">Copy Playbook</strong> to hand it off.</Step>
            </ul>
          </section>

          {/* Analytics */}
          <section className="space-y-3">
            <H id="analytics"><BarChart2 size={18} className="text-blue-400" /> Analytics & MITRE heatmap</H>
            <Card>
              The Analytics tab summarises everything classified this session: counts of critical and high events,
              a breakdown by attack type, an event-rate timeline for the last 6 hours, and a distribution of MITRE
              tactics. The <strong className="text-gray-100">MITRE ATT&CK heatmap</strong> plots tactics against a
              weekly grid — brighter cells mean more (or more severe) activity, so you can spot which stage of the
              kill chain is lighting up.
            </Card>
          </section>

          {/* Search */}
          <section className="space-y-3">
            <H id="search"><Search size={18} className="text-blue-400" /> Finding similar events</H>
            <Card>
              Every classified event is embedded (via a local <Code>nomic-embed-text</Code> model) and stored in a
              Qdrant vector database. Open any event's detail panel and scroll to
              <strong className="text-gray-100"> Similar past events</strong> to see semantically related incidents —
              useful for spotting a campaign made of individually low-severity events.
            </Card>
          </section>

          {/* Severity reference */}
          <section className="space-y-3">
            <H id="severity"><Shield size={18} className="text-blue-400" /> Severity reference</H>
            <div className="rounded-xl border border-white/5 overflow-hidden">
              {ALL_SEV.map(({ s, when }, i) => (
                <div
                  key={s}
                  className={`flex items-center gap-3 px-4 py-3 ${i > 0 ? 'border-t border-white/5' : ''}`}
                >
                  <SeverityBadge severity={s} size="sm" />
                  <span className="text-sm text-gray-400">{when}</span>
                </div>
              ))}
            </div>
          </section>

          {/* FAQ */}
          <section className="space-y-3">
            <H id="faq"><HelpCircle size={18} className="text-blue-400" /> Tips & FAQ</H>
            <div className="space-y-2">
              {[
                ['Why did no investigation fire?', 'Auto-investigation only triggers for P1/P2 events. Lower severities are classified but not escalated.'],
                ['My events disappeared after refresh.', 'The event list is per-session (kept in the browser). Analytics and similar-event search are backed by the server and persist.'],
                ['Threat-intel cards are empty.', 'AbuseIPDB and OTX require API keys (ABUSEIPDB_KEY, OTX_API_KEY) on the server. Without them the agent still runs, just without external enrichment.'],
                ['How accurate is the classification?', 'It is an LLM judgement, not ground truth. Use the confidence score and always verify P1s before acting.'],
              ].map(([q, a]) => (
                <details key={q} className="group rounded-lg border border-white/5 bg-white/[0.03] px-4 py-3">
                  <summary className="cursor-pointer text-sm font-medium text-gray-200 list-none flex items-center justify-between">
                    {q}
                    <ChevronRight size={14} className="text-gray-500 group-open:rotate-90 transition-transform" />
                  </summary>
                  <p className="text-xs text-gray-400 leading-relaxed mt-2">{a}</p>
                </details>
              ))}
            </div>
          </section>

          {/* API */}
          <section className="space-y-3">
            <H id="api"><Terminal size={18} className="text-blue-400" /> For developers</H>
            <Card>
              Everything in this UI is backed by a documented HTTP API. The full interactive
              OpenAPI / Swagger reference — with request/response schemas and a "try it out" console — is served at
              {' '}<a href="/docs" target="_blank" rel="noreferrer" className="text-blue-400 hover:underline">/docs</a>.
              Key endpoints:
            </Card>
            <div className="rounded-xl border border-white/5 overflow-hidden text-sm">
              {[
                ['POST', '/api/classify', 'Classify a single log line'],
                ['POST', '/api/ingest', 'Bulk-classify up to 500 lines'],
                ['GET', '/api/search', 'Semantic vector search'],
                ['GET', '/api/analytics/summary', 'Session analytics'],
                ['GET', '/ws/alerts', 'WebSocket live incident stream'],
              ].map(([m, p, d], i) => (
                <div key={p} className={`flex items-center gap-3 px-4 py-2.5 ${i > 0 ? 'border-t border-white/5' : ''}`}>
                  <span className={`font-mono text-[10px] font-semibold px-1.5 py-0.5 rounded ${
                    m === 'GET' ? 'bg-green-500/15 text-green-400' : 'bg-blue-500/15 text-blue-400'
                  }`}>{m}</span>
                  <Code>{p}</Code>
                  <span className="text-xs text-gray-500 ml-auto hidden sm:block">{d}</span>
                </div>
              ))}
            </div>
          </section>

          <footer className="border-t border-white/5 pt-4 text-xs text-gray-600">
            SIEMAgent · AI Security Classifier — this guide is also available offline inside the app.
          </footer>
        </div>
      </div>
    </div>
  )
}
