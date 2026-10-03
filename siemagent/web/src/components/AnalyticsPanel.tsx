import { useQuery } from '@tanstack/react-query'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
  LineChart, Line, PieChart, Pie, Legend,
} from 'recharts'
import { getAnalytics } from '../lib/api'
import type { Severity } from '../styles/tokens'
import { useChartColors } from '../theme/chartColors'
import { TrendingUp, Shield, Activity } from 'lucide-react'

const CARD = 'bg-surface border border-line rounded-xl p-3 shadow-card'
const CARD_TITLE = 'text-[10px] font-medium text-fg-subtle uppercase tracking-widest mb-3 flex items-center gap-1.5'

export function AnalyticsPanel() {
  const c = useChartColors()
  const tooltipStyle = {
    background: c.tooltipBg,
    border: `1px solid ${c.tooltipBorder}`,
    borderRadius: 8,
    color: c.tooltipText,
    fontSize: 11,
    padding: '6px 10px',
    boxShadow: '0 8px 24px -12px rgba(0,0,0,0.35)',
  }
  const tick = { fill: c.text, fontSize: 9 }

  const { data, isLoading, isError } = useQuery({
    queryKey: ['analytics'],
    queryFn: getAnalytics,
    refetchInterval: 30_000,
    staleTime: 15_000,
  })

  if (isLoading) {
    return (
      <div className="p-4 space-y-4">
        {[180, 140, 180].map((h, i) => (
          <div key={i} className="rounded-xl bg-fg/4 animate-pulse" style={{ height: h }} />
        ))}
      </div>
    )
  }

  if (isError || !data) {
    return (
      <div className="flex flex-col items-center justify-center h-40 text-center px-4">
        <Activity size={24} className="text-fg-subtle mb-2" />
        <p className="text-xs text-fg-subtle">Analytics unavailable</p>
      </div>
    )
  }

  const attackData = Object.entries(data.attack_type_counts)
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, 10)
    .map(([name, info]) => ({
      name: name.length > 16 ? name.slice(0, 14) + '…' : name,
      count: info.count,
      severity: info.severity,
    }))

  const timelineData = data.timeline.map(b => ({
    time: b.time,
    P1: b.counts['P1'] ?? 0,
    P2: b.counts['P2'] ?? 0,
    P3: b.counts['P3'] ?? 0,
  }))

  const tacticData = Object.entries(data.mitre_tactics)
    .filter(([t]) => t && t !== 'N/A')
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([name, value]) => ({ name, value }))

  const criticalCount = Object.values(data.attack_type_counts)
    .filter(v => v.severity === 'P1').reduce((a, v) => a + v.count, 0)
  const highCount = Object.values(data.attack_type_counts)
    .filter(v => v.severity === 'P2').reduce((a, v) => a + v.count, 0)

  return (
    <div className="p-4 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-fg flex items-center gap-2">
          <TrendingUp size={15} className="text-accent-text" />
          Analytics
        </h2>
        <span className="text-[10px] text-fg-subtle">{data.total_events} events total</span>
      </div>

      {/* Quick stat cards */}
      <div className="grid grid-cols-2 gap-2">
        <div className="bg-sev-p1/10 border border-sev-p1/25 rounded-xl p-3">
          <p className="text-[10px] text-sev-p1 uppercase tracking-widest">Critical</p>
          <p className="text-2xl font-bold text-sev-p1 mt-0.5">{criticalCount}</p>
        </div>
        <div className="bg-sev-p2/10 border border-sev-p2/25 rounded-xl p-3">
          <p className="text-[10px] text-sev-p2 uppercase tracking-widest">High</p>
          <p className="text-2xl font-bold text-sev-p2 mt-0.5">{highCount}</p>
        </div>
      </div>

      {/* Attack type bar chart */}
      {attackData.length > 0 && (
        <div className={CARD}>
          <p className={CARD_TITLE}>
            <Shield size={11} /> Attack Types
          </p>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={attackData} margin={{ left: -20, right: 4, top: 4, bottom: 36 }}>
              <XAxis
                dataKey="name"
                tick={tick}
                axisLine={{ stroke: c.axis }}
                tickLine={false}
                interval={0}
                angle={-35}
                textAnchor="end"
                height={50}
              />
              <YAxis
                tick={tick}
                axisLine={false}
                tickLine={false}
                allowDecimals={false}
              />
              <Tooltip contentStyle={tooltipStyle} itemStyle={{ color: c.tooltipText }} cursor={{ fill: c.grid, opacity: 0.5 }} />
              <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                {attackData.map((entry, i) => (
                  <Cell key={i} fill={c.severity[entry.severity as Severity] ?? c.axis} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Timeline */}
      <div className={CARD}>
        <p className={CARD_TITLE}>
          <Activity size={11} /> Event Rate (6h)
        </p>
        <ResponsiveContainer width="100%" height={120}>
          <LineChart data={timelineData} margin={{ left: -20, right: 4, top: 4, bottom: 0 }}>
            <XAxis
              dataKey="time"
              tick={tick}
              axisLine={{ stroke: c.axis }}
              tickLine={false}
              interval={5}
            />
            <YAxis
              tick={tick}
              axisLine={false}
              tickLine={false}
              allowDecimals={false}
            />
            <Tooltip contentStyle={tooltipStyle} itemStyle={{ color: c.tooltipText }} />
            <Line type="monotone" dataKey="P1" stroke={c.severity.P1} dot={false} strokeWidth={2} />
            <Line type="monotone" dataKey="P2" stroke={c.severity.P2} dot={false} strokeWidth={2} />
            <Line type="monotone" dataKey="P3" stroke={c.severity.P3} dot={false} strokeWidth={1.5} strokeDasharray="4 2" />
          </LineChart>
        </ResponsiveContainer>
        <div className="flex items-center gap-3 mt-2 justify-end">
          {(['P1','P2','P3'] as const).map(s => (
            <span key={s} className="flex items-center gap-1 text-[10px] text-fg-subtle">
              <span className="w-3 h-0.5 rounded-full inline-block" style={{ background: c.severity[s] }} />
              {s}
            </span>
          ))}
        </div>
      </div>

      {/* MITRE pie */}
      {tacticData.length > 0 && (
        <div className={CARD}>
          <p className={CARD_TITLE}>MITRE Tactics</p>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie
                data={tacticData}
                dataKey="value"
                nameKey="name"
                cx="50%"
                cy="45%"
                outerRadius={60}
                innerRadius={28}
                paddingAngle={2}
              >
                {tacticData.map((_, i) => (
                  <Cell key={i} fill={c.series[i % c.series.length]} stroke={c.tooltipBg} />
                ))}
              </Pie>
              <Tooltip contentStyle={tooltipStyle} itemStyle={{ color: c.tooltipText }} />
              <Legend
                wrapperStyle={{ color: c.text, fontSize: 10, paddingTop: 8 }}
                iconSize={8}
                iconType="circle"
              />
            </PieChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  )
}
