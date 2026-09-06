import { useArgus } from "@/data/api";
import React from "react";
import { Card, PageHeader, SectionHeader } from "@/components/ui";
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from "recharts";
import { severityColor } from "@/data/mockData";

export default function Analytics() {
  const { ALERTS, THREAT_TIMESERIES, THREAT_DISTRIBUTION, data, connected, updateAlert, mutate, busy } = useArgus();
  const ranks = (side: "source" | "target") => [...new Set(ALERTS.map(a => a[side].ip))].map(ip => ({ ip, count: ALERTS.filter(a => a[side].ip === ip).length, severity: ALERTS.find(a => a[side].ip === ip)!.severity, label: "Observed" })).sort((a,b) => b.count-a.count).slice(0,5);
  const TOP_SOURCES = ranks("source"), TOP_DESTS = ranks("target");
  const DETECTOR_PERF = data.detectors.map(d => ({ name: d.id, alerts: d.alerts_generated, observations: d.observations }));
  const PROTO_DIST = Object.entries(data.summary.protocols).map(([name,value],i) => ({ name, value, color: ["#4C9AFF","#F2C94C","#20D3A2"][i%3] }));
  return (
    <div className="p-6 max-w-[1440px] mx-auto space-y-5">
      <PageHeader
        title="Threat Analytics"
        breadcrumb="Analysis"
        subtitle="Aggregated threat intelligence across all detection engines."
      />

      {/* Threat volume over time */}
      <Card className="p-4">
        <SectionHeader title="Threat Volume Over Time" subtitle="Retained detection activity by severity" />
        <ResponsiveContainer width="100%" height={200}>
          <AreaChart data={THREAT_TIMESERIES} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
            <defs>
              {[["crit","#EB5757"],["high","#F2994A"],["med","#F2C94C"]].map(([k,c]) => (
                <linearGradient key={k} id={`g${k}`} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={c} stopOpacity={0.25} />
                  <stop offset="95%" stopColor={c} stopOpacity={0} />
                </linearGradient>
              ))}
            </defs>
            <CartesianGrid stroke="#1A2030" strokeDasharray="3 3" />
            <XAxis dataKey="time" tick={{ fill: "#66707D", fontSize: 10 }} tickLine={false} />
            <YAxis tick={{ fill: "#66707D", fontSize: 10 }} tickLine={false} axisLine={false} />
            <Tooltip contentStyle={{ background: "#11161D", border: "1px solid #242B35", borderRadius: 6, fontSize: 11 }} />
            <Area type="monotone" dataKey="critical" stroke="#EB5757" fill="url(#gcrit)" strokeWidth={2} name="Critical" />
            <Area type="monotone" dataKey="high" stroke="#F2994A" fill="url(#ghigh)" strokeWidth={1.5} name="High" />
            <Area type="monotone" dataKey="medium" stroke="#F2C94C" fill="url(#gmed)" strokeWidth={1.5} name="Medium" />
          </AreaChart>
        </ResponsiveContainer>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Detector Performance */}
        <Card className="p-4">
          <SectionHeader title="Detector Performance" subtitle="Alerts generated per detector" />
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={DETECTOR_PERF} layout="vertical" margin={{ top: 0, right: 10, left: 30, bottom: 0 }}>
              <CartesianGrid stroke="#1A2030" strokeDasharray="3 3" horizontal={false} />
              <XAxis type="number" tick={{ fill: "#66707D", fontSize: 10 }} tickLine={false} />
              <YAxis type="category" dataKey="name" tick={{ fill: "#9AA4B2", fontSize: 10, fontFamily: "JetBrains Mono" }} tickLine={false} width={80} />
              <Tooltip contentStyle={{ background: "#11161D", border: "1px solid #242B35", borderRadius: 6, fontSize: 11 }} />
              <Bar dataKey="alerts" fill="#20D3A2" radius={[0, 2, 2, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </Card>

        {/* Protocol Distribution */}
        <Card className="p-4">
          <SectionHeader title="Protocol Distribution" />
          <div className="flex items-center gap-6">
            <ResponsiveContainer width={180} height={180}>
              <PieChart>
                <Pie data={PROTO_DIST} cx="50%" cy="50%" innerRadius={45} outerRadius={75} dataKey="value" strokeWidth={2} stroke="#11161D">
                  {PROTO_DIST.map((e, i) => <Cell key={i} fill={e.color} />)}
                </Pie>
                <Tooltip contentStyle={{ background: "#11161D", border: "1px solid #242B35", borderRadius: 6, fontSize: 11 }} />
              </PieChart>
            </ResponsiveContainer>
            <div className="space-y-3">
              {PROTO_DIST.map((p) => (
                <div key={p.name} className="flex items-center justify-between gap-8">
                  <div className="flex items-center gap-2">
                    <span className="w-2.5 h-2.5 rounded-sm" style={{ background: p.color }} />
                    <span className="text-[12px] font-mono text-[#9AA4B2]">{p.name}</span>
                  </div>
                  <span className="text-[12px] font-mono text-[#F3F5F7] font-semibold">{p.value}%</span>
                </div>
              ))}
            </div>
          </div>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Top Source IPs */}
        <Card className="p-4">
          <SectionHeader title="Top Source IPs" subtitle="By threat count" />
          <div className="space-y-3">
            {TOP_SOURCES.map((s, i) => (
              <div key={s.ip} className="flex items-center gap-3">
                <span className="text-[11px] font-mono text-[#66707D] w-5">{String(i + 1).padStart(2, "0")}</span>
                <div className="flex-1">
                  <div className="flex justify-between mb-1">
                    <span className="text-[12px] font-mono text-[#F3F5F7]">{s.ip}</span>
                    <span className="text-[11px] font-mono" style={{ color: severityColor(s.severity) }}>{s.count} threats</span>
                  </div>
                  <div className="h-1.5 bg-[#1A2030] rounded-full overflow-hidden">
                    <div className="h-full rounded-full" style={{ width: `${(s.count / Math.max(1, ...TOP_SOURCES.map(s => s.count))) * 100}%`, background: severityColor(s.severity) }} />
                  </div>
                </div>
              </div>
            ))}
          </div>
        </Card>

        {/* Top Destinations */}
        <Card className="p-4">
          <SectionHeader title="Top Destination IPs" subtitle="Observed targets by frequency" />
          <div className="space-y-3">
            {TOP_DESTS.map((d, i) => (
              <div key={d.ip} className="flex items-center gap-3">
                <span className="text-[11px] font-mono text-[#66707D] w-5">{String(i + 1).padStart(2, "0")}</span>
                <div className="flex-1">
                  <div className="flex justify-between mb-1">
                    <span className="text-[12px] font-mono text-[#F3F5F7]">{d.ip}</span>
                    <span className="text-[11px] text-[#9AA4B2]">{d.label}</span>
                  </div>
                  <div className="h-1.5 bg-[#1A2030] rounded-full overflow-hidden">
                    <div className="h-full rounded-full bg-[#F2994A]" style={{ width: `${(d.count / Math.max(1, ...TOP_DESTS.map(d => d.count))) * 100}%` }} />
                  </div>
                </div>
                <span className="text-[11px] font-mono text-[#66707D]">{d.count}</span>
              </div>
            ))}
          </div>
        </Card>
      </div>

      {/* Threat class frequency */}
      <Card className="p-4">
        <SectionHeader title="Most Frequent Threat Classes" />
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-9 gap-3">
          {THREAT_DISTRIBUTION.map((t) => (
            <div key={t.name} className="text-center p-3 rounded-lg bg-[#0D1117] border border-[#1A2030]">
              <div className="text-[18px] font-bold font-mono" style={{ color: t.color }}>{t.value}</div>
              <div className="text-[10px] text-[#66707D] mt-1 leading-tight">{t.name}</div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
