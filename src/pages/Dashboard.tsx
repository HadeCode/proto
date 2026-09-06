import SimulationPanel from "@/components/SimulationPanel";
import HealthReport from "@/components/HealthReport";
import { useArgus } from "@/data/api";
import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend,
} from "recharts";
import {
  Card, MetricCard, SeverityBadge, SectionHeader, TableWrapper, Th, Td, LiveDot,
} from "@/components/ui";
import { formatBytes, severityColor } from "@/data/mockData";

const TIME_RANGES = ["5m", "15m", "1h", "6h", "24h"];
const CHART_FILTERS = ["All", "Critical", "High", "Medium", "Low"];

export default function Dashboard() {
  const { ALERTS, THREAT_TIMESERIES, THREAT_DISTRIBUTION, data, connected, updateAlert, mutate, busy } = useArgus();
  const navigate = useNavigate();
  const [timeRange, setTimeRange] = useState("1h");
  const [chartFilter, setChartFilter] = useState("All");

  const critical = ALERTS.filter((a) => a.severity === "critical").length;
  const high = ALERTS.filter((a) => a.severity === "high").length;
  const medium = ALERTS.filter((a) => a.severity === "medium").length;
  const low = ALERTS.filter((a) => a.severity === "low").length;
  const openAlerts = ALERTS.filter((a) => a.status === "OPEN").length;

  const topThreats = [...ALERTS].sort((a,b) => b.risk_score-a.risk_score).slice(0,5).map((a,i) => ({ rank: String(i+1).padStart(2,"0"), name: a.threat_class, severity: a.severity, pct: Math.round(a.risk_score*100) }));
  const minutes = ({ "5m": 5, "15m": 15, "1h": 60, "6h": 360, "24h": 1440 })[timeRange] ?? 60;
  const latest = Math.max(Date.now(), ...ALERTS.map(a => Date.parse(a.timestamp)));
  const chartData = THREAT_TIMESERIES.filter(b => Date.parse(b.time + ":00Z") >= latest-minutes*60000);

  return (
    <div className="p-6 max-w-[1440px] mx-auto space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-[26px] font-bold text-[#F3F5F7] tracking-tight">ARGUS-ONE</h1>
          <p className="text-[13px] text-[#9AA4B2] mt-0.5">Passive Network Threat Intelligence</p>
          <p className="text-[12px] text-[#66707D]">Real-time analysis of normalized network flow metadata.</p>
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1.5">
            <LiveDot />
            <span className="text-[12px] text-[#20D3A2] font-semibold">{connected ? "CONNECTED" : "OFFLINE"}</span>
          </div>
          <div className="flex items-center gap-1 bg-[#0D1117] border border-[#242B35] rounded-lg p-0.5">
            {TIME_RANGES.map((r) => (
              <button
                key={r}
                onClick={() => setTimeRange(r)}
                className={`px-3 py-1 text-[11px] font-semibold rounded transition-colors ${
                  timeRange === r
                    ? "bg-[#20D3A2]/10 text-[#20D3A2]"
                    : "text-[#66707D] hover:text-[#9AA4B2]"
                }`}
              >
                {r}
              </button>
            ))}
          </div>
        </div>
      </div>

      <SimulationPanel />

      {/* ML Engine Status Banner */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between p-3.5 rounded-lg bg-gradient-to-r from-[#11161D] via-[#151D28] to-[#11161D] border border-[#20D3A2]/30">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-[#20D3A2]/10 border border-[#20D3A2]/40 flex items-center justify-center text-[#20D3A2] font-bold text-sm">
            ⚡
          </div>
          <div>
            <div className="text-[13px] font-bold text-[#F3F5F7] flex items-center gap-2">
              <span>ML Engine: {data.ml?.active_model_name ?? "Random Forest Classifier"}</span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#20D3A2]/20 text-[#20D3A2]">
                HYBRID AI ENSEMBLE
              </span>
            </div>
            <div className="text-[11px] text-[#9AA4B2] mt-0.5">
              Trained on iperf3/TRex benign load & lab attack scenarios • Attack Recall: {((data.ml?.recall ?? 0.99) * 100).toFixed(1)}% • Latency: {data.ml?.avg_latency_ms ?? 0.4} ms
            </div>
          </div>
        </div>
        <button
          onClick={() => navigate("/ml-models")}
          className="mt-2 sm:mt-0 text-[12px] font-semibold text-[#20D3A2] hover:text-[#20D3A2]/80 hover:underline flex items-center gap-1"
        >
          Inspect ML Models & Inferences →
        </button>
      </div>

      {/* KPI Row */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        <MetricCard
          title="Flows Processed"
          value={data.summary.flows_processed.toLocaleString()}
          sub={<span className="text-[#20D3A2]">Retained history (up to 20,000)</span>}
        />
        <MetricCard
          title="Threats Detected"
          value={ALERTS.length}
          onClick={() => navigate("/threats")}
          sub={
            <div className="space-y-0.5">
              <div className="flex gap-1"><span className="text-[#EB5757]">●</span><span>{critical} Critical</span></div>
              <div className="flex gap-1"><span className="text-[#F2994A]">●</span><span>{high} High</span></div>
              <div className="flex gap-1"><span className="text-[#F2C94C]">●</span><span>{medium} Medium</span></div>
              <div className="flex gap-1"><span className="text-[#4C9AFF]">●</span><span>{low} Low</span></div>
            </div>
          }
        />
        <MetricCard
          title="Critical Threats"
          value={critical}
          accent="#EB5757"
          onClick={() => navigate("/threats?severity=critical")}
          sub={<span className="flex items-center gap-1"><span className="text-[#EB5757]">●</span> Requires attention</span>}
        />
        <MetricCard
          title="Active Alerts"
          value={openAlerts}
          onClick={() => navigate("/alerts")}
          sub={<span className="text-[#9AA4B2]">Open / unacknowledged</span>}
        />
        <MetricCard
          title="Detection Engine"
          value={connected ? "ACTIVE" : "OFFLINE"}
          accent="#20D3A2"
          onClick={() => navigate("/engines")}
          sub={<span className="text-[#9AA4B2]">9 detectors running</span>}
        />
        <MetricCard
          title="Data Sources"
          value={data.summary.collector_flows ? "1" : "0"}
          sub={<span className="text-[#20D3A2]">HTTP collector input</span>}
          onClick={() => navigate("/data-sources")}
        />
      </div>

      {/* System Health Report */}
      <HealthReport />

      {/* Threat Activity Chart */}
      <Card className="p-4">
        <div className="flex items-center justify-between mb-4">
          <div>
            <div className="text-[15px] font-semibold text-[#F3F5F7]">Threat Activity</div>
            <div className="text-[12px] text-[#9AA4B2]">Detected threats over time</div>
          </div>
          <div className="flex items-center gap-1 bg-[#0D1117] border border-[#242B35] rounded p-0.5">
            {CHART_FILTERS.map((f) => (
              <button
                key={f}
                onClick={() => setChartFilter(f)}
                className={`px-2.5 py-1 text-[11px] rounded transition-colors ${
                  chartFilter === f ? "bg-[#20D3A2]/10 text-[#20D3A2]" : "text-[#66707D] hover:text-[#9AA4B2]"
                }`}
              >
                {f}
              </button>
            ))}
          </div>
        </div>
        <ResponsiveContainer width="100%" height={180}>
          <AreaChart data={chartData} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
            <defs>
              <linearGradient id="gcrit" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#EB5757" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#EB5757" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="ghigh" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#F2994A" stopOpacity={0.2} />
                <stop offset="95%" stopColor="#F2994A" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="gmed" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#F2C94C" stopOpacity={0.2} />
                <stop offset="95%" stopColor="#F2C94C" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid stroke="#1A2030" strokeDasharray="3 3" />
            <XAxis dataKey="time" tick={{ fill: "#66707D", fontSize: 10 }} tickLine={false} />
            <YAxis tick={{ fill: "#66707D", fontSize: 10 }} tickLine={false} axisLine={false} />
            <Tooltip
              contentStyle={{ background: "#11161D", border: "1px solid #242B35", borderRadius: 6, fontSize: 12 }}
              labelStyle={{ color: "#9AA4B2" }}
            />
            {(chartFilter === "All" || chartFilter === "Critical") && (
              <Area type="monotone" dataKey="critical" stroke="#EB5757" fill="url(#gcrit)" strokeWidth={1.5} />
            )}
            {(chartFilter === "All" || chartFilter === "High") && (
              <Area type="monotone" dataKey="high" stroke="#F2994A" fill="url(#ghigh)" strokeWidth={1.5} />
            )}
            {(chartFilter === "All" || chartFilter === "Medium") && (
              <Area type="monotone" dataKey="medium" stroke="#F2C94C" fill="url(#gmed)" strokeWidth={1.5} />
            )}
            {(chartFilter === "All" || chartFilter === "Low") && (
              <Area type="monotone" dataKey="low" stroke="#4C9AFF" fill="none" strokeWidth={1} strokeDasharray="3 3" />
            )}
          </AreaChart>
        </ResponsiveContainer>
      </Card>

      {/* Distribution + Top Threats */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Donut */}
        <Card className="p-4">
          <SectionHeader title="Threat Distribution" />
          <div className="flex items-center gap-4">
            <ResponsiveContainer width={180} height={180}>
              <PieChart>
                <Pie data={THREAT_DISTRIBUTION} cx="50%" cy="50%" innerRadius={50} outerRadius={80} dataKey="value" strokeWidth={2} stroke="#11161D">
                  {THREAT_DISTRIBUTION.map((entry, index) => (
                    <Cell key={index} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ background: "#11161D", border: "1px solid #242B35", borderRadius: 6, fontSize: 11 }}
                  formatter={(val, name) => [val, name]}
                />
              </PieChart>
            </ResponsiveContainer>
            <div className="flex-1 space-y-1.5">
              {THREAT_DISTRIBUTION.slice(0, 6).map((d) => (
                <div key={d.name} className="flex items-center justify-between">
                  <div className="flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: d.color }} />
                    <span className="text-[11px] text-[#9AA4B2] truncate">{d.name}</span>
                  </div>
                  <span className="text-[11px] text-[#66707D] font-mono">{d.value}</span>
                </div>
              ))}
            </div>
          </div>
        </Card>

        {/* Top Threats */}
        <Card className="p-4">
          <SectionHeader title="Top Threats" />
          <div className="space-y-3">
            {topThreats.map((t) => (
              <div key={t.rank} className="flex items-center gap-3">
                <span className="text-[11px] font-mono text-[#66707D] w-5">{t.rank}</span>
                <div className="flex-1">
                  <div className="text-[13px] text-[#F3F5F7] font-medium">{t.name}</div>
                  <div className="mt-1 h-1.5 bg-[#1A2030] rounded-full overflow-hidden">
                    <div
                      className="h-full rounded-full"
                      style={{ width: `${t.pct}%`, background: severityColor(t.severity) }}
                    />
                  </div>
                </div>
                <SeverityBadge severity={t.severity} />
                <span className="text-[12px] font-mono font-semibold" style={{ color: severityColor(t.severity) }}>
                  {t.pct}%
                </span>
              </div>
            ))}
          </div>
        </Card>
      </div>

      {/* Live Detection Feed */}
      <Card>
        <div className="flex items-center justify-between px-4 pt-4 pb-3 border-b border-[#242B35]">
          <div>
            <div className="text-[15px] font-semibold text-[#F3F5F7] flex items-center gap-2">
              Live Detection Feed <LiveDot />
            </div>
            <div className="text-[12px] text-[#9AA4B2]">Most recent threat detections</div>
          </div>
          <button
            onClick={() => navigate("/alerts")}
            className="text-[12px] text-[#20D3A2] hover:underline"
          >
            View all →
          </button>
        </div>
        <TableWrapper>
          <thead>
            <tr>
              <Th>Time</Th>
              <Th>Severity</Th>
              <Th>Threat</Th>
              <Th>Source</Th>
              <Th>Target</Th>
              <Th>Risk</Th>
              <Th>Detector</Th>
              <Th>Status</Th>
            </tr>
          </thead>
          <tbody>
            {ALERTS.slice(0, 6).map((a) => (
              <tr
                key={a.alert_id}
                className="hoverable cursor-pointer"
                onClick={() => navigate(`/alerts/${a.alert_id}`)}
              >
                <Td mono>{a.timestamp.split("T")[1]?.replace("Z", "") ?? a.timestamp}</Td>
                <Td><SeverityBadge severity={a.severity} /></Td>
                <Td className="text-[#F3F5F7] font-medium">{a.threat_class}</Td>
                <Td mono>{a.source.ip}</Td>
                <Td mono>{a.target.ip}</Td>
                <Td>
                  <span className="font-mono font-semibold" style={{ color: severityColor(a.severity) }}>
                    {Math.round(a.risk_score * 100)}
                  </span>
                </Td>
                <Td mono className="text-[#66707D]">{a.detector}</Td>
                <Td>
                  <span className={`text-[11px] font-semibold ${
                    a.status === "OPEN" ? "text-[#EB5757]" : a.status === "ACKNOWLEDGED" ? "text-[#F2C94C]" : "text-[#20D3A2]"
                  }`}>{a.status}</span>
                </Td>
              </tr>
            ))}
          </tbody>
        </TableWrapper>
      </Card>
    </div>
  );
}
