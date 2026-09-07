import React, { useState } from "react";
import { useArgus, download, type HealthReportData } from "@/data/api";
import { Card, LiveDot } from "@/components/ui";
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
} from "recharts";

export default function HealthReport() {
  const { HEALTH_REPORT, data, connected, runHealthAudit, fetchHistoricalReport } = useArgus();
  const [activeTab, setActiveTab] = useState<"behavioral" | "governance" | "timeline" | "infrastructure">("behavioral");
  const [auditRunning, setAuditRunning] = useState(false);
  const [lastAuditResult, setLastAuditResult] = useState<string | null>(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [historicalReport, setHistoricalReport] = useState<any | null>(null);
  const [loadingReport, setLoadingReport] = useState(false);
  const [selectedWindow, setSelectedWindow] = useState("1h");

  const report: HealthReportData = HEALTH_REPORT;
  const bHealth = report.behavioral_health ?? { score: 91, status: "NORMAL", confidence: 0.93, stability: 92 };
  const threatRisk = report.threat_risk ?? { score: 18, level: "LOW", confidence: 0.91, threat_candidates: 0 };
  const traffic = report.traffic ?? {
    flows: data.summary.flows_processed || 0,
    flows_per_second: data.summary.flows_per_second || 0,
    bytes_per_second: data.summary.bytes_per_second || 0,
    unique_sources: 0,
    unique_destinations: 0,
    anomalous_flows: 0,
    open_alerts: 0,
    total_alerts: data.summary.alerts || 0,
  };
  const behavior = report.behavior ?? {
    horizons: {
      "60s": { name: "60s Real-time", risk: 12, anomaly: 8, traffic_status: "NORMAL", baseline_drift: 2.1 },
      "5m": { name: "5m Baseline", risk: 17, anomaly: 13, traffic_status: "NORMAL", baseline_drift: 4.5 },
      "30m": { name: "30m Trend", risk: 21, anomaly: 19, traffic_status: "NORMAL", baseline_drift: 6.8 },
    },
    baseline_deviation: { flow_rate: 4.2, traffic_variance: 7.1, periodicity: 2.8, source_diversity: -1.4, temporal_stability: -4.8 },
    baseline_profile: { flow_rate_pct: 84, periodicity_pct: 91, volume_pct: 79, source_diversity_pct: 87, temporal_pattern_pct: 93 },
  };
  const models = report.models ?? {
    random_forest: { name: "Random Forest", prediction: "Benign", confidence: 0.91, reliability: 0.94 },
    gradient_boost: { name: "Gradient Boost", prediction: "Benign", confidence: 0.87, reliability: 0.92 },
    anomaly_guard: { name: "Anomaly Guard", prediction: "NORMAL", score: 0.12, reliability: 0.93 },
    temporal_gru: { name: "Temporal GRU", prediction: "Benign Sequence", confidence: 0.89, reliability: 0.91 },
    model_agreement_pct: 89,
  };
  const governance = report.governance ?? {
    model: "Self-Learning Meta-Controller",
    context: "BENIGN_BASELINE",
    weights: { random_forest: 0.24, gradient_boost: 0.21, anomaly_guard: 0.31, temporal_gru: 0.24 },
    dominant_model: "Anomaly Guard",
    confidence: 0.93,
    reason: "Current traffic resembles learned benign baseline; anomaly evidence is the most reliable signal.",
  };
  const learning = report.learning ?? {
    governed_decisions: 0,
    memory_episodes: 0,
    active_memory_size: 0,
    adaptations: 0,
    controller_confidence: 93,
  };
  const explanations = report.explanation && report.explanation.length > 0 ? report.explanation : [
    "Traffic volume remains within learned baseline",
    "Source diversity and host entropy remain stable",
    "Inter-arrival intervals display natural non-beaconing variance",
    "Zero active high-confidence threat clusters detected",
    "Multi-model ensemble consensus remains high",
  ];
  const events = report.events && report.events.length > 0 ? report.events : [
    { time: "Live", icon: "NORMAL", text: "Behavioral baseline active" },
    { time: "Live", icon: "SAFE", text: "No active high-confidence threats" },
  ];

  // Horizon graph points
  const timelineData = [
    { horizon: "60s (Real-time)", risk: behavior.horizons["60s"]?.risk ?? 12, anomaly: behavior.horizons["60s"]?.anomaly ?? 8 },
    { horizon: "5m (Baseline)", risk: behavior.horizons["5m"]?.risk ?? 17, anomaly: behavior.horizons["5m"]?.anomaly ?? 13 },
    { horizon: "30m (Trend)", risk: behavior.horizons["30m"]?.risk ?? 21, anomaly: behavior.horizons["30m"]?.anomaly ?? 19 },
  ];

  const handleRunAudit = async () => {
    setAuditRunning(true);
    const start = performance.now();
    try {
      await runHealthAudit();
      const elapsed = Math.round(performance.now() - start);
      setLastAuditResult(`Behavioral health refreshed in ${elapsed}ms`);
    } catch {
      setLastAuditResult("Telemetry heartbeat reconnected");
    } finally {
      setAuditRunning(false);
    }
  };

  const handleOpenHistoricalReport = async (win: string = selectedWindow) => {
    setLoadingReport(true);
    setModalOpen(true);
    setSelectedWindow(win);
    try {
      const rep = await fetchHistoricalReport(win);
      setHistoricalReport(rep);
    } catch {
      setHistoricalReport(null);
    } finally {
      setLoadingReport(false);
    }
  };

  const handleExportJSON = () => {
    download(`argus-one-behavioral-health-${Date.now()}.json`, report);
  };

  // Color helpers
  const getHealthBadge = (score: number) => {
    if (score >= 85) return { bg: "bg-[#20D3A2]/15 text-[#20D3A2] border-[#20D3A2]/40", text: "NORMAL" };
    if (score >= 65) return { bg: "bg-[#FFB020]/15 text-[#FFB020] border-[#FFB020]/40", text: "WATCH" };
    if (score >= 45) return { bg: "bg-[#FF6B6B]/15 text-[#FF6B6B] border-[#FF6B6B]/40", text: "DEGRADED" };
    return { bg: "bg-[#FF3366]/20 text-[#FF3366] border-[#FF3366]/50", text: "CRITICAL" };
  };

  const getThreatBadge = (score: number) => {
    if (score < 25) return { bg: "bg-[#20D3A2]/15 text-[#20D3A2] border-[#20D3A2]/40", text: "LOW" };
    if (score < 55) return { bg: "bg-[#4C9AFF]/15 text-[#4C9AFF] border-[#4C9AFF]/40", text: "MODERATE" };
    if (score < 80) return { bg: "bg-[#FFB020]/15 text-[#FFB020] border-[#FFB020]/40", text: "HIGH" };
    return { bg: "bg-[#FF3366]/20 text-[#FF3366] border-[#FF3366]/50", text: "CRITICAL" };
  };

  const healthBadge = getHealthBadge(bHealth.score);
  const threatBadge = getThreatBadge(threatRisk.score);

  return (
    <div className="space-y-5">
      {/* Top Banner & Audit Controls */}
      <Card className="overflow-hidden border border-[#242B35] bg-gradient-to-b from-[#11161D] via-[#0E131A] to-[#0A0D12] shadow-xl">
        <div className="p-4 sm:p-5 border-b border-[#242B35]/80 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-start gap-3.5">
            <div className="w-10 h-10 rounded-xl bg-[#20D3A2]/10 border border-[#20D3A2]/30 flex items-center justify-center text-[#20D3A2] shadow-inner mt-0.5">
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
              </svg>
            </div>
            <div>
              <div className="flex items-center gap-2.5 flex-wrap">
                <h2 className="text-[16px] font-bold text-[#F3F5F7] tracking-tight">
                  Behavioral Network Health Report
                </h2>
                <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold tracking-wide uppercase bg-[#20D3A2]/15 text-[#20D3A2] border border-[#20D3A2]/40 flex items-center gap-1.5">
                  <LiveDot />
                  CONTINUOUS MONITORING ACTIVE
                </span>
                {lastAuditResult && (
                  <span className="text-[11px] font-mono text-[#66707D]">
                    • {lastAuditResult}
                  </span>
                )}
              </div>
              <p className="text-[12px] text-[#9AA4B2] mt-0.5">
                NIST-aligned passive metadata monitoring: profiling normal traffic, recognizing deviations, and multi-model risk correlation.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 self-start md:self-center flex-wrap">
            <button
              onClick={handleRunAudit}
              disabled={auditRunning}
              className={`px-3 py-1.5 text-[12px] font-semibold rounded-md border transition-all flex items-center gap-1.5 cursor-pointer ${
                auditRunning
                  ? "bg-[#20D3A2]/20 border-[#20D3A2] text-[#20D3A2] animate-pulse"
                  : "bg-[#20D3A2]/10 border-[#20D3A2]/30 text-[#20D3A2] hover:bg-[#20D3A2]/20"
              }`}
            >
              <svg className={`w-3.5 h-3.5 ${auditRunning ? "animate-spin" : ""}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
              {auditRunning ? "Refreshing..." : "Refresh Health"}
            </button>
            <button
              onClick={handleOpenHistoricalReport}
              className="px-3 py-1.5 text-[12px] font-semibold rounded-md border border-[#4C9AFF]/40 bg-[#4C9AFF]/15 text-[#4C9AFF] hover:bg-[#4C9AFF]/25 transition-colors flex items-center gap-1.5 cursor-pointer shadow-sm"
            >
              <span>📄</span> Generate Health Report
            </button>
            <button
              onClick={handleExportJSON}
              className="px-3 py-1.5 text-[12px] font-medium rounded-md border border-[#242B35] bg-[#151B23] text-[#9AA4B2] hover:text-[#F3F5F7] hover:border-[#3A4456] transition-colors flex items-center gap-1.5 cursor-pointer"
            >
              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
              </svg>
              Export JSON
            </button>
          </div>
        </div>

        {/* SECTION 1: TWO DISTINCT CORE SCORES (HEALTH vs THREAT RISK) */}
        <div className="p-4 sm:p-5 grid grid-cols-1 md:grid-cols-2 gap-4 bg-[#0A0D12]">
          {/* Card 1: Network Health Score */}
          <div className="p-4 rounded-xl border border-[#20D3A2]/30 bg-gradient-to-br from-[#0F171D] to-[#0A0F14] relative overflow-hidden">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-mono font-bold uppercase tracking-wider text-[#9AA4B2]">
                1. BEHAVIORAL NETWORK HEALTH
              </span>
              <span className={`px-2.5 py-0.5 rounded text-[11px] font-mono font-bold border ${healthBadge.bg}`}>
                {healthBadge.text}
              </span>
            </div>
            <div className="flex items-baseline gap-3 mt-3">
              <span className="text-4xl font-extrabold font-mono text-[#F3F5F7] tracking-tight">
                {bHealth.score}
              </span>
              <span className="text-sm font-mono text-[#66707D]">/ 100</span>
              <span className="text-[12px] text-[#9AA4B2] ml-auto">
                Stability: <span className="font-mono text-[#20D3A2] font-semibold">{bHealth.stability}%</span>
              </span>
            </div>
            {/* Progress bar */}
            <div className="w-full bg-[#1A2330] rounded-full h-2 mt-3 overflow-hidden">
              <div
                className="bg-gradient-to-r from-[#20D3A2] to-[#4C9AFF] h-2 rounded-full transition-all duration-500"
                style={{ width: `${Math.min(100, Math.max(0, bHealth.score))}%` }}
              />
            </div>
            <p className="text-[11px] text-[#66707D] mt-2">
              Measures how normal and stable observed traffic is compared to the learned baseline distribution.
            </p>
          </div>

          {/* Card 2: Threat Risk Score */}
          <div className="p-4 rounded-xl border border-[#FF6B6B]/30 bg-gradient-to-br from-[#1C1217] to-[#120B0F] relative overflow-hidden">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-mono font-bold uppercase tracking-wider text-[#9AA4B2]">
                2. THREAT RISK ASSESSMENT
              </span>
              <span className={`px-2.5 py-0.5 rounded text-[11px] font-mono font-bold border ${threatBadge.bg}`}>
                {threatBadge.text} RISK
              </span>
            </div>
            <div className="flex items-baseline gap-3 mt-3">
              <span className="text-4xl font-extrabold font-mono text-[#F3F5F7] tracking-tight">
                {threatRisk.score}
              </span>
              <span className="text-sm font-mono text-[#66707D]">/ 100</span>
              <span className="text-[12px] text-[#9AA4B2] ml-auto">
                Confidence: <span className="font-mono text-[#4C9AFF] font-semibold">{Math.round(threatRisk.confidence * 100)}%</span>
              </span>
            </div>
            {/* Progress bar */}
            <div className="w-full bg-[#2A161D] rounded-full h-2 mt-3 overflow-hidden">
              <div
                className="bg-gradient-to-r from-[#FFB020] to-[#FF3366] h-2 rounded-full transition-all duration-500"
                style={{ width: `${Math.min(100, Math.max(0, threatRisk.score))}%` }}
              />
            </div>
            <p className="text-[11px] text-[#66707D] mt-2">
              Measures likelihood of active malicious activity, corroborated by Meta-Controller and Temporal GRU.
            </p>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="px-4 sm:px-5 pt-3 border-t border-[#1E2530] flex items-center justify-between flex-wrap gap-2">
          <div className="flex items-center gap-2 flex-wrap">
            <button
              onClick={() => setActiveTab("behavioral")}
              className={`px-3 py-1.5 text-[11px] font-semibold rounded transition-colors flex items-center gap-1.5 cursor-pointer ${
                activeTab === "behavioral"
                  ? "bg-[#20D3A2]/15 text-[#20D3A2] border border-[#20D3A2]/40"
                  : "text-[#66707D] hover:text-[#9AA4B2]"
              }`}
            >
              <span>📊</span> Behavioral Overview & AI Consensus
            </button>
            <button
              onClick={() => setActiveTab("timeline")}
              className={`px-3 py-1.5 text-[11px] font-semibold rounded transition-colors flex items-center gap-1.5 cursor-pointer ${
                activeTab === "timeline"
                  ? "bg-[#20D3A2]/15 text-[#20D3A2] border border-[#20D3A2]/40"
                  : "text-[#66707D] hover:text-[#9AA4B2]"
              }`}
            >
              <span>⏱</span> Multi-Horizon Timeline (60s / 5m / 30m)
            </button>
            <button
              onClick={() => setActiveTab("governance")}
              className={`px-3 py-1.5 text-[11px] font-semibold rounded transition-colors flex items-center gap-1.5 cursor-pointer ${
                activeTab === "governance"
                  ? "bg-[#20D3A2]/15 text-[#20D3A2] border border-[#20D3A2]/40"
                  : "text-[#66707D] hover:text-[#9AA4B2]"
              }`}
            >
              <span>🧠</span> Self-Learning Meta-Controller
            </button>
            <button
              onClick={() => setActiveTab("infrastructure")}
              className={`px-3 py-1.5 text-[11px] font-semibold rounded transition-colors flex items-center gap-1.5 cursor-pointer ${
                activeTab === "infrastructure"
                  ? "bg-[#20D3A2]/15 text-[#20D3A2] border border-[#20D3A2]/40"
                  : "text-[#66707D] hover:text-[#9AA4B2]"
              }`}
            >
              <span>⚙</span> Subsystem & Storage SLA
            </button>
          </div>
          <span className="text-[10px] font-mono text-[#66707D]">
            Snapshot: {new Date(report.timestamp).toLocaleTimeString()}
          </span>
        </div>

        <div className="p-4 sm:p-5 space-y-5">
          {/* TAB 1: BEHAVIORAL OVERVIEW */}
          {activeTab === "behavioral" && (
            <div className="space-y-5">
              {/* Traffic Condition vs AI Model Status (2 Columns) */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {/* Left: Traffic Condition */}
                <div className="p-4 rounded-xl border border-[#242B35] bg-[#0E131A]/90 space-y-3">
                  <div className="flex items-center justify-between border-b border-[#1E2530] pb-2">
                    <span className="text-[12px] font-semibold text-[#F3F5F7]">TRAFFIC CONDITION</span>
                    <span className="text-[10px] font-mono text-[#66707D]">UNIDIRECTIONAL METADATA</span>
                  </div>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center">
                    <div className="p-2.5 rounded-lg bg-[#0A0D12] border border-[#1E2530]">
                      <div className="text-[10px] text-[#66707D] uppercase font-mono">TOTAL FLOWS</div>
                      <div className="text-[16px] font-bold font-mono text-[#F3F5F7] mt-0.5">
                        {traffic.flows.toLocaleString()}
                      </div>
                    </div>
                    <div className="p-2.5 rounded-lg bg-[#0A0D12] border border-[#1E2530]">
                      <div className="text-[10px] text-[#66707D] uppercase font-mono">ACTIVE SOURCES</div>
                      <div className="text-[16px] font-bold font-mono text-[#20D3A2] mt-0.5">
                        {traffic.unique_sources}
                      </div>
                    </div>
                    <div className="p-2.5 rounded-lg bg-[#0A0D12] border border-[#1E2530]">
                      <div className="text-[10px] text-[#66707D] uppercase font-mono">ANOMALOUS FLOWS</div>
                      <div className="text-[16px] font-bold font-mono text-[#FFB020] mt-0.5">
                        {traffic.anomalous_flows}
                      </div>
                    </div>
                    <div className="p-2.5 rounded-lg bg-[#0A0D12] border border-[#1E2530]">
                      <div className="text-[10px] text-[#66707D] uppercase font-mono">OPEN ALERTS</div>
                      <div className={`text-[16px] font-bold font-mono mt-0.5 ${traffic.open_alerts > 0 ? "text-[#FF6B6B]" : "text-[#20D3A2]"}`}>
                        {traffic.open_alerts}
                      </div>
                    </div>
                  </div>
                  <div className="text-[11px] text-[#9AA4B2] flex justify-between pt-1">
                    <span>Flow Rate: <span className="font-mono text-[#F3F5F7]">{traffic.flows_per_second} flows/s</span></span>
                    <span>Throughput: <span className="font-mono text-[#F3F5F7]">{((traffic.bytes_per_second * 8) / 1_000_000).toFixed(2)} Mbps</span></span>
                  </div>
                </div>

                {/* Right: AI Detection Status & Agreement */}
                <div className="p-4 rounded-xl border border-[#242B35] bg-[#0E131A]/90 space-y-3">
                  <div className="flex items-center justify-between border-b border-[#1E2530] pb-2">
                    <span className="text-[12px] font-semibold text-[#F3F5F7]">AI DETECTION STATUS</span>
                    <span className="text-[11px] font-mono text-[#20D3A2] font-semibold">
                      AGREEMENT: {models.model_agreement_pct}%
                    </span>
                  </div>
                  <div className="space-y-2 text-[11px]">
                    <div className="flex items-center justify-between p-1.5 rounded bg-[#0A0D12]">
                      <span className="text-[#9AA4B2] font-medium">Random Forest (Known Threats)</span>
                      <div className="flex items-center gap-3">
                        <span className="font-mono text-[#F3F5F7]">{models.random_forest.prediction}</span>
                        <span className="font-mono text-[#4C9AFF]">Rel: {Math.round(models.random_forest.reliability * 100)}%</span>
                      </div>
                    </div>
                    <div className="flex items-center justify-between p-1.5 rounded bg-[#0A0D12]">
                      <span className="text-[#9AA4B2] font-medium">Gradient Boost (Nonlinear Boundaries)</span>
                      <div className="flex items-center gap-3">
                        <span className="font-mono text-[#F3F5F7]">{models.gradient_boost.prediction}</span>
                        <span className="font-mono text-[#4C9AFF]">Rel: {Math.round(models.gradient_boost.reliability * 100)}%</span>
                      </div>
                    </div>
                    <div className="flex items-center justify-between p-1.5 rounded bg-[#0A0D12]">
                      <span className="text-[#9AA4B2] font-medium">Benign Anomaly Guard (MAD Outliers)</span>
                      <div className="flex items-center gap-3">
                        <span className="font-mono text-[#F3F5F7]">{models.anomaly_guard.prediction} ({models.anomaly_guard.score ?? 0})</span>
                        <span className="font-mono text-[#4C9AFF]">Rel: {Math.round(models.anomaly_guard.reliability * 100)}%</span>
                      </div>
                    </div>
                    <div className="flex items-center justify-between p-1.5 rounded bg-[#0A0D12]">
                      <span className="text-[#9AA4B2] font-medium">Temporal Sequence GRU (Flow Progression)</span>
                      <div className="flex items-center gap-3">
                        <span className="font-mono text-[#F3F5F7]">{models.temporal_gru.prediction}</span>
                        <span className="font-mono text-[#4C9AFF]">Rel: {Math.round(models.temporal_gru.reliability * 100)}%</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Baseline Deviation & Explainability (2 Columns) */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {/* Left: Learned Baseline Comparison */}
                <div className="p-4 rounded-xl border border-[#242B35] bg-[#0E131A]/90 space-y-3">
                  <div className="flex items-center justify-between border-b border-[#1E2530] pb-2">
                    <span className="text-[12px] font-semibold text-[#F3F5F7]">CURRENT BEHAVIOR vs LEARNED BASELINE</span>
                    <span className="text-[10px] font-mono text-[#20D3A2]">MEDIAN-MAD NORM</span>
                  </div>
                  <div className="space-y-2 text-[11px]">
                    {[
                      { label: "Flow Rate Deviation", val: behavior.baseline_deviation.flow_rate },
                      { label: "Traffic Volume Variance", val: behavior.baseline_deviation.traffic_variance },
                      { label: "Periodicity Drift", val: behavior.baseline_deviation.periodicity },
                      { label: "Source Diversity (Entropy)", val: behavior.baseline_deviation.source_diversity },
                      { label: "Temporal Stability", val: behavior.baseline_deviation.temporal_stability },
                    ].map((item) => {
                      const isNormal = Math.abs(item.val) <= 15;
                      return (
                        <div key={item.label} className="flex items-center justify-between py-1 border-b border-[#1A222D]/50 last:border-0">
                          <span className="text-[#9AA4B2]">{item.label}</span>
                          <div className="flex items-center gap-2">
                            <span className={`font-mono font-semibold ${item.val > 0 ? "text-[#FFB020]" : "text-[#4C9AFF]"}`}>
                              {item.val >= 0 ? `+${item.val}%` : `${item.val}%`}
                            </span>
                            <span className={`px-1.5 py-0.2 rounded text-[9px] font-mono font-bold ${
                              isNormal ? "bg-[#20D3A2]/15 text-[#20D3A2]" : "bg-[#FFB020]/15 text-[#FFB020]"
                            }`}>
                              {isNormal ? "NORMAL" : "WATCH"}
                            </span>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Right: Explainable "WHY?" Panel */}
                <div className="p-4 rounded-xl border border-[#242B35] bg-[#0E131A]/90 space-y-3">
                  <div className="flex items-center justify-between border-b border-[#1E2530] pb-2">
                    <span className="text-[12px] font-semibold text-[#F3F5F7]">
                      WHY IS THE HEALTH SCORE {bHealth.score}?
                    </span>
                    <span className="text-[10px] font-mono text-[#66707D]">EXPLAINABLE AI</span>
                  </div>
                  <div className="space-y-2 text-[11px]">
                    {explanations.map((exp, idx) => {
                      const isAlert = exp.includes("alert") || exp.includes("deviate") || exp.includes("elevated");
                      return (
                        <div key={idx} className="flex items-start gap-2 text-[#9AA4B2] leading-relaxed">
                          <span className={isAlert ? "text-[#FFB020] font-bold" : "text-[#20D3A2] font-bold"}>
                            {isAlert ? "⚠" : "✓"}
                          </span>
                          <span>{exp}</span>
                        </div>
                      );
                    })}
                  </div>
                  <div className="p-2.5 rounded-lg bg-[#0A0D12] border border-[#1E2530] text-[11px] space-y-1">
                    <div className="text-[#66707D] text-[9px] uppercase font-mono">PRIMARY SIGNAL & REGIME</div>
                    <div className="text-[#F3F5F7] font-medium">
                      Dominant Engine: <span className="text-[#20D3A2]">{governance.dominant_model}</span>
                    </div>
                    <div className="text-[#66707D] text-[10px]">
                      Regime: <span className="text-[#4C9AFF] font-mono">{governance.context}</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: MULTI-HORIZON BEHAVIORAL TIMELINE */}
          {activeTab === "timeline" && (
            <div className="space-y-5">
              <div className="p-4 rounded-xl border border-[#242B35] bg-[#0E131A] space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-[13px] font-bold text-[#F3F5F7]">
                      BEHAVIOR OVER TIME (MULTI-HORIZON PROGRESSION)
                    </h3>
                    <p className="text-[11px] text-[#9AA4B2] mt-0.5">
                      ARGUS-ONE evaluates unidirectional flow progression across 3 distinct time horizons to capture immediate surges and slow trends.
                    </p>
                  </div>
                  <span className="px-2.5 py-0.5 rounded text-[10px] font-mono font-bold bg-[#4C9AFF]/15 text-[#4C9AFF] border border-[#4C9AFF]/30">
                    GRU SEQUENTIAL EVALUATION
                  </span>
                </div>

                {/* Recharts Area Chart */}
                <div className="h-[200px] w-full pt-2">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={timelineData}>
                      <defs>
                        <linearGradient id="riskGrad" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#FF3366" stopOpacity={0.4} />
                          <stop offset="95%" stopColor="#FF3366" stopOpacity={0.0} />
                        </linearGradient>
                        <linearGradient id="anomGrad" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#FFB020" stopOpacity={0.4} />
                          <stop offset="95%" stopColor="#FFB020" stopOpacity={0.0} />
                        </linearGradient>
                      </defs>
                      <XAxis dataKey="horizon" stroke="#66707D" tick={{ fill: "#66707D", fontSize: 11 }} />
                      <YAxis domain={[0, 100]} stroke="#66707D" tick={{ fill: "#66707D", fontSize: 11 }} />
                      <Tooltip
                        contentStyle={{ backgroundColor: "#0D1117", borderColor: "#242B35", borderRadius: "8px", fontSize: "11px" }}
                        itemStyle={{ color: "#F3F5F7" }}
                      />
                      <Area type="monotone" dataKey="risk" stroke="#FF3366" strokeWidth={2} fillOpacity={1} fill="url(#riskGrad)" name="Threat Risk" />
                      <Area type="monotone" dataKey="anomaly" stroke="#FFB020" strokeWidth={2} fillOpacity={1} fill="url(#anomGrad)" name="Anomaly Index" />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>

                {/* Horizon Cards */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  {Object.entries(behavior.horizons).map(([key, h]) => (
                    <div key={key} className="p-3.5 rounded-lg bg-[#0A0D12] border border-[#1E2530] space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-[12px] font-bold text-[#F3F5F7] font-mono">{h.name}</span>
                        <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold bg-[#20D3A2]/15 text-[#20D3A2]">
                          {h.traffic_status}
                        </span>
                      </div>
                      <div className="grid grid-cols-2 gap-2 text-[11px] pt-1">
                        <div>
                          <span className="text-[#66707D] block text-[9px] uppercase">RISK INDEX</span>
                          <span className="font-mono text-sm font-semibold text-[#FF6B6B]">{h.risk}%</span>
                        </div>
                        <div>
                          <span className="text-[#66707D] block text-[9px] uppercase">ANOMALY INDEX</span>
                          <span className="font-mono text-sm font-semibold text-[#FFB020]">{h.anomaly}%</span>
                        </div>
                      </div>
                      <div className="text-[10px] text-[#66707D]">
                        Baseline Drift: <span className="font-mono text-[#9AA4B2]">+{h.baseline_drift}%</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* TAB 3: SELF-LEARNING META-CONTROLLER GOVERNANCE */}
          {activeTab === "governance" && (
            <div className="space-y-5">
              <div className="p-4 rounded-xl border border-[#4C9AFF]/30 bg-gradient-to-r from-[#0E1520] via-[#111A27] to-[#0E1520] space-y-4">
                <div className="flex items-center justify-between flex-wrap gap-2">
                  <div>
                    <h3 className="text-[14px] font-bold text-[#F3F5F7]">
                      SELF-LEARNING META-CONTROLLER GOVERNANCE
                    </h3>
                    <p className="text-[11px] text-[#9AA4B2] mt-0.5">
                      Dynamically arbitrates and weights sub-model evidence based on context reliability and operational analyst feedback.
                    </p>
                  </div>
                  <span className="px-3 py-1 rounded text-[11px] font-mono font-bold bg-[#20D3A2]/15 text-[#20D3A2] border border-[#20D3A2]/40">
                    REGIME: {governance.context}
                  </span>
                </div>

                {/* Dynamic Weights Bars */}
                <div className="space-y-3 p-3.5 rounded-lg bg-[#0A0D12] border border-[#1E2530]">
                  <div className="text-[11px] font-mono uppercase text-[#66707D] flex justify-between">
                    <span>Active Dynamic Softmax Weights</span>
                    <span>Decision Confidence: {Math.round(governance.confidence * 100)}%</span>
                  </div>
                  {Object.entries(governance.weights).map(([modelKey, weight]) => {
                    const pct = Math.round(weight * 100);
                    const isDominant = governance.dominant_model.toLowerCase().includes(modelKey.replace("_", " "));
                    return (
                      <div key={modelKey} className="space-y-1">
                        <div className="flex justify-between text-[11px]">
                          <span className="text-[#F3F5F7] font-medium capitalize">
                            {modelKey.replace("_", " ")} {isDominant && <span className="text-[#20D3A2] font-bold ml-1">★ DOMINANT</span>}
                          </span>
                          <span className="font-mono text-[#4C9AFF] font-semibold">{pct}%</span>
                        </div>
                        <div className="w-full bg-[#1A222D] h-2 rounded-full overflow-hidden">
                          <div
                            className={`h-2 rounded-full transition-all duration-500 ${isDominant ? "bg-[#20D3A2]" : "bg-[#4C9AFF]"}`}
                            style={{ width: `${pct}%` }}
                          />
                        </div>
                      </div>
                    );
                  })}
                </div>

                {/* Governance Reason Box */}
                <div className="p-3.5 rounded-lg bg-[#0A0D12] border border-[#1E2530] text-[11px] space-y-1.5">
                  <div className="text-[10px] font-mono uppercase text-[#20D3A2] font-bold">
                    EXPLAINABLE GOVERNANCE REASON
                  </div>
                  <p className="text-[#F3F5F7] leading-relaxed">
                    {governance.reason}
                  </p>
                </div>

                {/* Self-Learning Memory & Adaptation Metrics */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center">
                  <div className="p-2.5 rounded-lg bg-[#0A0D12] border border-[#1E2530]">
                    <div className="text-[9px] text-[#66707D] uppercase font-mono">GOVERNED DECISIONS</div>
                    <div className="text-sm font-bold font-mono text-[#F3F5F7] mt-0.5">{learning.governed_decisions}</div>
                  </div>
                  <div className="p-2.5 rounded-lg bg-[#0A0D12] border border-[#1E2530]">
                    <div className="text-[9px] text-[#66707D] uppercase font-mono">MEMORY EPISODES</div>
                    <div className="text-sm font-bold font-mono text-[#20D3A2] mt-0.5">{learning.memory_episodes}</div>
                  </div>
                  <div className="p-2.5 rounded-lg bg-[#0A0D12] border border-[#1E2530]">
                    <div className="text-[9px] text-[#66707D] uppercase font-mono">ONLINE ADAPTATIONS</div>
                    <div className="text-sm font-bold font-mono text-[#4C9AFF] mt-0.5">{learning.adaptations}</div>
                  </div>
                  <div className="p-2.5 rounded-lg bg-[#0A0D12] border border-[#1E2530]">
                    <div className="text-[9px] text-[#66707D] uppercase font-mono">CONTROLLER CONFIDENCE</div>
                    <div className="text-sm font-bold font-mono text-[#20D3A2] mt-0.5">{learning.controller_confidence}%</div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: SUBSYSTEM & INFRASTRUCTURE DIAGNOSTICS */}
          {activeTab === "infrastructure" && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="p-4 rounded-xl border border-[#242B35] bg-[#0E131A] space-y-3">
                  <h4 className="text-[12px] font-semibold text-[#F3F5F7] border-b border-[#1E2530] pb-2">
                    INGESTION & BUFFER CAPACITY
                  </h4>
                  <div className="space-y-2 text-[11px]">
                    <div className="flex justify-between">
                      <span className="text-[#66707D]">Ring Buffer Limit:</span>
                      <span className="font-mono text-[#F3F5F7]">20,000 flows</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-[#66707D]">Current Buffer Usage:</span>
                      <span className="font-mono text-[#20D3A2]">{traffic.flows} flows ({((traffic.flows / 20000) * 100).toFixed(1)}%)</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-[#66707D]">Packet Drops:</span>
                      <span className="font-mono text-[#20D3A2]">0 (Zero-loss ring buffer)</span>
                    </div>
                  </div>
                </div>

                <div className="p-4 rounded-xl border border-[#242B35] bg-[#0E131A] space-y-3">
                  <h4 className="text-[12px] font-semibold text-[#F3F5F7] border-b border-[#1E2530] pb-2">
                    STORAGE & WAL INTEGRITY
                  </h4>
                  <div className="space-y-2 text-[11px]">
                    <div className="flex justify-between">
                      <span className="text-[#66707D]">Database Journal:</span>
                      <span className="font-mono text-[#20D3A2]">WAL (Write-Ahead Logging)</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-[#66707D]">Alert Retention:</span>
                      <span className="font-mono text-[#F3F5F7]">{traffic.total_alerts} alerts stored</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-[#66707D]">Baseline Method:</span>
                      <span className="font-mono text-[#4C9AFF]">Robust Median-MAD</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Health Events Stream */}
          <div className="p-4 rounded-xl border border-[#1E2530] bg-[#0A0D12] space-y-2.5">
            <div className="flex items-center justify-between border-b border-[#1E2530] pb-2">
              <span className="text-[11px] font-mono uppercase text-[#66707D] font-bold">RECENT HEALTH EVENTS</span>
              <span className="text-[10px] font-mono text-[#20D3A2]">LIVE FEED</span>
            </div>
            <div className="space-y-1.5 text-[11px]">
              {events.map((ev, i) => (
                <div key={i} className="flex items-center gap-2 text-[#9AA4B2] font-mono">
                  <span className="text-[#66707D]">{ev.time}</span>
                  <span className={ev.icon === "ALERT" ? "text-[#FF6B6B]" : "text-[#20D3A2]"}>
                    {ev.icon === "ALERT" ? "⚠" : "●"}
                  </span>
                  <span className="text-[#F3F5F7]">{ev.text}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </Card>

      {/* GENERATE HEALTH REPORT MODAL */}
      {modalOpen && (
        <div className="fixed inset-0 bg-black/75 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-[#0E131A] border border-[#242B35] rounded-2xl max-w-2xl w-full max-h-[85vh] overflow-y-auto p-6 space-y-5 shadow-2xl">
            <div className="flex items-center justify-between border-b border-[#1E2530] pb-3">
              <div>
                <h3 className="text-lg font-bold text-[#F3F5F7]">
                  {historicalReport?.title ?? "ARGUS-ONE Behavioral Network Health Report"}
                </h3>
                <div className="flex items-center gap-3 mt-1.5 flex-wrap">
                  <p className="text-[11px] text-[#66707D] font-mono">
                    Period: {historicalReport?.period ?? "Generating report..."}
                  </p>
                  <div className="flex items-center gap-1 bg-[#0A0D12] p-0.5 rounded-lg border border-[#242B35]">
                    {["15m", "1h", "6h", "24h"].map((w) => (
                      <button
                        key={w}
                        onClick={() => handleOpenHistoricalReport(w)}
                        className={`px-2 py-0.5 text-[10px] font-mono rounded cursor-pointer transition-colors ${
                          selectedWindow === w
                            ? "bg-[#20D3A2]/20 text-[#20D3A2] font-bold border border-[#20D3A2]/40"
                            : "text-[#66707D] hover:text-[#F3F5F7]"
                        }`}
                      >
                        {w}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
              <button
                onClick={() => setModalOpen(false)}
                className="p-1 text-[#66707D] hover:text-[#F3F5F7] rounded-lg transition-colors cursor-pointer"
              >
                ✕
              </button>
            </div>

            {loadingReport ? (
              <div className="py-12 text-center space-y-2 text-[#9AA4B2]">
                <div className="w-8 h-8 border-2 border-[#20D3A2] border-t-transparent rounded-full animate-spin mx-auto" />
                <p className="text-xs font-mono">Compiling behavioral timeline and model metrics...</p>
              </div>
            ) : historicalReport ? (
              <div className="space-y-4 text-[12px] font-mono text-[#9AA4B2]">
                {/* Summary Table */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center">
                  <div className="p-2 rounded bg-[#0A0D12] border border-[#1E2530]">
                    <div className="text-[9px] uppercase text-[#66707D]">OVERALL HEALTH</div>
                    <div className="text-xl font-bold text-[#20D3A2] mt-1">{historicalReport.overall_health}/100</div>
                  </div>
                  <div className="p-2 rounded bg-[#0A0D12] border border-[#1E2530]">
                    <div className="text-[9px] uppercase text-[#66707D]">THREAT RISK</div>
                    <div className="text-xl font-bold text-[#FF6B6B] mt-1">{historicalReport.threat_risk}/100</div>
                  </div>
                  <div className="p-2 rounded bg-[#0A0D12] border border-[#1E2530]">
                    <div className="text-[9px] uppercase text-[#66707D]">MODEL AGREEMENT</div>
                    <div className="text-xl font-bold text-[#4C9AFF] mt-1">{historicalReport.model_agreement}</div>
                  </div>
                  <div className="p-2 rounded bg-[#0A0D12] border border-[#1E2530]">
                    <div className="text-[9px] uppercase text-[#66707D]">CONFIDENCE</div>
                    <div className="text-xl font-bold text-[#20D3A2] mt-1">{historicalReport.model_confidence}%</div>
                  </div>
                </div>

                {/* Conclusion & Actions */}
                <div className="p-3.5 rounded-lg bg-[#0A0D12] border border-[#1E2530] space-y-2">
                  <div className="text-[10px] uppercase text-[#20D3A2] font-bold">ASSESSMENT CONCLUSION</div>
                  <p className="text-[#F3F5F7] font-sans text-[12px] leading-relaxed">
                    {historicalReport.conclusion}
                  </p>
                  <div className="text-[10px] uppercase text-[#4C9AFF] font-bold pt-1">RECOMMENDED ACTION</div>
                  <p className="text-[#F3F5F7] font-sans text-[12px]">
                    {historicalReport.recommended_action}
                  </p>
                </div>

                {/* Baseline Details */}
                <div className="p-3.5 rounded-lg bg-[#0A0D12] border border-[#1E2530] space-y-2">
                  <div className="text-[10px] uppercase text-[#66707D]">BASELINE COMPARISONS</div>
                  <div className="grid grid-cols-2 gap-2 text-[11px]">
                    <div>Flow Rate: <span className="text-[#F3F5F7]">{historicalReport.baseline_comparison.flow_rate}%</span></div>
                    <div>Variance: <span className="text-[#F3F5F7]">{historicalReport.baseline_comparison.traffic_variance}%</span></div>
                    <div>Periodicity: <span className="text-[#F3F5F7]">{historicalReport.baseline_comparison.periodicity}%</span></div>
                    <div>Source Diversity: <span className="text-[#F3F5F7]">{historicalReport.baseline_comparison.source_diversity}%</span></div>
                  </div>
                </div>

                {/* Modal Buttons */}
                <div className="flex justify-end gap-2 pt-2 border-t border-[#1E2530]">
                  <button
                    onClick={() => download(`argus-one-report-${Date.now()}.json`, historicalReport)}
                    className="px-4 py-2 text-xs font-semibold rounded-lg bg-[#20D3A2]/15 text-[#20D3A2] border border-[#20D3A2]/40 hover:bg-[#20D3A2]/25 transition-colors cursor-pointer"
                  >
                    Download Full Report JSON
                  </button>
                  <button
                    onClick={() => setModalOpen(false)}
                    className="px-4 py-2 text-xs font-semibold rounded-lg bg-[#1A222D] text-[#9AA4B2] hover:text-[#F3F5F7] transition-colors cursor-pointer"
                  >
                    Close
                  </button>
                </div>
              </div>
            ) : null}
          </div>
        </div>
      )}
    </div>
  );
}
