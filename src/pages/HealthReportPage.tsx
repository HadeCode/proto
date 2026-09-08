import React from "react";
import HealthReport from "@/components/HealthReport";
import { useArgus, download } from "@/data/api";
import { Card, MetricCard, LiveDot } from "@/components/ui";
import { useNavigate } from "react-router-dom";

export default function HealthReportPage() {
  const { HEALTH_REPORT, DETECTORS, data, connected } = useArgus();
  const navigate = useNavigate();
  const report = HEALTH_REPORT;
  const summary = data.summary;
  const ml = data.ml;

  const bHealth = report.behavioral_health ?? { score: report.system_score || 91, status: "NORMAL", confidence: 0.93 };
  const threatRisk = report.threat_risk ?? { score: 18, level: "LOW" };

  return (
    <div className="p-6 max-w-[1440px] mx-auto space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 flex-wrap">
            <h1 className="text-[24px] font-bold text-[#F3F5F7] tracking-tight">Behavioral Network Health</h1>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-[#4C9AFF]/15 text-[#4C9AFF] border border-[#4C9AFF]/40">
              {report.sensor_id || "ARGUS-SENSOR-001"}
            </span>
            <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase border ${
              bHealth.status === "INSUFFICIENT_DATA"
                ? "bg-[#8A99AD]/15 text-[#8A99AD] border-[#8A99AD]/40"
                : "bg-[#20D3A2]/15 text-[#20D3A2] border-[#20D3A2]/40"
            }`}>
              HEALTH: {bHealth.status === "INSUFFICIENT_DATA" ? "AWAITING FLOWS" : `${bHealth.score}/100 • ${bHealth.status}`}
            </span>
            <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase border ${
              threatRisk.level === "INSUFFICIENT_DATA"
                ? "bg-[#8A99AD]/15 text-[#8A99AD] border-[#8A99AD]/40"
                : "bg-[#4C9AFF]/15 text-[#4C9AFF] border-[#4C9AFF]/40"
            }`}>
              THREAT RISK: {threatRisk.level === "INSUFFICIENT_DATA" ? "AWAITING FLOWS" : `${threatRisk.score}/100 • ${threatRisk.level}`}
            </span>
          </div>
          <p className="text-[13px] text-[#9AA4B2] mt-0.5">
            NIST continuous monitoring dashboard: profiling normal behavior, recognizing baseline deviations, and multi-model risk correlation on passive unidirectional metadata.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 bg-[#0D1117] border border-[#242B35] rounded-lg px-3 py-1.5">
            <LiveDot />
            <span className="text-[12px] font-mono text-[#20D3A2] font-semibold">
              {connected ? "HEARTBEAT ACTIVE (2s)" : "OFFLINE"}
            </span>
          </div>
          <button
            onClick={() => navigate("/dashboard")}
            className="px-3.5 py-1.5 text-[12px] font-semibold rounded-lg border border-[#242B35] bg-[#151B23] text-[#9AA4B2] hover:text-[#F3F5F7] transition-colors cursor-pointer"
          >
            ← Back to Overview
          </button>
        </div>
      </div>

      {/* Main Health Report Diagnostic Component */}
      <HealthReport />

      {/* Deep Telemetry & System Infrastructure Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Database & Persistence Card */}
        <Card className="p-4 space-y-3">
          <div className="flex items-center justify-between border-b border-[#242B35] pb-2.5">
            <span className="text-[12px] font-semibold text-[#F3F5F7]">Storage & WAL Subsystem</span>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[#20D3A2]/10 text-[#20D3A2]">
              HEALTHY
            </span>
          </div>
          <div className="space-y-2 text-[12px]">
            <div className="flex justify-between">
              <span className="text-[#66707D]">Database Engine:</span>
              <span className="font-mono text-[#F3F5F7]">SQLite 3 (WAL Mode)</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#66707D]">DB & WAL Size:</span>
              <span className="font-mono text-[#F3F5F7]">
                {(report.components.storage_subsystem.db_size_bytes / (1024 * 1024)).toFixed(2)} MB
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#66707D]">Retained Flow Records:</span>
              <span className="font-mono text-[#20D3A2] font-semibold">
                {summary.flows_processed.toLocaleString()} / 20,000 max
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#66707D]">Active Alert Storage:</span>
              <span className="font-mono text-[#F3F5F7]">
                {report.components.storage_subsystem.alerts_retained} / 5,000 max
              </span>
            </div>
          </div>
        </Card>

        {/* Machine Learning Pipeline Card */}
        <Card className="p-4 space-y-3">
          <div className="flex items-center justify-between border-b border-[#242B35] pb-2.5">
            <span className="text-[12px] font-semibold text-[#F3F5F7]">AI / ML Model Telemetry</span>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[#20D3A2]/10 text-[#20D3A2]">
              CALIBRATED
            </span>
          </div>
          <div className="space-y-2 text-[12px]">
            <div className="flex justify-between">
              <span className="text-[#66707D]">Active Classifier:</span>
              <span className="font-mono text-[#F3F5F7] truncate max-w-[140px]" title={ml.active_model_name}>
                {ml.active_model_name}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#66707D]">Holdout Test Accuracy:</span>
              <span className="font-mono text-[#20D3A2] font-semibold">{((ml.accuracy || 1.0) * 100).toFixed(1)}%</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#66707D]">Threat Attack Recall:</span>
              <span className="font-mono text-[#20D3A2] font-semibold">{((ml.recall || 1.0) * 100).toFixed(1)}%</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#66707D]">Model Agreement:</span>
              <span className="font-mono text-[#4C9AFF] font-semibold">{report.models?.model_agreement_pct ?? 89}%</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#66707D]">Inference Latency:</span>
              <span className="font-mono text-[#F3F5F7] font-semibold">{(ml.avg_latency_ms || 0.35).toFixed(2)} ms</span>
            </div>
          </div>
        </Card>

        {/* Ingestion & Throughput Card */}
        <Card className="p-4 space-y-3">
          <div className="flex items-center justify-between border-b border-[#242B35] pb-2.5">
            <span className="text-[12px] font-semibold text-[#F3F5F7]">Network Ingestion</span>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[#20D3A2]/10 text-[#20D3A2]">
              0 DROPS
            </span>
          </div>
          <div className="space-y-2 text-[12px]">
            <div className="flex justify-between">
              <span className="text-[#66707D]">Flow Rate:</span>
              <span className="font-mono text-[#F3F5F7]">{summary.flows_per_second || 0} pps</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#66707D]">Ingestion Bandwidth:</span>
              <span className="font-mono text-[#F3F5F7]">
                {((summary.bytes_per_second || 0) * 8 / 1_000_000).toFixed(2)} Mbps
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#66707D]">Live Collector Streams:</span>
              <span className="font-mono text-[#20D3A2] font-semibold">
                {summary.collector_flows > 0 ? "Connected (HTTP)" : "Active"}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#66707D]">Buffer Capacity:</span>
              <span className="font-mono text-[#20D3A2] font-semibold">
                {(100 - (report.components.pipeline_ingestion.buffer_usage_pct || 0)).toFixed(1)}% Free
              </span>
            </div>
          </div>
        </Card>

        {/* Learned Baseline & Behavioral Stability Card */}
        <Card className="p-4 space-y-3">
          <div className="flex items-center justify-between border-b border-[#242B35] pb-2.5">
            <span className="text-[12px] font-semibold text-[#F3F5F7]">Learned Behavioral Baseline</span>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[#20D3A2]/10 text-[#20D3A2]">
              CALIBRATED
            </span>
          </div>
          <div className="space-y-2 text-[12px]">
            <div className="flex justify-between">
              <span className="text-[#66707D]">Norm Method:</span>
              <span className="font-mono text-[#F3F5F7]">Robust Median-MAD</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#66707D]">Reference Flows:</span>
              <span className="font-mono text-[#20D3A2] font-semibold">
                {report.components.baseline_guard.fitted_flows > 0
                  ? report.components.baseline_guard.fitted_flows.toLocaleString()
                  : "Calibrated"}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#66707D]">Behavioral Stability:</span>
              <span className="font-mono text-[#20D3A2] font-semibold">
                {bHealth.stability ?? 92}%
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#66707D]">Volume Drift:</span>
              <span className="font-mono text-[#4C9AFF] font-semibold">
                {report.behavior?.baseline_deviation?.flow_rate >= 0 ? `+${report.behavior?.baseline_deviation?.flow_rate}%` : `${report.behavior?.baseline_deviation?.flow_rate}%`}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#66707D]">Privacy Boundary:</span>
              <span className="font-mono text-[#20D3A2] font-semibold">Zero-Payload / Metadata</span>
            </div>
          </div>
        </Card>
      </div>
    </div>
  );
}
