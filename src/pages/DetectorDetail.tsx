import { useArgus } from "@/data/api";
import React from "react";
import { useParams, useNavigate } from "react-router-dom";
import { Card, ElevatedCard, PageHeader, StatusBadge, Button } from "@/components/ui";


const FLOW_STEPS: Record<string, string[]> = {
  asymmetric_volume: [
    "Flow Metadata",
    "External Destination Filter",
    "Outbound Volume Calculation",
    "Inbound / Outbound Ratio",
    "Optional Baseline Deviation",
    "Risk Score",
    "Alert",
  ],
  syn_flood: ["Flow Metadata", "SYN Flag Filter", "Source Count per Target", "Rate Calculation", "Threshold Check", "Risk Score", "Alert"],
  dns_tunnel: ["DNS Query Metadata", "Query Type Filter", "Volume & Length Analysis", "Entropy Scoring", "Subdomain Counting", "Risk Score", "Alert"],
  dns_lexical: ["DNS Query Metadata", "Domain Extraction", "Lexical Entropy Analysis", "Length Check", "DGA Classification", "Risk Score", "Alert"],
  fanout_scan: ["Flow Metadata", "Unique Port / Host Counting", "Fanout Detection", "Rate Window", "Threshold Check", "Risk Score", "Alert"],
  periodic_beacon: ["Flow Metadata", "Periodic Interval Detection", "Jitter Calculation", "Observation Count", "C2 Pattern Match", "Risk Score", "Alert"],
  tls_quic_metadata: ["TLS / QUIC Metadata", "JA3/JA4 Fingerprinting", "Known Malicious Fingerprint Check", "Rare Fingerprint Detection", "SNI / ALPN Analysis", "Risk Score", "Alert"],
  udp_reflection: ["Flow Metadata", "UDP Protocol Filter", "Response Ratio Calculation", "Amplification Factor", "Threshold Check", "Risk Score", "Alert"],
  spoofed_source_flood: ["Flow Metadata", "Source Randomness Analysis", "Unique Source Rate", "Source Prefix Entropy", "Threshold Check", "Risk Score", "Alert"],
};

export default function DetectorDetail() {
  const { DETECTORS, data, connected, updateAlert, mutate, busy } = useArgus();
  const { id } = useParams();
  const navigate = useNavigate();
  const detector = DETECTORS.find((d) => d.id === id);
  if (!detector) return <div className="p-6 text-[#9AA4B2]">Detector not found or still loading.</div>;
  const steps = FLOW_STEPS[detector.id] ?? FLOW_STEPS.asymmetric_volume;

  return (
    <div className="p-6 max-w-[1000px] mx-auto space-y-5">
      <button
        onClick={() => navigate("/engines")}
        className="text-[12px] text-[#66707D] hover:text-[#9AA4B2] flex items-center gap-1"
      >
        ← Back to Detection Engines
      </button>

      <div className="flex items-start justify-between">
        <div>
          <div className="text-[11px] text-[#66707D] uppercase tracking-widest mb-1">Detection Engine</div>
          <h1 className="text-[24px] font-bold text-[#F3F5F7]">{detector.name}</h1>
          <div className="text-[13px] font-mono text-[#20D3A2] mt-0.5">{detector.id}</div>
        </div>
        <StatusBadge status={detector.status} />
      </div>

      <p className="text-[13px] text-[#9AA4B2] leading-relaxed">{detector.purpose}</p>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Configuration */}
        <Card className="p-4">
          <div className="text-[12px] font-semibold text-[#F3F5F7] uppercase tracking-wide mb-3">Configuration</div>
          <div className="space-y-2">
            <div className="flex justify-between">
              <span className="text-[12px] text-[#66707D]">Analysis Window</span>
              <span className="text-[12px] font-mono text-[#F3F5F7]">{detector.window}</span>
            </div>
            {detector.thresholds.map((t) => (
              <div key={t.key} className="flex justify-between">
                <span className="text-[12px] font-mono text-[#66707D]">{t.key}</span>
                <span className="text-[12px] font-mono font-semibold text-[#F3F5F7]">{t.value}</span>
              </div>
            ))}
          </div>
        </Card>

        {/* Stats */}
        <Card className="p-4">
          <div className="text-[12px] font-semibold text-[#F3F5F7] uppercase tracking-wide mb-3">Performance</div>
          <div className="grid grid-cols-2 gap-3">
            {[
              { label: "Retained input flows", val: detector.observations.toLocaleString() },
              { label: "Alerts Generated", val: String(detector.alerts_generated) },
              { label: "Last Triggered", val: detector.last_triggered.split("T")[1]?.split(".")[0] ?? "—" },
              { label: "Status", val: detector.status },
            ].map(({ label, val }) => (
              <div key={label}>
                <div className="text-[10px] text-[#66707D] uppercase tracking-wide">{label}</div>
                <div className="text-[15px] font-mono font-bold text-[#F3F5F7] mt-0.5">{val}</div>
              </div>
            ))}
          </div>
        </Card>
      </div>

      {/* Detection Logic Flowchart */}
      <Card className="p-5">
        <div className="text-[12px] font-semibold text-[#F3F5F7] uppercase tracking-wide mb-4">Detection Logic</div>
        <div className="flex flex-col items-center gap-0">
          {steps.map((step, i) => (
            <React.Fragment key={step}>
              <div className={`
                w-64 text-center px-4 py-2.5 rounded-lg border text-[12px] font-medium
                ${i === 0 ? "bg-[#20D3A2]/10 border-[#20D3A2]/30 text-[#20D3A2]" :
                  i === steps.length - 1 ? "bg-[#EB5757]/10 border-[#EB5757]/30 text-[#EB5757]" :
                  i === steps.length - 2 ? "bg-[#F2994A]/10 border-[#F2994A]/30 text-[#F2994A]" :
                  "bg-[#151B23] border-[#242B35] text-[#9AA4B2]"}
              `}>
                {step}
              </div>
              {i < steps.length - 1 && (
                <div className="flex flex-col items-center py-1">
                  <div className="w-px h-3 bg-[#242B35]" />
                  <div className="text-[#3A4456] text-[10px]">↓</div>
                </div>
              )}
            </React.Fragment>
          ))}
        </div>
      </Card>

      <div className="text-[10px] text-[#66707D] text-center uppercase tracking-widest">
        Passive Metadata Analysis · No Payload Inspection
      </div>
    </div>
  );
}
