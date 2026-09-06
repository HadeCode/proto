import { useArgus } from "@/data/api";
import React, { useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { Card, ElevatedCard, SeverityBadge, StatusBadge, RiskScore, EvidenceBar, Button } from "@/components/ui";
import { severityColor } from "@/data/mockData";

const ALL_CLASSES = [
  "Benign",
  "SYN Flood",
  "UDP Reflection / Amplification",
  "Spoofed-Source Flood",
  "Botnet C2 Beaconing",
  "DGA Domain",
  "DNS Tunnelling",
  "Encrypted-Session Malware",
  "Port Scanning",
  "Data Exfiltration",
];

export default function AlertDetail() {
  const { ALERTS, data, connected, updateAlert, submitAlertFeedback, mutate, busy } = useArgus();
  const { id } = useParams();
  const navigate = useNavigate();
  const alert = ALERTS.find((a) => a.alert_id === id);

  const [feedbackStatus, setFeedbackStatus] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [reclassOpen, setReclassOpen] = useState(false);
  const [selectedReclass, setSelectedReclass] = useState<string>("Benign");
  const [feedbackNotes, setFeedbackNotes] = useState<string>("");

  if (!alert) return <div className="p-6 text-[#9AA4B2]">Alert not found or still loading.</div>;
  const sColor = severityColor(alert.severity);

  return (
    <div className="p-6 max-w-[1100px] mx-auto space-y-5">
      {/* Back + Header */}
      <div className="flex items-center gap-3 mb-1">
        <button
          onClick={() => navigate("/threats")}
          className="text-[12px] text-[#66707D] hover:text-[#9AA4B2] flex items-center gap-1"
        >
          ← Back to Threats
        </button>
      </div>

      <div className="flex items-start justify-between">
        <div className="flex items-center gap-4">
          <RiskScore score={alert.risk_score} />
          <div>
            <div className="flex items-center gap-2 mb-1">
              <SeverityBadge severity={alert.severity} />
              <StatusBadge status={alert.status} />
            </div>
            <h1 className="text-[24px] font-bold text-[#F3F5F7] tracking-tight uppercase">{alert.threat_class}</h1>
            <div className="text-[13px] font-mono text-[#20D3A2] mt-0.5">{alert.alert_id}</div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="default" onClick={() => void updateAlert(alert.alert_id, "ACKNOWLEDGED")}>Acknowledge</Button>
          <Button variant="accent" onClick={() => void updateAlert(alert.alert_id, "RESOLVED")}>Resolve</Button>
        </div>
      </div>

      {/* Alert Summary */}
      <Card className="p-5">
        <div className="text-[13px] font-semibold text-[#F3F5F7] mb-3 uppercase tracking-wide">Alert Summary</div>
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
          {[
            { label: "Timestamp", val: alert.timestamp.replace("T", " ").replace("Z", " UTC"), mono: true },
            { label: "Source", val: alert.source.ip, mono: true },
            { label: "Target", val: alert.target.ip, mono: true },
            { label: "Detector", val: alert.detector, mono: true },
            { label: "Analysis Window", val: alert.window_seconds > 0 ? `${alert.window_seconds}s` : "N/A", mono: true },
            { label: "Status", val: alert.status, mono: false },
          ].map(({ label, val, mono }) => (
            <div key={label}>
              <div className="text-[10px] text-[#66707D] uppercase tracking-widest mb-1">{label}</div>
              <div className={`text-[13px] text-[#F3F5F7] font-medium ${mono ? "font-mono" : ""}`}>{val}</div>
            </div>
          ))}
        </div>
      </Card>

      {/* Continuous Learning & Model Mistake Correction Panel */}
      <Card className="p-5 border border-[#4C9AFF]/30 bg-gradient-to-r from-[#0C121A] via-[#101722] to-[#0C121A]">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-3">
          <div className="flex items-center gap-2.5">
            <span className="text-xl">🧠</span>
            <div>
              <div className="text-[13px] font-bold text-[#F3F5F7] tracking-wide uppercase flex items-center gap-2">
                Teach the Model: Continuous Self-Learning from Mistakes
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[#4C9AFF]/15 text-[#4C9AFF] border border-[#4C9AFF]/30">
                  SECONDARY DATA SOURCE
                </span>
              </div>
              <p className="text-[12px] text-[#9AA4B2] mt-0.5">
                Was this alert a false positive or misclassified? Submitting ground truth feeds this flow into the secondary mistake buffer for automated retraining.
              </p>
            </div>
          </div>
          {alert.status === "FALSE_POSITIVE" && (
            <span className="px-2.5 py-1 rounded text-[11px] font-mono font-bold bg-[#EB5757]/15 text-[#EB5757] border border-[#EB5757]/30 self-start sm:self-center">
              ALREADY MARKED FALSE POSITIVE
            </span>
          )}
        </div>

        {feedbackStatus && (
          <div className="mb-3 p-3 rounded-lg bg-[#20D3A2]/10 border border-[#20D3A2]/30 text-[#20D3A2] text-[12px] font-mono flex items-center gap-2">
            <span>✓</span> {feedbackStatus}
          </div>
        )}

        <div className="flex items-center gap-3 flex-wrap pt-1">
          <Button
            variant="default"
            disabled={isSubmitting || alert.status === "FALSE_POSITIVE"}
            onClick={async () => {
              setIsSubmitting(true);
              try {
                await submitAlertFeedback(alert.alert_id, "Benign", "FALSE_POSITIVE", "Analyst confirmed benign normal traffic");
                setFeedbackStatus("Flow recorded as Benign into secondary replay buffer. Model will adapt on next retrain.");
              } catch (e) {
                setFeedbackStatus("Failed to submit feedback: " + String(e));
              } finally {
                setIsSubmitting(false);
              }
            }}
            className="border-[#EB5757]/40 text-[#EB5757] hover:bg-[#EB5757]/10"
          >
            🛡 Mark as False Positive (Teach Model: Benign)
          </Button>

          <Button
            variant="default"
            disabled={isSubmitting}
            onClick={() => setReclassOpen(!reclassOpen)}
            className="border-[#4C9AFF]/40 text-[#4C9AFF] hover:bg-[#4C9AFF]/10"
          >
            🔄 Reclassify Threat Class
          </Button>
        </div>

        {reclassOpen && (
          <div className="mt-4 p-4 rounded-lg bg-[#090D13] border border-[#1E2530] space-y-3">
            <div className="text-[12px] font-semibold text-[#F3F5F7]">
              Select the Ground-Truth (True Attack Type) for this Flow:
            </div>
            <div className="flex flex-col sm:flex-row gap-3">
              <select
                value={selectedReclass}
                onChange={(e) => setSelectedReclass(e.target.value)}
                className="bg-[#151B23] border border-[#242B35] rounded px-3 py-1.5 text-[12px] text-[#F3F5F7] font-mono flex-1 focus:outline-none focus:border-[#4C9AFF]"
              >
                {ALL_CLASSES.filter((c) => c !== alert.threat_class).map((c) => (
                  <option key={c} value={c}>
                    {c}
                  </option>
                ))}
              </select>
              <input
                type="text"
                placeholder="Optional notes (e.g. why this was misclassified)..."
                value={feedbackNotes}
                onChange={(e) => setFeedbackNotes(e.target.value)}
                className="bg-[#151B23] border border-[#242B35] rounded px-3 py-1.5 text-[12px] text-[#F3F5F7] flex-1 focus:outline-none focus:border-[#4C9AFF]"
              />
              <Button
                variant="accent"
                disabled={isSubmitting}
                onClick={async () => {
                  setIsSubmitting(true);
                  try {
                    await submitAlertFeedback(
                      alert.alert_id,
                      selectedReclass,
                      "RECLASSIFIED",
                      feedbackNotes || `Reclassified by analyst from ${alert.threat_class} to ${selectedReclass}`
                    );
                    setFeedbackStatus(`Reclassified as ${selectedReclass}. Saved to secondary replay dataset.`);
                    setReclassOpen(false);
                  } catch (e) {
                    setFeedbackStatus("Failed to submit reclassification: " + String(e));
                  } finally {
                    setIsSubmitting(false);
                  }
                }}
              >
                Save Mistake Correction
              </Button>
            </div>
          </div>
        )}
      </Card>

      {/* Source → Target Visualization */}
      <Card className="p-5">
        <div className="text-[13px] font-semibold text-[#F3F5F7] mb-4 uppercase tracking-wide">
          Source → Target Flow
        </div>
        <div className="flex items-center justify-center gap-0">
          {/* Source */}
          <div className="text-center p-4 rounded-lg bg-[#0D1117] border border-[#242B35] w-36">
            <div className="text-[10px] text-[#66707D] uppercase tracking-widest mb-1">Source</div>
            <div className="text-[14px] font-mono font-bold text-[#F3F5F7]">{alert.source.ip}</div>
            <div className="text-[10px] text-[#66707D] mt-1">Source</div>
          </div>

          {/* Arrow */}
          <div className="flex flex-col items-center px-4 gap-2">
            <div className="text-[10px] text-[#66707D] font-mono">14 MB →</div>
            <div className="h-px w-24 bg-gradient-to-r from-[#F2994A] to-[#EB5757] relative">
              <div className="absolute right-0 top-1/2 -translate-y-1/2 w-2 h-2 border-r-2 border-t-2 border-[#EB5757] rotate-45 translate-x-0.5" />
            </div>
            <div className="text-[10px] text-[#66707D] font-mono">← 3 KB</div>
          </div>

          {/* ARGUS-ONE */}
          <div className="text-center p-4 rounded-lg bg-[#20D3A2]/5 border border-[#20D3A2]/30 w-40">
            <svg viewBox="0 0 24 24" fill="none" className="w-6 h-6 mx-auto mb-1">
              <circle cx="12" cy="12" r="9" stroke="#20D3A2" strokeWidth="1.5" />
              <circle cx="12" cy="12" r="4" stroke="#20D3A2" strokeWidth="1.5" />
              <circle cx="12" cy="12" r="1.5" fill="#20D3A2" />
            </svg>
            <div className="text-[11px] font-bold text-[#20D3A2]">ARGUS-ONE</div>
            <div className="text-[9px] text-[#66707D] mt-0.5">Passive Metadata Analysis</div>
          </div>

          {/* Arrow 2 */}
          <div className="flex flex-col items-center px-4">
            <div className="h-px w-24 bg-gradient-to-r from-[#EB5757] to-[#F2994A] relative">
              <div className="absolute right-0 top-1/2 -translate-y-1/2 w-2 h-2 border-r-2 border-t-2 border-[#F2994A] rotate-45 translate-x-0.5" />
            </div>
          </div>

          {/* Target */}
          <div className="text-center p-4 rounded-lg bg-[#0D1117] border border-[#242B35] w-36">
            <div className="text-[10px] text-[#66707D] uppercase tracking-widest mb-1">Target</div>
            <div className="text-[14px] font-mono font-bold text-[#F3F5F7]">{alert.target.ip}</div>
            <div className="text-[10px] text-[#66707D] mt-1">Target</div>
          </div>
        </div>

      </Card>

      {/* Evidence */}
      <Card className="p-5">
        <div className="text-[13px] font-semibold text-[#F3F5F7] mb-4 uppercase tracking-wide">
          Detection Evidence
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {alert.evidence.map((e) => (
            <ElevatedCard key={e.feature} className="p-4">
              <div className="flex items-center justify-between mb-1">
                <div className="text-[12px] font-semibold text-[#F3F5F7]">{e.label}</div>
                <span className="text-[10px] font-mono text-[#66707D] uppercase tracking-wide">{e.feature}</span>
              </div>
              <div className="text-[11px] text-[#9AA4B2] mb-2">{e.detail}</div>
              <p className="text-xs font-mono break-all">{String(e.value)} · threshold: {String(e.threshold)}</p>
              {typeof e.value === "number" && typeof e.threshold === "number" && <EvidenceBar value={e.value} threshold={e.threshold} />}
            </ElevatedCard>
          ))}
        </div>
      </Card>

      {/* Why ARGUS-ONE flagged this */}
      <Card className="p-5">
        <div className="flex items-center gap-2 mb-3">
          <div className="w-1 h-5 rounded" style={{ background: sColor }} />
          <div className="text-[13px] font-semibold text-[#F3F5F7] uppercase tracking-wide">
            Why ARGUS-ONE Flagged This
          </div>
        </div>
        <p className="text-[13px] text-[#9AA4B2] leading-relaxed mb-4">
          {alert.detector} detected {alert.threat_class} using the evidence below. {alert.evidence.map(e => e.detail).join(". ")}
        </p>
        <div className="text-[11px] text-[#EB5757]/80 bg-[#EB5757]/5 border border-[#EB5757]/20 rounded px-3 py-2 mb-3">
          Detection based on passive flow metadata only. No packet payloads were inspected or decrypted.
        </div>
        <div className="grid grid-cols-3 gap-3">
          {[
            { label: "Evidence Confidence", val: `${Math.round(alert.risk_score * 100)}%` },
            { label: "Detection Method", val: alert.detector },
            { label: "Analysis Window", val: alert.window_seconds > 0 ? `${alert.window_seconds}s` : "N/A" },
          ].map(({ label, val }) => (
            <div key={label} className="bg-[#0D1117] rounded p-3">
              <div className="text-[10px] text-[#66707D] uppercase tracking-wide mb-1">{label}</div>
              <div className="text-[13px] font-mono font-semibold text-[#F3F5F7]">{val}</div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
