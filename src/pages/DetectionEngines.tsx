import { useArgus } from "@/data/api";
import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Card, ElevatedCard, PageHeader, StatusBadge, Button } from "@/components/ui";


export default function DetectionEngines() {
  const { DETECTORS, data, connected, updateAlert, mutate, busy } = useArgus();
  const navigate = useNavigate();

  return (
    <div className="p-6 max-w-[1440px] mx-auto space-y-4">
      <PageHeader
        title="Detection Engines"
        breadcrumb="Detection"
        subtitle="Independent explainable detection modules."
        actions={
          <div className="flex items-center gap-2">
            <div className="px-3 py-1 rounded bg-[#20D3A2]/10 border border-[#20D3A2]/30 text-[#20D3A2] text-[12px] font-semibold">
              {connected ? `${DETECTORS.length} / 9 ACTIVE` : "OFFLINE"}
            </div>
          </div>
        }
      />

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {DETECTORS.map((d) => (
          <Card key={d.id} className="p-4 flex flex-col gap-3 hover:border-[#3A4456] transition-colors">
            <div className="flex items-start justify-between">
              <div>
                <div className="text-[14px] font-semibold text-[#F3F5F7]">{d.name}</div>
                <div className="text-[11px] font-mono text-[#66707D] mt-0.5">{d.id}</div>
              </div>
              <StatusBadge status={d.status} />
            </div>

            <p className="text-[12px] text-[#9AA4B2] leading-relaxed">{d.purpose}</p>

            {/* Thresholds */}
            <div className="bg-[#0D1117] rounded p-2.5 space-y-1">
              <div className="text-[10px] text-[#66707D] uppercase tracking-widest mb-1">Thresholds</div>
              {d.thresholds.map((t) => (
                <div key={t.key} className="flex justify-between items-center">
                  <span className="text-[11px] font-mono text-[#66707D]">{t.key}</span>
                  <span className="text-[11px] font-mono font-semibold text-[#F3F5F7]">{t.value}</span>
                </div>
              ))}
            </div>

            {/* Stats */}
            <div className="grid grid-cols-3 gap-2">
              {[
                { label: "Input flows", val: d.observations.toLocaleString() },
                { label: "Alerts", val: String(d.alerts_generated) },
                { label: "Window", val: d.window },
              ].map(({ label, val }) => (
                <div key={label} className="text-center">
                  <div className="text-[10px] text-[#66707D] uppercase tracking-wide">{label}</div>
                  <div className="text-[14px] font-mono font-bold text-[#F3F5F7] mt-0.5">{val}</div>
                </div>
              ))}
            </div>

            <div className="flex items-center justify-between pt-1 border-t border-[#1A2030]">
              <span className="text-[10px] text-[#66707D] font-mono">
                Last: {d.last_triggered.split("T")[1]?.split(".")[0] ?? "—"} UTC
              </span>
              <Button variant="accent" size="sm" onClick={() => navigate(`/engines/${d.id}`)}>
                View details →
              </Button>
            </div>
          </Card>
        ))}
      </div>
    </div>
  );
}
