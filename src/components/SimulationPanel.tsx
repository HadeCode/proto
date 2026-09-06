import React, { useState } from "react";
import { useArgus } from "@/data/api";

export default function SimulationPanel() {
  const { data, DETECTORS, connected, busy, mutate } = useArgus();
  const [scenario, setScenario] = useState("all");
  const s = data.simulation;
  const running = ["running", "stopping"].includes(s.status);
  return <section className="border border-[#242B35] rounded-lg p-4 bg-[#11161D] space-y-3">
    <div className="flex flex-wrap items-center gap-3">
      <div className="flex-1"><h2 className="font-semibold">Detection simulations</h2><p className="text-xs text-[#9AA4B2]">Replay synthetic flow metadata through the configured detection engines.</p></div>
      <select aria-label="Simulation scenario" className="bg-[#0D1117] border border-[#242B35] rounded px-3 py-2 text-xs" value={scenario} onChange={e => setScenario(e.target.value)} disabled={running}>
        <option value="all">All nine attacks</option>{DETECTORS.map(d => <option key={d.id} value={d.id}>{d.name}</option>)}
      </select>
      <button disabled={!connected || running || busy} className="bg-[#20D3A2]/20 text-[#20D3A2] rounded px-4 py-2 text-sm disabled:opacity-40" onClick={() => void mutate(`/simulate/${scenario}`)}>{running ? "Running…" : "Run simulation"}</button>
      {running && <button className="text-[#F2994A] text-sm" onClick={() => void mutate("/stop")} disabled={busy}>Stop</button>}
    </div>
    {s.status !== "idle" && <div role="status" className="text-xs text-[#9AA4B2] space-y-2">
      <p>{s.status.toUpperCase()} · {s.processed.toLocaleString()} / {s.total.toLocaleString()} flows · {s.detected.length} threat classes detected</p>
      <progress aria-label="Simulation progress" className="w-full accent-[#20D3A2]" value={s.processed} max={s.total || 1}/>
      <p className="text-[#20D3A2]">{s.detected.join(" · ")}</p>
      {s.status === "complete" && <p>{s.missing.length ? `Not detected at current thresholds: ${s.missing.join(", ")}` : "All expected scenarios detected."}</p>}
      {s.error && <p className="text-[#EB5757]">{s.error}</p>}
    </div>}
  </section>;
}
