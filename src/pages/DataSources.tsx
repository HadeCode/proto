import React, { useState } from "react";
import { Card, PageHeader } from "@/components/ui";
import { useArgus } from "@/data/api";
export default function DataSources() {
  const { data, connected, mutate, busy } = useArgus();
  const [input,setInput] = useState("");
  const [error,setError] = useState("");
  return <div className="p-6 max-w-[1100px] mx-auto space-y-5">
    <PageHeader title="Data Sources" breadcrumb="System" subtitle="Normalized metadata received through the HTTP ingestion API."/>
    <div className="grid grid-cols-2 gap-4">
      <Card className="p-4 space-y-2"><h2>Collector API</h2><p className="text-sm text-[#9AA4B2]">{connected ? "API reachable" : "API offline"} · {data.summary.collector_flows} retained collector records</p><code className="text-xs">POST /api/flows · POST /api/flows/batch</code></Card>
      <Card className="p-4 space-y-2"><h2>Synthetic simulations</h2><p className="text-sm text-[#9AA4B2]">{data.summary.simulation_flows} retained synthetic records</p><p className="text-xs text-[#9AA4B2]">Use the dashboard to run any of the nine attack scenarios.</p></Card>
    </div>
    <Card className="p-4 space-y-3">
      <p className="text-sm text-[#9AA4B2]">DNS, TLS, QUIC, and reputation are optional enrichment fields supplied by your collector. No external collector or intelligence feed is configured automatically.</p>
      <label htmlFor="flow-input" className="block text-sm">Submit normalized flow JSON (one object or an array)</label>
      <textarea id="flow-input" className="w-full h-44 bg-[#0D1117] rounded p-3 text-xs font-mono" value={input} onChange={e=>setInput(e.target.value)}/>
      <button className="text-[#20D3A2] disabled:opacity-40" disabled={!connected || busy || !input.trim()} onClick={async()=>{try { const rows: unknown = JSON.parse(input); setError(""); await mutate(Array.isArray(rows) ? "/flows/batch" : "/flows","POST",rows); } catch(e) {setError(String(e));}}}>Submit flow metadata</button>
      {error && <p role="alert" className="text-sm text-[#EB5757]">{error}</p>}
    </Card>
  </div>;
}
