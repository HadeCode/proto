import React, { useState } from "react";
import { Card, PageHeader, TableWrapper, Th, Td } from "@/components/ui";
import { useArgus } from "@/data/api";

export default function Baseline() {
  const { data, mutate, busy } = useArgus();
  const [input, setInput] = useState("");
  const [error, setError] = useState("");
  const b = data.baseline;
  return <div className="p-6 max-w-[1000px] mx-auto space-y-5">
    <PageHeader title="Baseline Analysis" breadcrumb="Analysis" subtitle="An optional median/MAD baseline fitted only from known-benign flow metadata."/>
    <Card className="p-4 space-y-2"><p>{b.fitted_at ? "FITTED" : "NOT FITTED"}</p><p className="text-sm text-[#9AA4B2]">Last fitted: {b.fitted_at ?? "Never"} · Benign flows: {b.flows}</p></Card>
    <Card><TableWrapper><thead><tr><Th>Feature</Th><Th>Median</Th><Th>MAD</Th></tr></thead><tbody>{Object.entries(b.median).map(([key,val]) => <tr key={key}><Td>{key}</Td><Td>{val}</Td><Td>{b.mad[key]}</Td></tr>)}</tbody></TableWrapper></Card>
    <Card className="p-4 space-y-3">
      <label htmlFor="benign-flows" className="text-sm">Paste a JSON array of known-benign normalized flows</label>
      <textarea id="benign-flows" value={input} onChange={e => setInput(e.target.value)} className="block w-full h-40 bg-[#0D1117] rounded p-3 font-mono text-xs" placeholder='[{ "timestamp": "...", "src_ip": "...", ... }]'/>
      <button disabled={busy || !input.trim()} className="text-[#20D3A2] disabled:opacity-40" onClick={async () => { try { const rows: unknown = JSON.parse(input); if (!Array.isArray(rows)) throw new Error("Expected a JSON array"); setError(""); await mutate("/baseline/fit","POST",rows); } catch(e) { setError(String(e)); } }}>Fit from these benign flows</button>
      {error && <p role="alert" className="text-[#EB5757] text-sm">{error}</p>}
    </Card>
  </div>;
}
