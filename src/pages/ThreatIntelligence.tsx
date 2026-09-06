import React, { useState } from "react";
import { Card, PageHeader, Button, Tabs, TableWrapper, Th, Td } from "@/components/ui";
import { useArgus, download } from "@/data/api";

export default function ThreatIntelligence() {
  const { data, mutate, busy } = useArgus();
  const [tab,setTab] = useState("Malicious Fingerprints");
  const [fingerprint,setFingerprint] = useState("");
  const key = tab === "Trusted Fingerprints" ? "trusted_tls_fingerprints" : "malicious_tls_fingerprints";
  const values = (data.config[key] as string[] | undefined) ?? [];
  const reputation = data.flows.filter(f=>f.context.destination_reputation);
  return <div className="p-6 max-w-[1100px] mx-auto space-y-5">
    <PageHeader title="Threat Intelligence" breadcrumb="Analysis" subtitle="Local fingerprint lists used by the detector, and reputation supplied in flow metadata."/>
    <Tabs tabs={["Malicious Fingerprints","Trusted Fingerprints","Destination Reputation"]} active={tab} onChange={setTab}/>
    {tab !== "Destination Reputation" ? <>
      <div className="flex gap-3"><input aria-label="Fingerprint" value={fingerprint} onChange={e=>setFingerprint(e.target.value)} className="bg-[#11161D] border border-[#242B35] rounded px-3 py-2 flex-1 text-sm" placeholder="JA3 / JA3S / JA4 fingerprint"/>
      <button disabled={busy || !fingerprint.trim()} className="text-[#20D3A2] disabled:opacity-40" onClick={async()=>{if(await mutate("/config","PUT",{[key]:[...new Set([...values,fingerprint.trim().toLowerCase()])]}))setFingerprint("");}}>Add fingerprint</button>
      <Button onClick={()=>download("argus-fingerprints.json",{[key]:values})}>Export</Button></div>
      <Card><TableWrapper><thead><tr><Th>Fingerprint</Th><Th>Action</Th></tr></thead><tbody>{values.map(fp=><tr key={fp}><Td mono>{fp}</Td><Td><Button variant="danger" onClick={()=>void mutate("/config","PUT",{[key]:values.filter(v=>v!==fp)})}>Remove</Button></Td></tr>)}</tbody></TableWrapper>{!values.length && <p className="p-4 text-sm text-[#9AA4B2]">No fingerprints configured.</p>}</Card>
    </> : <Card><TableWrapper><thead><tr><Th>Destination</Th><Th>Reputation</Th><Th>Origin</Th></tr></thead><tbody>{reputation.map(f=><tr key={f.id}><Td mono>{f.dst_ip}</Td><Td>{String(f.context.destination_reputation)}</Td><Td>{f.origin}</Td></tr>)}</tbody></TableWrapper></Card>}
  </div>;
}
