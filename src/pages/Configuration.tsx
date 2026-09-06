import React, { useEffect, useState } from "react";
import { Card, PageHeader, Button } from "@/components/ui";
import { useArgus, download, type Config } from "@/data/api";

const DEFAULTS = { syn_flows_per_second: 20, udp_flows_per_second: 30, scan_min_ports: 20, scan_min_hosts: 12, exfil_min_bytes: 10000000, exfil_min_ratio: 12, c2_min_observations: 5, alert_cooldown_seconds: 30 };

export default function Configuration() {
  const { data, connected, busy, mutate } = useArgus();
  const [draft, setDraft] = useState<Config | null>(null);
  const [saved, setSaved] = useState(false);
  const config = draft ?? data.config;
  return <div className="p-6 max-w-[900px] mx-auto space-y-5">
    <PageHeader title="Configuration" breadcrumb="System" subtitle="Saved thresholds apply to incoming flows and subsequent simulation runs." />
    <div className="flex gap-3">
      <Button onClick={() => { setDraft({...config,...DEFAULTS}); setSaved(false); }}>Reset Defaults</Button>
      <Button onClick={() => download("argus-config.json", config)}>Export JSON</Button>
      <button disabled={!connected || busy} className="text-[#20D3A2] disabled:opacity-40" onClick={async () => { if (await mutate("/config", "PUT", config)) { setDraft(null); setSaved(true); } }}>Save Configuration</button>
    </div>
    {saved && <p role="status" className="text-[#20D3A2] text-sm">Configuration saved.</p>}
    {Object.keys(DEFAULTS).map(key => <Card key={key} className="p-4 flex items-center justify-between">
      <label htmlFor={key} className="text-sm font-mono">{key}</label>
      <input id={key} type="number" min="0.001" step={key.includes("ratio") || key.includes("per_second") ? "any" : "1"} value={Number(config[key] ?? DEFAULTS[key as keyof typeof DEFAULTS])}
        onChange={e => { setDraft({...config, [key]: Number(e.target.value)}); setSaved(false); }}
        className="bg-[#0D1117] border border-[#242B35] rounded px-3 py-2 w-48"/>
    </Card>)}
  </div>;
}
