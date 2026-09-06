import React from "react";
import { Card, PageHeader } from "@/components/ui";
import { useArgus } from "@/data/api";
export default function AgentStatus() {
  const { data, connected } = useArgus();
  const stats = {
    "Backend": connected ? "ONLINE" : "OFFLINE",
    "Detection engines": connected ? data.detectors.length + " available" : "Unavailable",
    "Uptime": data.summary.uptime_seconds + " seconds",
    "Last received flow": data.summary.last_flow ?? "None",
    "Retained flow records": data.summary.flows_processed,
    "Retained alerts": data.alerts.length,
    "Baseline": data.baseline.fitted_at ? "Fitted" : "Not fitted",
    "Simulation": data.simulation.status,
  };
  return <div className="p-6 max-w-[1100px] mx-auto space-y-5">
    <PageHeader title="ARGUS-ONE Engine Status" breadcrumb="System" subtitle="Backend state refreshed every two seconds."/>
    <div className="grid grid-cols-2 gap-4">{Object.entries(stats).map(([key,val]) => <Card key={key} className="p-4"><p className="text-xs text-[#9AA4B2]">{key}</p><p className="font-mono mt-2 break-all">{val}</p></Card>)}</div>
    <Card className="p-4 text-sm space-y-2"><p>Flow metadata → validation → rolling detection windows → saved alerts → dashboard</p><p className="text-[#9AA4B2]">The dashboard uses HTTP polling. It displays up to 1,000 recent flows; history retains up to 20,000 flows and 5,000 alerts. Rolling detector state starts fresh when the API restarts.</p></Card>
  </div>;
}
