import { download } from "@/data/api";
import { useArgus } from "@/data/api";
import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Card, PageHeader, Tabs, TableWrapper, Th, Td, SeverityBadge, StatusBadge, Button } from "@/components/ui";
import { severityColor } from "@/data/mockData";

type Tab = "ALL" | "OPEN" | "ACKNOWLEDGED" | "RESOLVED";

export default function Alerts() {
  const { ALERTS, data, connected, updateAlert, mutate, busy } = useArgus();
  const navigate = useNavigate();
  const [tab, setTab] = useState<Tab>("ALL");

  const filtered = ALERTS.filter((a) => {
    if (tab === "ALL") return true;
    return a.status === tab;
  });

  return (
    <div className="p-6 max-w-[1440px] mx-auto space-y-4">
      <PageHeader
        title="Alerts"
        breadcrumb="Detection"
        subtitle="Alert queue for all ARGUS-ONE detection events."
        actions={
          <div className="flex gap-2">
            <Button variant="default" size="sm" onClick={() => download("argus-alerts.json", filtered)}>Export JSON</Button>
          </div>
        }
      />

      <Tabs
        tabs={["ALL", "OPEN", "ACKNOWLEDGED", "RESOLVED"]}
        active={tab}
        onChange={(t) => setTab(t as Tab)}
      />

      <Card>
        <TableWrapper>
          <thead>
            <tr>
              <Th>Severity</Th>
              <Th>Alert ID</Th>
              <Th>Threat</Th>
              <Th>Source</Th>
              <Th>Target</Th>
              <Th>Risk</Th>
              <Th>Created</Th>
              <Th>Detector</Th>
              <Th>Status</Th>
              <Th>Actions</Th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((a) => (
              <tr key={a.alert_id} className="hoverable">
                <Td><SeverityBadge severity={a.severity} /></Td>
                <Td mono className="text-[#20D3A2] cursor-pointer hover:underline" onClick={() => navigate(`/alerts/${a.alert_id}`)} title={a.alert_id}>
                  {a.alert_id}
                </Td>
                <Td className="text-[#F3F5F7] font-medium">{a.threat_class}</Td>
                <Td mono>{a.source.ip}</Td>
                <Td mono>{a.target.ip}</Td>
                <Td>
                  <span className="font-mono font-bold" style={{ color: severityColor(a.severity) }}>
                    {Math.round(a.risk_score * 100)}
                  </span>
                </Td>
                <Td mono className="text-[#66707D]">{a.timestamp.replace("T", " ").replace("Z", "")}</Td>
                <Td mono className="text-[#66707D]">{a.detector}</Td>
                <Td><StatusBadge status={a.status} /></Td>
                <Td>
                  <div className="flex gap-1">
                    <Button variant="ghost" size="sm" onClick={() => navigate(`/alerts/${a.alert_id}`)}>View</Button>
                    {a.status === "OPEN" && <Button variant="default" size="sm" onClick={() => void updateAlert(a.alert_id, "ACKNOWLEDGED")}>Ack</Button>}
                    {a.status !== "RESOLVED" && <Button variant="accent" size="sm" onClick={() => void updateAlert(a.alert_id, "RESOLVED")}>Resolve</Button>}
                  </div>
                </Td>
              </tr>
            ))}
          </tbody>
        </TableWrapper>
      </Card>
    </div>
  );
}
