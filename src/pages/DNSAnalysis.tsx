import { useArgus } from "@/data/api";
import React from "react";
import { Card, PageHeader, SectionHeader, TableWrapper, Th, Td, SeverityBadge } from "@/components/ui";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";
import { severityColor } from "@/data/mockData";

export default function DNSAnalysis() {
  const { DNS_RECORDS, data, connected, updateAlert, mutate, busy } = useArgus();
  const ENTROPY_DATA = DNS_RECORDS.slice(0,12).map(d => ({ domain: d.domain.slice(0,16), entropy: d.entropy }));
  const QUERY_VOL = DNS_RECORDS.reduce<{time: string; queries: number; flagged: number}[]>((out,d) => { let row = out.find(r => r.time === d.qtype); if (!row) { row = {time: d.qtype, queries: 0, flagged: 0}; out.push(row); } row.queries++; if (d.risk !== null) row.flagged++; return out; }, []);
  return (
    <div className="p-6 max-w-[1440px] mx-auto space-y-5">
      <PageHeader
        title="DNS Analysis"
        breadcrumb="Analysis"
        subtitle="DNS metadata analysis for DGA and tunnelling detection."
      />

      {/* KPIs */}
      <div className="grid grid-cols-5 gap-3">
        {[
          { label: "DNS Queries Analyzed", val: DNS_RECORDS.length },
          { label: "Unique Domains", val: new Set(DNS_RECORDS.map(d => d.domain)).size },
          { label: "DGA Detections", val: data.alerts.filter(a => a.detector === "dns_lexical").length, color: "#EB5757" },
          { label: "Tunnel Detections", val: data.alerts.filter(a => a.detector === "dns_tunnel").length, color: "#F2994A" },
          { label: "TXT/NULL/CNAME Activity", val: DNS_RECORDS.filter(d => ["TXT","NULL","CNAME"].includes(d.qtype)).length, color: "#F2C94C" },
        ].map((k) => (
          <Card key={k.label} className="p-3 flex flex-col gap-1">
            <span className="text-[10px] text-[#66707D] uppercase tracking-widest">{k.label}</span>
            <span className="text-[22px] font-bold font-mono" style={{ color: k.color ?? "#F3F5F7" }}>{k.val}</span>
          </Card>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Query Volume */}
        <Card className="p-4">
          <SectionHeader title="Query Volume" subtitle="Observed queries by record type" />
          <ResponsiveContainer width="100%" height={160}>
            <BarChart data={QUERY_VOL} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
              <CartesianGrid stroke="#1A2030" strokeDasharray="3 3" />
              <XAxis dataKey="time" tick={{ fill: "#66707D", fontSize: 9 }} tickLine={false} />
              <YAxis tick={{ fill: "#66707D", fontSize: 9 }} tickLine={false} />
              <Tooltip contentStyle={{ background: "#11161D", border: "1px solid #242B35", borderRadius: 6, fontSize: 11 }} />
              <Bar dataKey="queries" fill="#242B35" radius={[2, 2, 0, 0]} name="Queries" />
              <Bar dataKey="flagged" fill="#EB5757" radius={[2, 2, 0, 0]} name="Flagged" />
            </BarChart>
          </ResponsiveContainer>
        </Card>

        {/* Domain Entropy */}
        <Card className="p-4">
          <SectionHeader title="Domain Entropy" subtitle="Raw label entropy in bits; detection also checks length and digit density" />
          <ResponsiveContainer width="100%" height={160}>
            <BarChart data={ENTROPY_DATA} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
              <CartesianGrid stroke="#1A2030" strokeDasharray="3 3" />
              <XAxis dataKey="domain" tick={{ fill: "#66707D", fontSize: 9 }} tickLine={false} />
              <YAxis tick={{ fill: "#66707D", fontSize: 9 }} tickLine={false} domain={[0, 5]} />
              <Tooltip contentStyle={{ background: "#11161D", border: "1px solid #242B35", borderRadius: 6, fontSize: 11 }} />
              <Bar dataKey="entropy" radius={[2, 2, 0, 0]} fill="#4C9AFF"
                label={{ position: "top", fill: "#66707D", fontSize: 9 }}
              />
            </BarChart>
          </ResponsiveContainer>
        </Card>
      </div>

      {/* DNS Threat Table */}
      <Card>
        <div className="px-4 pt-4 pb-2">
          <SectionHeader title="DNS Threat Records" subtitle="Flagged domains and analysis results" />
        </div>
        <TableWrapper>
          <thead>
            <tr>
              <Th>Domain</Th>
              <Th>Source</Th>
              <Th>Query Type</Th>
              <Th>Entropy</Th>
              <Th>Length</Th>
              <Th>Detection</Th>
              <Th>Risk</Th>
            </tr>
          </thead>
          <tbody>
            {DNS_RECORDS.map((r, i) => (
              <tr key={i} className="hoverable">
                <Td mono className="text-[#F3F5F7] max-w-xs truncate">{r.domain}</Td>
                <Td mono>{r.source}</Td>
                <Td mono className="text-[#F2C94C]">{r.qtype}</Td>
                <Td mono>{r.entropy}</Td>
                <Td mono>{r.length}</Td>
                <Td>
                  {r.detection !== "-" ? (
                    <span className="text-[12px] font-medium text-[#F2994A]">{r.detection}</span>
                  ) : (
                    <span className="text-[#3A4456]">—</span>
                  )}
                </Td>
                <Td>
                  {r.risk !== null ? (
                    <span className="font-mono font-bold" style={{ color: severityColor(r.risk >= 80 ? "critical" : r.risk >= 60 ? "high" : "medium") }}>
                      {r.risk}
                    </span>
                  ) : <span className="text-[#3A4456]">—</span>}
                </Td>
              </tr>
            ))}
          </tbody>
        </TableWrapper>
      </Card>
    </div>
  );
}
