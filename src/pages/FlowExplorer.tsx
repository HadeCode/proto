import { useArgus } from "@/data/api";
import React, { useState } from "react";
import { Card, PageHeader, FilterBar, Select, Input, TableWrapper, Th, Td, Button, ElevatedCard } from "@/components/ui";
import { formatBytes, severityColor } from "@/data/mockData";
import type { FlowRecord } from "@/data/mockData";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";


export default function FlowExplorer() {
  const { FLOW_RECORDS, TIMELINE_DATA, data, connected, updateAlert, mutate, busy } = useArgus();
  const [search, setSearch] = useState(new URLSearchParams(window.location.search).get("src") ?? "");
  const [selected, setSelected] = useState<FlowRecord | null>(null);
  const [protoFilter, setProtoFilter] = useState("All");
  const [threatFilter, setThreatFilter] = useState("All");

  const filtered = FLOW_RECORDS.filter((r) => {
    const q = search.toLowerCase();
    if (q && !r.src_ip.includes(q) && !r.dst_ip.includes(q) && !r.protocol.toLowerCase().includes(q)) return false;
    if (protoFilter !== "All" && r.protocol !== protoFilter) return false;
    if (threatFilter === "Flagged" && r.risk === null) return false;
    return true;
  });

  return (
    <div className="p-6 max-w-[1440px] mx-auto space-y-4">
      <PageHeader
        title="Flow Explorer"
        breadcrumb="Monitor"
        subtitle="Advanced flow investigation and search"
      />

      <FilterBar>
        <Input value={search} onChange={setSearch} placeholder="Search IP or protocol..." className="w-72" />
        <Select value={protoFilter} onChange={setProtoFilter}>
          <option value="All">All Protocols</option>
          <option value="TCP">TCP</option>
          <option value="UDP">UDP</option>
        </Select>
        <Select value={threatFilter} onChange={setThreatFilter}>
          <option value="All">All Flows</option>
          <option value="Flagged">Flagged Only</option>
        </Select>

        <span className="ml-auto text-[11px] text-[#66707D]">{filtered.length} flows</span>
      </FilterBar>

      {/* Timeline */}
      <Card className="p-4">
        <div className="text-[13px] font-semibold text-[#F3F5F7] mb-3">Flow Timeline</div>
        <ResponsiveContainer width="100%" height={120}>
          <BarChart data={TIMELINE_DATA} margin={{ top: 0, right: 0, left: -30, bottom: 0 }}>
            <CartesianGrid stroke="#1A2030" strokeDasharray="3 3" />
            <XAxis dataKey="t" tick={{ fill: "#66707D", fontSize: 9 }} tickLine={false} />
            <YAxis tick={{ fill: "#66707D", fontSize: 9 }} tickLine={false} />
            <Tooltip contentStyle={{ background: "#11161D", border: "1px solid #242B35", borderRadius: 6, fontSize: 11 }} />
            <Bar dataKey="flows" fill="#242B35" radius={[2, 2, 0, 0]} />
            <Bar dataKey="flagged" fill="#EB5757" radius={[2, 2, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Flow Table */}
        <div className="lg:col-span-2">
          <Card>
            <TableWrapper>
              <thead>
                <tr>
                  <Th>Timestamp</Th>
                  <Th>Source</Th>
                  <Th>Destination</Th>
                  <Th>Proto</Th>
                  <Th>Bytes</Th>
                  <Th>Risk</Th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((r) => (
                  <tr
                    key={r.id}
                    className={`hoverable cursor-pointer ${selected?.id === r.id ? "bg-[#20D3A2]/5" : ""}`}
                    onClick={() => setSelected(r)}
                  >
                    <Td mono>{r.timestamp}</Td>
                    <Td mono className="text-[#F3F5F7]">{r.src_ip}:{r.src_port}</Td>
                    <Td mono className="text-[#F3F5F7]">{r.dst_ip}:{r.dst_port}</Td>
                    <Td>
                      <span className={`text-[11px] font-semibold font-mono ${
                        r.protocol === "TCP" ? "text-[#4C9AFF]" : "text-[#F2C94C]"
                      }`}>{r.protocol}</span>
                    </Td>
                    <Td mono>{formatBytes(r.bytes_out + r.bytes_in)}</Td>
                    <Td>
                      {r.risk !== null ? (
                        <span className="font-mono font-semibold" style={{ color: severityColor(r.risk >= 80 ? "critical" : r.risk >= 60 ? "high" : "medium") }}>
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

        {/* Flow Detail */}
        <div>
          {selected ? (
            <ElevatedCard className="p-4 space-y-4">
              <div className="flex items-center justify-between">
                <div className="text-[13px] font-semibold text-[#F3F5F7]">Flow Detail</div>
                <button onClick={() => setSelected(null)} className="text-[#66707D] hover:text-[#9AA4B2] text-lg leading-none">×</button>
              </div>
              {[
                { label: "Flow ID", val: selected.id, mono: true },
                { label: "Timestamp", val: selected.timestamp, mono: true },
                { label: "Source", val: `${selected.src_ip}:${selected.src_port}`, mono: true },
                { label: "Destination", val: `${selected.dst_ip}:${selected.dst_port}`, mono: true },
                { label: "Protocol", val: selected.protocol, mono: true },
                { label: "Bytes Out", val: formatBytes(selected.bytes_out), mono: true },
                { label: "Bytes In", val: formatBytes(selected.bytes_in), mono: true },
                { label: "Packets Out", val: String(selected.pkts_out), mono: true },
                { label: "Packets In", val: String(selected.pkts_in), mono: true },
                { label: "TCP Flags", val: selected.tcp_flags, mono: true },
              ].map(({ label, val, mono }) => (
                <div key={label} className="flex justify-between items-center border-b border-[#1A2030] pb-2 last:border-0">
                  <span className="text-[11px] text-[#66707D] uppercase tracking-wide">{label}</span>
                  <span className={`text-[12px] text-[#F3F5F7] ${mono ? "font-mono" : ""}`}>{val}</span>
                </div>
              ))}
              {selected.risk !== null && (
                <div className="mt-2 p-3 rounded bg-[#EB5757]/5 border border-[#EB5757]/20">
                  <div className="text-[11px] text-[#EB5757] font-semibold uppercase">Risk Score</div>
                  <div className="text-[24px] font-bold font-mono text-[#EB5757]">{selected.risk}</div>
                </div>
              )}
              <div className="pt-2">
                <div className="text-[11px] text-[#66707D] uppercase tracking-wide mb-2">Context</div>
                <pre className="text-xs whitespace-pre-wrap break-all text-[#9AA4B2]">{JSON.stringify(FLOW_RECORDS.find(f => f.id === selected.id)?.context ?? {}, null, 2)}</pre>
              </div>
            </ElevatedCard>
          ) : (
            <Card className="p-6 flex flex-col items-center justify-center text-center h-full min-h-[200px]">
              <div className="text-3xl text-[#242B35] mb-2">⊞</div>
              <div className="text-[13px] text-[#9AA4B2]">Select a flow</div>
              <div className="text-[11px] text-[#66707D] mt-1">Click any row to inspect flow details</div>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}
