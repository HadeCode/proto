import { useArgus } from "@/data/api";
import React, { useState, useEffect, useRef } from "react";
import { Card, PageHeader, FilterBar, Select, Input, TableWrapper, Th, Td, LiveDot, Button } from "@/components/ui";
import { formatBytes, severityColor } from "@/data/mockData";
import type { FlowRecord } from "@/data/mockData";

export default function LiveTraffic() {
  const { FLOW_RECORDS, data, connected, updateAlert, mutate, busy } = useArgus();
  const [paused, setPaused] = useState(false);
  const [refresh, setRefresh] = useState("5s");
  const [srcFilter, setSrcFilter] = useState("");
  const [dstFilter, setDstFilter] = useState("");
  const [protoFilter, setProtoFilter] = useState("All");
  const [rows, setRows] = useState<FlowRecord[]>(FLOW_RECORDS);
  const latest = useRef(FLOW_RECORDS);
  latest.current = FLOW_RECORDS;

  useEffect(() => {
    if (paused) return;
    const ms = refresh === "5s" ? 5000 : refresh === "10s" ? 10000 : 30000;
    setRows(latest.current);
    const id = setInterval(() => setRows(latest.current), ms);
    return () => clearInterval(id);
  }, [paused, refresh]);

  const filtered = rows.filter((r) => {
    if (srcFilter && !r.src_ip.includes(srcFilter)) return false;
    if (dstFilter && !r.dst_ip.includes(dstFilter)) return false;
    if (protoFilter !== "All" && r.protocol !== protoFilter) return false;
    return true;
  });

  const flagColor = (flags: string) => {
    if (flags.includes("S")) return "text-[#F2C94C]";
    if (flags.includes("R")) return "text-[#EB5757]";
    return "text-[#9AA4B2]";
  };

  return (
    <div className="p-6 max-w-[1440px] mx-auto space-y-4">
      <PageHeader
        title="Live Traffic"
        breadcrumb="Monitor"
        subtitle="Passive normalized flow telemetry"
        actions={
          <div className="flex items-center gap-2">
            <div className="flex items-center gap-1.5">
              <LiveDot />
              <span className="text-[11px] text-[#20D3A2] font-semibold uppercase">
                {paused ? "PAUSED" : connected ? "CONNECTED" : "OFFLINE"}
              </span>
            </div>
            <Button variant="default" size="sm" onClick={() => setPaused((p) => !p)}>
              {paused ? "▶ Resume" : "⏸ Pause"}
            </Button>
            <Select value={refresh} onChange={setRefresh} className="text-[11px]">
              <option value="5s">5s</option>
              <option value="10s">10s</option>
              <option value="30s">30s</option>
            </Select>
          </div>
        }
      />

      {/* Stats row */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: "Flows / sec", value: String(data.summary.flows_per_second) },
          { label: "Bytes / sec", value: formatBytes(data.summary.bytes_per_second) },
          { label: "Displayed flows", value: String(rows.length) },
          { label: "Flagged Flows", value: String(rows.filter(r => r.risk !== null).length), accent: "#EB5757" },
        ].map((s) => (
          <Card key={s.label} className="px-4 py-3 flex justify-between items-center">
            <span className="text-[11px] text-[#66707D] uppercase tracking-wide">{s.label}</span>
            <span
              className="text-[16px] font-bold font-mono"
              style={{ color: s.accent ?? "#F3F5F7" }}
            >
              {s.value}
            </span>
          </Card>
        ))}
      </div>

      {/* Filters */}
      <FilterBar>
        <Input value={srcFilter} onChange={setSrcFilter} placeholder="Source IP..." className="w-40" />
        <Input value={dstFilter} onChange={setDstFilter} placeholder="Destination IP..." className="w-40" />
        <Select value={protoFilter} onChange={setProtoFilter}>
          <option value="All">All Protocols</option>
          <option value="TCP">TCP</option>
          <option value="UDP">UDP</option>
          <option value="QUIC">QUIC</option>
          <option value="ICMP">ICMP</option>
        </Select>
        <Button variant="ghost" size="sm" onClick={() => { setSrcFilter(""); setDstFilter(""); setProtoFilter("All"); }}>
          Clear
        </Button>
        <span className="ml-auto text-[11px] text-[#66707D]">
          Showing {filtered.length} flows
        </span>
      </FilterBar>

      {/* Flow table */}
      <Card>
        <TableWrapper>
          <thead>
            <tr>
              <Th>Timestamp</Th>
              <Th>Source IP</Th>
              <Th>Src Port</Th>
              <Th>Destination IP</Th>
              <Th>Dst Port</Th>
              <Th>Proto</Th>
              <Th>Bytes Out</Th>
              <Th>Bytes In</Th>
              <Th>Pkts Out</Th>
              <Th>Pkts In</Th>
              <Th>Flags</Th>
              <Th>Risk</Th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((r) => (
              <tr key={r.id} className="hoverable">
                <Td mono>{r.timestamp}</Td>
                <Td mono className="text-[#F3F5F7]">{r.src_ip}</Td>
                <Td mono>{r.src_port}</Td>
                <Td mono className="text-[#F3F5F7]">{r.dst_ip}</Td>
                <Td mono>{r.dst_port}</Td>
                <Td>
                  <span className={`text-[11px] font-semibold font-mono ${
                    r.protocol === "TCP" ? "text-[#4C9AFF]" : r.protocol === "UDP" ? "text-[#F2C94C]" : "text-[#20D3A2]"
                  }`}>{r.protocol}</span>
                </Td>
                <Td mono>{formatBytes(r.bytes_out)}</Td>
                <Td mono>{formatBytes(r.bytes_in)}</Td>
                <Td mono>{r.pkts_out}</Td>
                <Td mono>{r.pkts_in}</Td>
                <Td mono className={flagColor(r.tcp_flags)}>{r.tcp_flags}</Td>
                <Td>
                  {r.risk !== null ? (
                    <span className="font-mono font-semibold text-[12px]" style={{ color: severityColor(r.risk >= 80 ? "critical" : r.risk >= 60 ? "high" : r.risk >= 40 ? "medium" : "low") }}>
                      {r.risk}
                    </span>
                  ) : (
                    <span className="text-[#3A4456]">—</span>
                  )}
                </Td>
              </tr>
            ))}
          </tbody>
        </TableWrapper>
      </Card>

      <div className="text-[10px] text-[#66707D] text-center uppercase tracking-widest">
        Passive Metadata Analysis · No Payload Inspection · Detection Based on Flow Records
      </div>
    </div>
  );
}
