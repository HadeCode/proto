import { useArgus } from "@/data/api";
import React from "react";
import { Card, PageHeader, SectionHeader, TableWrapper, Th, Td } from "@/components/ui";
import { severityColor } from "@/data/mockData";

export default function TLSAnalysis() {
  const { TLS_SESSIONS, data, connected, updateAlert, mutate, busy } = useArgus();
  const repColor = (r: string) => {
    if (r === "Malicious") return "text-[#EB5757]";
    if (r === "Trusted") return "text-[#20D3A2]";
    if (r === "Internal") return "text-[#4C9AFF]";
    return "text-[#9AA4B2]";
  };

  return (
    <div className="p-6 max-w-[1440px] mx-auto space-y-5">
      <PageHeader
        title="Encrypted Session Analysis"
        breadcrumb="Analysis"
        subtitle="TLS and QUIC session metadata analysis — no payload decryption."
      />

      <div className="px-3 py-2 rounded bg-[#20D3A2]/5 border border-[#20D3A2]/20 text-[12px] text-[#20D3A2]">
        Metadata only — encrypted payloads are not inspected or decrypted. Analysis is based on observable session characteristics.
      </div>

      {/* KPIs */}
      <div className="grid grid-cols-5 gap-3">
        {[
          { label: "TLS Sessions", val: TLS_SESSIONS.filter(t => t.protocol === "TLS").length },
          { label: "QUIC Sessions", val: TLS_SESSIONS.filter(t => t.protocol === "QUIC").length },
          { label: "Malicious Fingerprints", val: (data.config.malicious_tls_fingerprints as string[] | undefined)?.length ?? 0, color: "#EB5757" },
          { label: "Unique JA4", val: new Set(TLS_SESSIONS.map(t => t.ja4).filter(t => t !== "-")).size, color: "#F2994A" },
          { label: "Suspicious Destinations", val: new Set(TLS_SESSIONS.filter(t => /suspicious|malicious|high_risk/i.test(t.reputation)).map(t => t.destination)).size, color: "#F2C94C" },
        ].map((k) => (
          <Card key={k.label} className="p-3 flex flex-col gap-1">
            <span className="text-[10px] text-[#66707D] uppercase tracking-widest">{k.label}</span>
            <span className="text-[22px] font-bold font-mono" style={{ color: k.color ?? "#F3F5F7" }}>{k.val}</span>
          </Card>
        ))}
      </div>

      {/* Session Table */}
      <Card>
        <div className="px-4 pt-4 pb-2">
          <SectionHeader title="TLS / QUIC Session Records" />
        </div>
        <TableWrapper>
          <thead>
            <tr>
              <Th>Source</Th>
              <Th>Destination</Th>
              <Th>Protocol</Th>
              <Th>JA3</Th>
              <Th>JA3S</Th>
              <Th>JA4</Th>
              <Th>SNI</Th>
              <Th>ALPN</Th>
              <Th>Reputation</Th>
              <Th>Risk</Th>
            </tr>
          </thead>
          <tbody>
            {TLS_SESSIONS.map((s, i) => (
              <tr key={i} className="hoverable">
                <Td mono>{s.source}</Td>
                <Td mono>{s.destination}</Td>
                <Td mono className="text-[#4C9AFF]">{s.protocol}</Td>
                <Td mono className="text-[#66707D] max-w-[80px] truncate" title={s.ja3}>{s.ja3.length > 10 ? `${s.ja3.slice(0, 10)}…` : s.ja3}</Td>
                <Td mono className="text-[#66707D] max-w-[80px] truncate" title={s.ja3s}>{s.ja3s.length > 10 ? `${s.ja3s.slice(0, 10)}…` : s.ja3s}</Td>
                <Td mono className="text-[#66707D] max-w-[100px] truncate" title={s.ja4}>{s.ja4.slice(0, 12)}…</Td>
                <Td mono className="text-[#F3F5F7]">{s.sni}</Td>
                <Td mono>{s.alpn}</Td>
                <Td><span className={`text-[12px] font-semibold ${repColor(s.reputation)}`}>{s.reputation}</span></Td>
                <Td>
                  {s.risk !== null ? (
                    <span className="font-mono font-bold" style={{ color: severityColor(s.risk >= 80 ? "critical" : s.risk >= 60 ? "high" : "medium") }}>
                      {s.risk}
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
