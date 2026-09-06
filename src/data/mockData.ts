export type Severity = "critical" | "high" | "medium" | "low";
export type AlertStatus = "OPEN" | "ACKNOWLEDGED" | "RESOLVED" | "FALSE_POSITIVE";

export interface Alert {
  alert_id: string;
  timestamp: string;
  threat_class: string;
  risk_score: number;
  severity: Severity;
  source: { ip: string };
  target: { ip: string };
  detector: string;
  window_seconds: number;
  status: AlertStatus;
  evidence: Evidence[];
}

export interface Evidence {
  feature: string;
  value: number | string | boolean;
  threshold: number | string | boolean;
  detail: string;
  label: string;
}

export interface FlowRecord {
  id: string;
  timestamp: string;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  protocol: string;
  bytes_out: number;
  bytes_in: number;
  pkts_out: number;
  pkts_in: number;
  tcp_flags: string;
  risk: number | null;
}

export const DETECTORS = [
  {
    id: "syn_flood",
    name: "SYN Flood",
    status: "ACTIVE",
    purpose: "Detects SYN packet floods targeting hosts, indicating volumetric TCP-based denial-of-service attacks.",
    thresholds: [{ key: "syn_flows_per_second", value: "20" }],
    observations: 18420,
    last_triggered: "2026-09-05T10:31:42Z",
    alerts_generated: 14,
    window: "60s",
  },
  {
    id: "udp_reflection",
    name: "UDP Reflection / Amplification",
    status: "ACTIVE",
    purpose: "Detects UDP amplification attacks where small requests generate large reflected responses.",
    thresholds: [{ key: "udp_flows_per_second", value: "30" }, { key: "amplification_ratio", value: "5×" }],
    observations: 9301,
    last_triggered: "2026-09-04T22:14:07Z",
    alerts_generated: 6,
    window: "60s",
  },
  {
    id: "spoofed_source_flood",
    name: "Spoofed-Source Flood",
    status: "ACTIVE",
    purpose: "Identifies high-volume flows with randomized source IPs indicative of spoofed-source flood attacks.",
    thresholds: [{ key: "unique_sources_per_second", value: "50" }],
    observations: 4102,
    last_triggered: "2026-09-04T18:33:51Z",
    alerts_generated: 3,
    window: "30s",
  },
  {
    id: "periodic_beacon",
    name: "Botnet C2 Beaconing",
    status: "ACTIVE",
    purpose: "Detects periodic low-and-slow beaconing behavior consistent with botnet command-and-control communication.",
    thresholds: [{ key: "c2_min_observations", value: "5" }, { key: "jitter_tolerance", value: "0.15" }],
    observations: 2871,
    last_triggered: "2026-09-05T09:55:22Z",
    alerts_generated: 9,
    window: "900s",
  },
  {
    id: "dns_lexical",
    name: "DGA Domain",
    status: "ACTIVE",
    purpose: "Uses lexical entropy analysis to identify algorithmically generated domain names used by malware.",
    thresholds: [{ key: "entropy_threshold", value: "3.8" }, { key: "min_domain_length", value: "12" }],
    observations: 34102,
    last_triggered: "2026-09-05T10:28:09Z",
    alerts_generated: 22,
    window: "N/A",
  },
  {
    id: "dns_tunnel",
    name: "DNS Tunnelling",
    status: "ACTIVE",
    purpose: "Detects data exfiltration and C2 via DNS by analyzing query volume, length, entropy, and TXT/NULL record usage.",
    thresholds: [{ key: "txt_null_ratio", value: "0.3" }, { key: "avg_query_length", value: "50" }],
    observations: 28440,
    last_triggered: "2026-09-05T10:30:51Z",
    alerts_generated: 17,
    window: "300s",
  },
  {
    id: "tls_quic_metadata",
    name: "Encrypted-Session Malware",
    status: "ACTIVE",
    purpose: "Analyzes TLS and QUIC session metadata — JA3/JA4 fingerprints, SNI, ALPN — to identify malicious encrypted sessions without decryption.",
    thresholds: [{ key: "malicious_fingerprint_match", value: "exact" }, { key: "rare_fingerprint_threshold", value: "0.01%" }],
    observations: 61203,
    last_triggered: "2026-09-05T08:41:37Z",
    alerts_generated: 11,
    window: "N/A",
  },
  {
    id: "fanout_scan",
    name: "Port Scanning",
    status: "ACTIVE",
    purpose: "Detects reconnaissance activity by identifying single sources contacting many destinations or ports in short time windows.",
    thresholds: [{ key: "scan_min_ports", value: "20" }, { key: "scan_min_hosts", value: "12" }],
    observations: 7382,
    last_triggered: "2026-09-05T10:18:44Z",
    alerts_generated: 8,
    window: "60s",
  },
  {
    id: "asymmetric_volume",
    name: "Data Exfiltration",
    status: "ACTIVE",
    purpose: "Detects large asymmetric outbound flows where outbound volume significantly exceeds inbound, indicating potential data theft.",
    thresholds: [{ key: "exfil_min_bytes", value: "10,000,000" }, { key: "exfil_min_ratio", value: "12×" }],
    observations: 5294,
    last_triggered: "2026-09-05T10:32:14Z",
    alerts_generated: 7,
    window: "300s",
  },
];

export const ALERTS: Alert[] = [
  {
    alert_id: "ALT-8F32A19BC123",
    timestamp: "2026-09-05T10:32:14Z",
    threat_class: "Data Exfiltration",
    risk_score: 0.96,
    severity: "critical",
    source: { ip: "10.0.0.90" },
    target: { ip: "9.9.9.9" },
    detector: "asymmetric_volume",
    window_seconds: 300,
    status: "OPEN",
    evidence: [
      { feature: "outbound_bytes", value: 14000000, threshold: 10000000, detail: "Large external outbound volume", label: "Outbound Bytes" },
      { feature: "outbound_inbound_ratio", value: 4666, threshold: 12, detail: "Outbound volume strongly exceeds replies", label: "Outbound / Inbound Ratio" },
      { feature: "baseline_robust_z_score", value: 4.7, threshold: 3.0, detail: "Optional benign baseline deviation", label: "Baseline Robust Z-Score" },
      { feature: "total_bytes", value: 14003000, threshold: 10000000, detail: "Five-minute flow volume", label: "Total Bytes" },
    ],
  },
  {
    alert_id: "ALT-3C91D44FE882",
    timestamp: "2026-09-05T10:31:42Z",
    threat_class: "SYN Flood",
    risk_score: 0.87,
    severity: "high",
    source: { ip: "Multiple" },
    target: { ip: "10.0.0.20" },
    detector: "syn_flood",
    window_seconds: 60,
    status: "OPEN",
    evidence: [
      { feature: "syn_flows_per_second", value: 340, threshold: 20, detail: "SYN rate far exceeds threshold", label: "SYN Flows/Second" },
      { feature: "unique_sources", value: 218, threshold: 5, detail: "High unique source count indicates distributed flood", label: "Unique Sources" },
    ],
  },
  {
    alert_id: "ALT-7A55B2C09E41",
    timestamp: "2026-09-05T10:30:51Z",
    threat_class: "DNS Tunnelling",
    risk_score: 0.82,
    severity: "high",
    source: { ip: "10.0.0.80" },
    target: { ip: "1.1.1.1" },
    detector: "dns_tunnel",
    window_seconds: 300,
    status: "OPEN",
    evidence: [
      { feature: "txt_null_query_ratio", value: 0.68, threshold: 0.3, detail: "High ratio of TXT/NULL queries", label: "TXT/NULL Query Ratio" },
      { feature: "avg_query_length", value: 74, threshold: 50, detail: "Average query length exceeds normal DNS", label: "Avg Query Length" },
      { feature: "unique_subdomains", value: 412, threshold: 50, detail: "Large number of unique subdomains in short window", label: "Unique Subdomains" },
    ],
  },
  {
    alert_id: "ALT-1E84F76DA990",
    timestamp: "2026-09-05T10:28:09Z",
    threat_class: "DGA Domain",
    risk_score: 0.79,
    severity: "high",
    source: { ip: "10.0.0.55" },
    target: { ip: "185.220.101.47" },
    detector: "dns_lexical",
    window_seconds: 0,
    status: "OPEN",
    evidence: [
      { feature: "domain_entropy", value: 4.2, threshold: 3.8, detail: "Domain entropy above DGA threshold", label: "Domain Entropy" },
      { feature: "domain_length", value: 22, threshold: 12, detail: "Long algorithmically structured hostname", label: "Domain Length" },
    ],
  },
  {
    alert_id: "ALT-5D23E91CA774",
    timestamp: "2026-09-05T10:18:44Z",
    threat_class: "Port Scanning",
    risk_score: 0.65,
    severity: "medium",
    source: { ip: "10.0.0.50" },
    target: { ip: "Multiple" },
    detector: "fanout_scan",
    window_seconds: 60,
    status: "ACKNOWLEDGED",
    evidence: [
      { feature: "unique_ports_contacted", value: 47, threshold: 20, detail: "Single source contacted many distinct ports", label: "Unique Ports" },
      { feature: "unique_hosts_contacted", value: 23, threshold: 12, detail: "Wide host sweep detected", label: "Unique Hosts" },
    ],
  },
  {
    alert_id: "ALT-9B47C3DAE110",
    timestamp: "2026-09-05T09:55:22Z",
    threat_class: "Botnet C2 Beaconing",
    risk_score: 0.58,
    severity: "medium",
    source: { ip: "10.0.0.115" },
    target: { ip: "91.108.4.1" },
    detector: "periodic_beacon",
    window_seconds: 900,
    status: "OPEN",
    evidence: [
      { feature: "beacon_interval_seconds", value: 300, threshold: 300, detail: "Highly regular 5-minute interval", label: "Beacon Interval" },
      { feature: "jitter_coefficient", value: 0.02, threshold: 0.15, detail: "Very low jitter — consistent automated traffic", label: "Jitter Coefficient" },
      { feature: "observation_count", value: 9, threshold: 5, detail: "Sufficient observations to confirm pattern", label: "Observations" },
    ],
  },
  {
    alert_id: "ALT-2F60A87CB551",
    timestamp: "2026-09-05T08:41:37Z",
    threat_class: "Encrypted-Session Malware",
    risk_score: 0.44,
    severity: "low",
    source: { ip: "10.0.0.72" },
    target: { ip: "104.21.14.205" },
    detector: "tls_quic_metadata",
    window_seconds: 0,
    status: "RESOLVED",
    evidence: [
      { feature: "ja3_fingerprint_match", value: 1, threshold: 1, detail: "JA3 fingerprint matched known malware", label: "JA3 Match" },
      { feature: "rare_fingerprint_score", value: 0.003, threshold: 0.01, detail: "Fingerprint appears in < 0.01% of sessions", label: "Fingerprint Rarity" },
    ],
  },
];

export const FLOW_RECORDS: FlowRecord[] = [
  { id: "f001", timestamp: "10:32:14", src_ip: "10.10.1.25", src_port: 51000, dst_ip: "172.16.1.20", dst_port: 443, protocol: "TCP", bytes_out: 60, bytes_in: 0, pkts_out: 1, pkts_in: 0, tcp_flags: "S", risk: null },
  { id: "f002", timestamp: "10:32:13", src_ip: "10.0.0.90", src_port: 49821, dst_ip: "9.9.9.9", dst_port: 443, protocol: "TCP", bytes_out: 2800000, bytes_in: 600, pkts_out: 1940, pkts_in: 5, tcp_flags: "PA", risk: 96 },
  { id: "f003", timestamp: "10:32:12", src_ip: "10.10.2.14", src_port: 52311, dst_ip: "8.8.8.8", dst_port: 53, protocol: "UDP", bytes_out: 82, bytes_in: 128, pkts_out: 1, pkts_in: 1, tcp_flags: "-", risk: null },
  { id: "f004", timestamp: "10:32:11", src_ip: "10.0.0.55", src_port: 44210, dst_ip: "185.220.101.47", dst_port: 80, protocol: "TCP", bytes_out: 240, bytes_in: 0, pkts_out: 3, pkts_in: 0, tcp_flags: "S", risk: 79 },
  { id: "f005", timestamp: "10:32:10", src_ip: "10.0.0.80", src_port: 53001, dst_ip: "1.1.1.1", dst_port: 53, protocol: "UDP", bytes_out: 320, bytes_in: 40, pkts_out: 4, pkts_in: 1, tcp_flags: "-", risk: 82 },
  { id: "f006", timestamp: "10:32:09", src_ip: "192.168.1.5", src_port: 60000, dst_ip: "172.16.5.10", dst_port: 22, protocol: "TCP", bytes_out: 1440, bytes_in: 2800, pkts_out: 12, pkts_in: 18, tcp_flags: "PA", risk: null },
  { id: "f007", timestamp: "10:32:08", src_ip: "10.0.0.50", src_port: 34551, dst_ip: "192.168.100.1", dst_port: 8080, protocol: "TCP", bytes_out: 60, bytes_in: 0, pkts_out: 1, pkts_in: 0, tcp_flags: "S", risk: null },
  { id: "f008", timestamp: "10:32:07", src_ip: "10.10.1.88", src_port: 49910, dst_ip: "140.82.112.3", dst_port: 443, protocol: "TCP", bytes_out: 3200, bytes_in: 44100, pkts_out: 18, pkts_in: 32, tcp_flags: "PA", risk: null },
  { id: "f009", timestamp: "10:32:06", src_ip: "10.0.0.115", src_port: 43100, dst_ip: "91.108.4.1", dst_port: 443, protocol: "TCP", bytes_out: 220, bytes_in: 180, pkts_out: 3, pkts_in: 3, tcp_flags: "PA", risk: 58 },
  { id: "f010", timestamp: "10:32:05", src_ip: "10.10.3.21", src_port: 55100, dst_ip: "172.217.14.196", dst_port: 443, protocol: "TCP", bytes_out: 18200, bytes_in: 124000, pkts_out: 22, pkts_in: 90, tcp_flags: "PA", risk: null },
];

export const THREAT_TIMESERIES = Array.from({ length: 24 }, (_, i) => ({
  time: `${String(i).padStart(2, "0")}:00`,
  critical: Math.floor(Math.random() * 4),
  high: Math.floor(Math.random() * 8),
  medium: Math.floor(Math.random() * 12),
  low: Math.floor(Math.random() * 6),
}));

export const THREAT_DISTRIBUTION = [
  { name: "Data Exfiltration", value: 7, color: "#EB5757" },
  { name: "SYN Flood", value: 14, color: "#F2994A" },
  { name: "DNS Tunnelling", value: 17, color: "#F2994A" },
  { name: "DGA Domain", value: 22, color: "#F2C94C" },
  { name: "C2 Beaconing", value: 9, color: "#F2C94C" },
  { name: "Port Scanning", value: 8, color: "#4C9AFF" },
  { name: "Encrypted Malware", value: 11, color: "#4C9AFF" },
  { name: "UDP Reflection", value: 6, color: "#9AA4B2" },
  { name: "Spoofed-Source Flood", value: 3, color: "#66707D" },
];

export const DNS_RECORDS = [
  { domain: "m3k4j8n2q7v6x9z5.example.net", source: "10.0.0.55", qtype: "A", entropy: 4.2, length: 30, detection: "DGA Domain", risk: 79 },
  { domain: "xn8p2q7.tunnel-c2.io", source: "10.0.0.80", qtype: "TXT", entropy: 3.9, length: 22, detection: "DNS Tunnelling", risk: 82 },
  { domain: "analytics.cloudfront-cdn.net", source: "10.10.1.25", qtype: "A", entropy: 2.1, length: 28, detection: "-", risk: null },
  { domain: "k9mzxw4fjq2bv8nh.dga.biz", source: "10.0.0.55", qtype: "A", entropy: 4.5, length: 26, detection: "DGA Domain", risk: 85 },
  { domain: "api.github.com", source: "10.10.1.88", qtype: "A", entropy: 1.8, length: 14, detection: "-", risk: null },
  { domain: "aGVsbG8gd29ybGQK.tunnel.xyz", source: "10.0.0.80", qtype: "NULL", entropy: 4.1, length: 28, detection: "DNS Tunnelling", risk: 78 },
];

export const TLS_SESSIONS = [
  { source: "10.0.0.72", destination: "104.21.14.205", protocol: "TLS 1.3", ja3: "a0e9f5d64349fb13191bc781f81f42e1", ja3s: "b46ab1fe2f5f62e34d17e3f24de3bef5", ja4: "t13d1516h2_8daaf6152771_b0da82dd1658", sni: "updates.cdn-sys.io", alpn: "h2", reputation: "Malicious", risk: 44 },
  { source: "10.10.1.25", destination: "172.16.1.20", protocol: "TLS 1.3", ja3: "51c64c77e60f3980eea90869b68c58a8", ja3s: "ec74a5c51106f0419184d0dd08fb05bc", ja4: "t13d1516h2_8daaf6152771_e5627efa2ab1", sni: "internal.corp.local", alpn: "h2", reputation: "Internal", risk: null },
  { source: "10.10.1.88", destination: "140.82.112.3", protocol: "TLS 1.3", ja3: "771,49196-49200-159-52393", ja3s: "b31a14f56d462580ca0d19e8e7b35840", ja4: "t13d1516h2_8daaf6152771_f7b12d9f2331", sni: "github.com", alpn: "h2", reputation: "Trusted", risk: null },
  { source: "10.0.0.115", destination: "91.108.4.1", protocol: "QUIC", ja3: "-", ja3s: "-", ja4: "q1d1516h2_c4f7a2b9e011_34da92f17abc", sni: "telegram.org", alpn: "h3", reputation: "Neutral", risk: 58 },
];

export const formatBytes = (bytes: number): string => {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
};

export const severityColor = (s: Severity | string): string => {
  switch (s.toLowerCase()) {
    case "critical": return "#EB5757";
    case "high": return "#F2994A";
    case "medium": return "#F2C94C";
    case "low": return "#4C9AFF";
    default: return "#9AA4B2";
  }
};

export const severityClass = (s: Severity | string): string => {
  switch (s.toLowerCase()) {
    case "critical": return "bg-severity-critical";
    case "high": return "bg-severity-high";
    case "medium": return "bg-severity-medium";
    case "low": return "bg-severity-low";
    default: return "bg-severity-success";
  }
};
