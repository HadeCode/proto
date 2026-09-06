import React from "react";
import { severityClass } from "@/data/mockData";
import type { Severity } from "@/data/mockData";

export function SeverityBadge({ severity }: { severity: Severity | string }) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold font-mono tracking-wide uppercase ${severityClass(severity)}`}>
      {severity.toUpperCase()}
    </span>
  );
}

export function StatusBadge({ status }: { status: string }) {
  const styles: Record<string, string> = {
    OPEN: "bg-severity-critical",
    ACKNOWLEDGED: "bg-severity-medium",
    RESOLVED: "bg-severity-success",
    ACTIVE: "bg-severity-success",
    ONLINE: "bg-severity-success",
    HEALTHY: "bg-severity-success",
    OFFLINE: "bg-severity-critical",
    CONNECTED: "bg-severity-success",
  };
  const cls = styles[status.toUpperCase()] ?? "bg-severity-low";
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold uppercase tracking-wide ${cls}`}>
      {status}
    </span>
  );
}

export function Card({ children, className = "", onClick }: { children: React.ReactNode; className?: string; onClick?: () => void }) {
  return (
    <div className={`rounded-lg border border-[#242B35] bg-[#11161D] ${className}`} onClick={onClick}>
      {children}
    </div>
  );
}

export function ElevatedCard({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={`rounded-lg border border-[#242B35] bg-[#151B23] ${className}`}>
      {children}
    </div>
  );
}

export function MetricCard({
  title,
  value,
  sub,
  accent,
  onClick,
}: {
  title: string;
  value: React.ReactNode;
  sub?: React.ReactNode;
  accent?: string;
  onClick?: () => void;
}) {
  return (
    <Card
      className={`p-4 flex flex-col gap-2 ${onClick ? "cursor-pointer hover:border-[#20D3A2]/30 transition-colors" : ""}`}
    >
      <div
        className="text-[11px] font-semibold uppercase tracking-widest text-[#66707D]"
        onClick={onClick}
      >
        {title}
      </div>
      <div
        className={`text-3xl font-bold leading-none ${accent ? "" : "text-[#F3F5F7]"}`}
        style={accent ? { color: accent } : undefined}
        onClick={onClick}
      >
        {value}
      </div>
      {sub && <div className="text-[12px] text-[#9AA4B2]">{sub}</div>}
    </Card>
  );
}

export function LiveDot({ className = "" }: { className?: string }) {
  return (
    <span
      className={`inline-block w-2 h-2 rounded-full bg-[#20D3A2] animate-pulse-dot ${className}`}
    />
  );
}

export function SectionHeader({
  title,
  subtitle,
  actions,
}: {
  title: string;
  subtitle?: string;
  actions?: React.ReactNode;
}) {
  return (
    <div className="flex items-start justify-between mb-5">
      <div>
        <h2 className="text-[18px] font-semibold text-[#F3F5F7]">{title}</h2>
        {subtitle && <p className="text-[12px] text-[#9AA4B2] mt-0.5">{subtitle}</p>}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}

export function TableWrapper({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={`overflow-x-auto ${className}`}>
      <table className="w-full text-[13px] border-collapse">{children}</table>
    </div>
  );
}

export function Th({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return (
    <th className={`text-left text-[11px] font-semibold uppercase tracking-widest text-[#66707D] px-3 py-2.5 border-b border-[#242B35] bg-[#0D1117] whitespace-nowrap ${className}`}>
      {children}
    </th>
  );
}

export function Td({ children, className = "", mono = false, title, onClick }: { children: React.ReactNode; className?: string; mono?: boolean; title?: string; onClick?: () => void }) {
  return (
    <td title={title} onClick={onClick} className={`px-3 py-2.5 border-b border-[#1A2030] text-[#9AA4B2] ${mono ? "font-mono text-[12px]" : ""} ${className}`}>
      {children}
    </td>
  );
}

export function FilterBar({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex flex-wrap gap-2 items-center mb-4">{children}</div>
  );
}

export function Select({ value, onChange, children, className = "" }: {
  value: string;
  onChange: (v: string) => void;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className={`bg-[#11161D] border border-[#242B35] text-[#9AA4B2] text-[12px] rounded px-3 py-1.5 focus:outline-none focus:border-[#20D3A2]/50 ${className}`}
    >
      {children}
    </select>
  );
}

export function Input({ value, onChange, placeholder, className = "" }: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  className?: string;
}) {
  return (
    <input
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      className={`bg-[#11161D] border border-[#242B35] text-[#F3F5F7] text-[13px] rounded px-3 py-1.5 placeholder:text-[#66707D] focus:outline-none focus:border-[#20D3A2]/50 ${className}`}
    />
  );
}

export function Button({ children, onClick, variant = "default", size = "md", className = "" }: {
  children: React.ReactNode;
  onClick?: () => void;
  variant?: "default" | "accent" | "ghost" | "danger";
  size?: "sm" | "md";
  className?: string;
}) {
  const base = "inline-flex items-center gap-1.5 rounded font-medium transition-colors cursor-pointer border focus:outline-none";
  const sizes = { sm: "px-2.5 py-1 text-[11px]", md: "px-3.5 py-1.5 text-[13px]" };
  const variants = {
    default: "bg-[#151B23] border-[#242B35] text-[#9AA4B2] hover:text-[#F3F5F7] hover:border-[#3A4456]",
    accent: "bg-[#20D3A2]/10 border-[#20D3A2]/30 text-[#20D3A2] hover:bg-[#20D3A2]/20",
    ghost: "bg-transparent border-transparent text-[#9AA4B2] hover:text-[#F3F5F7]",
    danger: "bg-[#EB5757]/10 border-[#EB5757]/30 text-[#EB5757] hover:bg-[#EB5757]/20",
  };
  return (
    <button onClick={onClick} className={`${base} ${sizes[size]} ${variants[variant]} ${className}`}>
      {children}
    </button>
  );
}

export function Tabs({ tabs, active, onChange }: {
  tabs: string[];
  active: string;
  onChange: (t: string) => void;
}) {
  return (
    <div className="flex border-b border-[#242B35] mb-4">
      {tabs.map((t) => (
        <button
          key={t}
          onClick={() => onChange(t)}
          className={`px-4 py-2 text-[13px] font-medium border-b-2 -mb-px transition-colors ${
            active === t
              ? "border-[#20D3A2] text-[#20D3A2]"
              : "border-transparent text-[#66707D] hover:text-[#9AA4B2]"
          }`}
        >
          {t}
        </button>
      ))}
    </div>
  );
}

export function EmptyState({ icon, title, subtitle }: { icon?: React.ReactNode; title: string; subtitle?: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center">
      {icon && <div className="text-[#242B35] mb-3 text-4xl">{icon}</div>}
      <div className="text-[#9AA4B2] font-medium mb-1">{title}</div>
      {subtitle && <div className="text-[#66707D] text-[12px] max-w-sm">{subtitle}</div>}
    </div>
  );
}

export function PageHeader({ title, subtitle, breadcrumb, actions }: {
  title: string;
  subtitle?: string;
  breadcrumb?: string;
  actions?: React.ReactNode;
}) {
  return (
    <div className="flex items-start justify-between mb-6">
      <div>
        {breadcrumb && (
          <div className="text-[11px] text-[#66707D] uppercase tracking-widest mb-1">{breadcrumb}</div>
        )}
        <h1 className="text-[24px] font-bold text-[#F3F5F7] tracking-tight">{title}</h1>
        {subtitle && <p className="text-[13px] text-[#9AA4B2] mt-1">{subtitle}</p>}
      </div>
      {actions && <div className="flex items-center gap-2 mt-1">{actions}</div>}
    </div>
  );
}

export function RiskScore({ score }: { score: number }) {
  const pct = Math.round(score * 100);
  const color = pct >= 80 ? "#EB5757" : pct >= 60 ? "#F2994A" : pct >= 40 ? "#F2C94C" : "#4C9AFF";
  const r = 40;
  const circ = 2 * Math.PI * r;
  const offset = circ - (pct / 100) * circ;
  return (
    <div className="relative inline-flex items-center justify-center w-24 h-24">
      <svg className="absolute inset-0 -rotate-90" viewBox="0 0 100 100">
        <circle cx="50" cy="50" r={r} fill="none" stroke="#1A2030" strokeWidth="8" />
        <circle
          cx="50" cy="50" r={r} fill="none"
          stroke={color} strokeWidth="8"
          strokeDasharray={circ} strokeDashoffset={offset}
          strokeLinecap="round"
        />
      </svg>
      <div className="text-center">
        <div className="text-xl font-bold" style={{ color }}>{pct}</div>
        <div className="text-[10px] text-[#66707D]">RISK</div>
      </div>
    </div>
  );
}

export function EvidenceBar({ value, threshold, max }: { value: number; threshold: number; max?: number }) {
  const m = max ?? Math.max(value * 1.2, threshold * 1.5);
  const valPct = Math.min((value / m) * 100, 100);
  const thrPct = Math.min((threshold / m) * 100, 100);
  const exceeded = value > threshold;
  return (
    <div className="mt-2">
      <div className="relative h-2 bg-[#1A2030] rounded-full overflow-visible">
        <div
          className="absolute left-0 top-0 h-2 rounded-full transition-all"
          style={{
            width: `${valPct}%`,
            backgroundColor: exceeded ? "#EB5757" : "#20D3A2",
          }}
        />
        <div
          className="absolute top-[-4px] w-[2px] h-[16px] bg-[#F2C94C] rounded"
          style={{ left: `${thrPct}%` }}
          title={`Threshold: ${threshold}`}
        />
      </div>
      <div className="flex justify-between text-[10px] text-[#66707D] mt-1">
        <span className="font-mono">{value.toLocaleString()}</span>
        <span className="font-mono">threshold: {threshold.toLocaleString()}</span>
      </div>
    </div>
  );
}
