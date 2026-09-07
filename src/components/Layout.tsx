import { useArgus } from "@/data/api";
import React, { useState, useRef, useEffect } from "react";
import { NavLink, useLocation, useNavigate } from "react-router-dom";
import { LiveDot } from "./ui";


const NAV = [
  {
    group: "OVERVIEW",
    items: [
      { label: "Dashboard", path: "/dashboard", icon: "⬡" },
      { label: "Network Health", path: "/health-report", icon: "✚" },
    ],
  },
  {
    group: "MONITOR",
    items: [
      { label: "Live Traffic", path: "/live-traffic", icon: "◈" },
      { label: "Flow Explorer", path: "/flow-explorer", icon: "⊞" },
    ],
  },
  {
    group: "DETECTION",
    items: [
      { label: "Threats", path: "/threats", icon: "⚠" },
      { label: "Alerts", path: "/alerts", icon: "◉" },
      { label: "Detection Engines", path: "/engines", icon: "⊕" },
      { label: "Machine Learning", path: "/ml-models", icon: "⚡" },
    ],
  },
  {
    group: "ANALYSIS",
    items: [
      { label: "Threat Analytics", path: "/analytics", icon: "▦" },
      { label: "Baselines", path: "/baseline", icon: "≈" },
      { label: "DNS Analysis", path: "/dns-analysis", icon: "⊃" },
      { label: "TLS / QUIC", path: "/tls-analysis", icon: "⊕" },
      { label: "Threat Intel", path: "/threat-intel", icon: "◈" },
    ],
  },
  {
    group: "SYSTEM",
    items: [
      { label: "Agent Status", path: "/agent-status", icon: "◎" },
      { label: "Configuration", path: "/configuration", icon: "⊙" },
      { label: "Data Sources", path: "/data-sources", icon: "○" },
    ],
  },
];


export default function Layout({ children }: { children: React.ReactNode }) {
  const { ALERTS, data, connected, error, updateAlert, mutate, busy } = useArgus();
  const [collapsed, setCollapsed] = useState(false);
  const [notifOpen, setNotifOpen] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchQ, setSearchQ] = useState("");
  const location = useLocation();
  const navigate = useNavigate();
  const searchRef = useRef<HTMLDivElement>(null);

  const breadcrumb = (() => {
    const p = location.pathname;
    if (p.startsWith("/dashboard")) return "ARGUS-ONE / Overview / Dashboard";
    if (p.startsWith("/health-report") || p.startsWith("/health") || p.startsWith("/network-health")) return "ARGUS-ONE / Overview / Behavioral Network Health";
    if (p.startsWith("/live-traffic")) return "ARGUS-ONE / Monitor / Live Traffic";
    if (p.startsWith("/flow-explorer")) return "ARGUS-ONE / Monitor / Flow Explorer";
    if (p.startsWith("/threats")) return "ARGUS-ONE / Detection / Threats";
    if (p.startsWith("/alerts")) return "ARGUS-ONE / Detection / Alerts";
    if (p.startsWith("/engines")) return "ARGUS-ONE / Detection / Detection Engines";
    if (p.startsWith("/ml-models") || p.startsWith("/machine-learning")) return "ARGUS-ONE / Detection / Machine Learning";
    if (p.startsWith("/analytics")) return "ARGUS-ONE / Analysis / Threat Analytics";
    if (p.startsWith("/baseline")) return "ARGUS-ONE / Analysis / Baselines";
    if (p.startsWith("/agent-status")) return "ARGUS-ONE / System / Agent Status";
    if (p.startsWith("/configuration")) return "ARGUS-ONE / System / Configuration";
    if (p.startsWith("/data-sources")) return "ARGUS-ONE / System / Data Sources";
    if (p.startsWith("/dns-analysis")) return "ARGUS-ONE / Analysis / DNS Analysis";
    if (p.startsWith("/tls-analysis")) return "ARGUS-ONE / Analysis / TLS / QUIC Analysis";
    if (p.startsWith("/threat-intel")) return "ARGUS-ONE / Analysis / Threat Intelligence";
    return "ARGUS-ONE";
  })();

  const SEARCH_ITEMS = [
    ...ALERTS.map(a => ({ type: "Alert", label: a.alert_id + " — " + a.threat_class, path: "/alerts/" + a.alert_id })),
    ...data.detectors.map(d => ({ type: "Detector", label: d.name, path: "/engines/" + d.id })),
    ...[...new Set(data.flows.map(f => f.src_ip))].map(ip => ({ type: "Source IP", label: ip, path: "/flow-explorer?src=" + ip })),
  ];
  const searchResults = searchQ.length > 1
    ? SEARCH_ITEMS.filter((s) => s.label.toLowerCase().includes(searchQ.toLowerCase()))
    : [];

  useEffect(() => {
    function handler(e: MouseEvent) {
      if (searchRef.current && !searchRef.current.contains(e.target as Node)) {
        setSearchOpen(false);
        setSearchQ("");
      }
    }
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  return (
    <div className="flex h-full bg-[#080B10] overflow-hidden">
      {/* Sidebar */}
      <aside
        className={`flex flex-col bg-[#0D1117] border-r border-[#242B35] transition-all duration-200 flex-shrink-0 ${collapsed ? "w-14" : "w-52"}`}
      >
        {/* Logo */}
        <div className="flex items-center gap-2.5 px-3 py-4 border-b border-[#242B35]">
          <div className="w-8 h-8 flex-shrink-0 flex items-center justify-center rounded bg-[#20D3A2]/10 border border-[#20D3A2]/30">
            <svg viewBox="0 0 24 24" fill="none" className="w-4 h-4">
              <circle cx="12" cy="12" r="9" stroke="#20D3A2" strokeWidth="1.5" />
              <circle cx="12" cy="12" r="4" stroke="#20D3A2" strokeWidth="1.5" />
              <circle cx="12" cy="12" r="1.5" fill="#20D3A2" />
              <line x1="12" y1="3" x2="12" y2="7" stroke="#20D3A2" strokeWidth="1.5" />
              <line x1="12" y1="17" x2="12" y2="21" stroke="#20D3A2" strokeWidth="1.5" />
              <line x1="3" y1="12" x2="7" y2="12" stroke="#20D3A2" strokeWidth="1.5" />
              <line x1="17" y1="12" x2="21" y2="12" stroke="#20D3A2" strokeWidth="1.5" />
            </svg>
          </div>
          {!collapsed && (
            <div>
              <div className="text-[13px] font-bold text-[#F3F5F7] tracking-wider">ARGUS-ONE</div>
              <div className="text-[9px] text-[#66707D] tracking-widest uppercase">Threat Detection</div>
            </div>
          )}
          <button
            onClick={() => setCollapsed((c) => !c)}
            className="ml-auto text-[#66707D] hover:text-[#9AA4B2] flex-shrink-0"
          >
            {collapsed ? "›" : "‹"}
          </button>
        </div>

        {/* Nav */}
        <nav className="flex-1 overflow-y-auto py-3 space-y-4">
          {NAV.map((group) => (
            <div key={group.group}>
              {!collapsed && (
                <div className="px-3 mb-1 text-[10px] font-semibold uppercase tracking-widest text-[#66707D]">
                  {group.group}
                </div>
              )}
              {group.items.map((item) => (
                <NavLink
                  key={item.path + item.label}
                  to={item.path}
                  className={({ isActive }) =>
                    `flex items-center gap-2.5 px-3 py-2 text-[13px] transition-colors rounded mx-1 ${
                      isActive
                        ? "bg-[#20D3A2]/10 text-[#20D3A2] border-l-2 border-[#20D3A2] pl-[10px]"
                        : "text-[#9AA4B2] hover:text-[#F3F5F7] hover:bg-[#151B23]"
                    }`
                  }
                  title={collapsed ? item.label : undefined}
                >
                  <span className="flex-shrink-0 text-[14px]">{item.icon}</span>
                  {!collapsed && <span>{item.label}</span>}
                </NavLink>
              ))}
            </div>
          ))}
        </nav>

        {/* Bottom */}
        <div className="border-t border-[#242B35] p-3 space-y-2">
          <div className={`flex items-center gap-2 ${collapsed ? "justify-center" : ""}`}>
            <LiveDot />
            {!collapsed && <span className="text-[10px] text-[#20D3A2] font-semibold uppercase tracking-wider">{connected ? "ARGUS ENGINE ONLINE" : "BACKEND OFFLINE"}</span>}
          </div>
          <div className={`flex items-center gap-2 ${collapsed ? "justify-center" : ""}`}>
            <div className="w-6 h-6 rounded-full bg-[#20D3A2]/20 flex items-center justify-center flex-shrink-0">
              <span className="text-[10px] text-[#20D3A2] font-bold">SA</span>
            </div>
            {!collapsed && (
              <div>
                <div className="text-[12px] text-[#F3F5F7] font-medium">SOC Analyst</div>
                <div className="text-[10px] text-[#66707D]">Local workspace</div>
              </div>
            )}
          </div>
          {!collapsed && (
            <div className="text-[9px] text-[#66707D] uppercase tracking-widest pt-1 border-t border-[#1A2030]">
              Passive Metadata Analysis · No Payload Inspection
            </div>
          )}
        </div>
      </aside>

      {/* Main */}
      <div className="flex flex-col flex-1 min-w-0">
        {/* Top bar */}
        <header className="h-11 flex items-center px-4 border-b border-[#242B35] bg-[#0D1117] flex-shrink-0 gap-4">
          {/* Breadcrumb */}
          <div className="text-[12px] text-[#66707D] font-mono truncate flex-1">{breadcrumb}</div>

          {/* Live indicator */}
          <div className="flex items-center gap-1.5 text-[12px]">
            <LiveDot />
            <span className="text-[#20D3A2] font-semibold text-[11px]">{connected ? "CONNECTED" : "OFFLINE"}</span>
            <span className="text-[#66707D] text-[11px]">· Refresh every 2s</span>
          </div>

          {/* Search */}
          <div ref={searchRef} className="relative">
            <input
              type="text"
              placeholder="Search ARGUS-ONE..."
              value={searchQ}
              onChange={(e) => { setSearchQ(e.target.value); setSearchOpen(true); }}
              onFocus={() => setSearchOpen(true)}
              className="bg-[#11161D] border border-[#242B35] text-[#F3F5F7] text-[12px] rounded px-3 py-1.5 w-52 placeholder:text-[#66707D] focus:outline-none focus:border-[#20D3A2]/50"
            />
            {searchOpen && searchResults.length > 0 && (
              <div className="absolute top-full mt-1 right-0 w-80 bg-[#11161D] border border-[#242B35] rounded-lg shadow-2xl z-50 overflow-hidden">
                {searchResults.map((r, i) => (
                  <button
                    key={i}
                    onClick={() => { navigate(r.path); setSearchOpen(false); setSearchQ(""); }}
                    className="w-full flex items-start gap-3 px-3 py-2 hover:bg-[#151B23] text-left"
                  >
                    <span className="text-[10px] text-[#66707D] uppercase tracking-wide mt-0.5 w-16 flex-shrink-0">{r.type}</span>
                    <span className="text-[12px] text-[#F3F5F7] font-mono">{r.label}</span>
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Notifications */}
          <div className="relative">
            <button
              onClick={() => setNotifOpen((o) => !o)}
              className="relative w-8 h-8 flex items-center justify-center rounded hover:bg-[#151B23] text-[#9AA4B2] hover:text-[#F3F5F7]"
            >
              <svg viewBox="0 0 20 20" fill="currentColor" className="w-4 h-4">
                <path d="M10 2a6 6 0 00-6 6v3.5l-1.5 2.5h15L16 11.5V8a6 6 0 00-6-6z"/>
                <path d="M8 16a2 2 0 004 0H8z"/>
              </svg>
              <span className="absolute top-1 right-1 w-2 h-2 rounded-full bg-[#EB5757]" />
            </button>
            {notifOpen && (
              <div className="absolute top-full mt-1 right-0 w-80 bg-[#11161D] border border-[#242B35] rounded-lg shadow-2xl z-50 overflow-hidden">
                <div className="px-3 py-2 border-b border-[#242B35] text-[11px] font-semibold uppercase tracking-widest text-[#66707D]">
                  Notifications
                </div>
                {ALERTS.slice(0, 3).map((a) => (
                  <button
                    key={a.alert_id}
                    onClick={() => { navigate(`/alerts/${a.alert_id}`); setNotifOpen(false); }}
                    className="w-full px-3 py-2.5 flex items-start gap-2.5 hover:bg-[#151B23] text-left border-b border-[#1A2030] last:border-0"
                  >
                    <span className={`text-[10px] font-bold mt-0.5 ${
                      a.severity === "critical" ? "text-[#EB5757]" :
                      a.severity === "high" ? "text-[#F2994A]" :
                      a.severity === "medium" ? "text-[#F2C94C]" : "text-[#4C9AFF]"
                    }`}>{a.severity.toUpperCase()}</span>
                    <div>
                      <div className="text-[12px] text-[#F3F5F7]">{a.threat_class} detected</div>
                      <div className="text-[11px] text-[#66707D] font-mono">{a.source.ip} → {a.target.ip}</div>
                    </div>
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Settings */}
          <button
            onClick={() => navigate("/configuration")}
            className="w-8 h-8 flex items-center justify-center rounded hover:bg-[#151B23] text-[#9AA4B2] hover:text-[#F3F5F7]"
          >
            <svg viewBox="0 0 20 20" fill="currentColor" className="w-4 h-4">
              <path fillRule="evenodd" d="M11.49 3.17c-.38-1.56-2.6-1.56-2.98 0a1.532 1.532 0 01-2.286.948c-1.372-.836-2.942.734-2.106 2.106.54.886.061 2.042-.947 2.287-1.561.379-1.561 2.6 0 2.978a1.532 1.532 0 01.947 2.287c-.836 1.372.734 2.942 2.106 2.106a1.532 1.532 0 012.287.947c.379 1.561 2.6 1.561 2.978 0a1.533 1.533 0 012.287-.947c1.372.836 2.942-.734 2.106-2.106a1.533 1.533 0 01.947-2.287c1.561-.379 1.561-2.6 0-2.978a1.532 1.532 0 01-.947-2.287c.836-1.372-.734-2.942-2.106-2.106a1.532 1.532 0 01-2.287-.947zM10 13a3 3 0 100-6 3 3 0 000 6z" clipRule="evenodd"/>
            </svg>
          </button>
        </header>

        {/* Page content */}
        <main className="flex-1 overflow-y-auto bg-[#080B10]">
          {!connected && <div role="status" className="m-4 p-3 border border-[#F2994A]/40 rounded text-[#F2994A] text-sm">Backend unavailable. Start the API on port 8000. Displayed data may be stale.</div>}
          {error && <div role="alert" className="m-4 p-3 border border-[#EB5757]/40 rounded text-[#EB5757] text-sm">{error}</div>}
          {connected && data.summary.flows_processed === 0 && <div className="m-4 text-sm text-[#9AA4B2]">No flow records yet. Run a simulation from the dashboard or submit collector metadata.</div>}
          {children}
        </main>
      </div>
    </div>
  );
}
