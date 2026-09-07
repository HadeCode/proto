import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import ApiProvider from "@/data/api";
import Layout from "@/components/Layout";
import Login from "@/pages/Login";
import Dashboard from "@/pages/Dashboard";
import LiveTraffic from "@/pages/LiveTraffic";
import FlowExplorer from "@/pages/FlowExplorer";
import Threats from "@/pages/Threats";
import AlertDetail from "@/pages/AlertDetail";
import Alerts from "@/pages/Alerts";
import DetectionEngines from "@/pages/DetectionEngines";
import DetectorDetail from "@/pages/DetectorDetail";
import Analytics from "@/pages/Analytics";
import Baseline from "@/pages/Baseline";
import DNSAnalysis from "@/pages/DNSAnalysis";
import TLSAnalysis from "@/pages/TLSAnalysis";
import AgentStatus from "@/pages/AgentStatus";
import DataSources from "@/pages/DataSources";
import Configuration from "@/pages/Configuration";
import ThreatIntelligence from "@/pages/ThreatIntelligence";
import MachineLearning from "@/pages/MachineLearning";
import HealthReportPage from "@/pages/HealthReportPage";

function AppShell() {
  return (
    <Layout>
      <Routes>
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/health-report" element={<HealthReportPage />} />
        <Route path="/health" element={<HealthReportPage />} />
        <Route path="/network-health" element={<HealthReportPage />} />
        <Route path="/live-traffic" element={<LiveTraffic />} />
        <Route path="/flow-explorer" element={<FlowExplorer />} />
        <Route path="/threats" element={<Threats />} />
        <Route path="/alerts" element={<Alerts />} />
        <Route path="/alerts/:id" element={<AlertDetail />} />
        <Route path="/engines" element={<DetectionEngines />} />
        <Route path="/engines/:id" element={<DetectorDetail />} />
        <Route path="/ml-models" element={<MachineLearning />} />
        <Route path="/machine-learning" element={<MachineLearning />} />
        <Route path="/analytics" element={<Analytics />} />
        <Route path="/baseline" element={<Baseline />} />
        <Route path="/dns-analysis" element={<DNSAnalysis />} />
        <Route path="/tls-analysis" element={<TLSAnalysis />} />
        <Route path="/agent-status" element={<AgentStatus />} />
        <Route path="/data-sources" element={<DataSources />} />
        <Route path="/configuration" element={<Configuration />} />
        <Route path="/threat-intel" element={<ThreatIntelligence />} />
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </Layout>
  );
}

export default function App() {
  return (
    <ApiProvider><BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/*" element={<AppShell />} />
      </Routes>
    </BrowserRouter></ApiProvider>
  );
}
