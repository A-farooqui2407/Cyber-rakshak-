import React, { useState } from "react";
import { AuthProvider, useAuth } from "./context/AuthContext";
import { Sidebar } from "./components/layout/Sidebar";
import { Navbar } from "./components/layout/Navbar";
import { Dashboard } from "./pages/Dashboard";
import { LiveLogs } from "./pages/LiveLogs";
import { Alerts } from "./pages/Alerts";
import { Incidents } from "./pages/Incidents";
import { Detection } from "./pages/Detection";
import { RiskAnalysis } from "./pages/RiskAnalysis";
import { AIAssistant } from "./pages/AIAssistant";
import { Settings } from "./pages/Settings";
import { Login } from "./pages/Login";
import { SimulationModal } from "./components/ui/SimulationModal";
import { AlertDetailDrawer } from "./components/ui/AlertDetailDrawer";
import { IncidentDetailDrawer } from "./components/ui/IncidentDetailDrawer";
import { Alert, Incident } from "./types";
import { api } from "./services/api";

const MainLayout: React.FC = () => {
  const { isAuthenticated, role, user } = useAuth();
  const [currentTab, setCurrentTab] = useState("dashboard");

  // Drawers & Modals
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [isSimulationOpen, setIsSimulationOpen] = useState(false);

  // Refresh key to force re-fetches
  const [refreshKey, setRefreshKey] = useState(0);

  if (!isAuthenticated) {
    return <Login />;
  }

  const handleAlertStatusChange = async (id: string, newStatus: string) => {
    try {
      await api.updateAlertStatus(id, newStatus, user?.email);
      if (selectedAlert && selectedAlert.id === id) {
        setSelectedAlert({ ...selectedAlert, status: newStatus as any });
      }
      setRefreshKey((k) => k + 1);
    } catch (err) {
      console.error("Failed to update alert status", err);
    }
  };

  const handleIncidentStatusChange = async (id: string, newStatus: string) => {
    try {
      await api.updateIncidentStatus(id, newStatus);
      if (selectedIncident && selectedIncident.id === id) {
        setSelectedIncident({ ...selectedIncident, status: newStatus as any });
      }
      setRefreshKey((k) => k + 1);
    } catch (err) {
      console.error("Failed to update incident status", err);
    }
  };

  const handleSimulationComplete = (result: any) => {
    setRefreshKey((k) => k + 1);
  };

  return (
    <div className="flex h-screen bg-slate-950 text-slate-100 font-sans antialiased overflow-hidden selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Left Sidebar */}
      <Sidebar
        currentTab={currentTab}
        onSelectTab={setCurrentTab}
        onOpenSimulation={() => setIsSimulationOpen(true)}
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 h-screen overflow-hidden">
        {/* Sticky Top Navbar */}
        <Navbar
          onRefresh={() => setRefreshKey((k) => k + 1)}
          criticalAlertCount={1}
        />

        {/* Scrollable View Container */}
        <main className="flex-1 overflow-y-auto p-6">
          <div className="max-w-7xl mx-auto pb-12">
            {currentTab === "dashboard" && (
              <Dashboard
                key={refreshKey}
                onSelectAlert={(a) => setSelectedAlert(a)}
                onOpenSimulation={() => setIsSimulationOpen(true)}
                onNavigateTab={(tab) => setCurrentTab(tab)}
              />
            )}
            {currentTab === "logs" && <LiveLogs key={refreshKey} />}
            {currentTab === "alerts" && (
              <Alerts
                key={refreshKey}
                onSelectAlert={(a) => setSelectedAlert(a)}
              />
            )}
            {currentTab === "incidents" && (
              <Incidents
                key={refreshKey}
                onSelectIncident={(inc) => setSelectedIncident(inc)}
              />
            )}
            {currentTab === "detection" && <Detection key={refreshKey} />}
            {currentTab === "risk" && <RiskAnalysis key={refreshKey} />}
            {currentTab === "ai" && <AIAssistant key={refreshKey} />}
            {currentTab === "settings" && <Settings key={refreshKey} />}
          </div>
        </main>
      </div>

      {/* Attack Simulation Modal */}
      <SimulationModal
        isOpen={isSimulationOpen}
        onClose={() => setIsSimulationOpen(false)}
        onSimulationComplete={handleSimulationComplete}
      />

      {/* Alert Detail Drawer */}
      <AlertDetailDrawer
        alert={selectedAlert}
        onClose={() => setSelectedAlert(null)}
        onStatusChange={handleAlertStatusChange}
      />

      {/* Incident Detail Drawer */}
      <IncidentDetailDrawer
        incident={selectedIncident}
        onClose={() => setSelectedIncident(null)}
        onStatusChange={handleIncidentStatusChange}
      />
    </div>
  );
};

export function App() {
  return (
    <AuthProvider>
      <MainLayout />
    </AuthProvider>
  );
}

export default App;
