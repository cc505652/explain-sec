import React, { useState } from "react";
import { generatorConnector } from "../../telemetry/connectors/generatorConnector.js";
import { telemetryBus } from "../../telemetry/telemetryBus.js";
import { NewSimulationDialog } from "./NewSimulationDialog.jsx";

export function GeneratorControls({ onOpenManualModal }) {
  const [stats, setStats] = useState(telemetryBus.getStats());
  const [seedInput, setSeedInput] = useState("");
  const [showNewSimDialog, setShowNewSimDialog] = useState(false);

  React.useEffect(() => {
    const unsub = telemetryBus.on("stats_updated", (newStats) => {
      setStats({ ...newStats });
    });
    return unsub;
  }, []);

  const handleStartPause = () => {
    if (stats.generatorStatus === "RUNNING") {
      generatorConnector.pause();
    } else {
      generatorConnector.start();
    }
  };

  const handleConfirmNewSimulation = () => {
    generatorConnector.newSimulation();
  };

  const handleModeChange = (e) => {
    generatorConnector.setSimulationMode(e.target.value);
  };

  const handleSpeedChange = (spd) => {
    generatorConnector.setSpeed(spd);
  };

  const handleSeedSubmit = (e) => {
    e.preventDefault();
    if (seedInput.trim()) {
      generatorConnector.setSeed(seedInput.trim());
    } else {
      generatorConnector.setSeed(null);
    }
  };

  const handleToggleAutoPause = (e) => {
    generatorConnector.setPauseOnIncident(e.target.checked);
  };

  return (
    <>
      <div style={{
        background: "var(--card-bg, #1e293b)",
        padding: "14px 16px",
        borderRadius: "8px",
        border: "1px solid var(--border-color, rgba(255,255,255,0.1))",
        marginBottom: "16px",
        display: "flex",
        flexWrap: "wrap",
        gap: "16px",
        alignItems: "center",
        justifyContent: "space-between"
      }}>
        {/* Playback & Mode Controls */}
        <div style={{ display: "flex", gap: "10px", alignItems: "center", flexWrap: "wrap" }}>
          <button
            onClick={handleStartPause}
            style={{
              padding: "8px 16px",
              borderRadius: "6px",
              border: "none",
              fontWeight: "bold",
              fontSize: "12px",
              cursor: "pointer",
              background: stats.generatorStatus === "RUNNING" ? "#ef4444" : "#10b981",
              color: "#fff"
            }}
          >
            {stats.generatorStatus === "RUNNING" ? "⏸ Pause Engine" : "▶ Start Engine"}
          </button>

          <button
            onClick={() => generatorConnector.stepOnce()}
            style={{
              padding: "8px 12px",
              borderRadius: "6px",
              border: "1px solid #475569",
              background: "rgba(255,255,255,0.05)",
              color: "#f8fafc",
              fontSize: "12px",
              cursor: "pointer"
            }}
          >
            ⏭ Step Once
          </button>

          <button
            onClick={() => setShowNewSimDialog(true)}
            style={{
              padding: "8px 14px",
              borderRadius: "6px",
              border: "1px solid #38bdf8",
              background: "rgba(56,189,248,0.15)",
              color: "#38bdf8",
              fontSize: "12px",
              fontWeight: "bold",
              cursor: "pointer"
            }}
          >
            🔄 New Simulation
          </button>

          {/* Simulation Profile Selector */}
          <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
            <span style={{ fontSize: "12px", opacity: 0.8 }}>Profile:</span>
            <select
              value={stats.simulationProfile || "MidEnterprise"}
              onChange={(e) => generatorConnector.setSimulationProfile(e.target.value)}
              style={{
                padding: "6px 10px",
                borderRadius: "6px",
                background: "#0f172a",
                color: "#f8fafc",
                border: "1px solid #334155",
                fontSize: "12px"
              }}
            >
              <option value="SmallOffice">Small Office / Branch (25 Endpoints)</option>
              <option value="MidEnterprise">Mid Enterprise (250 Endpoints)</option>
              <option value="Fortune500">Fortune 500 Global (1,000+ Endpoints)</option>
              <option value="Government">Government Agency (500 Endpoints)</option>
              <option value="Hospital">Healthcare System (300 Endpoints)</option>
              <option value="University">University Campus (600 Endpoints)</option>
              <option value="Bank">Financial Institution (800 Endpoints)</option>
            </select>
          </div>

          {/* Simulation Mode Selector */}
          <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
            <span style={{ fontSize: "12px", opacity: 0.8 }}>Mode:</span>
            <select
              value={stats.simulationMode}
              onChange={handleModeChange}
              style={{
                padding: "6px 10px",
                borderRadius: "6px",
                background: "#0f172a",
                color: "#f8fafc",
                border: "1px solid #334155",
                fontSize: "12px"
              }}
            >
              <option value="Training">Training Mode (95% Noise)</option>
              <option value="Normal Enterprise">Normal Enterprise</option>
              <option value="High Threat">High Threat</option>
              <option value="Red Team Exercise">Red Team Exercise</option>
              <option value="Chaos Mode">Chaos Mode</option>
            </select>
          </div>

          {/* Speed Buttons */}
          <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
            <span style={{ fontSize: "12px", opacity: 0.8, marginRight: "4px" }}>Speed:</span>
            {[1, 2, 5, 10].map(s => (
              <button
                key={s}
                onClick={() => handleSpeedChange(s)}
                style={{
                  padding: "4px 8px",
                  borderRadius: "4px",
                  border: "none",
                  fontSize: "11px",
                  fontWeight: "bold",
                  cursor: "pointer",
                  background: stats.speedMultiplier === s ? "#38bdf8" : "rgba(255,255,255,0.1)",
                  color: stats.speedMultiplier === s ? "#0f172a" : "#94a3b8"
                }}
              >
                {s}x
              </button>
            ))}
          </div>
        </div>

        {/* Seed Input & Auto-Pause Toggle */}
        <div style={{ display: "flex", gap: "16px", alignItems: "center", flexWrap: "wrap" }}>
          <form onSubmit={handleSeedSubmit} style={{ display: "flex", gap: "6px", alignItems: "center" }}>
            <span style={{ fontSize: "12px", opacity: 0.8 }}>Seed:</span>
            <input
              type="text"
              placeholder="e.g. 12345"
              value={seedInput}
              onChange={(e) => setSeedInput(e.target.value)}
              style={{
                padding: "4px 8px",
                borderRadius: "4px",
                border: "1px solid #334155",
                background: "#0f172a",
                color: "#f8fafc",
                width: "80px",
                fontSize: "11px"
              }}
            />
            <button type="submit" style={{ padding: "4px 8px", borderRadius: "4px", border: "none", background: "#475569", color: "#fff", fontSize: "11px", cursor: "pointer" }}>Set</button>
          </form>

          <label style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "12px", cursor: "pointer" }}>
            <input
              type="checkbox"
              checked={stats.pauseOnIncident}
              onChange={handleToggleAutoPause}
            />
            <span>Pause on Incident Creation</span>
          </label>

          {/* Manual Incident Submission Trigger */}
          <button
            onClick={onOpenManualModal}
            style={{
              padding: "8px 14px",
              borderRadius: "6px",
              border: "none",
              fontWeight: "bold",
              fontSize: "12px",
              cursor: "pointer",
              background: "#8b5cf6",
              color: "#fff"
            }}
          >
            + New Manual Incident
          </button>
        </div>
      </div>

      {/* Confirmation Dialog */}
      <NewSimulationDialog
        isOpen={showNewSimDialog}
        onClose={() => setShowNewSimDialog(false)}
        onConfirm={handleConfirmNewSimulation}
      />
    </>
  );
}
