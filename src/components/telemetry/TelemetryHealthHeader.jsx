import React, { useState, useEffect } from "react";
import { telemetryBus } from "../../telemetry/telemetryBus.js";

export function TelemetryHealthHeader() {
  const [stats, setStats] = useState(telemetryBus.getStats());

  useEffect(() => {
    const unsub = telemetryBus.on("stats_updated", (newStats) => {
      setStats({ ...newStats });
    });
    return unsub;
  }, []);

  const isRunning = stats.generatorStatus === "RUNNING";

  return (
    <div style={{
      display: "flex",
      flexDirection: "column",
      gap: "8px",
      padding: "12px 16px",
      background: "var(--card-bg, #1e293b)",
      borderRadius: "8px",
      border: "1px solid var(--border-color, rgba(255,255,255,0.1))",
      marginBottom: "16px",
      color: "var(--text-main, #f8fafc)"
    }}>
      {/* Row 1: Engine Status & Session Badge */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "10px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <span style={{
            display: "inline-block",
            width: "10px",
            height: "10px",
            borderRadius: "50%",
            background: isRunning ? "#10b981" : "#ef4444",
            boxShadow: isRunning ? "0 0 8px #10b981" : "none"
          }} />
          <span style={{ fontWeight: "bold", fontSize: "13px" }}>
            ENGINE: <span style={{ color: isRunning ? "#10b981" : "#ef4444" }}>{stats.generatorStatus}</span>
          </span>
          <span style={{ fontSize: "11px", opacity: 0.7, marginLeft: "4px" }}>
            ({stats.simulationMode} Mode — {stats.speedMultiplier}x)
          </span>
        </div>

        {/* Current Session ID Badge */}
        {stats.currentSessionId && (
          <div style={{ fontSize: "11px", color: "#38bdf8", background: "rgba(56,189,248,0.1)", padding: "2px 8px", borderRadius: "4px", border: "1px solid rgba(56,189,248,0.2)" }}>
            Session ID: <b style={{ fontFamily: "monospace" }}>{stats.currentSessionId}</b>
          </div>
        )}
      </div>

      {/* Row 2: Current Simulation vs Lifetime Stats Ticker */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderTop: "1px solid rgba(255,255,255,0.06)", paddingTop: "8px", flexWrap: "wrap", gap: "12px" }}>
        {/* Current Session Stats */}
        <div style={{ display: "flex", gap: "14px", flexWrap: "wrap", alignItems: "center" }}>
          <span style={{ fontSize: "11px", color: "#38bdf8", fontWeight: "bold" }}>CURRENT SIMULATION:</span>
          <div style={{ fontSize: "11px" }}>Events: <b style={{ color: "#38bdf8" }}>{stats.eventsGenerated.toLocaleString()}</b></div>
          <div style={{ fontSize: "11px" }}>Rate: <b style={{ color: "#a855f7" }}>{stats.eventsPerSec} evt/s</b></div>
          <div style={{ fontSize: "11px" }}>Incidents: <b style={{ color: "#ef4444" }}>{stats.incidentsCreated}</b></div>
          <div style={{ fontSize: "11px" }}>Suppressed: <b style={{ color: "#64748b" }}>{stats.suppressedEvents.toLocaleString()}</b></div>
        </div>

        {/* Lifetime Cumulative Stats */}
        <div style={{ display: "flex", gap: "14px", flexWrap: "wrap", alignItems: "center", opacity: 0.85 }}>
          <span style={{ fontSize: "11px", color: "#a78bfa", fontWeight: "bold" }}>LIFETIME:</span>
          <div style={{ fontSize: "11px" }}>Total Events: <b style={{ color: "#a78bfa" }}>{(stats.lifetimeEventsGenerated || 0).toLocaleString()}</b></div>
          <div style={{ fontSize: "11px" }}>Total Incidents: <b style={{ color: "#ef4444" }}>{stats.lifetimeIncidentsCreated || 0}</b></div>
          <div style={{ fontSize: "11px" }}>Simulations: <b style={{ color: "#10b981" }}>{stats.lifetimeSimulationsCompleted || 0}</b></div>
        </div>
      </div>
    </div>
  );
}
