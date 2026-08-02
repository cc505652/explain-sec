import React, { useState, useEffect } from "react";
import { telemetryBus } from "../../telemetry/telemetryBus.js";

export function DetectionAnalyticsPanel() {
  const [stats, setStats] = useState(telemetryBus.getStats());

  useEffect(() => {
    const unsub = telemetryBus.on("stats_updated", (newStats) => {
      setStats({ ...newStats });
    });
    return unsub;
  }, []);

  const totalEvents = stats.eventsGenerated || 1;
  const suppressed = stats.suppressedEvents || 0;
  const correlated = stats.correlatedClusters || 0;
  const qualified = stats.qualifiedClusters || stats.incidentsCreated || 0;
  const activeAttacks = stats.activeCampaignsCount || 0;

  const benignPct = Math.max(92, 98 - (activeAttacks * 1.5)).toFixed(1);
  const suspiciousPct = (100 - benignPct - 0.5).toFixed(1);
  const maliciousPct = "0.5";

  const correlationSuccessRate = Math.min(100, Math.round((qualified / (correlated || 1)) * 100));

  return (
    <div style={{
      background: "var(--card-bg, #1e293b)",
      padding: "16px",
      borderRadius: "8px",
      border: "1px solid var(--border-color, rgba(255,255,255,0.1))",
      marginBottom: "16px",
      color: "#f8fafc"
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
        <h3 style={{ margin: 0, fontSize: "14px", color: "#f8fafc", display: "flex", alignItems: "center", gap: "6px" }}>
          <span>📊 Live SOC Detection Analytics & Noise Model</span>
        </h3>
        <span style={{ fontSize: "11px", color: "#38bdf8", background: "rgba(56,189,248,0.1)", padding: "2px 8px", borderRadius: "4px" }}>
          Mode: <b>{stats.simulationMode}</b> ({stats.simulationProfile || "MidEnterprise"})
        </span>
      </div>

      {/* Grid Metrics */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: "12px" }}>
        {/* Metric 1: Telemetry Noise Distribution */}
        <div style={{ background: "rgba(0,0,0,0.2)", padding: "10px", borderRadius: "6px", border: "1px solid rgba(255,255,255,0.06)" }}>
          <div style={{ fontSize: "11px", color: "#94a3b8", marginBottom: "4px" }}>Noise Breakdown</div>
          <div style={{ fontSize: "13px", fontWeight: "bold", color: "#10b981" }}>
            {benignPct}% <span style={{ fontSize: "10px", color: "#94a3b8" }}>Benign</span>
          </div>
          <div style={{ fontSize: "11px", color: "#cbd5e1", marginTop: "2px" }}>
            <span style={{ color: "#f59e0b" }}>{suspiciousPct}% Suspicious</span> | <span style={{ color: "#ef4444" }}>{maliciousPct}% Malicious</span>
          </div>
        </div>

        {/* Metric 2: Active Adversary Chains */}
        <div style={{ background: "rgba(0,0,0,0.2)", padding: "10px", borderRadius: "6px", border: "1px solid rgba(255,255,255,0.06)" }}>
          <div style={{ fontSize: "11px", color: "#94a3b8", marginBottom: "4px" }}>Active Adversary FSM Chains</div>
          <div style={{ fontSize: "18px", fontWeight: "bold", color: activeAttacks > 0 ? "#ef4444" : "#10b981" }}>
            {activeAttacks} <span style={{ fontSize: "11px", opacity: 0.8 }}>Concurrent Chains</span>
          </div>
        </div>

        {/* Metric 3: Correlation & Hypothesis Success Rate */}
        <div style={{ background: "rgba(0,0,0,0.2)", padding: "10px", borderRadius: "6px", border: "1px solid rgba(255,255,255,0.06)" }}>
          <div style={{ fontSize: "11px", color: "#94a3b8", marginBottom: "4px" }}>Correlation Qualification Rate</div>
          <div style={{ fontSize: "18px", fontWeight: "bold", color: "#38bdf8" }}>
            {correlationSuccessRate}% <span style={{ fontSize: "11px", opacity: 0.8 }}>({qualified}/{correlated || 1})</span>
          </div>
        </div>

        {/* Metric 4: Suppressed Noise Volume */}
        <div style={{ background: "rgba(0,0,0,0.2)", padding: "10px", borderRadius: "6px", border: "1px solid rgba(255,255,255,0.06)" }}>
          <div style={{ fontSize: "11px", color: "#94a3b8", marginBottom: "4px" }}>Suppressed Noise Events</div>
          <div style={{ fontSize: "18px", fontWeight: "bold", color: "#64748b" }}>
            {suppressed.toLocaleString()} <span style={{ fontSize: "11px", opacity: 0.8 }}>Filtered</span>
          </div>
        </div>
      </div>
    </div>
  );
}
