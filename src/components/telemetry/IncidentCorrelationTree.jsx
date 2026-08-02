import React, { useState } from "react";

export function IncidentCorrelationTree({ incident }) {
  const [expanded, setExpanded] = useState(false);

  if (!incident) return null;

  const sourceEvents = incident.sourceEvents || [];

  return (
    <div style={{
      background: "rgba(255,255,255,0.03)",
      borderRadius: "6px",
      border: "1px solid rgba(255,255,255,0.08)",
      padding: "12px",
      marginTop: "10px"
    }}>
      <div
        onClick={() => setExpanded(!expanded)}
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          cursor: "pointer",
          userSelect: "none"
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <span style={{ fontSize: "14px" }}>{expanded ? "▼" : "▶"}</span>
          <b style={{ fontSize: "12px", color: "#38bdf8" }}>
            🔍 Telemetry Cluster ({sourceEvents.length} Correlated Events)
          </b>
          {incident.originTelemetryClusterId && (
            <span style={{ fontSize: "10px", background: "rgba(56,189,248,0.15)", padding: "2px 6px", borderRadius: "4px", color: "#38bdf8" }}>
              Origin: {incident.originTelemetryClusterId}
            </span>
          )}
        </div>
        <span style={{ fontSize: "11px", color: "#94a3b8" }}>
          {expanded ? "Click to collapse" : "Click to view SIEM correlation breakdown"}
        </span>
      </div>

      {expanded && (
        <div style={{ marginTop: "12px", paddingTop: "12px", borderTop: "1px dashed rgba(255,255,255,0.1)", fontSize: "11px", display: "flex", flexDirection: "column", gap: "8px" }}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px", background: "rgba(0,0,0,0.2)", padding: "8px", borderRadius: "4px" }}>
            <div>
              <span style={{ opacity: 0.7 }}>Correlation Rule: </span>
              <b>{incident.correlationRule || "Rule Match"}</b>
            </div>
            <div>
              <span style={{ opacity: 0.7 }}>Cluster State: </span>
              <b style={{ color: "#10b981" }}>INCIDENT_CREATED</b>
            </div>
            <div>
              <span style={{ opacity: 0.7 }}>Confidence (Event / Corr / Incident): </span>
              <b style={{ color: "#10b981" }}>80% / 85% / {incident.confidence || 85}%</b>
            </div>
            <div>
              <span style={{ opacity: 0.7 }}>MITRE ATT&CK: </span>
              <b style={{ color: "#f59e0b" }}>{incident.mitreInfo?.id || "T1059"} ({incident.mitreInfo?.name || "Execution"})</b>
            </div>
          </div>

          <b style={{ marginTop: "6px", color: "#f8fafc" }}>Correlated Telemetry Event Chain:</b>

          <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
            {sourceEvents.length === 0 ? (
              <span style={{ opacity: 0.6 }}>No raw source events attached.</span>
            ) : (
              sourceEvents.map((evt, idx) => (
                <div key={idx} style={{
                  padding: "6px 10px",
                  borderRadius: "4px",
                  background: "rgba(255,255,255,0.02)",
                  borderLeft: "3px solid #38bdf8",
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center"
                }}>
                  <span>
                    <b>[{idx + 1}] {evt.sourceIcon || "📡"} {evt.source}</b> — {evt.description}
                  </span>
                  <span style={{ opacity: 0.6, fontSize: "10px" }}>
                    {evt.mitreTechnique?.id || "T1059"} | {new Date(evt.timestamp).toLocaleTimeString()}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
}
