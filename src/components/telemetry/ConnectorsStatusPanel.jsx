import React from "react";
import { getConnectorsStatus } from "../../telemetry/connectors/ingestConnector.js";

export function ConnectorsStatusPanel() {
  const connectors = getConnectorsStatus();

  return (
    <div style={{
      background: "var(--card-bg, #1e293b)",
      padding: "16px",
      borderRadius: "8px",
      border: "1px solid var(--border-color, rgba(255,255,255,0.1))",
      marginBottom: "16px"
    }}>
      <h3 style={{ margin: "0 0 12px 0", fontSize: "14px", color: "var(--text-main, #f8fafc)" }}>
        🔌 Telemetry Ingestion Connectors Architecture
      </h3>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "12px" }}>
        {connectors.map(c => {
          const isActive = c.status === "active";
          return (
            <div key={c.id} style={{
              padding: "10px",
              borderRadius: "6px",
              background: isActive ? "rgba(16, 185, 129, 0.1)" : "rgba(255,255,255,0.03)",
              border: `1px solid ${isActive ? "rgba(16, 185, 129, 0.4)" : "rgba(255,255,255,0.08)"}`,
              display: "flex",
              flexDirection: "column",
              gap: "4px"
            }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontSize: "13px", fontWeight: "bold", color: "#f8fafc" }}>
                  {c.icon} {c.name}
                </span>
                <span style={{
                  fontSize: "10px",
                  padding: "2px 6px",
                  borderRadius: "4px",
                  fontWeight: "bold",
                  background: isActive ? "#10b981" : "#475569",
                  color: "#fff"
                }}>
                  {isActive ? "ACTIVE" : "DISABLED (FUTURE)"}
                </span>
              </div>
              <span style={{ fontSize: "11px", color: "#94a3b8" }}>{c.description}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
