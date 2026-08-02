import React from "react";

export function AssetTab({ event }) {
  if (!event) return null;

  const asset = event.asset || {};

  const getCriticalityBadge = (crit) => {
    switch (crit) {
      case "critical": return { bg: "rgba(239,68,68,0.2)", text: "#ef4444", border: "#ef4444" };
      case "high": return { bg: "rgba(245,158,11,0.2)", text: "#f59e0b", border: "#f59e0b" };
      default: return { bg: "rgba(56,189,248,0.2)", text: "#38bdf8", border: "#38bdf8" };
    }
  };

  const critStyle = getCriticalityBadge(asset.criticality);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "12px", fontSize: "12px", color: "#e2e8f0" }}>
      <div style={{ background: "rgba(56,189,248,0.08)", padding: "12px", borderRadius: "6px", border: "1px solid rgba(56,189,248,0.2)" }}>
        <div style={{ color: "#38bdf8", fontSize: "11px", fontWeight: "bold", marginBottom: "4px" }}>TARGET ENDPOINT ASSET</div>
        <div style={{ fontSize: "16px", fontWeight: "bold", color: "#f8fafc", fontFamily: "monospace" }}>
          {asset.hostname || "WORKSTATION-01"}
        </div>
        <div style={{ color: "#94a3b8", fontSize: "11px", marginTop: "2px" }}>
          IP Address: <b style={{ color: "#38bdf8" }}>{asset.ip || "192.168.1.50"}</b> | Type: {asset.type || "endpoint"}
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px" }}>
        <div>
          <span style={{ color: "#94a3b8" }}>Department:</span>
          <div style={{ fontWeight: "bold" }}>{asset.department || "General Corporate"}</div>
        </div>

        <div>
          <span style={{ color: "#94a3b8" }}>Assigned Owner:</span>
          <div style={{ fontWeight: "bold" }}>{asset.owner || "Unassigned"}</div>
        </div>

        <div>
          <span style={{ color: "#94a3b8" }}>Asset Criticality:</span>
          <div>
            <span style={{
              padding: "2px 8px",
              borderRadius: "4px",
              fontWeight: "bold",
              fontSize: "11px",
              background: critStyle.bg,
              color: critStyle.text,
              border: `1px solid ${critStyle.border}`
            }}>
              {(asset.criticality || "medium").toUpperCase()}
            </span>
          </div>
        </div>

        <div>
          <span style={{ color: "#94a3b8" }}>Physical Location:</span>
          <div style={{ fontWeight: "bold" }}>{asset.location || "Campus HQ"}</div>
        </div>
      </div>
    </div>
  );
}
