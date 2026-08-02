import React from "react";

export function OverviewTab({ event }) {
  if (!event) return null;

  const timeStr = new Date(event.timestamp).toLocaleString();

  const getSeverityBadge = (sev) => {
    switch (sev) {
      case "critical": return { bg: "rgba(239,68,68,0.2)", border: "#ef4444", text: "#ef4444" };
      case "high": return { bg: "rgba(245,158,11,0.2)", border: "#f59e0b", text: "#f59e0b" };
      case "medium": return { bg: "rgba(56,189,248,0.2)", border: "#38bdf8", text: "#38bdf8" };
      default: return { bg: "rgba(100,116,139,0.2)", border: "#64748b", text: "#94a3b8" };
    }
  };

  const sevStyle = getSeverityBadge(event.severity);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "12px", fontSize: "12px", color: "#e2e8f0" }}>
      {/* Description Header */}
      <div style={{ background: "rgba(255,255,255,0.03)", padding: "10px 12px", borderRadius: "6px", border: "1px solid rgba(255,255,255,0.08)" }}>
        <div style={{ color: "#94a3b8", fontSize: "11px", marginBottom: "4px" }}>Event Description</div>
        <div style={{ fontWeight: "bold", color: "#f8fafc", fontSize: "13px" }}>{event.description}</div>
      </div>

      {/* Grid Properties */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px" }}>
        <div>
          <span style={{ color: "#94a3b8" }}>Event ID:</span>
          <div style={{ fontWeight: "bold", fontFamily: "monospace", color: "#38bdf8" }}>{event.eventId}</div>
        </div>

        <div>
          <span style={{ color: "#94a3b8" }}>Timestamp:</span>
          <div style={{ fontWeight: "bold" }}>{timeStr}</div>
        </div>

        <div>
          <span style={{ color: "#94a3b8" }}>Source & Icon:</span>
          <div style={{ fontWeight: "bold" }}>{event.sourceIcon} {event.source}</div>
        </div>

        <div>
          <span style={{ color: "#94a3b8" }}>Provider / Product:</span>
          <div style={{ fontWeight: "bold" }}>{event.provider} ({event.product})</div>
        </div>

        <div>
          <span style={{ color: "#94a3b8" }}>Connector ID:</span>
          <div style={{ fontWeight: "bold" }}>{event.connectorId}</div>
        </div>

        <div>
          <span style={{ color: "#94a3b8" }}>Severity:</span>
          <div>
            <span style={{
              padding: "2px 8px",
              borderRadius: "4px",
              fontWeight: "bold",
              fontSize: "11px",
              background: sevStyle.bg,
              color: sevStyle.text,
              border: `1px solid ${sevStyle.border}`
            }}>
              {event.severity?.toUpperCase()}
            </span>
          </div>
        </div>
      </div>

      {/* Confidence Level Bar */}
      <div>
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "4px" }}>
          <span style={{ color: "#94a3b8" }}>Event Confidence:</span>
          <span style={{ fontWeight: "bold", color: "#38bdf8" }}>{event.confidence}%</span>
        </div>
        <div style={{ width: "100%", height: "6px", background: "#334155", borderRadius: "3px", overflow: "hidden" }}>
          <div style={{ width: `${event.confidence}%`, height: "100%", background: "#38bdf8", transition: "width 0.5s ease" }} />
        </div>
      </div>

      {/* User Context */}
      <div style={{ background: "rgba(255,255,255,0.02)", padding: "10px 12px", borderRadius: "6px", border: "1px solid rgba(255,255,255,0.06)", marginTop: "4px" }}>
        <div style={{ color: "#38bdf8", fontSize: "11px", fontWeight: "bold", marginBottom: "6px" }}>👤 USER CONTEXT</div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px" }}>
          <div><span style={{ color: "#94a3b8" }}>Username:</span> <b>{event.user?.username || "N/A"}</b></div>
          <div><span style={{ color: "#94a3b8" }}>Domain:</span> <b>{event.user?.domain || "CAMPUS"}</b></div>
          <div><span style={{ color: "#94a3b8" }}>Principal:</span> <b style={{ fontSize: "11px" }}>{event.user?.userPrincipalName || "N/A"}</b></div>
          <div><span style={{ color: "#94a3b8" }}>Role:</span> <b>{event.user?.role || "User"}</b></div>
        </div>
      </div>
    </div>
  );
}
