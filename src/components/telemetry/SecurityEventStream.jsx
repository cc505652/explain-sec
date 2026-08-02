import React, { useState, useEffect } from "react";
import { telemetryBus } from "../../telemetry/telemetryBus.js";

export function SecurityEventStream({ onEventClick, onSwitchToHistory }) {
  const [events, setEvents] = useState(telemetryBus.getRecentEvents());
  const [filterSeverity, setFilterSeverity] = useState("all");
  const [filterSource, setFilterSource] = useState("all");

  useEffect(() => {
    const unsubEvent = telemetryBus.on("security_event", () => {
      setEvents(telemetryBus.getRecentEvents());
    });

    const unsubClear = telemetryBus.on("session_cleared", () => {
      setEvents([]);
    });

    return () => {
      unsubEvent();
      unsubClear();
    };
  }, []);

  const filteredEvents = events.filter(e => {
    if (filterSeverity !== "all" && e.severity !== filterSeverity) return false;
    if (filterSource !== "all" && e.source !== filterSource) return false;
    return true;
  });

  const getSeverityStyle = (sev) => {
    switch (sev) {
      case "critical": return { bg: "rgba(239,68,68,0.2)", border: "#ef4444", text: "#ef4444" };
      case "high": return { bg: "rgba(245,158,11,0.2)", border: "#f59e0b", text: "#f59e0b" };
      case "medium": return { bg: "rgba(56,189,248,0.2)", border: "#38bdf8", text: "#38bdf8" };
      default: return { bg: "rgba(100,116,139,0.2)", border: "#64748b", text: "#94a3b8" };
    }
  };

  return (
    <div style={{
      background: "var(--card-bg, #1e293b)",
      padding: "16px",
      borderRadius: "8px",
      border: "1px solid var(--border-color, rgba(255,255,255,0.1))",
      marginBottom: "16px"
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          <h3 style={{ margin: 0, fontSize: "14px", color: "var(--text-main, #f8fafc)" }}>
            📡 Live Telemetry Stream (latest {filteredEvents.length})
          </h3>
          {onSwitchToHistory && (
            <button
              onClick={onSwitchToHistory}
              style={{
                padding: "2px 8px",
                borderRadius: "4px",
                border: "1px solid #38bdf8",
                background: "rgba(56,189,248,0.1)",
                color: "#38bdf8",
                fontSize: "11px",
                cursor: "pointer"
              }}
            >
              View full history →
            </button>
          )}
        </div>
        
        {/* Filters */}
        <div style={{ display: "flex", gap: "10px" }}>
          <select
            value={filterSeverity}
            onChange={e => setFilterSeverity(e.target.value)}
            style={{ padding: "4px 8px", borderRadius: "4px", background: "#0f172a", color: "#f8fafc", border: "1px solid #334155", fontSize: "11px" }}
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical Only</option>
            <option value="high">High & Above</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
      </div>

      {/* Event Stream Ticker Table */}
      <div style={{ maxHeight: "360px", overflowY: "auto", display: "flex", flexDirection: "column", gap: "6px" }}>
        {filteredEvents.length === 0 ? (
          <div style={{ padding: "24px", textAlign: "center", opacity: 0.7, fontSize: "12px", color: "#94a3b8" }}>
            No active telemetry session. Start the Event Engine to begin generating security events.
          </div>
        ) : (
          filteredEvents.slice().reverse().map(evt => {
            const sevStyle = getSeverityStyle(evt.severity);
            const timeStr = new Date(evt.timestamp).toLocaleTimeString();
            return (
              <div
                key={evt.eventId}
                onClick={() => onEventClick?.(evt)}
                style={{
                  display: "grid",
                  gridTemplateColumns: "70px 140px 110px 140px 1fr 90px",
                  alignItems: "center",
                  padding: "8px 12px",
                  borderRadius: "6px",
                  background: "rgba(255,255,255,0.02)",
                  borderLeft: `4px solid ${sevStyle.border}`,
                  fontSize: "11px",
                  gap: "8px",
                  cursor: "pointer",
                  transition: "background 0.15s ease"
                }}
                onMouseEnter={e => e.currentTarget.style.background = "rgba(255,255,255,0.06)"}
                onMouseLeave={e => e.currentTarget.style.background = "rgba(255,255,255,0.02)"}
              >
                <span style={{ opacity: 0.7 }}>{timeStr}</span>
                <span style={{ fontWeight: "bold", color: "#f8fafc" }}>
                  {evt.sourceIcon} {evt.source}
                </span>
                <span style={{
                  padding: "2px 6px",
                  borderRadius: "4px",
                  fontWeight: "bold",
                  fontSize: "10px",
                  textAlign: "center",
                  background: sevStyle.bg,
                  color: sevStyle.text,
                  border: `1px solid ${sevStyle.border}`
                }}>
                  {evt.severity.toUpperCase()}
                </span>
                <span style={{ color: "#38bdf8" }}>{evt.asset?.hostname}</span>
                <span style={{ color: "#e2e8f0", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {evt.description}
                </span>
                <span style={{ opacity: 0.6, textAlign: "right", fontSize: "10px" }}>
                  {evt.mitreTechnique?.id || "T1059"}
                </span>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
