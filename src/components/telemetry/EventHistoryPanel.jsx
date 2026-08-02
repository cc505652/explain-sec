import React, { useState, useEffect } from "react";
import { telemetrySessionManager } from "../../telemetry/session/telemetrySessionManager.js";
import { telemetryBus } from "../../telemetry/telemetryBus.js";

export function EventHistoryPanel({ onEventClick }) {
  const [viewMode, setViewMode] = useState("current"); // current | previous
  const [sessionEvents, setSessionEvents] = useState(telemetrySessionManager.getSessionEvents());
  const [archivedSimulations, setArchivedSimulations] = useState([]);
  const [selectedArchivedSimId, setSelectedArchivedSimId] = useState(null);
  const [archivedEvents, setArchivedEvents] = useState([]);
  const [loadingArchive, setLoadingArchive] = useState(false);

  // Quick Filter Chips State
  const [filterSeverity, setFilterSeverity] = useState("all");
  const [filterCategory, setFilterCategory] = useState("all");
  const [filterSource, setFilterSource] = useState("all");
  const [filterStatus, setFilterStatus] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");

  useEffect(() => {
    const unsub = telemetryBus.on("security_event", () => {
      setSessionEvents(telemetrySessionManager.getSessionEvents());
    });
    return unsub;
  }, []);

  // Load archived simulations when switching to "previous"
  useEffect(() => {
    if (viewMode === "previous") {
      setLoadingArchive(true);
      telemetrySessionManager.loadArchivedSimulations().then(sims => {
        setArchivedSimulations(sims);
        setLoadingArchive(false);
      });
    }
  }, [viewMode]);

  // Load events for selected archived simulation
  const handleSelectArchivedSim = async (simId) => {
    setSelectedArchivedSimId(simId);
    setLoadingArchive(true);
    const evts = await telemetrySessionManager.loadArchivedEvents(simId);
    setArchivedEvents(evts);
    setLoadingArchive(false);
  };

  const activeEventsList = viewMode === "current"
    ? sessionEvents
    : (selectedArchivedSimId ? archivedEvents : []);

  // Apply filters
  const filteredEvents = activeEventsList.filter(e => {
    if (filterSeverity !== "all" && e.severity !== filterSeverity) return false;
    if (filterCategory !== "all" && e.category !== filterCategory) return false;
    if (filterSource !== "all" && !e.source?.toLowerCase().includes(filterSource.toLowerCase())) return false;
    if (filterStatus !== "all" && e.eventStatus !== filterStatus) return false;

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchId = e.eventId?.toLowerCase().includes(q);
      const matchDesc = e.description?.toLowerCase().includes(q);
      const matchHost = e.asset?.hostname?.toLowerCase().includes(q);
      const matchUser = e.user?.username?.toLowerCase().includes(q);
      return matchId || matchDesc || matchHost || matchUser;
    }
    return true;
  });

  const getSeverityBadge = (sev) => {
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
      border: "1px solid var(--border-color, rgba(255,255,255,0.1))"
    }}>
      {/* Top Controls: Mode Toggle & Search */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px", flexWrap: "wrap", gap: "12px" }}>
        {/* Toggle Mode */}
        <div style={{ display: "flex", gap: "4px", background: "#0f172a", padding: "3px", borderRadius: "6px", border: "1px solid #334155" }}>
          <button
            onClick={() => { setViewMode("current"); setSelectedArchivedSimId(null); }}
            style={{
              padding: "6px 12px",
              borderRadius: "4px",
              border: "none",
              fontSize: "12px",
              fontWeight: "bold",
              cursor: "pointer",
              background: viewMode === "current" ? "#38bdf8" : "transparent",
              color: viewMode === "current" ? "#0f172a" : "#94a3b8"
            }}
          >
            ⚡ Current Simulation ({sessionEvents.length})
          </button>

          <button
            onClick={() => setViewMode("previous")}
            style={{
              padding: "6px 12px",
              borderRadius: "4px",
              border: "none",
              fontSize: "12px",
              fontWeight: "bold",
              cursor: "pointer",
              background: viewMode === "previous" ? "#38bdf8" : "transparent",
              color: viewMode === "previous" ? "#0f172a" : "#94a3b8"
            }}
          >
            🗄️ Previous Simulations ({archivedSimulations.length})
          </button>
        </div>

        {/* Text Search Input */}
        <input
          type="text"
          placeholder="🔍 Search Event ID, host, user, description..."
          value={searchQuery}
          onChange={e => setSearchQuery(e.target.value)}
          style={{
            padding: "6px 12px",
            borderRadius: "6px",
            border: "1px solid #334155",
            background: "#0f172a",
            color: "#f8fafc",
            fontSize: "12px",
            width: "280px"
          }}
        />
      </div>

      {/* Quick Filter Chips */}
      <div style={{ display: "flex", gap: "16px", flexWrap: "wrap", marginBottom: "16px", fontSize: "11px", background: "rgba(0,0,0,0.2)", padding: "10px", borderRadius: "6px" }}>
        {/* Severity Chips */}
        <div style={{ display: "flex", gap: "4px", alignItems: "center" }}>
          <span style={{ color: "#94a3b8", marginRight: "2px" }}>Severity:</span>
          {["all", "critical", "high", "medium", "low"].map(sev => (
            <button
              key={sev}
              onClick={() => setFilterSeverity(sev)}
              style={{
                padding: "2px 8px",
                borderRadius: "10px",
                border: filterSeverity === sev ? "1px solid #38bdf8" : "1px solid transparent",
                background: filterSeverity === sev ? "rgba(56,189,248,0.2)" : "rgba(255,255,255,0.05)",
                color: filterSeverity === sev ? "#38bdf8" : "#94a3b8",
                cursor: "pointer",
                textTransform: "capitalize"
              }}
            >
              {sev}
            </button>
          ))}
        </div>

        {/* Status Chips */}
        <div style={{ display: "flex", gap: "4px", alignItems: "center" }}>
          <span style={{ color: "#94a3b8", marginRight: "2px" }}>Status:</span>
          {["all", "promoted", "qualified", "suppressed"].map(st => (
            <button
              key={st}
              onClick={() => setFilterStatus(st)}
              style={{
                padding: "2px 8px",
                borderRadius: "10px",
                border: filterStatus === st ? "1px solid #10b981" : "1px solid transparent",
                background: filterStatus === st ? "rgba(16,185,129,0.2)" : "rgba(255,255,255,0.05)",
                color: filterStatus === st ? "#10b981" : "#94a3b8",
                cursor: "pointer",
                textTransform: "capitalize"
              }}
            >
              {st}
            </button>
          ))}
        </div>
      </div>

      {/* View Mode: Previous Simulations Archive Cards */}
      {viewMode === "previous" && !selectedArchivedSimId && (
        <div style={{ display: "flex", flexDirection: "column", gap: "10px", marginBottom: "16px" }}>
          {loadingArchive ? (
            <div style={{ padding: "20px", textAlign: "center", color: "#94a3b8" }}>Loading simulation archive from Firestore...</div>
          ) : archivedSimulations.length === 0 ? (
            <div style={{ padding: "20px", textAlign: "center", opacity: 0.6 }}>No archived simulations found in Firestore.</div>
          ) : (
            archivedSimulations.map(sim => (
              <div
                key={sim.id}
                style={{
                  padding: "12px 16px",
                  borderRadius: "6px",
                  background: "rgba(255,255,255,0.03)",
                  border: "1px solid #334155",
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center"
                }}
              >
                <div>
                  <div style={{ fontWeight: "bold", color: "#f8fafc", fontSize: "13px" }}>
                    Simulation ID: <span style={{ fontFamily: "monospace", color: "#38bdf8" }}>{sim.sessionId}</span>
                  </div>
                  <div style={{ fontSize: "11px", color: "#94a3b8", marginTop: "4px" }}>
                    Scenario: <b>{sim.scenario || "Replay"}</b> | Started: {new Date(sim.startedAt).toLocaleString()}
                  </div>
                  <div style={{ fontSize: "11px", color: "#cbd5e1", marginTop: "4px" }}>
                    Events: <b>{sim.eventCount || sim.stats?.eventsGenerated || 0}</b> | Incidents: <b style={{ color: "#ef4444" }}>{sim.stats?.incidentsCreated || 0}</b> | Qualified: <b>{sim.stats?.qualifiedClusters || 0}</b>
                  </div>
                </div>

                <button
                  onClick={() => handleSelectArchivedSim(sim.sessionId)}
                  style={{
                    padding: "6px 14px",
                    borderRadius: "6px",
                    border: "1px solid #38bdf8",
                    background: "rgba(56,189,248,0.1)",
                    color: "#38bdf8",
                    fontWeight: "bold",
                    fontSize: "12px",
                    cursor: "pointer"
                  }}
                >
                  View Events →
                </button>
              </div>
            ))
          )}
        </div>
      )}

      {/* Selected Archived Sim Back Button Header */}
      {viewMode === "previous" && selectedArchivedSimId && (
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px", background: "rgba(56,189,248,0.1)", padding: "8px 12px", borderRadius: "6px" }}>
          <span style={{ fontSize: "12px", color: "#38bdf8", fontWeight: "bold" }}>
            Viewing Archive: <span style={{ fontFamily: "monospace" }}>{selectedArchivedSimId}</span> ({filteredEvents.length} events)
          </span>
          <button
            onClick={() => setSelectedArchivedSimId(null)}
            style={{ padding: "4px 10px", borderRadius: "4px", border: "1px solid #475569", background: "transparent", color: "#f8fafc", fontSize: "11px", cursor: "pointer" }}
          >
            ← Back to Archive List
          </button>
        </div>
      )}

      {/* Event History Table List */}
      {(viewMode === "current" || selectedArchivedSimId) && (
        <div style={{ maxHeight: "420px", overflowY: "auto", display: "flex", flexDirection: "column", gap: "6px" }}>
          {filteredEvents.length === 0 ? (
            <div style={{ padding: "20px", textAlign: "center", opacity: 0.6, fontSize: "12px" }}>
              No matching events found in history buffer.
            </div>
          ) : (
            filteredEvents.slice().reverse().map(evt => {
              const sevStyle = getSeverityBadge(evt.severity);
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
                    {evt.severity?.toUpperCase()}
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
      )}
    </div>
  );
}
