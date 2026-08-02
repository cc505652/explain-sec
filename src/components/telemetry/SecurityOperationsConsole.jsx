import React, { useState, useEffect } from "react";
import { TelemetryHealthHeader } from "./TelemetryHealthHeader.jsx";
import { ConnectorsStatusPanel } from "./ConnectorsStatusPanel.jsx";
import { GeneratorControls } from "./GeneratorControls.jsx";
import { CampaignVisualizer } from "./CampaignVisualizer.jsx";
import { SecurityEventStream } from "./SecurityEventStream.jsx";
import { EventHistoryPanel } from "./EventHistoryPanel.jsx";
import { EventDetailsDrawer } from "./EventDetailsDrawer.jsx";
import { IncidentCorrelationTree } from "./IncidentCorrelationTree.jsx";
import SubmitIssue from "../../SubmitIssue.jsx";
import IssueList from "../../IssueList.jsx";
import { collection, query, orderBy, onSnapshot } from "firebase/firestore";
import { db } from "../../firebase.js";

import { DetectionAnalyticsPanel } from "./DetectionAnalyticsPanel.jsx";

export function SecurityOperationsConsole({ userRole, currentUser }) {
  const [activeTab, setActiveTab] = useState("live_events"); // live_events | event_history | incident_queue | manual_reports | engine_stats
  const [showManualModal, setShowManualModal] = useState(false);
  const [incidents, setIncidents] = useState([]);
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [highlightedIncidentId, setHighlightedIncidentId] = useState(null);

  // Subscribe to Firestore 'issues' collection
  useEffect(() => {
    const q = query(collection(db, "issues"), orderBy("createdAt", "desc"));
    const unsub = onSnapshot(q, (snapshot) => {
      const docs = snapshot.docs.map(d => ({ id: d.id, ...d.data() }));
      setIncidents(docs);
    });
    return unsub;
  }, []);

  // Cross-component Navigation Helpers
  const handleNavigateToIncident = (incidentId) => {
    setSelectedEvent(null);
    setActiveTab("incident_queue");
    setHighlightedIncidentId(incidentId);

    // Scroll to incident item
    setTimeout(() => {
      const el = document.getElementById(`incident-${incidentId}`);
      if (el) {
        el.scrollIntoView({ behavior: "smooth", block: "center" });
      }
    }, 150);
  };

  const handleNavigateToCorrelation = (clusterId) => {
    setSelectedEvent(null);
    setActiveTab("incident_queue");
  };

  return (
    <div style={{ padding: "20px", maxWidth: "1400px", margin: "0 auto" }}>
      {/* Header Banner */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px", flexWrap: "wrap", gap: "12px" }}>
        <div>
          <h1 style={{ margin: 0, fontSize: "22px", color: "var(--text-main, #f8fafc)" }}>
            🛡️ Security Operations Console
          </h1>
          <p style={{ margin: "4px 0 0 0", fontSize: "12px", opacity: 0.7 }}>
            Enterprise Telemetry Ingestion, Event Correlation & Security Operations Feed
          </p>
        </div>

        {/* Navigation Tabs */}
        <div style={{ display: "flex", gap: "6px", background: "#0f172a", padding: "4px", borderRadius: "8px", border: "1px solid #334155", flexWrap: "wrap" }}>
          <button
            onClick={() => setActiveTab("live_events")}
            style={{
              padding: "6px 12px",
              borderRadius: "6px",
              border: "none",
              fontSize: "12px",
              fontWeight: "bold",
              cursor: "pointer",
              background: activeTab === "live_events" ? "#38bdf8" : "transparent",
              color: activeTab === "live_events" ? "#0f172a" : "#94a3b8"
            }}
          >
            📡 Live Events
          </button>
          <button
            onClick={() => setActiveTab("event_history")}
            style={{
              padding: "6px 12px",
              borderRadius: "6px",
              border: "none",
              fontSize: "12px",
              fontWeight: "bold",
              cursor: "pointer",
              background: activeTab === "event_history" ? "#38bdf8" : "transparent",
              color: activeTab === "event_history" ? "#0f172a" : "#94a3b8"
            }}
          >
            📋 Event History
          </button>
          <button
            onClick={() => setActiveTab("incident_queue")}
            style={{
              padding: "6px 12px",
              borderRadius: "6px",
              border: "none",
              fontSize: "12px",
              fontWeight: "bold",
              cursor: "pointer",
              background: activeTab === "incident_queue" ? "#38bdf8" : "transparent",
              color: activeTab === "incident_queue" ? "#0f172a" : "#94a3b8"
            }}
          >
            🚨 Incident Queue ({incidents.length})
          </button>
          <button
            onClick={() => setActiveTab("manual_reports")}
            style={{
              padding: "6px 12px",
              borderRadius: "6px",
              border: "none",
              fontSize: "12px",
              fontWeight: "bold",
              cursor: "pointer",
              background: activeTab === "manual_reports" ? "#38bdf8" : "transparent",
              color: activeTab === "manual_reports" ? "#0f172a" : "#94a3b8"
            }}
          >
            📝 Manual Reports
          </button>
          <button
            onClick={() => setActiveTab("engine_stats")}
            style={{
              padding: "6px 12px",
              borderRadius: "6px",
              border: "none",
              fontSize: "12px",
              fontWeight: "bold",
              cursor: "pointer",
              background: activeTab === "engine_stats" ? "#38bdf8" : "transparent",
              color: activeTab === "engine_stats" ? "#0f172a" : "#94a3b8"
            }}
          >
            ⚙️ Engine Stats
          </button>
        </div>
      </div>

      {/* Persistent Telemetry System Health Header */}
      <TelemetryHealthHeader />

      {/* Live SOC Detection Analytics Panel */}
      <DetectionAnalyticsPanel />

      {/* TAB 1: LIVE EVENTS */}
      {activeTab === "live_events" && (
        <>
          <GeneratorControls onOpenManualModal={() => setShowManualModal(true)} />
          <CampaignVisualizer />
          <SecurityEventStream
            onEventClick={(evt) => setSelectedEvent(evt)}
            onSwitchToHistory={() => setActiveTab("event_history")}
          />
        </>
      )}

      {/* TAB 2: EVENT HISTORY (UNIFIED PANEL) */}
      {activeTab === "event_history" && (
        <EventHistoryPanel onEventClick={(evt) => setSelectedEvent(evt)} />
      )}

      {/* TAB 3: INCIDENT QUEUE */}
      {activeTab === "incident_queue" && (
        <div style={{ background: "var(--card-bg, #1e293b)", padding: "16px", borderRadius: "8px", border: "1px solid var(--border-color, rgba(255,255,255,0.1))" }}>
          <h3 style={{ margin: "0 0 12px 0", fontSize: "14px", color: "var(--text-main, #f8fafc)" }}>
            🚨 Ingested & Generated Incidents ({incidents.length})
          </h3>
          <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
            {incidents.length === 0 ? (
              <div style={{ padding: "20px", textAlign: "center", opacity: 0.6, fontSize: "12px" }}>
                No incidents in queue. Start the Telemetry Generator or submit a manual report.
              </div>
            ) : (
              incidents.map(issue => {
                const isHighlighted = highlightedIncidentId === issue.id;
                return (
                  <div
                    id={`incident-${issue.id}`}
                    key={issue.id}
                    style={{
                      padding: "12px",
                      borderRadius: "6px",
                      background: isHighlighted ? "rgba(56,189,248,0.1)" : "rgba(255,255,255,0.02)",
                      border: isHighlighted ? "2px solid #38bdf8" : "1px solid rgba(255,255,255,0.08)",
                      transition: "all 0.3s ease"
                    }}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                      <div>
                        <b style={{ fontSize: "13px", color: "#f8fafc" }}>{issue.title}</b>
                        <span style={{ fontSize: "11px", color: "#94a3b8", marginLeft: "10px" }}>
                          Location: <b>{issue.location}</b> | Urgency: <b style={{ color: issue.urgency === "critical" ? "#ef4444" : "#f59e0b" }}>{issue.urgency?.toUpperCase()}</b>
                        </span>
                      </div>
                      <span style={{ fontSize: "10px", background: "rgba(139,92,246,0.2)", padding: "2px 8px", borderRadius: "4px", color: "#8b5cf6", fontWeight: "bold" }}>
                        Source: {issue.createdBy || "telemetry"}
                      </span>
                    </div>
                    <p style={{ margin: "6px 0 0 0", fontSize: "12px", color: "#cbd5e1" }}>{issue.description}</p>
                    
                    {/* SIEM Expandable Correlation Breakdown Tree */}
                    <IncidentCorrelationTree incident={issue} />
                  </div>
                );
              })
            )}
          </div>
        </div>
      )}

      {/* TAB 4: MANUAL REPORTS (Preserving Original Student Workflow) */}
      {activeTab === "manual_reports" && (
        <div style={{ background: "var(--card-bg, #1e293b)", padding: "16px", borderRadius: "8px", border: "1px solid var(--border-color, rgba(255,255,255,0.1))" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
            <h3 style={{ margin: 0, fontSize: "14px", color: "var(--text-main, #f8fafc)" }}>
              📝 Manual Incident Reporting
            </h3>
            <button
              onClick={() => setShowManualModal(true)}
              style={{ padding: "6px 12px", borderRadius: "6px", border: "none", background: "#8b5cf6", color: "#fff", fontWeight: "bold", fontSize: "12px", cursor: "pointer" }}
            >
              + Submit Manual Incident
            </button>
          </div>
          <IssueList userRole={userRole} currentUser={currentUser} />
        </div>
      )}

      {/* TAB 5: ENGINE STATS & SETTINGS */}
      {activeTab === "engine_stats" && (
        <>
          <GeneratorControls onOpenManualModal={() => setShowManualModal(true)} />
          <ConnectorsStatusPanel />
        </>
      )}

      {/* Interactive Slide-over Event Details Drawer */}
      {selectedEvent && (
        <EventDetailsDrawer
          event={selectedEvent}
          onClose={() => setSelectedEvent(null)}
          onNavigateToCorrelation={handleNavigateToCorrelation}
          onNavigateToIncident={handleNavigateToIncident}
        />
      )}

      {/* Modal Dialog for Manual Submission */}
      {showManualModal && (
        <div style={{
          position: "fixed",
          top: 0, left: 0, right: 0, bottom: 0,
          background: "rgba(0,0,0,0.7)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          zIndex: 9999
        }}>
          <div style={{
            background: "#1e293b",
            padding: "20px",
            borderRadius: "12px",
            maxWidth: "600px",
            width: "90%",
            maxHeight: "90vh",
            overflowY: "auto",
            position: "relative"
          }}>
            <button
              onClick={() => setShowManualModal(false)}
              style={{ position: "absolute", top: "12px", right: "12px", border: "none", background: "transparent", color: "#fff", fontSize: "16px", cursor: "pointer" }}
            >
              ✕
            </button>
            <SubmitIssue userRole={userRole} currentUser={currentUser} onSuccess={() => setShowManualModal(false)} />
          </div>
        </div>
      )}
    </div>
  );
}
