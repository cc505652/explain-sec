import React, { useState, useEffect } from "react";
import { PipelineStepper } from "./drawer/PipelineStepper.jsx";
import { OverviewTab } from "./drawer/OverviewTab.jsx";
import { DetectionTab } from "./drawer/DetectionTab.jsx";
import { EvidenceTab } from "./drawer/EvidenceTab.jsx";
import { AssetTab } from "./drawer/AssetTab.jsx";
import { CorrelationTab } from "./drawer/CorrelationTab.jsx";
import { TimelineTab } from "./drawer/TimelineTab.jsx";
import { RawEventTab } from "./drawer/RawEventTab.jsx";
import { ActionBar } from "./drawer/ActionBar.jsx";

export function EventDetailsDrawer({ event, onClose, onNavigateToCorrelation, onNavigateToIncident }) {
  const [activeTab, setActiveTab] = useState("overview"); // overview | detection | evidence | asset | correlation | timeline | raw

  // Handle ESC key listener
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === "Escape") {
        onClose?.();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [onClose]);

  if (!event) return null;

  const tabs = [
    { id: "overview", label: "Overview" },
    { id: "detection", label: "Detection" },
    { id: "evidence", label: "Evidence" },
    { id: "asset", label: "Asset" },
    { id: "correlation", label: "Correlation" },
    { id: "timeline", label: "Timeline" },
    { id: "raw", label: "Raw Event" }
  ];

  return (
    <div style={{
      position: "fixed",
      top: 0, left: 0, right: 0, bottom: 0,
      background: "rgba(0, 0, 0, 0.65)",
      backdropFilter: "blur(2px)",
      zIndex: 9999,
      display: "flex",
      justifyContent: "flex-end",
      animation: "fadeIn 200ms ease-out"
    }} onClick={onClose}>
      {/* Drawer Panel Container */}
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          width: "450px",
          maxWidth: "95vw",
          height: "100vh",
          background: "#1e293b",
          borderLeft: "1px solid #334155",
          display: "flex",
          flexDirection: "column",
          boxShadow: "-8px 0 24px rgba(0,0,0,0.5)",
          animation: "slideIn 250ms ease-out"
        }}
      >
        {/* Top Header */}
        <div style={{
          padding: "14px 16px",
          borderBottom: "1px solid #334155",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          background: "#0f172a"
        }}>
          <div>
            <div style={{ fontSize: "14px", fontWeight: "bold", color: "#f8fafc", display: "flex", alignItems: "center", gap: "6px" }}>
              <span>🔍 Security Event Investigation</span>
            </div>
            <div style={{ fontSize: "11px", color: "#94a3b8", fontFamily: "monospace", marginTop: "2px" }}>
              {event.eventId}
            </div>
          </div>
          <button
            onClick={onClose}
            style={{
              background: "transparent",
              border: "none",
              color: "#94a3b8",
              fontSize: "18px",
              cursor: "pointer",
              padding: "4px 8px"
            }}
          >
            ✕
          </button>
        </div>

        {/* Scrollable Content Body */}
        <div style={{ flex: 1, overflowY: "auto", padding: "16px" }}>
          {/* Animated Pipeline Stepper */}
          <PipelineStepper eventStatus={event.eventStatus || "promoted"} severity={event.severity} />

          {/* Navigation Tab Bar */}
          <div style={{
            display: "flex",
            gap: "2px",
            background: "#0f172a",
            padding: "3px",
            borderRadius: "6px",
            border: "1px solid #334155",
            marginBottom: "16px",
            overflowX: "auto"
          }}>
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                style={{
                  padding: "5px 9px",
                  borderRadius: "4px",
                  border: "none",
                  fontSize: "11px",
                  fontWeight: "bold",
                  cursor: "pointer",
                  whiteSpace: "nowrap",
                  background: activeTab === tab.id ? "#38bdf8" : "transparent",
                  color: activeTab === tab.id ? "#0f172a" : "#94a3b8",
                  transition: "all 0.15s ease"
                }}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* Tab Content Display */}
          {activeTab === "overview" && <OverviewTab event={event} />}
          {activeTab === "detection" && <DetectionTab event={event} />}
          {activeTab === "evidence" && <EvidenceTab event={event} />}
          {activeTab === "asset" && <AssetTab event={event} />}
          {activeTab === "correlation" && (
            <CorrelationTab
              event={event}
              onNavigateToCorrelation={onNavigateToCorrelation}
              onNavigateToIncident={onNavigateToIncident}
            />
          )}
          {activeTab === "timeline" && <TimelineTab event={event} />}
          {activeTab === "raw" && <RawEventTab event={event} />}
        </div>

        {/* Bottom Sentinel Action Bar */}
        <ActionBar
          event={event}
          onNavigateToCorrelation={onNavigateToCorrelation}
          onNavigateToIncident={onNavigateToIncident}
          onSelectTab={setActiveTab}
        />
      </div>

      <style>{`
        @keyframes fadeIn {
          from { opacity: 0; }
          to { opacity: 1; }
        }
        @keyframes slideIn {
          from { transform: translateX(100%); }
          to { transform: translateX(0); }
        }
      `}</style>
    </div>
  );
}
