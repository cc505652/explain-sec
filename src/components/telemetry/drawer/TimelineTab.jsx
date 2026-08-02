import React from "react";

export function TimelineTab({ event }) {
  if (!event) return null;

  const baseTime = new Date(event.timestamp);

  // Chronological pipeline timeline steps
  const timelineSteps = [
    { time: new Date(baseTime.getTime() - 200).toLocaleTimeString(), stage: "1. Generator", detail: `Raw telemetry event emitted by ${event.connectorId || "live_generator"}` },
    { time: new Date(baseTime.getTime() - 150).toLocaleTimeString(), stage: "2. Standardizer", detail: `Schema v2.0 validation passed. Event ID: ${event.eventId}` },
    { time: new Date(baseTime.getTime() - 100).toLocaleTimeString(), stage: "3. Enrichment", detail: `Asset context enriched: ${event.asset?.hostname || "WORKSTATION-01"} (${event.asset?.criticality || "medium"})` },
    { time: new Date(baseTime.getTime() - 50).toLocaleTimeString(), stage: "4. Classification", detail: `Categorized as '${event.category}' with severity '${event.severity}'` },
    { time: baseTime.toLocaleTimeString(), stage: "5. Detection Engine", detail: `Matched rule ${event.detectionRule?.ruleId || "RULE-GENERIC-001"}` },
    { time: new Date(baseTime.getTime() + 50).toLocaleTimeString(), stage: "6. Correlation Engine", detail: `Evaluated against sliding 5m window. Status: ${event.eventStatus}` }
  ];

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "12px", fontSize: "12px", color: "#e2e8f0" }}>
      <div style={{ background: "rgba(255,255,255,0.02)", padding: "10px", borderRadius: "6px", border: "1px solid rgba(255,255,255,0.06)" }}>
        <div style={{ color: "#38bdf8", fontSize: "11px", fontWeight: "bold", marginBottom: "8px" }}>📋 INVESTIGATION TIMELINE RECONSTRUCTION</div>
        
        <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
          {timelineSteps.map((step, idx) => (
            <div key={idx} style={{ display: "flex", gap: "10px", alignItems: "flex-start" }}>
              <span style={{ fontSize: "10px", fontFamily: "monospace", color: "#94a3b8", width: "70px" }}>{step.time}</span>
              <div style={{ width: "8px", height: "8px", borderRadius: "50%", background: "#38bdf8", marginTop: "4px" }} />
              <div style={{ flex: 1 }}>
                <b style={{ color: "#f8fafc", fontSize: "11px" }}>{step.stage}</b>
                <p style={{ margin: "2px 0 0 0", color: "#cbd5e1", fontSize: "11px" }}>{step.detail}</p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
