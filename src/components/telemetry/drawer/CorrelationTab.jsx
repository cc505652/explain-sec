import React from "react";
import { memoryClusterRepository } from "../../../telemetry/correlator/clusterRepository.js";

import { DynamicCorrelationGraph } from "./DynamicCorrelationGraph.jsx";

export function CorrelationTab({ event, onNavigateToCorrelation, onNavigateToIncident }) {
  if (!event) return null;

  // Search cluster repository for matching cluster
  const cluster = event.campaignId 
    ? memoryClusterRepository.findActiveByCampaign(event.campaignId)
    : memoryClusterRepository.findActiveByRuleAndAsset(event.detectionRule?.ruleId, event.asset?.hostname);

  const clusterId = cluster?.clusterId || `cluster_evt_${event.eventId.substring(4, 12)}`;
  const status = cluster?.status || (event.eventStatus === "promoted" ? "INCIDENT_CREATED" : (event.eventStatus === "suppressed" ? "SUPPRESSED" : "CORRELATING"));
  const riskScore = cluster?.riskScore || (event.severity === "critical" ? 85 : (event.severity === "high" ? 72 : 45));
  const isQualified = cluster?.incidentQualified || event.eventStatus === "promoted" || riskScore >= 60;
  const qualReason = cluster?.qualificationReason || (isQualified ? "Risk score threshold crossed" : "Noise below threshold");
  const explanation = cluster?.explanation || [
    `Matched ${event.detectionRule?.ruleId || "Detection Rule"}`,
    `Primary Endpoint: ${event.asset?.hostname || "WORKSTATION-01"}`,
    `Risk Score: ${riskScore}/100`,
    `Qualification Status: ${isQualified ? "QUALIFIED" : "SUPPRESSED"} (${qualReason})`
  ];

  const incidentId = cluster?.incidentId || (event.eventStatus === "promoted" ? "inc_sim_generated" : null);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "12px", fontSize: "12px", color: "#e2e8f0" }}>
      {/* Cluster Overview Header */}
      <div style={{ background: "rgba(16,185,129,0.08)", padding: "12px", borderRadius: "6px", border: "1px solid rgba(16,185,129,0.2)" }}>
        <div style={{ color: "#10b981", fontSize: "11px", fontWeight: "bold", marginBottom: "4px" }}>CORRELATION CLUSTER SUMMARY</div>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <span style={{ fontSize: "13px", fontWeight: "bold", fontFamily: "monospace", color: "#38bdf8" }}>{clusterId}</span>
          <span style={{ padding: "2px 8px", borderRadius: "4px", fontSize: "10px", fontWeight: "bold", background: isQualified ? "rgba(16,185,129,0.2)" : "rgba(239,68,68,0.2)", color: isQualified ? "#10b981" : "#ef4444" }}>
            {status}
          </span>
        </div>
      </div>

      {/* Risk & Qualification */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px" }}>
        <div>
          <span style={{ color: "#94a3b8" }}>Cluster Risk Score:</span>
          <div style={{ fontSize: "16px", fontWeight: "bold", color: riskScore >= 75 ? "#ef4444" : "#f59e0b" }}>
            {riskScore} / 100
          </div>
        </div>

        <div>
          <span style={{ color: "#94a3b8" }}>Incident Qualified:</span>
          <div style={{ fontWeight: "bold", color: isQualified ? "#10b981" : "#ef4444" }}>
            {isQualified ? "✓ Qualified" : "✗ Suppressed"}
          </div>
        </div>
      </div>

      {/* Qualification Reason */}
      <div style={{ background: "rgba(255,255,255,0.02)", padding: "8px 10px", borderRadius: "4px", borderLeft: "3px solid #38bdf8" }}>
        <span style={{ color: "#94a3b8", fontSize: "11px" }}>Qualification Reason:</span>
        <div style={{ color: "#f8fafc", fontWeight: "bold", marginTop: "2px" }}>{qualReason}</div>
      </div>

      {/* Explanation Bullets */}
      <div>
        <div style={{ color: "#94a3b8", fontSize: "11px", fontWeight: "bold", marginBottom: "4px" }}>CORRELATION EXPLAINABILITY</div>
        <ul style={{ margin: 0, paddingLeft: "18px", color: "#cbd5e1", fontSize: "11px", display: "flex", flexDirection: "column", gap: "4px" }}>
          {explanation.map((item, idx) => (
            <li key={idx}>{item}</li>
          ))}
        </ul>
      </div>

      {/* Dynamic Entity Graph */}
      <DynamicCorrelationGraph event={event} />

      {/* Navigation Triggers */}
      <div style={{ display: "flex", gap: "8px", marginTop: "4px" }}>
        <button
          onClick={() => onNavigateToCorrelation?.(clusterId)}
          style={{ flex: 1, padding: "6px 10px", borderRadius: "4px", border: "1px solid #38bdf8", background: "rgba(56,189,248,0.1)", color: "#38bdf8", fontSize: "11px", fontWeight: "bold", cursor: "pointer" }}
        >
          🔍 Jump to Cluster
        </button>
        {incidentId && (
          <button
            onClick={() => onNavigateToIncident?.(incidentId)}
            style={{ flex: 1, padding: "6px 10px", borderRadius: "4px", border: "1px solid #10b981", background: "rgba(16,185,129,0.1)", color: "#10b981", fontSize: "11px", fontWeight: "bold", cursor: "pointer" }}
          >
            🚨 Open Incident Queue
          </button>
        )}
      </div>
    </div>
  );
}
