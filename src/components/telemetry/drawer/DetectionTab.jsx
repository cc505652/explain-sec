import React from "react";

export function DetectionTab({ event }) {
  if (!event) return null;

  const rule = event.detectionRule || {};
  const mitre = event.mitreTechnique || {};

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "12px", fontSize: "12px", color: "#e2e8f0" }}>
      {/* Rule Info Card */}
      <div style={{ background: "rgba(139,92,246,0.1)", padding: "12px", borderRadius: "6px", border: "1px solid rgba(139,92,246,0.3)" }}>
        <div style={{ color: "#a78bfa", fontSize: "11px", fontWeight: "bold", marginBottom: "4px" }}>DETECTION RULE METADATA</div>
        <div style={{ fontSize: "14px", fontWeight: "bold", color: "#f8fafc" }}>{rule.ruleName || "Generic Detection Rule"}</div>
        <div style={{ color: "#cbd5e1", fontSize: "11px", marginTop: "4px" }}>Rule ID: <span style={{ fontFamily: "monospace", color: "#a78bfa" }}>{rule.ruleId || "RULE-GENERIC-001"}</span> | Version: {rule.ruleVersion || "1.0"}</div>
      </div>

      {/* MITRE ATT&CK Card */}
      <div style={{ background: "rgba(245,158,11,0.1)", padding: "12px", borderRadius: "6px", border: "1px solid rgba(245,158,11,0.3)" }}>
        <div style={{ color: "#fbbf24", fontSize: "11px", fontWeight: "bold", marginBottom: "6px" }}>🎯 MITRE ATT&CK MAPPING</div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px" }}>
          <div>
            <span style={{ color: "#94a3b8" }}>Technique ID:</span>
            <div style={{ fontWeight: "bold", color: "#fbbf24", fontFamily: "monospace" }}>{mitre.id || "T1059"}</div>
          </div>
          <div>
            <span style={{ color: "#94a3b8" }}>Tactic:</span>
            <div style={{ fontWeight: "bold", color: "#f8fafc" }}>{mitre.tactic || "Execution"}</div>
          </div>
        </div>
        <div style={{ marginTop: "8px" }}>
          <span style={{ color: "#94a3b8" }}>Technique Name:</span>
          <div style={{ fontWeight: "bold", color: "#f8fafc" }}>{mitre.name || "Command and Scripting Interpreter"}</div>
        </div>
      </div>

      {/* Additional Rule Details */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px" }}>
        <div>
          <span style={{ color: "#94a3b8" }}>Detection Threshold:</span>
          <div style={{ fontWeight: "bold" }}>{rule.threshold || "1 event"}</div>
        </div>
        <div>
          <span style={{ color: "#94a3b8" }}>Rule Author:</span>
          <div style={{ fontWeight: "bold" }}>{rule.author || "ExplainSec Telemetry Engine"}</div>
        </div>
      </div>
    </div>
  );
}
