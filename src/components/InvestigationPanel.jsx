/**
 * ======================================================================
 * CAMPUS SOC — INVESTIGATION PANEL (Phase 6)
 * ======================================================================
 *
 * Deep-dive investigation workspace for individual incidents.
 * Features:
 * - Evidence timeline with visual chronology
 * - MITRE ATT&CK mapping display
 * - Risk score visualization
 * - Investigation notes (via Cloud Function)
 * - Evidence attachment (via Cloud Function)
 * - Tag management (via Cloud Function)
 * - Attack stage classification
 * ======================================================================
 */

import React, { useState, useMemo, useCallback } from "react";
import { auth } from "../firebase";
import {
  callAddEvidence,
  callUpdateTags,
  callUpdateRiskScore,
} from "../utils/socFunctions";
import {
  computeRiskScore,
  computeConfidenceScore,
  getRiskPill,
  getAttackStageDisplay,
  getMitreInfo,
  getIncidentAging,
  ATTACK_STAGE_OPTIONS,
  MITRE_MAPPING,
} from "../utils/riskEngine";
import { STATUS_LABELS } from "../utils/incidentStateGuard";
import { computeSLA } from "../utils/slaEngine";

/* ─── STYLES ─────────────────────────────────────────────────────────────── */

const panelStyle = {
  background: "rgba(15, 23, 42, 0.75)",
  backdropFilter: "blur(16px)",
  border: "1px solid rgba(255,255,255,0.08)",
  borderRadius: 20,
  padding: 24,
  boxShadow: "0 8px 32px rgba(0,0,0,0.36)",
  marginBottom: 16,
};

const sectionTitle = {
  fontSize: 14,
  fontWeight: 700,
  color: "#e2e8f0",
  marginBottom: 12,
  display: "flex",
  alignItems: "center",
  gap: 8,
};

const tagStyle = (bg = "rgba(6,182,212,0.15)", fg = "#06b6d4") => ({
  display: "inline-flex",
  alignItems: "center",
  gap: 4,
  padding: "3px 10px",
  borderRadius: 999,
  background: bg,
  color: fg,
  fontSize: 11,
  fontWeight: 700,
});

const inputStyle = {
  padding: "8px 12px",
  borderRadius: 10,
  background: "rgba(255,255,255,0.06)",
  border: "1px solid rgba(255,255,255,0.12)",
  color: "#fff",
  fontSize: 12,
  outline: "none",
  width: "100%",
};

const btnStyle = (bg = "var(--primary)", color = "#fff") => ({
  padding: "6px 14px",
  borderRadius: 8,
  background: bg,
  color,
  border: "none",
  cursor: "pointer",
  fontSize: 12,
  fontWeight: 700,
});

/* ─── EVIDENCE TIMELINE ──────────────────────────────────────────────────── */

function EvidenceTimeline({ events = [] }) {
  if (events.length === 0) {
    return <div style={{ color: "#64748b", fontSize: 12, padding: 12 }}>No timeline events yet</div>;
  }

  const sorted = [...events].sort((a, b) => {
    const aTime = a.at?.toMillis?.() || a.at?.seconds * 1000 || new Date(a.at).getTime() || 0;
    const bTime = b.at?.toMillis?.() || b.at?.seconds * 1000 || new Date(b.at).getTime() || 0;
    return bTime - aTime;
  });

  const getIcon = (status) => {
    const icons = {
      open: "🟢", assigned: "👤", in_progress: "🔄", resolved: "✅",
      escalated: "🚨", ESCALATION_REQUESTED: "🚨", escalation_pending: "⏳",
      escalation_approved: "✅", ir_in_progress: "🔍", containment_pending: "🛡️",
      contained: "🔒", false_positive: "❌", severity_adjusted: "⚡",
      tags_updated: "🏷️", evidence_added: "📎", risk_updated: "📊",
      approval_requested: "📋", approval_approved: "✅", approval_denied: "❌",
      GOVERNANCE_LOCKED: "🔐", GOVERNANCE_UNLOCKED: "🔓",
    };
    return icons[status] || "📌";
  };

  return (
    <div style={{ maxHeight: 400, overflowY: "auto", paddingRight: 8 }}>
      {sorted.map((event, i) => {
        const time = event.at?.toMillis?.() || event.at?.seconds * 1000 || new Date(event.at).getTime() || 0;
        const timeStr = time ? new Date(time).toLocaleString() : "—";
        
        return (
          <div key={i} style={{
            display: "flex", gap: 12, marginBottom: 2,
            padding: "8px 0",
            borderLeft: "2px solid rgba(6,182,212,0.2)",
            paddingLeft: 16,
            position: "relative",
          }}>
            <div style={{
              position: "absolute", left: -8,
              width: 14, height: 14, borderRadius: "50%",
              background: "#0f172a", border: "2px solid #06b6d4",
              display: "flex", alignItems: "center", justifyContent: "center",
              fontSize: 8,
            }}>
              {i === 0 && <div style={{ width: 6, height: 6, borderRadius: "50%", background: "#06b6d4" }} />}
            </div>
            <div style={{ flex: 1 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontWeight: 600, color: "#e2e8f0", fontSize: 12 }}>
                  {getIcon(event.status)} {event.status?.replace(/_/g, " ")}
                </span>
                <span style={{ fontSize: 10, color: "#64748b" }}>{timeStr}</span>
              </div>
              {event.note && (
                <div style={{ fontSize: 11, color: "#94a3b8", marginTop: 2 }}>{event.note}</div>
              )}
              {event.by && (
                <div style={{ fontSize: 10, color: "#475569", marginTop: 1 }}>by {event.by}</div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}

/* ─── MITRE DISPLAY ──────────────────────────────────────────────────────── */

function MitreDisplay({ category, attackStage }) {
  const mitre = getMitreInfo(category);
  const stage = attackStage ? getAttackStageDisplay(attackStage) : null;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      {mitre && (
        <div style={{
          padding: "12px 16px", borderRadius: 12,
          background: "rgba(139,92,246,0.08)",
          border: "1px solid rgba(139,92,246,0.2)",
        }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: "#8b5cf6", marginBottom: 4 }}>
            MITRE ATT&CK Mapping
          </div>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <span style={tagStyle("rgba(139,92,246,0.2)", "#a78bfa")}>
              {mitre.tactic}
            </span>
            <span style={tagStyle("rgba(139,92,246,0.2)", "#a78bfa")}>
              {mitre.technique}
            </span>
            <span style={{ fontSize: 12, color: "#c4b5fd" }}>{mitre.name}</span>
          </div>
        </div>
      )}
      {stage && (
        <div style={{
          padding: "12px 16px", borderRadius: 12,
          background: `${stage.color}11`,
          border: `1px solid ${stage.color}44`,
        }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: stage.color, marginBottom: 4 }}>
            Kill Chain Stage
          </div>
          <div style={{ fontSize: 14, fontWeight: 700, color: stage.color }}>
            🎯 {stage.label} (#{stage.order}/7)
          </div>
          <div style={{
            width: "100%", height: 6, borderRadius: 3,
            background: "rgba(255,255,255,0.06)", marginTop: 6,
          }}>
            <div style={{
              width: `${(stage.order / 7) * 100}%`,
              height: "100%", borderRadius: 3,
              background: `linear-gradient(90deg, #10b981, ${stage.color})`,
              transition: "width 0.5s ease",
            }} />
          </div>
        </div>
      )}
      {!mitre && !stage && (
        <div style={{ color: "#64748b", fontSize: 12 }}>No MITRE mapping available</div>
      )}
    </div>
  );
}

/* ─── EVIDENCE LIST ──────────────────────────────────────────────────────── */

function EvidenceList({ evidence = [] }) {
  if (evidence.length === 0) {
    return <div style={{ color: "#64748b", fontSize: 12, padding: 8 }}>No evidence attached</div>;
  }

  const typeIcons = { file: "📄", link: "🔗", note: "📝", screenshot: "📸" };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
      {evidence.map((ev, i) => (
        <div key={ev.id || i} style={{
          display: "flex", alignItems: "center", gap: 10,
          padding: "8px 12px", borderRadius: 10,
          background: "rgba(255,255,255,0.03)",
          border: "1px solid rgba(255,255,255,0.06)",
        }}>
          <span style={{ fontSize: 18 }}>{typeIcons[ev.type] || "📎"}</span>
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 12, fontWeight: 600, color: "#e2e8f0" }}>
              {ev.description || ev.type}
            </div>
            {ev.url && (
              <a href={ev.url} target="_blank" rel="noopener noreferrer"
                style={{ fontSize: 11, color: "#06b6d4", textDecoration: "none" }}>
                {ev.url.slice(0, 60)}...
              </a>
            )}
            {ev.content && !ev.url && (
              <div style={{ fontSize: 11, color: "#94a3b8", marginTop: 2 }}>
                {ev.content.slice(0, 120)}{ev.content.length > 120 ? "..." : ""}
              </div>
            )}
          </div>
          <div style={{ fontSize: 10, color: "#475569", textAlign: "right" }}>
            <div>{ev.addedByRole || ""}</div>
            <div>{ev.addedAt ? new Date(ev.addedAt).toLocaleDateString() : ""}</div>
          </div>
        </div>
      ))}
    </div>
  );
}

/* ─── MAIN COMPONENT ─────────────────────────────────────────────────────── */

export default function InvestigationPanel({ issue, onClose }) {
  const [newTag, setNewTag] = useState("");
  const [evidenceType, setEvidenceType] = useState("note");
  const [evidenceContent, setEvidenceContent] = useState("");
  const [evidenceDesc, setEvidenceDesc] = useState("");
  const [selectedStage, setSelectedStage] = useState(issue.attackStage || "");
  const [loading, setLoading] = useState(false);
  const [toast, setToast] = useState("");

  // Computed values
  const risk = useMemo(() => computeRiskScore({
    urgency: issue.urgency,
    attackStage: issue.attackStage,
    confidenceScore: issue.confidenceScore || 50,
    escalated: issue.escalated,
    slaBreached: computeSLA(issue).breached,
  }), [issue]);

  const confidence = useMemo(() => computeConfidenceScore({
    aiEngine: issue.aiEngine || null,
    evidenceCount: (issue.evidenceList || []).length,
    hasMitreMatch: !!getMitreInfo(issue.category),
    analystConfirmed: issue.triageStatus === "confirmed_threat",
  }), [issue]);

  const aging = useMemo(() => getIncidentAging(issue.createdAt), [issue.createdAt]);
  const riskPill = getRiskPill(issue.riskScore ?? risk.score);
  const sla = computeSLA(issue);
  const tags = issue.tags || [];

  const showToast = (msg) => {
    setToast(msg);
    setTimeout(() => setToast(""), 3000);
  };

  // Handlers
  const handleAddTag = useCallback(async () => {
    if (!newTag.trim()) return;
    setLoading(true);
    try {
      const updatedTags = [...tags, ...newTag.split(",").map(t => t.trim()).filter(Boolean)];
      await callUpdateTags(issue.id, updatedTags);
      showToast("✅ Tags updated");
      setNewTag("");
    } catch (err) {
      alert("Failed to update tags: " + (err?.message || ""));
    } finally {
      setLoading(false);
    }
  }, [newTag, tags, issue.id]);

  const handleRemoveTag = useCallback(async (tagToRemove) => {
    setLoading(true);
    try {
      await callUpdateTags(issue.id, tags.filter(t => t !== tagToRemove));
      showToast("✅ Tag removed");
    } catch (err) {
      alert("Failed to remove tag: " + (err?.message || ""));
    } finally {
      setLoading(false);
    }
  }, [tags, issue.id]);

  const handleAddEvidence = useCallback(async () => {
    if (!evidenceContent.trim()) return;
    setLoading(true);
    try {
      await callAddEvidence(issue.id, {
        type: evidenceType,
        content: evidenceType === "note" ? evidenceContent : null,
        url: evidenceType === "link" ? evidenceContent : null,
        description: evidenceDesc || `${evidenceType} evidence`,
      });
      showToast("✅ Evidence added");
      setEvidenceContent("");
      setEvidenceDesc("");
    } catch (err) {
      alert("Failed to add evidence: " + (err?.message || ""));
    } finally {
      setLoading(false);
    }
  }, [evidenceType, evidenceContent, evidenceDesc, issue.id]);

  const handleUpdateStage = useCallback(async () => {
    if (!selectedStage) return;
    setLoading(true);
    try {
      const newRisk = computeRiskScore({
        urgency: issue.urgency,
        attackStage: selectedStage,
        confidenceScore: confidence,
        escalated: issue.escalated,
        slaBreached: sla.breached,
      });
      await callUpdateRiskScore(issue.id, {
        attackStage: selectedStage,
        riskScore: newRisk.score,
        confidenceScore: confidence,
      });
      showToast("✅ Attack stage & risk updated");
    } catch (err) {
      alert("Failed to update: " + (err?.message || ""));
    } finally {
      setLoading(false);
    }
  }, [selectedStage, issue, confidence, sla.breached]);

  return (
    <div style={{
      position: "fixed", top: 0, left: 0, right: 0, bottom: 0,
      background: "rgba(0,0,0,0.7)", backdropFilter: "blur(4px)",
      zIndex: 9999, display: "flex", justifyContent: "center",
      alignItems: "flex-start", padding: "40px 20px",
      overflowY: "auto",
    }}>
      <div style={{ maxWidth: 900, width: "100%" }}>
        {/* Toast */}
        {toast && (
          <div style={{
            position: "fixed", top: 20, right: 20,
            padding: "10px 20px", borderRadius: 12,
            background: "rgba(16,185,129,0.9)", color: "#fff",
            fontWeight: 700, fontSize: 13, zIndex: 10000,
          }}>{toast}</div>
        )}

        {/* Header */}
        <div style={{
          ...panelStyle,
          display: "flex", justifyContent: "space-between", alignItems: "flex-start",
        }}>
          <div style={{ flex: 1 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
              <h2 style={{
                margin: 0, fontSize: 20, fontWeight: 800,
                fontFamily: "'Space Grotesk', sans-serif", color: "#e2e8f0",
              }}>
                🔍 {issue.title}
              </h2>
              <span style={{
                padding: "3px 10px", borderRadius: 999,
                background: riskPill.bg, color: riskPill.color,
                fontSize: 11, fontWeight: 700,
              }}>
                Risk: {issue.riskScore ?? risk.score} — {riskPill.label}
              </span>
            </div>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 8 }}>
              <span style={tagStyle()}>{STATUS_LABELS[issue.status] || issue.status}</span>
              <span style={tagStyle("rgba(245,158,11,0.15)", "#f59e0b")}>{issue.urgency}</span>
              <span style={tagStyle("rgba(139,92,246,0.15)", "#8b5cf6")}>{issue.category}</span>
              <span style={tagStyle(`${aging.color}22`, aging.color)}>
                {aging.label} ({Math.round(aging.ageHours)}h)
              </span>
              <span style={tagStyle(`${sla.color}22`, sla.color)}>{sla.label}</span>
            </div>
            <div style={{ fontSize: 12, color: "#94a3b8" }}>
              ID: {issue.id} • Assigned: {issue.assignedTo || "Unassigned"} • Confidence: {confidence}%
            </div>
          </div>
          <button onClick={onClose} style={{
            ...btnStyle("rgba(239,68,68,0.2)", "#ef4444"),
            fontSize: 18, padding: "4px 12px",
          }}>✕</button>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
          {/* Left Column */}
          <div>
            {/* Timeline */}
            <div style={panelStyle}>
              <div style={sectionTitle}>📅 Investigation Timeline</div>
              <EvidenceTimeline events={issue.statusHistory || []} />
            </div>

            {/* Evidence */}
            <div style={panelStyle}>
              <div style={sectionTitle}>📎 Evidence ({(issue.evidenceList || []).length})</div>
              <EvidenceList evidence={issue.evidenceList || []} />
              
              {/* Add Evidence Form */}
              <div style={{ marginTop: 12, padding: "12px 16px", borderRadius: 12, background: "rgba(255,255,255,0.03)" }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: "#64748b", marginBottom: 8 }}>ADD EVIDENCE</div>
                <div style={{ display: "flex", gap: 8, marginBottom: 8 }}>
                  <select
                    value={evidenceType}
                    onChange={e => setEvidenceType(e.target.value)}
                    style={{ ...inputStyle, width: "auto" }}
                  >
                    <option value="note">📝 Note</option>
                    <option value="link">🔗 Link</option>
                    <option value="file">📄 File Ref</option>
                    <option value="screenshot">📸 Screenshot</option>
                  </select>
                  <input
                    placeholder="Description"
                    value={evidenceDesc}
                    onChange={e => setEvidenceDesc(e.target.value)}
                    style={inputStyle}
                  />
                </div>
                <div style={{ display: "flex", gap: 8 }}>
                  <input
                    placeholder={evidenceType === "link" ? "URL..." : "Content..."}
                    value={evidenceContent}
                    onChange={e => setEvidenceContent(e.target.value)}
                    style={{ ...inputStyle, flex: 1 }}
                  />
                  <button
                    onClick={handleAddEvidence}
                    disabled={loading || !evidenceContent.trim()}
                    style={btnStyle()}
                  >
                    {loading ? "..." : "+ Add"}
                  </button>
                </div>
              </div>
            </div>
          </div>

          {/* Right Column */}
          <div>
            {/* MITRE & Kill Chain */}
            <div style={panelStyle}>
              <div style={sectionTitle}>🎯 MITRE ATT&CK Analysis</div>
              <MitreDisplay category={issue.category} attackStage={issue.attackStage} />
              
              {/* Attack Stage Selector */}
              <div style={{ marginTop: 12, display: "flex", gap: 8, alignItems: "center" }}>
                <select
                  value={selectedStage}
                  onChange={e => setSelectedStage(e.target.value)}
                  style={{ ...inputStyle, width: "auto", flex: 1 }}
                >
                  <option value="">Select stage...</option>
                  {ATTACK_STAGE_OPTIONS.map(s => (
                    <option key={s.value} value={s.value}>#{s.order} {s.label}</option>
                  ))}
                </select>
                <button
                  onClick={handleUpdateStage}
                  disabled={loading || !selectedStage}
                  style={btnStyle("rgba(139,92,246,0.8)")}
                >
                  Update
                </button>
              </div>
            </div>

            {/* Tags */}
            <div style={panelStyle}>
              <div style={sectionTitle}>🏷️ Tags</div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginBottom: 10 }}>
                {tags.length === 0 && <span style={{ color: "#64748b", fontSize: 12 }}>No tags</span>}
                {tags.map(t => (
                  <span key={t} style={tagStyle()}>
                    {t}
                    <button
                      onClick={() => handleRemoveTag(t)}
                      style={{ background: "none", border: "none", color: "#06b6d4", cursor: "pointer", fontSize: 12 }}
                    >×</button>
                  </span>
                ))}
              </div>
              <div style={{ display: "flex", gap: 8 }}>
                <input
                  placeholder="Add tags (comma-separated)"
                  value={newTag}
                  onChange={e => setNewTag(e.target.value)}
                  onKeyDown={e => e.key === "Enter" && handleAddTag()}
                  style={{ ...inputStyle, flex: 1 }}
                />
                <button onClick={handleAddTag} disabled={loading} style={btnStyle()}>
                  {loading ? "..." : "+ Tag"}
                </button>
              </div>
            </div>

            {/* Risk Details */}
            <div style={panelStyle}>
              <div style={sectionTitle}>📊 Risk Assessment</div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                <div style={{
                  padding: 16, borderRadius: 12,
                  background: `${risk.color}11`, border: `1px solid ${risk.color}33`,
                  textAlign: "center",
                }}>
                  <div style={{ fontSize: 32, fontWeight: 800, color: risk.color }}>{issue.riskScore ?? risk.score}</div>
                  <div style={{ fontSize: 11, color: "#94a3b8" }}>Risk Score</div>
                </div>
                <div style={{
                  padding: 16, borderRadius: 12,
                  background: "rgba(6,182,212,0.08)", border: "1px solid rgba(6,182,212,0.2)",
                  textAlign: "center",
                }}>
                  <div style={{ fontSize: 32, fontWeight: 800, color: "#06b6d4" }}>{confidence}</div>
                  <div style={{ fontSize: 11, color: "#94a3b8" }}>Confidence</div>
                </div>
              </div>

              {/* Risk Factors */}
              <div style={{ marginTop: 12, display: "flex", flexDirection: "column", gap: 4 }}>
                <div style={{ fontSize: 11, color: "#64748b", fontWeight: 700 }}>RISK FACTORS</div>
                {[
                  { label: "Urgency", value: issue.urgency, active: ["high", "critical"].includes(issue.urgency) },
                  { label: "Escalated", value: issue.escalated ? "Yes" : "No", active: issue.escalated },
                  { label: "SLA Breached", value: sla.breached ? "Yes" : "No", active: sla.breached },
                  { label: "Kill Chain", value: issue.attackStage?.replace(/_/g, " ") || "—", active: !!issue.attackStage },
                ].map(f => (
                  <div key={f.label} style={{
                    display: "flex", justifyContent: "space-between",
                    padding: "4px 8px", borderRadius: 6,
                    background: f.active ? "rgba(239,68,68,0.06)" : "transparent",
                  }}>
                    <span style={{ fontSize: 12, color: "#94a3b8" }}>{f.label}</span>
                    <span style={{ fontSize: 12, fontWeight: 700, color: f.active ? "#ef4444" : "#64748b" }}>
                      {f.value}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* Incident Description */}
            <div style={panelStyle}>
              <div style={sectionTitle}>📋 Description</div>
              <div style={{ fontSize: 13, color: "#cbd5e1", lineHeight: 1.6, whiteSpace: "pre-wrap" }}>
                {issue.description || "No description provided."}
              </div>
              {issue.location && (
                <div style={{ marginTop: 8, fontSize: 12, color: "#64748b" }}>
                  📍 Location: {issue.location}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
