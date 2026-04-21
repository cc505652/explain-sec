/**
 * ======================================================================
 * CAMPUS SOC — COLLABORATION PANEL (Phase 7)
 * ======================================================================
 *
 * Shift handoff notes + inter-analyst collaboration module.
 * Supports:
 * - Handoff notes (visible to all analysts on the incident)
 * - Pending approvals display + process UI
 * - Owner assignment
 * ======================================================================
 */

import React, { useState, useCallback } from "react";
import { auth } from "../firebase";
import { callGovernanceAction } from "../utils/socFunctions";

/* ─── STYLES ─────────────────────────────────────────────────────────────── */

const cardStyle = {
  background: "rgba(15, 23, 42, 0.65)",
  backdropFilter: "blur(14px)",
  border: "1px solid rgba(255,255,255,0.08)",
  borderRadius: 16,
  padding: 20,
  marginBottom: 12,
};

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

const btnStyle = (bg = "#06b6d4", fg = "#fff") => ({
  padding: "6px 14px",
  borderRadius: 8,
  background: bg,
  color: fg,
  border: "none",
  cursor: "pointer",
  fontSize: 12,
  fontWeight: 700,
});

/* ─── HANDOFF NOTES ──────────────────────────────────────────────────────── */

function HandoffNotes({ notes = [], onAddNote, loading }) {
  const [draft, setDraft] = useState("");

  const handleAdd = () => {
    if (!draft.trim()) return;
    onAddNote(draft.trim());
    setDraft("");
  };

  return (
    <div style={cardStyle}>
      <h4 style={{ margin: "0 0 12px", fontSize: 14, fontWeight: 700, color: "#e2e8f0" }}>
        📝 Shift Handoff Notes
      </h4>
      
      <div style={{ maxHeight: 300, overflowY: "auto", marginBottom: 12 }}>
        {notes.length === 0 ? (
          <div style={{ color: "#64748b", fontSize: 12, padding: 8 }}>
            No handoff notes yet. Add one before your shift ends.
          </div>
        ) : (
          [...notes].reverse().map((note, i) => (
            <div key={i} style={{
              padding: "10px 14px", borderRadius: 10,
              background: "rgba(255,255,255,0.03)",
              border: "1px solid rgba(255,255,255,0.06)",
              marginBottom: 6,
            }}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                <span style={{ fontSize: 11, fontWeight: 700, color: "#06b6d4" }}>
                  {note.by || "Unknown"}
                </span>
                <span style={{ fontSize: 10, color: "#64748b" }}>
                  {note.at ? new Date(note.at).toLocaleString() : "—"}
                </span>
              </div>
              <div style={{ fontSize: 12, color: "#cbd5e1", lineHeight: 1.5 }}>
                {note.content}
              </div>
              {note.priority === "high" && (
                <span style={{
                  display: "inline-flex", marginTop: 4,
                  padding: "2px 8px", borderRadius: 999,
                  background: "rgba(239,68,68,0.15)", color: "#ef4444",
                  fontSize: 10, fontWeight: 700,
                }}>⚠ HIGH PRIORITY</span>
              )}
            </div>
          ))
        )}
      </div>

      <div style={{ display: "flex", gap: 8 }}>
        <textarea
          placeholder="Add handoff note for next shift..."
          value={draft}
          onChange={e => setDraft(e.target.value)}
          rows={2}
          style={{ ...inputStyle, resize: "vertical", minHeight: 40 }}
        />
        <button
          onClick={handleAdd}
          disabled={loading || !draft.trim()}
          style={btnStyle()}
        >
          {loading ? "..." : "Add Note"}
        </button>
      </div>
    </div>
  );
}

/* ─── PENDING APPROVALS ──────────────────────────────────────────────────── */

function PendingApprovals({ approvals = [], onProcess, loading, userRole }) {
  const pending = approvals.filter(a => a.status === "pending");
  const processed = approvals.filter(a => a.status !== "pending");
  const canProcess = ["soc_manager", "admin"].includes(userRole);

  return (
    <div style={cardStyle}>
      <h4 style={{ margin: "0 0 12px", fontSize: 14, fontWeight: 700, color: "#e2e8f0" }}>
        📋 Approval Queue ({pending.length} pending)
      </h4>

      {pending.length === 0 && processed.length === 0 && (
        <div style={{ color: "#64748b", fontSize: 12, padding: 8 }}>No approval requests</div>
      )}

      {/* Pending */}
      {pending.map(apr => (
        <div key={apr.id} style={{
          padding: "12px 16px", borderRadius: 12, marginBottom: 8,
          background: "rgba(245,158,11,0.08)",
          border: "1px solid rgba(245,158,11,0.25)",
        }}>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
            <span style={{ fontSize: 12, fontWeight: 700, color: "#f59e0b" }}>
              ⏳ {apr.requestedAction?.replace(/_/g, " ")}
            </span>
            <span style={{ fontSize: 10, color: "#64748b" }}>
              {apr.requestedAt ? new Date(apr.requestedAt).toLocaleString() : ""}
            </span>
          </div>
          <div style={{ fontSize: 11, color: "#94a3b8" }}>
            Requested by: {apr.requestedByRole} • {apr.reason || "No reason given"}
          </div>
          {canProcess && (
            <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
              <button
                onClick={() => onProcess(apr.id, "approved")}
                disabled={loading}
                style={btnStyle("rgba(16,185,129,0.8)")}
              >✅ Approve</button>
              <button
                onClick={() => onProcess(apr.id, "denied")}
                disabled={loading}
                style={btnStyle("rgba(239,68,68,0.8)")}
              >❌ Deny</button>
            </div>
          )}
        </div>
      ))}

      {/* Processed (collapsed) */}
      {processed.length > 0 && (
        <details style={{ marginTop: 8 }}>
          <summary style={{ cursor: "pointer", fontSize: 12, color: "#64748b" }}>
            {processed.length} processed approval(s)
          </summary>
          {processed.map(apr => (
            <div key={apr.id} style={{
              padding: "8px 12px", borderRadius: 8, marginTop: 4,
              background: apr.status === "approved" ? "rgba(16,185,129,0.06)" : "rgba(239,68,68,0.06)",
              border: `1px solid ${apr.status === "approved" ? "rgba(16,185,129,0.2)" : "rgba(239,68,68,0.2)"}`,
            }}>
              <div style={{ fontSize: 11, color: apr.status === "approved" ? "#10b981" : "#ef4444" }}>
                {apr.status === "approved" ? "✅" : "❌"} {apr.requestedAction} — {apr.status}
              </div>
              <div style={{ fontSize: 10, color: "#475569" }}>
                {apr.processedAt ? new Date(apr.processedAt).toLocaleString() : ""}
              </div>
            </div>
          ))}
        </details>
      )}
    </div>
  );
}

/* ─── MAIN COLLABORATION PANEL ───────────────────────────────────────────── */

export default function CollaborationPanel({ issue, userRole = "analyst" }) {
  const [loading, setLoading] = useState(false);

  const handleAddNote = useCallback(async (content) => {
    setLoading(true);
    try {
      // Use ADD_EVIDENCE with type "note" for handoff notes
      const { callAddEvidence } = await import("../utils/socFunctions");
      await callAddEvidence(issue.id, {
        type: "note",
        content,
        description: `Handoff note by ${auth.currentUser?.email}`,
      });
    } catch (err) {
      alert("Failed to add note: " + (err?.message || ""));
    } finally {
      setLoading(false);
    }
  }, [issue.id]);

  const handleProcessApproval = useCallback(async (approvalId, decision) => {
    const reason = decision === "denied"
      ? window.prompt("Denial reason:")
      : "";
    if (decision === "denied" && !reason) return;

    setLoading(true);
    try {
      await callGovernanceAction(issue.id, "PROCESS_APPROVAL", {
        approvalId,
        decision,
        reason: reason || "",
      });
    } catch (err) {
      alert("Failed to process approval: " + (err?.message || ""));
    } finally {
      setLoading(false);
    }
  }, [issue.id]);

  // Extract handoff notes from evidenceList
  const handoffNotes = (issue.evidenceList || [])
    .filter(e => e.type === "note")
    .map(e => ({
      content: e.content || e.description || "",
      by: e.addedByRole || e.addedBy || "Unknown",
      at: e.addedAt,
      priority: e.priority || "normal",
    }));

  return (
    <div>
      <HandoffNotes
        notes={handoffNotes}
        onAddNote={handleAddNote}
        loading={loading}
      />
      <PendingApprovals
        approvals={issue.pendingApprovals || []}
        onProcess={handleProcessApproval}
        loading={loading}
        userRole={userRole}
      />
    </div>
  );
}
