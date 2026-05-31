/**
 * ======================================================================
 * TIMELINE READER — UI Rendering Bridge
 * ======================================================================
 *
 * Phase: TIMELINE RENDERER MIGRATION (Microphase 1.6.2)
 *
 * PURPOSE:
 *   Bridges the timeline engine's `incident_timeline` Firestore collection
 *   to UI renderers. Provides pure functions for:
 *     - Normalizing legacy `statusHistory[]` entries to timeline format
 *     - Merging timeline engine events with legacy entries
 *     - Deduplicating equivalent events across both sources
 *     - Sorting into chronological order
 *     - Producing renderable timeline arrays
 *
 * DESIGN:
 *   - Pure functions only (no Firestore calls, no React)
 *   - Immutable — all functions return new objects
 *   - Fail-safe — graceful degradation on bad input
 *   - Legacy-compatible — old incidents with only statusHistory still work
 *
 * ======================================================================
 */

import { getRoleDisplayLabel } from "./normalizeRole";


// ─── EVENT DISPLAY MAP ───────────────────────────────────────────────────────
//
// Maps TIMELINE_EVENTS constants to human-readable labels and icons.
// Used by buildRenderableTimeline() to produce display-ready entries.
// ─────────────────────────────────────────────────────────────────────────────

const EVENT_DISPLAY = Object.freeze({
  // Lifecycle
  INCIDENT_CREATED:       { label: "Incident Created",           icon: "📋" },
  INCIDENT_UPDATED:       { label: "Incident Updated",           icon: "📝" },
  INCIDENT_CLOSED:        { label: "Incident Closed",            icon: "✅" },
  INCIDENT_REOPENED:      { label: "Incident Reopened",          icon: "🔄" },
  INCIDENT_DELETED:       { label: "Incident Deleted",           icon: "🗑️" },
  INCIDENT_ASSIGNED:      { label: "Assigned",                   icon: "👤" },
  INCIDENT_REASSIGNED:    { label: "Reassigned",                 icon: "🔀" },
  STATUS_CHANGED:         { label: "Status Changed",             icon: "🔄" },
  SEVERITY_CHANGED:       { label: "Severity Changed",           icon: "⚡" },

  // Investigation
  NOTE_ADDED:             { label: "Note Added",                 icon: "📝" },
  EVIDENCE_ADDED:         { label: "Evidence Added",             icon: "🔍" },
  TRIAGE_UPDATED:         { label: "Triage Updated",             icon: "🔬" },
  THREAT_CONFIRMED:       { label: "Threat Confirmed",           icon: "🚨" },

  // Escalation
  ESCALATION_REQUESTED:   { label: "Escalation Requested",       icon: "⬆️" },
  ESCALATION_APPROVED:    { label: "Escalation Approved",        icon: "✅" },
  ESCALATION_DENIED:      { label: "Escalation Denied",          icon: "❌" },
  ESCALATION_ROUTED:      { label: "Routed to IR",               icon: "🎯" },

  // Containment
  CONTAINMENT_REQUESTED:  { label: "Containment Requested",      icon: "🛡️" },
  CONTAINMENT_APPROVED:   { label: "Containment Approved",       icon: "✅" },
  CONTAINMENT_REJECTED:   { label: "Containment Rejected",       icon: "❌" },
  CONTAINMENT_EXECUTED:   { label: "Containment Executed",       icon: "⚔️" },
  IR_ACTION_SUBMITTED:    { label: "IR Action Submitted",        icon: "📤" },

  // Governance
  GOVERNANCE_LOCK:        { label: "Governance Locked",          icon: "🔒" },
  GOVERNANCE_UNLOCK:      { label: "Governance Unlocked",        icon: "🔓" },
  GOVERNANCE_OVERRIDE:    { label: "Governance Override",        icon: "⚠️" },
  RISK_ACCEPTED:          { label: "Risk Accepted",              icon: "🛡️" },
  PIR_TAGGED:             { label: "Tagged for PIR",             icon: "📋" },
  PIR_ASSIGNED:           { label: "PIR Assigned",               icon: "👤" },
  PIR_REASSIGNED:         { label: "PIR Reassigned",             icon: "🔄" },
  PIR_CONTRIBUTOR_ADDED:  { label: "PIR Contributor Added",      icon: "➕" },
  PIR_CONTRIBUTOR_REMOVED:{ label: "PIR Contributor Removed",    icon: "➖" },
  PIR_STARTED:            { label: "PIR Started",                icon: "📝" },
  PIR_COMPLETED:          { label: "PIR Completed",              icon: "✅" },
  PIR_APPROVED:           { label: "PIR Approved",               icon: "✔" },
  PIR_REJECTED:           { label: "PIR Rejected",               icon: "❌" },
  RCA_RECOMMENDED:        { label: "RCA Recommended",            icon: "🚨" },
  RCA_TAGGED:             { label: "Tagged for RCA",             icon: "🔍" },
  RCA_ASSIGNED:           { label: "RCA Assigned",               icon: "👤" },
  RCA_REASSIGNED:         { label: "RCA Reassigned",             icon: "🔄" },
  RCA_CONTRIBUTOR_ADDED:  { label: "RCA Contributor Added",      icon: "➕" },
  RCA_CONTRIBUTOR_REMOVED:{ label: "RCA Contributor Removed",    icon: "➖" },
  RCA_STARTED:            { label: "RCA Started",                icon: "📝" },
  ROOT_CAUSE_IDENTIFIED:  { label: "Root Cause Identified",      icon: "🎯" },
  RCA_COMPLETED:          { label: "RCA Completed",              icon: "✅" },
  RCA_APPROVED:           { label: "RCA Approved",               icon: "✔" },
  RCA_REJECTED:           { label: "RCA Rejected",               icon: "❌" },
  THREAT_HUNT_CONVERTED:  { label: "Converted To Threat Hunt",   icon: "🔍" },
  THREAT_HUNT_STARTED:    { label: "Threat Hunt Started",        icon: "🕵️" },
  ATTACK_TECHNIQUE_MAPPED:{ label: "ATT&CK Technique Added",     icon: "🎯" },
  HUNT_RECOMMENDATION_SUBMITTED: { label: "Hunt Recommendation Submitted", icon: "📝" },
  THREAT_HUNT_RETURNED:   { label: "Returned To L2",             icon: "↩" },
  THREAT_HUNT_COMPLETED:  { label: "Threat Hunt Completed",      icon: "✅" },
  THREAT_HUNT_APPROVED:   { label: "Threat Hunt Approved",       icon: "✔" },
  THREAT_HUNT_REJECTED:   { label: "Threat Hunt Rejected",       icon: "❌" },
  SLA_OVERRIDE:           { label: "SLA Urgency Overridden",     icon: "⚡" },
});


// ─── LEGACY STATUS → TIMELINE EVENT MAP ──────────────────────────────────────
//
// Maps legacy `statusHistory[].status` strings to TIMELINE_EVENTS constants.
// Used for deduplication between legacy and timeline engine events.
// ─────────────────────────────────────────────────────────────────────────────

const LEGACY_STATUS_MAP = Object.freeze({
  "open":                         "INCIDENT_CREATED",
  "assigned":                     "INCIDENT_ASSIGNED",
  "in_progress":                  "STATUS_CHANGED",
  "confirmed_threat":             "THREAT_CONFIRMED",
  "false_positive":               "STATUS_CHANGED",
  "escalation_pending":           "ESCALATION_REQUESTED",
  "escalation_approved":          "ESCALATION_APPROVED",
  "escalation_denied":            "ESCALATION_DENIED",
  "ir_in_progress":               "STATUS_CHANGED",
  "contained":                    "CONTAINMENT_EXECUTED",
  "containment_pending":          "CONTAINMENT_REQUESTED",
  "containment_action_submitted": "IR_ACTION_SUBMITTED",
  "containment_completed":        "CONTAINMENT_EXECUTED",
  "containment_rejected":         "CONTAINMENT_REJECTED",
  "containment_review_again":     "CONTAINMENT_REJECTED",
  "resolved":                     "INCIDENT_CLOSED",
  "reopened":                     "INCIDENT_REOPENED",
  "deleted":                      "INCIDENT_DELETED",
  "governance_locked":            "GOVERNANCE_LOCK",
  "governance_unlocked":          "GOVERNANCE_UNLOCK",
  "triage_updated":               "TRIAGE_UPDATED",
  "triage_status":                "TRIAGE_UPDATED",
  "threat_hunt":                  "THREAT_HUNT_CONVERTED",
  "risk_accepted":                "RISK_ACCEPTED",
  "risk_accepted_flag":           "RISK_ACCEPTED",
  "rca_pending":                  "RCA_TAGGED",
  "rca_tagged":                   "RCA_TAGGED",
  "rca_completed":                "RCA_COMPLETED",
  "pir_pending":                  "PIR_TAGGED",
  "pir_tagged":                   "PIR_TAGGED",
  "pir_completed":                "PIR_COMPLETED",
  "threat_hunt_started":          "THREAT_HUNT_STARTED",
  "attack_technique_mapped":      "ATTACK_TECHNIQUE_MAPPED",
  "hunt_recommendation_submitted": "HUNT_RECOMMENDATION_SUBMITTED",
  "threat_hunt_returned":         "THREAT_HUNT_RETURNED",
  "threat_hunt_completed":        "THREAT_HUNT_COMPLETED",
  "threat_hunt_approved":         "THREAT_HUNT_APPROVED",
  "threat_hunt_rejected":         "THREAT_HUNT_REJECTED",
  "sla_override":                 "SLA_OVERRIDE",
  "pir_assigned":                 "PIR_ASSIGNED",
  "pir_reassigned":               "PIR_REASSIGNED",
  "pir_contributor_added":        "PIR_CONTRIBUTOR_ADDED",
  "pir_contributor_removed":      "PIR_CONTRIBUTOR_REMOVED",
  "pir_started":                  "PIR_STARTED",
  "pir_approved":                 "PIR_APPROVED",
  "pir_rejected":                 "PIR_REJECTED",
  "rca_assigned":                 "RCA_ASSIGNED",
  "rca_reassigned":               "RCA_REASSIGNED",
  "rca_contributor_added":        "RCA_CONTRIBUTOR_ADDED",
  "rca_contributor_removed":      "RCA_CONTRIBUTOR_REMOVED",
  "rca_started":                  "RCA_STARTED",
  "rca_approved":                 "RCA_APPROVED",
  "rca_rejected":                 "RCA_REJECTED",
});


// ─── LEGACY INVESTIGATION → TIMELINE EVENT MAP ────────────────────────────────
//
// Maps legacy `investigationHistory[].action` strings to TIMELINE_EVENTS constants.
// Used for backwards compatibility and timeline reconstruction of older incidents.
// ─────────────────────────────────────────────────────────────────────────────

const LEGACY_INVESTIGATION_MAP = Object.freeze({
  "classified_as_phishing":       "TRIAGE_UPDATED",
  "classified_as_malware":        "TRIAGE_UPDATED",
  "classified_as_network_attack": "TRIAGE_UPDATED",
  "classified_as_suspicious":     "TRIAGE_UPDATED",
  "note_added":                   "NOTE_ADDED",
});


// ─── TIMESTAMP NORMALIZATION ─────────────────────────────────────────────────

/**
 * Convert any timestamp format to milliseconds.
 * Handles: Firestore Timestamp, ISO string, Date, epoch ms, { seconds } obj.
 *
 * @param {*} ts - Timestamp in any format
 * @returns {number} Milliseconds since epoch, or 0 if invalid
 */
function toMillis(ts) {
  if (!ts) return 0;
  if (typeof ts === "number") return ts;
  if (typeof ts === "string") {
    const d = new Date(ts);
    return isNaN(d.getTime()) ? 0 : d.getTime();
  }
  if (ts.toMillis) return ts.toMillis();
  if (ts.seconds) return ts.seconds * 1000;
  if (ts instanceof Date) return ts.getTime();
  return 0;
}


// ═══════════════════════════════════════════════════════════════════════════════
// PUBLIC API
// ═══════════════════════════════════════════════════════════════════════════════


/**
 * Normalize a legacy statusHistory array into renderable timeline entries.
 *
 * @param {Array} statusHistory - Legacy `issue.statusHistory[]` array
 * @returns {Array} Normalized timeline entries with { eventType, label, icon, timestamp, note, source }
 */
export function normalizeLegacyStatusHistory(statusHistory) {
  if (!Array.isArray(statusHistory)) return [];

  return statusHistory
    .filter((h) => h && typeof h === "object" && h.status)
    .map((h) => {
      const mappedType = LEGACY_STATUS_MAP[h.status] || "STATUS_CHANGED";
      const display = EVENT_DISPLAY[mappedType] || { label: h.status, icon: "📌" };

      return {
        eventType: mappedType,
        displayLabel: display.label,
        icon: display.icon,
        timestamp: toMillis(h.at),
        rawStatus: h.status,
        note: h.note || null,
        actor: h.by || null,
        source: "legacy_status_history",
        _fingerprint: `${mappedType}:${toMillis(h.at)}`,
      };
    });
}


/**
 * Normalize a legacy investigationHistory array into renderable timeline entries.
 *
 * @param {Array} investigationHistory - Legacy `issue.investigationHistory[]` array
 * @returns {Array} Normalized timeline entries
 */
export function normalizeLegacyInvestigationHistory(investigationHistory) {
  if (!Array.isArray(investigationHistory)) return [];

  return investigationHistory
    .filter((h) => h && typeof h === "object" && h.action)
    .map((h) => {
      const mappedType = LEGACY_INVESTIGATION_MAP[h.action] || "INCIDENT_UPDATED";
      const display = EVENT_DISPLAY[mappedType] || { label: h.action, icon: "📌" };

      // Make a clean display note
      const noteText = h.action.replace(/_/g, " ");
      const displayNote = noteText.charAt(0).toUpperCase() + noteText.slice(1);

      return {
        eventType: mappedType,
        displayLabel: display.label,
        icon: display.icon,
        timestamp: toMillis(h.at),
        rawStatus: h.action,
        note: displayNote,
        actor: h.by || null,
        source: "legacy_investigation_history",
        _fingerprint: `${mappedType}:${toMillis(h.at)}`,
      };
    });
}


/**
 * Normalize timeline engine events into renderable timeline entries.
 *
 * @param {Array} timelineEvents - Events from `incident_timeline` collection
 * @returns {Array} Normalized timeline entries
 */
export function normalizeTimelineEvents(timelineEvents) {
  if (!Array.isArray(timelineEvents)) return [];

  return timelineEvents
    .filter((e) => e && typeof e === "object" && e.eventType)
    .map((e) => {
      const display = EVENT_DISPLAY[e.eventType] || { label: e.eventType, icon: "📌" };

      // Build note from metadata
      let note = null;
      if (e.metadata?.reason) note = e.metadata.reason;
      else if (e.metadata?.actionType) note = `Action: ${e.metadata.actionType}`;
      else if (e.newState && e.previousState) note = `${e.previousState} → ${e.newState}`;
      else if (e.newState) note = e.newState;

      return {
        eventType: e.eventType,
        displayLabel: display.label,
        icon: display.icon,
        timestamp: toMillis(e.timestamp) || toMillis(e._serverTimestamp),
        rawStatus: e.newState || e.eventType,
        note,
        actor: e.actorId || null,
        actorRole: e.actorRole ? getRoleDisplayLabel(e.actorRole) : null,
        source: "timeline_engine",
        _fingerprint: `${e.eventType}:${toMillis(e.timestamp)}`,
      };
    });
}


/**
 * Deduplicate timeline entries.
 *
 * Uses a 5-second window for fingerprint matching — events of the same type
 * within 5 seconds are considered duplicates. Timeline engine events take
 * priority over legacy entries.
 *
 * @param {Array} entries - Combined normalized entries
 * @returns {Array} Deduplicated entries
 */
export function deduplicateTimeline(entries) {
  if (!Array.isArray(entries) || entries.length <= 1) return entries;

  const result = [];
  const seen = new Map(); // eventType → latest timestamp

  // Sort by timestamp first (ascending)
  const sorted = [...entries].sort((a, b) => a.timestamp - b.timestamp);

  for (const entry of sorted) {
    const key = entry.eventType;
    const prevTs = seen.get(key);

    if (prevTs && Math.abs(entry.timestamp - prevTs) < 5000) {
      // Duplicate within 5s window — keep timeline_engine version if exists
      if (entry.source === "timeline_engine") {
        // Replace the legacy entry with the richer timeline engine entry
        const idx = result.findIndex(
          (r) => r.eventType === key && Math.abs(r.timestamp - prevTs) < 5000
        );
        if (idx >= 0) result[idx] = entry;
      }
      // Otherwise skip (legacy duplicate of timeline engine entry)
      continue;
    }

    seen.set(key, entry.timestamp);
    result.push(entry);
  }

  return result;
}


/**
 * Sort timeline entries chronologically.
 *
 * @param {Array} entries - Timeline entries
 * @param {"asc"|"desc"} order - Sort order (default: "asc")
 * @returns {Array} Sorted entries
 */
export function sortTimelineChronology(entries, order = "asc") {
  if (!Array.isArray(entries)) return [];
  return [...entries].sort((a, b) =>
    order === "asc" ? a.timestamp - b.timestamp : b.timestamp - a.timestamp
  );
}


/**
 * Build a complete renderable timeline from both data sources.
 *
 * This is the primary entry point for UI renderers.
 *
 * Priority:
 *   1. Timeline engine events (from `incident_timeline` collection)
 *   2. Legacy statusHistory entries (from incident document)
 *   3. Deduplicated, merged, sorted chronologically
 *
 * @param {Array|null} timelineEvents        - Events from `incident_timeline` (may be null)
 * @param {Array|null} statusHistory         - Legacy `issue.statusHistory[]` (may be null)
 * @param {"asc"|"desc"} order               - Sort order (default: "desc" for UI — newest first)
 * @param {Array|null} [investigationHistory] - Legacy `issue.investigationHistory[]` (may be null)
 * @returns {Array} Renderable timeline entries
 */
export function buildRenderableTimeline(timelineEvents, statusHistory, order = "desc", investigationHistory = []) {
  const engineEntries = normalizeTimelineEvents(timelineEvents);
  const legacyEntries = normalizeLegacyStatusHistory(statusHistory);
  const investigationEntries = normalizeLegacyInvestigationHistory(investigationHistory);

  // Merge all sources
  const combined = [...engineEntries, ...legacyEntries, ...investigationEntries];

  // Deduplicate
  const deduped = deduplicateTimeline(combined);

  // Sort
  return sortTimelineChronology(deduped, order);
}


/**
 * Get display info for a timeline event type.
 *
 * @param {string} eventType - TIMELINE_EVENTS constant
 * @returns {{ label: string, icon: string }}
 */
export function getEventDisplay(eventType) {
  return EVENT_DISPLAY[eventType] || { label: eventType || "Unknown", icon: "📌" };
}
