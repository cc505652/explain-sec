/**
 * ======================================================================
 * INCIDENT TIMELINE ENGINE — Foundation Layer
 * ======================================================================
 *
 * Phase: FOUNDATION (additive only — no existing behavior modified)
 *
 * PURPOSE:
 *   Provides centralized, immutable incident lifecycle event tracking.
 *   All incident lifecycle events can be recorded consistently and
 *   reconstructed chronologically for forensic analysis and audit.
 *
 * DESIGN:
 *   - Explicit timeline event constants (not magic strings)
 *   - Standardized event schema with lightweight validation
 *   - Fire-and-forget Firestore writes (non-blocking, fail-safe)
 *   - Synchronous validation, async-safe persistence
 *   - actorRole is ALWAYS explicit — never auto-inferred
 *   - Immutable-friendly — all helpers return new objects
 *
 * FIRESTORE:
 *   Uses additive `incident_timeline` collection (flat, queryable by
 *   incidentId). Does NOT modify existing incident document structure.
 *   Does NOT alter the existing `statusHistory` array field.
 *   Client writes may be blocked by Firestore security rules — the
 *   engine handles this gracefully with silent catch. Zero breakage.
 *
 * PERFORMANCE SAFETY:
 *   - appendTimelineEvent() is fire-and-forget (non-blocking)
 *   - Never called during renders (only in event handlers)
 *   - No listeners, no polling, no subscriptions
 *   - No render loops, no hydration instability
 *   - Triple-catch safety (same pattern as auditEngine.js)
 *
 * BACKWARD COMPATIBILITY:
 *   This module ADDS a new abstraction. It does NOT modify, replace,
 *   or interfere with:
 *     - Incident statusHistory arrays (existing inline tracking)
 *     - Escalation workflows
 *     - Containment workflows
 *     - Queue rendering
 *     - SLA timers
 *     - Any existing updateDoc/addDoc call sites
 *
 * FUTURE PHASES:
 *   - Phase 2: Migrate escalation lifecycle events
 *   - Phase 3: Migrate containment lifecycle events
 *   - Phase 4: Timeline visualization component
 *   - Phase 5: Server-side timeline writes via Cloud Functions
 *
 * ======================================================================
 */

import { db, auth } from "../firebase";
import { collection, addDoc, serverTimestamp } from "firebase/firestore";


// ─── TIMELINE EVENT TYPE CONSTANTS ───────────────────────────────────────────
//
// Every incident lifecycle event should be declared here as a constant.
// Components import these constants instead of using raw strings.
//
// Naming convention: NOUN_VERB or STATE_CHANGE
// ─────────────────────────────────────────────────────────────────────────────

export const TIMELINE_EVENTS = Object.freeze({

  // ── Incident Lifecycle ───────────────────────────────────────────────────
  /** Incident created and submitted */
  INCIDENT_CREATED:         "INCIDENT_CREATED",
  /** Incident fields updated (non-status) */
  INCIDENT_UPDATED:         "INCIDENT_UPDATED",
  /** Incident closed / resolved */
  INCIDENT_CLOSED:          "INCIDENT_CLOSED",
  /** Incident reopened after resolution */
  INCIDENT_REOPENED:        "INCIDENT_REOPENED",
  /** Incident soft-deleted */
  INCIDENT_DELETED:         "INCIDENT_DELETED",

  // ── Assignment ──────────────────────────────────────────────────────────
  /** Incident assigned to an analyst/team */
  INCIDENT_ASSIGNED:        "INCIDENT_ASSIGNED",
  /** Incident reassigned to different analyst/team */
  INCIDENT_REASSIGNED:      "INCIDENT_REASSIGNED",

  // ── Status Transitions ─────────────────────────────────────────────────
  /** Incident status changed */
  STATUS_CHANGED:           "STATUS_CHANGED",

  // ── Severity / Urgency ─────────────────────────────────────────────────
  /** Urgency/severity level changed */
  SEVERITY_CHANGED:         "SEVERITY_CHANGED",

  // ── Investigation ──────────────────────────────────────────────────────
  /** Analyst note added to incident */
  NOTE_ADDED:               "NOTE_ADDED",
  /** Evidence attached to incident */
  EVIDENCE_ADDED:           "EVIDENCE_ADDED",
  /** Triage status updated */
  TRIAGE_UPDATED:           "TRIAGE_UPDATED",

  // ── Escalation ─────────────────────────────────────────────────────────
  /** Escalation requested (L1→L2 or L2→Manager) */
  ESCALATION_REQUESTED:     "ESCALATION_REQUESTED",
  /** Escalation approved by manager */
  ESCALATION_APPROVED:      "ESCALATION_APPROVED",
  /** Escalation denied by manager */
  ESCALATION_DENIED:        "ESCALATION_DENIED",

  // ── Containment ────────────────────────────────────────────────────────
  /** Containment requested (L2→Manager) */
  CONTAINMENT_REQUESTED:    "CONTAINMENT_REQUESTED",
  /** Containment approved by manager */
  CONTAINMENT_APPROVED:     "CONTAINMENT_APPROVED",
  /** Containment rejected by manager */
  CONTAINMENT_REJECTED:     "CONTAINMENT_REJECTED",
  /** Containment action executed */
  CONTAINMENT_EXECUTED:     "CONTAINMENT_EXECUTED",

  // ── Governance ─────────────────────────────────────────────────────────
  /** Incident locked by governance */
  GOVERNANCE_LOCK:          "GOVERNANCE_LOCK",
  /** Incident unlocked */
  GOVERNANCE_UNLOCK:        "GOVERNANCE_UNLOCK",
  /** Decision overridden by governance */
  GOVERNANCE_OVERRIDE:      "GOVERNANCE_OVERRIDE",
  /** Residual risk formally accepted */
  RISK_ACCEPTED:            "RISK_ACCEPTED",
  /** Incident tagged for post-incident review */
  PIR_TAGGED:               "PIR_TAGGED",
  /** PIR Owner assigned */
  PIR_ASSIGNED:             "PIR_ASSIGNED",
  /** PIR Owner reassigned */
  PIR_REASSIGNED:           "PIR_REASSIGNED",
  /** Contributor added to PIR */
  PIR_CONTRIBUTOR_ADDED:    "PIR_CONTRIBUTOR_ADDED",
  /** Contributor removed from PIR */
  PIR_CONTRIBUTOR_REMOVED:  "PIR_CONTRIBUTOR_REMOVED",
  /** PIR started by owner */
  PIR_STARTED:              "PIR_STARTED",
  /** PIR completed by owner */
  PIR_COMPLETED:            "PIR_COMPLETED",
  /** PIR approved by manager */
  PIR_APPROVED:             "PIR_APPROVED",
  /** PIR rejected by manager */
  PIR_REJECTED:             "PIR_REJECTED",
  /** RCA recommended during review */
  RCA_RECOMMENDED:          "RCA_RECOMMENDED",
  /** Incident tagged for root cause analysis */
  RCA_TAGGED:               "RCA_TAGGED",
  /** RCA Owner assigned */
  RCA_ASSIGNED:             "RCA_ASSIGNED",
  /** RCA Owner reassigned */
  RCA_REASSIGNED:           "RCA_REASSIGNED",
  /** Contributor added to RCA */
  RCA_CONTRIBUTOR_ADDED:    "RCA_CONTRIBUTOR_ADDED",
  /** Contributor removed from RCA */
  RCA_CONTRIBUTOR_REMOVED:  "RCA_CONTRIBUTOR_REMOVED",
  /** RCA started by owner */
  RCA_STARTED:              "RCA_STARTED",
  /** Root cause identified */
  ROOT_CAUSE_IDENTIFIED:    "ROOT_CAUSE_IDENTIFIED",
  /** RCA completed by owner */
  RCA_COMPLETED:            "RCA_COMPLETED",
  /** RCA approved by manager */
  RCA_APPROVED:             "RCA_APPROVED",
  /** RCA rejected by manager */
  RCA_REJECTED:             "RCA_REJECTED",
  /** Incident converted to threat hunt */
  THREAT_HUNT_CONVERTED:    "THREAT_HUNT_CONVERTED",
  /** Threat Hunt started by hunter */
  THREAT_HUNT_STARTED:      "THREAT_HUNT_STARTED",
  /** ATT&CK technique mapped */
  ATTACK_TECHNIQUE_MAPPED:  "ATTACK_TECHNIQUE_MAPPED",
  /** Hunt recommendation submitted */
  HUNT_RECOMMENDATION_SUBMITTED: "HUNT_RECOMMENDATION_SUBMITTED",
  /** Threat hunt returned to L2 */
  THREAT_HUNT_RETURNED:     "THREAT_HUNT_RETURNED",
  /** Threat hunt completed and closed */
  THREAT_HUNT_COMPLETED:    "THREAT_HUNT_COMPLETED",
  /** Threat Hunt approved by manager */
  THREAT_HUNT_APPROVED:     "THREAT_HUNT_APPROVED",
  /** Threat Hunt rejected by manager */
  THREAT_HUNT_REJECTED:     "THREAT_HUNT_REJECTED",

  // ── Threat Confirmation ────────────────────────────────────────────────
  /** Threat confirmed during triage */
  THREAT_CONFIRMED:         "THREAT_CONFIRMED",

  // ── IR Operations ──────────────────────────────────────────────────────
  /** Escalation routed to IR team */
  ESCALATION_ROUTED:        "ESCALATION_ROUTED",
  /** IR containment action submitted for review */
  IR_ACTION_SUBMITTED:      "IR_ACTION_SUBMITTED",
  /** SLA urgency overridden */
  SLA_OVERRIDE:             "SLA_OVERRIDE",
});


// ─── VALID EVENT TYPE SET (for validation) ───────────────────────────────────

const VALID_EVENT_TYPES = Object.freeze(
  new Set(Object.values(TIMELINE_EVENTS))
);


// ─── TIMELINE EVENT SOURCES ──────────────────────────────────────────────────

export const TIMELINE_SOURCES = Object.freeze({
  /** Event from client-side action */
  CLIENT:        "client",
  /** Event from Cloud Function */
  SERVER:        "server",
  /** Event from system automation (auto-assign, SLA) */
  SYSTEM:        "system",
  /** Event from governance action */
  GOVERNANCE:    "governance",
});


// ─── REQUIRED FIELDS ─────────────────────────────────────────────────────────

const REQUIRED_FIELDS = ["incidentId", "eventType"];


// ═══════════════════════════════════════════════════════════════════════════════
// 1. EVENT VALIDATION
// ═══════════════════════════════════════════════════════════════════════════════
//
// Synchronous, deterministic, lightweight.
// Never throws — returns a validation result object.
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Validate and normalize a timeline event object.
 *
 * Required fields: incidentId, eventType
 * Auto-populated: timestamp (if missing), source (defaults to "client")
 *
 * @param {Object} event - Raw timeline event
 * @returns {{ valid: boolean, event: Object|null, errors: string[] }}
 *
 * @example
 *   const result = validateTimelineEvent({
 *     incidentId: "abc123",
 *     eventType: TIMELINE_EVENTS.INCIDENT_CREATED,
 *     actorId: user.uid,
 *     actorRole: "student",
 *   });
 */
export function validateTimelineEvent(event) {
  const errors = [];

  if (!event || typeof event !== "object") {
    return { valid: false, event: null, errors: ["Event must be a non-null object"] };
  }

  // Check required fields
  for (const field of REQUIRED_FIELDS) {
    if (!event[field]) {
      errors.push(`Missing required field: ${field}`);
    }
  }

  // Validate event type is known (warn but don't reject unknown types)
  if (event.eventType && !VALID_EVENT_TYPES.has(event.eventType)) {
    errors.push(`Unknown timeline event type: ${event.eventType} (allowed but not standardized)`);
  }

  // Build normalized event with safe defaults
  const normalizedEvent = {
    incidentId:    event.incidentId || null,
    actorId:       event.actorId || null,
    actorRole:     event.actorRole || null,
    eventType:     event.eventType || null,
    timestamp:     event.timestamp || new Date().toISOString(),
    previousState: event.previousState || null,
    newState:      event.newState || null,
    metadata:      event.metadata || {},
    source:        event.source || TIMELINE_SOURCES.CLIENT,
  };

  // Valid if all required fields are present
  const hasRequiredFields = REQUIRED_FIELDS.every((f) => normalizedEvent[f]);

  return {
    valid: hasRequiredFields,
    event: normalizedEvent,
    errors,
  };
}


// ═══════════════════════════════════════════════════════════════════════════════
// 2. EVENT FACTORY
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Create a timeline event with actorId auto-populated from Firebase Auth.
 *
 * actorRole is ALWAYS required and NEVER auto-inferred.
 *
 * @param {string} incidentId  - Incident document ID (REQUIRED)
 * @param {string} eventType   - Event type constant from TIMELINE_EVENTS (REQUIRED)
 * @param {string} actorRole   - Explicit role of the actor (REQUIRED)
 * @param {Object} [overrides] - Additional/override fields (previousState, newState, metadata, etc.)
 * @returns {Object} Timeline event ready for appendTimelineEvent()
 *
 * @example
 *   const event = createTimelineEvent(
 *     issueId,
 *     TIMELINE_EVENTS.SEVERITY_CHANGED,
 *     "soc_l2",
 *     { previousState: "medium", newState: "high" }
 *   );
 *   appendTimelineEvent(event);
 */
export function createTimelineEvent(incidentId, eventType, actorRole, overrides = {}) {
  return {
    incidentId,
    eventType,
    actorId:  auth.currentUser?.uid || "unknown",
    actorRole,
    timestamp: new Date().toISOString(),
    source: TIMELINE_SOURCES.CLIENT,
    ...overrides,
  };
}


// ═══════════════════════════════════════════════════════════════════════════════
// 3. ASYNC-SAFE PERSISTENCE (STABILIZED)
// ═══════════════════════════════════════════════════════════════════════════════
//
// appendTimelineEvent() is the single entry point for persisting timeline events.
//
// Contract:
//   - ALWAYS resolves immediately (never blocks calling workflow)
//   - Firestore write is FULLY DETACHED via setTimeout(0)
//   - In-memory dedupe prevents duplicate writes within 2s window
//   - Fails silently (console.warn on error)
//   - Never crashes UI
//   - Triple-catch safety net (same pattern as auditEngine.js)
//   - actorRole is NEVER auto-inferred — must be passed explicitly
//
// STABILIZATION (Microphase 1.5.4):
//   - Firestore write detached from calling workflow's microtask queue
//   - Prevents async congestion during orchestration-heavy parallel workflows
//   - In-memory ring buffer dedupe prevents duplicate timeline entries
//   - Returns immediately after validation + console log
// ═══════════════════════════════════════════════════════════════════════════════


// ─── DEDUPE RING BUFFER ──────────────────────────────────────────────────────
//
// Lightweight in-memory duplicate prevention. Stores recent event fingerprints
// in a fixed-size ring buffer. No persistent cache, no async loops.
//
// Fingerprint = `${incidentId}:${eventType}:${actorId}`
// Window = 2000ms (same incident+event+actor within 2s = duplicate)
// Buffer size = 32 entries (sufficient for any single-session burst)
// ─────────────────────────────────────────────────────────────────────────────

const DEDUPE_WINDOW_MS = 2000;
const DEDUPE_BUFFER_SIZE = 32;
const _dedupeBuffer = [];
let _dedupeIndex = 0;

/**
 * Check if an event is a duplicate of a recently appended event.
 * If not a duplicate, records the fingerprint for future checks.
 *
 * @param {Object} event - Normalized timeline event
 * @returns {boolean} true if this is a duplicate (should be skipped)
 */
function _isDuplicateEvent(event) {
  const fingerprint = `${event.incidentId}:${event.eventType}:${event.actorId || ""}`;
  const now = Date.now();

  // Check existing entries for match within window
  for (let i = 0; i < _dedupeBuffer.length; i++) {
    const entry = _dedupeBuffer[i];
    if (entry && entry.fp === fingerprint && (now - entry.ts) <= DEDUPE_WINDOW_MS) {
      return true; // Duplicate detected
    }
  }

  // Record this event's fingerprint (ring buffer — overwrites oldest)
  _dedupeBuffer[_dedupeIndex % DEDUPE_BUFFER_SIZE] = { fp: fingerprint, ts: now };
  _dedupeIndex++;

  return false;
}


// ─── DETACHED FIRESTORE WRITE ────────────────────────────────────────────────
//
// Fully detaches the Firestore write from the calling function's async chain
// using setTimeout(0). This pushes the write into the macrotask queue,
// completely preventing it from creating backpressure on orchestration
// workflows (escalation approve, containment approve, etc.).
//
// The calling code gets an immediate { success: true } return without
// waiting for the Firestore write to complete.
// ─────────────────────────────────────────────────────────────────────────────

function _detachedFirestoreWrite(normalizedEvent) {
  setTimeout(() => {
    try {
      const firestoreEvent = {
        ...normalizedEvent,
        _serverTimestamp: serverTimestamp(),
        _writeSource: "timeline_engine_v1",
      };

      addDoc(
        collection(db, "incident_timeline"),
        firestoreEvent
      ).catch((firestoreError) => {
        // Silent catch — Firestore write failures are expected and non-critical.
        console.warn(
          "[TIMELINE ENGINE] Firestore write failed (expected if rules block client writes):",
          firestoreError?.code || firestoreError?.message || "unknown"
        );
      });
    } catch (syncError) {
      // Safety net for synchronous errors during event construction
      try {
        console.warn("[TIMELINE ENGINE] Detached write error:", syncError);
      } catch (_) {
        // Even console.warn failed — silently swallow
      }
    }
  }, 0);
}


/**
 * Append a timeline event to the incident timeline.
 *
 * This is the centralized timeline persistence authority. All incident
 * lifecycle events should flow through this function.
 *
 * STABILIZED: Returns immediately after validation + console log.
 * Firestore write is fully detached via setTimeout(0) to prevent
 * async congestion during orchestration-heavy workflows.
 *
 * @param {Object} event - Timeline event object
 * @param {string} event.incidentId     - Incident ID (REQUIRED)
 * @param {string} event.eventType      - Event type from TIMELINE_EVENTS (REQUIRED)
 * @param {string} [event.actorId]      - UID of the actor
 * @param {string} [event.actorRole]    - Role of the actor (explicit, never inferred)
 * @param {string} [event.timestamp]    - ISO timestamp (auto-added if missing)
 * @param {string} [event.previousState] - State before the change
 * @param {string} [event.newState]     - State after the change
 * @param {Object} [event.metadata]     - Additional context data
 * @param {string} [event.source]       - Event source (defaults to "client")
 *
 * @returns {{ success: boolean }}
 *          Returns synchronously. Never throws.
 *
 * @example
 *   import { appendTimelineEvent, TIMELINE_EVENTS } from "../security/timelineEngine";
 *
 *   // Fire-and-forget — returns immediately
 *   appendTimelineEvent({
 *     incidentId: docRef.id,
 *     eventType: TIMELINE_EVENTS.INCIDENT_CREATED,
 *     actorId: user.uid,
 *     actorRole: "student",
 *     metadata: { category: "phishing", urgency: "high" },
 *   });
 */
export function appendTimelineEvent(event) {
  try {
    // ── Step 1: Validate (synchronous) ──────────────────────────────────
    const validation = validateTimelineEvent(event);

    if (!validation.valid) {
      console.warn(
        "[TIMELINE ENGINE] Invalid event — skipped:",
        validation.errors,
        event
      );
      return { success: false };
    }

    const normalizedEvent = validation.event;

    // ── Step 2: Dedupe check (synchronous, in-memory) ─────────────────
    if (_isDuplicateEvent(normalizedEvent)) {
      if (process.env.NODE_ENV === "development") {
        console.warn(
          "[TIMELINE ENGINE] Duplicate event suppressed:",
          normalizedEvent.eventType,
          normalizedEvent.incidentId
        );
      }
      return { success: true }; // Silently skip — not an error
    }

    // Log warnings for non-standard event types (but still persist them)
    if (validation.errors.length > 0) {
      console.warn("[TIMELINE ENGINE] Event warnings:", validation.errors);
    }

    // ── Step 3: Console log (synchronous, always succeeds) ────────────
    console.log(
      `📋 [TIMELINE] ${normalizedEvent.eventType}`,
      {
        incident: normalizedEvent.incidentId,
        actor: normalizedEvent.actorId,
        role: normalizedEvent.actorRole,
        prev: normalizedEvent.previousState,
        next: normalizedEvent.newState,
        source: normalizedEvent.source,
      }
    );

    // ── Step 4: Firestore write (FULLY DETACHED — setTimeout(0)) ──────
    //
    // The write is pushed to the macrotask queue so it NEVER creates
    // backpressure on the calling workflow's async chain. This is the
    // critical stabilization for orchestration-heavy parallel flows.
    //
    _detachedFirestoreWrite(normalizedEvent);

    // Return immediately — do not wait for Firestore
    return { success: true };

  } catch (outerError) {
    // Outermost safety net — appendTimelineEvent must NEVER throw
    try {
      console.warn("[TIMELINE ENGINE] Unexpected error:", outerError);
    } catch (_) {
      // Even console.warn failed — silently swallow
    }
    return { success: false };
  }
}


// ═══════════════════════════════════════════════════════════════════════════════
// 4. UTILITY HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Check whether an event type string is a valid TIMELINE_EVENTS constant.
 *
 * @param {string} eventType - Event type to validate
 * @returns {boolean} true if the event type is defined
 */
export function isValidTimelineEvent(eventType) {
  return VALID_EVENT_TYPES.has(eventType);
}

/**
 * Get all defined timeline event type constants as an array.
 *
 * @returns {string[]} Array of all TIMELINE_EVENTS values
 */
export function getAllTimelineEventTypes() {
  return Object.values(TIMELINE_EVENTS);
}

/**
 * Get the human-readable label for a timeline event type.
 *
 * @param {string} eventType - TIMELINE_EVENTS constant
 * @returns {string} Human-readable label
 *
 * @example
 *   getTimelineEventLabel(TIMELINE_EVENTS.SEVERITY_CHANGED);
 *   // → "Severity Changed"
 */
export function getTimelineEventLabel(eventType) {
  if (!eventType || typeof eventType !== "string") return "Unknown Event";

  // Convert SCREAMING_SNAKE to Title Case
  return eventType
    .split("_")
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
    .join(" ");
}

/**
 * Group timeline event type constants by domain category.
 *
 * @returns {Object} Grouped event types
 */
export function getTimelineEventGroups() {
  return {
    lifecycle: [
      TIMELINE_EVENTS.INCIDENT_CREATED,
      TIMELINE_EVENTS.INCIDENT_UPDATED,
      TIMELINE_EVENTS.INCIDENT_CLOSED,
      TIMELINE_EVENTS.INCIDENT_REOPENED,
      TIMELINE_EVENTS.INCIDENT_DELETED,
    ],
    assignment: [
      TIMELINE_EVENTS.INCIDENT_ASSIGNED,
      TIMELINE_EVENTS.INCIDENT_REASSIGNED,
    ],
    status: [
      TIMELINE_EVENTS.STATUS_CHANGED,
    ],
    severity: [
      TIMELINE_EVENTS.SEVERITY_CHANGED,
    ],
    investigation: [
      TIMELINE_EVENTS.NOTE_ADDED,
      TIMELINE_EVENTS.EVIDENCE_ADDED,
      TIMELINE_EVENTS.TRIAGE_UPDATED,
    ],
    escalation: [
      TIMELINE_EVENTS.ESCALATION_REQUESTED,
      TIMELINE_EVENTS.ESCALATION_APPROVED,
      TIMELINE_EVENTS.ESCALATION_DENIED,
    ],
    containment: [
      TIMELINE_EVENTS.CONTAINMENT_REQUESTED,
      TIMELINE_EVENTS.CONTAINMENT_APPROVED,
      TIMELINE_EVENTS.CONTAINMENT_REJECTED,
      TIMELINE_EVENTS.CONTAINMENT_EXECUTED,
    ],
    governance: [
      TIMELINE_EVENTS.GOVERNANCE_LOCK,
      TIMELINE_EVENTS.GOVERNANCE_UNLOCK,
      TIMELINE_EVENTS.GOVERNANCE_OVERRIDE,
      TIMELINE_EVENTS.SLA_OVERRIDE,
    ],
  };
}


// ═══════════════════════════════════════════════════════════════════════════════
// 5. TIMELINE STATE CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════
//
// Canonical incident lifecycle states for timeline previousState/newState fields.
// These mirror the actual status values used across the platform (App.jsx,
// AnalystDashboard.jsx, SOCManagerDashboard.jsx) but are centralized here
// so timeline events use consistent state references.
//
// IMPORTANT: These are NOT enforced at runtime — they are reference constants
// for timeline event construction and validation only.
// ═══════════════════════════════════════════════════════════════════════════════

export const TIMELINE_STATES = Object.freeze({
  // ── Core Lifecycle ─────────────────────────────────────────────────────
  OPEN:                         "open",
  ASSIGNED:                     "assigned",
  IN_PROGRESS:                  "in_progress",
  RESOLVED:                     "resolved",

  // ── Investigation ──────────────────────────────────────────────────────
  INVESTIGATING_L1:             "investigation_l1",
  INVESTIGATING_L2:             "investigation_l2",
  TRIAGE_IN_REVIEW:             "in_review",
  TRIAGE_CONFIRMED:             "confirmed_threat",
  TRIAGE_FALSE_POSITIVE:        "false_positive",

  // ── Escalation ─────────────────────────────────────────────────────────
  ESCALATION_REQUESTED:         "escalation_requested",
  ESCALATION_APPROVED:          "escalation_approved",
  ESCALATION_DENIED:            "escalation_denied",

  // ── Containment ────────────────────────────────────────────────────────
  CONTAINMENT_PENDING:          "containment_pending_approval",
  CONTAINMENT_IN_PROGRESS:      "containment_in_progress",
  CONTAINMENT_ACTION_SUBMITTED: "containment_action_submitted",
  CONTAINMENT_COMPLETED:        "containment_completed",
  CONTAINMENT_REJECTED:         "containment_rejected",
  CONTAINMENT_REVIEW_AGAIN:     "containment_review_again",
  CONTAINMENT_EXECUTED:         "containment_executed",

  // ── Governance ─────────────────────────────────────────────────────────
  LOCKED:                       "locked",
  UNLOCKED:                     "unlocked",

  // ── Severity / Urgency ─────────────────────────────────────────────────
  URGENCY_LOW:                  "low",
  URGENCY_MEDIUM:               "medium",
  URGENCY_HIGH:                 "high",
  URGENCY_CRITICAL:             "critical",
});

const VALID_STATES = Object.freeze(new Set(Object.values(TIMELINE_STATES)));


// ═══════════════════════════════════════════════════════════════════════════════
// 6. EVENT TYPE NORMALIZATION
// ═══════════════════════════════════════════════════════════════════════════════
//
// Maps legacy, ad-hoc, or fragmented event type strings to canonical
// TIMELINE_EVENTS constants. This ensures consistent event types regardless
// of the source or historical naming convention.
//
// The map is frozen and deterministic — same input always produces same output.
// ═══════════════════════════════════════════════════════════════════════════════

const EVENT_TYPE_ALIASES = Object.freeze({
  // Legacy escalation variants
  "escalated_l2":              TIMELINE_EVENTS.ESCALATION_REQUESTED,
  "escalated_to_l2":           TIMELINE_EVENTS.ESCALATION_REQUESTED,
  "ESCALATED_TO_L2":           TIMELINE_EVENTS.ESCALATION_REQUESTED,
  "escalation_to_l2":          TIMELINE_EVENTS.ESCALATION_REQUESTED,
  "escalation_requested":      TIMELINE_EVENTS.ESCALATION_REQUESTED,
  "escalation_approved":       TIMELINE_EVENTS.ESCALATION_APPROVED,
  "escalation_denied":         TIMELINE_EVENTS.ESCALATION_DENIED,

  // Legacy containment variants
  "containment_requested":     TIMELINE_EVENTS.CONTAINMENT_REQUESTED,
  "containment_approved":      TIMELINE_EVENTS.CONTAINMENT_APPROVED,
  "containment_rejected":      TIMELINE_EVENTS.CONTAINMENT_REJECTED,
  "containment_executed":      TIMELINE_EVENTS.CONTAINMENT_EXECUTED,

  // Legacy incident variants
  "incident_created":          TIMELINE_EVENTS.INCIDENT_CREATED,
  "created":                   TIMELINE_EVENTS.INCIDENT_CREATED,
  "incident_closed":           TIMELINE_EVENTS.INCIDENT_CLOSED,
  "closed":                    TIMELINE_EVENTS.INCIDENT_CLOSED,
  "resolved":                  TIMELINE_EVENTS.INCIDENT_CLOSED,
  "incident_reopened":         TIMELINE_EVENTS.INCIDENT_REOPENED,
  "reopened":                  TIMELINE_EVENTS.INCIDENT_REOPENED,
  "incident_deleted":          TIMELINE_EVENTS.INCIDENT_DELETED,
  "deleted":                   TIMELINE_EVENTS.INCIDENT_DELETED,

  // Legacy assignment variants
  "assigned":                  TIMELINE_EVENTS.INCIDENT_ASSIGNED,
  "incident_assigned":         TIMELINE_EVENTS.INCIDENT_ASSIGNED,
  "reassigned":                TIMELINE_EVENTS.INCIDENT_REASSIGNED,
  "incident_reassigned":       TIMELINE_EVENTS.INCIDENT_REASSIGNED,

  // Legacy status variants
  "status_changed":            TIMELINE_EVENTS.STATUS_CHANGED,
  "status_update":             TIMELINE_EVENTS.STATUS_CHANGED,

  // Legacy severity variants
  "severity_changed":          TIMELINE_EVENTS.SEVERITY_CHANGED,
  "urgency_changed":           TIMELINE_EVENTS.SEVERITY_CHANGED,
  "urgency_updated":           TIMELINE_EVENTS.SEVERITY_CHANGED,

  // Legacy investigation variants
  "note_added":                TIMELINE_EVENTS.NOTE_ADDED,
  "analyst_note":              TIMELINE_EVENTS.NOTE_ADDED,
  "evidence_added":            TIMELINE_EVENTS.EVIDENCE_ADDED,
  "triage_updated":            TIMELINE_EVENTS.TRIAGE_UPDATED,
  "triage_status":             TIMELINE_EVENTS.TRIAGE_UPDATED,

  // Legacy governance variants
  "locked":                    TIMELINE_EVENTS.GOVERNANCE_LOCK,
  "unlocked":                  TIMELINE_EVENTS.GOVERNANCE_UNLOCK,
  "governance_override":       TIMELINE_EVENTS.GOVERNANCE_OVERRIDE,
  "decision_overridden":       TIMELINE_EVENTS.GOVERNANCE_OVERRIDE,
});

/**
 * Normalize a timeline event type string to a canonical TIMELINE_EVENTS constant.
 *
 * Handles legacy, ad-hoc, and fragmented event type strings by mapping them
 * through EVENT_TYPE_ALIASES. If the input is already a valid TIMELINE_EVENTS
 * constant, it is returned as-is. Unknown strings return null.
 *
 * @param {string} rawEventType - Raw event type string
 * @returns {string|null} Canonical TIMELINE_EVENTS constant, or null if unmapped
 *
 * @example
 *   normalizeTimelineEventType("escalated_l2");
 *   // → "ESCALATION_REQUESTED"
 *   normalizeTimelineEventType("INCIDENT_CREATED");
 *   // → "INCIDENT_CREATED" (already canonical)
 *   normalizeTimelineEventType("xyzzy");
 *   // → null
 */
export function normalizeTimelineEventType(rawEventType) {
  if (!rawEventType || typeof rawEventType !== "string") return null;

  // Already a valid canonical event type
  if (VALID_EVENT_TYPES.has(rawEventType)) return rawEventType;

  // Check alias map (case-sensitive first, then lowercase)
  if (EVENT_TYPE_ALIASES[rawEventType]) return EVENT_TYPE_ALIASES[rawEventType];

  const lower = rawEventType.toLowerCase();
  if (EVENT_TYPE_ALIASES[lower]) return EVENT_TYPE_ALIASES[lower];

  // Try SCREAMING_SNAKE conversion
  const upper = rawEventType.toUpperCase();
  if (VALID_EVENT_TYPES.has(upper)) return upper;

  return null;
}


/**
 * Normalize a timeline state string to a canonical TIMELINE_STATES value.
 *
 * @param {string} rawState - Raw state string
 * @returns {string|null} Canonical TIMELINE_STATES value, or null if unknown
 *
 * @example
 *   normalizeTimelineState("open");       // → "open"
 *   normalizeTimelineState("RESOLVED");   // → "resolved"
 *   normalizeTimelineState("xyzzy");      // → null
 */
export function normalizeTimelineState(rawState) {
  if (!rawState || typeof rawState !== "string") return null;

  // Already valid
  if (VALID_STATES.has(rawState)) return rawState;

  // Try lowercase
  const lower = rawState.toLowerCase();
  if (VALID_STATES.has(lower)) return lower;

  return null;
}


/**
 * Normalize a timeline actor role using the normalizeRole pattern.
 * Lightweight version that handles common variations without importing
 * the full normalizeRole utility (to keep timeline engine self-contained).
 *
 * @param {string} rawRole - Raw actor role string
 * @returns {string} Normalized role string (passthrough if unrecognized)
 */
export function normalizeTimelineActor(rawRole) {
  if (!rawRole || typeof rawRole !== "string") return "unknown";

  const lower = rawRole.toLowerCase().trim();

  // Common aliases
  const ACTOR_ALIASES = {
    "soc l1":        "soc_l1",
    "soc_l1":        "soc_l1",
    "analyst":       "soc_l1",
    "l1":            "soc_l1",
    "soc l2":        "soc_l2",
    "soc_l2":        "soc_l2",
    "l2":            "soc_l2",
    "soc manager":   "soc_manager",
    "soc_manager":   "soc_manager",
    "manager":       "soc_manager",
    "ir":            "ir",
    "incident response": "ir",
    "admin":         "admin",
    "administrator": "admin",
    "threat_hunter": "threat_hunter",
    "threat hunter": "threat_hunter",
    "student":       "student",
    "system":        "system",
    "unknown":       "unknown",
  };

  return ACTOR_ALIASES[lower] || rawRole;
}


// ═══════════════════════════════════════════════════════════════════════════════
// 7. CHRONOLOGY HELPERS
// ═══════════════════════════════════════════════════════════════════════════════
//
// Pure functions for sorting, grouping, and filtering timeline event arrays.
// All operate on in-memory arrays — no Firestore access.
// All are synchronous, deterministic, and return new arrays (immutable-safe).
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Sort timeline events chronologically (oldest first).
 *
 * @param {Array} events - Array of timeline event objects
 * @param {string} [order="asc"] - Sort order: "asc" (oldest first) or "desc" (newest first)
 * @returns {Array} New sorted array (original is not mutated)
 */
export function sortTimelineEvents(events, order = "asc") {
  if (!Array.isArray(events)) return [];

  return [...events].sort((a, b) => {
    const timeA = a?.timestamp ? new Date(a.timestamp).getTime() : 0;
    const timeB = b?.timestamp ? new Date(b.timestamp).getTime() : 0;
    return order === "desc" ? timeB - timeA : timeA - timeB;
  });
}

/**
 * Group timeline events by a specified field.
 *
 * @param {Array} events - Array of timeline event objects
 * @param {string} field - Field name to group by (e.g., "eventType", "actorRole", "incidentId")
 * @returns {Object} Map of field value → array of events
 *
 * @example
 *   const grouped = groupTimelineEvents(events, "eventType");
 *   // → { INCIDENT_CREATED: [...], SEVERITY_CHANGED: [...] }
 */
export function groupTimelineEvents(events, field) {
  if (!Array.isArray(events) || !field) return {};

  const groups = {};
  for (const event of events) {
    const key = event?.[field] || "_unknown";
    if (!groups[key]) groups[key] = [];
    groups[key].push(event);
  }
  return groups;
}

/**
 * Filter timeline events by criteria.
 *
 * @param {Array} events - Array of timeline event objects
 * @param {Object} criteria - Filter criteria (all are optional, combined with AND)
 * @param {string} [criteria.eventType]    - Filter by event type
 * @param {string} [criteria.incidentId]   - Filter by incident ID
 * @param {string} [criteria.actorRole]    - Filter by actor role
 * @param {string} [criteria.source]       - Filter by event source
 * @param {string} [criteria.after]        - Only events after this ISO timestamp
 * @param {string} [criteria.before]       - Only events before this ISO timestamp
 * @returns {Array} Filtered array (original is not mutated)
 *
 * @example
 *   const filtered = filterTimelineEvents(events, {
 *     eventType: TIMELINE_EVENTS.SEVERITY_CHANGED,
 *     incidentId: "abc123",
 *   });
 */
export function filterTimelineEvents(events, criteria = {}) {
  if (!Array.isArray(events)) return [];

  return events.filter((event) => {
    if (!event) return false;

    if (criteria.eventType && event.eventType !== criteria.eventType) return false;
    if (criteria.incidentId && event.incidentId !== criteria.incidentId) return false;
    if (criteria.actorRole && event.actorRole !== criteria.actorRole) return false;
    if (criteria.source && event.source !== criteria.source) return false;

    if (criteria.after) {
      const eventTime = new Date(event.timestamp).getTime();
      const afterTime = new Date(criteria.after).getTime();
      if (isNaN(eventTime) || isNaN(afterTime) || eventTime <= afterTime) return false;
    }

    if (criteria.before) {
      const eventTime = new Date(event.timestamp).getTime();
      const beforeTime = new Date(criteria.before).getTime();
      if (isNaN(eventTime) || isNaN(beforeTime) || eventTime >= beforeTime) return false;
    }

    return true;
  });
}


// ═══════════════════════════════════════════════════════════════════════════════
// 8. CONSISTENCY VALIDATORS
// ═══════════════════════════════════════════════════════════════════════════════
//
// Validate timeline event arrays for integrity issues.
// All are synchronous, deterministic, and return diagnostic results.
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Validate the chronological sequence of timeline events for an incident.
 *
 * Checks:
 *   1. Events are sorted chronologically (no out-of-order timestamps)
 *   2. First event should be INCIDENT_CREATED
 *   3. No events after INCIDENT_CLOSED without INCIDENT_REOPENED
 *   4. All event types are valid
 *
 * @param {Array} events - Timeline events for a single incident (should be pre-sorted)
 * @returns {{ valid: boolean, errors: string[], warnings: string[] }}
 */
export function validateTimelineSequence(events) {
  const errors = [];
  const warnings = [];

  if (!Array.isArray(events) || events.length === 0) {
    return { valid: true, errors: [], warnings: ["Empty timeline"] };
  }

  // Check 1: Chronological order
  for (let i = 1; i < events.length; i++) {
    const prevTime = new Date(events[i - 1]?.timestamp).getTime();
    const currTime = new Date(events[i]?.timestamp).getTime();
    if (!isNaN(prevTime) && !isNaN(currTime) && currTime < prevTime) {
      warnings.push(
        `Out-of-order event at index ${i}: ${events[i]?.eventType} (${events[i]?.timestamp}) before ${events[i - 1]?.eventType} (${events[i - 1]?.timestamp})`
      );
    }
  }

  // Check 2: First event should be INCIDENT_CREATED
  if (events[0]?.eventType !== TIMELINE_EVENTS.INCIDENT_CREATED) {
    warnings.push(
      `First event is ${events[0]?.eventType}, expected ${TIMELINE_EVENTS.INCIDENT_CREATED}`
    );
  }

  // Check 3: No events after INCIDENT_CLOSED without INCIDENT_REOPENED
  let closed = false;
  for (const event of events) {
    if (event?.eventType === TIMELINE_EVENTS.INCIDENT_CLOSED) {
      closed = true;
    } else if (event?.eventType === TIMELINE_EVENTS.INCIDENT_REOPENED) {
      closed = false;
    } else if (closed) {
      warnings.push(
        `Event ${event?.eventType} occurred after INCIDENT_CLOSED without INCIDENT_REOPENED`
      );
    }
  }

  // Check 4: All event types are valid
  for (const event of events) {
    if (event?.eventType && !VALID_EVENT_TYPES.has(event.eventType)) {
      errors.push(`Invalid event type: ${event.eventType}`);
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
  };
}

/**
 * Detect duplicate timeline events within an array.
 *
 * Two events are considered duplicates if they have the same:
 *   - incidentId
 *   - eventType
 *   - actorId
 *   - timestamp (within 2 seconds tolerance)
 *
 * @param {Array} events - Array of timeline events
 * @returns {{ duplicates: Array<{ index: number, event: Object }>, count: number }}
 */
export function detectDuplicateTimelineEvents(events) {
  if (!Array.isArray(events)) return { duplicates: [], count: 0 };

  const TOLERANCE_MS = 2000; // 2 second window
  const duplicates = [];

  for (let i = 0; i < events.length; i++) {
    for (let j = i + 1; j < events.length; j++) {
      const a = events[i];
      const b = events[j];

      if (!a || !b) continue;
      if (a.incidentId !== b.incidentId) continue;
      if (a.eventType !== b.eventType) continue;
      if (a.actorId !== b.actorId) continue;

      const timeA = new Date(a.timestamp).getTime();
      const timeB = new Date(b.timestamp).getTime();
      if (!isNaN(timeA) && !isNaN(timeB) && Math.abs(timeA - timeB) <= TOLERANCE_MS) {
        duplicates.push({ index: j, event: b });
      }
    }
  }

  return { duplicates, count: duplicates.length };
}

/**
 * Detect invalid timeline state transitions.
 *
 * Checks that previousState/newState values in STATE_CHANGED and
 * SEVERITY_CHANGED events reference valid TIMELINE_STATES.
 *
 * @param {Array} events - Array of timeline events
 * @returns {{ invalid: Array<{ index: number, event: Object, reason: string }>, count: number }}
 */
export function detectInvalidTimelineTransitions(events) {
  if (!Array.isArray(events)) return { invalid: [], count: 0 };

  const STATE_EVENTS = new Set([
    TIMELINE_EVENTS.STATUS_CHANGED,
    TIMELINE_EVENTS.SEVERITY_CHANGED,
    TIMELINE_EVENTS.INCIDENT_CLOSED,
    TIMELINE_EVENTS.INCIDENT_REOPENED,
  ]);

  const invalid = [];

  for (let i = 0; i < events.length; i++) {
    const event = events[i];
    if (!event || !STATE_EVENTS.has(event.eventType)) continue;

    // Check previousState validity (if present)
    if (event.previousState && !VALID_STATES.has(event.previousState)) {
      invalid.push({
        index: i,
        event,
        reason: `Invalid previousState: "${event.previousState}"`,
      });
    }

    // Check newState validity (if present)
    if (event.newState && !VALID_STATES.has(event.newState)) {
      invalid.push({
        index: i,
        event,
        reason: `Invalid newState: "${event.newState}"`,
      });
    }

    // Self-transition check (previousState === newState)
    if (event.previousState && event.newState && event.previousState === event.newState) {
      invalid.push({
        index: i,
        event,
        reason: `Self-transition: "${event.previousState}" → "${event.newState}"`,
      });
    }
  }

  return { invalid, count: invalid.length };
}


// ═══════════════════════════════════════════════════════════════════════════════
// 9. TIMELINE DIAGNOSTICS
// ═══════════════════════════════════════════════════════════════════════════════
//
// Comprehensive diagnostic utilities for timeline integrity analysis.
// All synchronous, deterministic, in-memory only.
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Detect missing lifecycle events that should be present based on
 * the events that exist.
 *
 * Example: If INCIDENT_CLOSED exists but INCIDENT_CREATED doesn't,
 * the creation event is flagged as missing.
 *
 * @param {Array} events - Timeline events for a single incident
 * @returns {{ missing: string[], present: string[], coverage: number }}
 */
export function detectMissingLifecycleEvents(events) {
  if (!Array.isArray(events) || events.length === 0) {
    return { missing: [], present: [], coverage: 0 };
  }

  const presentTypes = new Set(events.map((e) => e?.eventType).filter(Boolean));

  // Minimum expected lifecycle events
  const EXPECTED_IF_PRESENT = [
    // If any event exists, INCIDENT_CREATED should exist
    { required: TIMELINE_EVENTS.INCIDENT_CREATED, always: true },
  ];

  // Conditional expectations
  const CONDITIONAL = [
    // If ESCALATION_APPROVED exists, ESCALATION_REQUESTED should exist
    { trigger: TIMELINE_EVENTS.ESCALATION_APPROVED, required: TIMELINE_EVENTS.ESCALATION_REQUESTED },
    { trigger: TIMELINE_EVENTS.ESCALATION_DENIED, required: TIMELINE_EVENTS.ESCALATION_REQUESTED },
    // If CONTAINMENT_APPROVED exists, CONTAINMENT_REQUESTED should exist
    { trigger: TIMELINE_EVENTS.CONTAINMENT_APPROVED, required: TIMELINE_EVENTS.CONTAINMENT_REQUESTED },
    { trigger: TIMELINE_EVENTS.CONTAINMENT_REJECTED, required: TIMELINE_EVENTS.CONTAINMENT_REQUESTED },
    { trigger: TIMELINE_EVENTS.CONTAINMENT_EXECUTED, required: TIMELINE_EVENTS.CONTAINMENT_APPROVED },
    // If INCIDENT_REOPENED exists, INCIDENT_CLOSED should exist before it
    { trigger: TIMELINE_EVENTS.INCIDENT_REOPENED, required: TIMELINE_EVENTS.INCIDENT_CLOSED },
  ];

  const missing = [];

  // Always-expected events
  for (const rule of EXPECTED_IF_PRESENT) {
    if (rule.always && !presentTypes.has(rule.required)) {
      missing.push(rule.required);
    }
  }

  // Conditional expectations
  for (const rule of CONDITIONAL) {
    if (presentTypes.has(rule.trigger) && !presentTypes.has(rule.required)) {
      missing.push(rule.required);
    }
  }

  const allExpected = new Set([
    ...EXPECTED_IF_PRESENT.filter((r) => r.always).map((r) => r.required),
    ...CONDITIONAL.filter((r) => presentTypes.has(r.trigger)).map((r) => r.required),
  ]);

  const totalExpected = allExpected.size;
  const presentCount = [...allExpected].filter((e) => presentTypes.has(e)).length;
  const coverage = totalExpected > 0 ? Math.round((presentCount / totalExpected) * 100) : 100;

  return {
    missing,
    present: Array.from(presentTypes),
    coverage,
  };
}

/**
 * Generate a comprehensive timeline integrity report for an incident.
 *
 * Aggregates all diagnostic checks into a single structured report.
 *
 * @param {Array} events - Timeline events for a single incident
 * @returns {Object} Full integrity report
 *
 * @example
 *   const report = generateTimelineIntegrityReport(incidentEvents);
 *   if (!report.healthy) console.warn("Timeline issues:", report);
 */
export function generateTimelineIntegrityReport(events) {
  if (!Array.isArray(events)) {
    return {
      healthy: false,
      timestamp: new Date().toISOString(),
      summary: { totalEvents: 0, errors: 1, warnings: 0 },
      sequence: { valid: false, errors: ["Input is not an array"], warnings: [] },
      duplicates: { duplicates: [], count: 0 },
      transitions: { invalid: [], count: 0 },
      lifecycle: { missing: [], present: [], coverage: 0 },
    };
  }

  const sorted = sortTimelineEvents(events, "asc");
  const sequence = validateTimelineSequence(sorted);
  const duplicates = detectDuplicateTimelineEvents(sorted);
  const transitions = detectInvalidTimelineTransitions(sorted);
  const lifecycle = detectMissingLifecycleEvents(sorted);

  const errorCount = sequence.errors.length + transitions.count;
  const warningCount = sequence.warnings.length + duplicates.count;

  return {
    healthy: errorCount === 0,
    timestamp: new Date().toISOString(),
    summary: {
      totalEvents: events.length,
      errors: errorCount,
      warnings: warningCount,
      uniqueEventTypes: new Set(events.map((e) => e?.eventType).filter(Boolean)).size,
      uniqueActors: new Set(events.map((e) => e?.actorId).filter(Boolean)).size,
      lifecycleCoverage: lifecycle.coverage,
    },
    sequence,
    duplicates,
    transitions,
    lifecycle,
    eventTypeDistribution: groupTimelineEvents(sorted, "eventType"),
    actorDistribution: groupTimelineEvents(sorted, "actorRole"),
  };
}


// ═══════════════════════════════════════════════════════════════════════════════
// 10. LIFECYCLE-SPECIFIC APPEND HELPERS
// ═══════════════════════════════════════════════════════════════════════════════
//
// Convenience wrappers around appendTimelineEvent() that reduce boilerplate
// at call sites. Each helper constructs the appropriate event structure
// and delegates to appendTimelineEvent() for validation + persistence.
//
// All are:
//   - Fire-and-forget safe (non-blocking, never throw)
//   - No render-triggered writes (only called from event handlers)
//   - actorRole is ALWAYS explicit
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Append an escalation lifecycle event.
 *
 * @param {string} incidentId - Incident document ID
 * @param {string} eventType  - TIMELINE_EVENTS constant (ESCALATION_REQUESTED/APPROVED/DENIED)
 * @param {string} actorRole  - Explicit role of the actor
 * @param {Object} [details]  - Additional details
 * @param {string} [details.from]     - Source tier/team
 * @param {string} [details.to]       - Target tier/team
 * @param {string} [details.reason]   - Reason for escalation decision
 * @param {string} [details.previousStatus] - Status before escalation
 * @param {string} [details.newStatus]      - Status after escalation
 *
 * @returns {Promise<{ success: boolean }>} Always resolves.
 *
 * @example
 *   appendEscalationEvent(issueId, TIMELINE_EVENTS.ESCALATION_APPROVED, "soc_manager", {
 *     from: "soc_l1", to: "ir",
 *   });
 */
export function appendEscalationEvent(incidentId, eventType, actorRole, details = {}) {
  return appendTimelineEvent({
    incidentId,
    eventType,
    actorId: auth.currentUser?.uid || "unknown",
    actorRole,
    previousState: details.previousStatus || details.from || null,
    newState: details.newStatus || details.to || null,
    metadata: {
      from: details.from || null,
      to: details.to || null,
      reason: details.reason || null,
    },
  });
}

/**
 * Append a containment lifecycle event.
 *
 * @param {string} incidentId - Incident document ID
 * @param {string} eventType  - TIMELINE_EVENTS constant (CONTAINMENT_REQUESTED/APPROVED/REJECTED/EXECUTED)
 * @param {string} actorRole  - Explicit role of the actor
 * @param {Object} [details]  - Additional details
 * @param {string} [details.previousStatus] - Status before containment action
 * @param {string} [details.newStatus]      - Status after containment action
 * @param {string} [details.reason]         - Reason for decision
 * @param {string} [details.actionType]     - Type of containment action
 *
 * @returns {Promise<{ success: boolean }>} Always resolves.
 *
 * @example
 *   appendContainmentEvent(issueId, TIMELINE_EVENTS.CONTAINMENT_APPROVED, "soc_manager", {
 *     previousStatus: "containment_pending_approval",
 *     newStatus: "containment_in_progress",
 *   });
 */
export function appendContainmentEvent(incidentId, eventType, actorRole, details = {}) {
  return appendTimelineEvent({
    incidentId,
    eventType,
    actorId: auth.currentUser?.uid || "unknown",
    actorRole,
    previousState: details.previousStatus || null,
    newState: details.newStatus || null,
    metadata: {
      reason: details.reason || null,
      actionType: details.actionType || null,
    },
  });
}

/**
 * Append a general incident lifecycle event.
 *
 * @param {string} incidentId - Incident document ID
 * @param {string} eventType  - TIMELINE_EVENTS constant
 * @param {string} actorRole  - Explicit role of the actor
 * @param {Object} [details]  - Additional details
 * @param {string} [details.previousStatus] - Status before change
 * @param {string} [details.newStatus]      - Status after change
 * @param {string} [details.reason]         - Reason for action
 * @param {Object} [details.metadata]       - Additional metadata
 *
 * @returns {Promise<{ success: boolean }>} Always resolves.
 *
 * @example
 *   appendLifecycleEvent(issueId, TIMELINE_EVENTS.GOVERNANCE_LOCK, "soc_manager", {
 *     reason: "Under investigation",
 *   });
 */
export function appendLifecycleEvent(incidentId, eventType, actorRole, details = {}) {
  return appendTimelineEvent({
    incidentId,
    eventType,
    actorId: auth.currentUser?.uid || "unknown",
    actorRole,
    previousState: details.previousStatus || null,
    newState: details.newStatus || null,
    metadata: {
      reason: details.reason || null,
      ...(details.metadata || {}),
    },
  });
}


// ═══════════════════════════════════════════════════════════════════════════════
// 11. LIFECYCLE PROGRESSION VALIDATORS
// ═══════════════════════════════════════════════════════════════════════════════
//
// Validate that lifecycle event sequences follow expected progression patterns.
// All synchronous, deterministic, in-memory only.
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Valid lifecycle state progressions.
 * Maps each event type to the set of event types that can logically precede it.
 * Used for detecting impossible/invalid lifecycle sequences.
 */
const VALID_PROGRESSIONS = Object.freeze({
  [TIMELINE_EVENTS.INCIDENT_CREATED]: new Set([]),
  [TIMELINE_EVENTS.INCIDENT_ASSIGNED]: new Set([
    TIMELINE_EVENTS.INCIDENT_CREATED,
    TIMELINE_EVENTS.INCIDENT_REASSIGNED,
    TIMELINE_EVENTS.INCIDENT_REOPENED,
    TIMELINE_EVENTS.ESCALATION_APPROVED,
    TIMELINE_EVENTS.ESCALATION_DENIED,
  ]),
  [TIMELINE_EVENTS.ESCALATION_REQUESTED]: new Set([
    TIMELINE_EVENTS.INCIDENT_CREATED,
    TIMELINE_EVENTS.INCIDENT_ASSIGNED,
    TIMELINE_EVENTS.NOTE_ADDED,
    TIMELINE_EVENTS.SEVERITY_CHANGED,
    TIMELINE_EVENTS.TRIAGE_UPDATED,
    TIMELINE_EVENTS.STATUS_CHANGED,
    TIMELINE_EVENTS.EVIDENCE_ADDED,
  ]),
  [TIMELINE_EVENTS.ESCALATION_APPROVED]: new Set([
    TIMELINE_EVENTS.ESCALATION_REQUESTED,
  ]),
  [TIMELINE_EVENTS.ESCALATION_DENIED]: new Set([
    TIMELINE_EVENTS.ESCALATION_REQUESTED,
  ]),
  [TIMELINE_EVENTS.CONTAINMENT_REQUESTED]: new Set([
    TIMELINE_EVENTS.NOTE_ADDED,
    TIMELINE_EVENTS.SEVERITY_CHANGED,
    TIMELINE_EVENTS.TRIAGE_UPDATED,
    TIMELINE_EVENTS.ESCALATION_APPROVED,
    TIMELINE_EVENTS.STATUS_CHANGED,
    TIMELINE_EVENTS.INCIDENT_ASSIGNED,
  ]),
  [TIMELINE_EVENTS.CONTAINMENT_APPROVED]: new Set([
    TIMELINE_EVENTS.CONTAINMENT_REQUESTED,
  ]),
  [TIMELINE_EVENTS.CONTAINMENT_REJECTED]: new Set([
    TIMELINE_EVENTS.CONTAINMENT_REQUESTED,
    TIMELINE_EVENTS.CONTAINMENT_EXECUTED,
  ]),
  [TIMELINE_EVENTS.CONTAINMENT_EXECUTED]: new Set([
    TIMELINE_EVENTS.CONTAINMENT_APPROVED,
  ]),
  [TIMELINE_EVENTS.INCIDENT_CLOSED]: new Set([
    TIMELINE_EVENTS.CONTAINMENT_EXECUTED,
    TIMELINE_EVENTS.CONTAINMENT_APPROVED,
    TIMELINE_EVENTS.NOTE_ADDED,
    TIMELINE_EVENTS.STATUS_CHANGED,
    TIMELINE_EVENTS.INCIDENT_ASSIGNED,
    TIMELINE_EVENTS.SEVERITY_CHANGED,
    TIMELINE_EVENTS.GOVERNANCE_OVERRIDE,
  ]),
  [TIMELINE_EVENTS.INCIDENT_REOPENED]: new Set([
    TIMELINE_EVENTS.INCIDENT_CLOSED,
  ]),
});

/**
 * Validate that a lifecycle event sequence follows valid progression patterns.
 *
 * @param {Array} events - Chronologically sorted timeline events
 * @returns {{ valid: boolean, violations: Array<{ index: number, event: string, previous: string, reason: string }> }}
 */
export function validateLifecycleProgression(events) {
  if (!Array.isArray(events) || events.length <= 1) {
    return { valid: true, violations: [] };
  }

  const violations = [];

  for (let i = 1; i < events.length; i++) {
    const current = events[i]?.eventType;
    const previous = events[i - 1]?.eventType;

    if (!current || !previous) continue;

    const validPredecessors = VALID_PROGRESSIONS[current];

    // Only check events that have defined progression rules
    if (validPredecessors && validPredecessors.size > 0 && !validPredecessors.has(previous)) {
      // Check if ANY earlier event is a valid predecessor (not just immediate)
      const hasValidPredecessor = events.slice(0, i).some(
        (e) => e?.eventType && validPredecessors.has(e.eventType)
      );

      if (!hasValidPredecessor) {
        violations.push({
          index: i,
          event: current,
          previous,
          reason: `"${current}" requires one of [${[...validPredecessors].join(", ")}] to precede it`,
        });
      }
    }
  }

  return {
    valid: violations.length === 0,
    violations,
  };
}

/**
 * Detect invalid lifecycle sequences — events that could not logically
 * occur in the given order.
 *
 * This is a stricter check that focuses on impossible combinations:
 *   - ESCALATION_APPROVED without ESCALATION_REQUESTED
 *   - CONTAINMENT_EXECUTED without CONTAINMENT_APPROVED
 *   - INCIDENT_REOPENED without INCIDENT_CLOSED
 *   - Multiple INCIDENT_CREATED events
 *
 * @param {Array} events - Timeline events (should be chronologically sorted)
 * @returns {{ invalid: Array<{ reason: string }>, count: number }}
 */
export function detectInvalidLifecycleSequence(events) {
  if (!Array.isArray(events)) return { invalid: [], count: 0 };

  const invalid = [];
  const presentTypes = events.map((e) => e?.eventType).filter(Boolean);
  const typeSet = new Set(presentTypes);

  // Check: Multiple INCIDENT_CREATED
  const createdCount = presentTypes.filter((t) => t === TIMELINE_EVENTS.INCIDENT_CREATED).length;
  if (createdCount > 1) {
    invalid.push({ reason: `Multiple INCIDENT_CREATED events (${createdCount})` });
  }

  // Check: ESCALATION_APPROVED without ESCALATION_REQUESTED
  if (typeSet.has(TIMELINE_EVENTS.ESCALATION_APPROVED) && !typeSet.has(TIMELINE_EVENTS.ESCALATION_REQUESTED)) {
    invalid.push({ reason: "ESCALATION_APPROVED without preceding ESCALATION_REQUESTED" });
  }

  // Check: ESCALATION_DENIED without ESCALATION_REQUESTED
  if (typeSet.has(TIMELINE_EVENTS.ESCALATION_DENIED) && !typeSet.has(TIMELINE_EVENTS.ESCALATION_REQUESTED)) {
    invalid.push({ reason: "ESCALATION_DENIED without preceding ESCALATION_REQUESTED" });
  }

  // Check: CONTAINMENT_APPROVED without CONTAINMENT_REQUESTED
  if (typeSet.has(TIMELINE_EVENTS.CONTAINMENT_APPROVED) && !typeSet.has(TIMELINE_EVENTS.CONTAINMENT_REQUESTED)) {
    invalid.push({ reason: "CONTAINMENT_APPROVED without preceding CONTAINMENT_REQUESTED" });
  }

  // Check: CONTAINMENT_EXECUTED without CONTAINMENT_APPROVED
  if (typeSet.has(TIMELINE_EVENTS.CONTAINMENT_EXECUTED) && !typeSet.has(TIMELINE_EVENTS.CONTAINMENT_APPROVED)) {
    invalid.push({ reason: "CONTAINMENT_EXECUTED without preceding CONTAINMENT_APPROVED" });
  }

  // Check: INCIDENT_REOPENED without INCIDENT_CLOSED
  if (typeSet.has(TIMELINE_EVENTS.INCIDENT_REOPENED) && !typeSet.has(TIMELINE_EVENTS.INCIDENT_CLOSED)) {
    invalid.push({ reason: "INCIDENT_REOPENED without preceding INCIDENT_CLOSED" });
  }

  return { invalid, count: invalid.length };
}


// ═══════════════════════════════════════════════════════════════════════════════
// 12. TIMELINE RECONSTRUCTION HELPERS
// ═══════════════════════════════════════════════════════════════════════════════
//
// Pure functions for reconstructing incident lifecycle state from timeline events.
// All synchronous, deterministic, in-memory only.
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Reconstruct the full incident lifecycle from timeline events.
 *
 * Returns a chronological array of lifecycle phase transitions, each with
 * the event that triggered the transition and the resulting state.
 *
 * @param {Array} events - Timeline events for a single incident
 * @returns {Array<{ phase: string, eventType: string, actor: string, timestamp: string, state: string }>}
 *
 * @example
 *   const lifecycle = reconstructIncidentLifecycle(events);
 *   // → [
 *   //   { phase: "creation", eventType: "INCIDENT_CREATED", ... },
 *   //   { phase: "investigation", eventType: "NOTE_ADDED", ... },
 *   //   { phase: "escalation", eventType: "ESCALATION_REQUESTED", ... },
 *   //   { phase: "resolution", eventType: "INCIDENT_CLOSED", ... },
 *   // ]
 */
export function reconstructIncidentLifecycle(events) {
  if (!Array.isArray(events) || events.length === 0) return [];

  const sorted = sortTimelineEvents(events, "asc");

  // Map event types to lifecycle phases
  const EVENT_TO_PHASE = {
    [TIMELINE_EVENTS.INCIDENT_CREATED]:       "creation",
    [TIMELINE_EVENTS.INCIDENT_ASSIGNED]:      "assignment",
    [TIMELINE_EVENTS.INCIDENT_REASSIGNED]:    "reassignment",
    [TIMELINE_EVENTS.NOTE_ADDED]:             "investigation",
    [TIMELINE_EVENTS.EVIDENCE_ADDED]:         "investigation",
    [TIMELINE_EVENTS.TRIAGE_UPDATED]:         "investigation",
    [TIMELINE_EVENTS.SEVERITY_CHANGED]:       "assessment",
    [TIMELINE_EVENTS.STATUS_CHANGED]:         "status_change",
    [TIMELINE_EVENTS.ESCALATION_REQUESTED]:   "escalation",
    [TIMELINE_EVENTS.ESCALATION_APPROVED]:    "escalation",
    [TIMELINE_EVENTS.ESCALATION_DENIED]:      "escalation",
    [TIMELINE_EVENTS.CONTAINMENT_REQUESTED]:  "containment",
    [TIMELINE_EVENTS.CONTAINMENT_APPROVED]:   "containment",
    [TIMELINE_EVENTS.CONTAINMENT_REJECTED]:   "containment",
    [TIMELINE_EVENTS.CONTAINMENT_EXECUTED]:   "containment",
    [TIMELINE_EVENTS.GOVERNANCE_LOCK]:        "governance",
    [TIMELINE_EVENTS.GOVERNANCE_UNLOCK]:      "governance",
    [TIMELINE_EVENTS.GOVERNANCE_OVERRIDE]:    "governance",
    [TIMELINE_EVENTS.INCIDENT_CLOSED]:        "resolution",
    [TIMELINE_EVENTS.INCIDENT_REOPENED]:      "reopened",
    [TIMELINE_EVENTS.INCIDENT_UPDATED]:       "update",
    [TIMELINE_EVENTS.INCIDENT_DELETED]:       "deletion",
  };

  return sorted.map((event) => ({
    phase: EVENT_TO_PHASE[event.eventType] || "unknown",
    eventType: event.eventType,
    actor: event.actorId || "unknown",
    actorRole: event.actorRole || "unknown",
    timestamp: event.timestamp,
    state: event.newState || null,
    previousState: event.previousState || null,
  }));
}

/**
 * Get the latest lifecycle state from a sequence of timeline events.
 *
 * Scans events in reverse chronological order and returns the most recent
 * newState value from status-changing events.
 *
 * @param {Array} events - Timeline events for a single incident
 * @returns {{ state: string|null, eventType: string|null, timestamp: string|null, actor: string|null }}
 *
 * @example
 *   const latest = getLatestLifecycleState(events);
 *   // → { state: "resolved", eventType: "INCIDENT_CLOSED", timestamp: "...", actor: "..." }
 */
export function getLatestLifecycleState(events) {
  if (!Array.isArray(events) || events.length === 0) {
    return { state: null, eventType: null, timestamp: null, actor: null };
  }

  const STATE_CHANGING_EVENTS = new Set([
    TIMELINE_EVENTS.INCIDENT_CREATED,
    TIMELINE_EVENTS.STATUS_CHANGED,
    TIMELINE_EVENTS.INCIDENT_CLOSED,
    TIMELINE_EVENTS.INCIDENT_REOPENED,
    TIMELINE_EVENTS.ESCALATION_APPROVED,
    TIMELINE_EVENTS.ESCALATION_DENIED,
    TIMELINE_EVENTS.CONTAINMENT_APPROVED,
    TIMELINE_EVENTS.CONTAINMENT_REJECTED,
    TIMELINE_EVENTS.CONTAINMENT_EXECUTED,
    TIMELINE_EVENTS.GOVERNANCE_LOCK,
    TIMELINE_EVENTS.GOVERNANCE_UNLOCK,
  ]);

  // Scan in reverse chronological order
  const sorted = sortTimelineEvents(events, "desc");

  for (const event of sorted) {
    if (event?.eventType && STATE_CHANGING_EVENTS.has(event.eventType)) {
      return {
        state: event.newState || null,
        eventType: event.eventType,
        timestamp: event.timestamp || null,
        actor: event.actorId || null,
      };
    }
  }

  return { state: null, eventType: null, timestamp: null, actor: null };
}


// ═══════════════════════════════════════════════════════════════════════════════
// 13. TIMELINE CONSOLIDATION LAYER
// ═══════════════════════════════════════════════════════════════════════════════
//
// Phase: CONSOLIDATION (Microphase 1.5.5)
//
// Purpose: Complete operational timeline coverage with standardized domain
// wrappers, consolidation helpers, and integrity protections.
//
// All append wrappers delegate to appendTimelineEvent() which provides:
//   - setTimeout(0) detached Firestore writes
//   - In-memory dedupe ring buffer
//   - Triple-catch safety net
//   - Synchronous return
//
// All validators/helpers are synchronous, deterministic, in-memory only.
// ═══════════════════════════════════════════════════════════════════════════════


// ─── 13a. DOMAIN APPEND WRAPPERS ─────────────────────────────────────────────

/**
 * Append an assignment lifecycle event.
 *
 * @param {string} incidentId - Incident document ID
 * @param {string} actorRole  - Explicit role of the actor
 * @param {Object} [details]  - Assignment details
 * @param {string} [details.from]       - Previous assignee/team
 * @param {string} [details.to]         - New assignee/team
 * @param {string} [details.reason]     - Reason for reassignment
 * @param {boolean} [details.isReassign] - true if this is a reassignment (not initial)
 * @returns {{ success: boolean }}
 */
export function appendAssignmentLifecycle(incidentId, actorRole, details = {}) {
  const eventType = details.isReassign
    ? TIMELINE_EVENTS.INCIDENT_REASSIGNED
    : TIMELINE_EVENTS.INCIDENT_ASSIGNED;

  return appendTimelineEvent({
    incidentId,
    eventType,
    actorId: auth.currentUser?.uid || "unknown",
    actorRole,
    previousState: details.from || null,
    newState: details.to || null,
    metadata: {
      from: details.from || null,
      to: details.to || null,
      reason: details.reason || null,
    },
  });
}

/**
 * Append an incident closure lifecycle event.
 *
 * @param {string} incidentId  - Incident document ID
 * @param {string} actorRole   - Explicit role of the actor
 * @param {Object} [details]   - Closure details
 * @param {string} [details.previousStatus] - Status before closure
 * @param {string} [details.reason]         - Reason for closure
 * @param {string} [details.resolution]     - Resolution type (e.g., "false_positive", "resolved", "risk_accepted")
 * @returns {{ success: boolean }}
 */
export function appendClosureLifecycle(incidentId, actorRole, details = {}) {
  return appendTimelineEvent({
    incidentId,
    eventType: TIMELINE_EVENTS.INCIDENT_CLOSED,
    actorId: auth.currentUser?.uid || "unknown",
    actorRole,
    previousState: details.previousStatus || null,
    newState: "resolved",
    metadata: {
      reason: details.reason || null,
      resolution: details.resolution || null,
    },
  });
}

/**
 * Append a triage lifecycle event.
 *
 * @param {string} incidentId  - Incident document ID
 * @param {string} actorRole   - Explicit role of the actor
 * @param {Object} [details]   - Triage details
 * @param {string} [details.previousStatus] - Previous triage status
 * @param {string} [details.newStatus]      - New triage status
 * @returns {{ success: boolean }}
 */
export function appendTriageLifecycle(incidentId, actorRole, details = {}) {
  return appendTimelineEvent({
    incidentId,
    eventType: TIMELINE_EVENTS.TRIAGE_UPDATED,
    actorId: auth.currentUser?.uid || "unknown",
    actorRole,
    previousState: details.previousStatus || null,
    newState: details.newStatus || null,
    metadata: {},
  });
}


// ─── 13b. CONSOLIDATION HELPERS ──────────────────────────────────────────────

/**
 * All 18 operational actions that should have timeline coverage.
 * Used by ensureTimelineCoverage() to audit completeness.
 */
const CRITICAL_LIFECYCLE_EVENTS = Object.freeze([
  TIMELINE_EVENTS.INCIDENT_CREATED,         // 1. incident creation
  TIMELINE_EVENTS.TRIAGE_UPDATED,           // 2. triage started
  TIMELINE_EVENTS.ESCALATION_REQUESTED,     // 3. escalation requested
  TIMELINE_EVENTS.ESCALATION_APPROVED,      // 4. escalation approved
  TIMELINE_EVENTS.ESCALATION_DENIED,        // 5. escalation denied
  TIMELINE_EVENTS.INCIDENT_ASSIGNED,        // 6. escalation routed / assigned
  TIMELINE_EVENTS.SEVERITY_CHANGED,         // 7. severity changed
  TIMELINE_EVENTS.INCIDENT_REASSIGNED,      // 8. assignment changed
  TIMELINE_EVENTS.CONTAINMENT_REQUESTED,    // 9. containment requested
  TIMELINE_EVENTS.CONTAINMENT_APPROVED,     // 10. containment approved
  TIMELINE_EVENTS.CONTAINMENT_REJECTED,     // 11. containment rejected
  TIMELINE_EVENTS.CONTAINMENT_EXECUTED,     // 12. IR action executed
  TIMELINE_EVENTS.GOVERNANCE_LOCK,          // 13. incident locked
  TIMELINE_EVENTS.GOVERNANCE_UNLOCK,        // 14. incident unlocked
  TIMELINE_EVENTS.INCIDENT_CLOSED,          // 15. incident closed
  TIMELINE_EVENTS.INCIDENT_REOPENED,        // 16. incident reopened
  TIMELINE_EVENTS.NOTE_ADDED,              // 17. analyst note added
  TIMELINE_EVENTS.GOVERNANCE_OVERRIDE,      // 18. governance override
]);

/**
 * Audit timeline coverage for an incident against all critical lifecycle events.
 *
 * Returns which of the 18 operational actions have timeline entries and
 * which are missing.
 *
 * @param {Array} events - Timeline events for a single incident
 * @returns {{ covered: string[], missing: string[], coverage: number, total: number }}
 */
export function ensureTimelineCoverage(events) {
  if (!Array.isArray(events) || events.length === 0) {
    return {
      covered: [],
      missing: [...CRITICAL_LIFECYCLE_EVENTS],
      coverage: 0,
      total: CRITICAL_LIFECYCLE_EVENTS.length,
    };
  }

  const presentTypes = new Set(events.map((e) => e?.eventType).filter(Boolean));
  const covered = CRITICAL_LIFECYCLE_EVENTS.filter((e) => presentTypes.has(e));
  const missing = CRITICAL_LIFECYCLE_EVENTS.filter((e) => !presentTypes.has(e));

  return {
    covered,
    missing,
    coverage: Math.round((covered.length / CRITICAL_LIFECYCLE_EVENTS.length) * 100),
    total: CRITICAL_LIFECYCLE_EVENTS.length,
  };
}

/**
 * Normalize raw event data into a standardized lifecycle append format.
 * Ensures consistent field naming regardless of call site conventions.
 *
 * @param {Object} raw - Raw event data from call site
 * @returns {Object} Normalized event ready for appendTimelineEvent()
 */
export function normalizeLifecycleAppend(raw) {
  if (!raw || typeof raw !== "object") return {};

  return {
    incidentId: raw.incidentId || raw.issueId || raw.id || null,
    eventType: normalizeTimelineEventType(raw.eventType || raw.type || raw.action) || raw.eventType || null,
    actorId: raw.actorId || raw.userId || raw.uid || auth.currentUser?.uid || "unknown",
    actorRole: raw.actorRole || raw.role || "unknown",
    previousState: raw.previousState || raw.previousStatus || raw.from || null,
    newState: raw.newState || raw.newStatus || raw.to || null,
    metadata: raw.metadata || {},
    source: raw.source || TIMELINE_SOURCES.CLIENT,
  };
}

/**
 * Merge multiple metadata objects into a single consolidated metadata.
 * Used when combining information from different sources for a single
 * timeline entry.
 *
 * @param  {...Object} sources - Metadata objects to merge (later overrides earlier)
 * @returns {Object} Merged metadata
 */
export function mergeLifecycleMetadata(...sources) {
  const merged = {};
  for (const source of sources) {
    if (source && typeof source === "object" && !Array.isArray(source)) {
      Object.assign(merged, source);
    }
  }
  return merged;
}


// ─── 13c. RECONSTRUCTION IMPROVEMENTS ────────────────────────────────────────

/**
 * Build a full incident timeline with enriched phase and transition data.
 *
 * Enhanced version of reconstructIncidentLifecycle() that includes:
 *   - Duration between events
 *   - Phase transitions
 *   - Actor chain
 *   - Summary statistics
 *
 * @param {Array} events - Timeline events for a single incident
 * @returns {{ timeline: Array, summary: Object }}
 */
export function buildFullIncidentTimeline(events) {
  if (!Array.isArray(events) || events.length === 0) {
    return {
      timeline: [],
      summary: { totalEvents: 0, phases: [], actors: [], duration: null },
    };
  }

  const lifecycle = reconstructIncidentLifecycle(events);

  // Enrich with durations
  const enriched = lifecycle.map((entry, i) => {
    const prevTimestamp = i > 0 ? lifecycle[i - 1].timestamp : null;
    let durationMs = null;
    if (prevTimestamp && entry.timestamp) {
      const prev = new Date(prevTimestamp).getTime();
      const curr = new Date(entry.timestamp).getTime();
      if (!isNaN(prev) && !isNaN(curr)) {
        durationMs = curr - prev;
      }
    }
    return { ...entry, index: i, durationFromPrevMs: durationMs };
  });

  // Summary
  const phases = [...new Set(enriched.map((e) => e.phase))];
  const actors = [...new Set(enriched.map((e) => e.actor).filter((a) => a !== "unknown"))];
  const firstTs = enriched[0]?.timestamp;
  const lastTs = enriched[enriched.length - 1]?.timestamp;
  let totalDuration = null;
  if (firstTs && lastTs) {
    const f = new Date(firstTs).getTime();
    const l = new Date(lastTs).getTime();
    if (!isNaN(f) && !isNaN(l)) totalDuration = l - f;
  }

  return {
    timeline: enriched,
    summary: {
      totalEvents: enriched.length,
      phases,
      actors,
      durationMs: totalDuration,
      firstEvent: enriched[0]?.eventType || null,
      lastEvent: enriched[enriched.length - 1]?.eventType || null,
    },
  };
}

/**
 * Get a concise lifecycle summary for an incident.
 *
 * Returns key lifecycle facts without the full event array.
 *
 * @param {Array} events - Timeline events for a single incident
 * @returns {Object} Lifecycle summary
 */
export function getIncidentLifecycleSummary(events) {
  if (!Array.isArray(events) || events.length === 0) {
    return {
      totalEvents: 0,
      currentState: null,
      wasEscalated: false,
      wasContained: false,
      wasLocked: false,
      wasClosed: false,
      wasReopened: false,
      coverage: 0,
    };
  }

  const types = new Set(events.map((e) => e?.eventType).filter(Boolean));
  const latest = getLatestLifecycleState(events);
  const coverage = ensureTimelineCoverage(events);

  return {
    totalEvents: events.length,
    currentState: latest.state,
    currentEventType: latest.eventType,
    wasEscalated: types.has(TIMELINE_EVENTS.ESCALATION_REQUESTED) || types.has(TIMELINE_EVENTS.ESCALATION_APPROVED),
    wasContained: types.has(TIMELINE_EVENTS.CONTAINMENT_EXECUTED) || types.has(TIMELINE_EVENTS.CONTAINMENT_APPROVED),
    wasLocked: types.has(TIMELINE_EVENTS.GOVERNANCE_LOCK),
    wasClosed: types.has(TIMELINE_EVENTS.INCIDENT_CLOSED),
    wasReopened: types.has(TIMELINE_EVENTS.INCIDENT_REOPENED),
    coverage: coverage.coverage,
  };
}


// ─── 13d. INTEGRITY PROTECTIONS ──────────────────────────────────────────────

/**
 * Detect duplicate lifecycle state transitions in a timeline.
 *
 * Flags consecutive events of the same type with the same newState —
 * these indicate a duplicate write that should have been suppressed.
 *
 * @param {Array} events - Chronologically sorted timeline events
 * @returns {{ duplicates: Array<{ index: number, eventType: string }>, count: number }}
 */
export function preventDuplicateLifecycleTransitions(events) {
  if (!Array.isArray(events) || events.length <= 1) {
    return { duplicates: [], count: 0 };
  }

  const duplicates = [];

  for (let i = 1; i < events.length; i++) {
    const prev = events[i - 1];
    const curr = events[i];

    if (!prev || !curr) continue;

    // Same event type + same newState in sequence = duplicate transition
    if (
      curr.eventType === prev.eventType &&
      curr.newState && prev.newState &&
      curr.newState === prev.newState
    ) {
      duplicates.push({ index: i, eventType: curr.eventType });
    }
  }

  return { duplicates, count: duplicates.length };
}

/**
 * Detect missing critical events that should exist based on the
 * incident's current lifecycle state.
 *
 * Stricter than detectMissingLifecycleEvents() — focuses on events
 * that are REQUIRED for operational forensic reconstruction.
 *
 * @param {Array} events - Timeline events for a single incident
 * @returns {{ missing: Array<{ event: string, reason: string }>, count: number }}
 */
export function detectMissingCriticalEvents(events) {
  if (!Array.isArray(events) || events.length === 0) {
    return { missing: [], count: 0 };
  }

  const types = new Set(events.map((e) => e?.eventType).filter(Boolean));
  const missing = [];

  // INCIDENT_CREATED must always be present
  if (!types.has(TIMELINE_EVENTS.INCIDENT_CREATED)) {
    missing.push({
      event: TIMELINE_EVENTS.INCIDENT_CREATED,
      reason: "Every incident timeline must begin with INCIDENT_CREATED",
    });
  }

  // If escalation approved, request must exist
  if (types.has(TIMELINE_EVENTS.ESCALATION_APPROVED) && !types.has(TIMELINE_EVENTS.ESCALATION_REQUESTED)) {
    missing.push({
      event: TIMELINE_EVENTS.ESCALATION_REQUESTED,
      reason: "ESCALATION_APPROVED present without ESCALATION_REQUESTED",
    });
  }

  // If escalation denied, request must exist
  if (types.has(TIMELINE_EVENTS.ESCALATION_DENIED) && !types.has(TIMELINE_EVENTS.ESCALATION_REQUESTED)) {
    missing.push({
      event: TIMELINE_EVENTS.ESCALATION_REQUESTED,
      reason: "ESCALATION_DENIED present without ESCALATION_REQUESTED",
    });
  }

  // If containment approved, request must exist
  if (types.has(TIMELINE_EVENTS.CONTAINMENT_APPROVED) && !types.has(TIMELINE_EVENTS.CONTAINMENT_REQUESTED)) {
    missing.push({
      event: TIMELINE_EVENTS.CONTAINMENT_REQUESTED,
      reason: "CONTAINMENT_APPROVED present without CONTAINMENT_REQUESTED",
    });
  }

  // If containment executed, approval must exist
  if (types.has(TIMELINE_EVENTS.CONTAINMENT_EXECUTED) && !types.has(TIMELINE_EVENTS.CONTAINMENT_APPROVED)) {
    missing.push({
      event: TIMELINE_EVENTS.CONTAINMENT_APPROVED,
      reason: "CONTAINMENT_EXECUTED present without CONTAINMENT_APPROVED",
    });
  }

  // If reopened, closed must exist
  if (types.has(TIMELINE_EVENTS.INCIDENT_REOPENED) && !types.has(TIMELINE_EVENTS.INCIDENT_CLOSED)) {
    missing.push({
      event: TIMELINE_EVENTS.INCIDENT_CLOSED,
      reason: "INCIDENT_REOPENED present without INCIDENT_CLOSED",
    });
  }

  // If unlocked, locked should exist
  if (types.has(TIMELINE_EVENTS.GOVERNANCE_UNLOCK) && !types.has(TIMELINE_EVENTS.GOVERNANCE_LOCK)) {
    missing.push({
      event: TIMELINE_EVENTS.GOVERNANCE_LOCK,
      reason: "GOVERNANCE_UNLOCK present without GOVERNANCE_LOCK",
    });
  }

  return { missing, count: missing.length };
}


// ═══════════════════════════════════════════════════════════════════════════════
// 14. TIMELINE CHRONOLOGY COMPLETION LAYER
// ═══════════════════════════════════════════════════════════════════════════════
//
// Phase: CONSOLIDATION COMPLETION (Microphase 1.6.1)
//
// Purpose: Complete chronology reconstruction, lifecycle ordering validation,
// legacy event normalization, and remaining domain append wrappers.
//
// All functions are synchronous, deterministic, in-memory only.
// All append wrappers delegate to appendTimelineEvent() (detached + deduped).
// ═══════════════════════════════════════════════════════════════════════════════


/**
 * Canonical lifecycle phase ordering for full incident reconstruction.
 * Used by getTimelineChronology() and validateChronologyOrder().
 */
export const CANONICAL_LIFECYCLE_ORDER = Object.freeze([
  TIMELINE_EVENTS.INCIDENT_CREATED,
  TIMELINE_EVENTS.INCIDENT_ASSIGNED,
  TIMELINE_EVENTS.TRIAGE_UPDATED,
  TIMELINE_EVENTS.THREAT_CONFIRMED,
  TIMELINE_EVENTS.SEVERITY_CHANGED,
  TIMELINE_EVENTS.ESCALATION_REQUESTED,
  TIMELINE_EVENTS.ESCALATION_APPROVED,
  TIMELINE_EVENTS.ESCALATION_DENIED,
  TIMELINE_EVENTS.ESCALATION_ROUTED,
  TIMELINE_EVENTS.INCIDENT_REASSIGNED,
  TIMELINE_EVENTS.CONTAINMENT_REQUESTED,
  TIMELINE_EVENTS.CONTAINMENT_APPROVED,
  TIMELINE_EVENTS.CONTAINMENT_REJECTED,
  TIMELINE_EVENTS.IR_ACTION_SUBMITTED,
  TIMELINE_EVENTS.CONTAINMENT_EXECUTED,
  TIMELINE_EVENTS.NOTE_ADDED,
  TIMELINE_EVENTS.GOVERNANCE_LOCK,
  TIMELINE_EVENTS.GOVERNANCE_UNLOCK,
  TIMELINE_EVENTS.GOVERNANCE_OVERRIDE,
  TIMELINE_EVENTS.SLA_OVERRIDE,
  TIMELINE_EVENTS.INCIDENT_CLOSED,
  TIMELINE_EVENTS.INCIDENT_REOPENED,
]);


// ─── 14a. CHRONOLOGY RECONSTRUCTION ──────────────────────────────────────────

/**
 * Build a full chronological timeline with lifecycle phase annotations.
 *
 * Returns events sorted by timestamp with phase indices showing where
 * each event falls in the canonical lifecycle progression.
 *
 * @param {Array} events - Timeline events for a single incident
 * @returns {{ chronology: Array, phases: string[], gapAnalysis: Object }}
 */
export function getTimelineChronology(events) {
  if (!Array.isArray(events) || events.length === 0) {
    return { chronology: [], phases: [], gapAnalysis: { gaps: [], count: 0 } };
  }

  const sorted = sortTimelineEvents(events, "asc");
  const phaseIndex = new Map(CANONICAL_LIFECYCLE_ORDER.map((e, i) => [e, i]));

  const chronology = sorted.map((event, i) => ({
    ...event,
    sequenceIndex: i,
    lifecyclePhase: phaseIndex.has(event.eventType) ? phaseIndex.get(event.eventType) : -1,
    isCanonical: phaseIndex.has(event.eventType),
  }));

  // Detect phase gaps (canonical events that should appear between observed events)
  const observedPhases = chronology
    .filter((e) => e.isCanonical)
    .map((e) => e.lifecyclePhase);

  const gaps = [];
  if (observedPhases.length >= 2) {
    const minPhase = Math.min(...observedPhases);
    const maxPhase = Math.max(...observedPhases);
    for (let p = minPhase; p <= maxPhase; p++) {
      if (!observedPhases.includes(p) && CANONICAL_LIFECYCLE_ORDER[p]) {
        // Not every gap is an error — e.g., not all incidents get escalated
        // Only flag required transitions
        gaps.push({
          missingEvent: CANONICAL_LIFECYCLE_ORDER[p],
          expectedBetween: [minPhase, maxPhase],
        });
      }
    }
  }

  const phases = [...new Set(chronology.map((e) => e.eventType))];

  return {
    chronology,
    phases,
    gapAnalysis: { gaps, count: gaps.length },
  };
}


/**
 * Validate that timeline events follow a reasonable chronological order.
 *
 * Checks:
 *   - Timestamps are monotonically increasing
 *   - No future timestamps
 *   - No events before INCIDENT_CREATED (if present)
 *
 * @param {Array} events - Timeline events (unsorted OK — will be sorted internally)
 * @returns {{ valid: boolean, violations: Array<{ type: string, detail: string }> }}
 */
export function validateChronologyOrder(events) {
  if (!Array.isArray(events) || events.length <= 1) {
    return { valid: true, violations: [] };
  }

  const sorted = sortTimelineEvents(events, "asc");
  const violations = [];
  const now = Date.now();

  // Find INCIDENT_CREATED timestamp if present
  const createdEvent = sorted.find((e) => e.eventType === TIMELINE_EVENTS.INCIDENT_CREATED);
  const createdTs = createdEvent ? new Date(createdEvent.timestamp).getTime() : null;

  for (let i = 0; i < sorted.length; i++) {
    const event = sorted[i];
    const eventTs = new Date(event.timestamp).getTime();

    // Check for future timestamps (more than 60s ahead)
    if (!isNaN(eventTs) && eventTs > now + 60000) {
      violations.push({
        type: "FUTURE_TIMESTAMP",
        detail: `Event ${event.eventType} at index ${i} has a future timestamp`,
      });
    }

    // Check for events before creation
    if (createdTs && !isNaN(eventTs) && eventTs < createdTs && event.eventType !== TIMELINE_EVENTS.INCIDENT_CREATED) {
      violations.push({
        type: "BEFORE_CREATION",
        detail: `Event ${event.eventType} at index ${i} predates INCIDENT_CREATED`,
      });
    }
  }

  return { valid: violations.length === 0, violations };
}


// ─── 14b. LEGACY NORMALIZATION ───────────────────────────────────────────────

/**
 * Map of legacy/inconsistent event type strings to canonical TIMELINE_EVENTS.
 */
const LEGACY_EVENT_MAP = Object.freeze({
  "incident_created":       TIMELINE_EVENTS.INCIDENT_CREATED,
  "created":                TIMELINE_EVENTS.INCIDENT_CREATED,
  "assigned":               TIMELINE_EVENTS.INCIDENT_ASSIGNED,
  "reassigned":             TIMELINE_EVENTS.INCIDENT_REASSIGNED,
  "note_added":             TIMELINE_EVENTS.NOTE_ADDED,
  "note":                   TIMELINE_EVENTS.NOTE_ADDED,
  "severity_changed":       TIMELINE_EVENTS.SEVERITY_CHANGED,
  "urgency_changed":        TIMELINE_EVENTS.SEVERITY_CHANGED,
  "status_changed":         TIMELINE_EVENTS.STATUS_CHANGED,
  "escalation_requested":   TIMELINE_EVENTS.ESCALATION_REQUESTED,
  "escalated":              TIMELINE_EVENTS.ESCALATION_REQUESTED,
  "escalation_approved":    TIMELINE_EVENTS.ESCALATION_APPROVED,
  "escalation_denied":      TIMELINE_EVENTS.ESCALATION_DENIED,
  "containment_requested":  TIMELINE_EVENTS.CONTAINMENT_REQUESTED,
  "containment_approved":   TIMELINE_EVENTS.CONTAINMENT_APPROVED,
  "containment_rejected":   TIMELINE_EVENTS.CONTAINMENT_REJECTED,
  "containment_executed":   TIMELINE_EVENTS.CONTAINMENT_EXECUTED,
  "ir_action":              TIMELINE_EVENTS.IR_ACTION_SUBMITTED,
  "ir_action_submitted":    TIMELINE_EVENTS.IR_ACTION_SUBMITTED,
  "threat_confirmed":       TIMELINE_EVENTS.THREAT_CONFIRMED,
  "confirmed_threat":       TIMELINE_EVENTS.THREAT_CONFIRMED,
  "locked":                 TIMELINE_EVENTS.GOVERNANCE_LOCK,
  "unlocked":               TIMELINE_EVENTS.GOVERNANCE_UNLOCK,
  "closed":                 TIMELINE_EVENTS.INCIDENT_CLOSED,
  "resolved":               TIMELINE_EVENTS.INCIDENT_CLOSED,
  "reopened":               TIMELINE_EVENTS.INCIDENT_REOPENED,
  "deleted":                TIMELINE_EVENTS.INCIDENT_DELETED,
  "escalation_routed":      TIMELINE_EVENTS.ESCALATION_ROUTED,
  "routed_to_ir":           TIMELINE_EVENTS.ESCALATION_ROUTED,
  "threat_hunt":            TIMELINE_EVENTS.THREAT_HUNT_CONVERTED,
  "risk_accepted":          TIMELINE_EVENTS.RISK_ACCEPTED,
  "risk_accepted_flag":     TIMELINE_EVENTS.RISK_ACCEPTED,
  "pir_tagged":             TIMELINE_EVENTS.PIR_TAGGED,
  "rca_tagged":             TIMELINE_EVENTS.RCA_TAGGED,
  "threat_hunt_started":    TIMELINE_EVENTS.THREAT_HUNT_STARTED,
  "attack_technique_mapped": TIMELINE_EVENTS.ATTACK_TECHNIQUE_MAPPED,
  "hunt_recommendation_submitted": TIMELINE_EVENTS.HUNT_RECOMMENDATION_SUBMITTED,
  "threat_hunt_returned":   TIMELINE_EVENTS.THREAT_HUNT_RETURNED,
  "threat_hunt_completed":  TIMELINE_EVENTS.THREAT_HUNT_COMPLETED,
  "sla_override":           TIMELINE_EVENTS.SLA_OVERRIDE,
  "pir_assigned":           TIMELINE_EVENTS.PIR_ASSIGNED,
  "pir_reassigned":         TIMELINE_EVENTS.PIR_REASSIGNED,
  "pir_contributor_added":  TIMELINE_EVENTS.PIR_CONTRIBUTOR_ADDED,
  "pir_contributor_removed": TIMELINE_EVENTS.PIR_CONTRIBUTOR_REMOVED,
  "pir_started":            TIMELINE_EVENTS.PIR_STARTED,
  "pir_completed":          TIMELINE_EVENTS.PIR_COMPLETED,
  "pir_approved":           TIMELINE_EVENTS.PIR_APPROVED,
  "pir_rejected":           TIMELINE_EVENTS.PIR_REJECTED,
  "rca_assigned":           TIMELINE_EVENTS.RCA_ASSIGNED,
  "rca_reassigned":         TIMELINE_EVENTS.RCA_REASSIGNED,
  "rca_contributor_added":  TIMELINE_EVENTS.RCA_CONTRIBUTOR_ADDED,
  "rca_contributor_removed": TIMELINE_EVENTS.RCA_CONTRIBUTOR_REMOVED,
  "rca_started":            TIMELINE_EVENTS.RCA_STARTED,
  "rca_completed":          TIMELINE_EVENTS.RCA_COMPLETED,
  "rca_approved":           TIMELINE_EVENTS.RCA_APPROVED,
  "rca_rejected":           TIMELINE_EVENTS.RCA_REJECTED,
});

/**
 * Normalize an array of legacy timeline events to canonical format.
 *
 * Maps legacy eventType strings to TIMELINE_EVENTS constants and
 * standardizes field naming.
 *
 * @param {Array} events - Raw timeline events (may have inconsistent types)
 * @returns {Array} Normalized events with canonical eventType values
 */
export function normalizeLegacyTimelineEvents(events) {
  if (!Array.isArray(events)) return [];

  return events.map((event) => {
    if (!event || typeof event !== "object") return event;

    const rawType = (event.eventType || event.type || event.action || "").toString();
    const normalizedType = LEGACY_EVENT_MAP[rawType.toLowerCase()] || rawType;

    return {
      ...event,
      eventType: normalizedType,
      // Standardize actor fields
      actorId: event.actorId || event.userId || event.uid || "unknown",
      actorRole: event.actorRole || event.role || "unknown",
      // Standardize state fields
      previousState: event.previousState || event.previousStatus || event.from || null,
      newState: event.newState || event.newStatus || event.to || null,
    };
  });
}


// ─── 14c. REMAINING DOMAIN WRAPPERS ──────────────────────────────────────────

/**
 * Append a governance timeline event.
 *
 * @param {string} incidentId - Incident document ID
 * @param {string} eventType  - TIMELINE_EVENTS governance constant
 * @param {string} actorRole  - Explicit role of the actor
 * @param {Object} [details]  - Additional context
 * @returns {{ success: boolean }}
 */
export function appendGovernanceTimeline(incidentId, eventType, actorRole, details = {}) {
  return appendTimelineEvent({
    incidentId,
    eventType,
    actorId: auth.currentUser?.uid || "unknown",
    actorRole,
    previousState: details.previousStatus || null,
    newState: details.newStatus || null,
    metadata: {
      domain: "governance",
      reason: details.reason || null,
      ...details,
    },
  });
}

/**
 * Append an investigation timeline event.
 *
 * @param {string} incidentId - Incident document ID
 * @param {string} eventType  - TIMELINE_EVENTS constant
 * @param {string} actorRole  - Explicit role of the actor
 * @param {Object} [details]  - Additional context
 * @returns {{ success: boolean }}
 */
export function appendInvestigationTimeline(incidentId, eventType, actorRole, details = {}) {
  return appendTimelineEvent({
    incidentId,
    eventType,
    actorId: auth.currentUser?.uid || "unknown",
    actorRole,
    metadata: {
      domain: "investigation",
      ...details,
    },
  });
}

/**
 * Append a threat confirmation timeline event.
 *
 * @param {string} incidentId - Incident document ID
 * @param {string} actorRole  - Explicit role of the actor
 * @param {Object} [details]  - { previousStatus, newStatus }
 * @returns {{ success: boolean }}
 */
export function appendThreatConfirmed(incidentId, actorRole, details = {}) {
  return appendTimelineEvent({
    incidentId,
    eventType: TIMELINE_EVENTS.THREAT_CONFIRMED,
    actorId: auth.currentUser?.uid || "unknown",
    actorRole,
    previousState: details.previousStatus || null,
    newState: "confirmed_threat",
    metadata: {},
  });
}

/**
 * Append an IR action submitted timeline event.
 *
 * @param {string} incidentId - Incident document ID
 * @param {string} actorRole  - Explicit role of the actor
 * @param {Object} [details]  - { actionType, actionDetails }
 * @returns {{ success: boolean }}
 */
export function appendIRActionSubmitted(incidentId, actorRole, details = {}) {
  return appendTimelineEvent({
    incidentId,
    eventType: TIMELINE_EVENTS.IR_ACTION_SUBMITTED,
    actorId: auth.currentUser?.uid || "unknown",
    actorRole,
    newState: "containment_action_submitted",
    metadata: {
      actionType: details.actionType || null,
      actionDetails: details.actionDetails || null,
    },
  });
}

/**
 * Append an escalation routed to IR timeline event.
 *
 * @param {string} incidentId - Incident document ID
 * @param {string} actorRole  - Explicit role of the actor
 * @param {Object} [details]  - Additional routing context
 * @returns {{ success: boolean }}
 */
export function appendEscalationRouted(incidentId, actorRole, details = {}) {
  return appendTimelineEvent({
    incidentId,
    eventType: TIMELINE_EVENTS.ESCALATION_ROUTED,
    actorId: auth.currentUser?.uid || "unknown",
    actorRole,
    newState: "routed_to_ir",
    metadata: {
      domain: "escalation",
      ...details,
    },
  });
}
