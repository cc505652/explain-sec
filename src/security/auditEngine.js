/**
 * ======================================================================
 * UNIFIED AUDIT ENGINE — Finalized Operational Layer
 * ======================================================================
 *
 * Phase: FINALIZATION (Microphase 1.6)
 *
 * PURPOSE:
 *   Provides a centralized, standardized security audit logging authority.
 *   All security-relevant events flow through logSecurityEvent() which
 *   validates, normalizes, and persists audit records.
 *
 * DESIGN:
 *   - Explicit action constants (not magic strings)
 *   - Standardized event schema with lightweight validation
 *   - Detached Firestore writes (setTimeout(0) isolation — same pattern as timelineEngine)
 *   - In-memory dedupe ring buffer (16-entry, 3s window)
 *   - Console-structured logging for debugging
 *   - actorRole is ALWAYS explicit — never auto-inferred
 *   - Domain wrappers for escalation, containment, governance, investigation
 *   - Pre-auth logout snapshot for safe teardown audit
 *
 * FIRESTORE:
 *   Uses existing `audit_logs` collection. Client writes may be blocked
 *   by Firestore security rules in production — the engine handles this
 *   gracefully with silent catch. Zero breakage risk.
 *
 * BACKWARD COMPATIBILITY:
 *   This module preserves ALL existing exports and adds new ones.
 *   It does NOT modify, replace, or interfere with:
 *     - src/utils/logger.js         (existing structured logger)
 *     - src/utils/errorHandler.js   (error categorization)
 *     - src/security/permissions.js (permission engine)
 *     - AdminDashboard.logAuditAction() (existing console-only logger)
 *     - Any component-level inline logging
 *
 * ======================================================================
 */

import { db, auth } from "../firebase";
import { collection, addDoc, serverTimestamp } from "firebase/firestore";


// ═══════════════════════════════════════════════════════════════════════════════
// 1. AUDIT ACTION CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════
//
// Every auditable action in the platform is declared here.
// Components import these constants instead of using raw strings.
//
// Naming convention: NOUN_VERB or STATE (e.g., LOGIN_SUCCESS, USER_CREATED)
// ═══════════════════════════════════════════════════════════════════════════════

export const AUDIT_ACTIONS = Object.freeze({

  // ── Authentication ──────────────────────────────────────────────────────
  /** User successfully authenticated */
  LOGIN_SUCCESS:              "LOGIN_SUCCESS",
  /** Authentication attempt failed */
  LOGIN_FAILED:               "LOGIN_FAILED",
  /** User logged out */
  LOGOUT:                     "LOGOUT",

  // ── User Management ────────────────────────────────────────────────────
  /** New user account created */
  USER_CREATED:               "USER_CREATED",
  /** User account details updated */
  USER_UPDATED:               "USER_UPDATED",
  /** User account deleted */
  USER_DELETED:               "USER_DELETED",

  // ── Role Management ────────────────────────────────────────────────────
  /** User's role was changed */
  ROLE_CHANGED:               "ROLE_CHANGED",

  // ── Access ─────────────────────────────────────────────────────────────
  /** User accessed a protected dashboard */
  DASHBOARD_ACCESS:           "DASHBOARD_ACCESS",
  /** User accessed the Investigation Console */
  INVESTIGATION_ACCESS:       "INVESTIGATION_ACCESS",

  // ── Configuration ──────────────────────────────────────────────────────
  /** System settings were modified */
  SETTINGS_CHANGED:           "SETTINGS_CHANGED",

  // ── Escalation ─────────────────────────────────────────────────────────
  /** Analyst requested escalation */
  ESCALATION_REQUESTED:       "ESCALATION_REQUESTED",
  /** Manager approved escalation */
  ESCALATION_APPROVED:        "ESCALATION_APPROVED",
  /** Manager denied escalation */
  ESCALATION_DENIED:          "ESCALATION_DENIED",
  /** Incident routed to IR after escalation */
  ESCALATION_ROUTED:          "ESCALATION_ROUTED",

  // ── Containment ────────────────────────────────────────────────────────
  /** L2 requested containment */
  CONTAINMENT_REQUESTED:      "CONTAINMENT_REQUESTED",
  /** Manager approved containment */
  CONTAINMENT_APPROVED:       "CONTAINMENT_APPROVED",
  /** Manager rejected containment */
  CONTAINMENT_REJECTED:       "CONTAINMENT_REJECTED",
  /** Manager returned containment for review */
  CONTAINMENT_REVIEW:         "CONTAINMENT_REVIEW",
  /** IR submitted containment action */
  IR_ACTION_SUBMITTED:        "IR_ACTION_SUBMITTED",
  /** Containment action executed */
  CONTAINMENT_EXECUTED:       "CONTAINMENT_EXECUTED",

  // ── Incident Lifecycle ─────────────────────────────────────────────────
  /** Incident created */
  INCIDENT_CREATED:           "INCIDENT_CREATED",
  /** Incident closed/resolved */
  INCIDENT_CLOSED:            "INCIDENT_CLOSED",
  /** Incident reopened */
  INCIDENT_REOPENED:          "INCIDENT_REOPENED",
  /** Incident assigned/reassigned */
  INCIDENT_ASSIGNED:          "INCIDENT_ASSIGNED",
  /** Incident severity changed */
  SEVERITY_CHANGED:           "SEVERITY_CHANGED",
  /** Incident status changed */
  STATUS_CHANGED:             "STATUS_CHANGED",
  /** Handoff note added */
  NOTE_ADDED:                 "NOTE_ADDED",
  /** Threat confirmed by L1 */
  THREAT_CONFIRMED:           "THREAT_CONFIRMED",
  /** Assignment or ownership changed */
  ASSIGNMENT_CHANGED:         "ASSIGNMENT_CHANGED",

  // ── Governance ─────────────────────────────────────────────────────────
  /** Incident locked by governance */
  GOVERNANCE_LOCK:            "GOVERNANCE_LOCK",
  /** Incident unlocked by governance */
  GOVERNANCE_UNLOCK:          "GOVERNANCE_UNLOCK",
  /** Governance override applied */
  GOVERNANCE_OVERRIDE:        "GOVERNANCE_OVERRIDE",
  /** Risk accepted */
  RISK_ACCEPTED:              "RISK_ACCEPTED",
  /** Converted to threat hunt */
  THREAT_HUNT_CONVERTED:      "THREAT_HUNT_CONVERTED",
  /** SLA Urgency Overridden */
  SLA_OVERRIDE:               "SLA_OVERRIDE",
  /** Post-incident review tagged */
  PIR_TAGGED:                 "PIR_TAGGED",
  /** PIR owner assigned */
  PIR_ASSIGNED:               "PIR_ASSIGNED",
  /** PIR owner reassigned */
  PIR_REASSIGNED:             "PIR_REASSIGNED",
  /** Contributor added to PIR */
  PIR_CONTRIBUTOR_ADDED:      "PIR_CONTRIBUTOR_ADDED",
  /** Contributor removed from PIR */
  PIR_CONTRIBUTOR_REMOVED:    "PIR_CONTRIBUTOR_REMOVED",
  /** PIR started by owner */
  PIR_STARTED:                "PIR_STARTED",
  /** PIR completed by owner */
  PIR_COMPLETED:              "PIR_COMPLETED",
  /** PIR approved by manager */
  PIR_APPROVED:               "PIR_APPROVED",
  /** PIR rejected by manager */
  PIR_REJECTED:               "PIR_REJECTED",
  /** RCA recommended during review */
  RCA_RECOMMENDED:            "RCA_RECOMMENDED",
  /** Root cause analysis tagged */
  RCA_TAGGED:                 "RCA_TAGGED",
  /** RCA owner assigned */
  RCA_ASSIGNED:               "RCA_ASSIGNED",
  /** RCA owner reassigned */
  RCA_REASSIGNED:             "RCA_REASSIGNED",
  /** Contributor added to RCA */
  RCA_CONTRIBUTOR_ADDED:      "RCA_CONTRIBUTOR_ADDED",
  /** Contributor removed from RCA */
  RCA_CONTRIBUTOR_REMOVED:    "RCA_CONTRIBUTOR_REMOVED",
  /** RCA started by owner */
  RCA_STARTED:                "RCA_STARTED",
  /** Root cause identified */
  ROOT_CAUSE_IDENTIFIED:      "ROOT_CAUSE_IDENTIFIED",
  /** RCA completed by owner */
  RCA_COMPLETED:              "RCA_COMPLETED",
  /** RCA approved by manager */
  RCA_APPROVED:               "RCA_APPROVED",
  /** RCA rejected by manager */
  RCA_REJECTED:               "RCA_REJECTED",
  /** Threat Hunt started by hunter */
  THREAT_HUNT_STARTED:        "THREAT_HUNT_STARTED",
  /** ATT&CK technique mapped */
  ATTACK_TECHNIQUE_MAPPED:    "ATTACK_TECHNIQUE_MAPPED",
  /** Hunt recommendation submitted */
  HUNT_RECOMMENDATION_SUBMITTED: "HUNT_RECOMMENDATION_SUBMITTED",
  /** Threat hunt returned to L2 */
  THREAT_HUNT_RETURNED:       "THREAT_HUNT_RETURNED",
  /** Threat hunt completed and closed */
  THREAT_HUNT_COMPLETED:      "THREAT_HUNT_COMPLETED",
  /** Threat hunt approved by manager */
  THREAT_HUNT_APPROVED:       "THREAT_HUNT_APPROVED",
  /** Threat hunt rejected by manager */
  THREAT_HUNT_REJECTED:       "THREAT_HUNT_REJECTED",
});


// ═══════════════════════════════════════════════════════════════════════════════
// 2. SEVERITY LEVELS & EVENT STATUS
// ═══════════════════════════════════════════════════════════════════════════════

export const AUDIT_SEVERITY = Object.freeze({
  INFO:     "INFO",
  LOW:      "LOW",
  MEDIUM:   "MEDIUM",
  HIGH:     "HIGH",
  CRITICAL: "CRITICAL",
});

export const AUDIT_STATUS = Object.freeze({
  SUCCESS:  "SUCCESS",
  FAILURE:  "FAILURE",
  DENIED:   "DENIED",
  ERROR:    "ERROR",
});


// ═══════════════════════════════════════════════════════════════════════════════
// 3. AUDIT DEDUPE RING BUFFER
// ═══════════════════════════════════════════════════════════════════════════════
//
// In-memory circular buffer prevents duplicate audit writes within a 3-second
// window. Fingerprint = `${actorId}:${action}:${targetId}`.
//
// Same pattern as timelineEngine dedupe — deterministic, zero-allocation after
// warmup, near-zero overhead.
// ═══════════════════════════════════════════════════════════════════════════════

const AUDIT_DEDUPE_SIZE = 16;
const AUDIT_DEDUPE_WINDOW_MS = 3000;
const _auditDedupeBuffer = new Array(AUDIT_DEDUPE_SIZE).fill(null);
let _auditDedupeIdx = 0;

/**
 * Check if an audit event is a duplicate within the dedupe window.
 * If not a duplicate, registers the fingerprint.
 *
 * @param {string} fingerprint - Event fingerprint
 * @returns {boolean} true if duplicate (should be suppressed)
 */
function _isAuditDuplicate(fingerprint) {
  const now = Date.now();
  for (let i = 0; i < AUDIT_DEDUPE_SIZE; i++) {
    const entry = _auditDedupeBuffer[i];
    if (entry && entry.fp === fingerprint && (now - entry.ts) < AUDIT_DEDUPE_WINDOW_MS) {
      return true;
    }
  }
  // Register
  _auditDedupeBuffer[_auditDedupeIdx] = { fp: fingerprint, ts: now };
  _auditDedupeIdx = (_auditDedupeIdx + 1) % AUDIT_DEDUPE_SIZE;
  return false;
}


// ═══════════════════════════════════════════════════════════════════════════════
// 4. VALIDATION
// ═══════════════════════════════════════════════════════════════════════════════

const REQUIRED_FIELDS = ["actorId", "action"];
const VALID_ACTIONS = new Set(Object.values(AUDIT_ACTIONS));

/**
 * Validate and normalize an audit event object.
 *
 * Required fields: actorId, action
 * Auto-populated: timestamp (if missing)
 * Defaults: severity → INFO, status → SUCCESS
 *
 * @param {Object} event - Raw audit event
 * @returns {{ valid: boolean, event: Object, errors: string[] }}
 */
export function validateAuditEvent(event) {
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

  // Validate action is a known constant (warn but don't reject unknown actions)
  if (event.action && !VALID_ACTIONS.has(event.action)) {
    errors.push(`Unknown audit action: ${event.action} (allowed but not standardized)`);
  }

  // Build normalized event with safe defaults
  const normalizedEvent = {
    actorId:    event.actorId || null,
    actorRole:  event.actorRole || null,
    action:     event.action || null,
    targetId:   event.targetId || null,
    targetType: event.targetType || null,
    incidentId: event.incidentId || event.targetId || null,
    severity:   event.severity || AUDIT_SEVERITY.INFO,
    timestamp:  event.timestamp || new Date().toISOString(),
    metadata:   event.metadata || {},
    source:     event.source || "client",
    status:     event.status || AUDIT_STATUS.SUCCESS,
  };

  const hasRequiredFields = REQUIRED_FIELDS.every((f) => normalizedEvent[f]);

  return {
    valid: hasRequiredFields,
    event: normalizedEvent,
    errors,
  };
}


// ═══════════════════════════════════════════════════════════════════════════════
// 5. DETACHED FIRESTORE WRITE
// ═══════════════════════════════════════════════════════════════════════════════
//
// Pushes audit persistence to the macrotask queue via setTimeout(0).
// Same isolation pattern as timelineEngine — ensures audit writes NEVER
// create backpressure on calling workflows.
// ═══════════════════════════════════════════════════════════════════════════════

function _detachedAuditWrite(normalizedEvent) {
  try {
    setTimeout(() => {
      try {
        const firestoreEvent = {
          ...normalizedEvent,
          _serverTimestamp: serverTimestamp(),
          _writeSource: "audit_engine_v2",
        };

        addDoc(collection(db, "audit_logs"), firestoreEvent)
          .then(() => {
            // Silent success — audit persisted
          })
          .catch((err) => {
            console.warn(
              "[AUDIT ENGINE] Firestore write failed (expected if rules block client writes):",
              err?.code || err?.message || "unknown"
            );
          });
      } catch (syncErr) {
        console.warn("[AUDIT ENGINE] Detached write setup error:", syncErr?.message || "unknown");
      }
    }, 0);
  } catch (outerErr) {
    // setTimeout itself failed — extremely rare, silently swallow
  }
}


// ═══════════════════════════════════════════════════════════════════════════════
// 6. CORE LOGGING FUNCTION
// ═══════════════════════════════════════════════════════════════════════════════
//
// logSecurityEvent() is the single entry point for all audit logging.
//
// Contract:
//   - Synchronous return (never blocks caller)
//   - Detached Firestore write (setTimeout(0) — macrotask queue)
//   - In-memory dedupe (3s window)
//   - Fails silently (console.warn on error)
//   - Never crashes UI
//   - actorRole is NEVER auto-inferred — must be passed explicitly
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Log a security audit event.
 *
 * This is the centralized audit logging authority. All security-relevant
 * events should flow through this function.
 *
 * @param {Object} event - Audit event object
 * @param {string} event.actorId    - UID of the user performing the action (REQUIRED)
 * @param {string} event.actorRole  - Role of the actor (REQUIRED — never auto-inferred)
 * @param {string} event.action     - Action constant from AUDIT_ACTIONS (REQUIRED)
 * @param {string} [event.targetId]   - ID of the target entity
 * @param {string} [event.targetType] - Type of the target (e.g., "user", "incident")
 * @param {string} [event.incidentId] - Incident ID (auto-falls back to targetId)
 * @param {string} [event.severity]   - Severity level (defaults to INFO)
 * @param {string} [event.timestamp]  - ISO timestamp (auto-added if missing)
 * @param {Object} [event.metadata]   - Additional context data
 * @param {string} [event.source]     - Event source (defaults to "client")
 * @param {string} [event.status]     - Event status (defaults to SUCCESS)
 *
 * @returns {{ success: boolean }}
 *          Always returns synchronously. Never throws.
 *
 * @example
 *   logSecurityEvent({
 *     actorId: user.uid,
 *     actorRole: "admin",
 *     action: AUDIT_ACTIONS.USER_CREATED,
 *     targetId: newUserId,
 *     targetType: "user",
 *   });
 */
export function logSecurityEvent(event) {
  try {
    // ── Step 1: Validate ──────────────────────────────────────────────────
    const validation = validateAuditEvent(event);

    if (!validation.valid) {
      console.warn(
        "[AUDIT ENGINE] Invalid event — skipped:",
        validation.errors,
        event
      );
      return { success: false };
    }

    const normalizedEvent = validation.event;

    // Log warnings for non-standard actions (but still persist them)
    if (validation.errors.length > 0) {
      console.warn("[AUDIT ENGINE] Event warnings:", validation.errors);
    }

    // ── Step 2: Dedupe check ──────────────────────────────────────────────
    const fingerprint = `${normalizedEvent.actorId}:${normalizedEvent.action}:${normalizedEvent.targetId || ""}`;
    if (_isAuditDuplicate(fingerprint)) {
      if (typeof process !== "undefined" && process.env?.NODE_ENV === "development") {
        console.warn("[AUDIT ENGINE] Duplicate suppressed:", fingerprint);
      }
      return { success: true };
    }

    // ── Step 3: Console log (structured, always succeeds) ─────────────────
    console.log(
      `🔒 [AUDIT] ${normalizedEvent.action}`,
      {
        actor: normalizedEvent.actorId,
        role: normalizedEvent.actorRole,
        target: normalizedEvent.targetId,
        severity: normalizedEvent.severity,
        status: normalizedEvent.status,
        timestamp: normalizedEvent.timestamp,
      }
    );

    // ── Step 4: Detached Firestore write ──────────────────────────────────
    _detachedAuditWrite(normalizedEvent);

    return { success: true };
  } catch (outerError) {
    // Outermost safety net — logSecurityEvent must NEVER throw
    try {
      console.warn("[AUDIT ENGINE] Unexpected error:", outerError);
    } catch (_) {
      // Even console.warn failed — silently swallow
    }
    return { success: false };
  }
}


// ═══════════════════════════════════════════════════════════════════════════════
// 7. EVENT FACTORY
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Create an audit event with actorId auto-populated from Firebase Auth.
 *
 * actorRole is ALWAYS required and NEVER auto-inferred.
 *
 * @param {string} action      - Action constant from AUDIT_ACTIONS
 * @param {string} actorRole   - Explicit role of the actor (REQUIRED)
 * @param {Object} [overrides] - Additional/override fields
 * @returns {Object} Audit event ready for logSecurityEvent()
 */
export function createAuditEvent(action, actorRole, overrides = {}) {
  return {
    actorId: auth.currentUser?.uid || "unknown",
    actorRole: actorRole,
    action: action,
    ...overrides,
  };
}


// ═══════════════════════════════════════════════════════════════════════════════
// 8. PRE-AUTH LOGOUT SNAPSHOT
// ═══════════════════════════════════════════════════════════════════════════════
//
// Captures actor context BEFORE auth.signOut() is called, so the audit
// write can reference the correct UID and role even after the auth state
// has been cleared.
//
// Usage:
//   const snapshot = captureLogoutSnapshot(role);
//   await signOut(auth);
//   logSecurityEvent(snapshot);  // Uses pre-captured UID
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Capture a pre-auth logout audit snapshot.
 *
 * MUST be called BEFORE signOut(auth) to preserve actor context.
 * The returned object is a complete audit event ready for logSecurityEvent().
 *
 * @param {string} actorRole - Explicit role of the actor logging out
 * @returns {Object} Complete audit event with pre-captured actorId
 */
export function captureLogoutSnapshot(actorRole) {
  return {
    actorId: auth.currentUser?.uid || "unknown",
    actorRole: actorRole || "unknown",
    action: AUDIT_ACTIONS.LOGOUT,
    severity: AUDIT_SEVERITY.INFO,
    timestamp: new Date().toISOString(),
    metadata: {
      logoutMethod: "user_initiated",
      capturedAt: Date.now(),
    },
  };
}


// ═══════════════════════════════════════════════════════════════════════════════
// 9. DOMAIN AUDIT WRAPPERS
// ═══════════════════════════════════════════════════════════════════════════════
//
// Centralized wrappers that standardize audit payloads for each operational
// domain. Components call these instead of constructing raw audit events.
//
// All wrappers delegate to logSecurityEvent() which provides:
//   - Detached Firestore writes
//   - Dedupe ring buffer
//   - Validation + normalization
//   - Fail-safe guarantees
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Log an escalation audit event.
 *
 * @param {string} incidentId - Incident document ID
 * @param {string} action     - AUDIT_ACTIONS escalation constant
 * @param {string} actorRole  - Explicit role of the actor
 * @param {Object} [details]  - Additional context (reason, outcome, etc.)
 * @returns {{ success: boolean }}
 */
export function logEscalationAudit(incidentId, action, actorRole, details = {}) {
  return logSecurityEvent({
    actorId: auth.currentUser?.uid || "unknown",
    actorRole,
    action,
    targetId: incidentId,
    targetType: "incident",
    incidentId,
    severity: AUDIT_SEVERITY.HIGH,
    metadata: {
      domain: "escalation",
      ...details,
    },
  });
}

/**
 * Log a containment audit event.
 *
 * @param {string} incidentId - Incident document ID
 * @param {string} action     - AUDIT_ACTIONS containment constant
 * @param {string} actorRole  - Explicit role of the actor
 * @param {Object} [details]  - Additional context
 * @returns {{ success: boolean }}
 */
export function logContainmentAudit(incidentId, action, actorRole, details = {}) {
  return logSecurityEvent({
    actorId: auth.currentUser?.uid || "unknown",
    actorRole,
    action,
    targetId: incidentId,
    targetType: "incident",
    incidentId,
    severity: AUDIT_SEVERITY.HIGH,
    metadata: {
      domain: "containment",
      ...details,
    },
  });
}

/**
 * Log a governance audit event.
 *
 * @param {string} incidentId - Incident document ID
 * @param {string} action     - AUDIT_ACTIONS governance constant
 * @param {string} actorRole  - Explicit role of the actor
 * @param {Object} [details]  - Additional context (reason, override type, etc.)
 * @returns {{ success: boolean }}
 */
export function logGovernanceAudit(incidentId, action, actorRole, details = {}) {
  return logSecurityEvent({
    actorId: auth.currentUser?.uid || "unknown",
    actorRole,
    action,
    targetId: incidentId,
    targetType: "incident",
    incidentId,
    severity: AUDIT_SEVERITY.CRITICAL,
    metadata: {
      domain: "governance",
      ...details,
    },
  });
}

/**
 * Log an investigation console access audit event.
 *
 * @param {string} actorRole - Explicit role of the actor
 * @param {Object} [details] - Additional context
 * @returns {{ success: boolean }}
 */
export function logInvestigationAudit(actorRole, details = {}) {
  return logSecurityEvent({
    actorId: auth.currentUser?.uid || "unknown",
    actorRole,
    action: AUDIT_ACTIONS.INVESTIGATION_ACCESS,
    targetType: "console",
    severity: AUDIT_SEVERITY.LOW,
    metadata: {
      domain: "investigation",
      ...details,
    },
  });
}

/**
 * Log an incident lifecycle audit event.
 *
 * @param {string} incidentId - Incident document ID
 * @param {string} action     - AUDIT_ACTIONS lifecycle constant
 * @param {string} actorRole  - Explicit role of the actor
 * @param {Object} [details]  - Additional context
 * @returns {{ success: boolean }}
 */
export function logLifecycleAudit(incidentId, action, actorRole, details = {}) {
  return logSecurityEvent({
    actorId: auth.currentUser?.uid || "unknown",
    actorRole,
    action,
    targetId: incidentId,
    targetType: "incident",
    incidentId,
    severity: AUDIT_SEVERITY.MEDIUM,
    metadata: {
      domain: "lifecycle",
      ...details,
    },
  });
}

/**
 * Log an assignment/reassignment audit event.
 *
 * @param {string} incidentId - Incident document ID
 * @param {string} actorRole  - Explicit role of the actor
 * @param {Object} [details]  - { from, to, reason }
 * @returns {{ success: boolean }}
 */
export function logAssignmentAudit(incidentId, actorRole, details = {}) {
  return logSecurityEvent({
    actorId: auth.currentUser?.uid || "unknown",
    actorRole,
    action: AUDIT_ACTIONS.ASSIGNMENT_CHANGED,
    targetId: incidentId,
    targetType: "incident",
    incidentId,
    severity: AUDIT_SEVERITY.MEDIUM,
    metadata: {
      domain: "assignment",
      from: details.from || null,
      to: details.to || null,
      reason: details.reason || null,
    },
  });
}


// ═══════════════════════════════════════════════════════════════════════════════
// 10. COMPATIBILITY BRIDGE
// ═══════════════════════════════════════════════════════════════════════════════

const LEGACY_ACTION_MAP = Object.freeze({
  "user_created":       AUDIT_ACTIONS.USER_CREATED,
  "user_updated":       AUDIT_ACTIONS.USER_UPDATED,
  "user_deleted":       AUDIT_ACTIONS.USER_DELETED,
  "role_updated":       AUDIT_ACTIONS.ROLE_CHANGED,
  "soc_config_updated": AUDIT_ACTIONS.SETTINGS_CHANGED,
});

/**
 * Bridge legacy action strings to the new audit engine.
 *
 * @param {string} legacyAction - Legacy action string (e.g., "user_created")
 * @returns {string} Standardized AUDIT_ACTIONS constant or original string
 */
export function mapLegacyAction(legacyAction) {
  return LEGACY_ACTION_MAP[legacyAction] || legacyAction;
}
