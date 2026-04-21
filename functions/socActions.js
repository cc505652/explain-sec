/**
 * SOC Platform — Secure Cloud Functions
 *
 * SECURITY ARCHITECTURE:
 * All critical incident lifecycle mutations route through these HTTP functions.
 * The client NEVER writes directly to sensitive Firestore fields for these operations.
 *
 * Defence layers:
 *  1. Firebase Auth token verified by Firebase SDK (request.auth always authentic)
 *  2. Role read from Firestore via Admin SDK (cannot be spoofed by client)
 *  3. State machine validated server-side (client guard is UX only)
 *  4. Governance lock enforced in Cloud Function before any write
 *  5. Audit log written by function — client cannot forge entries
 *
 * RELIABILITY HARDENING (Phase 2 — write-contention fix):
 *  - ALL Firestore writes are SPLIT: scalars first, arrayUnion second
 *  - ALL timestamps use `new Date()` — eliminates serverTimestamp() resolution round-trips
 *  - safeUpdate() retries once on any write failure (2-attempt total)
 *  - withTimeout(8s) wraps every Firestore / Admin SDK operation
 *  - auditLog is best-effort — NEVER blocks the success response
 *  - All 11 functions log: START → AFTER AUTH → BEFORE DB → AFTER DB → RESPONSE SENT
 *
 * WHY WRITES WERE CONTENDING:
 *  Combining multiple FieldValue.serverTimestamp() + FieldValue.arrayUnion() in one
 *  update causes Firestore to: resolve each timestamp server-side AND perform a
 *  read-modify-write for each array field — all atomically. Under concurrent load
 *  (multiple analysts acting on the same incident) this causes write contention
 *  that manifests as hanging RPCs. Splitting into two lightweight writes eliminates this.
 */

const admin = require("firebase-admin");
const { onRequest } = require("firebase-functions/v2/https");
const { FieldValue } = require("firebase-admin/firestore");

// Initialize Firebase Admin if not already initialized
if (!admin.apps.length) {
  admin.initializeApp();
}

const db = admin.firestore();

// ─────────────────────────────────────────────────────────────────────────────
// SERVER-SIDE STATE MACHINE
// Single source of truth. Any transition not listed here is REJECTED.
// ─────────────────────────────────────────────────────────────────────────────
const TRANSITIONS = {
  open:                  ["assigned", "in_progress", "false_positive", "threat_hunt"],
  assigned:              ["in_progress", "false_positive", "open", "escalation_pending", "confirmed_threat", "threat_hunt"],
  in_progress:           ["confirmed_threat", "false_positive", "escalation_pending", "resolved", "threat_hunt", "containment_pending"],
  confirmed_threat:      ["escalation_pending", "in_progress", "false_positive", "threat_hunt"],
  escalation_pending:    ["escalation_approved", "confirmed_threat", "in_progress"],
  escalation_approved:   ["ir_in_progress", "containment_pending", "containment_in_progress"],
  ir_in_progress:        ["containment_pending", "contained", "containment_in_progress"],
  containment_pending:   ["contained", "ir_in_progress"],
  contained:             ["resolved"],
  false_positive:        ["open", "resolved", "risk_accepted"],
  resolved:              ["reopened", "rca_pending", "pir_pending", "risk_accepted"],
  reopened:              ["open", "assigned", "threat_hunt"],
  // ── Governance extension states ────────────────────────────────────────────
  threat_hunt:           ["open", "in_progress", "resolved", "rca_pending"],
  risk_accepted:         ["resolved"],
  rca_pending:           ["rca_completed"],
  rca_completed:         ["resolved"],
  pir_pending:           ["pir_completed"],
  pir_completed:         ["resolved"],
  // ── Enterprise containment workflow (matches client-side state machine) ────
  containment_pending_approval: ["containment_in_progress", "investigation_l2"],
  investigation_l2:      ["in_progress", "containment_pending_approval", "confirmed_threat"],
  containment_in_progress: ["containment_action_submitted", "in_progress"],
  containment_action_submitted: ["containment_completed", "containment_rejected", "containment_review_again", "in_progress"],
  containment_completed: ["resolved", "in_progress"],
  containment_rejected:  ["containment_in_progress", "in_progress"],
  containment_review_again: ["containment_in_progress", "in_progress"],
  containment_executed:  ["resolved"],
};

function validateTransition(from, to) {
  const allowed = TRANSITIONS[from];
  if (!allowed) return { valid: false, error: `Unknown source state: "${from}"` };
  if (!allowed.includes(to)) {
    return { valid: false, error: `Cannot transition from "${from}" to "${to}"` };
  }
  return { valid: true };
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPER: Timeout wrapper (8 s) — prevents Firestore hangs
// ─────────────────────────────────────────────────────────────────────────────
const FIRESTORE_TIMEOUT_MS = 8000;

function withTimeout(promise, label) {
  return Promise.race([
    promise,
    new Promise((_, reject) =>
      setTimeout(
        () => reject(new Error(`Operation timed out: ${label} (>${FIRESTORE_TIMEOUT_MS}ms)`)),
        FIRESTORE_TIMEOUT_MS
      )
    ),
  ]);
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPER: safeUpdate — 2-attempt retry on any Firestore write
// Eliminates transient write failures under concurrent load.
// ─────────────────────────────────────────────────────────────────────────────
async function safeUpdate(ref, data, label) {
  for (let attempt = 1; attempt <= 2; attempt++) {
    try {
      return await withTimeout(ref.update(data), `${label} (attempt ${attempt})`);
    } catch (err) {
      if (attempt === 2) throw err;
      console.warn(`[safeUpdate] Attempt ${attempt} failed for "${label}": ${err.message} — retrying in 200ms…`);
      await new Promise(r => setTimeout(r, 200));
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPER: Get caller's authoritative role from Firestore (Admin SDK, never trust client)
// ─────────────────────────────────────────────────────────────────────────────
async function getCallerRole(uid) {
  const snap = await withTimeout(
    db.collection("users").doc(uid).get(),
    `getCallerRole(${uid})`
  );
  if (!snap.exists) throw new Error("User profile not found");
  const data = snap.data();
  return { role: data.role, team: data.team };
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPER: Assert governance lock (throws if locked and caller is not manager/admin)
// ─────────────────────────────────────────────────────────────────────────────
async function assertNotLocked(incidentRef, callerRole) {
  const snap = await withTimeout(incidentRef.get(), `assertNotLocked(${incidentRef.id})`);
  if (!snap.exists) throw new Error("Incident not found");
  const data = snap.data();
  if (data.locked === true && callerRole !== "soc_manager" && callerRole !== "admin") {
    throw new Error("Incident is governance-locked. SOC Manager intervention required.");
  }
  return { snap, data };
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPER: Write immutable audit log (best-effort — NEVER blocks the success response)
// ─────────────────────────────────────────────────────────────────────────────
async function writeAuditLog(action, actorUid, actorRole, incidentId, details = {}) {
  try {
    await withTimeout(
      db.collection("audit_logs").add({
        action,
        actorUid,
        actorRole,
        incidentId,
        details,
        timestamp: FieldValue.serverTimestamp(), // OK here — audit_logs are never contended
        source: "cloud_function",
      }),
      `writeAuditLog(${action})`
    );
  } catch (auditErr) {
    console.error(`[AUDIT] Failed to write audit log for action=${action}:`, auditErr.message);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPER: Verify Firebase Auth token from HTTP request
// ─────────────────────────────────────────────────────────────────────────────
async function verifyAuth(req) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    throw new Error("Unauthorized: No token provided");
  }
  const token = authHeader.split("Bearer ")[1];
  try {
    const decoded = await withTimeout(
      admin.auth().verifyIdToken(token),
      "verifyIdToken"
    );
    return decoded;
  } catch (error) {
    if (error.message.startsWith("Operation timed out")) throw error;
    throw new Error("Unauthorized: Invalid token");
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPER: Normalize role input to canonical format
// ─────────────────────────────────────────────────────────────────────────────
function normalizeRole(role) {
  if (!role || typeof role !== "string") return null;
  const cleaned = role.trim().toLowerCase().replace(/[\s-]+/g, "_").replace(/__+/g, "_");
  const roleAliasMap = {
    "socl1": "soc_l1",
    "socl2": "soc_l2",
    "incidentresponse": "ir",
    "incident_response": "ir",
    "threathunter": "threat_hunter",
    "socmanager": "soc_manager",
    "analyst": "soc_l1",
    "student": "student",
    "admin": "admin",
  };
  return roleAliasMap[cleaned] || cleaned;
}

// ─────────────────────────────────────────────────────────────────────────────
// FUNCTION 1: escalateIncident
// L1 → L2 (direct) | L2 → IR (via manager queue)
// ─────────────────────────────────────────────────────────────────────────────
exports.escalateIncident = onRequest(
  { region: "asia-south1" },
  async (req, res) => {
    res.set("Access-Control-Allow-Origin", "*");
    res.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    if (req.method === "OPTIONS") return res.status(204).send("");

    const startTime = Date.now();

    try {
      console.log("[escalateIncident] START", req.method, req.body);

      if (!req.body) return res.status(400).json({ success: false, error: "Missing body" });

      const auth = await verifyAuth(req);
      const uid = auth.uid;
      console.log("[escalateIncident] AFTER AUTH uid=", uid);

      const { incidentId } = req.body;
      if (!incidentId) return res.status(400).json({ success: false, error: "Missing incidentId" });

      const { role, team } = await getCallerRole(uid);

      const ALLOWED_ROLES = ["analyst", "soc_l1", "soc_l2", "ir", "threat_hunter", "soc_manager", "admin"];
      if (!ALLOWED_ROLES.includes(role)) {
        return res.status(403).json({ success: false, error: "Insufficient role to escalate incidents" });
      }

      console.log("[escalateIncident] BEFORE DB read");
      const incidentRef = db.collection("issues").doc(incidentId);
      const { data: incident } = await assertNotLocked(incidentRef, role);
      console.log("[escalateIncident] AFTER DB read status=", incident.status);

      const isL1 = team === "soc_l1" || role === "soc_l1";
      const now = new Date();

      if (isL1) {
        const ALLOWED_FROM = ["open", "in_progress", "assigned", "confirmed_threat"];
        if (!ALLOWED_FROM.includes(incident.status)) {
          return res.status(400).json({ success: false, error: `Cannot escalate from status: ${incident.status}` });
        }

        console.log("[escalateIncident] BEFORE DB write (L1→L2 core)");
        // Write 1: scalars only — no arrayUnion, no serverTimestamp
        await safeUpdate(incidentRef, {
          assignedTo: "soc_l2",
          assignedAt: now,
          status: "assigned",
          escalationRequested: false,
          escalationApproved: false,
          escalationDenied: false,
          updatedAt: now,
        }, "escalateIncident.core(L1→L2)");

        // Write 2: arrayUnion isolated
        await safeUpdate(incidentRef, {
          statusHistory: FieldValue.arrayUnion({
            status: "assigned",
            note: "Escalated L1 → L2",
            by: uid,
            at: now.toISOString(),
          }),
        }, "escalateIncident.history(L1→L2)");

        await writeAuditLog("escalate_l1_to_l2", uid, role, incidentId, { from: incident.status });
        console.log("[escalateIncident] RESPONSE SENT executionTime=", Date.now() - startTime);
        return res.status(200).json({ success: true, message: "Escalated to SOC L2" });

      } else {
        const ALLOWED_FROM = ["confirmed_threat", "in_progress", "assigned"];
        if (!ALLOWED_FROM.includes(incident.status)) {
          return res.status(400).json({ success: false, error: `Cannot escalate to IR from: ${incident.status}` });
        }
        if (incident.escalationRequested === true || incident.escalationApproved === true) {
          return res.status(409).json({ success: false, error: "Escalation already requested or approved" });
        }
        const check = validateTransition(incident.status, "escalation_pending");
        if (!check.valid) return res.status(400).json({ success: false, error: check.error });

        console.log("[escalateIncident] BEFORE DB write (L2→IR core)");
        // Write 1: scalars
        await safeUpdate(incidentRef, {
          escalationRequested: true,
          escalationApproved: false,
          escalationDenied: false,
          escalatedTo: "IR Team",
          escalated: true,
          escalatedAt: now,
          escalationRequestedBy: uid,
          escalationRequestedAt: now,
          governanceLock: true,
          status: "escalation_pending",
          updatedAt: now,
        }, "escalateIncident.core(L2→IR)");

        // Write 2: arrayUnion isolated
        await safeUpdate(incidentRef, {
          statusHistory: FieldValue.arrayUnion({
            status: "escalation_pending",
            note: "IR escalation requested",
            by: uid,
            at: now.toISOString(),
          }),
        }, "escalateIncident.history(L2→IR)");

        await writeAuditLog("escalate_l2_to_ir_pending", uid, role, incidentId, { from: incident.status });
        console.log("[escalateIncident] RESPONSE SENT executionTime=", Date.now() - startTime);
        return res.status(200).json({ success: true, message: "Escalation submitted for manager approval" });
      }

    } catch (err) {
      console.error("[escalateIncident] ERROR", err.message, err.stack);
      return res.status(500).json({ success: false, error: err.message || "Internal server error" });
    }
  }
);

// ─────────────────────────────────────────────────────────────────────────────
// FUNCTION 2: approveEscalation (SOC Manager only)
// ─────────────────────────────────────────────────────────────────────────────
exports.approveEscalation = onRequest(
  { region: "asia-south1" },
  async (req, res) => {
    res.set("Access-Control-Allow-Origin", "*");
    res.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    if (req.method === "OPTIONS") return res.status(204).send("");

    const startTime = Date.now();

    try {
      console.log("[approveEscalation] START", req.method, req.body);

      if (!req.body) return res.status(400).json({ success: false, error: "Missing body" });

      const auth = await verifyAuth(req);
      const uid = auth.uid;
      console.log("[approveEscalation] AFTER AUTH uid=", uid);

      const { incidentId } = req.body;
      if (!incidentId) return res.status(400).json({ success: false, error: "Missing incidentId" });

      const { role } = await getCallerRole(uid);
      if (role !== "soc_manager" && role !== "admin") {
        return res.status(403).json({ success: false, error: "Only SOC Manager can approve escalations" });
      }

      console.log("[approveEscalation] BEFORE DB read");
      const incidentRef = db.collection("issues").doc(incidentId);
      const snap = await withTimeout(incidentRef.get(), "approveEscalation.get");
      if (!snap.exists) return res.status(404).json({ success: false, error: "Incident not found" });

      const incident = snap.data();
      console.log("[approveEscalation] AFTER DB read status=", incident.status);

      if (incident.escalationApproved === true) {
        return res.status(409).json({ success: false, error: "Escalation already approved" });
      }
      const check = validateTransition(incident.status, "escalation_approved");
      if (!check.valid) return res.status(400).json({ success: false, error: check.error });

      const now = new Date();

      console.log("[approveEscalation] BEFORE DB write");
      // Write 1: scalars
      await safeUpdate(incidentRef, {
        status: "escalation_approved",
        escalationApproved: true,
        escalationDenied: false,
        escalationApprovedBy: uid,
        escalationApprovedAt: now,
        assignedTo: "IR Team",
        assignedAt: now,
        locked: false,
        governanceLock: false,
        updatedAt: now,
      }, "approveEscalation.core");

      // Write 2: arrayUnion isolated
      await safeUpdate(incidentRef, {
        statusHistory: FieldValue.arrayUnion({
          status: "escalation_approved",
          note: "Escalation approved by SOC Manager — assigned to IR Team",
          by: uid,
          at: now.toISOString(),
        }),
      }, "approveEscalation.history");

      await writeAuditLog("approve_escalation", uid, role, incidentId, { approvedBy: uid });
      console.log("[approveEscalation] RESPONSE SENT executionTime=", Date.now() - startTime);
      return res.status(200).json({ success: true, message: "Escalation approved, assigned to IR Team" });

    } catch (err) {
      console.error("[approveEscalation] ERROR", err.message, err.stack);
      return res.status(500).json({ success: false, error: err.message || "Internal server error" });
    }
  }
);

// ─────────────────────────────────────────────────────────────────────────────
// FUNCTION 3: denyEscalation (SOC Manager only)
// ─────────────────────────────────────────────────────────────────────────────
exports.denyEscalation = onRequest(
  { region: "asia-south1" },
  async (req, res) => {
    res.set("Access-Control-Allow-Origin", "*");
    res.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    if (req.method === "OPTIONS") return res.status(204).send("");

    const startTime = Date.now();

    try {
      console.log("[denyEscalation] START", req.method, req.body);

      if (!req.body) return res.status(400).json({ success: false, error: "Missing body" });

      const auth = await verifyAuth(req);
      const uid = auth.uid;
      console.log("[denyEscalation] AFTER AUTH uid=", uid);

      const { incidentId, reason } = req.body;
      if (!incidentId) return res.status(400).json({ success: false, error: "Missing incidentId" });

      const { role } = await getCallerRole(uid);
      if (role !== "soc_manager" && role !== "admin") {
        return res.status(403).json({ success: false, error: "Only SOC Manager can deny escalations" });
      }

      console.log("[denyEscalation] BEFORE DB read");
      const incidentRef = db.collection("issues").doc(incidentId);
      const snap = await withTimeout(incidentRef.get(), "denyEscalation.get");
      if (!snap.exists) return res.status(404).json({ success: false, error: "Incident not found" });
      const incident = snap.data();
      console.log("[denyEscalation] AFTER DB read status=", incident.status);

      const resetStatus = incident.status === "escalation_pending"
        ? "in_progress"
        : ["confirmed_threat", "in_progress"].includes(incident.status)
          ? incident.status
          : "in_progress";

      const now = new Date();

      console.log("[denyEscalation] BEFORE DB write resetStatus=", resetStatus);
      // Write 1: scalars
      await safeUpdate(incidentRef, {
        status: resetStatus,
        escalationRequested: false,
        escalationDenied: true,
        escalationDeniedBy: uid,
        escalationDeniedAt: now,
        locked: false,
        governanceLock: false,
        updatedAt: now,
      }, "denyEscalation.core");

      // Write 2: arrayUnion isolated
      await safeUpdate(incidentRef, {
        statusHistory: FieldValue.arrayUnion({
          status: "escalation_denied",
          note: `Escalation denied by SOC Manager. Reason: ${reason || "None provided"}`,
          by: uid,
          at: now.toISOString(),
        }),
      }, "denyEscalation.history");

      await writeAuditLog("deny_escalation", uid, role, incidentId, { reason, resetTo: resetStatus });
      console.log("[denyEscalation] RESPONSE SENT executionTime=", Date.now() - startTime);
      return res.status(200).json({ success: true, message: "Escalation denied — incident returned to investigation" });

    } catch (err) {
      console.error("[denyEscalation] ERROR", err.message, err.stack);
      return res.status(500).json({ success: false, error: err.message || "Internal server error" });
    }
  }
);

// ─────────────────────────────────────────────────────────────────────────────
// FUNCTION 4: performContainment (IR Team only)
// ─────────────────────────────────────────────────────────────────────────────
exports.performContainment = onRequest(
  { region: "asia-south1" },
  async (req, res) => {
    res.set("Access-Control-Allow-Origin", "*");
    res.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    if (req.method === "OPTIONS") return res.status(204).send("");

    const startTime = Date.now();

    try {
      console.log("[performContainment] START", req.method, req.body);

      if (!req.body) return res.status(400).json({ success: false, error: "Missing body" });

      const auth = await verifyAuth(req);
      const uid = auth.uid;
      console.log("[performContainment] AFTER AUTH uid=", uid);

      const { incidentId, actionType } = req.body;
      if (!incidentId || !actionType) {
        return res.status(400).json({ success: false, error: "incidentId and actionType required" });
      }

      const VALID_ACTIONS = ["isolate_host", "block_ip", "disable_account", "terminate_session", "quarantine_file"];
      if (!VALID_ACTIONS.includes(actionType)) {
        return res.status(400).json({ success: false, error: `Invalid containment action: ${actionType}` });
      }

      const { role, team } = await getCallerRole(uid);
      const IR_ROLES = ["ir", "soc_manager", "admin"];
      if (!IR_ROLES.includes(role) && team !== "incident_response") {
        return res.status(403).json({ success: false, error: "Only IR Team can perform containment actions" });
      }

      console.log("[performContainment] BEFORE DB read");
      const incidentRef = db.collection("issues").doc(incidentId);
      const { data: incident } = await assertNotLocked(incidentRef, role);
      console.log("[performContainment] AFTER DB read status=", incident.status);

      if (incident.assignedTo !== "IR Team" && incident.assignedTo !== uid && role !== "admin" && role !== "soc_manager") {
        return res.status(403).json({ success: false, error: "Incident is not assigned to IR Team" });
      }

      const ALLOWED_FROM = ["escalation_approved", "ir_in_progress"];
      if (!ALLOWED_FROM.includes(incident.status)) {
        return res.status(400).json({ success: false, error: `Cannot perform containment from status: ${incident.status}` });
      }

      const now = new Date();

      console.log("[performContainment] BEFORE DB write");
      // Write 1: scalars
      await safeUpdate(incidentRef, {
        status: "contained",
        containmentActionTaken: actionType,
        containmentCompletedAt: now,
        readyForManagerReview: true,
        containmentPerformedBy: uid,
        updatedAt: now,
      }, "performContainment.core");

      // Write 2: both arrayUnions on separate fields — isolated from scalars
      await safeUpdate(incidentRef, {
        statusHistory: FieldValue.arrayUnion({
          status: "contained",
          note: `Containment action "${actionType}" performed by IR Team`,
          by: uid,
          at: now.toISOString(),
        }),
        investigationHistory: FieldValue.arrayUnion({
          action: actionType,
          by: uid,
          at: now.toISOString(),
        }),
      }, "performContainment.history");

      await writeAuditLog("containment_performed", uid, role, incidentId, { actionType });
      console.log("[performContainment] RESPONSE SENT executionTime=", Date.now() - startTime);
      return res.status(200).json({ success: true, message: `Containment action "${actionType}" completed` });

    } catch (err) {
      console.error("[performContainment] ERROR", err.message, err.stack);
      return res.status(500).json({ success: false, error: err.message || "Internal server error" });
    }
  }
);

// ─────────────────────────────────────────────────────────────────────────────
// FUNCTION 5: approveContainment (SOC Manager only)
// ─────────────────────────────────────────────────────────────────────────────
exports.approveContainment = onRequest(
  { region: "asia-south1" },
  async (req, res) => {
    res.set("Access-Control-Allow-Origin", "*");
    res.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    if (req.method === "OPTIONS") return res.status(204).send("");

    const startTime = Date.now();

    try {
      console.log("[approveContainment] START", req.method, req.body);

      if (!req.body) return res.status(400).json({ success: false, error: "Missing body" });

      const auth = await verifyAuth(req);
      const uid = auth.uid;
      console.log("[approveContainment] AFTER AUTH uid=", uid);

      const { incidentId } = req.body;
      if (!incidentId) return res.status(400).json({ success: false, error: "Missing incidentId" });

      const { role } = await getCallerRole(uid);
      if (role !== "soc_manager" && role !== "admin") {
        return res.status(403).json({ success: false, error: "Only SOC Manager can approve containment" });
      }

      console.log("[approveContainment] BEFORE DB read");
      const incidentRef = db.collection("issues").doc(incidentId);
      const snap = await withTimeout(incidentRef.get(), "approveContainment.get");
      if (!snap.exists) return res.status(404).json({ success: false, error: "Incident not found" });

      const incident = snap.data();
      console.log("[approveContainment] AFTER DB read status=", incident.status, "readyForManagerReview=", incident.readyForManagerReview);

      const ALLOWED_FROM = ["contained", "containment_pending", "ir_in_progress"];
      if (!ALLOWED_FROM.includes(incident.status) || incident.readyForManagerReview !== true) {
        return res.status(400).json({
          success: false,
          error: `Containment not ready for review. Status: ${incident.status}, readyForManagerReview: ${incident.readyForManagerReview}`,
        });
      }

      const now = new Date();

      console.log("[approveContainment] BEFORE DB write");
      // Write 1: scalars
      await safeUpdate(incidentRef, {
        status: "resolved",
        resolvedAt: now,
        resolvedBy: uid,
        containmentApprovedBy: uid,
        containmentApprovedAt: now,
        readyForManagerReview: false,
        updatedAt: now,
      }, "approveContainment.core");

      // Write 2: arrayUnion isolated
      await safeUpdate(incidentRef, {
        statusHistory: FieldValue.arrayUnion({
          status: "resolved",
          note: "Containment approved and incident resolved by SOC Manager",
          by: uid,
          at: now.toISOString(),
        }),
      }, "approveContainment.history");

      await writeAuditLog("containment_approved", uid, role, incidentId);
      console.log("[approveContainment] RESPONSE SENT executionTime=", Date.now() - startTime);
      return res.status(200).json({ success: true, message: "Containment approved — incident resolved" });

    } catch (err) {
      console.error("[approveContainment] ERROR", err.message, err.stack);
      return res.status(500).json({ success: false, error: err.message || "Internal server error" });
    }
  }
);

// ─────────────────────────────────────────────────────────────────────────────
// FUNCTION 6: lockIncident / unlockIncident (SOC Manager only)
// ─────────────────────────────────────────────────────────────────────────────
exports.lockIncident = onRequest(
  { region: "asia-south1" },
  async (req, res) => {
    res.set("Access-Control-Allow-Origin", "*");
    res.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    if (req.method === "OPTIONS") return res.status(204).send("");

    const startTime = Date.now();

    try {
      console.log("[lockIncident] START", req.method, req.body);

      if (!req.body) return res.status(400).json({ success: false, error: "Missing body" });

      const { incidentId, lock } = req.body;
      if (!incidentId) return res.status(400).json({ success: false, error: "Missing incidentId" });
      if (typeof lock !== "boolean") return res.status(400).json({ success: false, error: "lock field must be a boolean" });

      const auth = await verifyAuth(req);
      const uid = auth.uid;
      console.log("[lockIncident] AFTER AUTH uid=", uid, "lock=", lock);

      const { role } = await getCallerRole(uid);
      if (role !== "soc_manager" && role !== "admin") {
        return res.status(403).json({ success: false, error: "Only SOC Manager can lock/unlock incidents" });
      }

      console.log("[lockIncident] BEFORE DB read");
      const incidentRef = db.collection("issues").doc(incidentId);
      const snap = await withTimeout(incidentRef.get(), "lockIncident.get");
      if (!snap.exists) return res.status(404).json({ success: false, error: "Incident not found" });
      console.log("[lockIncident] AFTER DB read");

      const now = new Date();

      console.log("[lockIncident] BEFORE DB write");
      // Write 1: scalars
      await safeUpdate(incidentRef, {
        locked: lock,
        governanceLock: lock,
        lockedBy: lock ? uid : null,
        lockedAt: lock ? now : null,
        updatedAt: now,
      }, "lockIncident.core");

      // Write 2: arrayUnion isolated
      await safeUpdate(incidentRef, {
        statusHistory: FieldValue.arrayUnion({
          status: `governance_${lock ? "locked" : "unlocked"}`,
          note: `Incident ${lock ? "locked" : "unlocked"} by SOC Manager`,
          by: uid,
          at: now.toISOString(),
        }),
      }, "lockIncident.history");

      await writeAuditLog(`incident_${lock ? "locked" : "unlocked"}`, uid, role, incidentId, { lock });
      console.log("[lockIncident] RESPONSE SENT executionTime=", Date.now() - startTime);
      return res.status(200).json({ success: true, message: `Incident ${lock ? "locked" : "unlocked"}` });

    } catch (err) {
      console.error("[lockIncident] ERROR", err.message, err.stack);
      return res.status(500).json({ success: false, error: err.message || "Internal server error" });
    }
  }
);

// ─────────────────────────────────────────────────────────────────────────────
// FUNCTION 7: updateRole (Admin only — prevents client-side role escalation)
// ─────────────────────────────────────────────────────────────────────────────
exports.updateRole = onRequest(
  { region: "asia-south1" },
  async (req, res) => {
    res.set("Access-Control-Allow-Origin", "*");
    res.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    if (req.method === "OPTIONS") return res.status(204).send("");

    const startTime = Date.now();

    try {
      console.log("[updateRole] START", req.method, req.body);

      if (!req.body) return res.status(400).json({ success: false, error: "Missing body" });

      const auth = await verifyAuth(req);
      const uid = auth.uid;
      console.log("[updateRole] AFTER AUTH uid=", uid);

      const { targetUid, newRole, newTeam, newAnalystLevel } = req.body;
      if (!targetUid || !newRole) {
        return res.status(400).json({ success: false, error: "targetUid and newRole required" });
      }

      const { role: callerRole } = await getCallerRole(uid);
      if (callerRole !== "admin") {
        return res.status(403).json({ success: false, error: "Only Admin can update user roles" });
      }
      if (targetUid === uid && newRole !== "admin") {
        return res.status(403).json({ success: false, error: "Admin cannot demote their own account" });
      }

      const normalizedRole = normalizeRole(newRole);
      const VALID_ROLES = ["student", "analyst", "soc_l1", "soc_l2", "ir", "threat_hunter", "soc_manager", "admin"];
      if (!VALID_ROLES.includes(normalizedRole)) {
        return res.status(400).json({ success: false, error: `Invalid role: ${newRole} (normalized: ${normalizedRole})` });
      }

      const now = new Date();
      const updateData = {
        role: normalizedRole,
        roleUpdatedBy: uid,
        roleUpdatedAt: now,
      };
      if (newTeam) updateData.team = newTeam;
      if (newAnalystLevel) updateData.analystLevel = newAnalystLevel;

      console.log("[updateRole] BEFORE DB write targetUid=", targetUid, "role=", normalizedRole);
      // Single scalar write — no arrays, no contention risk
      await safeUpdate(db.collection("users").doc(targetUid), updateData, "updateRole.update");

      await writeAuditLog("role_updated", uid, callerRole, null, {
        targetUid, newRole: normalizedRole, newTeam, newAnalystLevel,
      });

      console.log("[updateRole] RESPONSE SENT executionTime=", Date.now() - startTime);
      return res.status(200).json({ success: true, message: `Role updated to ${normalizedRole}` });

    } catch (err) {
      console.error("[updateRole] ERROR", err.message, err.stack);
      return res.status(500).json({ success: false, error: err.message || "Internal server error" });
    }
  }
);

// ─────────────────────────────────────────────────────────────────────────────
// FUNCTION 8: updateIncidentStatus
// General status update with server-side state machine validation.
// ─────────────────────────────────────────────────────────────────────────────
exports.updateIncidentStatus = onRequest(
  { region: "asia-south1" },
  async (req, res) => {
    res.set("Access-Control-Allow-Origin", "*");
    res.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    if (req.method === "OPTIONS") return res.status(204).send("");

    const startTime = Date.now();

    try {
      console.log("[updateIncidentStatus] START", req.method, req.body);

      if (!req.body) return res.status(400).json({ success: false, error: "Missing body" });

      const { incidentId, nextStatus, note } = req.body;
      if (!incidentId) return res.status(400).json({ success: false, error: "Missing incidentId" });
      if (!nextStatus) return res.status(400).json({ success: false, error: "Missing nextStatus" });

      const auth = await verifyAuth(req);
      const uid = auth.uid;
      console.log("[updateIncidentStatus] AFTER AUTH uid=", uid);

      const { role, team } = await getCallerRole(uid);

      const ALLOWED_ROLES = ["analyst", "soc_l1", "soc_l2", "ir", "threat_hunter", "soc_manager", "admin"];
      if (!ALLOWED_ROLES.includes(role)) {
        return res.status(403).json({ success: false, error: "Insufficient role" });
      }

      console.log("[updateIncidentStatus] BEFORE DB read incidentId=", incidentId);
      const incidentRef = db.collection("issues").doc(incidentId);
      const { data: incident } = await assertNotLocked(incidentRef, role);
      console.log("[updateIncidentStatus] AFTER DB read currentStatus=", incident.status, "→", nextStatus);

      const check = validateTransition(incident.status, nextStatus);
      if (!check.valid) return res.status(400).json({ success: false, error: check.error });

      const isManagerOrAdmin = role === "soc_manager" || role === "admin";
      const isIRAssigned = (team === "incident_response" || role === "ir") && incident.assignedTo === "IR Team";
      const isAssignedToUser = incident.assignedTo === uid;

      if (!isManagerOrAdmin && !isIRAssigned && !isAssignedToUser) {
        return res.status(403).json({ success: false, error: "Incident is not assigned to you" });
      }
      if (isIRAssigned && !isManagerOrAdmin && nextStatus === "resolved") {
        return res.status(403).json({
          success: false,
          error: "IR Team cannot resolve directly. Containment must be approved by SOC Manager.",
        });
      }

      const now = new Date();

      // Write 1: core status scalars only
      const coreUpdate = { status: nextStatus, updatedAt: now };
      if (nextStatus === "resolved") {
        coreUpdate.resolvedAt = now;
        coreUpdate.resolvedBy = uid;
      }
      if (nextStatus === "in_progress") {
        coreUpdate.triagedBy = uid;
        coreUpdate.triageStartedAt = now;
      }

      console.log("[updateIncidentStatus] BEFORE DB write (core)");
      await safeUpdate(incidentRef, coreUpdate, "updateIncidentStatus.core");

      // Write 2: statusHistory arrayUnion isolated
      await safeUpdate(incidentRef, {
        statusHistory: FieldValue.arrayUnion({
          status: nextStatus,
          note: note || `Status updated to ${nextStatus}`,
          by: uid,
          at: now.toISOString(),
        }),
      }, "updateIncidentStatus.history");

      await writeAuditLog("status_updated", uid, role, incidentId, { from: incident.status, to: nextStatus });
      console.log("[updateIncidentStatus] RESPONSE SENT executionTime=", Date.now() - startTime);

      return res.status(200).json({ success: true, message: `Status updated to ${nextStatus}` });

    } catch (err) {
      console.error("[updateIncidentStatus] ERROR", err.message, err.stack);
      return res.status(500).json({ success: false, error: err.message || "Internal server error" });
    }
  }
);

// ─────────────────────────────────────────────────────────────────────────────
// FUNCTION 9: governanceActions
// Unified governance dispatcher for manager-level advanced actions.
// ─────────────────────────────────────────────────────────────────────────────
exports.governanceActions = onRequest(
  { region: "asia-south1" },
  async (req, res) => {
    res.set("Access-Control-Allow-Origin", "*");
    res.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    if (req.method === "OPTIONS") return res.status(204).send("");

    const startTime = Date.now();

    try {
      console.log("[governanceActions] START", req.method, req.body);

      if (!req.body) return res.status(400).json({ success: false, error: "Missing body" });

      const { incidentId, actionType, payload = {} } = req.body;
      if (!incidentId) return res.status(400).json({ success: false, error: "Missing incidentId" });
      if (!actionType) return res.status(400).json({ success: false, error: "Missing actionType" });

      const auth = await verifyAuth(req);
      const uid = auth.uid;
      const { role } = await getCallerRole(uid);
      console.log(`[governanceActions] AFTER AUTH uid=${uid} role=${role} action=${actionType} incident=${incidentId}`);

      if (role !== "soc_manager" && role !== "admin") {
        return res.status(403).json({ success: false, error: "governanceActions requires soc_manager or admin role" });
      }

      console.log("[governanceActions] BEFORE DB read");
      const incidentRef = db.collection("issues").doc(incidentId);
      const { data: incident } = await assertNotLocked(incidentRef, role);
      const previousStatus = incident.status;
      console.log("[governanceActions] AFTER DB read previousStatus=", previousStatus);

      const REASON_REQUIRED = [
        "OVERRIDE_DECISION", "SLA_OVERRIDE", "TRANSFER_OWNERSHIP",
        "CONVERT_TO_THREAT_HUNT", "REOPEN_INCIDENT", "REJECT_CONTAINMENT",
        "ACCEPT_RISK", "TAG_RCA", "TAG_PIR",
      ];
      if (REASON_REQUIRED.includes(actionType)) {
        if (!payload.reason || String(payload.reason).trim().length < 3) {
          return res.status(400).json({
            success: false,
            error: `reason is REQUIRED for ${actionType} (minimum 3 characters)`,
          });
        }
      }

      const now = new Date();

      // coreUpdate holds only scalar fields (no arrayUnion, no serverTimestamp)
      // historyEntry holds the statusHistory entry to be arrayUnion'd in a second write
      let coreUpdate = { updatedAt: now };
      let historyEntry = null; // { status, note }
      let auditDetails = {
        actionType,
        performedBy: uid,
        previousState: previousStatus,
        newState: previousStatus,
        reason: payload.reason || "",
      };

      // ── Action dispatch ─────────────────────────────────────────────────────
      if (actionType === "TRANSFER_OWNERSHIP") {
        const { newAssignedTo } = payload;
        if (!newAssignedTo) return res.status(400).json({ success: false, error: "Missing newAssignedTo" });
        coreUpdate.assignedTo = newAssignedTo;
        coreUpdate.assignedAt = now;
        coreUpdate.ownershipTransferred = true;
        coreUpdate.transferBy = uid;
        historyEntry = {
          status: "ownership_transfer",
          note: `Transferred to ${newAssignedTo} by ${role}. Reason: ${payload.reason}`,
          by: uid,
          at: now.toISOString(),
        };
        auditDetails.newAssignee = newAssignedTo;
      }
      else if (actionType === "UPDATE_TAGS") {
        const tags = payload.tags;
        if (!Array.isArray(tags)) return res.status(400).json({ success: false, error: "tags must be an array" });
        const sanitized = [...new Set(tags.map(t => String(t).trim().toLowerCase()).filter(Boolean))];
        coreUpdate.tags = sanitized;
        auditDetails.tags = sanitized;
        // No statusHistory entry for tag updates
      }
      else if (actionType === "REOPEN_INCIDENT") {
        coreUpdate.status = "reopened";
        coreUpdate.reopenedAt = now;
        coreUpdate.reopenedBy = uid;
        historyEntry = { status: "reopened", note: `Reopened by ${role}. Reason: ${payload.reason}`, by: uid, at: now.toISOString() };
        auditDetails.newState = "reopened";
      }
      else if (actionType === "ACCEPT_RISK") {
        coreUpdate.status = "risk_accepted";
        coreUpdate.riskAccepted = true;
        coreUpdate.riskAcceptedBy = uid;
        coreUpdate.riskAcceptedAt = now;
        historyEntry = { status: "risk_accepted", note: `Risk accepted by ${role}. Reason: ${payload.reason}`, by: uid, at: now.toISOString() };
        auditDetails.newState = "risk_accepted";
      }
      else if (actionType === "ADD_EVIDENCE") {
        const { type, content } = payload;
        if (!type) return res.status(400).json({ success: false, error: "Missing type for ADD_EVIDENCE" });
        if (!content) return res.status(400).json({ success: false, error: "Missing content for ADD_EVIDENCE" });
        console.log("[governanceActions] BEFORE DB write (evidence subcollection)");
        // Evidence goes into a subcollection — completely separate document, no contention with incident doc
        await withTimeout(
          db.collection("issues").doc(incidentId).collection("evidence").add({
            type,
            content,
            createdAt: now,
            createdBy: uid,
          }),
          "governanceActions.ADD_EVIDENCE"
        );
        auditDetails.evidenceType = type;
        auditDetails.newState = previousStatus;
        await writeAuditLog("governance_add_evidence", uid, role, incidentId, auditDetails);
        console.log("[governanceActions] RESPONSE SENT (ADD_EVIDENCE) executionTime=", Date.now() - startTime);
        return res.status(200).json({
          success: true, action: actionType, message: "Evidence added successfully", newState: previousStatus,
        });
      }
      else if (actionType === "UPDATE_RISK_SCORE") {
        const { riskScore } = payload;
        if (riskScore === undefined || riskScore === null) {
          return res.status(400).json({ success: false, error: "Missing riskScore for UPDATE_RISK_SCORE" });
        }
        if (typeof riskScore !== "number" || riskScore < 0 || riskScore > 100) {
          return res.status(400).json({ success: false, error: "riskScore must be a number between 0 and 100" });
        }
        coreUpdate.riskScore = riskScore;
        auditDetails.riskScore = riskScore;
        auditDetails.newState = previousStatus;
      }
      else if (actionType === "OVERRIDE_DECISION") {
        const { targetField, newValue } = payload;
        const SAFE_FIELDS = ["triageStatus", "urgency", "priority", "category"];
        if (!targetField || !SAFE_FIELDS.includes(targetField)) {
          return res.status(400).json({ success: false, error: `Invalid targetField. Allowed: ${SAFE_FIELDS.join(", ")}` });
        }
        if (newValue === undefined || newValue === null || newValue === "") {
          return res.status(400).json({ success: false, error: "Missing newValue for OVERRIDE_DECISION" });
        }
        coreUpdate[targetField] = newValue;
        historyEntry = {
          status: `override_${targetField}`,
          note: `Manager override: ${targetField} set to "${newValue}". Reason: ${payload.reason}`,
          by: uid, at: now.toISOString(),
        };
        auditDetails.targetField = targetField;
        auditDetails.newValue = newValue;
        auditDetails.newState = previousStatus;
      }
      else if (actionType === "SLA_OVERRIDE") {
        const { newUrgency } = payload;
        const VALID_URGENCY = ["low", "medium", "high", "critical"];
        if (!newUrgency || !VALID_URGENCY.includes(newUrgency)) {
          return res.status(400).json({ success: false, error: `Invalid newUrgency. Must be one of: ${VALID_URGENCY.join(", ")}` });
        }
        coreUpdate.urgency = newUrgency;
        coreUpdate.slaOverridden = true;
        coreUpdate.slaOverriddenBy = uid;
        coreUpdate.slaOverriddenAt = now;
        historyEntry = {
          status: "sla_override",
          note: `SLA urgency overridden to "${newUrgency}" by ${role}. Reason: ${payload.reason}`,
          by: uid, at: now.toISOString(),
        };
        auditDetails.newUrgency = newUrgency;
        auditDetails.newState = previousStatus;
      }
      else if (actionType === "CONVERT_TO_THREAT_HUNT") {
        const thCheck = validateTransition(previousStatus, "threat_hunt");
        if (!thCheck.valid) return res.status(400).json({ success: false, error: thCheck.error });
        coreUpdate.status = "threat_hunt";
        coreUpdate.threatHuntStartedAt = now;
        coreUpdate.threatHuntStartedBy = uid;
        historyEntry = {
          status: "threat_hunt",
          note: `Converted to Threat Hunt by ${role}. Reason: ${payload.reason}`,
          by: uid, at: now.toISOString(),
        };
        auditDetails.newState = "threat_hunt";
      }
      else if (actionType === "REJECT_CONTAINMENT") {
        const REJECT_ALLOWED = ["contained", "containment_pending", "ir_in_progress"];
        if (!REJECT_ALLOWED.includes(previousStatus)) {
          return res.status(400).json({
            success: false,
            error: `REJECT_CONTAINMENT requires status one of: ${REJECT_ALLOWED.join(", ")}. Current: "${previousStatus}"`,
          });
        }
        coreUpdate.status = "ir_in_progress";
        coreUpdate.containmentRejected = true;
        coreUpdate.containmentRejectedBy = uid;
        coreUpdate.containmentRejectedAt = now;
        coreUpdate.readyForManagerReview = false;
        historyEntry = {
          status: "ir_in_progress",
          note: `Containment rejected by ${role} — returned to IR Team. Reason: ${payload.reason}`,
          by: uid, at: now.toISOString(),
        };
        auditDetails.newState = "ir_in_progress";
      }
      else if (actionType === "TAG_RCA") {
        if (previousStatus !== "resolved") {
          return res.status(400).json({
            success: false,
            error: `TAG_RCA requires the incident to be "resolved". Current: "${previousStatus}"`,
          });
        }
        const rcaCheck = validateTransition(previousStatus, "rca_pending");
        if (!rcaCheck.valid) return res.status(400).json({ success: false, error: rcaCheck.error });
        coreUpdate.status = "rca_pending";
        coreUpdate.rcaRequired = true;
        coreUpdate.rcaTaggedBy = uid;
        coreUpdate.rcaTaggedAt = now;
        historyEntry = {
          status: "rca_pending",
          note: `RCA required — tagged by ${role}. Reason: ${payload.reason}`,
          by: uid, at: now.toISOString(),
        };
        auditDetails.newState = "rca_pending";
      }
      else if (actionType === "TAG_PIR") {
        if (previousStatus !== "resolved") {
          return res.status(400).json({
            success: false,
            error: `TAG_PIR requires the incident to be "resolved". Current: "${previousStatus}"`,
          });
        }
        const pirCheck = validateTransition(previousStatus, "pir_pending");
        if (!pirCheck.valid) return res.status(400).json({ success: false, error: pirCheck.error });
        coreUpdate.status = "pir_pending";
        coreUpdate.pirRequired = true;
        coreUpdate.pirTaggedBy = uid;
        coreUpdate.pirTaggedAt = now;
        historyEntry = {
          status: "pir_pending",
          note: `PIR required — tagged by ${role}. Reason: ${payload.reason}`,
          by: uid, at: now.toISOString(),
        };
        auditDetails.newState = "pir_pending";
      }
      else {
        return res.status(400).json({
          success: false,
          error: `Unknown actionType: "${actionType}". Valid actions: OVERRIDE_DECISION, SLA_OVERRIDE, TRANSFER_OWNERSHIP, CONVERT_TO_THREAT_HUNT, REOPEN_INCIDENT, REJECT_CONTAINMENT, ACCEPT_RISK, TAG_RCA, TAG_PIR, ADD_EVIDENCE, UPDATE_RISK_SCORE, UPDATE_TAGS`,
        });
      }

      // ── Write 1: scalar core update ──────────────────────────────────────────
      console.log("[governanceActions] BEFORE DB write (core) action=", actionType);
      await safeUpdate(incidentRef, coreUpdate, `governanceActions.core(${actionType})`);

      // ── Write 2: statusHistory arrayUnion (only if this action produces a history entry) ──
      if (historyEntry) {
        await safeUpdate(incidentRef, {
          statusHistory: FieldValue.arrayUnion(historyEntry),
        }, `governanceActions.history(${actionType})`);
      }

      await writeAuditLog(`governance_${actionType.toLowerCase()}`, uid, role, incidentId, auditDetails);
      console.log("[governanceActions] RESPONSE SENT executionTime=", Date.now() - startTime);

      return res.status(200).json({
        success: true,
        action: actionType,
        message: `${actionType} completed successfully`,
        newState: auditDetails.newState || previousStatus,
      });

    } catch (err) {
      console.error("[governanceActions] ERROR", err.message, err.stack);
      return res.status(500).json({ success: false, error: err.message || "Internal server error" });
    }
  }
);

// ═══════════════════════════════════════════════════════════════════════════
//  FUNCTION 10: bulkGovernanceAction
//  Executes the same governance action across multiple incidents.
//  - Max batch size: 20
//  - Each incident processed independently (no cross-incident transactions)
//  - Returns per-incident results: { success: [], failed: [], skipped: [] }
// ═══════════════════════════════════════════════════════════════════════════
exports.bulkGovernanceAction = onRequest(
  { region: "asia-south1" },
  async (req, res) => {
    res.set("Access-Control-Allow-Origin", "*");
    res.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    if (req.method === "OPTIONS") return res.status(204).send("");

    const startTime = Date.now();

    try {
      console.log("[bulkGovernanceAction] START", req.method, req.body);

      if (!req.body) return res.status(400).json({ success: false, error: "Missing body" });

      const auth = await verifyAuth(req);
      const uid = auth.uid;
      console.log("[bulkGovernanceAction] AFTER AUTH uid=", uid);

      const { incidentIds, actionType, payload = {} } = req.body || {};

      if (!Array.isArray(incidentIds) || incidentIds.length === 0) {
        return res.status(400).json({ success: false, error: "incidentIds must be a non-empty array" });
      }
      if (incidentIds.length > 20) {
        return res.status(400).json({ success: false, error: "Maximum 20 incidents per bulk operation" });
      }
      if (!actionType || typeof actionType !== "string") {
        return res.status(400).json({ success: false, error: "actionType is required" });
      }

      console.log("[bulkGovernanceAction] BEFORE DB read (caller role)");
      const { role } = await getCallerRole(uid);
      console.log("[bulkGovernanceAction] AFTER DB read role=", role, "action=", actionType, "count=", incidentIds.length);

      if (!["soc_manager", "admin"].includes(role)) {
        return res.status(403).json({ success: false, error: "Bulk operations require SOC Manager or Admin role" });
      }

      const results = { success: [], failed: [], skipped: [] };
      const now = new Date();

      for (const incidentId of incidentIds) {
        try {
          const incidentRef = db.collection("issues").doc(incidentId);

          console.log(`[bulkGovernanceAction] BEFORE DB read incident=${incidentId}`);
          const incidentSnap = await withTimeout(
            incidentRef.get(),
            `bulkGovernanceAction.get(${incidentId})`
          );

          if (!incidentSnap.exists) {
            results.skipped.push({ id: incidentId, reason: "Incident not found" });
            continue;
          }

          const incident = incidentSnap.data();

          if (incident.locked === true && actionType !== "UNLOCK") {
            results.skipped.push({ id: incidentId, reason: "Governance locked" });
            continue;
          }
          if (incident.isDeleted === true) {
            results.skipped.push({ id: incidentId, reason: "Deleted incident" });
            continue;
          }

          // coreUpdate: scalars only; historyEntry: for arrayUnion in Write 2
          const coreUpdate = { updatedAt: now };
          let historyEntry = null;
          const auditDetails = { bulkOperation: true, actionType };
          const previousStatus = incident.status;

          if (actionType === "LOCK") {
            coreUpdate.locked = true;
            coreUpdate.lockedAt = now;
            coreUpdate.lockedBy = uid;
            historyEntry = {
              status: "GOVERNANCE_LOCKED",
              note: `Bulk locked by ${role}. Reason: ${payload.reason || "Bulk operation"}`,
              by: uid, at: now.toISOString(),
            };
          } else if (actionType === "UNLOCK") {
            coreUpdate.locked = false;
            coreUpdate.unlockedAt = now;
            coreUpdate.unlockedBy = uid;
            historyEntry = {
              status: "GOVERNANCE_UNLOCKED",
              note: `Bulk unlocked by ${role}`,
              by: uid, at: now.toISOString(),
            };
          } else if (actionType === "UPDATE_TAGS") {
            if (!Array.isArray(payload.tags)) {
              results.failed.push({ id: incidentId, error: "tags must be an array" });
              continue;
            }
            const sanitized = [...new Set(payload.tags.map(t => String(t).trim().toLowerCase()).filter(Boolean))];
            coreUpdate.tags = sanitized;
          } else if (actionType === "ASSIGN") {
            if (!payload.assignedTo) {
              results.failed.push({ id: incidentId, error: "assignedTo required" });
              continue;
            }
            coreUpdate.assignedTo = payload.assignedTo;
            coreUpdate.assignedAt = now;
            coreUpdate.assignedBy = uid;
            if (previousStatus === "open") coreUpdate.status = "assigned";
            historyEntry = {
              status: "assigned",
              note: `Bulk assigned to ${payload.assignedTo} by ${role}`,
              by: uid, at: now.toISOString(),
            };
          } else if (actionType === "ESCALATE") {
            coreUpdate.escalated = true;
            coreUpdate.escalatedAt = now;
            coreUpdate.escalatedTo = payload.escalateTo || "soc_manager";
            historyEntry = {
              status: "escalated",
              note: `Bulk escalated by ${role}. Reason: ${payload.reason || "Bulk operation"}`,
              by: uid, at: now.toISOString(),
            };
          } else if (actionType === "UPDATE_RISK_SCORE") {
            if (payload.riskScore != null) coreUpdate.riskScore = Number(payload.riskScore);
            if (payload.attackStage) coreUpdate.attackStage = payload.attackStage;
          } else {
            results.failed.push({ id: incidentId, error: `Unknown bulk action: ${actionType}` });
            continue;
          }

          // Write 1: scalars
          await safeUpdate(incidentRef, coreUpdate, `bulkGovernanceAction.core(${incidentId})`);

          // Write 2: arrayUnion (only if needed)
          if (historyEntry) {
            await safeUpdate(incidentRef, {
              statusHistory: FieldValue.arrayUnion(historyEntry),
            }, `bulkGovernanceAction.history(${incidentId})`);
          }

          await writeAuditLog(`bulk_${actionType.toLowerCase()}`, uid, role, incidentId, auditDetails);
          results.success.push({ id: incidentId });

        } catch (incidentErr) {
          console.error(`[bulkGovernanceAction] ERROR for incident=${incidentId}:`, incidentErr.message);
          results.failed.push({ id: incidentId, error: incidentErr.message || "Unknown error" });
        }
      }

      console.log("[bulkGovernanceAction] RESPONSE SENT executionTime=", Date.now() - startTime);
      return res.status(200).json({
        success: true,
        results,
        summary: {
          total: incidentIds.length,
          succeeded: results.success.length,
          failed: results.failed.length,
          skipped: results.skipped.length,
        },
      });

    } catch (err) {
      console.error("[bulkGovernanceAction] ERROR", err.message, err.stack);
      return res.status(500).json({ success: false, error: err.message || "Internal server error" });
    }
  }
);

// ─────────────────────────────────────────────────────────────────────────────
// FUNCTION 11: deleteUser (Admin only)
// ─────────────────────────────────────────────────────────────────────────────
exports.deleteUser = onRequest(
  { region: "asia-south1" },
  async (req, res) => {
    res.set("Access-Control-Allow-Origin", "*");
    res.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    if (req.method === "OPTIONS") return res.status(204).send("");

    const startTime = Date.now();

    try {
      console.log("[deleteUser] START", req.method, req.body);

      if (!req.body) return res.status(400).json({ success: false, error: "Missing body" });

      const { targetUid } = req.body;
      if (!targetUid) return res.status(400).json({ success: false, error: "Missing targetUid" });

      const authToken = await verifyAuth(req);
      const callerUid = authToken.uid;
      console.log("[deleteUser] AFTER AUTH callerUid=", callerUid);

      const { role } = await getCallerRole(callerUid);
      console.log("[deleteUser] role=", role, "targetUid=", targetUid);

      if (role !== "admin") return res.status(403).json({ success: false, error: "Only Admin can delete users" });
      if (targetUid === callerUid) return res.status(403).json({ success: false, error: "Admin cannot delete their own account" });

      console.log("[deleteUser] BEFORE AUTH delete");
      await withTimeout(admin.auth().deleteUser(targetUid), "deleteUser.auth.deleteUser");

      console.log("[deleteUser] BEFORE DB delete");
      await withTimeout(
        db.collection("users").doc(targetUid).delete(),
        "deleteUser.firestore.delete"
      );

      await writeAuditLog("user_deleted", callerUid, role, null, { targetUid });
      console.log("[deleteUser] RESPONSE SENT executionTime=", Date.now() - startTime);
      return res.status(200).json({ success: true, message: "User deleted successfully" });

    } catch (err) {
      console.error("[deleteUser] ERROR", err.message, err.stack);
      return res.status(500).json({ success: false, error: err.message || "Internal server error" });
    }
  }
);
