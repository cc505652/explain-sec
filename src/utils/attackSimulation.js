/**
 * SOC Platform — Adversarial Attack Simulation Test Suite
 * 
 * PURPOSE: Verify all critical VULN-* vulnerabilities are closed after hardening.
 * Run these in browser DevTools console while logged in as a test student user.
 * Expected result: ALL attacks FAIL with appropriate error messages.
 * 
 * HOW TO USE:
 *   1. Log in as a student user
 *   2. Open browser DevTools → Console
 *   3. Import firebase from the running app (available on window if exposed, or use SDK directly)
 *   4. Paste each test and observe the result
 */

// ─────────────────────────────────────────────────────────────────────────────
// SETUP: Get Firestore references (assumes Firebase SDK is loaded)
// ─────────────────────────────────────────────────────────────────────────────
import { doc, updateDoc, addDoc, collection, setDoc } from "firebase/firestore";
import { doc, getDoc } from "firebase/firestore";
import { auth, db } from "../firebase";
import { normalizeRole } from "./roleNormalization";
import { app } from "../firebase";

// Base URL for Cloud Functions in asia-south1 region
const FUNCTIONS_BASE_URL = "https://asia-south1-explain-sec.cloudfunctions.net";

/**
 * ATTACK 1: VULN-01 — Student self-promotes to admin
 * 
 * BEFORE FIX: updateDoc on own profile with role:"admin" → succeeds
 * AFTER FIX:  Firestore rule blocks write because "role" is in the blocked fields list
 * 
 * Expected: FirebaseError: Missing or insufficient permissions
 */
async function attack_selfPromoteToAdmin() {
  console.log("🔴 ATTACK 1: Self-promote to admin");
  try {
    await updateDoc(doc(db, "users", auth.currentUser.uid), {
      role: "admin"  // ← blocked by new Firestore rules
    });
    console.error("❌ ATTACK SUCCEEDED — SYSTEM IS VULNERABLE");
  } catch (e) {
    console.log("✅ ATTACK BLOCKED:", e.code, e.message);
    // Expected: "FirebaseError: Missing or insufficient permissions"
  }
}

/**
 * ATTACK 2: VULN-05 — Analyst writes escalationApproved directly
 * 
 * BEFORE FIX: updateDoc with escalationApproved:true on assigned incident → succeeds
 * AFTER FIX:  Firestore rule blocks write because "escalationApproved" not in analyst field list
 * 
 * Expected: FirebaseError: Missing or insufficient permissions
 */
async function attack_analystWritesEscalationApproved(incidentId) {
  console.log("🔴 ATTACK 2: Analyst self-approves escalation");
  try {
    await updateDoc(doc(db, "issues", incidentId), {
      escalationApproved: true,
      status: "escalation_approved",
      assignedTo: "ir"
    });
    console.error("❌ ATTACK SUCCEEDED — SYSTEM IS VULNERABLE");
  } catch (e) {
    console.log("✅ ATTACK BLOCKED:", e.code, e.message);
  }
}

/**
 * ATTACK 3: VULN-06 — Direct updateDoc bypasses state machine
 * Attempt to jump from "open" directly to "resolved"
 * 
 * BEFORE FIX: direct updateDoc succeeds, state machine only enforced client-side
 * AFTER FIX:  Firestore rule blocks direct status writes for analysts.
 *             Manager/Admin direct writes still work (they have governance authority)
 *             but analysts cannot jump states without calling the Cloud Function
 *             which enforces the server-side state machine.
 * 
 * Expected: FirebaseError or function returns error
 */
async function attack_stateBypassViaDirectUpdateDoc(incidentId) {
  console.log("🔴 ATTACK 3: Direct status bypass open→resolved");
  try {
    // Analysts can only write: urgency, triageStatus, triageClassification,
    // investigationHistory, analystNotes, updatedAt (per new rules)
    // "status" is NOT in the allow list → blocked
    await updateDoc(doc(db, "issues", incidentId), {
      status: "resolved"  // ← not in analyst allowed fields
    });
    console.error("❌ ATTACK SUCCEEDED — SYSTEM IS VULNERABLE");
  } catch (e) {
    console.log("✅ ATTACK BLOCKED:", e.code, e.message);
  }
}

/**
 * ATTACK 3b: VULN-06 — Try via Cloud Function with invalid transition
 * Even if someone calls updateIncidentStatus correctly, server rejects illegal transition.
 * 
 * Expected: functions/failed-precondition
 */
async function attack_stateBypassViaFunction(incidentId) {
  console.log("🔴 ATTACK 3b: Invalid state machine transition via Cloud Function");
  try {
    const token = await auth.currentUser.getIdToken();
    const res = await fetch(`${FUNCTIONS_BASE_URL}/updateIncidentStatus`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`
      },
      body: JSON.stringify({ incidentId, nextStatus: "resolved", note: "bypass" })
    });
    // "open" → "resolved" is not a valid transition → server rejects
    if (res.ok) {
      console.error("❌ ATTACK SUCCEEDED — SYSTEM IS VULNERABLE");
    } else {
      const err = await res.json();
      console.log("✅ ATTACK BLOCKED:", err.error);
    }
  } catch (e) {
    console.log("✅ ATTACK BLOCKED:", e.message);
  }
}

/**
 * ATTACK 4: VULN-21 — Direct write to audit_logs
 * 
 * BEFORE FIX: allow create: if request.auth != null → any user can forge audit entries
 * AFTER FIX:  allow create: if false → NO client can write; only Admin SDK (Cloud Functions)
 * 
 * Expected: FirebaseError: Missing or insufficient permissions
 */
async function attack_forgeAuditLog() {
  console.log("🔴 ATTACK 4: Forge audit log entry");
  try {
    await addDoc(collection(db, "audit_logs"), {
      action: "admin_deleted_all_users",
      performedBy: "attacker@evil.com",
      timestamp: new Date(),
      details: { targetUid: "all_users" }
    });
    console.error("❌ ATTACK SUCCEEDED — SYSTEM IS VULNERABLE");
  } catch (e) {
    console.log("✅ ATTACK BLOCKED:", e.code, e.message);
    // Expected: "permission-denied"
  }
}

/**
 * ATTACK 5: VULN-11 — Write to locked incident
 * 
 * BEFORE FIX: Lock enforced client-side only; direct updateDoc bypasses it
 * AFTER FIX:  Firestore rule checks resource.data.locked != true for IR/analyst writes
 * 
 * Expected: FirebaseError: Missing or insufficient permissions (if incident is locked)
 */
async function attack_writeToLockedIncident(lockedIncidentId) {
  console.log("🔴 ATTACK 5: Write to governance-locked incident");
  try {
    await updateDoc(doc(db, "issues", lockedIncidentId), {
      triageStatus: "false_positive",  // Even this safe field blocked on locked incident
    });
    console.error("❌ ATTACK SUCCEEDED — SYSTEM IS VULNERABLE");
  } catch (e) {
    console.log("✅ ATTACK BLOCKED:", e.code, e.message);
  }
}

/**
 * ATTACK 6: VULN-02 — AnalystDashboard creating analyst profile for any user
 * 
 * BEFORE FIX: AnalystDashboard's onAuthStateChanged created analyst profile if none existed
 * AFTER FIX:  Profile creation code removed from AnalystDashboard;
 *             app.jsx creates student profile only; roles updated via callUpdateRole (admin only)
 * 
 * Verification: Load AnalystDashboard as a student → profile should NOT be upgraded to analyst
 */
async function verify_noAnalystProfileCreation() {
  console.log("🔍 VERIFICATION 6: AnalystDashboard should not create profiles");
  const { doc: firestoreDoc, getDoc: firestoreGetDoc } = await import("firebase/firestore");
  const snap = await firestoreGetDoc(firestoreDoc(db, "users", auth.currentUser.uid));
  if (snap.exists()) {
    const data = snap.data();
    console.log("User profile:", { role: data.role, team: data.team });
    if (normalizeRole(data.role) === "soc_l1" && normalizeRole(data.team) === "soc_l1") {
      console.error("❌ Profile was auto-upgraded to analyst — VULN-02 NOT FIXED");
    } else {
      console.log("✅ Profile role:", data.role, "— AnalystDashboard did not upgrade role");
    }
  }
}

/**
 * ATTACK 7: Escalation via Cloud Function as wrong role
 * 
 * Student tries to call escalateIncident function
 * Expected: functions/permission-denied
 */
async function attack_studentCallsEscalation(incidentId) {
  console.log("🔴 ATTACK 7: Student calls escalateIncident Cloud Function");
  try {
    const token = await auth.currentUser.getIdToken();
    const res = await fetch(`${FUNCTIONS_BASE_URL}/escalateIncident`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`
      },
      body: JSON.stringify({ incidentId })
    });
    if (res.ok) {
      console.error("❌ ATTACK SUCCEEDED — SYSTEM IS VULNERABLE");
    } else {
      const err = await res.json();
      console.log("✅ ATTACK BLOCKED:", err.error);
    }
  } catch (e) {
    console.log("✅ ATTACK BLOCKED:", e.message);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// RUN ALL ATTACKS (usage example — replace IDs with real incident IDs)
// ─────────────────────────────────────────────────────────────────────────────
export async function runAllAttackSimulations(openIncidentId, lockedIncidentId) {
  console.log("═══════════════════════════════════════");
  console.log("🔴 SOC PLATFORM ADVERSARIAL TEST SUITE");
  console.log("═══════════════════════════════════════");
  console.log("Running as:", auth.currentUser?.email, "role: (check Firestore)");
  console.log("");

  await attack_selfPromoteToAdmin();
  if (openIncidentId) {
    await attack_analystWritesEscalationApproved(openIncidentId);
    await attack_stateBypassViaDirectUpdateDoc(openIncidentId);
    await attack_stateBypassViaFunction(openIncidentId);
    await attack_studentCallsEscalation(openIncidentId);
  }
  if (lockedIncidentId) {
    await attack_writeToLockedIncident(lockedIncidentId);
  }
  await attack_forgeAuditLog();
  await verify_noAnalystProfileCreation();

  console.log("");
  console.log("═══════════════════════════════════════");
  console.log("✅ Attack simulation complete.");
  console.log("All ✅ = system is hardened");
  console.log("Any ❌ = vulnerability still present");
  console.log("═══════════════════════════════════════");
}
