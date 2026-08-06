import {
  collection,
  onSnapshot,
  orderBy,
  query,
  doc,
  getDoc,
  setDoc,
  serverTimestamp,
  Timestamp,
  arrayUnion,
  updateDoc,
  where,
  getDocs,
  limit as limitFn,
  writeBatch,
  deleteDoc
} from "firebase/firestore";
import { auth, db } from "./firebase";
import { useNavigate } from "react-router-dom";
import { onAuthStateChanged } from "firebase/auth";
import { normalizeRole, isVisibleToRole, getVisibleToForStatus } from "./utils/roleNormalization";
import { validateTransition } from "./utils/incidentStateGuard";
import { useEffect, useMemo, useState } from "react";
import {
  callEscalateIncident,
  callPerformContainment,
  callUpdateIncidentStatus,
  callGovernanceAction,
} from "./utils/socFunctions";
import { appendTimelineEvent, appendContainmentEvent, appendEscalationEvent, appendTriageLifecycle, appendThreatConfirmed, appendIRActionSubmitted, appendAssignmentLifecycle, appendLifecycleEvent, TIMELINE_EVENTS } from "./security/timelineEngine";
import { logLifecycleAudit, logContainmentAudit, logGovernanceAudit, AUDIT_ACTIONS } from "./security/auditEngine";
import { useIncidentTimelines } from "./hooks/useIncidentTimelines";
import { buildRenderableTimeline } from "./utils/timelineReader";
import React from "react";
import { computeSLA } from "./utils/slaEngine";

const getCanonicalUserRole = (user) => {
  if (!user) return null;
  const normRole = normalizeRole(user.role);
  const normTeam = normalizeRole(user.team);
  if (normRole === "soc_manager" || normRole === "admin" || normRole === "ir" || normRole === "threat_hunter") {
    return normRole;
  }
  return normTeam || normRole;
};

const eligiblePIRRoles = ["soc_manager", "soc_l2", "ir", "threat_hunter", "admin"];

/* ---------- SLA HELPERS (reused from Analyst Console) ---------- */

const MS_IN_HOUR = 60 * 60 * 1000;
const urgencyRank = { high: 3, medium: 2, low: 1 };
const attentionOrder = { overdue: 0, delayed: 1, "on-time": 2 };

function hoursSince(ts) {
  if (!ts) return 0;
  const d = ts.toDate ? ts.toDate() : new Date(ts);
  return (Date.now() - d.getTime()) / MS_IN_HOUR;
}

function getSlaFlag(issue) {
  const sla = computeSLA(issue);
  if (sla.status === "breached") return "overdue";
  if (sla.status === "at_risk") return "delayed";
  return "on-time";
}

function tsToMillis(ts) {
  if (!ts) return 0;
  if (typeof ts === "number") return ts;
  if (ts.toMillis) return ts.toMillis();
  if (ts.seconds) return ts.seconds * 1000;
  return 0;
}

function formatTimeAgo(ms) {
  if (!ms) return "—";
  const diff = Date.now() - ms;
  const sec = Math.floor(diff / 1000);
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const h = Math.floor(min / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  return `${d}d ago`;
}

function getSlaDisplay(issue) {
  const sla = computeSLA(issue);
  return {
    label: sla.label,
    color: sla.color,
    breached: sla.breached
  };
}

/* ---------- UI HELPERS ---------- */

function pillStyle(bg, fg = "#fff") {
  return {
    background: bg,
    color: fg,
    padding: "4px 10px",
    borderRadius: 999,
    fontSize: 12,
    fontWeight: 800,
    lineHeight: "16px",
    display: "inline-flex",
    alignItems: "center",
    gap: 6
  };
}

function statusPill(status) {
  if (status === "open") return pillStyle("#fb8c00");
  if (status === "assigned") return pillStyle("#1976d2");
  if (status === "in_progress") return pillStyle("#6a1b9a");
  if (status === "resolved") return pillStyle("#2e7d32");
  return pillStyle("#455a64");
}

function urgencyPill(urg) {
  if (urg === "high") return pillStyle("#d32f2f");
  if (urg === "medium") return pillStyle("#f57c00");
  if (urg === "low") return pillStyle("#388e3c");
  return pillStyle("#455a64");
}

const STAFF_OPTIONS = [
  { value: "soc_l1", label: "SOC L1 Analyst" },
  { value: "soc_l2", label: "SOC L2 Analyst" },
  { value: "ir", label: "Incident Response" },
  { value: "threat_hunter", label: "Threat Hunter" },
  { value: "forensics", label: "Digital Forensics" },
  { value: "cloud_security", label: "Cloud Security Team" },
  { value: "network_security", label: "Network Security Team" }
];

// 🔹 ENHANCED USER DISPLAY SYSTEM
function getAnalystDisplayLabel(assignedTo, usersData) {
  // If no assignment, return unassigned
  if (!assignedTo) return "Unassigned";
  if (assignedTo === "system") return "Auto-Routed";

  // Check if we have user data for this UID
  if (usersData && usersData[assignedTo]) {
    const userData = usersData[assignedTo];

    // Build display name based on user data
    let displayName = userData.displayName || userData.email || "Unknown User";

    // Add role/level information
    if (userData.analystLevel) {
      const levelLabels = {
        "L1": "SOC L1 Analyst",
        "L2": "SOC L2 Analyst",
        "IR": "Incident Response",
        "TH": "Threat Hunter"
      };
      displayName += ` (${levelLabels[userData.analystLevel] || userData.analystLevel})`;
    } else if (userData.role) {
      const roleLabels = {
        "admin": "Admin",
        "analyst": "Analyst",
        "student": "Reporter"
      };
      displayName += ` (${roleLabels[userData.role] || userData.role})`;
    }

    return displayName;
  }

  // Fallback to staff options if no user data
  const found = STAFF_OPTIONS.find((x) => x.value === assignedTo);
  if (found) return found.label;

  // Last resort: show the UID if it's a recognizable format
  if (assignedTo.includes("@")) {
    return assignedTo.split("@")[0]; // Show email prefix
  }
  return assignedTo; // Return as-is if nothing else matches
}

// 🔹 GENERATE USER OPTIONS FOR ASSIGNMENT DROPDOWN
function generateUserOptions(usersData, currentUserRole) {
  if (!usersData || Object.keys(usersData).length === 0) {
    return STAFF_OPTIONS; // Fallback to old options if no user data
  }

  const userOptions = [];

  Object.entries(usersData).forEach(([uid, userData]) => {
    // Only show users that can be assigned (not admins unless current user is admin)
    if (normalizeRole(userData.role) === 'admin' && normalizeRole(currentUserRole) !== 'admin') return;

    let displayName = userData.displayName || userData.email || "Unknown User";

    // Add analyst level information
    if (userData.analystLevel) {
      const levelLabels = {
        "L1": "SOC L1 Analyst",
        "L2": "SOC L2 Analyst",
        "IR": "Incident Response",
        "TH": "Threat Hunter"
      };
      displayName += ` (${levelLabels[userData.analystLevel] || userData.analystLevel})`;
    } else if (userData.role) {
      const roleLabels = {
        "admin": "Admin",
        "analyst": "Analyst",
        "student": "Reporter"
      };
      displayName += ` (${roleLabels[userData.role] || userData.role})`;
    }

    userOptions.push({
      value: uid, // Use actual user UID
      label: displayName,
      level: userData.analystLevel || userData.role || 'unknown'
    });
  });

  // Sort by level priority: L2 > L1 > IR > TH > Student > Admin
  const levelPriority = { 'L2': 1, 'L1': 2, 'IR': 3, 'TH': 4, 'analyst': 5, 'student': 6, 'admin': 7 };

  userOptions.sort((a, b) => {
    const priorityA = levelPriority[a.level] || 999;
    const priorityB = levelPriority[b.level] || 999;
    return priorityA - priorityB;
  });

  return userOptions;
}

/* ---------- ERROR BOUNDARY ---------- */
class AnalystDashboardErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error("🚨 AnalystDashboard Error Boundary caught an error:", error, errorInfo);
    this.setState({ error, errorInfo });
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{ padding: 20, textAlign: 'center' }}>
          <h2 style={{ color: 'var(--danger)', marginBottom: 16 }}>🚨 Analyst Dashboard Error</h2>
          <div style={{
            background: 'rgba(239, 68, 68, 0.1)',
            padding: 20,
            borderRadius: 8,
            marginTop: 20
          }}>
            <h3>Something went wrong</h3>
            <p style={{ color: 'var(--text-muted)', marginBottom: 12 }}>
              The Analyst Dashboard encountered an error and could not display properly.
            </p>
            <details style={{ marginTop: 16 }}>
              <summary style={{ cursor: 'pointer', color: 'var(--primary)' }}>🔍 Technical Details</summary>
              <pre style={{
                background: 'rgba(0,0,0,0.8)',
                color: '#fff',
                padding: 12,
                borderRadius: 4,
                fontSize: 12,
                overflow: 'auto',
                textAlign: 'left'
              }}>
                {this.state.error && this.state.error.toString()}
                {this.state.errorInfo && JSON.stringify(this.state.errorInfo, null, 2)}
              </pre>
            </details>
            <button
              onClick={() => window.location.reload()}
              style={{
                background: 'var(--primary)',
                color: '#fff',
                border: 'none',
                padding: '12px 24px',
                borderRadius: 6,
                fontSize: 14,
                fontWeight: 600,
                cursor: 'pointer',
                marginTop: 20
              }}
            >
              🔄 Reload Dashboard
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

/* ---------- MAIN COMPONENT ---------- */

export default function AnalystDashboard() {
  const [issues, setIssues] = useState([]);

  // ── Timeline renderer migration: batch fetch from incident_timeline ──
  const incidentIds = useMemo(() => issues.map(i => i.id).filter(Boolean), [issues]);
  const timelineDependencyKey = useMemo(() => {
    return issues.map(i => `${i.id}:${i.status}:${i.updatedAt?.seconds || 0}`).sort().join(",");
  }, [issues]);
  const { timelines } = useIncidentTimelines(incidentIds, timelineDependencyKey);

  const [currentUser, setCurrentUser] = useState(null);
  const [analystLevel, setAnalystLevel] = useState(null);
  const [analystTeam, setAnalystTeam] = useState(null);
  const [usersData, setUsersData] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [message, setMessage] = useState("");
  const [nowTick, setNowTick] = useState(Date.now());

  // 🔹 1 — Add Note State
  const [noteText, setNoteText] = useState("");

  // 🔹 1 — Add Toast State
  const [toast, setToast] = useState("");

  // ✅ SECURITY HARDENED — performContainment calls Cloud Function (server validates IR role)
  const performContainment = async (issueId, actionType) => {
    try {
      const result = await callPerformContainment(issueId, actionType);
      setToast(result.message || `✅ Containment: ${actionType}`);
    } catch (err) {
      const msg = err?.message || "Containment failed";
      alert(err?.code === "permission-denied" ? "🔒 " + msg : "❌ " + msg);
      console.error("performContainment error:", err);
    }
  };

  // 🔹 3 — Create L1 Permission Boolean (using normalized roles)
  const normalizedRole = normalizeRole(analystTeam);
  const isL1 = normalizedRole === "soc_l1";
  const isL2 = normalizedRole === "soc_l2";
  const navigate = useNavigate();
  const isIR = normalizedRole === "ir";
  const isManager = normalizedRole === "soc_manager";

  // 🔹 STEP 3 — CAPABILITY FLAGS (using normalized roles)
  const canEscalate = isL1 || isL2;
  const canContain = isIR; // Only IR can perform containment actions
  const canRequestContainment = isL2; // L2 can request containment (sends to Manager)
  const canReassign = isL2 || isManager;
  const canThreatHunt = analystLevel === "TH"; // TH is a separate level, not a team

  // 🔹 STEP 2 — Add SOC L1 Actions
  const canStartTriage = isL1;
  const canMarkFalsePositive = isL1;
  const canEscalateToL2 = isL1;

  useEffect(() => {
    const t = setInterval(() => setNowTick(Date.now()), 60 * 1000);
    return () => clearInterval(t);
  }, []);

  // 🔹 FETCH ALL USERS DATA FOR DISPLAY (REAL-TIME)
  useEffect(() => {
    const unsubscribe = onSnapshot(
      collection(db, "users"),
      (snapshot) => {
        const users = {};
        snapshot.forEach(doc => {
          users[doc.id] = {
            uid: doc.id,
            ...doc.data()
          };
        });
        setUsersData(users);
        console.log("REALTIME UPDATE: Users data loaded for display:", Object.keys(users).length, "users");
      },
      (error) => {
        console.error("Firestore listener error (users):", error);
      }
    );

    return () => unsubscribe();
  }, []);

  // 🔹 ALERT SYSTEM - Generate alerts for important events
  const activeAlerts = useMemo(() => {
    const newAlerts = [];
    // Show alerts for assigned incidents AND unassigned incidents that analysts can see
    const active = issues.filter(i => !i.isDeleted && (
      i.assignedTo === auth.currentUser?.uid || // Assigned to current user
      (!i.assignedTo && i.status === "open") // Unassigned open incidents
    ));

    active.forEach(issue => {
      const slaDisplay = getSlaDisplay(issue);

      // SLA Breach Alerts
      if (slaDisplay.breached) {
        newAlerts.push({
          id: `breach-${issue.id}`,
          type: 'critical',
          title: 'SLA Breached',
          message: `"${issue.title}" has breached SLA - ${slaDisplay.label}`,
          issueId: issue.id,
          timestamp: Date.now()
        });
      }

      // SLA Approaching Alerts (within 1 hour)
      else if (slaDisplay.remaining && slaDisplay.remaining < (60 * 60 * 1000)) {
        newAlerts.push({
          id: `approaching-${issue.id}`,
          type: 'warning',
          title: 'SLA Approaching',
          message: `"${issue.title}" - ${slaDisplay.label}`,
          issueId: issue.id,
          timestamp: Date.now()
        });
      }

      // Delayed Assignment Alerts
      if (issue.status === "open" && getSlaFlag(issue) === "delayed") {
        newAlerts.push({
          id: `delayed-open-${issue.id}`,
          type: 'warning',
          title: 'Delayed Assignment',
          message: `"${issue.title}" has been open too long without assignment`,
          issueId: issue.id,
          timestamp: Date.now()
        });
      }

      // Delayed Action Alerts
      if (issue.status === "assigned" && getSlaFlag(issue) === "overdue") {
        newAlerts.push({
          id: `delayed-action-${issue.id}`,
          type: 'warning',
          title: 'Action Required',
          message: `"${issue.title}" assigned but not started - action required`,
          issueId: issue.id,
          timestamp: Date.now()
        });
      }
    });

    // Sort by severity and timestamp
    newAlerts.sort((a, b) => {
      const severityOrder = { critical: 0, warning: 1, info: 2 };
      if (severityOrder[a.type] !== severityOrder[b.type]) {
        return severityOrder[a.type] - severityOrder[b.type];
      }
      return b.timestamp - a.timestamp;
    });

    return newAlerts.slice(0, 10); // Limit to 10 most recent alerts
  }, [issues, nowTick]);

  /* ---------- REALTIME FETCH ---------- */
  useEffect(() => {
    const unsubAuth = auth.onAuthStateChanged(async (user) => {
      if (!user) return;

      // SECURITY FIX (VULN-02): Profile creation removed from AnalystDashboard.
      // App.jsx is the single authoritative place for first-time profile creation.
      // AnalystDashboard only READS the profile — never writes role/team fields.
      const userRef = doc(db, "users", user.uid);
      const userSnap = await getDoc(userRef);

      if (userSnap.exists()) {
        const data = userSnap.data();
        setAnalystLevel(data.analystLevel || "L1");
        setAnalystTeam(data.team || "soc_l1");
        console.log("📋 Loaded existing user profile:", data.analystLevel, data.team);
      } else {
        // Profile should have been created by App.jsx. Log and wait.
        console.warn("⚠️ User profile not found in Firestore. App.jsx should have created it.");
        setAnalystLevel("L1");
        setAnalystTeam("soc_l1");
      }

      // 🔹 STEP 2 — Set up incident listener separately
      // This will be re-run when analystTeam changes
      return () => {
        // Cleanup auth listener when component unmounts
        if (unsubAuth) {
          unsubAuth();
        }
      };
    });
  }, []);

  // ✅ FIXED — IR Team query (Bug #2: compound where caused missing index errors; simplified)
  useEffect(() => {
    if (!analystTeam) {
      console.log("⏳ Waiting for analyst team to load...");
      return;
    }

    // BUG FIX #2: IR query was using compound where (assignedTo + escalationApproved)
    // which requires a Firestore composite index that won't exist by default.
    // Simplify to single where on escalatedTo only; filter escalationApproved in JS.
    // Use normalized role for query selection
    const normalizedRole = normalizeRole(analystTeam);
    const q = query(
      collection(db, "issues"),
      where("isDeleted", "!=", true),
      orderBy("isDeleted", "asc"),
      orderBy("createdAt", "desc")
    );

    const unsubSnap = onSnapshot(q, (snap) => {
      const data = snap.docs.map((d) => ({ id: d.id, ...d.data() }));

      // Normalize role for query
      const normalizedRole = normalizeRole(analystTeam);
      console.log(`🔧 ROLE NORMALIZATION - Raw role: "${analystTeam}" → Normalized: "${normalizedRole}"`);

      // Use unified visibility function that checks visibleTo, assignedTo, and escalatedTo
      let filtered = data.filter(i => isVisibleToRole(i, normalizedRole));

      if (normalizedRole === "soc_l2") {
        filtered = filtered.filter(i =>
          (i.pirOwner === auth.currentUser?.uid) ||
          (i.pirContributors && i.pirContributors.includes(auth.currentUser?.uid)) ||
          (i.rcaOwner === auth.currentUser?.uid) ||
          (i.rcaContributors && i.rcaContributors.includes(auth.currentUser?.uid)) ||
          (i.status !== "false_positive" &&
            i.status !== "resolved" &&
            i.status !== "closed" &&
            i.status !== "threat_hunt" &&
            !i.isDeleted)
        );
      }

      console.log(`ROLE: ${normalizedRole}`);
      console.log(`VISIBLE INCIDENTS:`, filtered);
      console.log(` Loaded ${filtered.length} incidents for team: ${normalizedRole}`);

      // Debug logs for visibility breakdown
      if (normalizedRole === "ir") {
        console.log(`🔴 IR DEBUG - visibleTo includes "ir":`, data.filter(i => i.visibleTo?.includes("ir")).length);
        console.log(`🔴 IR DEBUG - escalatedTo === "ir":`, data.filter(i => i.escalatedTo === "ir").length);
        console.log(`🔴 IR DEBUG - assignedTo === "ir":`, data.filter(i => i.assignedTo === "ir").length);
        console.log(`🔴 IR DEBUG - isVisibleToRole total:`, filtered.length);
      }
      if (normalizedRole === "soc_l2") {
        console.log(`🟠 L2 DEBUG - visibleTo includes "soc_l2":`, data.filter(i => i.visibleTo?.includes("soc_l2")).length);
        console.log(`🟠 L2 DEBUG - escalatedTo === "soc_l2":`, data.filter(i => i.escalatedTo === "soc_l2").length);
        console.log(`🟠 L2 DEBUG - assignedTo === "soc_l2":`, data.filter(i => i.assignedTo === "soc_l2").length);
        console.log(`🟠 L2 DEBUG - escalatedTo === "ir":`, data.filter(i => i.escalatedTo === "ir").length);
        console.log(`🟠 L2 DEBUG - visibleTo includes "soc_manager":`, data.filter(i => i.visibleTo?.includes("soc_manager")).length);
        console.log(`🟠 L2 DEBUG - isVisibleToRole total:`, filtered.length);
      }
      setIssues(filtered);
    }, (error) => {
      console.error(" Error fetching incidents:", error);
      // Fallback: load all non-deleted without filters
      const fallbackQ = query(
        collection(db, "issues"),
        orderBy("createdAt", "desc")
      );
      const unsubFallback = onSnapshot(fallbackQ, (fallbackSnap) => {
        const fallbackData = fallbackSnap.docs
          .map((d) => ({ id: d.id, ...d.data() }))
          .filter(i => !i.isDeleted);

        // Normalize role for fallback query
        const normalizedRole = normalizeRole(analystTeam);
        console.log(`🔧 FALLBACK ROLE NORMALIZATION - Raw role: "${analystTeam}" → Normalized: "${normalizedRole}"`);

        // Use unified visibility function for fallback query
        let filtered = fallbackData.filter(i => isVisibleToRole(i, normalizedRole));
        if (normalizedRole === "soc_l2") {
          filtered = filtered.filter(i =>
            (i.pirOwner === auth.currentUser?.uid) ||
            (i.pirContributors && i.pirContributors.includes(auth.currentUser?.uid)) ||
            (i.rcaOwner === auth.currentUser?.uid) ||
            (i.rcaContributors && i.rcaContributors.includes(auth.currentUser?.uid)) ||
            (i.status !== "false_positive" &&
              i.status !== "resolved" &&
              i.status !== "closed" &&
              i.status !== "threat_hunt" &&
              !i.isDeleted)
          );
        }
        setIssues(filtered);
        console.log("🔄 Using fallback query (no compound index required)");
      });
      return () => unsubFallback();
    });

    return () => unsubSnap();
  }, [analystTeam]);

  // ✅ SECURITY HARDENED — escalateIncident now calls Cloud Function (server-side state + role validation)
  const escalateIncident = async (issueId) => {
    try {
      const result = await callEscalateIncident(issueId);

      // ── Timeline: escalation requested (fire-and-forget) ──
      appendEscalationEvent(issueId, TIMELINE_EVENTS.ESCALATION_REQUESTED, normalizedRole || "unknown");

      setToast(result.message || "✅ Escalated successfully");
    } catch (err) {
      const msg = err?.message || "Escalation failed";
      if (err?.code === "permission-denied") {
        alert("🔒 " + msg);
      } else if (err?.code === "failed-precondition") {
        alert("⚠️ " + msg);
      } else {
        setToast("❌ " + msg);
      }
      console.error("escalateIncident error:", err);
    }
  };

  // 🔹 STEP 4 — AUTO HIDE MESSAGE AFTER 3 SECONDS
  useEffect(() => {
    if (message) {
      const timer = setTimeout(() => setMessage(""), 3000);
      return () => clearTimeout(timer);
    }
  }, [message]);

  // 🔹 5 — Auto Hide Toast
  useEffect(() => {
    if (toast) {
      setTimeout(() => setToast(""), 3000);
    }
  }, [toast]);

  // 🔹 2 — Create addNote Function
  const addNote = async (issueId) => {
    // Check if incident is locked
    const issueRef = doc(db, "issues", issueId);
    const issueSnap = await getDoc(issueRef);
    const issue = issueSnap.data();

    // STEP 4 — Backend guard for resolved incidents
    if (issue.status === "resolved") {
      alert("Incident already resolved. Reopen to continue investigation.");
      return;
    }

    if (issue.locked === true) {
      alert("🔒 Governance Lock Active. Action restricted.");
      return;
    }
    try {
      await updateDoc(doc(db, "issues", issueId), {
        analystNotes: arrayUnion({
          note: noteText,
          by: auth.currentUser?.uid,
          at: Timestamp.now()
        }),
        investigationHistory: arrayUnion({
          action: "note_added",
          by: auth.currentUser?.uid,
          at: Timestamp.now()
        }),
        updatedAt: serverTimestamp()
      });

      // ── Timeline: note added (fire-and-forget) ──
      appendTimelineEvent({
        incidentId: issueId,
        eventType: TIMELINE_EVENTS.NOTE_ADDED,
        actorId: auth.currentUser?.uid,
        actorRole: normalizedRole || "unknown",
        metadata: { noteLength: noteText?.length || 0 },
      });

      setNoteText("");
    } catch (err) {
      console.error("Note failed", err);
    }
  };

  // PHASE 1 FIX: adjustSeverity — urgency is in Tier 3b allowlist (safe direct write)
  // but statusHistory/investigationHistory removed (only Cloud Functions write those)
  const adjustSeverity = async (issueId, newUrgency) => {
    const issueRef = doc(db, "issues", issueId);
    const issueSnap = await getDoc(issueRef);
    const issue = issueSnap.data();

    if (issue.locked === true) {
      alert("🔒 Governance Lock Active. Action restricted.");
      return;
    }
    try {
      await updateDoc(doc(db, "issues", issueId), {
        urgency: newUrgency,
        updatedAt: serverTimestamp()
      });

      // ── Timeline: severity changed (fire-and-forget) ──
      appendTimelineEvent({
        incidentId: issueId,
        eventType: TIMELINE_EVENTS.SEVERITY_CHANGED,
        actorId: auth.currentUser?.uid,
        actorRole: normalizedRole || "unknown",
        previousState: issue.urgency || null,
        newState: newUrgency,
      });

      logLifecycleAudit(issueId, AUDIT_ACTIONS.SEVERITY_CHANGED, normalizedRole || "unknown", {
        previousState: issue.urgency || null,
        newState: newUrgency,
      });

      setToast(`✅ Urgency updated to ${newUrgency}`);
    } catch (err) {
      console.error("Severity adjustment failed", err);
      alert("Severity adjustment failed: " + (err?.message || "Unknown error"));
    }
  };

  // PHASE 1 FIX: updateTriageStatus — triageStatus is in Tier 3b allowlist (safe direct write)
  // but when status sync is needed (confirmed_threat/false_positive), route through CF
  const updateTriageStatus = async (issueId, newStatus) => {
    const issueRef = doc(db, "issues", issueId);
    const issueSnap = await getDoc(issueRef);
    const issue = issueSnap.data();

    if (issue.locked === true) {
      alert("🔒 Governance Lock Active. Action restricted.");
      return;
    }

    // For status-changing triage decisions, route through Cloud Function
    if (newStatus === "confirmed_threat" || newStatus === "false_positive") {
      try {
        const note = `Triage marked as ${newStatus}`;
        await callUpdateIncidentStatus(issueId, newStatus, note);

        // ── Timeline: triage decision (fire-and-forget) ──
        appendTriageLifecycle(issueId, normalizedRole || "unknown", {
          newStatus,
        });

        // ── Timeline: threat confirmed (fire-and-forget) ──
        if (newStatus === "confirmed_threat") {
          appendThreatConfirmed(issueId, normalizedRole || "unknown", {
            previousStatus: issue.triageStatus || null,
          });
          logLifecycleAudit(issueId, AUDIT_ACTIONS.THREAT_CONFIRMED, normalizedRole || "unknown", {
            previousState: issue.status || null,
            newState: "confirmed_threat",
          });
        }

        setToast(`✅ Triage: ${newStatus}`);
      } catch (err) {
        console.error("Triage status update failed", err);
        alert("Triage update failed: " + (err?.message || "Unknown error"));
      }
      return;
    }

    // For non-status-changing triage updates (e.g. in_review), safe direct write
    try {
      await updateDoc(doc(db, "issues", issueId), {
        triageStatus: newStatus,
        updatedAt: serverTimestamp()
      });

      // ── Timeline: triage updated (fire-and-forget) ──
      appendTriageLifecycle(issueId, normalizedRole || "unknown", {
        previousStatus: issue.triageStatus || null,
        newStatus,
      });

      setToast(`✅ Triage updated to ${newStatus}`);
    } catch (err) {
      console.error("Triage update failed", err);
    }
  };

  // PHASE 1 FIX: requestContainment — escalate L2→SOC Manager for approval
  const requestContainment = async (issueId) => {
    const issueRef = doc(db, "issues", issueId);
    const issueSnap = await getDoc(issueRef);
    const issue = issueSnap.data();

    if (issue.locked === true) {
      alert("🔒 Governance Lock Active. Action restricted.");
      return;
    }

    try {
      await updateDoc(issueRef, {
        status: "containment_pending_approval",
        escalatedTo: "soc_manager",
        assignedTo: null,
        visibleTo: getVisibleToForStatus("containment_pending_approval"),
        requestedBy: auth.currentUser?.uid,
        requestedAt: serverTimestamp(),
        containmentRequested: true,
        containmentRequestedAt: serverTimestamp(),
        approvalStatus: "pending",
        updatedAt: serverTimestamp()
      });

      // ── Timeline: containment requested (fire-and-forget) ──
      appendContainmentEvent(issueId, TIMELINE_EVENTS.CONTAINMENT_REQUESTED, normalizedRole || "soc_l2", {
        previousStatus: issue.status,
        newStatus: "containment_pending_approval",
      });

      logContainmentAudit(issueId, AUDIT_ACTIONS.CONTAINMENT_REQUESTED, normalizedRole || "soc_l2", {
        previousState: issue.status || null,
        newState: "containment_pending_approval",
      });

      setToast("🛡️ Containment request submitted to SOC Manager for approval");
    } catch (err) {
      const msg = err?.message || "Containment request failed";
      alert("❌ " + msg);
      console.error("requestContainment error:", err);
    }
  };

  // 🔹 NEW: withdrawRequest — withdraw containment request and return to L2 investigation
  const withdrawRequest = async (issueId) => {
    const issueRef = doc(db, "issues", issueId);
    const issueSnap = await getDoc(issueRef);
    const issue = issueSnap.data();

    if (issue.locked === true) {
      alert("🔒 Governance Lock Active. Action restricted.");
      return;
    }

    try {
      await updateDoc(issueRef, {
        status: "investigation_l2",
        escalatedTo: "soc_l2",
        visibleTo: ["soc_l2", "soc_manager"], // Keep soc_manager visibility for audit trail
        containmentRequested: false,
        approvalStatus: "withdrawn",
        statusHistory: arrayUnion({
          status: "in_progress",
          note: "Containment request withdrawn by analyst",
          at: Timestamp.now(),
          by: auth.currentUser?.email || "unknown"
        }),
        updatedAt: serverTimestamp()
      });
      appendTimelineEvent({
        incidentId: issueId,
        eventType: TIMELINE_EVENTS.STATUS_CHANGED,
        actorId: auth.currentUser?.uid || "unknown",
        actorRole: normalizedRole || "unknown",
        previousState: "containment_pending_approval",
        newState: "investigation_l2",
        metadata: { reason: "Containment request withdrawn by analyst" }
      });
      console.log(`🟠 L2 WITHDRAW REQUEST:`, { issueId, status: "investigation_l2", visibleTo: ["soc_l2", "soc_manager"] });
      setToast("↩️ Request withdrawn — returned to L2 investigation");
    } catch (err) {
      const msg = err?.message || "Withdraw failed";
      alert("❌ " + msg);
      console.error("withdrawRequest error:", err);
    }
  };

  // 🔹 NEW: submitContainmentAction — IR submits containment action for manager review
  const submitContainmentAction = async (issueId, action, details) => {
    const issueRef = doc(db, "issues", issueId);
    const issueSnap = await getDoc(issueRef);
    const issue = issueSnap.data();

    // Role-based control - only IR can submit
    if (normalizeRole(analystTeam) !== "ir") {
      alert("❌ Unauthorized: Only IR team can submit containment actions");
      return;
    }

    if (issue.locked === true) {
      alert("🔒 Governance Lock Active. Action restricted.");
      return;
    }

    try {
      await updateDoc(issueRef, {
        status: "containment_action_submitted",
        irAction: {
          type: action,
          details: details,
          performedBy: auth.currentUser?.uid,
          timestamp: serverTimestamp()
        },
        managerDecision: null,
        visibleTo: getVisibleToForStatus("containment_action_submitted"),
        updatedAt: serverTimestamp()
      });
      console.log(`🔴 IR ACTION SUBMITTED:`, { type: action, details, performedBy: auth.currentUser?.uid, visibleTo: getVisibleToForStatus("containment_action_submitted") });

      // ── Timeline: IR action submitted (fire-and-forget) ──
      appendIRActionSubmitted(issueId, normalizedRole || "ir", {
        actionType: action,
        actionDetails: details,
      });

      setToast(`✅ Containment action submitted for manager review`);
    } catch (err) {
      const msg = err?.message || "Submission failed";
      alert("❌ " + msg);
      console.error("submitContainmentAction error:", err);
    }
  };

  // 🔹 NEW: updateContainmentAction — IR updates containment action without submitting for review
  const updateContainmentAction = async (issueId, action, details) => {
    const issueRef = doc(db, "issues", issueId);
    const issueSnap = await getDoc(issueRef);
    const issue = issueSnap.data();

    // Role-based control - only IR can update actions
    if (normalizeRole(analystTeam) !== "ir") {
      alert("❌ Unauthorized: Only IR team can update containment actions");
      return;
    }

    if (issue.locked === true) {
      alert("🔒 Governance Lock Active. Action restricted.");
      return;
    }

    try {
      await updateDoc(issueRef, {
        irAction: {
          type: action,
          details: details,
          performedBy: auth.currentUser?.uid,
          timestamp: serverTimestamp()
        },
        updatedAt: serverTimestamp()
      });
      console.log(`🔴 IR ACTION UPDATED:`, { type: action, details, performedBy: auth.currentUser?.uid });
      setToast(`✅ Containment action updated`);
    } catch (err) {
      const msg = err?.message || "Update failed";
      alert("❌ " + msg);
      console.error("updateContainmentAction error:", err);
    }
  };

  // 🔹 1 — Create getSlaWarning Function
  const getSlaWarning = (issue) => {
    const sla = computeSLA(issue);
    return sla.atRisk;
  };

  // 1. Analyst Workload Panel
  // BUG FIX #16: also match team string assignments (ir, soc_l2, etc.)
  const analystWorkload = useMemo(() => {
    void nowTick;
    const workload = {};
    // Include incidents assigned to current user's UID OR to their team string
    const teamStrings = {
      "ir": "ir",
      "soc_l2": "soc_l2",
      "soc_l1": "soc_l1",
      "threat_hunter": "threat_hunter"
    };
    const userTeamString = teamStrings[analystTeam] || null;

    const activeIssues = issues.filter(i => !i.isDeleted && i.status !== "resolved" && (
      i.assignedTo === auth.currentUser?.uid ||
      (userTeamString && i.assignedTo === userTeamString)
    ));

    activeIssues.forEach(issue => {
      const analyst = issue.assignedTo || "unassigned";
      if (!workload[analyst]) {
        workload[analyst] = { total: 0, active: 0, slaBreached: 0, escalated: 0, resolved: 0 };
      }
      workload[analyst].total++;
      if (issue.status !== "resolved") workload[analyst].active++;
      if (getSlaDisplay(issue).breached) workload[analyst].slaBreached++;
      if (issue.escalated) workload[analyst].escalated++;
      if (issue.status === "resolved") workload[analyst].resolved++;
    });

    return workload;
  }, [issues, nowTick, analystTeam]);

  // 2. SLA Risk Monitor
  const slaRiskData = useMemo(() => {
    void nowTick;
    const active = issues.filter(i => !i.isDeleted && i.assignedTo === auth.currentUser?.uid);
    const approaching = [];
    const breached = [];
    const delayedOpen = [];
    const delayedAssigned = [];

    active.forEach(issue => {
      const slaDisplay = getSlaDisplay(issue);
      if (slaDisplay.breached) {
        breached.push(issue);
      } else {
        approaching.push(issue);
      }

      if (issue.status === "open" && getSlaFlag(issue) === "delayed") {
        delayedOpen.push(issue);
      }
      if (issue.status === "assigned" && getSlaFlag(issue) === "overdue") {
        delayedAssigned.push(issue);
      }
    });

    return { approaching, breached, delayedOpen, delayedAssigned };
  }, [issues, nowTick]);

  // 3. Escalation Tracker
  const escalatedIncidents = useMemo(() => {
    return issues.filter(i => !i.isDeleted && i.escalated && i.assignedTo === auth.currentUser?.uid);
  }, [issues]);

  // 4. Incident Aging Monitor
  const incidentAging = useMemo(() => {
    void nowTick;
    const active = issues.filter(i => !i.isDeleted && i.status !== "resolved" && i.assignedTo === auth.currentUser?.uid);
    const agingData = {
      lessThan1h: 0,
      oneTo6h: 0,
      sixTo24h: 0,
      moreThan24h: 0
    };

    active.forEach(issue => {
      const age = hoursSince(issue.createdAt);
      if (age < 1) agingData.lessThan1h++;
      else if (age < 6) agingData.oneTo6h++;
      else if (age < 24) agingData.sixTo24h++;
      else agingData.moreThan24h++;
    });

    return agingData;
  }, [issues, nowTick]);

  // 5. Category-wise Threat Count
  const categoryThreatCount = useMemo(() => {
    const threats = {};
    issues.filter(i => !i.isDeleted && i.assignedTo === auth.currentUser?.uid).forEach(issue => {
      threats[issue.category] = (threats[issue.category] || 0) + 1;
    });
    return threats;
  }, [issues]);

  // 6. Top 3 Hotspot Locations
  const topHotspots = useMemo(() => {
    const locations = {};
    issues.filter(i => !i.isDeleted && i.assignedTo === auth.currentUser?.uid).forEach(issue => {
      locations[issue.location] = (locations[issue.location] || 0) + 1;
    });
    return Object.entries(locations)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 3)
      .map(([loc, count]) => ({ location: loc, count }));
  }, [issues]);

  // 7. Urgency Distribution
  const urgencyDistribution = useMemo(() => {
    const distribution = { high: 0, medium: 0, low: 0 };
    issues.filter(i => !i.isDeleted && i.assignedTo === auth.currentUser?.uid).forEach(issue => {
      if (distribution[issue.urgency] !== undefined) {
        distribution[issue.urgency]++;
      }
    });
    return distribution;
  }, [issues]);

  // 8. Weekly Ops Summary
  const weeklySummary = useMemo(() => {
    const last7Days = issues.filter(i => !i.isDeleted &&
      tsToMillis(i.createdAt) > Date.now() - 7 * 24 * 60 * 60 * 1000 &&
      i.assignedTo === auth.currentUser?.uid
    );

    const total = last7Days.length;
    const resolved = last7Days.filter(i => i.status === "resolved").length;
    const slaBreached = last7Days.filter(i => getSlaDisplay(i).breached).length;

    return {
      total,
      resolved,
      slaBreached,
      resolutionRate: total > 0 ? Math.round((resolved / total) * 100) : 0
    };
  }, [issues]);

  // 9. Overall Stats
  const overallStats = useMemo(() => {
    void nowTick;
    // Show stats for assigned incidents AND unassigned open incidents
    const active = issues.filter(i => !i.isDeleted && (
      i.assignedTo === auth.currentUser?.uid || // Assigned to current user
      (!i.assignedTo && i.status === "open") // Unassigned open incidents
    ));

    const open = active.filter(i => i.status === "open").length;
    const assigned = active.filter(i => i.status === "assigned").length;
    const inProgress = active.filter(i => i.status === "in_progress").length;
    const resolved = active.filter(i => i.status === "resolved").length;
    const breached = active.filter(i => getSlaDisplay(i).breached).length;
    const escalated = active.filter(i => i.escalated).length;

    return { open, assigned, inProgress, resolved, breached, escalated };
  }, [issues, nowTick]);

  // ✅ SECURITY HARDENED — updateStatus calls Cloud Function (server-side state machine)
  const updateStatus = async (issue, nextStatus) => {
    try {
      const note = nextStatus === "in_progress" ? "Investigation started" :
        nextStatus === "resolved" ? "Incident resolved" :
          `Status updated to ${nextStatus}`;
      const result = await callUpdateIncidentStatus(issue.id, nextStatus, note);
      setToast(result.message || `✅ Status → ${nextStatus}`);
    } catch (err) {
      const msg = err?.message || "Status update failed";
      if (err?.code === "failed-precondition") {
        alert("⚠️ Invalid transition: " + msg);
      } else if (err?.code === "permission-denied") {
        alert("🔒 " + msg);
      } else {
        alert("❌ " + msg);
      }
      console.error("updateStatus error:", err);
    }
  };

  // ✅ SECURITY HARDENED — startTriage calls Cloud Function
  const startTriage = async (issueId) => {
    try {
      const result = await callUpdateIncidentStatus(issueId, "in_progress", "Triage started by SOC L1");
      setToast(result.message || "✅ Triage started");
    } catch (err) {
      alert("Error starting triage: " + (err?.message || "Unknown error"));
      console.error("startTriage error:", err);
    }
  };

  // Reassignment handler
  const reassignIssue = async (issue, newAnalyst) => {
    // Check if incident is locked
    if (issue.locked === true) {
      alert("🔒 Governance Lock Active. Action restricted.");
      return;
    }
    if (!canReassign) {
      alert("You don't have permission to reassign incidents.");
      return;
    }

    await updateDoc(doc(db, "issues", issue.id), {
      assignedTo: newAnalyst,
      status: "assigned",
      statusHistory: [
        ...(issue.statusHistory || []),
        { status: "assigned", at: Timestamp.now(), note: `Reassigned by ${auth.currentUser?.email}` }
      ],
      updatedAt: serverTimestamp()
    });

    appendAssignmentLifecycle(issue.id, normalizedRole || "unknown", {
      from: issue.assignedTo || null,
      to: newAnalyst,
      reason: `Reassigned by ${auth.currentUser?.email}`,
      isReassign: true
    });
  };

  return (
    <AnalystDashboardErrorBoundary>
      <div style={{ padding: 16 }}>

        {/* 🔹 4 — Show Toast Message */}
        {toast && (
          <div
            style={{
              position: "fixed",
              top: 20,
              right: 20,
              background: "#2e7d32",
              color: "#fff",
              padding: 10,
              borderRadius: 8,
              zIndex: 1000,
              boxShadow: "0 4px 12px rgba(0,0,0,0.15)"
            }}
          >
            {toast}
          </div>
        )}

        {/* 🔹 STEP 7 — DISPLAY ANALYST LEVEL BADGE */}
        <div style={{
          background: "rgba(6, 182, 212, 0.1)",
          borderRadius: 12,
          padding: 12,
          marginBottom: 16,
          border: "1px solid rgba(6, 182, 212, 0.3)"
        }}>
          <div style={{ fontSize: 14, fontWeight: 600, color: "var(--text-main)" }}>
            🎯 Logged in as: SOC Analyst {analystLevel || 'Loading...'} | Team: {analystTeam || 'Loading...'}
          </div>
        </div>

        {/* 🔹 ALERTS SYSTEM */}
        {activeAlerts.length > 0 && (
          <div className="glass-panel" style={{ padding: 16, marginBottom: 16 }}>
            <h3 style={{ margin: "0 0 12px 0", color: "var(--text-main)" }}>🚨 Active Alerts</h3>
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {activeAlerts.map(alert => (
                <div key={alert.id} style={{
                  padding: 12,
                  borderRadius: 8,
                  border: alert.type === 'critical'
                    ? "1px solid var(--danger)"
                    : alert.type === 'warning'
                      ? "1px solid var(--warning)"
                      : "1px solid var(--primary)",
                  background: alert.type === 'critical'
                    ? "rgba(239, 68, 68, 0.1)"
                    : alert.type === 'warning'
                      ? "rgba(245, 158, 11, 0.1)"
                      : "rgba(25, 118, 210, 0.1)"
                }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <span style={{
                      fontSize: 16,
                      color: alert.type === 'critical'
                        ? "var(--danger)"
                        : alert.type === 'warning'
                          ? "var(--warning)"
                          : "var(--primary)"
                    }}>
                      {alert.type === 'critical' ? "🚨" : alert.type === 'warning' ? "⚠️" : "ℹ️"}
                    </span>
                    <div style={{ flex: 1 }}>
                      <div style={{ fontWeight: 600, fontSize: 14, color: "var(--text-main)" }}>
                        {alert.title}
                      </div>
                      <div style={{ fontSize: 12, color: "var(--text-muted)" }}>
                        {alert.message}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
          <h2 style={{ margin: 0 }}>
            {normalizedRole === "soc_l1" ? "SOC L1 Alert Triage Console" : "SOC Analyst Console"}
          </h2>
          {isL2 && (
            <button
              onClick={() => navigate("/command-console")}
              style={{
                background: "linear-gradient(135deg, #8b5cf6, #06b6d4)",
                color: "#fff",
                border: "none",
                padding: "10px 20px",
                borderRadius: 8,
                cursor: "pointer",
                fontSize: 13,
                fontWeight: 700,
              }}
            >
              🔬 Launch Investigation Console
            </button>
          )}
        </div>

        {/* OVERVIEW STATS */}
        <div className="glass-panel" style={{ padding: 20, marginBottom: 16 }}>
          <h3>🔍 Operations Overview</h3>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))", gap: 12, marginTop: 12 }}>
            <div style={{ textAlign: "center", padding: 16, background: "rgba(6, 182, 212, 0.1)", borderRadius: 12, border: "1px solid rgba(6, 182, 212, 0.3)" }}>
              <div style={{ fontSize: 24, fontWeight: 900, color: "var(--text-main)" }}>{overallStats.open}</div>
              <div style={{ color: "var(--text-muted)" }}>Open</div>
            </div>
            <div style={{ textAlign: "center", padding: 16, background: "rgba(139, 92, 246, 0.1)", borderRadius: 12, border: "1px solid rgba(139, 92, 246, 0.3)" }}>
              <div style={{ fontSize: 24, fontWeight: 900, color: "var(--text-main)" }}>{overallStats.assigned}</div>
              <div style={{ color: "var(--text-muted)" }}>Assigned</div>
            </div>
            <div style={{ textAlign: "center", padding: 16, background: "rgba(168, 85, 247, 0.1)", borderRadius: 12, border: "1px solid rgba(168, 85, 247, 0.3)" }}>
              <div style={{ fontSize: 24, fontWeight: 900, color: "var(--text-main)" }}>{overallStats.inProgress}</div>
              <div style={{ color: "var(--text-muted)" }}>In Progress</div>
            </div>
            <div style={{ textAlign: "center", padding: 16, background: "rgba(16, 185, 129, 0.1)", borderRadius: 12, border: "1px solid rgba(16, 185, 129, 0.3)" }}>
              <div style={{ fontSize: 24, fontWeight: 900, color: "var(--success)" }}>{overallStats.resolved}</div>
              <div style={{ color: "var(--text-muted)" }}>Resolved</div>
            </div>
            <div style={{ textAlign: "center", padding: 16, background: "rgba(239, 68, 68, 0.1)", borderRadius: 12, border: "1px solid rgba(239, 68, 68, 0.3)" }}>
              <div style={{ fontSize: 24, fontWeight: 900, color: "var(--danger)" }}>{overallStats.breached}</div>
              <div style={{ color: "var(--text-muted)" }}>SLA Breached</div>
            </div>
            <div style={{ textAlign: "center", padding: 16, background: "rgba(245, 158, 11, 0.1)", borderRadius: 12, border: "1px solid rgba(245, 158, 11, 0.3)" }}>
              <div style={{ fontSize: 24, fontWeight: 900, color: "var(--warning)" }}>{overallStats.escalated}</div>
              <div style={{ color: "var(--text-muted)" }}>Escalated</div>
            </div>
          </div>
        </div>

        {/* WEEKLY SUMMARY */}
        <div className="glass-panel" style={{ padding: 20, marginBottom: 16 }}>
          <h3>📈 Weekly Ops Summary</h3>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))", gap: 12, marginTop: 12 }}>
            <div style={{ textAlign: "center", padding: 16, background: "rgba(6, 182, 212, 0.1)", borderRadius: 12, border: "1px solid rgba(6, 182, 212, 0.3)" }}>
              <div style={{ fontSize: 20, fontWeight: 900, color: "var(--text-main)" }}>{weeklySummary.total}</div>
              <div style={{ color: "var(--text-muted)" }}>Total Incidents</div>
            </div>
            <div style={{ textAlign: "center", padding: 16, background: "rgba(16, 185, 129, 0.1)", borderRadius: 12, border: "1px solid rgba(16, 185, 129, 0.3)" }}>
              <div style={{ fontSize: 20, fontWeight: 900, color: "var(--success)" }}>{weeklySummary.resolved}</div>
              <div style={{ color: "var(--text-muted)" }}>Resolved</div>
            </div>
            <div style={{ textAlign: "center", padding: 16, background: "rgba(239, 68, 68, 0.1)", borderRadius: 12, border: "1px solid rgba(239, 68, 68, 0.3)" }}>
              <div style={{ fontSize: 20, fontWeight: 900, color: "var(--danger)" }}>{weeklySummary.slaBreached}</div>
              <div style={{ color: "var(--text-muted)" }}>SLA Breached</div>
            </div>
            <div style={{ textAlign: "center", padding: 16, background: "rgba(245, 158, 11, 0.1)", borderRadius: 12, border: "1px solid rgba(245, 158, 11, 0.3)" }}>
              <div style={{ fontSize: 20, fontWeight: 900, color: "var(--warning)" }}>{weeklySummary.resolutionRate}%</div>
              <div style={{ color: "var(--text-muted)" }}>Resolution Rate</div>
            </div>
          </div>
        </div>

        {/* 🔹 STEP 6: THREAT HUNTER PANELS */}
        {canThreatHunt && (
          <div className="glass-panel" style={{ padding: 20, marginBottom: 16 }}>
            <h3>🔍 Threat Hunting Intelligence</h3>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginTop: 12 }}>
              <div>
                <h4 style={{ color: "var(--text-main)", marginBottom: 8 }}>🎯 Similar Incident Clusters</h4>
                <div style={{ fontSize: 12, color: "var(--text-muted)" }}>
                  Detect patterns and campaign activities across multiple incidents
                </div>
              </div>
              <div>
                <h4 style={{ color: "var(--text-main)", marginBottom: 8 }}>🛡 MITRE ATT&CK Mapping</h4>
                <div style={{ fontSize: 12, color: "var(--text-muted)" }}>
                  Threat intelligence and technique analysis for proactive defense
                </div>
              </div>
            </div>
          </div>
        )}

        {/* LIVE INCIDENTS MONITOR */}
        <div className="glass-panel" style={{ padding: 20 }}>
          <h3>🔴 Live Incidents Monitor</h3>
          <div style={{ maxHeight: 400, overflowY: "auto", marginTop: 12 }}>
            {(() => {
              // Normalize role for display filter
              const normalizedRole = normalizeRole(analystTeam);

              // Filter incidents based on user role using unified visibility function
              const displayIncidents = issues.filter(incident =>
                !incident.isDeleted && isVisibleToRole(incident, normalizedRole)
              );

              console.log(" Display Filter Debug - analystTeam:", analystTeam);
              console.log(" Display Filter Debug - total issues:", issues.length);
              console.log(" Display Filter Debug - IR assigned issues:", issues.filter(i => i.assignedTo === "ir").length);
              console.log(" Display Filter Debug - displayIncidents length:", displayIncidents.length);

              return displayIncidents.slice(0, 20).map(issue => {
                // 🔹 2 — Detect Warning in Incident Card
                const slaWarning = getSlaWarning(issue);

                // 🔹 STEP 5 — Calculate incident age for SOC L1
                const getIncidentAge = (createdAt) => {
                  if (!createdAt) return "Unknown";
                  const now = Date.now();
                  const created = tsToMillis(createdAt);
                  const diffMs = now - created;
                  const diffMins = Math.floor(diffMs / (1000 * 60));
                  const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
                  const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

                  if (diffMins < 60) return `${diffMins} min ago`;
                  if (diffHours < 24) return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
                  return `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;
                };

                // 🔹 STEP 6 — Get severity badge color for SOC L1
                const getSeverityBadge = (urgency) => {
                  const colors = {
                    low: { bg: "#6c757d", text: "LOW" },
                    medium: { bg: "#007bff", text: "MEDIUM" },
                    high: { bg: "#fd7e14", text: "HIGH" },
                    critical: { bg: "#dc3545", text: "CRITICAL" }
                  };
                  return colors[urgency?.toLowerCase()] || colors.low;
                };

                return (
                  <div key={issue.id} data-testid={`incident-card-${issue.id}`} style={{
                    // 🔹 3 — Highlight Card Border
                    border: getSlaDisplay(issue).breached
                      ? "2px solid red"
                      : slaWarning
                        ? "2px solid orange"
                        : "1px solid var(--glass-border)",
                    borderRadius: 8,
                    padding: 12,
                    marginBottom: 8,
                    background: getSlaDisplay(issue).breached ? "rgba(239, 68, 68, 0.1)" : "rgba(0, 0, 0, 0.2)"
                  }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                      <div style={{ flex: 1 }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                          <div style={{ fontWeight: 900, fontSize: 14, color: "var(--text-main)" }}>
                            {issue.title}
                            {issue.locked && (
                              <span style={{ color: "red", fontWeight: "bold", marginLeft: 8 }}>
                                🔒 Manager Locked
                              </span>
                            )}
                            {isL2 && issue.status === "escalation_pending" && (
                              <span style={{
                                background: "#ffc107",
                                color: "#000",
                                padding: "2px 8px",
                                borderRadius: "12px",
                                fontSize: "10px",
                                fontWeight: "600",
                                marginLeft: "8px"
                              }}>
                                🟡 Waiting for Manager Approval
                              </span>
                            )}
                            {isL2 && issue.escalationApproved === true && (
                              <span style={{
                                background: "#28a745",
                                color: "#fff",
                                padding: "2px 8px",
                                borderRadius: "12px",
                                fontSize: "10px",
                                fontWeight: "600",
                                marginLeft: "8px"
                              }}>
                                ✅ Incident escalated to ir
                              </span>
                            )}
                            {normalizeRole(issue.assignedTo) === "soc_l2" && (
                              <span style={{
                                background: "#ff9800",
                                color: "#fff",
                                padding: "2px 8px",
                                borderRadius: "12px",
                                fontSize: "10px",
                                fontWeight: "600",
                                marginLeft: "8px"
                              }}>
                                ⚡ Escalated to soc_l2
                              </span>
                            )}
                            {issue.triageStatus === "confirmed_threat" && (
                              <span style={{
                                background: "#d32f2f",
                                color: "#fff",
                                padding: "2px 6px",
                                borderRadius: 12,
                                fontSize: 10,
                                marginLeft: "8px"
                              }}>
                                🚨 Threat Confirmed
                              </span>
                            )}
                          </div>
                          {/* 🔹 STEP 7 — Add Severity Badge for SOC L1 */}
                          {isL1 && (
                            <span style={{
                              background: getSeverityBadge(issue.urgency).bg,
                              color: "#fff",
                              padding: "2px 6px",
                              borderRadius: 4,
                              fontSize: 10,
                              fontWeight: 600
                            }}>
                              {getSeverityBadge(issue.urgency).text}
                            </span>
                          )}
                          {/* 🔹 STEP 8 — Add Triage Required Badge for SOC L1 */}
                          {isL1 && issue.status === "open" && (
                            <span style={{
                              background: "#fd7e14",
                              color: "#fff",
                              padding: "2px 6px",
                              borderRadius: 4,
                              fontSize: 10,
                              fontWeight: 600
                            }}>
                              TRIAGE REQUIRED
                            </span>
                          )}
                        </div>
                        <div style={{ fontSize: 12, marginTop: 6, color: "var(--text-muted)" }}>
                          {/* 🔹 STEP 9 — Add Incident Age for SOC L1 */}
                          {isL1 ? (
                            <span>⏱ Reported {getIncidentAge(issue.createdAt)}</span>
                          ) : (
                            <span>📍 {issue.location} • 🧠 {issue.category} • 👤 {getAnalystDisplayLabel(issue.assignedTo, usersData)}</span>
                          )}
                        </div>

                        {/* 🔹 2 — Add Severity Dropdown in Incident Card */}
                        {isL2 && (
                          <select
                            defaultValue={issue.urgency}
                            onChange={(e) => adjustSeverity(issue.id, e.target.value)}
                            style={{
                              marginTop: 6,
                              padding: "4px 8px",
                              borderRadius: 4,
                              fontSize: 11,
                              border: "1px solid var(--glass-border)",
                              background: "var(--glass-bg)",
                              color: "var(--text-main)"
                            }}
                          >
                            <option value="low">Low</option>
                            <option value="medium">Medium</option>
                            <option value="high">High</option>
                          </select>
                        )}

                        {/* 🔹 2 — Add Triage Action Buttons Inside Incident Card */}
                        {isL2 && (
                          <div style={{ marginTop: 8 }}>
                            <button
                              onClick={() => updateTriageStatus(issue.id, "in_review")}
                              style={{
                                background: "var(--secondary)",
                                color: "#fff",
                                border: "none",
                                padding: "4px 8px",
                                borderRadius: 4,
                                fontSize: 10,
                                fontWeight: 600,
                                cursor: "pointer",
                                marginRight: 4
                              }}
                            >
                              🔍 Mark In Review
                            </button>

                            <button
                              onClick={() => updateTriageStatus(issue.id, "false_positive")}
                              data-testid="mark-false-positive"
                              style={{
                                background: "var(--warning)",
                                color: "#fff",
                                border: "none",
                                padding: "4px 8px",
                                borderRadius: 4,
                                fontSize: 10,
                                fontWeight: 600,
                                cursor: "pointer",
                                marginRight: 4
                              }}
                            >
                              ❌ Mark False Positive
                            </button>

                            <button
                              onClick={() => updateTriageStatus(issue.id, "confirmed_threat")}
                              data-testid="confirm-threat"
                              style={{
                                background: "var(--danger)",
                                color: "#fff",
                                border: "none",
                                padding: "4px 8px",
                                borderRadius: 4,
                                fontSize: 10,
                                fontWeight: 600,
                                cursor: "pointer"
                              }}
                            >
                              🚨 Confirm Threat
                            </button>
                          </div>
                        )}

                        {/* 🔹 2 — Add Containment Button in Incident Card */}
                        {isL2 && normalizeRole(issue.escalatedTo) === "soc_l2" && !issue.containmentRequested && (
                          <button
                            disabled={issue.locked === true}
                            onClick={() => requestContainment(issue.id)}
                            style={{
                              marginTop: 6,
                              background: "var(--warning)",
                              color: "#fff",
                              border: "none",
                              padding: "4px 8px",
                              borderRadius: 4,
                              fontSize: 10,
                              fontWeight: 600,
                              cursor: "pointer"
                            }}
                          >
                            🛡️ Request IR Containment
                          </button>
                        )}

                        {/* 🔹 Withdraw Request Button */}
                        {isL2 && normalizeRole(issue.escalatedTo) !== "soc_l2" && issue.approvalStatus === "pending" && (
                          <button
                            disabled={issue.locked === true}
                            onClick={() => withdrawRequest(issue.id)}
                            style={{
                              marginTop: 6,
                              background: "rgba(239,68,68,0.2)",
                              color: "#fff",
                              border: "1px solid rgba(239,68,68,0.3)",
                              padding: "4px 8px",
                              borderRadius: 4,
                              fontSize: 10,
                              fontWeight: 600,
                              cursor: "pointer"
                            }}
                          >
                            ↩️ Withdraw Request
                          </button>
                        )}

                        {/* 🔹 Approval Status Badge */}
                        {issue.approvalStatus && (
                          <div style={{ marginTop: 4, fontSize: 11, fontWeight: 600 }}>
                            {issue.approvalStatus === "approved" && (
                              <span style={{ background: "#22c55e", color: "#fff", padding: "2px 8px", borderRadius: 4 }}>
                                ✅ Approved
                              </span>
                            )}
                            {issue.approvalStatus === "rejected" && (
                              <span style={{ background: "#ef4444", color: "#fff", padding: "2px 8px", borderRadius: 4 }}>
                                ❌ Rejected
                              </span>
                            )}
                            {issue.approvalStatus === "pending" && (
                              <span style={{ background: "#f59e0b", color: "#fff", padding: "2px 8px", borderRadius: 4 }}>
                                ⏳ Pending Approval
                              </span>
                            )}
                          </div>
                        )}
                        <div style={{ marginTop: 4, fontSize: 12, color: getSlaDisplay(issue).color }}>
                          {getSlaDisplay(issue).label}
                        </div>

                        {/* 🔹 STEP 3 — Add IR Containment Panel in Incident Card */}
                        {/* 🔹 STEP 3 — Add IR Containment Panel in Incident Card */}
                        {isIR && (!["resolved", "closed", "completed", "false_positive", "risk_accepted"].includes(issue.status) && !issue.isDeleted) && (
                          (normalizeRole(issue.assignedTo) === "ir" || normalizeRole(issue.escalatedTo) === "ir" || issue.assignedTo === "IR Team" || issue.escalationApproved === true || ["escalation_approved", "ir_in_progress", "containment_pending_approval", "containment_in_progress", "containment_action_submitted", "containment_approved", "containment_rejected", "containment_review_again", "containment_executed", "containment_pending"].includes(issue.status))
                        ) && (
                            <div style={{ marginTop: 10, padding: 8, background: "rgba(0,0,0,0.05)", borderRadius: 4 }}>
                              <b style={{ fontSize: 12, color: "var(--text-main)", marginBottom: 4 }}>Containment Actions</b>

                              {/* Show manager decision if rejected or review_again */}
                              {(issue.status === "containment_rejected" || issue.status === "containment_review_again") && issue.managerDecision && (
                                <div style={{ marginTop: 4, padding: 4, background: "rgba(239,68,68,0.1)", borderRadius: 4, fontSize: 11 }}>
                                  <div style={{ color: "#ef4444", fontWeight: "bold" }}>
                                    {issue.status === "containment_rejected" ? "❌ Action Rejected" : "⚠ Manager requested changes"}
                                  </div>
                                  <div style={{ color: "#aaa" }}>{issue.managerDecision.comment}</div>
                                </div>
                              )}

                              {/* Show submit buttons when IR can submit action (active IR state, not pending manager review) */}
                              {issue.status !== "containment_action_submitted" && issue.status !== "containment_approved" && (
                                <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginTop: 4 }}>
                                  <button
                                    disabled={issue.locked === true}
                                    onClick={() => submitContainmentAction(issue.id, "block_ip", "Block malicious IP address")}
                                    style={{
                                      background: "var(--danger)",
                                      color: "#fff",
                                      border: "none",
                                      padding: "4px 8px",
                                      borderRadius: 4,
                                      fontSize: 10,
                                      opacity: issue.locked ? 0.5 : 1,
                                      cursor: issue.locked ? "not-allowed" : "pointer"
                                    }}
                                  >
                                    Submit Block IP
                                  </button>
                                  <button
                                    disabled={issue.locked === true}
                                    onClick={() => submitContainmentAction(issue.id, "patch_system", "Patch vulnerable system")}
                                    style={{
                                      background: "var(--warning)",
                                      color: "#fff",
                                      border: "none",
                                      padding: "4px 8px",
                                      borderRadius: 4,
                                      fontSize: 10,
                                      opacity: issue.locked ? 0.5 : 1,
                                      cursor: issue.locked ? "not-allowed" : "pointer"
                                    }}
                                  >
                                    Submit Patch System
                                  </button>
                                  <button
                                    disabled={issue.locked === true}
                                    onClick={() => submitContainmentAction(issue.id, "isolate_host", "Isolate compromised host")}
                                    style={{
                                      background: "var(--secondary)",
                                      color: "#fff",
                                      border: "none",
                                      padding: "4px 8px",
                                      borderRadius: 4,
                                      fontSize: 10,
                                      opacity: issue.locked ? 0.5 : 1,
                                      cursor: issue.locked ? "not-allowed" : "pointer"
                                    }}
                                  >
                                    Submit Isolate Host
                                  </button>
                                  <button
                                    disabled={issue.locked === true}
                                    onClick={() => submitContainmentAction(issue.id, "disable_account", "Disable compromised account")}
                                    style={{
                                      background: "var(--primary)",
                                      color: "#fff",
                                      border: "none",
                                      padding: "4px 8px",
                                      borderRadius: 4,
                                      fontSize: 10,
                                      opacity: issue.locked ? 0.5 : 1,
                                      cursor: issue.locked ? "not-allowed" : "pointer"
                                    }}
                                  >
                                    Submit Disable Account
                                  </button>
                                </div>
                              )}

                              {/* Show action buttons without submit for review_again state */}
                              {issue.status === "containment_review_again" && (
                                <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginTop: 4 }}>
                                  <button
                                    disabled={issue.locked === true}
                                    onClick={() => updateContainmentAction(issue.id, "block_ip", "Block malicious IP address")}
                                    style={{
                                      background: "var(--danger)",
                                      color: "#fff",
                                      border: "none",
                                      padding: "4px 8px",
                                      borderRadius: 4,
                                      fontSize: 10,
                                      opacity: issue.locked ? 0.5 : 1,
                                      cursor: issue.locked ? "not-allowed" : "pointer"
                                    }}
                                  >
                                    Block IP
                                  </button>
                                  <button
                                    disabled={issue.locked === true}
                                    onClick={() => updateContainmentAction(issue.id, "patch_system", "Patch vulnerable system")}
                                    style={{
                                      background: "var(--warning)",
                                      color: "#fff",
                                      border: "none",
                                      padding: "4px 8px",
                                      borderRadius: 4,
                                      fontSize: 10,
                                      opacity: issue.locked ? 0.5 : 1,
                                      cursor: issue.locked ? "not-allowed" : "pointer"
                                    }}
                                  >
                                    Patch System
                                  </button>
                                  <button
                                    disabled={issue.locked === true}
                                    onClick={() => updateContainmentAction(issue.id, "isolate_host", "Isolate compromised host")}
                                    style={{
                                      background: "var(--secondary)",
                                      color: "#fff",
                                      border: "none",
                                      padding: "4px 8px",
                                      borderRadius: 4,
                                      fontSize: 10,
                                      opacity: issue.locked ? 0.5 : 1,
                                      cursor: issue.locked ? "not-allowed" : "pointer"
                                    }}
                                  >
                                    Isolate Host
                                  </button>
                                  <button
                                    disabled={issue.locked === true}
                                    onClick={() => updateContainmentAction(issue.id, "disable_account", "Disable compromised account")}
                                    style={{
                                      background: "var(--primary)",
                                      color: "#fff",
                                      border: "none",
                                      padding: "4px 8px",
                                      borderRadius: 4,
                                      fontSize: 10,
                                      opacity: issue.locked ? 0.5 : 1,
                                      cursor: issue.locked ? "not-allowed" : "pointer"
                                    }}
                                  >
                                    Disable Account
                                  </button>
                                  <button
                                    disabled={issue.locked === true}
                                    onClick={() => submitContainmentAction(issue.id, issue.irAction?.type || "block_ip", issue.irAction?.details || "Updated action")}
                                    style={{
                                      background: "var(--success)",
                                      color: "#fff",
                                      border: "none",
                                      padding: "4px 8px",
                                      borderRadius: 4,
                                      fontSize: 10,
                                      opacity: issue.locked ? 0.5 : 1,
                                      cursor: issue.locked ? "not-allowed" : "pointer"
                                    }}
                                  >
                                    Resubmit
                                  </button>
                                </div>
                              )}

                              {/* Show execute button when manager approved */}
                              {issue.status === "containment_approved" && issue.irAction && (
                                <div style={{ marginTop: 4, padding: 4, background: "rgba(34,197,94,0.1)", borderRadius: 4 }}>
                                  <div style={{ color: "#22c55e", fontWeight: "bold", fontSize: 11 }}>
                                    ✅ Action Approved: {issue.irAction.type}
                                  </div>
                                  <div style={{ color: "#aaa", fontSize: 10 }}>{issue.irAction.details}</div>
                                </div>
                              )}

                              {/* Show submitted status */}
                              {issue.status === "containment_action_submitted" && (
                                <div style={{ marginTop: 4, padding: 4, background: "rgba(245,158,11,0.1)", borderRadius: 4 }}>
                                  <div style={{ color: "#f59e0b", fontWeight: "bold", fontSize: 11 }}>
                                    🟡 Action Submitted - Awaiting Manager Review
                                  </div>
                                  <div style={{ color: "#aaa", fontSize: 10 }}>{issue.irAction?.details}</div>
                                </div>
                              )}

                              {/* Show executed status */}
                              {issue.status === "containment_executed" && (
                                <div style={{ marginTop: 4, padding: 4, background: "rgba(16,185,129,0.1)", borderRadius: 4 }}>
                                  <div style={{ color: "#10b981", fontWeight: "bold", fontSize: 11 }}>
                                    ✅ Containment Executed Successfully
                                  </div>
                                </div>
                              )}
                            </div>
                          )}

                        {/* 🔹 Display IR Actions */}
                        {issue.containmentActions && issue.containmentActions.length > 0 && (
                          <div style={{ marginTop: 8, padding: 8, background: "rgba(0,255,0,0.05)", borderRadius: 4 }}>
                            <b style={{ fontSize: 12, color: "var(--text-main)", marginBottom: 4 }}>Execution Log</b>
                            {issue.containmentActions.map((action, idx) => (
                              <div key={idx} style={{ fontSize: 11, color: "#aaa", marginTop: 2 }}>
                                {action.action} by {action.performedBy} at {action.timestamp?.toDate?.()?.toLocaleString() || "Unknown"}
                              </div>
                            ))}
                          </div>
                        )}

                        {/* 🔹 3 — Add Notes Panel Inside Each Live Incident Card */}
                        {isL1 && (
                          <textarea
                            placeholder="Add investigation notes..."
                            value={noteText}
                            onChange={(e) => setNoteText(e.target.value)}
                            style={{
                              width: "100%",
                              marginTop: 8,
                              padding: 8,
                              borderRadius: 4,
                              border: "1px solid var(--glass-border)",
                              background: "var(--glass-bg)",
                              color: "var(--text-main)",
                              fontSize: 12,
                              minHeight: 60,
                              resize: "vertical"
                            }}
                          />
                        )}

                        {isL1 && issue.status !== "resolved" && (
                          <button
                            onClick={() => addNote(issue.id)}
                            data-testid="submit-note"
                            style={{
                              marginTop: 6,
                              background: "var(--primary)",
                              color: "#fff",
                              border: "none",
                              padding: "6px 12px",
                              borderRadius: 4,
                              fontSize: 11,
                              fontWeight: 600,
                              cursor: "pointer"
                            }}
                          >
                            📝 Add Note
                          </button>
                        )}

                        {/* 🔹 4 — Display Analyst Notes Below Timeline */}
                        {issue.analystNotes?.length > 0 && (
                          <div style={{ marginTop: 12, padding: 8, background: "rgba(0,0,0,0.1)", borderRadius: 4 }}>
                            <b style={{ fontSize: 12, color: "var(--text-main)", marginBottom: 4 }}>📝 Analyst Notes</b>
                            {issue.analystNotes.map((n, idx) => (
                              <div key={idx} style={{
                                fontSize: 11,
                                color: "var(--text-muted)",
                                marginBottom: 4,
                                padding: 4,
                                background: "rgba(255,255,255,0.05)",
                                borderRadius: 3,
                                borderLeft: "2px solid var(--primary)"
                              }}>
                                <div style={{ fontSize: 10, color: "var(--text-muted)", marginBottom: 2 }}>
                                  {formatTimeAgo(tsToMillis(n.at))} • {getAnalystDisplayLabel(n.by, usersData)}
                                </div>
                                <div>{n.note}</div>
                              </div>
                            ))}
                          </div>
                        )}

                        {/* 📋 PIR Workspace Panel */}
                        <PIRWorkspacePanel
                          issue={issue}
                          usersData={usersData}
                          normalizedRole={normalizedRole}
                          getAnalystDisplayLabel={getAnalystDisplayLabel}
                          setToast={setToast}
                        />

                        {/* 🔍 RCA Workspace Panel */}
                        <RCAWorkspacePanel
                          issue={issue}
                          usersData={usersData}
                          normalizedRole={normalizedRole}
                          getAnalystDisplayLabel={getAnalystDisplayLabel}
                          setToast={setToast}
                        />

                        {/* 🕵️ Threat Hunt Workspace Panel */}
                        <ThreatHuntWorkspacePanel
                          issue={issue}
                          usersData={usersData}
                          normalizedRole={normalizedRole}
                          getAnalystDisplayLabel={getAnalystDisplayLabel}
                          setToast={setToast}
                        />

                        {/* 🔹 6 — Display Timeline Inside Incident Card */}
                        {(() => {
                          const renderedTimeline = buildRenderableTimeline(
                            timelines.get(issue.id),
                            issue.statusHistory,
                            "desc",
                            issue.investigationHistory
                          );
                          if (renderedTimeline.length === 0) return null;
                          return (
                            <div style={{ marginTop: 8, padding: 8, background: "rgba(0,0,0,0.05)", borderRadius: 4 }}>
                              <b style={{ fontSize: 12, color: "var(--text-main)", marginBottom: 4 }}>🕐 Investigation Timeline</b>
                              {renderedTimeline.map((event, idx) => (
                                <div key={idx} style={{
                                  fontSize: 12,
                                  color: "var(--text-muted)",
                                  marginBottom: 4,
                                  padding: 4,
                                  background: "rgba(255,255,255,0.03)",
                                  borderRadius: 3,
                                  borderLeft: "2px solid var(--secondary)"
                                }}>
                                  <div style={{ fontSize: 10, color: "var(--text-muted)", marginBottom: 2 }}>
                                    {event.icon} {event.displayLabel} at {event.timestamp ? new Date(event.timestamp).toLocaleTimeString() : "—"}
                                    {event.note ? ` — ${event.note}` : ""}
                                    {event.actor ? <span style={{ opacity: 0.7 }}> (by {event.actor})</span> : ""}
                                  </div>
                                </div>
                              ))}
                            </div>
                          );
                        })()}
                      </div>
                      <div style={{ textAlign: "right", marginLeft: 12 }}>
                        <div style={{ fontSize: 12, fontWeight: 900, color: getSlaDisplay(issue).color }}>
                          {getSlaDisplay(issue).label}
                        </div>

                        {/* 🔹 4 — Add Warning Label */}
                        {slaWarning && (
                          <span style={{
                            display: "block",
                            marginTop: 4,
                            background: "#f57c00",
                            color: "#fff",
                            padding: "2px 6px",
                            borderRadius: 12,
                            fontSize: 10,
                            fontWeight: 600
                          }}>
                            ⚠ SLA Near Breach
                          </span>
                        )}
                        <div style={{ fontSize: 11, opacity: 0.7, marginTop: 4, color: "var(--text-muted)" }}>
                          {formatTimeAgo(tsToMillis(issue.createdAt))}
                        </div>

                        {/* 🔹 3 — Display Current Triage Status */}
                        <div style={{ marginTop: 4 }}>
                          <span style={{
                            background: issue.triageStatus === "confirmed_threat" ? "var(--danger)" :
                              issue.triageStatus === "false_positive" ? "var(--warning)" :
                                issue.triageStatus === "in_review" ? "var(--secondary)" : "var(--primary)",
                            color: "#fff",
                            padding: "2px 6px",
                            borderRadius: 12,
                            fontSize: 10,
                            fontWeight: 600
                          }}>
                            {issue.triageStatus || "pending"}
                          </span>

                          {/* 🔹 5 — Add Read-Only Label For Other Teams */}
                          {!isL1 && (
                            <span style={{
                              marginLeft: 8,
                              background: "#455a64",
                              color: "#fff",
                              padding: "2px 6px",
                              borderRadius: 12,
                              fontSize: 10,
                              fontWeight: 600
                            }}>
                              Investigation Restricted
                            </span>
                          )}

                          {/* 🔹 STEP 4 — Show Containment Completed Label */}
                          {issue.containmentActionTaken && (
                            <span style={{
                              marginLeft: 8,
                              background: "#2e7d32",
                              color: "#fff",
                              padding: "2px 6px",
                              borderRadius: 12,
                              fontSize: 10,
                              fontWeight: 600
                            }}>
                              Contained: {issue.containmentActionTaken}
                            </span>
                          )}

                          {/* 🔹 STEP 2 — Show Manager Review Label */}
                          {issue.readyForManagerReview && (
                            <span style={{
                              marginLeft: 8,
                              background: "#1976d2",
                              color: "#fff",
                              padding: "2px 6px",
                              borderRadius: 12,
                              fontSize: 10,
                              fontWeight: 600
                            }}>
                              Awaiting Manager Review
                            </span>
                          )}
                        </div>

                        {/* 🔹 STEP 5: DYNAMIC INCIDENT ACTIONS */}
                        <div style={{ display: "flex", gap: 6, marginTop: 8, flexDirection: "column" }}>
                          {/* Claim button for unassigned incidents and old staff assignments */}
                          {(!issue.assignedTo || (issue.assignedTo && ["soc_network", "soc_endpoint", "soc_email", "soc_identity", "soc_l1", "soc_l2", "ir", "threat_hunter", "forensics", "cloud_security", "network_security", "soc_netw"].includes(issue.assignedTo))) && issue.status === "open" && issue.status !== "resolved" && (
                            <button
                              disabled={issue.locked === true}
                              onClick={async () => {
                                try {
                                  // BUG FIX #10: also update status to "assigned" when claiming
                                  await updateDoc(doc(db, "issues", issue.id), {
                                    assignedTo: auth.currentUser?.uid,
                                    assignedAt: serverTimestamp(),
                                    status: "assigned",   // BUG FIX: was missing, incident stayed "open"
                                    statusHistory: arrayUnion({
                                      status: "assigned",
                                      at: Timestamp.now(),
                                      note: `Claimed by ${auth.currentUser?.email}`
                                    }),
                                    updatedAt: serverTimestamp()
                                  });
                                  appendAssignmentLifecycle(issue.id, normalizedRole || "unknown", {
                                    from: issue.assignedTo || null,
                                    to: auth.currentUser?.uid,
                                    reason: `Claimed by ${auth.currentUser?.email}`,
                                    isReassign: !!issue.assignedTo
                                  });
                                } catch (err) {
                                  console.error("Claim failed:", err);
                                }
                              }}
                              style={{
                                background: "var(--success)",
                                color: "#fff",
                                border: "none",
                                padding: "6px 12px",
                                borderRadius: 4,
                                fontSize: 11,
                                fontWeight: 600,
                                cursor: "pointer",
                                marginBottom: 4
                              }}
                            >
                              🎯 Claim Incident
                            </button>
                          )}

                          {issue.status === "open" && issue.status !== "resolved" && (
                            <button
                              disabled={issue.locked === true}
                              onClick={() => updateStatus(issue, "in_progress")}
                              style={{
                                background: "var(--primary)",
                                color: "#fff",
                                border: "none",
                                padding: "6px 12px",
                                borderRadius: 4,
                                fontSize: 11,
                                fontWeight: 600,
                                cursor: "pointer",
                                marginBottom: 4
                              }}
                            >
                              ▶ Start Investigation
                            </button>
                          )}

                          {/* 🔹 STEP 6 — Add Escalate Button in Incident Card */}
                          {isL1 && !issue.escalated && issue.status !== "resolved" && issue.triageStatus === "confirmed_threat" && (
                            <button
                              disabled={issue.locked === true}
                              onClick={() => escalateIncident(issue.id)}
                              data-testid="escalate-l2"
                              style={{
                                background: "var(--warning)",
                                color: "#fff",
                                border: "none",
                                padding: "4px 8px",
                                borderRadius: 4,
                                fontSize: 10,
                                fontWeight: 600,
                                cursor: "pointer",
                                marginBottom: 4
                              }}
                            >
                              ⚡ Escalate to L2
                            </button>
                          )}



                          {isL1 && (
                            <div style={{ marginTop: 8 }}>
                              {(issue.status === "open" || issue.status === "assigned") && (
                                <button
                                  onClick={() => startTriage(issue.id)}
                                  data-testid="start-triage"
                                  style={{
                                    background: "var(--primary)",
                                    color: "#fff",
                                    border: "none",
                                    padding: "6px 12px",
                                    borderRadius: 4,
                                    fontSize: 11,
                                    fontWeight: 600,
                                    cursor: "pointer",
                                    marginRight: 4
                                  }}
                                >
                                  📋 Start Triage
                                </button>
                              )}
                              {(issue.status === "assigned" || issue.status === "in_progress") && (
                                <button
                                  onClick={() => updateTriageStatus(issue.id, "false_positive")}
                                  data-testid="mark-false-positive"
                                  style={{
                                    background: "var(--secondary)",
                                    color: "#fff",
                                    border: "none",
                                    padding: "6px 12px",
                                    borderRadius: 4,
                                    fontSize: 11,
                                    fontWeight: 600,
                                    cursor: "pointer",
                                    marginRight: 4
                                  }}
                                >
                                  ✅ Mark False Positive
                                </button>
                              )}
                              {issue.status === "in_progress" && issue.triageStatus !== "confirmed_threat" && (
                                <button
                                  disabled={issue.locked === true}
                                  onClick={() => updateTriageStatus(issue.id, "confirmed_threat")}
                                  style={{
                                    background: "var(--danger)",
                                    color: "#fff",
                                    border: "none",
                                    padding: "6px 12px",
                                    borderRadius: 4,
                                    fontSize: 11,
                                    fontWeight: 600,
                                    cursor: "pointer",
                                    marginRight: 4
                                  }}
                                >
                                  🚨 Confirm Threat
                                </button>
                              )}

                              {/* 🔹 STEP 10 — Add Quick Classification Buttons for SOC L1 */}
                              <div style={{ marginTop: 8 }}>
                                <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 4 }}>Quick Classification:</div>
                                <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                                  <button
                                    onClick={async () => {
                                      try {
                                        console.log("Classifying as phishing:", issue.id);
                                        await updateDoc(doc(db, "issues", issue.id), {
                                          triageClassification: "phishing",
                                          statusHistory: arrayUnion({
                                            status: "triage_updated",
                                            note: "Triage classification: phishing",
                                            at: Timestamp.now(),
                                            by: auth.currentUser?.email || "unknown"
                                          }),
                                          investigationHistory: arrayUnion({
                                            action: "classified_as_phishing",
                                            by: auth.currentUser?.uid,
                                            at: Timestamp.now()
                                          }),
                                          updatedAt: serverTimestamp()
                                        });
                                        appendTimelineEvent({
                                          incidentId: issue.id,
                                          eventType: TIMELINE_EVENTS.TRIAGE_UPDATED,
                                          actorId: auth.currentUser?.uid || "unknown",
                                          actorRole: normalizedRole || "soc_l1",
                                          previousState: issue.triageClassification || null,
                                          newState: "phishing",
                                          metadata: { reason: "Triage classification: phishing" }
                                        });
                                        console.log("Phishing classification successful");
                                      } catch (error) {
                                        console.error("Error classifying as phishing:", error);
                                        alert("Error classifying incident: " + error.message);
                                      }
                                    }}
                                    style={{
                                      background: "#e3f2fd",
                                      color: "#1976d2",
                                      border: "1px solid #90caf9",
                                      padding: "4px 8px",
                                      borderRadius: 4,
                                      fontSize: 10,
                                      cursor: "pointer"
                                    }}
                                  >
                                    Likely Phishing
                                  </button>
                                  <button
                                    onClick={async () => {
                                      try {
                                        console.log("Classifying as malware:", issue.id);
                                        await updateDoc(doc(db, "issues", issue.id), {
                                          triageClassification: "malware",
                                          statusHistory: arrayUnion({
                                            status: "triage_updated",
                                            note: "Triage classification: malware",
                                            at: Timestamp.now(),
                                            by: auth.currentUser?.email || "unknown"
                                          }),
                                          investigationHistory: arrayUnion({
                                            action: "classified_as_malware",
                                            by: auth.currentUser?.uid,
                                            at: Timestamp.now()
                                          }),
                                          updatedAt: serverTimestamp()
                                        });
                                        appendTimelineEvent({
                                          incidentId: issue.id,
                                          eventType: TIMELINE_EVENTS.TRIAGE_UPDATED,
                                          actorId: auth.currentUser?.uid || "unknown",
                                          actorRole: normalizedRole || "soc_l1",
                                          previousState: issue.triageClassification || null,
                                          newState: "malware",
                                          metadata: { reason: "Triage classification: malware" }
                                        });
                                        console.log("Malware classification successful");
                                      } catch (error) {
                                        console.error("Error classifying as malware:", error);
                                        alert("Error classifying incident: " + error.message);
                                      }
                                    }}
                                    style={{
                                      background: "#fce4ec",
                                      color: "#c62828",
                                      border: "1px solid #f8bbd9",
                                      padding: "4px 8px",
                                      borderRadius: 4,
                                      fontSize: 10,
                                      cursor: "pointer"
                                    }}
                                  >
                                    Likely Malware
                                  </button>
                                  <button
                                    onClick={async () => {
                                      try {
                                        console.log("Classifying as network attack:", issue.id);
                                        await updateDoc(doc(db, "issues", issue.id), {
                                          triageClassification: "network_attack",
                                          statusHistory: arrayUnion({
                                            status: "triage_updated",
                                            note: "Triage classification: network attack",
                                            at: Timestamp.now(),
                                            by: auth.currentUser?.email || "unknown"
                                          }),
                                          investigationHistory: arrayUnion({
                                            action: "classified_as_network_attack",
                                            by: auth.currentUser?.uid,
                                            at: Timestamp.now()
                                          }),
                                          updatedAt: serverTimestamp()
                                        });
                                        appendTimelineEvent({
                                          incidentId: issue.id,
                                          eventType: TIMELINE_EVENTS.TRIAGE_UPDATED,
                                          actorId: auth.currentUser?.uid || "unknown",
                                          actorRole: normalizedRole || "soc_l1",
                                          previousState: issue.triageClassification || null,
                                          newState: "network_attack",
                                          metadata: { reason: "Triage classification: network attack" }
                                        });
                                        console.log("Network attack classification successful");
                                      } catch (error) {
                                        console.error("Error classifying as network attack:", error);
                                        alert("Error classifying incident: " + error.message);
                                      }
                                    }}
                                    style={{
                                      background: "#fff3e0",
                                      color: "#f57c00",
                                      border: "1px solid #ffcc02",
                                      padding: "4px 8px",
                                      borderRadius: 4,
                                      fontSize: 10,
                                      cursor: "pointer"
                                    }}
                                  >
                                    Likely Network Attack
                                  </button>
                                  <button
                                    onClick={async () => {
                                      try {
                                        console.log("Classifying as suspicious:", issue.id);
                                        await updateDoc(doc(db, "issues", issue.id), {
                                          triageClassification: "suspicious",
                                          statusHistory: arrayUnion({
                                            status: "triage_updated",
                                            note: "Triage classification: suspicious",
                                            at: Timestamp.now(),
                                            by: auth.currentUser?.email || "unknown"
                                          }),
                                          investigationHistory: arrayUnion({
                                            action: "classified_as_suspicious",
                                            by: auth.currentUser?.uid,
                                            at: Timestamp.now()
                                          }),
                                          updatedAt: serverTimestamp()
                                        });
                                        appendTimelineEvent({
                                          incidentId: issue.id,
                                          eventType: TIMELINE_EVENTS.TRIAGE_UPDATED,
                                          actorId: auth.currentUser?.uid || "unknown",
                                          actorRole: normalizedRole || "soc_l1",
                                          previousState: issue.triageClassification || null,
                                          newState: "suspicious",
                                          metadata: { reason: "Triage classification: suspicious" }
                                        });
                                        console.log("Suspicious classification successful");
                                      } catch (error) {
                                        console.error("Error classifying as suspicious:", error);
                                        alert("Error classifying incident: " + error.message);
                                      }
                                    }}
                                    style={{
                                      background: "#f3e5f5",
                                      color: "#7b1fa2",
                                      border: "1px solid #ce93d8",
                                      padding: "4px 8px",
                                      borderRadius: 4,
                                      fontSize: 10,
                                      cursor: "pointer"
                                    }}
                                  >
                                    Suspicious
                                  </button>
                                </div>
                              </div>
                            </div>
                          )}



                          {canReassign && (
                            <select
                              defaultValue=""
                              onChange={(e) => {
                                const v = e.target.value;
                                if (v) reassignIssue(issue, v);
                              }}
                              style={{
                                padding: "4px 8px",
                                borderRadius: 4,
                                fontSize: 11,
                                border: "1px solid var(--glass-border)",
                                background: "var(--glass-bg)",
                                color: "var(--text-main)",
                                marginBottom: 4
                              }}
                            >
                              <option value="">Reassign to...</option>
                              {generateUserOptions(usersData, analystLevel).map(userOption => (
                                <option key={userOption.value} value={userOption.value}>
                                  {userOption.label}
                                </option>
                              ))}
                            </select>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                );
              });
            })()}
          </div>
        </div>
      </div>
    </AnalystDashboardErrorBoundary>
  );
}

// 📋 Post-Incident Review Workspace Sub-Component
function PIRWorkspacePanel({ issue, usersData, normalizedRole, getAnalystDisplayLabel, setToast }) {
  const currentUid = auth.currentUser?.uid;
  const isOwner = issue.pirOwner === currentUid;
  const isContributor = issue.pirContributors && issue.pirContributors.includes(currentUid);
  const isManager = normalizedRole === "soc_manager" || normalizedRole === "admin";

  // Only show if tagged for PIR and user is owner, contributor, or manager
  const showPIR = issue.pirTagged === true && (isOwner || isContributor || isManager);
  if (!showPIR) return null;

  // Local state for edit forms
  const [localSummary, setLocalSummary] = useState(issue.pirSummary || "");
  const [localLessons, setLocalLessons] = useState(issue.pirLessonsLearned || "");
  const [recommendRCA, setRecommendRCA] = useState(!!issue.recommendRCA);
  const [activeTab, setActiveTab] = useState("findings");

  // Sync state if issue updates in background
  useEffect(() => {
    setLocalSummary(issue.pirSummary || "");
    setLocalLessons(issue.pirLessonsLearned || "");
    setRecommendRCA(!!issue.recommendRCA);
  }, [issue.pirSummary, issue.pirLessonsLearned, issue.recommendRCA]);

  // Action item form state
  const [actionDesc, setActionDesc] = useState("");
  const [actionOwner, setActionOwner] = useState("");
  const [actionPriority, setActionPriority] = useState("medium");
  const [actionDueDate, setActionDueDate] = useState("");

  const handleStartReview = async () => {
    try {
      await callGovernanceAction(issue.id, "START_PIR", { callerRole: normalizedRole });
      appendLifecycleEvent(issue.id, TIMELINE_EVENTS.PIR_STARTED, normalizedRole || "analyst");
      logGovernanceAudit(issue.id, AUDIT_ACTIONS.PIR_STARTED, normalizedRole || "analyst");
      setToast("📝 PIR Review started");
    } catch (err) {
      alert("Failed to start PIR review: " + err.message);
    }
  };

  const handleSaveDraft = async () => {
    try {
      await updateDoc(doc(db, "issues", issue.id), {
        pirSummary: localSummary,
        pirLessonsLearned: localLessons,
        updatedAt: serverTimestamp()
      });
      setToast("💾 Draft findings saved successfully");
    } catch (err) {
      alert("Failed to save draft findings: " + err.message);
    }
  };

  const handleCompletePIR = async () => {
    if (!localSummary.trim() || !localLessons.trim()) {
      alert("Summary and Lessons Learned are required to complete the PIR.");
      return;
    }
    try {
      await callGovernanceAction(issue.id, "COMPLETE_PIR", {
        summary: localSummary,
        lessonsLearned: localLessons,
        recommendRCA,
        callerRole: normalizedRole
      });
      appendLifecycleEvent(issue.id, TIMELINE_EVENTS.PIR_COMPLETED, normalizedRole || "analyst", { recommendRCA });
      logGovernanceAudit(issue.id, AUDIT_ACTIONS.PIR_COMPLETED, normalizedRole || "analyst", { recommendRCA });

      if (recommendRCA) {
        appendLifecycleEvent(issue.id, TIMELINE_EVENTS.RCA_RECOMMENDED, normalizedRole || "analyst");
        logGovernanceAudit(issue.id, AUDIT_ACTIONS.RCA_RECOMMENDED, normalizedRole || "analyst");
      }

      setToast("✅ PIR completed successfully");
    } catch (err) {
      alert("Failed to complete PIR: " + err.message);
    }
  };

  const handleAddActionItem = async (e) => {
    e.preventDefault();
    if (!actionDesc.trim() || !actionOwner || !actionDueDate) {
      alert("Please fill in all action item fields.");
      return;
    }
    try {
      await callGovernanceAction(issue.id, "ADD_PIR_ACTION_ITEM", {
        description: actionDesc,
        owner: actionOwner,
        dueDate: actionDueDate,
        priority: actionPriority
      });
      setActionDesc("");
      setActionOwner("");
      setActionPriority("medium");
      setActionDueDate("");
      setToast("➕ Action item added");
    } catch (err) {
      alert("Failed to add action item: " + err.message);
    }
  };

  const handleCompleteActionItem = async (itemId) => {
    try {
      await callGovernanceAction(issue.id, "COMPLETE_PIR_ACTION_ITEM", {
        actionItemId: itemId
      });
      setToast("✔ Action item marked completed");
    } catch (err) {
      alert("Failed to complete action item: " + err.message);
    }
  };

  const isEditable = issue.pirStatus === "in_progress";

  return (
    <div style={{
      marginTop: "12px",
      padding: "16px",
      background: "var(--glass-bg)",
      border: "1px solid var(--glass-border)",
      borderRadius: "12px",
      boxShadow: "var(--glass-shadow)",
      borderLeft: `4px solid ${issue.pirStatus === "completed" ? "var(--success)" : "var(--primary)"}`,
      textAlign: "left"
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
        <h4 style={{ color: "var(--text-main)", margin: 0, fontSize: "14px" }}>📋 Post-Incident Review (PIR) Workspace</h4>
        <span style={{
          background: issue.pirStatus === "completed" ? "var(--success)" :
            issue.pirStatus === "in_progress" ? "var(--primary)" :
              issue.pirStatus === "assigned" ? "var(--warning)" : "var(--text-muted)",
          color: "#fff",
          fontSize: "10px",
          padding: "2px 8px",
          borderRadius: "12px",
          fontWeight: "bold"
        }}>
          Status: {issue.pirStatus ? issue.pirStatus.toUpperCase() : "PENDING"} {issue.pirApproved ? "(APPROVED)" : ""}
        </span>
      </div>

      <div style={{ marginBottom: "10px", fontSize: "12px", color: "var(--text-muted)", display: "flex", flexDirection: "column", gap: "2px" }}>
        <div><strong>PIR Owner:</strong> <span style={{ color: "var(--text-main)" }}>{issue.pirOwner ? getAnalystDisplayLabel(issue.pirOwner, usersData) : "Not Assigned"}</span></div>
        <div>
          <strong>Contributors:</strong> <span style={{ color: "var(--text-main)" }}>{issue.pirContributors && issue.pirContributors.length > 0
            ? issue.pirContributors.map(uid => getAnalystDisplayLabel(uid, usersData)).join(", ")
            : "None"}</span>
        </div>
      </div>

      {/* State 1: Assigned (Waiting to start) */}
      {issue.pirStatus === "assigned" && (
        <div style={{ marginTop: "8px", textAlign: "center", padding: "12px", background: "rgba(0,0,0,0.2)", borderRadius: "8px", border: "1px solid var(--glass-border)" }}>
          {isOwner ? (
            <button
              onClick={handleStartReview}
              style={{
                padding: "8px 16px",
                background: "var(--primary)",
                color: "#fff",
                border: "none",
                borderRadius: "8px",
                fontWeight: "bold",
                cursor: "pointer",
                boxShadow: "0 0 10px rgba(6,182,212,0.2)"
              }}
            >
              ▶ Start PIR Review
            </button>
          ) : (
            <span style={{ fontSize: "12px", color: "var(--text-muted)" }}>⏳ Awaiting PIR Owner to start the review.</span>
          )}
        </div>
      )}

      {/* State 2 & 3: In Progress / Completed */}
      {(issue.pirStatus === "in_progress" || issue.pirStatus === "completed") && (
        <div style={{ marginTop: "10px" }}>
          {/* Tab Navigation */}
          <div style={{ display: "flex", borderBottom: "1px solid var(--glass-border)", marginBottom: "12px", gap: "16px" }}>
            <button
              onClick={() => setActiveTab("findings")}
              style={{
                background: "none",
                border: "none",
                borderBottom: activeTab === "findings" ? "2px solid var(--primary)" : "2px solid transparent",
                color: activeTab === "findings" ? "var(--text-main)" : "var(--text-muted)",
                padding: "6px 4px",
                fontSize: "12px",
                fontWeight: "bold",
                cursor: "pointer",
                outline: "none"
              }}
            >
              📝 Findings & Lessons
            </button>
            <button
              onClick={() => setActiveTab("actionItems")}
              style={{
                background: "none",
                border: "none",
                borderBottom: activeTab === "actionItems" ? "2px solid var(--primary)" : "2px solid transparent",
                color: activeTab === "actionItems" ? "var(--text-main)" : "var(--text-muted)",
                padding: "6px 4px",
                fontSize: "12px",
                fontWeight: "bold",
                cursor: "pointer",
                outline: "none"
              }}
            >
              🎯 Action Items {issue.pirActionItems && issue.pirActionItems.length > 0 ? `(${issue.pirActionItems.length})` : ""}
            </button>
            <button
              onClick={() => setActiveTab("complete")}
              style={{
                background: "none",
                border: "none",
                borderBottom: activeTab === "complete" ? "2px solid var(--primary)" : "2px solid transparent",
                color: activeTab === "complete" ? "var(--text-main)" : "var(--text-muted)",
                padding: "6px 4px",
                fontSize: "12px",
                fontWeight: "bold",
                cursor: "pointer",
                outline: "none"
              }}
            >
              ✔ Sign-off & RCA
            </button>
          </div>

          {/* Tab 1: Findings, Lessons Learned, Save Draft */}
          {activeTab === "findings" && (
            <div>
              <div style={{ marginBottom: "10px" }}>
                <label style={{ display: "block", fontSize: "12px", fontWeight: "bold", color: "var(--text-main)", marginBottom: "6px" }}>Summary of Findings</label>
                {isEditable ? (
                  <textarea
                    value={localSummary}
                    onChange={(e) => setLocalSummary(e.target.value)}
                    placeholder="Detail what happened, impact, timeline key highlights..."
                    style={{
                      width: "100%",
                      padding: "10px 12px",
                      borderRadius: "8px",
                      border: "1px solid var(--glass-border)",
                      background: "rgba(0, 0, 0, 0.35)",
                      color: "var(--text-main)",
                      fontSize: "12px",
                      minHeight: "80px",
                      resize: "vertical"
                    }}
                  />
                ) : (
                  <div style={{ padding: "10px 12px", background: "rgba(0,0,0,0.2)", borderRadius: "8px", border: "1px solid var(--glass-border)", fontSize: "12px", color: "var(--text-muted)", whiteSpace: "pre-wrap" }}>
                    {issue.pirSummary || "No summary recorded."}
                  </div>
                )}
              </div>

              <div style={{ marginBottom: "12px" }}>
                <label style={{ display: "block", fontSize: "12px", fontWeight: "bold", color: "var(--text-main)", marginBottom: "6px" }}>Lessons Learned</label>
                {isEditable ? (
                  <textarea
                    value={localLessons}
                    onChange={(e) => setLocalLessons(e.target.value)}
                    placeholder="What went well? What failed? What should be improved?"
                    style={{
                      width: "100%",
                      padding: "10px 12px",
                      borderRadius: "8px",
                      border: "1px solid var(--glass-border)",
                      background: "rgba(0, 0, 0, 0.35)",
                      color: "var(--text-main)",
                      fontSize: "12px",
                      minHeight: "80px",
                      resize: "vertical"
                    }}
                  />
                ) : (
                  <div style={{ padding: "10px 12px", background: "rgba(0,0,0,0.2)", borderRadius: "8px", border: "1px solid var(--glass-border)", fontSize: "12px", color: "var(--text-muted)", whiteSpace: "pre-wrap" }}>
                    {issue.pirLessonsLearned || "No lessons learned recorded."}
                  </div>
                )}
              </div>

              {isEditable && (
                <div style={{ display: "flex", justifyContent: "flex-end" }}>
                  <button
                    onClick={handleSaveDraft}
                    style={{
                      padding: "8px 16px",
                      background: "rgba(0,0,0,0.25)",
                      color: "var(--text-main)",
                      border: "1px solid var(--glass-border)",
                      borderRadius: "8px",
                      fontSize: "12px",
                      fontWeight: "600",
                      cursor: "pointer"
                    }}
                  >
                    💾 Save Draft
                  </button>
                </div>
              )}
            </div>
          )}

          {/* Tab 2: Existing Action Items & Add Action Item */}
          {activeTab === "actionItems" && (
            <div>
              {/* List */}
              {issue.pirActionItems && issue.pirActionItems.length > 0 ? (
                <div style={{ display: "grid", gap: "8px", marginBottom: "12px" }}>
                  {issue.pirActionItems.map(item => {
                    const canCheckOff = item.status === "open" && (item.owner === currentUid || isOwner);
                    return (
                      <div key={item.id} style={{
                        padding: "10px 12px",
                        background: item.status === "completed" ? "rgba(16,185,129,0.06)" : "rgba(0,0,0,0.2)",
                        borderRadius: "8px",
                        border: "1px solid var(--glass-border)",
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                        borderLeft: `4px solid ${item.priority === "high" ? "var(--danger)" : item.priority === "medium" ? "var(--warning)" : "var(--primary)"}`
                      }}>
                        <div>
                          <div style={{ fontSize: "12px", fontWeight: "bold", color: "var(--text-main)" }}>{item.description}</div>
                          <div style={{ fontSize: "10px", color: "var(--text-muted)", marginTop: "3px" }}>
                            Owner: {getAnalystDisplayLabel(item.owner, usersData)} • Due: {item.dueDate} • Priority: {item.priority.toUpperCase()}
                          </div>
                        </div>
                        <div>
                          {item.status === "completed" ? (
                            <span style={{ color: "var(--success)", fontSize: "11px", fontWeight: "bold" }}>✔ Completed</span>
                          ) : canCheckOff ? (
                            <button
                              onClick={() => handleCompleteActionItem(item.id)}
                              style={{
                                padding: "4px 8px",
                                background: "var(--success)",
                                color: "#fff",
                                border: "none",
                                borderRadius: "6px",
                                fontSize: "10px",
                                fontWeight: "bold",
                                cursor: "pointer"
                              }}
                            >
                              Mark Done
                            </button>
                          ) : (
                            <span style={{ color: "var(--warning)", fontSize: "11px" }}>⏳ Pending</span>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div style={{ fontSize: "11px", color: "var(--text-muted)", marginBottom: "10px" }}>No action items created yet.</div>
              )}

              {/* Creator Form */}
              {isEditable && (
                <form onSubmit={handleAddActionItem} style={{
                  background: "rgba(0,0,0,0.18)",
                  border: "1px solid var(--glass-border)",
                  padding: "12px",
                  borderRadius: "8px",
                  display: "grid",
                  gap: "8px"
                }}>
                  <div style={{ fontSize: "11px", fontWeight: "bold", color: "var(--text-muted)" }}>Add New Action Item</div>
                  <input
                    type="text"
                    placeholder="Task description..."
                    value={actionDesc}
                    onChange={(e) => setActionDesc(e.target.value)}
                    style={{
                      padding: "6px 12px",
                      borderRadius: "6px",
                      border: "1px solid var(--glass-border)",
                      background: "rgba(0,0,0,0.35)",
                      color: "var(--text-main)",
                      fontSize: "11px"
                    }}
                  />
                  <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
                    <select
                      value={actionOwner}
                      onChange={(e) => setActionOwner(e.target.value)}
                      style={{
                        flex: 2,
                        minWidth: "180px",
                        padding: "8px 10px",
                        borderRadius: "6px",
                        border: "1px solid var(--glass-border)",
                        background: "rgba(0,0,0,0.35)",
                        color: "var(--text-main)",
                        fontSize: "12px"
                      }}
                    >
                      <option value="">Assignee...</option>
                      {Object.entries(usersData)
                        .filter(([uid, u]) => eligiblePIRRoles.includes(getCanonicalUserRole(u)))
                        .map(([uid, u]) => (
                          <option key={uid} value={uid}>
                            {u.displayName || u.email}
                          </option>
                        ))}
                    </select>
                    <select
                      value={actionPriority}
                      onChange={(e) => setActionPriority(e.target.value)}
                      style={{
                        padding: "6px",
                        borderRadius: "6px",
                        border: "1px solid var(--glass-border)",
                        background: "rgba(0,0,0,0.35)",
                        color: "var(--text-main)",
                        fontSize: "11px"
                      }}
                    >
                      <option value="low">Low</option>
                      <option value="medium">Medium</option>
                      <option value="high">High</option>
                    </select>
                    <input
                      type="date"
                      value={actionDueDate}
                      onChange={(e) => setActionDueDate(e.target.value)}
                      style={{
                        padding: "5px 8px",
                        borderRadius: "6px",
                        border: "1px solid var(--glass-border)",
                        background: "rgba(0,0,0,0.35)",
                        color: "var(--text-main)",
                        fontSize: "11px"
                      }}
                    />
                  </div>
                  <button
                    type="submit"
                    style={{
                      background: "var(--primary)",
                      color: "#fff",
                      border: "none",
                      padding: "8px",
                      borderRadius: "6px",
                      fontSize: "11px",
                      fontWeight: "bold",
                      cursor: "pointer"
                    }}
                  >
                    ➕ Add Item
                  </button>
                </form>
              )}
            </div>
          )}

          {/* Tab 3: Recommend RCA & Complete PIR Review */}
          {activeTab === "complete" && (
            <div>
              {isEditable ? (
                <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
                  {isOwner ? (
                    <>
                      <label style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: "12px", color: "var(--text-main)", cursor: "pointer" }}>
                        <input
                          type="checkbox"
                          checked={recommendRCA}
                          onChange={(e) => setRecommendRCA(e.target.checked)}
                          style={{ cursor: "pointer" }}
                        />
                        🚨 Recommend Root Cause Analysis (RCA)
                      </label>
                      <button
                        onClick={handleCompletePIR}
                        style={{
                          padding: "10px 16px",
                          background: "var(--success)",
                          color: "#fff",
                          border: "none",
                          borderRadius: "8px",
                          fontSize: "12px",
                          fontWeight: "bold",
                          cursor: "pointer"
                        }}
                      >
                        ✔ Complete PIR Review
                      </button>
                    </>
                  ) : (
                    <span style={{ fontSize: "12px", color: "var(--text-muted)" }}>⏳ Only the PIR Owner can complete and sign-off this review.</span>
                  )}
                </div>
              ) : (
                <div style={{ padding: "12px", background: "rgba(16,185,129,0.06)", border: "1px solid rgba(16,185,129,0.15)", borderRadius: "8px", fontSize: "12px", color: "var(--success)", display: "flex", flexDirection: "column", gap: "6px" }}>
                  <span>✔ PIR Review Completed by Owner.</span>
                  {issue.recommendRCA && <span>🚨 RCA Recommended.</span>}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// 🔍 Root Cause Analysis Workspace Sub-Component
const RCA_FACTOR_CATEGORIES = ["People", "Process", "Technology", "Configuration", "Policy"];
const eligibleRCARoles = ["soc_manager", "soc_l2", "ir", "threat_hunter", "admin"];

function RCAWorkspacePanel({ issue, usersData, normalizedRole, getAnalystDisplayLabel, setToast }) {
  const currentUid = auth.currentUser?.uid;
  const isOwner = issue.rcaOwner === currentUid;
  const isContributor = issue.rcaContributors && issue.rcaContributors.includes(currentUid);
  const isManager = normalizedRole === "soc_manager" || normalizedRole === "admin";

  const showRCA = issue.rcaTagged === true && (isOwner || isContributor || isManager);
  if (!showRCA) return null;

  const [activeTab, setActiveTab] = useState("rootcause");
  const [localRootCause, setLocalRootCause] = useState(issue.rootCause || "");
  const [localTechnicalAnalysis, setLocalTechnicalAnalysis] = useState(issue.technicalAnalysis || "");
  const [localFactors, setLocalFactors] = useState(issue.contributingFactors || []);

  // Contributing factor form state
  const [newFactor, setNewFactor] = useState("");
  const [newFactorCategory, setNewFactorCategory] = useState("Technology");

  // Preventive action form state
  const [paDesc, setPaDesc] = useState("");
  const [paOwner, setPaOwner] = useState("");
  const [paPriority, setPaPriority] = useState("medium");
  const [paDueDate, setPaDueDate] = useState("");

  // Sync state if issue updates in background
  useEffect(() => {
    setLocalRootCause(issue.rootCause || "");
    setLocalTechnicalAnalysis(issue.technicalAnalysis || "");
    setLocalFactors(issue.contributingFactors || []);
  }, [issue.rootCause, issue.technicalAnalysis, issue.contributingFactors]);

  const isEditable = issue.rcaStatus === "in_progress" && !issue.rcaApproved;
  const isApproved = !!issue.rcaApproved;

  const handleStartRCA = async () => {
    try {
      await callGovernanceAction(issue.id, "START_RCA", { callerRole: normalizedRole });
      appendLifecycleEvent(issue.id, TIMELINE_EVENTS.RCA_STARTED, normalizedRole || "analyst");
      logGovernanceAudit(issue.id, AUDIT_ACTIONS.RCA_STARTED, normalizedRole || "analyst");
      setToast("📝 RCA started");
    } catch (err) {
      alert("Failed to start RCA: " + err.message);
    }
  };

  const handleSaveDraft = async () => {
    try {
      await updateDoc(doc(db, "issues", issue.id), {
        rootCause: localRootCause,
        technicalAnalysis: localTechnicalAnalysis,
        contributingFactors: localFactors,
        updatedAt: serverTimestamp()
      });
      setToast("💾 RCA draft saved successfully");
    } catch (err) {
      alert("Failed to save RCA draft: " + err.message);
    }
  };

  const handleAddFactor = () => {
    if (!newFactor.trim()) { alert("Factor description is required."); return; }
    setLocalFactors([...localFactors, { factor: newFactor.trim(), category: newFactorCategory }]);
    setNewFactor("");
  };

  const handleRemoveFactor = (index) => {
    setLocalFactors(localFactors.filter((_, i) => i !== index));
  };

  const handleCompleteRCA = async () => {
    if (!localRootCause.trim()) {
      alert("Root Cause is required to complete the RCA.");
      return;
    }
    try {
      await callGovernanceAction(issue.id, "COMPLETE_RCA", {
        rootCause: localRootCause,
        contributingFactors: localFactors,
        technicalAnalysis: localTechnicalAnalysis,
        callerRole: normalizedRole
      });
      appendLifecycleEvent(issue.id, TIMELINE_EVENTS.ROOT_CAUSE_IDENTIFIED, normalizedRole || "analyst", {
        rootCause: localRootCause.substring(0, 100)
      });
      appendLifecycleEvent(issue.id, TIMELINE_EVENTS.RCA_COMPLETED, normalizedRole || "analyst");
      logGovernanceAudit(issue.id, AUDIT_ACTIONS.ROOT_CAUSE_IDENTIFIED, normalizedRole || "analyst", {
        rootCause: localRootCause.substring(0, 100)
      });
      logGovernanceAudit(issue.id, AUDIT_ACTIONS.RCA_COMPLETED, normalizedRole || "analyst");
      setToast("✅ RCA completed successfully");
    } catch (err) {
      alert("Failed to complete RCA: " + err.message);
    }
  };

  const handleAddPreventiveAction = async (e) => {
    e.preventDefault();
    if (!paDesc.trim() || !paOwner || !paDueDate) {
      alert("Please fill in all preventive action fields.");
      return;
    }
    try {
      await callGovernanceAction(issue.id, "ADD_RCA_PREVENTIVE_ACTION", {
        description: paDesc,
        owner: paOwner,
        dueDate: paDueDate,
        priority: paPriority
      });
      setPaDesc("");
      setPaOwner("");
      setPaPriority("medium");
      setPaDueDate("");
      setToast("➕ Preventive action added");
    } catch (err) {
      alert("Failed to add preventive action: " + err.message);
    }
  };

  const handleCompletePreventiveAction = async (itemId) => {
    try {
      await callGovernanceAction(issue.id, "COMPLETE_RCA_PREVENTIVE_ACTION", {
        actionItemId: itemId
      });
      setToast("✔ Preventive action marked completed");
    } catch (err) {
      alert("Failed to complete preventive action: " + err.message);
    }
  };

  const inputStyle = {
    width: "100%",
    padding: "8px 10px",
    borderRadius: "6px",
    border: "1px solid var(--glass-border)",
    background: "rgba(0,0,0,0.35)",
    color: "var(--text-main)",
    fontSize: "12px",
    resize: "vertical"
  };

  const tabBtnStyle = (tabName) => ({
    background: "none",
    border: "none",
    borderBottom: activeTab === tabName ? "2px solid var(--primary)" : "2px solid transparent",
    color: activeTab === tabName ? "var(--text-main)" : "var(--text-muted)",
    padding: "6px 4px",
    fontSize: "12px",
    fontWeight: "bold",
    cursor: "pointer",
    outline: "none"
  });

  return (
    <div style={{
      marginTop: "12px",
      padding: "16px",
      background: "var(--glass-bg)",
      border: "1px solid var(--glass-border)",
      borderRadius: "12px",
      boxShadow: "var(--glass-shadow)",
      borderLeft: `4px solid ${isApproved ? "var(--success)" : issue.rcaStatus === "completed" ? "#f59e0b" : "var(--primary)"}`,
      textAlign: "left"
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px", flexWrap: "wrap", gap: "6px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <h4 style={{ color: "var(--text-main)", margin: 0, fontSize: "14px" }}>🔍 Root Cause Analysis (RCA) Workspace</h4>
          {issue.recommendRCA && (
            <span style={{
              background: "rgba(239,68,68,0.15)",
              color: "var(--danger)",
              fontSize: "9px",
              padding: "2px 8px",
              borderRadius: "12px",
              fontWeight: "bold"
            }}>
              🚨 Recommended by PIR
            </span>
          )}
        </div>
        <span style={{
          background: isApproved ? "var(--success)" :
            issue.rcaStatus === "completed" ? "#f59e0b" :
              issue.rcaStatus === "in_progress" ? "var(--primary)" :
                issue.rcaStatus === "assigned" ? "var(--warning)" : "var(--text-muted)",
          color: "#fff",
          fontSize: "10px",
          padding: "2px 8px",
          borderRadius: "12px",
          fontWeight: "bold"
        }}>
          Status: {issue.rcaStatus ? issue.rcaStatus.toUpperCase() : "PENDING"} {isApproved ? "(APPROVED)" : ""}
        </span>
      </div>

      <div style={{ marginBottom: "10px", fontSize: "12px", color: "var(--text-muted)", display: "flex", flexDirection: "column", gap: "2px" }}>
        <div><strong>RCA Owner:</strong> <span style={{ color: "var(--text-main)" }}>{issue.rcaOwner ? getAnalystDisplayLabel(issue.rcaOwner, usersData) : "Not Assigned"}</span></div>
        <div>
          <strong>Contributors:</strong> <span style={{ color: "var(--text-main)" }}>{issue.rcaContributors && issue.rcaContributors.length > 0
            ? issue.rcaContributors.map(uid => getAnalystDisplayLabel(uid, usersData)).join(", ")
            : "None"}</span>
        </div>
      </div>

      {/* State 1: Assigned (Waiting to start) */}
      {issue.rcaStatus === "assigned" && (
        <div style={{ marginTop: "8px", textAlign: "center", padding: "12px", background: "rgba(0,0,0,0.2)", borderRadius: "8px", border: "1px solid var(--glass-border)" }}>
          {isOwner ? (
            <button
              onClick={handleStartRCA}
              style={{
                padding: "8px 16px",
                background: "var(--primary)",
                color: "#fff",
                border: "none",
                borderRadius: "8px",
                fontWeight: "bold",
                cursor: "pointer",
                boxShadow: "0 0 10px rgba(6,182,212,0.2)"
              }}
            >
              ▶ Start RCA
            </button>
          ) : (
            <span style={{ fontSize: "12px", color: "var(--text-muted)" }}>⏳ Awaiting RCA Owner to start the analysis.</span>
          )}
        </div>
      )}

      {/* State 2 & 3: In Progress / Completed */}
      {(issue.rcaStatus === "in_progress" || issue.rcaStatus === "completed") && (
        <div style={{ marginTop: "10px" }}>
          {/* Tab Navigation */}
          <div style={{ display: "flex", borderBottom: "1px solid var(--glass-border)", marginBottom: "12px", gap: "16px" }}>
            <button onClick={() => setActiveTab("rootcause")} style={tabBtnStyle("rootcause")}>
              🎯 Root Cause & Analysis
            </button>
            <button onClick={() => setActiveTab("factors")} style={tabBtnStyle("factors")}>
              📊 Factors & Actions
            </button>
            {!isApproved && (
              <button onClick={() => setActiveTab("complete")} style={tabBtnStyle("complete")}>
                ✔ Complete RCA
              </button>
            )}
          </div>

          {/* Tab 1: Root Cause & Technical Analysis */}
          {activeTab === "rootcause" && (
            <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
              <div>
                <label style={{ fontSize: "11px", color: "var(--text-muted)", display: "block", marginBottom: "4px", fontWeight: "bold" }}>Root Cause</label>
                {isEditable && (isOwner || isContributor) ? (
                  <textarea
                    value={localRootCause}
                    onChange={(e) => setLocalRootCause(e.target.value)}
                    rows={4}
                    placeholder="Describe the root cause of the incident..."
                    style={inputStyle}
                  />
                ) : (
                  <div style={{ padding: "8px 10px", background: "rgba(0,0,0,0.2)", borderRadius: "6px", border: "1px solid var(--glass-border)", fontSize: "12px", color: "var(--text-muted)", whiteSpace: "pre-wrap" }}>
                    {issue.rootCause || "Not documented yet."}
                  </div>
                )}
              </div>
              <div>
                <label style={{ fontSize: "11px", color: "var(--text-muted)", display: "block", marginBottom: "4px", fontWeight: "bold" }}>Technical Analysis</label>
                {isEditable && (isOwner || isContributor) ? (
                  <textarea
                    value={localTechnicalAnalysis}
                    onChange={(e) => setLocalTechnicalAnalysis(e.target.value)}
                    rows={4}
                    placeholder="Detailed technical analysis of what happened..."
                    style={inputStyle}
                  />
                ) : (
                  <div style={{ padding: "8px 10px", background: "rgba(0,0,0,0.2)", borderRadius: "6px", border: "1px solid var(--glass-border)", fontSize: "12px", color: "var(--text-muted)", whiteSpace: "pre-wrap" }}>
                    {issue.technicalAnalysis || "Not documented yet."}
                  </div>
                )}
              </div>
              {isEditable && (isOwner || isContributor) && (
                <button
                  onClick={handleSaveDraft}
                  style={{
                    padding: "8px 16px",
                    background: "var(--primary)",
                    color: "#fff",
                    border: "none",
                    borderRadius: "8px",
                    fontSize: "12px",
                    fontWeight: "bold",
                    cursor: "pointer",
                    alignSelf: "flex-start"
                  }}
                >
                  💾 Save Draft
                </button>
              )}
            </div>
          )}

          {/* Tab 2: Contributing Factors & Preventive Actions */}
          {activeTab === "factors" && (
            <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
              {/* Contributing Factors Section */}
              <div>
                <label style={{ fontSize: "11px", color: "var(--text-muted)", display: "block", marginBottom: "6px", fontWeight: "bold" }}>Contributing Factors</label>
                {localFactors.length > 0 && (
                  <div style={{ display: "flex", flexDirection: "column", gap: "4px", marginBottom: "8px" }}>
                    {localFactors.map((cf, i) => (
                      <div key={i} style={{
                        display: "flex",
                        gap: "8px",
                        alignItems: "center",
                        padding: "6px 8px",
                        background: "rgba(0,0,0,0.2)",
                        borderRadius: "6px",
                        border: "1px solid var(--glass-border)"
                      }}>
                        <span style={{
                          fontSize: "9px",
                          padding: "1px 6px",
                          borderRadius: "4px",
                          background: "rgba(6,182,212,0.15)",
                          color: "var(--primary)",
                          fontWeight: "bold",
                          whiteSpace: "nowrap"
                        }}>
                          {cf.category}
                        </span>
                        <span style={{ color: "var(--text-main)", fontSize: "12px", flex: 1 }}>{cf.factor}</span>
                        {isEditable && !isApproved && (isOwner || isContributor) && (
                          <button
                            onClick={() => handleRemoveFactor(i)}
                            style={{
                              background: "rgba(239,68,68,0.15)",
                              color: "var(--danger)",
                              border: "none",
                              borderRadius: "4px",
                              fontSize: "10px",
                              padding: "2px 6px",
                              cursor: "pointer"
                            }}
                          >
                            ✕
                          </button>
                        )}
                      </div>
                    ))}
                  </div>
                )}

                {isEditable && !isApproved && (isOwner || isContributor) && (
                  <div style={{ display: "flex", gap: "6px", alignItems: "center", flexWrap: "wrap" }}>
                    <input
                      type="text"
                      value={newFactor}
                      onChange={(e) => setNewFactor(e.target.value)}
                      placeholder="Contributing factor..."
                      style={{ ...inputStyle, flex: 2, minWidth: "160px", width: "auto" }}
                    />
                    <select
                      value={newFactorCategory}
                      onChange={(e) => setNewFactorCategory(e.target.value)}
                      style={{
                        padding: "8px 10px",
                        borderRadius: "6px",
                        border: "1px solid var(--glass-border)",
                        background: "rgba(0,0,0,0.35)",
                        color: "var(--text-main)",
                        fontSize: "12px"
                      }}
                    >
                      {RCA_FACTOR_CATEGORIES.map(cat => (
                        <option key={cat} value={cat}>{cat}</option>
                      ))}
                    </select>
                    <button
                      onClick={handleAddFactor}
                      style={{
                        padding: "8px 12px",
                        background: "var(--primary)",
                        color: "#fff",
                        border: "none",
                        borderRadius: "6px",
                        fontSize: "11px",
                        fontWeight: "600",
                        cursor: "pointer",
                        whiteSpace: "nowrap"
                      }}
                    >
                      ➕ Add Factor
                    </button>
                  </div>
                )}

                {isEditable && !isApproved && localFactors.length > 0 && (isOwner || isContributor) && (
                  <button
                    onClick={handleSaveDraft}
                    style={{
                      marginTop: "8px",
                      padding: "6px 12px",
                      background: "var(--primary)",
                      color: "#fff",
                      border: "none",
                      borderRadius: "6px",
                      fontSize: "11px",
                      fontWeight: "600",
                      cursor: "pointer",
                      alignSelf: "flex-start"
                    }}
                  >
                    💾 Save Factors
                  </button>
                )}
              </div>

              {/* Preventive Actions Section */}
              <div>
                <label style={{ fontSize: "11px", color: "var(--text-muted)", display: "block", marginBottom: "6px", fontWeight: "bold" }}>Preventive Actions</label>

                {/* Existing actions list */}
                {issue.rcaPreventiveActions && issue.rcaPreventiveActions.length > 0 && (
                  <div style={{ display: "grid", gap: "6px", marginBottom: "10px" }}>
                    {issue.rcaPreventiveActions.map(item => (
                      <div key={item.id} style={{
                        padding: "8px 10px",
                        background: item.status === "completed" ? "rgba(16,185,129,0.06)" : "rgba(0, 0, 0, 0.2)",
                        borderRadius: "8px",
                        border: "1px solid var(--glass-border)",
                        borderLeft: `4px solid ${item.priority === "high" ? "var(--danger)" : item.priority === "medium" ? "var(--warning)" : "var(--primary)"}`
                      }}>
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                          <strong style={{ color: "var(--text-main)", fontSize: "12px" }}>{item.description}</strong>
                          <div style={{ display: "flex", gap: "6px", alignItems: "center" }}>
                            <span style={{
                              fontSize: "10px",
                              padding: "1px 6px",
                              borderRadius: "4px",
                              background: item.priority === "high" ? "rgba(239,68,68,0.15)" : item.priority === "medium" ? "rgba(245,158,11,0.15)" : "rgba(6,182,212,0.15)",
                              color: item.priority === "high" ? "var(--danger)" : item.priority === "medium" ? "var(--warning)" : "var(--primary)",
                              fontWeight: "bold"
                            }}>
                              {item.priority.toUpperCase()}
                            </span>
                            {item.status !== "completed" && !isApproved && (isOwner || isManager) && (
                              <button
                                onClick={() => handleCompletePreventiveAction(item.id)}
                                style={{
                                  background: "var(--success)",
                                  color: "#fff",
                                  border: "none",
                                  borderRadius: "4px",
                                  fontSize: "10px",
                                  padding: "2px 6px",
                                  cursor: "pointer"
                                }}
                              >
                                ✔ Done
                              </button>
                            )}
                          </div>
                        </div>
                        <div style={{ fontSize: "10px", color: "var(--text-muted)", marginTop: "4px" }}>
                          Owner: {getAnalystDisplayLabel(item.owner, usersData)} • Due: {item.dueDate} • Status: <strong style={{ color: item.status === "completed" ? "var(--success)" : "var(--warning)" }}>{item.status.toUpperCase()}</strong>
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                {/* Add new preventive action form */}
                {!isApproved && (isOwner || isContributor || isManager) && (
                  <form onSubmit={handleAddPreventiveAction} style={{
                    display: "flex",
                    flexDirection: "column",
                    gap: "8px",
                    padding: "10px",
                    background: "rgba(0,0,0,0.15)",
                    borderRadius: "8px",
                    border: "1px solid var(--glass-border)"
                  }}>
                    <input
                      type="text"
                      value={paDesc}
                      onChange={(e) => setPaDesc(e.target.value)}
                      placeholder="Preventive action description..."
                      style={{ ...inputStyle, fontSize: "11px" }}
                    />
                    <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
                      <select
                        value={paOwner}
                        onChange={(e) => setPaOwner(e.target.value)}
                        style={{
                          flex: 2,
                          minWidth: "180px",
                          padding: "8px 10px",
                          borderRadius: "6px",
                          border: "1px solid var(--glass-border)",
                          background: "rgba(0,0,0,0.35)",
                          color: "var(--text-main)",
                          fontSize: "12px"
                        }}
                      >
                        <option value="">Assignee...</option>
                        {Object.entries(usersData)
                          .filter(([uid, u]) => eligibleRCARoles.includes(getCanonicalUserRole(u)))
                          .map(([uid, u]) => (
                            <option key={uid} value={uid}>
                              {u.displayName || u.email}
                            </option>
                          ))}
                      </select>
                      <select
                        value={paPriority}
                        onChange={(e) => setPaPriority(e.target.value)}
                        style={{
                          padding: "8px 10px",
                          borderRadius: "6px",
                          border: "1px solid var(--glass-border)",
                          background: "rgba(0,0,0,0.35)",
                          color: "var(--text-main)",
                          fontSize: "12px"
                        }}
                      >
                        <option value="low">Low</option>
                        <option value="medium">Medium</option>
                        <option value="high">High</option>
                      </select>
                      <input
                        type="date"
                        value={paDueDate}
                        onChange={(e) => setPaDueDate(e.target.value)}
                        style={{
                          padding: "8px 10px",
                          borderRadius: "6px",
                          border: "1px solid var(--glass-border)",
                          background: "rgba(0,0,0,0.35)",
                          color: "var(--text-main)",
                          fontSize: "11px"
                        }}
                      />
                    </div>
                    <button
                      type="submit"
                      style={{
                        padding: "8px 12px",
                        background: "var(--primary)",
                        color: "#fff",
                        border: "none",
                        borderRadius: "6px",
                        fontSize: "11px",
                        fontWeight: "600",
                        cursor: "pointer",
                        alignSelf: "flex-start"
                      }}
                    >
                      ➕ Add Action
                    </button>
                  </form>
                )}
              </div>
            </div>
          )}

          {/* Tab 3: Complete RCA */}
          {activeTab === "complete" && (
            <div>
              {isEditable ? (
                <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
                  {isOwner ? (
                    <button
                      onClick={handleCompleteRCA}
                      style={{
                        padding: "10px 16px",
                        background: "var(--success)",
                        color: "#fff",
                        border: "none",
                        borderRadius: "8px",
                        fontSize: "12px",
                        fontWeight: "bold",
                        cursor: "pointer"
                      }}
                    >
                      ✔ Complete RCA
                    </button>
                  ) : (
                    <span style={{ fontSize: "12px", color: "var(--text-muted)" }}>⏳ Only the RCA Owner can complete and sign-off this analysis.</span>
                  )}
                </div>
              ) : (
                <div style={{ padding: "12px", background: "rgba(16,185,129,0.06)", border: "1px solid rgba(16,185,129,0.15)", borderRadius: "8px", fontSize: "12px", color: "var(--success)", display: "flex", flexDirection: "column", gap: "6px" }}>
                  <span>✔ RCA Completed by Owner.</span>
                  {isApproved && <span>✔ Approved by Manager.</span>}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// 🕵️ Threat Hunting Workspace Sub-Component
function ThreatHuntWorkspacePanel({ issue, usersData, normalizedRole, getAnalystDisplayLabel, setToast }) {
  const currentUid = auth.currentUser?.uid;
  const isHunter = normalizedRole === "threat_hunter";
  const isManager = normalizedRole === "soc_manager" || normalizedRole === "admin";
  const isAuthorized = isHunter || isManager;

  const showHunt = isAuthorized && (
    issue.status === "threat_hunt" ||
    issue.huntStatus === "in_progress" ||
    issue.huntStatus === "submitted" ||
    issue.huntStatus === "approved" ||
    issue.huntStatus === "completed"
  );
  if (!showHunt) return null;

  const isEditable = issue.huntStatus === "in_progress";
  const isSubmitted = issue.huntStatus === "submitted";
  const isApproved = issue.huntStatus === "approved" || issue.huntStatus === "completed";

  const [activeTab, setActiveTab] = useState("details");
  const [localNotes, setLocalNotes] = useState(issue.huntNotes || "");
  const [localFindings, setLocalFindings] = useState(issue.huntFindings || "");
  const [localRecommendation, setLocalRecommendation] = useState(issue.huntRecommendation || "");

  const [newTechId, setNewTechId] = useState("");
  const [newTechName, setNewTechName] = useState("");
  const [completeOption, setCompleteOption] = useState(issue.huntCompleteOption || "return_l2");
  const [rejectionReason, setRejectionReason] = useState("");
  const [showRejectionForm, setShowRejectionForm] = useState(false);

  // Sync state if issue updates in background
  useEffect(() => {
    setLocalNotes(issue.huntNotes || "");
    setLocalFindings(issue.huntFindings || "");
    setLocalRecommendation(issue.huntRecommendation || "");
    if (issue.huntCompleteOption) {
      setCompleteOption(issue.huntCompleteOption);
    }
  }, [issue.huntNotes, issue.huntFindings, issue.huntRecommendation, issue.huntCompleteOption]);

  const handleStartHunt = async () => {
    try {
      await callGovernanceAction(issue.id, "START_HUNT", { callerRole: normalizedRole });
      appendLifecycleEvent(issue.id, TIMELINE_EVENTS.THREAT_HUNT_STARTED, normalizedRole || "analyst");
      logGovernanceAudit(issue.id, AUDIT_ACTIONS.THREAT_HUNT_STARTED, normalizedRole || "analyst");
      setToast("🕵️ Threat Hunt started");
    } catch (err) {
      alert("Failed to start Threat Hunt: " + err.message);
    }
  };

  const handleSaveDraft = async () => {
    try {
      await callGovernanceAction(issue.id, "SAVE_HUNT_DRAFT", {
        notes: localNotes,
        findings: localFindings,
        recommendation: localRecommendation,
        callerRole: normalizedRole
      });
      setToast("💾 Threat Hunt draft saved");
    } catch (err) {
      alert("Failed to save draft: " + err.message);
    }
  };

  const handleMapTechnique = async (e) => {
    e.preventDefault();
    if (!newTechId.trim() || !newTechName.trim()) {
      alert("Technique ID and Name are required");
      return;
    }
    try {
      await callGovernanceAction(issue.id, "MAP_ATTACK_TECHNIQUE", {
        techniqueId: newTechId.trim(),
        techniqueName: newTechName.trim(),
        callerRole: normalizedRole
      });
      appendLifecycleEvent(issue.id, TIMELINE_EVENTS.ATTACK_TECHNIQUE_MAPPED, normalizedRole || "analyst", {
        metadata: { techniqueId: newTechId.trim(), techniqueName: newTechName.trim() }
      });
      logGovernanceAudit(issue.id, AUDIT_ACTIONS.ATTACK_TECHNIQUE_MAPPED, normalizedRole || "analyst", {
        techniqueId: newTechId.trim(),
        techniqueName: newTechName.trim()
      });
      setNewTechId("");
      setNewTechName("");
      setToast("🎯 MITRE ATT&CK technique mapped");
    } catch (err) {
      alert("Failed to map technique: " + err.message);
    }
  };

  const handleUnmapTechnique = async (techId) => {
    try {
      await callGovernanceAction(issue.id, "UNMAP_ATTACK_TECHNIQUE", {
        techniqueId: techId,
        callerRole: normalizedRole
      });
      setToast("❌ MITRE ATT&CK technique unmapped");
    } catch (err) {
      alert("Failed to unmap technique: " + err.message);
    }
  };

  const handleSubmitHunt = async () => {
    if (!localNotes.trim() || !localFindings.trim() || !localRecommendation.trim()) {
      alert("Notes, Findings, and Recommendation are required to submit the hunt.");
      return;
    }
    try {
      appendLifecycleEvent(issue.id, TIMELINE_EVENTS.HUNT_RECOMMENDATION_SUBMITTED, normalizedRole || "analyst", {
        metadata: { recommendation: localRecommendation }
      });
      logGovernanceAudit(issue.id, AUDIT_ACTIONS.HUNT_RECOMMENDATION_SUBMITTED, normalizedRole || "analyst", {
        recommendation: localRecommendation
      });

      await callGovernanceAction(issue.id, "SUBMIT_HUNT", {
        option: completeOption,
        notes: localNotes,
        findings: localFindings,
        recommendation: localRecommendation,
        callerRole: normalizedRole
      });

      setToast("📝 Threat Hunt submitted for review");
    } catch (err) {
      alert("Failed to submit Threat Hunt: " + err.message);
    }
  };

  const handleApproveHunt = async () => {
    try {
      await callGovernanceAction(issue.id, "APPROVE_HUNT", {
        callerRole: normalizedRole
      });
      appendLifecycleEvent(issue.id, TIMELINE_EVENTS.THREAT_HUNT_APPROVED, normalizedRole || "soc_manager");
      logGovernanceAudit(issue.id, AUDIT_ACTIONS.THREAT_HUNT_APPROVED, normalizedRole || "soc_manager");

      const option = issue.huntCompleteOption || completeOption;
      if (option === "return_l2") {
        appendLifecycleEvent(issue.id, TIMELINE_EVENTS.THREAT_HUNT_RETURNED, normalizedRole || "soc_manager");
        logGovernanceAudit(issue.id, AUDIT_ACTIONS.THREAT_HUNT_RETURNED, normalizedRole || "soc_manager");
      } else {
        appendLifecycleEvent(issue.id, TIMELINE_EVENTS.THREAT_HUNT_COMPLETED, normalizedRole || "soc_manager");
        logGovernanceAudit(issue.id, AUDIT_ACTIONS.THREAT_HUNT_COMPLETED, normalizedRole || "soc_manager");
      }
      setToast("✔ Threat Hunt approved");
    } catch (err) {
      alert("Failed to approve Threat Hunt: " + err.message);
    }
  };

  const handleRejectHunt = async () => {
    if (!rejectionReason.trim()) {
      alert("A reason is required to reject the Threat Hunt.");
      return;
    }
    try {
      await callGovernanceAction(issue.id, "REJECT_HUNT", {
        reason: rejectionReason,
        callerRole: normalizedRole
      });
      appendLifecycleEvent(issue.id, TIMELINE_EVENTS.THREAT_HUNT_REJECTED, normalizedRole || "soc_manager", {
        reason: rejectionReason
      });
      logGovernanceAudit(issue.id, AUDIT_ACTIONS.THREAT_HUNT_REJECTED, normalizedRole || "soc_manager", {
        reason: rejectionReason
      });
      setRejectionReason("");
      setShowRejectionForm(false);
      setToast("❌ Threat Hunt rejected");
    } catch (err) {
      alert("Failed to reject Threat Hunt: " + err.message);
    }
  };

  const tabStyle = (tabName) => ({
    padding: "6px 12px",
    background: activeTab === tabName ? "var(--primary)" : "transparent",
    color: "#fff",
    border: "none",
    borderRadius: "4px",
    fontSize: "12px",
    fontWeight: "bold",
    cursor: "pointer",
    outline: "none"
  });

  return (
    <div style={{
      marginTop: "12px",
      padding: "16px",
      background: "var(--glass-bg)",
      border: "1px solid var(--glass-border)",
      borderRadius: "12px",
      boxShadow: "var(--glass-shadow)",
      borderLeft: `4px solid ${isApproved ? "var(--success)" : isSubmitted ? "#f59e0b" : "var(--primary)"}`,
      textAlign: "left"
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px", flexWrap: "wrap", gap: "6px" }}>
        <h4 style={{ color: "var(--text-main)", margin: 0, fontSize: "14px" }}>🕵️ Threat Hunting Workspace</h4>
        <span style={{
          background: isApproved ? "var(--success)" : isSubmitted ? "#f59e0b" : "var(--primary)",
          color: "#fff",
          fontSize: "10px",
          padding: "2px 8px",
          borderRadius: "12px",
          fontWeight: "bold"
        }}>
          {issue.huntStatus ? issue.huntStatus.toUpperCase() : "PENDING"}
        </span>
      </div>

      {issue.huntRejectionReason && isEditable && (
        <div style={{
          marginBottom: "12px",
          padding: "10px",
          background: "rgba(239, 68, 68, 0.1)",
          border: "1px solid rgba(239, 68, 68, 0.3)",
          borderRadius: "6px",
          fontSize: "12px",
          color: "var(--danger)"
        }}>
          <strong>❌ Threat Hunt Rejected:</strong> {issue.huntRejectionReason}
        </div>
      )}

      {(!issue.huntStatus || issue.huntStatus === "pending") ? (
        <div style={{ display: "flex", flexDirection: "column", gap: "10px", alignItems: "flex-start" }}>
          <p style={{ margin: 0, fontSize: "12px", color: "var(--text-muted)" }}>
            Incident is tagged for proactive Threat Hunting. Start the hunt to begin logging notes, mapping ATT&CK techniques, and submitting recommendations.
          </p>
          <button
            onClick={handleStartHunt}
            style={{
              padding: "8px 14px",
              background: "var(--primary)",
              color: "#fff",
              border: "none",
              borderRadius: "6px",
              fontSize: "12px",
              fontWeight: "600",
              cursor: "pointer"
            }}
          >
            🕵️ Start Threat Hunt
          </button>
        </div>
      ) : (
        <div>
          {/* Tabs */}
          <div style={{ display: "flex", gap: "6px", borderBottom: "1px solid var(--glass-border)", paddingBottom: "8px", marginBottom: "12px" }}>
            <button onClick={() => setActiveTab("details")} style={tabStyle("details")}>Notes & Findings</button>
            <button onClick={() => setActiveTab("attack")} style={tabStyle("attack")}>MITRE ATT&CK</button>
            <button onClick={() => setActiveTab("complete")} style={tabStyle("complete")}>Complete & Review</button>
          </div>

          {/* Tab 1: Notes & Findings */}
          {activeTab === "details" && (
            <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
              <div>
                <label style={{ display: "block", fontSize: "11px", fontWeight: "bold", color: "var(--text-main)", marginBottom: "4px" }}>Hunt Notes</label>
                <textarea
                  placeholder="Record investigation notes, observed indicators, and analysis..."
                  value={localNotes}
                  onChange={(e) => setLocalNotes(e.target.value)}
                  disabled={!isEditable}
                  style={{
                    width: "100%",
                    minHeight: "80px",
                    padding: "8px",
                    borderRadius: "6px",
                    border: "1px solid var(--glass-border)",
                    background: "rgba(0,0,0,0.2)",
                    color: "var(--text-main)",
                    fontSize: "12px",
                    resize: "vertical"
                  }}
                />
              </div>
              <div>
                <label style={{ display: "block", fontSize: "11px", fontWeight: "bold", color: "var(--text-main)", marginBottom: "4px" }}>Hunt Findings</label>
                <textarea
                  placeholder="Document threat hunt findings..."
                  value={localFindings}
                  onChange={(e) => setLocalFindings(e.target.value)}
                  disabled={!isEditable}
                  style={{
                    width: "100%",
                    minHeight: "80px",
                    padding: "8px",
                    borderRadius: "6px",
                    border: "1px solid var(--glass-border)",
                    background: "rgba(0,0,0,0.2)",
                    color: "var(--text-main)",
                    fontSize: "12px",
                    resize: "vertical"
                  }}
                />
              </div>
              {isEditable && (
                <button
                  onClick={handleSaveDraft}
                  style={{
                    alignSelf: "flex-start",
                    padding: "8px 12px",
                    background: "var(--secondary)",
                    color: "#fff",
                    border: "none",
                    borderRadius: "6px",
                    fontSize: "11px",
                    fontWeight: "600",
                    cursor: "pointer"
                  }}
                >
                  💾 Save Draft
                </button>
              )}
            </div>
          )}

          {/* Tab 2: MITRE ATT&CK Mapping */}
          {activeTab === "attack" && (
            <div>
              {isEditable && (
                <form onSubmit={handleMapTechnique} style={{ display: "flex", gap: "6px", flexWrap: "wrap", marginBottom: "12px" }}>
                  <input
                    type="text"
                    placeholder="Technique ID (e.g. T1566)"
                    value={newTechId}
                    onChange={(e) => setNewTechId(e.target.value)}
                    style={{
                      flex: 1,
                      minWidth: "120px",
                      padding: "8px 10px",
                      borderRadius: "6px",
                      border: "1px solid var(--glass-border)",
                      background: "rgba(0,0,0,0.35)",
                      color: "var(--text-main)",
                      fontSize: "12px"
                    }}
                  />
                  <input
                    type="text"
                    placeholder="Technique Name (e.g. Phishing)"
                    value={newTechName}
                    onChange={(e) => setNewTechName(e.target.value)}
                    style={{
                      flex: 2,
                      minWidth: "180px",
                      padding: "8px 10px",
                      borderRadius: "6px",
                      border: "1px solid var(--glass-border)",
                      background: "rgba(0,0,0,0.35)",
                      color: "var(--text-main)",
                      fontSize: "12px"
                    }}
                  />
                  <button
                    type="submit"
                    style={{
                      padding: "8px 12px",
                      background: "var(--primary)",
                      color: "#fff",
                      border: "none",
                      borderRadius: "6px",
                      fontSize: "11px",
                      fontWeight: "600",
                      cursor: "pointer"
                    }}
                  >
                    🎯 Map
                  </button>
                </form>
              )}

              <div style={{ marginTop: "10px" }}>
                <h5 style={{ color: "var(--text-main)", margin: "0 0 6px 0", fontSize: "12px" }}>Mapped Techniques</h5>
                {(!issue.attackTechniques || issue.attackTechniques.length === 0) ? (
                  <p style={{ margin: 0, fontSize: "11px", color: "var(--text-muted)" }}>No techniques mapped yet.</p>
                ) : (
                  <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
                    {issue.attackTechniques.map((tech, idx) => (
                      <div key={idx} style={{
                        background: "rgba(63, 81, 181, 0.2)",
                        border: "1px solid rgba(63, 81, 181, 0.4)",
                        borderRadius: "4px",
                        padding: "4px 8px",
                        fontSize: "11px",
                        color: "var(--text-main)",
                        display: "flex",
                        alignItems: "center",
                        gap: "6px"
                      }}>
                        <span style={{ fontWeight: "bold", color: "#7986cb" }}>{tech.techniqueId}</span>
                        <span>{tech.techniqueName}</span>
                        {isEditable && (
                          <button
                            onClick={() => handleUnmapTechnique(tech.techniqueId)}
                            style={{
                              background: "transparent",
                              border: "none",
                              color: "var(--danger)",
                              cursor: "pointer",
                              padding: "0 0 0 6px",
                              fontSize: "12px",
                              fontWeight: "bold",
                              lineHeight: "1"
                            }}
                            title="Remove technique"
                          >
                            ×
                          </button>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Tab 3: Complete & Review */}
          {activeTab === "complete" && (
            <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
              {isApproved && (
                <div style={{ padding: "12px", background: "rgba(16,185,129,0.06)", border: "1px solid rgba(16,185,129,0.15)", borderRadius: "8px", fontSize: "12px", color: "var(--success)" }}>
                  ✔ Threat Hunt Approved by {getAnalystDisplayLabel(issue.huntApprovedBy, usersData)}.
                </div>
              )}

              {isEditable && (
                <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                  <div>
                    <label style={{ display: "block", fontSize: "11px", fontWeight: "bold", color: "var(--text-main)", marginBottom: "4px" }}>Threat Hunter Recommendation</label>
                    <textarea
                      placeholder="e.g. Escalate back to L2 for containment review or No malicious activity identified..."
                      value={localRecommendation}
                      onChange={(e) => setLocalRecommendation(e.target.value)}
                      style={{
                        width: "100%",
                        minHeight: "60px",
                        padding: "8px",
                        borderRadius: "6px",
                        border: "1px solid var(--glass-border)",
                        background: "rgba(0,0,0,0.2)",
                        color: "var(--text-main)",
                        fontSize: "12px",
                        resize: "vertical"
                      }}
                    />
                  </div>

                  <div>
                    <label style={{ display: "block", fontSize: "11px", fontWeight: "bold", color: "var(--text-main)", marginBottom: "4px" }}>Action Option</label>
                    <div style={{ display: "flex", gap: "12px", fontSize: "12px", color: "var(--text-main)" }}>
                      <label style={{ display: "flex", alignItems: "center", gap: "4px", cursor: "pointer" }}>
                        <input
                          type="radio"
                          name="completeOption"
                          value="return_l2"
                          checked={completeOption === "return_l2"}
                          onChange={() => setCompleteOption("return_l2")}
                        />
                        Option A: Return To L2
                      </label>
                      <label style={{ display: "flex", alignItems: "center", gap: "4px", cursor: "pointer" }}>
                        <input
                          type="radio"
                          name="completeOption"
                          value="close"
                          checked={completeOption === "close"}
                          onChange={() => setCompleteOption("close")}
                        />
                        Option B: Close Hunt
                      </label>
                    </div>
                  </div>

                  <button
                    onClick={handleSubmitHunt}
                    style={{
                      alignSelf: "flex-start",
                      padding: "8px 14px",
                      background: "var(--primary)",
                      color: "#fff",
                      border: "none",
                      borderRadius: "6px",
                      fontSize: "12px",
                      fontWeight: "bold",
                      cursor: "pointer"
                    }}
                  >
                    🚀 Submit Threat Hunt
                  </button>
                </div>
              )}

              {isSubmitted && !isManager && (
                <div style={{ padding: "12px", background: "rgba(245,158,11,0.06)", border: "1px solid rgba(245,158,11,0.15)", borderRadius: "8px", fontSize: "12px", color: "var(--warning)" }}>
                  ⏳ Threat Hunt Recommendation Submitted. Awaiting Manager Approval.
                  <div style={{ marginTop: "10px" }}>
                    <strong>Selected Option:</strong> {issue.huntCompleteOption === "return_l2" ? "Option A: Return To L2" : "Option B: Close Hunt"}
                  </div>
                  <div style={{ marginTop: "6px" }}>
                    <strong>Recommendation:</strong>
                    <pre style={{ margin: "4px 0 0 0", padding: "8px", background: "rgba(0,0,0,0.15)", borderRadius: "4px", fontSize: "11px", color: "var(--text-muted)", whiteSpace: "pre-wrap", fontFamily: "inherit" }}>
                      {issue.huntRecommendation || "N/A"}
                    </pre>
                  </div>
                </div>
              )}

              {isSubmitted && isManager && (
                <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                  <div style={{ padding: "12px", background: "rgba(245,158,11,0.06)", border: "1px solid rgba(245,158,11,0.15)", borderRadius: "8px", fontSize: "12px", color: "var(--warning)" }}>
                    📢 <strong>Manager Review Required:</strong> A Threat Hunt recommendation has been submitted.
                  </div>

                  <div style={{ fontSize: "12px", color: "var(--text-main)", display: "flex", flexDirection: "column", gap: "8px" }}>
                    <div>
                      <strong>Proposed Option:</strong> {issue.huntCompleteOption === "return_l2" ? "Option A: Return To L2" : "Option B: Close Hunt"}
                    </div>
                    <div>
                      <strong>Notes:</strong>
                      <pre style={{ margin: "4px 0 0 0", padding: "8px", background: "rgba(0,0,0,0.15)", borderRadius: "4px", fontSize: "11px", color: "var(--text-muted)", whiteSpace: "pre-wrap", fontFamily: "inherit" }}>
                        {issue.huntNotes || "N/A"}
                      </pre>
                    </div>
                    <div>
                      <strong>Findings:</strong>
                      <pre style={{ margin: "4px 0 0 0", padding: "8px", background: "rgba(0,0,0,0.15)", borderRadius: "4px", fontSize: "11px", color: "var(--text-muted)", whiteSpace: "pre-wrap", fontFamily: "inherit" }}>
                        {issue.huntFindings || "N/A"}
                      </pre>
                    </div>
                    <div>
                      <strong>Recommendation:</strong>
                      <pre style={{ margin: "4px 0 0 0", padding: "8px", background: "rgba(0,0,0,0.15)", borderRadius: "4px", fontSize: "11px", color: "var(--text-muted)", whiteSpace: "pre-wrap", fontFamily: "inherit" }}>
                        {issue.huntRecommendation || "N/A"}
                      </pre>
                    </div>
                  </div>

                  {!showRejectionForm ? (
                    <div style={{ display: "flex", gap: "8px", marginTop: "8px" }}>
                      <button
                        onClick={handleApproveHunt}
                        style={{
                          padding: "8px 14px",
                          background: "var(--success)",
                          color: "#fff",
                          border: "none",
                          borderRadius: "6px",
                          fontSize: "12px",
                          fontWeight: "bold",
                          cursor: "pointer"
                        }}
                      >
                        ✔ Approve Hunt
                      </button>
                      <button
                        onClick={() => setShowRejectionForm(true)}
                        style={{
                          padding: "8px 14px",
                          background: "var(--danger)",
                          color: "#fff",
                          border: "none",
                          borderRadius: "6px",
                          fontSize: "12px",
                          fontWeight: "bold",
                          cursor: "pointer"
                        }}
                      >
                        ❌ Reject Hunt
                      </button>
                    </div>
                  ) : (
                    <div style={{ display: "flex", flexDirection: "column", gap: "8px", marginTop: "8px", padding: "10px", background: "rgba(0,0,0,0.15)", borderRadius: "6px", border: "1px solid var(--glass-border)" }}>
                      <label style={{ fontSize: "11px", fontWeight: "bold", color: "var(--text-main)" }}>Rejection Reason (Required)</label>
                      <input
                        type="text"
                        placeholder="Please explain why the hunt is rejected..."
                        value={rejectionReason}
                        onChange={(e) => setRejectionReason(e.target.value)}
                        style={{
                          padding: "6px 10px",
                          borderRadius: "4px",
                          border: "1px solid var(--glass-border)",
                          background: "rgba(0,0,0,0.3)",
                          color: "var(--text-main)",
                          fontSize: "12px"
                        }}
                      />
                      <div style={{ display: "flex", gap: "6px" }}>
                        <button
                          onClick={handleRejectHunt}
                          style={{
                            padding: "6px 10px",
                            background: "var(--danger)",
                            color: "#fff",
                            border: "none",
                            borderRadius: "4px",
                            fontSize: "11px",
                            fontWeight: "bold",
                            cursor: "pointer"
                          }}
                        >
                          Confirm Rejection
                        </button>
                        <button
                          onClick={() => { setShowRejectionForm(false); setRejectionReason(""); }}
                          style={{
                            padding: "6px 10px",
                            background: "var(--secondary)",
                            color: "#fff",
                            border: "none",
                            borderRadius: "4px",
                            fontSize: "11px",
                            fontWeight: "bold",
                            cursor: "pointer"
                          }}
                        >
                          Cancel
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {isApproved && (
                <div style={{ fontSize: "12px", color: "var(--text-main)", display: "flex", flexDirection: "column", gap: "8px" }}>
                  <div>
                    <strong>Option Selected & Approved:</strong> {issue.huntCompleteOption === "return_l2" ? "Option A: Return To L2" : "Option B: Close Hunt"}
                  </div>
                  <div>
                    <b>Notes:</b>
                    <pre style={{ margin: "4px 0 0 0", padding: "8px", background: "rgba(0,0,0,0.15)", borderRadius: "4px", fontSize: "11px", color: "var(--text-muted)", whiteSpace: "pre-wrap", fontFamily: "inherit" }}>
                      {issue.huntNotes || "N/A"}
                    </pre>
                  </div>
                  <div>
                    <b>Findings:</b>
                    <pre style={{ margin: "4px 0 0 0", padding: "8px", background: "rgba(0,0,0,0.15)", borderRadius: "4px", fontSize: "11px", color: "var(--text-muted)", whiteSpace: "pre-wrap", fontFamily: "inherit" }}>
                      {issue.huntFindings || "N/A"}
                    </pre>
                  </div>
                  <div>
                    <b>Recommendation:</b>
                    <pre style={{ margin: "4px 0 0 0", padding: "8px", background: "rgba(0,0,0,0.15)", borderRadius: "4px", fontSize: "11px", color: "var(--text-muted)", whiteSpace: "pre-wrap", fontFamily: "inherit" }}>
                      {issue.huntRecommendation || "N/A"}
                    </pre>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
