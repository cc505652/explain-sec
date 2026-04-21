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
import { onAuthStateChanged } from "firebase/auth";
import { normalizeRole, isVisibleToRole, getVisibleToForStatus } from "./utils/roleNormalization";
import { validateTransition } from "./utils/incidentStateGuard";
import { useEffect, useMemo, useState } from "react";
import {
  callEscalateIncident,
  callPerformContainment,
  callUpdateIncidentStatus,
} from "./utils/socFunctions";
import React from "react";

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
  if (issue.status === "open") {
    const openedAt = issue.statusHistory?.[0]?.at;
    if (openedAt && hoursSince(openedAt) > 24) return "delayed";
  }
  if (issue.status === "assigned") {
    const assigned = issue.statusHistory?.find((h) => h.status === "assigned");
    if (assigned && hoursSince(assigned.at) > 48) return "overdue";
  }
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

const SLA_HOURS = {
  open: 24,
  assigned: 48,
  in_progress: 72
};

function getSlaDisplay(issue) {
  const now = Date.now();
  const createdAtMs = tsToMillis(issue.createdAt);

  if (issue.status === "open") {
    const deadline = createdAtMs + SLA_HOURS.open * 60 * 60 * 1000;
    const remaining = deadline - now;
    if (remaining >= 0) {
      return {
        label: `⏱ SLA: ${formatDuration(remaining)} left`,
        color: "#1b5e20",
        breached: false
      };
    }
    return {
      label: `SLA BREACHED: ${formatDuration(remaining)} ago`,
      color: "#b71c1c",
      breached: true
    };
  }

  if (issue.status === "assigned" || issue.status === "in_progress" || issue.status === "escalation_pending") {
    const assignedEntry = issue.statusHistory?.find((h) => h.status === "assigned");
    const assignedAtMs = tsToMillis(assignedEntry?.at) || createdAtMs;
    const deadline = assignedAtMs + SLA_HOURS.assigned * 60 * 60 * 1000;
    const remaining = deadline - now;
    if (remaining >= 0) {
      return {
        label: `⏱ SLA: ${formatDuration(remaining)} left`,
        color: "#1b5e20",
        breached: false
      };
    }
    return {
      label: `SLA BREACHED: ${formatDuration(remaining)} ago`,
      color: "#b71c1c",
      breached: true
    };
  }

  // BUG FIX #18: SLA marks complete for resolved, contained, false_positive
  if (
    issue.status === "resolved" ||
    issue.status === "contained" ||
    issue.status === "containment_executed" ||
    issue.status === "false_positive" ||
    issue.status === "escalation_approved"
  ) {
    return { label: "SLA: complete", color: "#0d47a1", breached: false };
  }

  // Default case for other statuses
  const assignedEntry = issue.statusHistory?.find((h) => h.status === "assigned");
  const assignedAtMs = tsToMillis(assignedEntry?.at) || createdAtMs;
  const deadline = assignedAtMs + SLA_HOURS.assigned * 60 * 60 * 1000;
  const remaining = deadline - now;
  if (remaining >= 0) {
    return {
      label: `⏱ SLA: ${formatDuration(remaining)} left`,
      color: "#1b5e20",
      breached: false
    };
  }
  return {
    label: `SLA BREACHED: ${formatDuration(remaining)} ago`,
    color: "#b71c1c",
    breached: true
  };
}

function formatDuration(ms) {
  const abs = Math.abs(ms);
  const totalMin = Math.floor(abs / (60 * 1000));
  const h = Math.floor(totalMin / 60);
  const m = totalMin % 60;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
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
  { value: "soc_l1", label: "SOC Analyst L1" },
  { value: "soc_l2", label: "SOC Analyst L2" },
  { value: "incident_response", label: "Incident Response Team" },
  { value: "threat_hunter", label: "Threat Hunter" },
  { value: "forensics", label: "Digital Forensics" },
  { value: "cloud_security", label: "Cloud Security Team" },
  { value: "network_security", label: "Network Security Team" }
];

// 🔹 ENHANCED USER DISPLAY SYSTEM
function getAnalystDisplayLabel(assignedTo, usersData) {
  // If no assignment, return unassigned
  if (!assignedTo) return "Unassigned";

  // Check if we have user data for this UID
  if (usersData && usersData[assignedTo]) {
    const userData = usersData[assignedTo];

    // Build display name based on user data
    let displayName = userData.displayName || userData.email || "Unknown User";

    // Add role/level information
    if (userData.analystLevel) {
      const levelLabels = {
        "L1": "L1 Analyst",
        "L2": "L2 Analyst",
        "IR": "IR Specialist",
        "TH": "Threat Hunter"
      };
      displayName += ` (${levelLabels[userData.analystLevel] || userData.analystLevel})`;
    } else if (userData.role) {
      const roleLabels = {
        "admin": "Admin",
        "analyst": "Analyst",
        "student": "Student"
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
        "L1": "L1 Analyst",
        "L2": "L2 Analyst",
        "IR": "IR Specialist",
        "TH": "Threat Hunter"
      };
      displayName += ` (${levelLabels[userData.analystLevel] || userData.analystLevel})`;
    } else if (userData.role) {
      const roleLabels = {
        "admin": "Admin",
        "analyst": "Analyst",
        "student": "Student"
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
      const filtered = data.filter(i => isVisibleToRole(i, normalizedRole));

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
        const filtered = fallbackData.filter(i => isVisibleToRole(i, normalizedRole));
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
        visibleTo: ["soc_l2", "soc_manager"],
        requestedBy: auth.currentUser?.uid,
        requestedAt: serverTimestamp(),
        containmentRequested: true,
        containmentRequestedAt: serverTimestamp(),
        approvalStatus: "pending",
        updatedAt: serverTimestamp()
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
        updatedAt: serverTimestamp()
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
    if (analystTeam !== "incident_response") {
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
        visibleTo: ["soc_l2", "soc_manager", "ir"], // Always preserve L2 visibility
        updatedAt: serverTimestamp()
      });
      console.log(`🔴 IR ACTION SUBMITTED:`, { type: action, details, performedBy: auth.currentUser?.uid, visibleTo: ["soc_l2", "soc_manager", "ir"] });
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
    if (analystTeam !== "incident_response") {
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
    const createdAtMs = issue.createdAt?.toMillis?.() ?? 0;
    const now = Date.now();

    if (!createdAtMs) return false;

    if (issue.status === "open") {
      const deadline = createdAtMs + 24 * 60 * 60 * 1000;
      const remaining = deadline - now;
      return remaining > 0 && remaining < 2 * 60 * 60 * 1000;
    }

    if (issue.status === "assigned" || issue.status === "in_progress") {
      const assignedEntry = issue.statusHistory?.find(
        (h) => h.status === "assigned"
      );

      const assignedAtMs = assignedEntry?.at?.toMillis?.() ?? createdAtMs;
      const deadline = assignedAtMs + 48 * 60 * 60 * 1000;
      const remaining = deadline - now;

      return remaining > 0 && remaining < 2 * 60 * 60 * 1000;
    }

    return false;
  };

  // 1. Analyst Workload Panel
  // BUG FIX #16: also match team string assignments (ir, soc_l2, etc.)
  const analystWorkload = useMemo(() => {
    void nowTick;
    const workload = {};
    // Include incidents assigned to current user's UID OR to their team string
    const teamStrings = {
      "incident_response": "ir",
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

        <h2 style={{ marginBottom: 10 }}>
          {normalizedRole === "soc_l1" ? "SOC L1 Alert Triage Console" : "SOC Analyst Console"}
        </h2>

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
                          {/* � STEP 9 — Add Incident Age for SOC L1 */}
                          {isL1 ? (
                            <span>⏱ Reported {getIncidentAge(issue.createdAt)}</span>
                          ) : (
                            <span>� {issue.location} • 🧠 {issue.category} • 👷 {getAnalystDisplayLabel(issue.assignedTo, usersData)}</span>
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
                        {isIR && (
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

                            {/* Show submit buttons when IR can submit action (in_progress or rejected only, not review_again) */}
                            {(issue.status === "containment_in_progress" || issue.status === "containment_rejected") && (
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
                            onClick={() => addNoteToIssue(issue.id, noteText)}
                            data-testid="add-note"
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

                        {/* 🔹 6 — Display Timeline Inside Incident Card */}
                        {issue.investigationHistory?.length > 0 && (
                          <div style={{ marginTop: 8, padding: 8, background: "rgba(0,0,0,0.05)", borderRadius: 4 }}>
                            <b style={{ fontSize: 12, color: "var(--text-main)", marginBottom: 4 }}>🕐 Investigation Timeline</b>
                            {issue.investigationHistory.map((h, idx) => (
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
                                  {h.action} at {new Date(h.at?.seconds * 1000).toLocaleTimeString()}
                                </div>
                              </div>
                            ))}
                          </div>
                        )}
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
                          {(!issue.assignedTo || (issue.assignedTo && ["soc_network", "soc_endpoint", "soc_email", "soc_identity", "soc_l1", "soc_l2", "incident_response", "threat_hunter", "forensics", "cloud_security", "network_security", "soc_netw"].includes(issue.assignedTo))) && issue.status === "open" && issue.status !== "resolved" && (
                            <button
                              disabled={issue.locked === true}
                              onClick={() => {
                                // BUG FIX #10: also update status to "assigned" when claiming
                                updateDoc(doc(db, "issues", issue.id), {
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
                              <button
                                onClick={() => updateTriageStatus(issue.id, "false_positive")}
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
                                            note: "Triage classification: phishing",
                                            at: Timestamp.now()
                                          }),
                                          investigationHistory: arrayUnion({
                                            action: "classified_as_phishing",
                                            by: auth.currentUser?.uid,
                                            at: Timestamp.now()
                                          }),
                                          updatedAt: serverTimestamp()
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
                                            note: "Triage classification: malware",
                                            at: Timestamp.now()
                                          }),
                                          investigationHistory: arrayUnion({
                                            action: "classified_as_malware",
                                            by: auth.currentUser?.uid,
                                            at: Timestamp.now()
                                          }),
                                          updatedAt: serverTimestamp()
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
                                            note: "Triage classification: network attack",
                                            at: Timestamp.now()
                                          }),
                                          investigationHistory: arrayUnion({
                                            action: "classified_as_network_attack",
                                            by: auth.currentUser?.uid,
                                            at: Timestamp.now()
                                          }),
                                          updatedAt: serverTimestamp()
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
                                            note: "Triage classification: suspicious",
                                            at: Timestamp.now()
                                          }),
                                          investigationHistory: arrayUnion({
                                            action: "classified_as_suspicious",
                                            by: auth.currentUser?.uid,
                                            at: Timestamp.now()
                                          }),
                                          updatedAt: serverTimestamp()
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
