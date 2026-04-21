import {
  collection,
  onSnapshot,
  orderBy,
  query,
  updateDoc,
  doc,
  serverTimestamp,
  Timestamp,
  getDoc,
  setDoc,
  getDocs,
  where,
  limit,
  writeBatch
} from "firebase/firestore";
import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { app, auth, db } from "./firebase";
import { normalizeRole } from "./utils/normalizeRole";
import {
  callUpdateIncidentStatus,
  callEscalateIncident,
  callGovernanceAction,
  callBulkGovernanceAction,
} from "./utils/socFunctions";
import InvestigationPanel from "./components/InvestigationPanel";
import CollaborationPanel from "./components/CollaborationPanel";

/* ---------- RBAC & INTELLIGENCE MODULES ---------- */

// Role-based permissions
const ROLE_PERMISSIONS = {
  analyst: ['start_incident', 'resolve_incident'],
  admin: ['assign_incident', 'start_incident', 'resolve_incident'],
  soc_manager: ['escalate_incident', 'archive_incident', 'assign_incident', 'start_incident', 'resolve_incident']
};

// MITRE ATT&CK Mapping
const MITRE_MAPPING = {
  phishing: { tactic: 'TA0006', technique: 'T1566', name: 'Phishing' },
  malware: { tactic: 'TA0002', technique: 'T1204', name: 'User Execution' },
  account_compromise: { tactic: 'TA0006', technique: 'T1110', name: 'Brute Force' },
  network_attack: { tactic: 'TA0007', technique: 'T1046', name: 'Network Service Discovery' },
  data_leak: { tactic: 'TA0010', technique: 'T1041', name: 'Exfiltration Over C2 Channel' }
};

// Urgency weights for risk calculation
const URGENCY_WEIGHTS = { high: 3, medium: 2, low: 1 };

// Risk threshold for SLA breach prediction
const RISK_THRESHOLD = 2.5;

// Stuck incident threshold (6 hours)
const STUCK_THRESHOLD_HOURS = 6;

// Clustering time window (30 minutes)
const CLUSTER_WINDOW_MS = 30 * 60 * 1000;

/* ---------- SLA HELPERS ---------- */

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

/* ---------- TIME HELPERS ---------- */

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
  if (min < 60) return `${min} min ago`;

  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;

  const day = Math.floor(hr / 24);
  return `${day}d ago`;
}

function formatClock(ts) {
  const ms = tsToMillis(ts);
  if (!ms) return "—";
  const d = new Date(ms);
  return d.toLocaleString();
}

const SLA_HOURS = {
  open: 24,
  assigned: 48
};

function formatDuration(ms) {
  const abs = Math.abs(ms);
  const totalMin = Math.floor(abs / (60 * 1000));
  const h = Math.floor(totalMin / 60);
  const m = totalMin % 60;
  if (h === 0) return `${m}m`;
  return `${h}h ${m}m`;
}

function getSlaDisplay(issue) {
  const createdAtMs = tsToMillis(issue.createdAt);
  const now = Date.now();
  if (!createdAtMs) return { label: "SLA: —", color: "#999", breached: false };

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

  if (issue.status === "assigned" || issue.status === "in_progress") {
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

  return { label: "SLA: complete", color: "#0d47a1", breached: false };
}

/* ---------- ENHANCED SLA HELPERS FOR ANALYSTS ---------- */

function needsAttention(issue) {
  const slaDisplay = getSlaDisplay(issue);
  if (slaDisplay.breached) return true;
  
  // Check if approaching breach (< 2 hours left)
  const createdAtMs = tsToMillis(issue.createdAt);
  const now = Date.now();
  
  if (issue.status === "open") {
    const deadline = createdAtMs + SLA_HOURS.open * 60 * 60 * 1000;
    const remaining = deadline - now;
    return remaining > 0 && remaining < 2 * 60 * 60 * 1000; // < 2 hours
  }
  
  if (issue.status === "assigned" || issue.status === "in_progress") {
    const assignedEntry = issue.statusHistory?.find((h) => h.status === "assigned");
    const assignedAtMs = tsToMillis(assignedEntry?.at) || createdAtMs;
    const deadline = assignedAtMs + SLA_HOURS.assigned * 60 * 60 * 1000;
    const remaining = deadline - now;
    return remaining > 0 && remaining < 2 * 60 * 60 * 1000; // < 2 hours
  }
  
  return false;
}

/* ---------- PREMIUM PILLS ---------- */

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

/* ---------- STAFF OPTIONS ---------- */

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

/* ---------- INTELLIGENCE MODULES ---------- */

// RBAC Permission Check
function hasPermission(userRole, permission) {
  return ROLE_PERMISSIONS[userRole]?.includes(permission) || false;
}

// SLA Breach Prediction Score
function calculateBreachRiskScore(issue, analystActiveTickets, categoryAvgResolveTime) {
  const urgencyWeight = URGENCY_WEIGHTS[issue.urgency] || 1;
  const riskScore = (analystActiveTickets * 0.4) + (categoryAvgResolveTime * 0.3) + (urgencyWeight * 0.3);
  
  return {
    score: Math.round(riskScore * 100) / 100,
    riskLevel: riskScore > RISK_THRESHOLD ? 'high' : riskScore > 1.5 ? 'medium' : 'low'
  };
}

// Incident Stuck Detection
function isStuckIncident(issue) {
  if (issue.status !== 'in_progress') return false;
  
  const updatedAtMs = tsToMillis(issue.updatedAt);
  const hoursSinceUpdate = (Date.now() - updatedAtMs) / (60 * 60 * 1000);
  
  return hoursSinceUpdate > STUCK_THRESHOLD_HOURS;
}

// Incident Clustering
function findIncidentClusters(issues) {
  const clusters = [];
  const processed = new Set();
  
  issues.forEach(issue => {
    if (processed.has(issue.id)) return;
    
    const issueTime = tsToMillis(issue.createdAt);
    const cluster = issues.filter(other => {
      if (other.id === issue.id || processed.has(other.id)) return false;
      
      const otherTime = tsToMillis(other.createdAt);
      const timeDiff = Math.abs(issueTime - otherTime);
      
      return issue.category === other.category && 
             issue.location === other.location && 
             timeDiff <= CLUSTER_WINDOW_MS;
    });
    
    if (cluster.length > 0) {
      const clusterId = `cluster_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      const allClusterIssues = [issue, ...cluster];
      
      allClusterIssues.forEach(clusterIssue => {
        processed.add(clusterIssue.id);
      });
      
      clusters.push({
        id: clusterId,
        issues: allClusterIssues,
        category: issue.category,
        location: issue.location,
        count: allClusterIssues.length,
        createdAt: issue.createdAt
      });
    }
  });
  
  return clusters;
}

// MTTA/MTTR Calculation
function calculateMTTAMTTR(issues) {
  const analystStats = {};
  const categoryStats = {};
  const urgencyStats = {};
  
  issues.forEach(issue => {
    if (issue.status !== 'resolved' || !issue.assignedTo) return;
    
    const createdAtMs = tsToMillis(issue.createdAt);
    const assignedAtMs = tsToMillis(issue.assignedAt);
    const resolvedAtMs = tsToMillis(issue.resolvedAt);
    
    if (!assignedAtMs || !resolvedAtMs) return;
    
    const mtaa = assignedAtMs - createdAtMs;
    const mttr = resolvedAtMs - createdAtMs;
    
    // Analyst stats
    if (!analystStats[issue.assignedTo]) {
      analystStats[issue.assignedTo] = { mtaa: [], mttr: [], count: 0 };
    }
    analystStats[issue.assignedTo].mtaa.push(mtaa);
    analystStats[issue.assignedTo].mttr.push(mttr);
    analystStats[issue.assignedTo].count++;
    
    // Category stats
    if (!categoryStats[issue.category]) {
      categoryStats[issue.category] = { mtaa: [], mttr: [], count: 0 };
    }
    categoryStats[issue.category].mtaa.push(mtaa);
    categoryStats[issue.category].mttr.push(mttr);
    categoryStats[issue.category].count++;
    
    // Urgency stats
    if (!urgencyStats[issue.urgency]) {
      urgencyStats[issue.urgency] = { mtaa: [], mttr: [], count: 0 };
    }
    urgencyStats[issue.urgency].mtaa.push(mtaa);
    urgencyStats[issue.urgency].mttr.push(mttr);
    urgencyStats[issue.urgency].count++;
  });
  
  // Calculate averages
  const calculateAvg = (arr) => {
    if (arr.length === 0) return 0;
    return arr.reduce((a, b) => a + b, 0) / arr.length;
  };
  
  const formatMs = (ms) => {
    const hours = Math.floor(ms / (60 * 60 * 1000));
    const minutes = Math.floor((ms % (60 * 60 * 1000)) / (60 * 1000));
    return `${hours}h ${minutes}m`;
  };
  
  return {
    analyst: Object.fromEntries(
      Object.entries(analystStats).map(([key, stats]) => [
        key,
        {
          avgMTTA: formatMs(calculateAvg(stats.mtaa)),
          avgMTTR: formatMs(calculateAvg(stats.mttr)),
          count: stats.count
        }
      ])
    ),
    category: Object.fromEntries(
      Object.entries(categoryStats).map(([key, stats]) => [
        key,
        {
          avgMTTA: formatMs(calculateAvg(stats.mtaa)),
          avgMTTR: formatMs(calculateAvg(stats.mttr)),
          count: stats.count
        }
      ])
    ),
    urgency: Object.fromEntries(
      Object.entries(urgencyStats).map(([key, stats]) => [
        key,
        {
          avgMTTA: formatMs(calculateAvg(stats.mtaa)),
          avgMTTR: formatMs(calculateAvg(stats.mttr)),
          count: stats.count
        }
      ])
    )
  };
}

/* ---------- DARK UI HELPERS ---------- */

const darkSelectStyle = {
  padding: "10px 12px",
  borderRadius: 12,
  background: "rgba(255,255,255,0.08)",
  color: "#fff",
  border: "1px solid rgba(255,255,255,0.16)",
  outline: "none"
};

const darkBtnStyle = {
  background: "#000",
  color: "#fff",
  border: "1px solid rgba(255,255,255,0.18)",
  padding: "10px 12px",
  borderRadius: 12,
  fontWeight: 900,
  cursor: "pointer"
};

/* ---------- COMPONENT ---------- */

export default function SOCManager_CommandConsole() {
  const navigate = useNavigate();
  const [issues, setIssues] = useState([]);
  const [currentUser, setCurrentUser] = useState(null);
  const [userRole, setUserRole] = useState("analyst");
  const [users, setUsers] = useState({});

  // ✅ Live refresh tick
  const [nowTick, setNowTick] = useState(Date.now());
  useEffect(() => {
    const t = setInterval(() => setNowTick(Date.now()), 60 * 1000);
    return () => clearInterval(t);
  }, []);

  // 🔹 STEP 3 — Add Firebase Project Debug
  useEffect(() => {
    console.log("🔥 Firebase Project ID:", db._databaseId.projectId);
    console.log("🔥 Firebase App Name:", app.name);
  }, []);

  // filters
  const [filterStatus, setFilterStatus] = useState("all");
  const [filterCategory, setFilterCategory] = useState("all");
  const [filterUrgency, setFilterUrgency] = useState("all");
  const [filterAssignedTo, setFilterAssignedTo] = useState("all");
  const [onlyUnassigned, setOnlyUnassigned] = useState(false);
  const [showDeleted, setShowDeleted] = useState(false);

  // AI summary
  const [aiSummary, setAiSummary] = useState("");
  const [aiLoading, setAiLoading] = useState(false);

  // Evidence gallery
  const [galleryOpen, setGalleryOpen] = useState(false);
  const [galleryCategory, setGalleryCategory] = useState("all");
  const [galleryUrgency, setGalleryUrgency] = useState("all");
  const [gallerySelected, setGallerySelected] = useState(null);

  // Intelligence modules state
  const [clusters, setClusters] = useState([]);
  const [mttaMttrStats, setMttaMttrStats] = useState({ analyst: {}, category: {}, urgency: {} });
  const [autoAssignmentEnabled, setAutoAssignmentEnabled] = useState(true);

  // Phase 4: Global search + bulk operations
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedIds, setSelectedIds] = useState(new Set());
  const [bulkAction, setBulkAction] = useState("");
  const [bulkPayload, setBulkPayload] = useState("");
  const [bulkLoading, setBulkLoading] = useState(false);
  const [bulkResult, setBulkResult] = useState(null);

  // Phase 6: Investigation workspace
  const [investigateIssue, setInvestigateIssue] = useState(null);

  /* ---------- REALTIME FETCH ---------- */
  useEffect(() => {
    const unsubAuth = auth.onAuthStateChanged((user) => {
      if (!user) return;
      setCurrentUser(user);

      const q = query(
        collection(db, "issues"),
        orderBy("urgencyScore", "desc"),
        orderBy("createdAt", "desc")
      );

      const unsubSnap = onSnapshot(q, (snap) => {
        const data = snap.docs.map((d) => ({ id: d.id, ...d.data() }));
        setIssues(data);
        console.log("REALTIME UPDATE: Incidents updated in Command Console", data.length);

        // Process intelligence modules
        const foundClusters = findIncidentClusters(data);
        setClusters(foundClusters);

        const stats = calculateMTTAMTTR(data);
        setMttaMttrStats(stats);
      }, (error) => {
        console.error("Firestore listener error (Command Console incidents):", error);
      });

      return () => unsubSnap();
    });

    return () => unsubAuth();
  }, []);

  // Fetch user roles and permissions
  useEffect(() => {
    if (!currentUser) return;
    
    const fetchUserRole = async () => {
      try {
        const userDoc = await getDoc(doc(db, "users", currentUser.uid));
        
        // PHASE 1 FIX: Profile creation removed — only App.jsx creates profiles.
        // If profile doesn't exist, log warning and use read-only fallback.
        if (!userDoc.exists()) {
          console.warn("⚠️ CommandConsole - User profile not found. App.jsx should have created it.");
          setUserRole("analyst");
        } else {
          const userData = userDoc.data();
          console.log("👤 CommandConsole - User role fetched:", { uid: currentUser.uid, role: userData.role });
          setUserRole(userData.role || "analyst");
        }
      } catch (error) {
        console.error("Error fetching user role:", error);
      }
    };
    
    fetchUserRole();
  }, [currentUser]);

  // Fetch all users for analytics (REAL-TIME)
  useEffect(() => {
    const unsubscribe = onSnapshot(
      collection(db, "users"),
      (snapshot) => {
        const usersData = {};
        snapshot.forEach(doc => {
          usersData[doc.id] = doc.data();
        });
        setUsers(usersData);
        console.log("REALTIME UPDATE: Users data updated", Object.keys(usersData).length);
      },
      (error) => {
        console.error("Firestore listener error (users):", error);
      }
    );

    return () => unsubscribe();
  }, []);

  /* ---------- STATUS UPDATE (PHASE 1 FIX: via Cloud Function) ---------- */
  const updateStatus = async (issue, nextStatus) => {
    console.log("🔐 updateStatus called:", { nextStatus, userRole, issueId: issue.id });
    
    if (issue.locked === true) {
      alert("Incident locked by SOC Manager");
      return;
    }
    
    // RBAC Check (UX-only — server validates too)
    if (nextStatus === "in_progress" && !hasPermission(userRole, 'start_incident')) {
      alert("You don't have permission to start incidents.");
      return;
    }
    
    if (nextStatus === "resolved" && !hasPermission(userRole, 'resolve_incident')) {
      alert("You don't have permission to resolve incidents.");
      return;
    }
    
    try {
      const user = auth.currentUser;
      const auditNote = nextStatus === "in_progress" ? `Investigation started by ${user?.email}` : 
                       nextStatus === "resolved" ? `Resolved by ${user?.email}` : 
                       `Status updated to ${nextStatus} by ${user?.email}`;
      
      const result = await callUpdateIncidentStatus(issue.id, nextStatus, auditNote);
      console.log("✅ Status updated via Cloud Function:", result);
    } catch (err) {
      console.error("Status update failed:", err);
      alert("Status update failed: " + (err?.message || "Unknown error"));
    }
  };

  /* ---------- AUTO-ASSIGNMENT ENGINE ---------- */
  const autoAssignIssue = async (issue) => {
    if (!autoAssignmentEnabled || issue.status !== "open" || issue.assignedTo) return;
    
    try {
      // Find analysts with matching skills
      const availableAnalysts = Object.entries(users).filter(([uid, userData]) => {
        return normalizeRole(userData.role) === "soc_l1" &&
               userData.skills?.includes(issue.category);
      });
      
      if (availableAnalysts.length === 0) return;
      
      // Calculate active tickets for each analyst
      const analystWorkloads = await Promise.all(
        availableAnalysts.map(async ([uid, userData]) => {
          const activeTicketsQuery = query(
            collection(db, "issues"),
            where("assignedTo", "==", uid),
            where("status", "in", ["assigned", "in_progress"])
          );
          
          const snapshot = await getDocs(activeTicketsQuery);
          const activeTickets = snapshot.size;
          
          return {
            uid,
            userData,
            activeTickets,
            avgResolveTime: userData.avgResolveTime || 24 // Default 24 hours
          };
        })
      );
      
      // Sort by lowest active tickets, then by avg resolve time
      analystWorkloads.sort((a, b) => {
        if (a.activeTickets !== b.activeTickets) {
          return a.activeTickets - b.activeTickets;
        }
        return a.avgResolveTime - b.avgResolveTime;
      });
      
      const bestAnalyst = analystWorkloads[0];
      if (bestAnalyst) {
        await assignIssue(issue, bestAnalyst.uid);
      }
    } catch (error) {
      console.error("Auto-assignment failed:", error);
    }
  };

  /* ---------- STAFF ASSIGN (PHASE 1 FIX: via Cloud Function) ---------- */
  const assignIssue = async (issue, assignedToValue) => {
    if (issue.locked === true) {
      alert("Incident locked by SOC Manager");
      return;
    }
    
    // RBAC Check (UX-only — server validates too)
    if (!hasPermission(userRole, 'assign_incident')) {
      alert("You don't have permission to assign incidents.");
      return;
    }
    
    try {
      const reason = `Assigned to ${assignedToValue} via Command Console`;
      const result = await callGovernanceAction(issue.id, "TRANSFER_OWNERSHIP", {
        newAssignedTo: assignedToValue,
        reason,
      });
      console.log("✅ Assignment via Cloud Function:", result);
    } catch (err) {
      // If TRANSFER_OWNERSHIP fails (e.g. same team), fall back to updateIncidentStatus
      console.error("Assignment failed:", err);
      alert("Assignment failed: " + (err?.message || "Unknown error"));
    }
  };

  /* ---------- ESCALATE (PHASE 1 FIX: via Cloud Function) ---------- */
  const escalateIssue = async (issue) => {
    if (issue.locked === true) {
      alert("Incident locked by SOC Manager");
      return;
    }
    
    // RBAC Check (UX-only — server validates too)
    if (!hasPermission(userRole, 'escalate_incident')) {
      alert("You don't have permission to escalate incidents.");
      return;
    }
    
    const ok = window.confirm(`Escalate issue to SOC Manager?\n\n"${issue.title}"`);
    if (!ok) return;

    try {
      const result = await callEscalateIncident(issue.id);
      console.log("✅ Escalation via Cloud Function:", result);
      alert(result.message || "✅ Escalated successfully");
    } catch (err) {
      console.error("Escalation failed:", err);
      alert("Escalation failed: " + (err?.message || "Unknown error"));
    }
  };

  /* ---------- DELETE COMPLETED (WITH RBAC) ---------- */
  const deleteResolvedIssue = async (issue) => {
    if (issue.locked === true) {
      alert("Incident locked by SOC Manager");
      return;
    }
    
    // Governance lock check
    const incidentDoc = await getDoc(doc(db,"issues",issue.id));
    const data = incidentDoc.data();
    
    if(data.locked === true){
      alert("This incident is Governance Locked by SOC Manager");
      return;
    }
    
    // 🔹 STEP 1 — Add Debug Log
    console.log("🧪 Admin Role Debug:", userRole);
    
    // 🔹 STEP 2 — Replace With Safe Admin Check
    const isAdmin =
      normalizeRole(userRole) === "admin" ||
      normalizeRole(userRole?.role) === "admin";
    
    if (!isAdmin) {
      alert("You don't have permission to archive incidents.");
      return;
    }
    
    const ok = window.confirm(`Delete resolved issue?\n\n"${issue.title}"`);
    if (!ok) return;

    try {
      console.log("🧪 ARCHIVE DEBUG START");
      console.log("Incident ID:", issue.id);
      console.log("Admin UID:", auth.currentUser?.uid);
      console.log("Admin Email:", auth.currentUser?.email);
      console.log("Incident Title:", issue.title);
      console.log("Current Status:", issue.status);
      console.log("Is Deleted:", issue.isDeleted);

      const user = auth.currentUser;
      const ref = doc(db, "issues", issue.id);
      
      console.log("Firestore Path:", ref.path);
      console.log("Firestore Database:", db._databaseId.projectId);

      // Use governance action instead of direct updateDoc to ensure state machine validation
      try {
        const result = await callGovernanceAction(issue.id, "ARCHIVE_INCIDENT", {
          reason: `Archived by ${user?.email || 'SOC Manager'}`
        });
        console.log("✅ ARCHIVE SUCCESS");
        alert(result.message || "Incident archived successfully");
      } catch (governanceError) {
        // Fallback to direct updateDoc if governance action fails (for backward compatibility)
        console.warn("Governance action failed, falling back to direct updateDoc:", governanceError);
        await updateDoc(ref, {
          isDeleted: true,
          deletedAt: serverTimestamp(),
          deletedBy: user?.uid || null,
          statusHistory: [
            ...(issue.statusHistory || []),
            { status: "deleted", at: Timestamp.now(), note: `Deleted by ${user?.email}` }
          ],
          updatedAt: serverTimestamp()
        });
        console.log("✅ ARCHIVE SUCCESS (fallback)");
        alert("Incident archived successfully");
      }

    } catch (err) {
      console.error("❌ ARCHIVE FAILED:", err);
      console.error("Error Code:", err.code);
      console.error("Error Message:", err.message);
      console.error("Full Error Object:", err);
      
      alert("Archive Failed: " + err.message);
    }
  };

  /* ---------- ANALYST WORKLOAD INDICATOR ---------- */
  const analystWorkload = useMemo(() => {
    if (!currentUser) return 0;
    return issues.filter(i => 
      !i.isDeleted && 
      i.assignedTo === currentUser.uid && 
      i.status !== "resolved"
    ).length;
  }, [issues, currentUser]);

  /* ---------- ENHANCED INTELLIGENCE ANALYTICS ---------- */
  const enhancedIssues = useMemo(() => {
    return issues.map(issue => {
      // Add MITRE ATT&CK mapping
      const mitreInfo = MITRE_MAPPING[issue.category] || { tactic: '', technique: '', name: '' };
      
      // Calculate SLA breach prediction
      const analystActiveTickets = issues.filter(i => 
        i.assignedTo === issue.assignedTo && 
        i.status !== 'resolved' && 
        !i.isDeleted
      ).length;
      
      const categoryAvgTime = mttaMttrStats.category[issue.category]?.avgMTTR || '24h';
      const avgHours = parseInt(categoryAvgTime) || 24;
      
      const riskScore = calculateBreachRiskScore(issue, analystActiveTickets, avgHours);
      
      // Check if stuck
      const stuck = isStuckIncident(issue);
      
      return {
        ...issue,
        ...mitreInfo,
        predictedBreachRiskScore: riskScore.score,
        breachRiskLevel: riskScore.riskLevel,
        stuck
      };
    });
  }, [issues, mttaMttrStats]);

  // Auto-assignment effect
  useEffect(() => {
    if (!autoAssignmentEnabled) return;
    
    const openUnassignedIssues = issues.filter(issue => 
      issue.status === 'open' && !issue.assignedTo && !issue.isDeleted
    );
    
    openUnassignedIssues.forEach(issue => {
      autoAssignIssue(issue);
    });
  }, [issues, autoAssignmentEnabled, users]);

  // Analyst Fatigue Index
  const analystFatigueIndex = useMemo(() => {
    const fatigueData = {};
    
    Object.entries(users).forEach(([uid, userData]) => {
      if (userData.role !== 'analyst') return;
      
      const activeTickets = issues.filter(i => 
        i.assignedTo === uid && 
        i.status !== 'resolved' && 
        !i.isDeleted
      ).length;
      
      const highUrgencyTickets = issues.filter(i => 
        i.assignedTo === uid && 
        i.urgency === 'high' && 
        i.status !== 'resolved' && 
        !i.isDeleted
      ).length;
      
      const stuckTickets = issues.filter(i => 
        i.assignedTo === uid && 
        isStuckIncident(i) && 
        !i.isDeleted
      ).length;
      
      // Calculate fatigue score (0-100)
      const fatigueScore = Math.min(100, (activeTickets * 10) + (highUrgencyTickets * 20) + (stuckTickets * 30));
      
      fatigueData[uid] = {
        name: userData.email || uid,
        activeTickets,
        highUrgencyTickets,
        stuckTickets,
        fatigueScore,
        fatigueLevel: fatigueScore > 80 ? 'critical' : fatigueScore > 50 ? 'high' : fatigueScore > 20 ? 'medium' : 'low'
      };
    });
    
    return fatigueData;
  }, [issues, users]);

  // Stuck incidents
  const stuckIncidents = useMemo(() => {
    return enhancedIssues.filter(issue => issue.stuck && !issue.isDeleted);
  }, [enhancedIssues]);

  // High risk incidents
  const highRiskIncidents = useMemo(() => {
    return enhancedIssues.filter(issue => 
      issue.breachRiskLevel === 'high' && !issue.isDeleted
    );
  }, [enhancedIssues]);

  /* ---------- FILTER + SORT ---------- */
  const filtered = useMemo(() => {
    void nowTick;

    return enhancedIssues.filter((i) => {
      if (!showDeleted && i.isDeleted) return false;

      // Phase 4: Global search filter
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchTitle = (i.title || "").toLowerCase().includes(q);
        const matchId = (i.id || "").toLowerCase().includes(q);
        const matchAssignee = (i.assignedTo || "").toLowerCase().includes(q);
        const matchCategory = (i.category || "").toLowerCase().includes(q);
        const matchTags = Array.isArray(i.tags) && i.tags.some(t => t.toLowerCase().includes(q));
        if (!matchTitle && !matchId && !matchAssignee && !matchCategory && !matchTags) return false;
      }

      const okStatus = filterStatus === "all" || i.status === filterStatus;
      const okCat = filterCategory === "all" || i.category === filterCategory;
      const okUrg = filterUrgency === "all" || i.urgency === filterUrgency;

      const isUnassigned = !i.assignedTo;
      const okUnassignedToggle = !onlyUnassigned || isUnassigned;

      let okAssigned = true;
      if (filterAssignedTo === "unassigned") okAssigned = isUnassigned;
      else if (filterAssignedTo !== "all") okAssigned = i.assignedTo === filterAssignedTo;

      return okStatus && okCat && okUrg && okAssigned && okUnassignedToggle;
    });
  }, [
    enhancedIssues,
    filterStatus,
    filterCategory,
    filterUrgency,
    filterAssignedTo,
    onlyUnassigned,
    showDeleted,
    nowTick
  ]);

  const sortedIssues = [...filtered].sort((a, b) => {
    const slaDiff = attentionOrder[getSlaFlag(a)] - attentionOrder[getSlaFlag(b)];
    if (slaDiff !== 0) return slaDiff;

    const aScore = a.urgencyScore ?? urgencyRank[a.urgency] ?? 0;
    const bScore = b.urgencyScore ?? urgencyRank[b.urgency] ?? 0;
    if (bScore !== aScore) return bScore - aScore;

    const aTime = tsToMillis(a.createdAt);
    const bTime = tsToMillis(b.createdAt);
    return bTime - aTime;
  });

  /* ---------- HEATMAP ---------- */
  const hostelCounts = useMemo(() => {
    return issues.reduce((acc, i) => {
      if (i.isDeleted) return acc;
      acc[i.location] = (acc[i.location] || 0) + 1;
      return acc;
    }, {});
  }, [issues]);

  /* ---------- TOP STATS ---------- */
  const topStats = useMemo(() => {
    void nowTick;
    const active = issues.filter((i) => !i.isDeleted);
    const open = active.filter((i) => i.status === "open").length;
    const assigned = active.filter((i) => i.status === "assigned").length;
    const inProgress = active.filter((i) => i.status === "in_progress").length;
    const resolved = active.filter((i) => i.status === "resolved").length;
    const breached = active.filter((i) => getSlaDisplay(i).breached).length;
    const escalated = active.filter((i) => i.escalated).length;
    return { open, assigned, inProgress, resolved, breached, escalated };
  }, [issues, nowTick]);

  /* ---------- OPS HIGHLIGHTS ---------- */
  const opsHighlights = useMemo(() => {
    void nowTick;

    const active = issues.filter((i) => !i.isDeleted);

    const urgent = [...active]
      .filter((i) => i.status !== "resolved")
      .sort((a, b) => (b.urgencyScore ?? 0) - (a.urgencyScore ?? 0))[0];

    const hotspotEntry = Object.entries(hostelCounts).sort((a, b) => b[1] - a[1])[0];

    const staffLoad = {};
    for (const i of active) {
      const ass = i.assignedTo || "unassigned";
      staffLoad[ass] = (staffLoad[ass] || 0) + 1;
    }
    const topStaffEntry = Object.entries(staffLoad).sort((a, b) => b[1] - a[1])[0];

    return {
      urgent,
      hotspot: hotspotEntry ? { location: hotspotEntry[0], count: hotspotEntry[1] } : null,
      topStaff: topStaffEntry ? { staff: topStaffEntry[0], count: topStaffEntry[1] } : null
    };
  }, [issues, hostelCounts, nowTick]);

  /* ---------- EVIDENCE LIST ---------- */
  const evidenceIssues = useMemo(() => {
    const withEvidence = issues
      .filter((i) => !i.isDeleted)
      .filter((i) => i.evidenceImage?.url);

    return withEvidence.filter((i) => {
      const okCat = galleryCategory === "all" || i.category === galleryCategory;
      const okUrg = galleryUrgency === "all" || i.urgency === galleryUrgency;
      return okCat && okUrg;
    });
  }, [issues, galleryCategory, galleryUrgency]);

  /* ---------- AI WEEKLY SUMMARY ---------- */
  const generateWeeklySummary = async () => {
    try {
      setAiLoading(true);

      const last7 = issues
        .filter((i) => !i.isDeleted)
        .filter((i) => {
          const ms = i.createdAt?.toMillis?.() ?? 0;
          return ms > Date.now() - 7 * 24 * 60 * 60 * 1000;
        });

      const byCategory = {};
      const byUrgency = {};
      const byLocation = {};
      const byAssigned = {};
      let slaBreached = 0;
      let resolvedCount = 0;

      for (const i of last7) {
        byCategory[i.category] = (byCategory[i.category] || 0) + 1;
        byUrgency[i.urgency] = (byUrgency[i.urgency] || 0) + 1;
        byLocation[i.location] = (byLocation[i.location] || 0) + 1;

        const ass = i.assignedTo || "unassigned";
        byAssigned[ass] = (byAssigned[ass] || 0) + 1;

        if (getSlaDisplay(i).breached) slaBreached++;
        if (i.status === "resolved") resolvedCount++;
      }

      const hotspots = Object.entries(byLocation)
        .map(([location, count]) => ({ location, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 3);

      const stats = {
        totalIssues: last7.length,
        resolvedCount,
        slaBreached,
        byCategory,
        byUrgency,
        hotspots,
        byAssigned
      };

      const accurateSummary = `
Weekly Ops Summary (Last 7 Days)

✅ Total Issues: ${stats.totalIssues}
✅ Resolved: ${stats.resolvedCount}
⚠ SLA Breached: ${stats.slaBreached}

🏠 Top Hotspots:
${stats.hotspots.length ? stats.hotspots.map((h, idx) => `${idx + 1}) ${h.location}: ${h.count}`).join("\n") : "—"}

📌 Category Breakdown:
${Object.entries(stats.byCategory).length
  ? Object.entries(stats.byCategory).map(([k, v]) => `- ${k}: ${v}`).join("\n")
  : "—"}

⚡ Urgency Breakdown:
${Object.entries(stats.byUrgency).length
  ? Object.entries(stats.byUrgency).map(([k, v]) => `- ${k}: ${v}`).join("\n")
  : "—"}`.trim();

      // AI narration feature removed - using accurate summary only
      const finalSummary = accurateSummary;
      setAiSummary(finalSummary);
    } catch (e) {
      console.error(e);
      alert("Failed to generate weekly summary");
    } finally {
      setAiLoading(false);
    }
  };

  /* ---------- UI ---------- */
  return (
    <div style={{ padding: 16 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          <button 
            onClick={() => navigate("/soc-manager")}
            style={{
              background: "var(--primary)",
              color: "#fff",
              border: "none",
              padding: "8px 16px",
              borderRadius: "6px",
              cursor: "pointer",
              fontSize: "14px",
              fontWeight: "600"
            }}
          >
            Back to Manager Dashboard
          </button>
          <h2 style={{ color: "var(--text-main)", margin: 0 }}>SOC Manager Command Console</h2>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          {/* Phase 4: Global Search */}
          <div style={{ position: "relative" }}>
            <input
              type="text"
              placeholder="🔍 Search incidents..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              style={{
                padding: "8px 14px 8px 14px",
                borderRadius: 12,
                background: "rgba(255,255,255,0.06)",
                border: searchQuery ? "1px solid var(--primary)" : "1px solid rgba(255,255,255,0.12)",
                color: "#fff",
                fontSize: 13,
                width: 220,
                outline: "none",
              }}
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery("")}
                style={{
                  position: "absolute", right: 8, top: "50%", transform: "translateY(-50%)",
                  background: "none", border: "none", color: "#94a3b8", cursor: "pointer", fontSize: 14,
                }}
              >✕</button>
            )}
          </div>
          <button
            onClick={() => navigate("/analytics")}
            style={{
              background: "linear-gradient(135deg, #06b6d4, #8b5cf6)",
              color: "#fff", border: "none", padding: "8px 14px",
              borderRadius: 10, cursor: "pointer", fontSize: 12, fontWeight: 700,
            }}
          >📊 Analytics</button>
          {/* Analyst Workload Indicator */}
          <div className="glass-panel" style={{ 
            background: analystWorkload > 5 ? "rgba(239, 68, 68, 0.1)" : "rgba(16, 185, 129, 0.1)", 
            padding: "8px 16px", 
            borderRadius: 20, 
            fontWeight: 900,
            color: analystWorkload > 5 ? "var(--danger)" : "var(--success)",
            border: analystWorkload > 5 ? "1px solid rgba(239, 68, 68, 0.3)" : "1px solid rgba(16, 185, 129, 0.3)"
          }}>
            🎯 Active: {analystWorkload}
          </div>
        </div>
      </div>

      {/* Phase 4: Bulk Operations Toolbar */}
      {selectedIds.size > 0 && (
        <div className="glass-panel" style={{
          padding: "12px 20px", marginBottom: 16, display: "flex",
          alignItems: "center", gap: 12, flexWrap: "wrap",
          background: "rgba(6,182,212,0.08)",
          border: "1px solid rgba(6,182,212,0.25)",
        }}>
          <span style={{ fontWeight: 700, color: "var(--primary)", fontSize: 13 }}>
            ✅ {selectedIds.size} selected
          </span>
          <select
            value={bulkAction}
            onChange={e => setBulkAction(e.target.value)}
            style={{ ...darkSelectStyle, minWidth: 160 }}
          >
            <option value="">Choose action...</option>
            <option value="LOCK">🔒 Bulk Lock</option>
            <option value="UNLOCK">🔓 Bulk Unlock</option>
            <option value="ESCALATE">🚨 Bulk Escalate</option>
            <option value="UPDATE_TAGS">🏷️ Bulk Tag</option>
          </select>
          {bulkAction === "UPDATE_TAGS" && (
            <input
              type="text"
              placeholder="Tags (comma-separated)"
              value={bulkPayload}
              onChange={e => setBulkPayload(e.target.value)}
              style={{ ...darkSelectStyle, minWidth: 200 }}
            />
          )}
          <button
            disabled={!bulkAction || bulkLoading}
            onClick={async () => {
              if (!window.confirm(`Execute ${bulkAction} on ${selectedIds.size} incidents?`)) return;
              setBulkLoading(true);
              try {
                const payload = bulkAction === "UPDATE_TAGS"
                  ? { tags: bulkPayload.split(",").map(t => t.trim()).filter(Boolean) }
                  : { reason: "Bulk operation via Command Console" };
                const result = await callBulkGovernanceAction(
                  Array.from(selectedIds), bulkAction, payload
                );
                setBulkResult(result);
                setSelectedIds(new Set());
                setBulkAction("");
                setBulkPayload("");
                alert(`✅ Done: ${result.summary.succeeded} succeeded, ${result.summary.failed} failed, ${result.summary.skipped} skipped`);
              } catch (err) {
                alert("Bulk operation failed: " + (err?.message || "Unknown error"));
              } finally {
                setBulkLoading(false);
              }
            }}
            style={{
              ...darkBtnStyle,
              background: bulkAction ? "var(--primary)" : "#333",
              opacity: bulkAction && !bulkLoading ? 1 : 0.5,
            }}
          >
            {bulkLoading ? "Processing..." : "Execute"}
          </button>
          <button
            onClick={() => { setSelectedIds(new Set()); setBulkAction(""); setBulkResult(null); }}
            style={{ ...darkBtnStyle, background: "rgba(239,68,68,0.2)", color: "#ef4444" }}
          >
            Clear Selection
          </button>
          {/* Select All visible */}
          <button
            onClick={() => {
              const allIds = new Set(sortedIssues.map(i => i.id));
              setSelectedIds(allIds);
            }}
            style={{ ...darkBtnStyle, background: "rgba(139,92,246,0.15)", color: "#8b5cf6" }}
          >
            Select All ({sortedIssues.length})
          </button>
        </div>
      )}

      {/* 🚀 NEW INTELLIGENCE PANELS */}
      {normalizeRole(userRole) === 'admin' || normalizeRole(userRole) === 'soc_manager' ? (
        <>
          {/* ANALYST FATIGUE INDEX */}
          <div className="glass-panel" style={{ padding: 20, marginBottom: 16 }}>
            <h3 style={{ marginTop: 0, color: "var(--text-main)" }}>🧠 Analyst Fatigue Index</h3>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(250px, 1fr))", gap: 12 }}>
              {Object.entries(analystFatigueIndex).map(([uid, data]) => (
                <div key={uid} className="glass-panel" style={{ 
                  padding: 12, 
                  background: data.fatigueLevel === 'critical' ? "rgba(239, 68, 68, 0.1)" : 
                             data.fatigueLevel === 'high' ? "rgba(245, 158, 11, 0.1)" : 
                             "rgba(0, 0, 0, 0.2)",
                  border: data.fatigueLevel === 'critical' ? "1px solid var(--danger)" : 
                         data.fatigueLevel === 'high' ? "1px solid var(--warning)" : 
                         "1px solid var(--glass-border)"
                }}>
                  <div style={{ fontWeight: 900, color: "var(--text-main)" }}>{data.name}</div>
                  <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 4 }}>
                    Active: {data.activeTickets} | High Urgency: {data.highUrgencyTickets} | Stuck: {data.stuckTickets}
                  </div>
                  <div style={{ 
                    fontSize: 14, 
                    fontWeight: 900, 
                    marginTop: 6,
                    color: data.fatigueLevel === 'critical' ? "var(--danger)" : 
                           data.fatigueLevel === 'high' ? "var(--warning)" : 
                           "var(--success)"
                  }}>
                    Fatigue: {data.fatigueScore}% ({data.fatigueLevel})
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* SLA RISK DISTRIBUTION */}
          <div className="glass-panel" style={{ padding: 20, marginBottom: 16 }}>
            <h3 style={{ marginTop: 0, color: "var(--text-main)" }}>⚠ SLA Risk Distribution</h3>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 12 }}>
              <div className="glass-panel" style={{ padding: 16, background: "rgba(239, 68, 68, 0.1)", border: "1px solid var(--danger)" }}>
                <div style={{ fontSize: 24, fontWeight: 900, color: "var(--danger)" }}>{highRiskIncidents.length}</div>
                <div style={{ color: "var(--text-main)" }}>High Risk Incidents</div>
              </div>
              <div className="glass-panel" style={{ padding: 16, background: "rgba(245, 158, 11, 0.1)", border: "1px solid var(--warning)" }}>
                <div style={{ fontSize: 24, fontWeight: 900, color: "var(--warning)" }}>{highRiskIncidents.length}</div>
                <div style={{ color: "var(--text-main)" }}>High Risk Incidents</div>
              </div>
              <div className="glass-panel" style={{ padding: 16, background: "rgba(245, 158, 11, 0.1)", border: "1px solid var(--warning)" }}>
                <div style={{ fontSize: 24, fontWeight: 900, color: "var(--warning)" }}>
                  {enhancedIssues.filter(i => i.breachRiskLevel === 'medium' && !i.isDeleted).length}
                </div>
                <div style={{ color: "var(--text-main)" }}>Medium Risk</div>
              </div>
              <div className="glass-panel" style={{ padding: 16, background: "rgba(16, 185, 129, 0.1)", border: "1px solid var(--success)" }}>
                <div style={{ fontSize: 24, fontWeight: 900, color: "var(--success)" }}>
                  {enhancedIssues.filter(i => i.breachRiskLevel === 'low' && !i.isDeleted).length}
                </div>
                <div style={{ color: "var(--text-main)" }}>Low Risk</div>
              </div>
            </div>
          </div>

          {/* STUCK INCIDENTS PANEL */}
          <div className="glass-panel" style={{ padding: 20, marginBottom: 16 }}>
            <h3 style={{ marginTop: 0, color: "var(--text-main)" }}>🚨 Stuck Incidents Panel</h3>
            {stuckIncidents.length === 0 ? (
              <div style={{ color: "var(--text-muted)", textAlign: "center", padding: 20 }}>
                No stuck incidents detected
              </div>
            ) : (
              <div style={{ display: "grid", gap: 12 }}>
                {stuckIncidents.map(issue => (
                  <div key={issue.id} className="glass-panel" style={{ 
                    padding: 12, 
                    background: "rgba(239, 68, 68, 0.1)", 
                    border: "1px solid var(--danger)" 
                  }}>
                    <div style={{ display: "flex", justifyContent: "space-between" }}>
                      <div>
                        <div style={{ fontWeight: 900, color: "var(--text-main)" }}>{issue.title}</div>
                        <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 4 }}>
                          {issue.category} • {issue.location} • Assigned to: {getAnalystDisplayLabel(issue.assignedTo, users)}
                        </div>
                      </div>
                      {hasPermission(userRole, 'assign_incident') && (
                        <button 
                          onClick={() => {
                            const newAnalyst = prompt("Reassign to:", issue.assignedTo);
                            if (newAnalyst && newAnalyst !== issue.assignedTo && issue.locked !== true) {
                              assignIssue(issue, newAnalyst);
                            }
                          }}
                          disabled={issue.locked === true}
                          className="btn-primary"
                          style={{ 
                            padding: "6px 12px", fontSize: 12,
                            opacity: issue.locked === true ? 0.5 : 1,
                            cursor: issue.locked === true ? "not-allowed" : "pointer"
                          }}
                        >
                          Reassign
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* CAMPAIGN CLUSTERS PANEL */}
          <div className="glass-panel" style={{ padding: 20, marginBottom: 16 }}>
            <h3 style={{ marginTop: 0, color: "var(--text-main)" }}>🎯 Campaign Clusters Panel</h3>
            {clusters.length === 0 ? (
              <div style={{ color: "var(--text-muted)", textAlign: "center", padding: 20 }}>
                No campaign clusters detected
              </div>
            ) : (
              <div style={{ display: "grid", gap: 12 }}>
                {clusters.map(cluster => (
                  <div key={cluster.id} className="glass-panel" style={{ 
                    padding: 12, 
                    background: "rgba(139, 92, 246, 0.1)", 
                    border: "1px solid rgba(139, 92, 246, 0.3)" 
                  }}>
                    <div style={{ fontWeight: 900, color: "var(--text-main)" }}>
                      🚨 Campaign Cluster: {cluster.count} incidents linked
                    </div>
                    <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 4 }}>
                      {cluster.category} • {cluster.location} • Started: {formatTimeAgo(tsToMillis(cluster.createdAt))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* MTTR LEADERBOARD */}
          <div className="glass-panel" style={{ padding: 20, marginBottom: 16 }}>
            <h3 style={{ marginTop: 0, color: "var(--text-main)" }}>🏆 MTTR Leaderboard</h3>
            <div style={{ display: "grid", gap: 8 }}>
              {Object.entries(mttaMttrStats.analyst)
                .sort(([,a], [,b]) => {
                  const aMinutes = parseInt(a.avgMTTR) || 9999;
                  const bMinutes = parseInt(b.avgMTTR) || 9999;
                  return aMinutes - bMinutes;
                })
                .slice(0, 5)
                .map(([uid, stats], index) => (
                  <div key={uid} className="glass-panel" style={{ 
                    padding: 12, 
                    background: index === 0 ? "rgba(255, 215, 0, 0.1)" : "rgba(0, 0, 0, 0.2)",
                    border: index === 0 ? "1px solid gold" : "1px solid var(--glass-border)"
                  }}>
                    <div style={{ display: "flex", justifyContent: "space-between" }}>
                      <div>
                        <span style={{ fontSize: 18, marginRight: 8 }}>
                          {index === 0 ? "🥇" : index === 1 ? "🥈" : index === 2 ? "🥉" : "🏅"}
                        </span>
                        <span style={{ fontWeight: 900, color: "var(--text-main)" }}>
                          {users[uid]?.email || uid}
                        </span>
                      </div>
                      <div style={{ textAlign: "right" }}>
                        <div style={{ fontWeight: 900, color: "var(--success)" }}>{stats.avgMTTR}</div>
                        <div style={{ fontSize: 12, color: "var(--text-muted)" }}>{stats.count} cases</div>
                      </div>
                    </div>
                  </div>
                ))}
            </div>
          </div>

          {/* MITRE TECHNIQUE FREQUENCY */}
          <div className="glass-panel" style={{ padding: 20, marginBottom: 16 }}>
            <h3 style={{ marginTop: 0, color: "var(--text-main)" }}>🛡 MITRE Technique Frequency</h3>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 12 }}>
              {Object.entries(
                enhancedIssues.reduce((acc, issue) => {
                  if (!issue.isDeleted && issue.technique) {
                    acc[issue.technique] = (acc[issue.technique] || 0) + 1;
                  }
                  return acc;
                }, {})
              ).map(([technique, count]) => {
                const mitreInfo = Object.values(MITRE_MAPPING).find(m => m.technique === technique);
                return (
                  <div key={technique} className="glass-panel" style={{ padding: 12, background: "rgba(0, 0, 0, 0.2)" }}>
                    <div style={{ fontWeight: 900, color: "var(--text-main)" }}>{technique}</div>
                    <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 4 }}>
                      {mitreInfo?.name || technique}
                    </div>
                    <div style={{ fontSize: 18, fontWeight: 900, color: "var(--primary)", marginTop: 4 }}>
                      {count} incidents
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </>
      ) : (
        // Basic content for non-admin users
        <div style={{ textAlign: "center", padding: "40px" }}>
          <h3 style={{ color: "var(--text-main)", marginBottom: "20px" }}>👤 Analyst Dashboard</h3>
          <p style={{ color: "var(--text-muted)", fontSize: "16px" }}>
            You have analyst access. Admin and SOC Manager features require elevated permissions.
          </p>
        </div>
      )}

      {/* OPS HIGHLIGHTS */}
      <div className="glass-panel" style={{ padding: 20, marginBottom: 16 }}>
        <div style={{ display: "flex", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}>
          <div>
            <b style={{ fontSize: 14, color: "var(--text-main)" }}>Live Security Operations</b>
            <div style={{ fontSize: 12, opacity: 0.75, color: "var(--text-muted)" }}>Active cyber incidents & response</div>
          </div>

          <button onClick={() => setGalleryOpen(true)} style={{ background: "var(--primary)", color: "#fff", border: "none", padding: "10px 16px", borderRadius: 12, fontWeight: 600 }}>
            Open Evidence Gallery
          </button>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 12, marginTop: 12 }}>
          <div style={{ background: "rgba(0, 0, 0, 0.2)", borderRadius: 12, padding: 16, border: "1px solid var(--glass-border)" }}>
            <b style={{ color: "var(--text-main)" }}>Highest Risk Incident</b>
            <div style={{ marginTop: 6, fontSize: 13 }}>
              {opsHighlights.urgent ? (
                <>
                  <div><b style={{ color: "var(--text-main)" }}>{opsHighlights.urgent.title}</b></div>
                  <div style={{ opacity: 0.8, marginTop: 4, color: "var(--text-muted)" }}>
                    {opsHighlights.urgent.category} • {opsHighlights.urgent.location} • {opsHighlights.urgent.urgency}
                  </div>
                </>
              ) : "—"}
            </div>
          </div>

          <div style={{ background: "rgba(239, 68, 68, 0.1)", borderRadius: 12, padding: 16, border: "1px solid rgba(239, 68, 68, 0.3)" }}>
            <b style={{ color: "var(--text-main)" }}>SLA Breached</b>
            <div style={{ marginTop: 6, fontSize: 28, fontWeight: 900, color: topStats.breached ? "var(--danger)" : "var(--success)" }}>
              {topStats.breached}
            </div>
          </div>

          <div style={{ background: "rgba(6, 182, 212, 0.1)", borderRadius: 12, padding: 16, border: "1px solid rgba(6, 182, 212, 0.3)" }}>
            <b style={{ color: "var(--text-main)" }}>Most Targeted System</b>
            <div style={{ marginTop: 6, fontSize: 13 }}>
              {opsHighlights.hotspot ? (
                <>
                  <div><b style={{ color: "var(--text-main)" }}>{opsHighlights.hotspot.location}</b></div>
                  <div style={{ opacity: 0.8, marginTop: 4, color: "var(--text-muted)" }}>{opsHighlights.hotspot.count} total issues</div>
                </>
              ) : "—"}
            </div>
          </div>

          <div style={{ background: "rgba(139, 92, 246, 0.1)", borderRadius: 12, padding: 16, border: "1px solid rgba(139, 92, 246, 0.3)" }}>
            <b style={{ color: "var(--text-main)" }}>Most Loaded Analyst</b>
            <div style={{ marginTop: 6, fontSize: 13 }}>
              {opsHighlights.topStaff ? (
                <>
                  <div><b style={{ color: "var(--text-main)" }}>{getAnalystDisplayLabel(opsHighlights.topStaff.staff, users)}</b></div>
                  <div style={{ opacity: 0.8, marginTop: 4, color: "var(--text-muted)" }}>{opsHighlights.topStaff.count} assigned tickets</div>
                </>
              ) : "—"}
            </div>
          </div>
        </div>
      </div>

      {/* TOP STATS */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 12, marginBottom: 16 }}>
        <div className="glass-panel" style={{ padding: 16, textAlign: "center" }}><b style={{ color: "var(--text-main)" }}>Open</b><div style={{ fontSize: 26, fontWeight: 900, color: "var(--text-main)" }}>{topStats.open}</div></div>
        <div className="glass-panel" style={{ padding: 16, textAlign: "center" }}><b style={{ color: "var(--text-main)" }}>Assigned</b><div style={{ fontSize: 26, fontWeight: 900, color: "var(--text-main)" }}>{topStats.assigned}</div></div>
        <div className="glass-panel" style={{ padding: 16, textAlign: "center" }}><b style={{ color: "var(--text-main)" }}>In Progress</b><div style={{ fontSize: 26, fontWeight: 900, color: "var(--text-main)" }}>{topStats.inProgress}</div></div>
        <div className="glass-panel" style={{ padding: 16, textAlign: "center" }}><b style={{ color: "var(--text-main)" }}>Resolved</b><div style={{ fontSize: 26, fontWeight: 900, color: "var(--success)" }}>{topStats.resolved}</div></div>
        <div className="glass-panel" style={{ padding: 16, textAlign: "center", background: "rgba(245, 158, 11, 0.1)", border: "1px solid rgba(245, 158, 11, 0.3)" }}><b style={{ color: "var(--text-main)" }}>SLA Breached</b><div style={{ fontSize: 26, fontWeight: 900, color: "var(--warning)" }}>{topStats.breached}</div></div>
        <div className="glass-panel" style={{ padding: 16, textAlign: "center", background: "rgba(239, 68, 68, 0.1)", border: "1px solid rgba(239, 68, 68, 0.3)" }}><b style={{ color: "var(--text-main)" }}>Escalated</b><div style={{ fontSize: 26, fontWeight: 900, color: "var(--danger)" }}>{topStats.escalated}</div></div>
      </div>

      {/* AI SUMMARY */}
      <div className="glass-panel" style={{ padding: 20, marginBottom: 16 }}>
        <div style={{ display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
          <button onClick={generateWeeklySummary} disabled={aiLoading} className="btn-primary">
            {aiLoading ? "Generating..." : "Generate Weekly Summary"}
          </button>
          <span style={{ fontSize: 12, opacity: 0.7, color: "var(--text-muted)" }}>Accurate stats + AI narration</span>
        </div>

        {aiSummary && (
          <div style={{ marginTop: 10 }}>
            <strong style={{ color: "var(--text-main)" }}>Weekly Summary</strong>
            <p style={{ marginTop: 6, whiteSpace: "pre-line", color: "var(--text-muted)" }}>{aiSummary}</p>
          </div>
        )}
      </div>

      {/* HEATMAP */}
      <div className="glass-panel" style={{ padding: 20, marginBottom: 16 }}>
        <h3 style={{ marginTop: 0, color: "var(--text-main)" }}>Issue Distribution</h3>
        <table border="1" cellPadding="8" style={{ width: "100%", background: "rgba(0, 0, 0, 0.2)", borderRadius: 8 }}>
          <tbody>
            {Object.entries(hostelCounts).map(([k, v]) => (
              <tr key={k} style={{ borderBottom: "1px solid var(--glass-border)" }}>
                <td style={{ padding: "8px 12px", color: "var(--text-muted)" }}>{k}</td>
                <td style={{ padding: "8px 12px", textAlign: "center", fontWeight: 900, color: "var(--text-main)" }}>{v}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* FILTERS */}
      <div className="glass-panel" style={{ padding: 20, marginBottom: 16 }}>
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
          <select onChange={(e) => setFilterStatus(e.target.value)} value={filterStatus} className="glass-panel" style={{ padding: "8px 12px", border: "1px solid var(--glass-border)", background: "rgba(0, 0, 0, 0.3)", color: "var(--text-main)" }}>
            <option value="all" style={{ background: "#000" }}>All Status</option>
            <option value="open" style={{ background: "#000" }}>Open</option>
            <option value="assigned" style={{ background: "#000" }}>Assigned</option>
            <option value="in_progress" style={{ background: "#000" }}>In Progress</option>
            <option value="resolved" style={{ background: "#000" }}>Resolved</option>
          </select>

          <select onChange={(e) => setFilterCategory(e.target.value)} value={filterCategory} className="glass-panel" style={{ padding: "8px 12px", border: "1px solid var(--glass-border)", background: "rgba(0, 0, 0, 0.3)", color: "var(--text-main)" }}>
            <option value="all" style={{ background: "#000" }}>All Categories</option>
            <option value="phishing" style={{ background: "#000" }}>Phishing</option>
            <option value="malware" style={{ background: "#000" }}>Malware</option>
            <option value="account_compromise" style={{ background: "#000" }}>Account Compromise</option>
            <option value="data_leak" style={{ background: "#000" }}>Data Leak</option>
            <option value="network_attack" style={{ background: "#000" }}>Network Attack</option>
          </select>

          <select onChange={(e) => setFilterUrgency(e.target.value)} value={filterUrgency} className="glass-panel" style={{ padding: "8px 12px", border: "1px solid var(--glass-border)", background: "rgba(0, 0, 0, 0.3)", color: "var(--text-main)" }}>
            <option value="all" style={{ background: "#000" }}>All Urgency</option>
            <option value="high" style={{ background: "#000" }}>High</option>
            <option value="medium" style={{ background: "#000" }}>Medium</option>
            <option value="low" style={{ background: "#000" }}>Low</option>
          </select>

          <select onChange={(e) => setFilterAssignedTo(e.target.value)} value={filterAssignedTo} className="glass-panel" style={{ padding: "8px 12px", border: "1px solid var(--glass-border)", background: "rgba(0, 0, 0, 0.3)", color: "var(--text-main)", borderRadius: 8 }}>
            <option value="all" style={{ background: "#000" }}>All Assigned</option>
            <option value="unassigned" style={{ background: "#000" }}>Unassigned Only</option>
            {STAFF_OPTIONS.map((s) => (
              <option key={s.value} value={s.value} style={{ background: "#000" }}>
                {s.label}
              </option>
            ))}
          </select>

          <label style={{ display: "flex", gap: 6, alignItems: "center", color: "var(--text-muted)" }}>
            <input type="checkbox" checked={onlyUnassigned} onChange={(e) => setOnlyUnassigned(e.target.checked)} />
            Show only unassigned
          </label>

          <label style={{ display: "flex", gap: 6, alignItems: "center", color: "var(--text-muted)" }}>
            <input type="checkbox" checked={showDeleted} onChange={(e) => setShowDeleted(e.target.checked)} />
            Show deleted
          </label>
        </div>
      </div>

      {/* ISSUES GRID */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(360px, 1fr))", gap: 14 }}>
        {sortedIssues.map((issue) => {
          const isLockedVar = issue.locked === true;
          const slaFlag = getSlaFlag(issue);
          const slaDisplay = getSlaDisplay(issue);
          const isUnassigned = !issue.assignedTo;
          const createdMs = tsToMillis(issue.createdAt);
          const updatedMs = tsToMillis(issue.updatedAt);
          const canEscalate = slaDisplay.breached && !issue.escalated && !issue.isDeleted;
          const needsAttn = needsAttention(issue);

          return (
            <div 
              key={issue.id} 
              className="glass-panel"
              style={{ 
                border: slaDisplay.breached ? "2px solid var(--danger)" : "1px solid var(--glass-border)", 
                padding: 16, 
                borderRadius: 14, 
                boxShadow: "var(--glass-shadow)",
                background: slaDisplay.breached ? "rgba(239, 68, 68, 0.1)" : "var(--glass-bg)"
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", gap: 12 }}>
                <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    {/* Phase 4: Selection Checkbox */}
                    <input
                      type="checkbox"
                      checked={selectedIds.has(issue.id)}
                      onChange={e => {
                        const next = new Set(selectedIds);
                        if (e.target.checked) next.add(issue.id);
                        else next.delete(issue.id);
                        setSelectedIds(next);
                      }}
                      style={{ width: 16, height: 16, cursor: "pointer", accentColor: "var(--primary)" }}
                    />
                    <strong style={{ fontSize: 15, color: "var(--text-main)" }}>{issue.title}</strong>
                    {issue.locked && (
                      <span style={{
                        background:"#ef4444",
                        padding:"4px 8px",
                        borderRadius:"6px",
                        marginLeft:"8px",
                        fontSize:"12px"
                      }}>
                        🔒 Governance Locked
                      </span>
                    )}
                    {needsAttn && (
                      <span style={{ 
                        background: "var(--warning)", 
                        color: "#fff", 
                        padding: "2px 8px", 
                        borderRadius: 12, 
                        fontSize: 10, 
                        fontWeight: 900 
                      }}>
                        ⚠ NEEDS ATTENTION
                      </span>
                    )}
                  </div>

                  <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                    <span style={statusPill(issue.status)}>{issue.status?.toUpperCase() || "STATUS"}</span>
                    <span style={urgencyPill(issue.urgency)}>⚡ {issue.urgency?.toUpperCase() || "URGENCY"}</span>
                    <span style={pillStyle(
                      slaFlag === "overdue" ? "#b71c1c" : slaFlag === "delayed" ? "#f57c00" : "#1b5e20"
                    )}>⏱ {slaFlag.toUpperCase()}</span>
                    {issue.escalated && <span style={pillStyle("#000")}>🚨 ESCALATED</span>}
                    {issue.breachRiskLevel === 'high' && (
                      <span style={pillStyle("#d32f2f")}>⚠ HIGH SLA RISK</span>
                    )}
                    {issue.stuck && (
                      <span style={pillStyle("#ff6f00")}>🚫 STUCK</span>
                    )}
                    {issue.technique && (
                      <span style={pillStyle("#6a1b9a")}>🛡 {issue.technique}</span>
                    )}
                  </div>
                </div>
              </div>

              <div style={{ marginTop: 10, display: "grid", gap: 6 }}>
                <div style={{ display: "flex", justifyContent: "space-between", gap: 10 }}>
                  <span style={{ opacity: 0.8, color: "var(--text-muted)" }}>🕒 Reported: <b style={{ color: "var(--text-main)" }}>{formatTimeAgo(createdMs)}</b></span>
                  <span style={{ opacity: 0.8, color: "var(--text-muted)" }}>♻ Updated: <b style={{ color: "var(--text-main)" }}>{updatedMs ? formatTimeAgo(updatedMs) : "—"}</b></span>
                </div>

                <div style={{ fontWeight: 900, color: slaDisplay.color }}>{slaDisplay.label}</div>

                {issue.locked && (
                  <div style={{color:"#f87171"}}>
                    SOC Manager Governance Lock Active
                  </div>
                )}

                {issue.predictedBreachRiskScore && (
                  <div style={{ 
                    fontSize: 12, 
                    color: issue.breachRiskLevel === 'high' ? 'var(--danger)' : 
                           issue.breachRiskLevel === 'medium' ? 'var(--warning)' : 'var(--success)',
                    fontWeight: 900 
                  }}>
                    🎯 SLA Breach Risk: {issue.predictedBreachRiskScore} ({issue.breachRiskLevel?.toUpperCase()})
                  </div>
                )}

                <div style={{ display: "flex", flexWrap: "wrap", gap: 10 }}>
                  <span style={{ color: "var(--text-muted)" }}>🧠 Threat Type: <b style={{ color: "var(--text-main)" }}>{issue.category}</b></span>
                  <span style={{ color: "var(--text-muted)" }}>💻 Affected System: <b style={{ color: "var(--text-main)" }}>{issue.location}</b></span>
                </div>

                <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
                  <span style={pillStyle("#263238")}>🛡 Analyst: {getAnalystDisplayLabel(issue.assignedTo, users)}</span>
                </div>

                {issue.evidenceImage?.url && (
                  <div style={{ marginTop: 10 }}>
                    <strong style={{ fontSize: 13, color: "var(--text-main)" }}>Evidence</strong>
                    <div style={{ marginTop: 6 }}>
                      <a href={issue.evidenceImage.url} target="_blank" rel="noreferrer">
                        <img
                          src={issue.evidenceImage.url}
                          alt="evidence"
                          style={{
                            width: "100%",
                            maxHeight: 220,
                            objectFit: "cover",
                            borderRadius: 12,
                            border: "1px solid var(--glass-border)"
                          }}
                        />
                      </a>
                    </div>
                  </div>
                )}
              </div>

              {isUnassigned && issue.status === "open" && (
                <div style={{ marginTop: 12 }}>
                  <select
                    disabled={issue.locked === true}
                    style={{
                      opacity: issue.locked === true ? 0.5 : 1,
                      cursor: issue.locked === true ? "not-allowed" : "pointer",
                      width: "100%", 
                      padding: 10, 
                      borderRadius: 10, 
                      border: "1px solid var(--glass-border)", 
                      background: "rgba(0, 0, 0, 0.3)", 
                      color: "var(--text-main)" 
                    }}
                    onChange={(e) => {
                      const v = e.target.value;
                      if (v && issue.locked !== true) assignIssue(issue, v);
                    }}
                    className="glass-panel"
                  >
                    <option value="" style={{ background: "#000" }}>Assign to...</option>
                    {generateUserOptions(users, userRole).map((userOption) => (
                      <option key={userOption.value} value={userOption.value} style={{ background: "#000" }}>
                        {userOption.label}
                      </option>
                    ))}
                  </select>
                </div>
              )}

              <div style={{ marginTop: 12, display: "flex", gap: 8, flexWrap: "wrap" }}>
                {issue.status === "assigned" && (
                  <>
                    <button 
                      disabled={issue.locked === true}
                      style={{
                        opacity: issue.locked === true ? 0.5 : 1,
                        cursor: issue.locked === true ? "not-allowed" : "pointer"
                      }}
                      onClick={issue.locked === true ? null : () => updateStatus(issue, "in_progress")}
                      className="btn-primary"
                    >Start Investigation</button>
                    <button 
                      disabled={issue.locked === true}
                      style={{
                        opacity: issue.locked === true ? 0.5 : 1,
                        cursor: issue.locked === true ? "not-allowed" : "pointer",
                        background: "var(--success)", 
                        color: "#fff", 
                        border: "none", 
                        padding: "8px 12px", 
                        borderRadius: 8 
                      }}
                      onClick={issue.locked === true ? null : () => updateStatus(issue, "resolved")}
                    >Resolve</button>
                  </>
                )}

                {issue.status === "in_progress" && (
                  <button 
                    disabled={issue.locked === true}
                      style={{
                        opacity: issue.locked === true ? 0.5 : 1,
                        cursor: issue.locked === true ? "not-allowed" : "pointer",
                        background: "var(--success)", 
                        color: "#fff", 
                        border: "none", 
                        padding: "8px 12px", 
                        borderRadius: 8 
                      }}
                      onClick={issue.locked === true ? null : () => updateStatus(issue, "resolved")}
                    >Mark Contained</button>
                )}

                {canEscalate && (
                  <button 
                    disabled={issue.locked === true}
                      style={{
                        opacity: issue.locked === true ? 0.5 : 1,
                        cursor: issue.locked === true ? "not-allowed" : "pointer",
                        background: "var(--warning)", 
                        color: "#fff", 
                        border: "none", 
                        padding: "8px 12px", 
                        borderRadius: 8 
                      }}
                      onClick={issue.locked === true ? null : () => escalateIssue(issue)}
                    >Escalate to SOC Lead</button>
                )}

                {issue.status === "resolved" && !issue.isDeleted && (
                  <button 
                    disabled={issue.locked === true}
                    style={{
                      opacity: issue.locked === true ? 0.5 : 1,
                      cursor: issue.locked === true ? "not-allowed" : "pointer",
                      background: "var(--danger)", 
                      color: "#fff", 
                      border: "none", 
                      padding: "8px 12px", 
                      borderRadius: 8 
                    }}
                    onClick={issue.locked === true ? null : () => deleteResolvedIssue(issue)}
                  >Archive Incident</button>
                )}

                {issue.isDeleted && (
                  <span style={{ fontSize: 12, opacity: 0.7, color: "var(--text-muted)" }}>🗑 Deleted</span>
                )}

                {/* Phase 6: Investigate Button */}
                <button
                  onClick={() => setInvestigateIssue(issue)}
                  style={{
                    background: "linear-gradient(135deg, #06b6d4, #8b5cf6)",
                    color: "#fff", border: "none",
                    padding: "8px 12px", borderRadius: 8,
                    cursor: "pointer", fontSize: 12, fontWeight: 700,
                  }}
                >🔍 Investigate</button>
              </div>

              <div style={{ marginTop: 12, paddingTop: 10, borderTop: "1px dashed var(--glass-border)" }}>
                <strong style={{ fontSize: 13, color: "var(--text-main)" }}>Incident Timeline</strong>
                <ul style={{ marginTop: 8, paddingLeft: 18 }}>
                  {(issue.statusHistory || []).slice().reverse().map((h, idx) => (
                    <li key={idx} style={{ fontSize: 12, marginBottom: 6, opacity: 0.9, color: "var(--text-muted)" }}>
                      <b style={{ color: "var(--text-main)" }}>{String(h.status).toUpperCase()}</b> — {formatClock(h.at)}
                      {h.note ? ` — ${h.note}` : ""}
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          );
        })}
      </div>

      {/* ✅ DARK PREMIUM EVIDENCE GALLERY */}
      {galleryOpen && (
        <div
          onClick={() => {
            setGallerySelected(null);
            setGalleryOpen(false);
          }}
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(0,0,0,0.65)",
            zIndex: 9999,
            padding: 20,
            overflowY: "auto"
          }}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            style={{
              maxWidth: 1100,
              margin: "0 auto",
              background: "rgba(18,18,18,0.92)",
              border: "1px solid rgba(255,255,255,0.12)",
              backdropFilter: "blur(16px)",
              WebkitBackdropFilter: "blur(16px)",
              borderRadius: 18,
              padding: 16,
              color: "#fff",
              boxShadow: "0 18px 60px rgba(0,0,0,0.55)"
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}>
              <div>
                <b style={{ fontSize: 16 }}>Threat Evidence</b>
                <div style={{ fontSize: 12, opacity: 0.75 }}>Visual proof of issues (click image to inspect)</div>
              </div>

              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                <select value={galleryCategory} onChange={(e) => setGalleryCategory(e.target.value)} style={darkSelectStyle}>
                  <option value="all">All Categories</option>
                  <option value="phishing">Phishing</option>
                  <option value="malware">Malware</option>
                  <option value="account_compromise">Account Compromise</option>
                  <option value="data_leak">Data Leak</option>
                  <option value="network_attack">Network Attack</option>
                </select>

                <select value={galleryUrgency} onChange={(e) => setGalleryUrgency(e.target.value)} style={darkSelectStyle}>
                  <option value="all">All Urgency</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>

                <button
                  onClick={() => {
                    setGallerySelected(null);
                    setGalleryOpen(false);
                  }}
                  style={darkBtnStyle}
                >
                  Close
                </button>
              </div>
            </div>

            {/* Grid */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))", gap: 12, marginTop: 14 }}>
              {evidenceIssues.length === 0 && (
                <div style={{ opacity: 0.75, padding: 10 }}>
                  No evidence images found for selected filters.
                </div>
              )}

              {evidenceIssues.map((i) => (
                <div
                  key={i.id}
                  style={{
                    border: "1px solid rgba(255,255,255,0.12)",
                    borderRadius: 16,
                    overflow: "hidden",
                    cursor: "pointer",
                    background: "rgba(255,255,255,0.06)",
                    color: "#fff",
                    boxShadow: "0 10px 30px rgba(0,0,0,0.25)",
                    transition: "transform 180ms ease, box-shadow 180ms ease"
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.transform = "translateY(-4px)";
                    e.currentTarget.style.boxShadow = "0 16px 40px rgba(0,0,0,0.38)";
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.transform = "translateY(0px)";
                    e.currentTarget.style.boxShadow = "0 10px 30px rgba(0,0,0,0.25)";
                  }}
                  onClick={() => setGallerySelected(i)}
                >
                  <img
                    src={i.evidenceImage.url}
                    alt="evidence"
                    style={{ width: "100%", height: 160, objectFit: "cover" }}
                  />
                  <div style={{ padding: 10 }}>
                    <div style={{ fontWeight: 900, fontSize: 13 }}>{i.title}</div>
                    <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 8 }}>
                      <span style={statusPill(i.status)}>{String(i.status).toUpperCase()}</span>
                      <span style={urgencyPill(i.urgency)}>{String(i.urgency).toUpperCase()}</span>
                    </div>
                    <div style={{ fontSize: 12, opacity: 0.8, marginTop: 8 }}>
                      {i.category} • {i.location}
                    </div>
                  </div>
                </div>
              ))}
            </div>

            {/* Selected inspector */}
            {gallerySelected && (
              <div style={{ marginTop: 16, borderTop: "1px solid rgba(255,255,255,0.12)", paddingTop: 14 }}>
                <b style={{ fontSize: 14 }}>Inspection</b>

                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginTop: 10 }}>
                  <div>
                    <img
                      src={gallerySelected.evidenceImage.url}
                      alt="selected evidence"
                      style={{
                        width: "100%",
                        maxHeight: 360,
                        objectFit: "cover",
                        borderRadius: 16,
                        border: "1px solid rgba(255,255,255,0.12)"
                      }}
                    />
                  </div>

                  <div style={{ display: "grid", gap: 10 }}>
                    <div style={{ fontSize: 18, fontWeight: 900 }}>{gallerySelected.title}</div>

                    <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                      <span style={statusPill(gallerySelected.status)}>{String(gallerySelected.status).toUpperCase()}</span>
                      <span style={urgencyPill(gallerySelected.urgency)}>{String(gallerySelected.urgency).toUpperCase()}</span>
                      {gallerySelected.escalated && <span style={pillStyle("#000")}>🚨 ESCALATED</span>}
                      <span style={pillStyle("#263238")}>👷 {getAnalystDisplayLabel(gallerySelected.assignedTo, users)}</span>
                    </div>

                    <div style={{ opacity: 0.9 }}>
                      📌 <b>{gallerySelected.category}</b> • 📍 <b>{gallerySelected.location}</b>
                    </div>

                    <div style={{ opacity: 0.9 }}>
                      🕒 Reported: <b>{formatTimeAgo(tsToMillis(gallerySelected.createdAt))}</b>
                    </div>

                    <div style={{ fontWeight: 900, color: getSlaDisplay(gallerySelected).color }}>
                      {getSlaDisplay(gallerySelected).label}
                    </div>

                    {gallerySelected.description && (
                      <div
                        style={{
                          padding: 10,
                          background: "rgba(255,255,255,0.06)",
                          border: "1px solid rgba(255,255,255,0.12)",
                          borderRadius: 14,
                          color: "#fff"
                        }}
                      >
                        {gallerySelected.description}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
      {/* Phase 6: Investigation Panel Overlay */}
      {investigateIssue && (
        <InvestigationPanel
          issue={investigateIssue}
          onClose={() => setInvestigateIssue(null)}
        />
      )}
    </div>
  );
}
