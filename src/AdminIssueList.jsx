import {
  collection,
  onSnapshot,
  orderBy,
  query,
  updateDoc,
  doc,
  serverTimestamp,
  Timestamp
} from "firebase/firestore";
import { useEffect, useMemo, useState } from "react";
import { auth, db } from "./firebase";

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
        label: `SLA: ${formatDuration(remaining)} left`,
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
        label: `SLA: ${formatDuration(remaining)} left`,
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


function staffLabel(v) {
  const found = STAFF_OPTIONS.find((x) => x.value === v);
  return found ? found.label : v || "Unassigned";
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

export default function AdminIssueList() {
  const [issues, setIssues] = useState([]);

  // ✅ Live refresh tick
  const [nowTick, setNowTick] = useState(Date.now());
  useEffect(() => {
    const t = setInterval(() => setNowTick(Date.now()), 60 * 1000);
    return () => clearInterval(t);
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

  /* ---------- REALTIME FETCH ---------- */
  useEffect(() => {
    const unsubAuth = auth.onAuthStateChanged((user) => {
      if (!user) return;

      const q = query(
        collection(db, "issues"),
        orderBy("urgencyScore", "desc"),
        orderBy("createdAt", "desc")
      );

      const unsubSnap = onSnapshot(q, (snap) => {
        const data = snap.docs.map((d) => ({ id: d.id, ...d.data() }));
        setIssues(data);
        console.log("REALTIME UPDATE: AdminIssueList updated", data.length);
      }, (error) => {
        console.error("Firestore listener error (AdminIssueList):", error);
      });

      return () => unsubSnap();
    });

    return () => unsubAuth();
  }, []);

  /* ---------- STATUS UPDATE ---------- */
  const updateStatus = async (issue, nextStatus) => {
    await updateDoc(doc(db, "issues", issue.id), {
      status: nextStatus,
      statusHistory: [
        ...(issue.statusHistory || []),
        { status: nextStatus, at: Timestamp.now() }
      ],
      updatedAt: serverTimestamp()
    });
  };

  /* ---------- STAFF ASSIGN ---------- */
  const assignIssue = async (issue, assignedToValue) => {
    const user = auth.currentUser;

    await updateDoc(doc(db, "issues", issue.id), {
      assignedTo: assignedToValue,
      status: "assigned",
      assignedAt: serverTimestamp(),
      assignedBy: user?.uid || null,
      statusHistory: [
        ...(issue.statusHistory || []),
        {
          status: "assigned",
          at: Timestamp.now(),
          note: `Assigned to ${assignedToValue}`
        }
      ],
      updatedAt: serverTimestamp()
    });
  };

  /* ---------- ESCALATE ---------- */
  const escalateIssue = async (issue) => {
    const ok = window.confirm(`Escalate issue to SOC Manager?\n\n"${issue.title}"`);
    if (!ok) return;

    await updateDoc(doc(db, "issues", issue.id), {
      escalated: true,
      escalatedAt: serverTimestamp(),
      escalatedTo: "soc_manager",
      statusHistory: [
        ...(issue.statusHistory || []),
        { status: "escalated", at: Timestamp.now(), note: "Escalated to SOC Manager" }
      ],
      updatedAt: serverTimestamp()
    });
  };

  /* ---------- DELETE COMPLETED (SOFT DELETE) ---------- */
  const deleteResolvedIssue = async (issue) => {
    const ok = window.confirm(`Delete resolved issue?\n\n"${issue.title}"`);
    if (!ok) return;

    const user = auth.currentUser;

    await updateDoc(doc(db, "issues", issue.id), {
      isDeleted: true,
      deletedAt: serverTimestamp(),
      deletedBy: user?.uid || null,
      statusHistory: [
        ...(issue.statusHistory || []),
        { status: "deleted", at: Timestamp.now(), note: "Deleted by admin" }
      ],
      updatedAt: serverTimestamp()
    });
  };

  /* ---------- FILTER + SORT ---------- */
  const filtered = useMemo(() => {
    void nowTick;

    return issues.filter((i) => {
      if (!showDeleted && i.isDeleted) return false;

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
    issues,
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
  : "—"}

--- 

Note: AI narration has been disabled. This report uses accurate statistics only.
`.trim();

      // AI narration removed - using static summary only
      setAiSummary(accurateSummary);
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
      <h2 style={{ marginBottom: 10 }}>SOC Analyst Console</h2>

      {/* OPS HIGHLIGHTS */}
      <div style={{ border: "1px solid #ddd", borderRadius: 14, padding: 14, marginBottom: 16 }}>
        <div style={{ display: "flex", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}>
          <div>
            <b style={{ fontSize: 14 }}>Live Security Operations</b>
            <div style={{ fontSize: 12, opacity: 0.75 }}>Active cyber incidents & response</div>
          </div>

          <button onClick={() => setGalleryOpen(true)} style={{ background: "#000", color: "#fff" }}>
            Open Evidence Gallery
          </button>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 12, marginTop: 12 }}>
          <div style={{ border: "1px solid #eee", borderRadius: 12, padding: 12 }}>
            <b>Highest Risk Incident</b>
            <div style={{ marginTop: 6, fontSize: 13 }}>
              {opsHighlights.urgent ? (
                <>
                  <div><b>{opsHighlights.urgent.title}</b></div>
                  <div style={{ opacity: 0.8, marginTop: 4 }}>
                    {opsHighlights.urgent.category} • {opsHighlights.urgent.location} • {opsHighlights.urgent.urgency}
                  </div>
                </>
              ) : "—"}
            </div>
          </div>

          <div style={{ border: "1px solid #eee", borderRadius: 12, padding: 12 }}>
            <b>SLA Breached</b>
            <div style={{ marginTop: 6, fontSize: 28, fontWeight: 900, color: topStats.breached ? "#b71c1c" : "#1b5e20" }}>
              {topStats.breached}
            </div>
          </div>

          <div style={{ border: "1px solid #eee", borderRadius: 12, padding: 12 }}>
            <b>Most Targeted System</b>
            <div style={{ marginTop: 6, fontSize: 13 }}>
              {opsHighlights.hotspot ? (
                <>
                  <div><b>{opsHighlights.hotspot.location}</b></div>
                  <div style={{ opacity: 0.8, marginTop: 4 }}>{opsHighlights.hotspot.count} total issues</div>
                </>
              ) : "—"}
            </div>
          </div>

          <div style={{ border: "1px solid #eee", borderRadius: 12, padding: 12 }}>
            <b>Most Loaded Analyst</b>
            <div style={{ marginTop: 6, fontSize: 13 }}>
              {opsHighlights.topStaff ? (
                <>
                  <div><b>{staffLabel(opsHighlights.topStaff.staff)}</b></div>
                  <div style={{ opacity: 0.8, marginTop: 4 }}>{opsHighlights.topStaff.count} assigned tickets</div>
                </>
              ) : "—"}
            </div>
          </div>
        </div>
      </div>

      {/* TOP STATS */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 12, marginBottom: 16 }}>
        <div style={{ border: "1px solid #ddd", borderRadius: 12, padding: 12 }}><b>Open</b><div style={{ fontSize: 26 }}>{topStats.open}</div></div>
        <div style={{ border: "1px solid #ddd", borderRadius: 12, padding: 12 }}><b>Assigned</b><div style={{ fontSize: 26 }}>{topStats.assigned}</div></div>
        <div style={{ border: "1px solid #ddd", borderRadius: 12, padding: 12 }}><b>In Progress</b><div style={{ fontSize: 26 }}>{topStats.inProgress}</div></div>
        <div style={{ border: "1px solid #ddd", borderRadius: 12, padding: 12 }}><b>Resolved</b><div style={{ fontSize: 26 }}>{topStats.resolved}</div></div>
        <div style={{ border: "1px solid #ddd", borderRadius: 12, padding: 12, background: "#fff3e0" }}><b>SLA Breached</b><div style={{ fontSize: 26 }}>{topStats.breached}</div></div>
        <div style={{ border: "1px solid #ddd", borderRadius: 12, padding: 12, background: "#ffebee" }}><b>Escalated</b><div style={{ fontSize: 26 }}>{topStats.escalated}</div></div>
      </div>

      {/* AI SUMMARY */}
      <div style={{ border: "1px solid #ddd", padding: 12, borderRadius: 12, marginBottom: 16 }}>
        <div style={{ display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
          <button onClick={generateWeeklySummary} disabled={aiLoading}>
            {aiLoading ? "Generating..." : "Generate Weekly Summary"}
          </button>
          <span style={{ fontSize: 12, opacity: 0.7 }}>Accurate stats (AI narration disabled)</span>
        </div>

        {aiSummary && (
          <div style={{ marginTop: 10 }}>
            <strong>Weekly Summary</strong>
            <p style={{ marginTop: 6, whiteSpace: "pre-line" }}>{aiSummary}</p>
          </div>
        )}
      </div>

      {/* HEATMAP */}
      <div style={{ border: "1px solid #ddd", padding: 12, borderRadius: 12, marginBottom: 16 }}>
        <h3 style={{ marginTop: 0 }}>Issue Distribution</h3>
        <table border="1" cellPadding="6" style={{ width: "100%" }}>
          <tbody>
            {Object.entries(hostelCounts).map(([k, v]) => (
              <tr key={k}>
                <td>{k}</td>
                <td>{v}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* FILTERS */}
      <div style={{ border: "1px solid #ddd", padding: 12, borderRadius: 12, marginBottom: 16 }}>
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
          <select onChange={(e) => setFilterStatus(e.target.value)} value={filterStatus}>
            <option value="all">All Status</option>
            <option value="open">Open</option>
            <option value="assigned">Assigned</option>
            <option value="in_progress">In Progress</option>
            <option value="resolved">Resolved</option>
          </select>

          <select onChange={(e) => setFilterCategory(e.target.value)} value={filterCategory}>
            <option value="phishing">Phishing</option>
            <option value="malware">Malware</option>
            <option value="account_compromise">Account Compromise</option>
            <option value="data_leak">Data Leak</option>
            <option value="network_attack">Network Attack</option>

          </select>

          <select onChange={(e) => setFilterUrgency(e.target.value)} value={filterUrgency}>
            <option value="all">All Urgency</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          <select onChange={(e) => setFilterAssignedTo(e.target.value)} value={filterAssignedTo}>
            <option value="all">All Assigned</option>
            <option value="unassigned">Unassigned Only</option>
            {STAFF_OPTIONS.map((s) => (
              <option key={s.value} value={s.value}>{s.label}</option>
            ))}
          </select>

          <label style={{ display: "flex", gap: 6, alignItems: "center" }}>
            <input type="checkbox" checked={onlyUnassigned} onChange={(e) => setOnlyUnassigned(e.target.checked)} />
            Show only unassigned
          </label>

          <label style={{ display: "flex", gap: 6, alignItems: "center" }}>
            <input type="checkbox" checked={showDeleted} onChange={(e) => setShowDeleted(e.target.checked)} />
            Show deleted
          </label>
        </div>
      </div>

      {/* ISSUES GRID */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(360px, 1fr))", gap: 14 }}>
        {sortedIssues.map((issue) => {
          const slaFlag = getSlaFlag(issue);
          const slaDisplay = getSlaDisplay(issue);
          const isUnassigned = !issue.assignedTo;
          const createdMs = tsToMillis(issue.createdAt);
          const updatedMs = tsToMillis(issue.updatedAt);
          const canEscalate = slaDisplay.breached && !issue.escalated && !issue.isDeleted;

          return (
            <div key={issue.id} style={{ border: "1px solid #ddd", padding: 14, borderRadius: 14, boxShadow: "0 6px 16px rgba(0,0,0,0.04)" }}>
              <div style={{ display: "flex", justifyContent: "space-between", gap: 12 }}>
                <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                  <strong style={{ fontSize: 15 }}>{issue.title}</strong>

                  <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                    <span style={statusPill(issue.status)}>{issue.status?.toUpperCase() || "STATUS"}</span>
                    <span style={urgencyPill(issue.urgency)}>⚡ {issue.urgency?.toUpperCase() || "URGENCY"}</span>
                    <span style={pillStyle(
                      slaFlag === "overdue" ? "#b71c1c" : slaFlag === "delayed" ? "#f57c00" : "#1b5e20"
                    )}>⏱ {slaFlag.toUpperCase()}</span>
                    {issue.escalated && <span style={pillStyle("#000")}>🚨 ESCALATED</span>}
                  </div>
                </div>
              </div>

              <div style={{ marginTop: 10, display: "grid", gap: 6 }}>
                <div style={{ display: "flex", justifyContent: "space-between", gap: 10 }}>
                  <span style={{ opacity: 0.8 }}>🕒 Reported: <b>{formatTimeAgo(createdMs)}</b></span>
                  <span style={{ opacity: 0.8 }}>♻ Updated: <b>{updatedMs ? formatTimeAgo(updatedMs) : "—"}</b></span>
                </div>

                <div style={{ fontWeight: 900, color: slaDisplay.color }}>{slaDisplay.label}</div>

                <div style={{ display: "flex", flexWrap: "wrap", gap: 10 }}>
                  <span>🧠 Threat Type: <b>{issue.category}</b></span>
                  <span>💻 Affected System: <b>{issue.location}</b></span>
                </div>

                <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
                  <span style={pillStyle("#263238")}>🛡 Analyst: {staffLabel(issue.assignedTo)}</span>
                </div>

                {issue.evidenceImage?.url && (
                  <div style={{ marginTop: 10 }}>
                    <strong style={{ fontSize: 13 }}>Evidence</strong>
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
                            border: "1px solid #eee"
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
                    defaultValue=""
                    onChange={(e) => {
                      const v = e.target.value;
                      if (v) assignIssue(issue, v);
                    }}
                    style={{ width: "100%", padding: 10, borderRadius: 10 }}
                  >
                    <option value="">Assign to...</option>
                    {STAFF_OPTIONS.map((s) => (
                      <option key={s.value} value={s.value}>{s.label}</option>
                    ))}
                  </select>
                </div>
              )}

              <div style={{ marginTop: 12, display: "flex", gap: 8, flexWrap: "wrap" }}>
                {issue.status === "assigned" && (
                  <>
                    <button onClick={() => updateStatus(issue, "in_progress")}>Start Investigation</button>
                    <button onClick={() => updateStatus(issue, "resolved")}>Resolve</button>
                  </>
                )}

                {issue.status === "in_progress" && (
                  <button onClick={() => updateStatus(issue, "resolved")}>Mark Contained</button>
                )}

                {canEscalate && (
                  <button onClick={() => escalateIssue(issue)} style={{ background: "#000", color: "#fff" }}>
                    Escalate to SOC Lead
                  </button>
                )}

                {issue.status === "resolved" && !issue.isDeleted && (
                  <button onClick={() => deleteResolvedIssue(issue)} style={{ background: "#d32f2f", color: "#fff" }}>
                    Archive Incident
                  </button>
                )}

                {issue.isDeleted && (
                  <span style={{ fontSize: 12, opacity: 0.7 }}>🗑 Deleted</span>
                )}
              </div>

              <div style={{ marginTop: 12, paddingTop: 10, borderTop: "1px dashed #ddd" }}>
                <strong style={{ fontSize: 13 }}>Incident Timeline</strong>
                <ul style={{ marginTop: 8, paddingLeft: 18 }}>
                  {(issue.statusHistory || []).slice().reverse().map((h, idx) => (
                    <li key={idx} style={{ fontSize: 12, marginBottom: 6, opacity: 0.9 }}>
                      <b>{String(h.status).toUpperCase()}</b> — {formatClock(h.at)}
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
                  <option value="water">Water</option>
                  <option value="electricity">Electricity</option>
                  <option value="wifi">Wi-Fi</option>
                  <option value="mess">Mess</option>
                  <option value="maintenance">Maintenance</option>
                  <option value="other">Other</option>
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
                      <span style={pillStyle("#263238")}>👷 {staffLabel(gallerySelected.assignedTo)}</span>
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
    </div>
  );
}

