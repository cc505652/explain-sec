import { collection, query, where, onSnapshot, orderBy } from "firebase/firestore";
import { useEffect, useMemo, useState } from "react";
import { auth, db } from "./firebase";

/* ---------- HELPERS ---------- */

const statusLabel = (s) => {
  if (s === "open") return "Open";
  if (s === "assigned") return "Assigned";
  if (s === "in_progress") return "In Progress";
  if (s === "resolved") return "Resolved";
  if (s === "merged") return "Merged";
  if (s === "deleted") return "Deleted";
  if (s === "escalated") return "Escalated";
  return s || "Unknown";
};

const assignedLabel = (v) => {
  if (!v) return "Unassigned";
  if (v === "plumber") return "Plumber";
  if (v === "electrician") return "Electrician";
  if (v === "wifi_team") return "WiFi/Network Team";
  if (v === "mess_supervisor") return "Mess Supervisor";
  if (v === "maintenance") return "Maintenance/Carpenter";
  if (v === "system") return "Auto-Routed";
  return v;
};

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

function pillStyle(bg, fg = "#fff") {
  return {
    background: bg,
    color: fg,
    padding: "4px 10px",
    borderRadius: 999,
    fontSize: 12,
    fontWeight: 800,
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

/* ---------- COMPONENT ---------- */

export default function IssueList() {
  const [issues, setIssues] = useState([]);
  const [sortMode, setSortMode] = useState("newest"); // newest | priority
  const [nowTick, setNowTick] = useState(Date.now());

  // live refresh tick for "12 min ago"
  useEffect(() => {
    const t = setInterval(() => setNowTick(Date.now()), 60 * 1000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    const unsubscribeAuth = auth.onAuthStateChanged((user) => {
      if (!user) return;

      const q = query(
        collection(db, "issues"),
        where("createdBy", "==", user.uid),
        orderBy("createdAt", "desc")
      );

      const unsubscribeSnapshot = onSnapshot(q, (snapshot) => {
        const data = snapshot.docs.map((doc) => ({
          id: doc.id,
          ...doc.data()
        }));

        // ✅ hide deleted issues from students
        setIssues(data.filter((i) => !i.isDeleted));
        console.log("REALTIME UPDATE: IssueList updated", data.length);
      }, (error) => {
        console.error("Firestore listener error (IssueList):", error);
      });

      return () => unsubscribeSnapshot();
    });

    return () => unsubscribeAuth();
  }, []);

  // sort
  const displayIssues = useMemo(() => {
    void nowTick;

    return [...issues].sort((a, b) => {
      if (sortMode !== "priority") {
        const aTime = tsToMillis(a.createdAt);
        const bTime = tsToMillis(b.createdAt);
        return bTime - aTime;
      }

      const aScore = a.urgencyScore ?? 0;
      const bScore = b.urgencyScore ?? 0;
      if (bScore !== aScore) return bScore - aScore;

      const aTime = tsToMillis(a.createdAt);
      const bTime = tsToMillis(b.createdAt);
      return bTime - aTime;
    });
  }, [issues, sortMode, nowTick]);

  return (
    <div style={{ padding: 16 }}>
      <h2>My Reported Security Incidents</h2>

      <div style={{ marginBottom: 12, display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
        <label style={{ fontWeight: 800 }}>Sort:</label>
        <select value={sortMode} onChange={(e) => setSortMode(e.target.value)}>
          <option value="newest">Newest</option>
          <option value="priority">Priority (High → Low)</option>
        </select>
      </div>

      {displayIssues.length === 0 && <p>No issues yet.</p>}

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(360px, 1fr))", gap: 14 }}>
        {displayIssues.map((issue) => {
          const createdMs = tsToMillis(issue.createdAt);
          const updatedMs = tsToMillis(issue.updatedAt);

          return (
            <div
              key={issue.id}
              style={{
                border: "1px solid #ddd",
                padding: 14,
                borderRadius: 14,
                boxShadow: "0 6px 16px rgba(0,0,0,0.04)"
              }}
            >
              {/* HEADER */}
              <div style={{ display: "flex", justifyContent: "space-between", gap: 12 }}>
                <strong style={{ fontSize: 15 }}>{issue.title}</strong>
              </div>

              {/* BADGES */}
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 10 }}>
                <span style={statusPill(issue.status)}>{(issue.status || "status").toUpperCase()}</span>
                <span style={urgencyPill(issue.urgency)}>
                  ⚡ {(issue.urgency || "urgency").toUpperCase()}
                </span>

                {issue.escalated && (
                  <span style={pillStyle("#000")}>🚨 ESCALATED</span>
                )}

                <span style={pillStyle("#263238")}>👷 {assignedLabel(issue.assignedTo)}</span>
              </div>

              {/* META */}
              <div style={{ marginTop: 10, display: "grid", gap: 6, fontSize: 13 }}>
                <div style={{ display: "flex", justifyContent: "space-between", gap: 10 }}>
                  <span style={{ opacity: 0.8 }}>
                    🕒 Reported: <b>{formatTimeAgo(createdMs)}</b>
                  </span>
                  <span style={{ opacity: 0.8 }}>
                    ♻ Updated: <b>{updatedMs ? formatTimeAgo(updatedMs) : "—"}</b>
                  </span>
                </div>

                <div style={{ display: "flex", flexWrap: "wrap", gap: 10 }}>
                  <span>🧠 Threat Type: <b>{issue.category}</b></span>
                  <span>💻 Affected System: <b>{issue.location}</b></span>

                </div>
              </div>

              {/* DESCRIPTION */}
              {issue.description && (
                <p style={{ marginTop: 10, marginBottom: 0, opacity: 0.9 }}>
                  {issue.description}
                </p>
              )}

              {/* ✅ Evidence Image */}
              {issue.evidenceImage?.url && (
                <div style={{ marginTop: 12 }}>
                  <strong style={{ fontSize: 13 }}>Threat Evidence</strong>
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

              {/* ✅ Auto-tagging reason */}
              {issue.autoReason && (
                <p style={{ marginTop: 10, fontSize: 12, opacity: 0.7 }}>
                  🤖 Auto-tagging: {issue.autoReason}
                </p>
              )}

              {/* ✅ TIMELINE */}
              <div style={{ marginTop: 12, paddingTop: 10, borderTop: "1px dashed #ddd" }}>
                <strong style={{ fontSize: 13 }}>Incident Timeline</strong>
                <ul style={{ marginTop: 8, paddingLeft: 18 }}>
                  {(issue.statusHistory || [])
                    .slice()
                    .reverse()
                    .map((h, idx) => (
                      <li key={idx} style={{ fontSize: 12, marginBottom: 6, opacity: 0.9 }}>
                        <b>{statusLabel(h.status).toUpperCase()}</b> — {formatClock(h.at)}
                        {h.note ? ` — ${h.note}` : ""}
                      </li>
                    ))}
                </ul>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
