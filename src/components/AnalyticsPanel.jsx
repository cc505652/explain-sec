/**
 * ======================================================================
 * CAMPUS SOC — ANALYTICS PANEL (Phase 3)
 * ======================================================================
 * 
 * Full-featured SOC analytics dashboard with:
 * - Role-based access matrix
 * - MTTA/MTTR KPIs
 * - Incident trend chart (SVG)
 * - Category breakdown
 * - Heatmap (Canvas)
 * - Analyst workload heatmap
 * - SLA compliance monitor
 * - CSV/JSON export
 * ======================================================================
 */

import React, { useState, useEffect, useMemo, useRef, useCallback } from "react";
import { collection, onSnapshot, orderBy, query } from "firebase/firestore";
import { db, auth } from "../firebase";
import { useNavigate } from "react-router-dom";
import {
  computeFullSnapshot,
  exportToCSV,
  exportToJSON,
} from "../utils/analyticsEngine";
import { getRiskPill } from "../utils/riskEngine";

/* ─── ROLE ACCESS MATRIX ─────────────────────────────────────────────────── */

const ROLE_ACCESS = {
  admin:       "full",
  soc_manager: "full",
  soc_l2:      "limited",
  ir:          "limited",
  soc_l1:      "minimal",
  analyst:     "minimal",
  student:     "none",
};

function getAccessLevel(role) {
  return ROLE_ACCESS[role] || "none";
}

/* ─── STYLES ─────────────────────────────────────────────────────────────── */

const glassCard = {
  background: "rgba(15, 23, 42, 0.65)",
  backdropFilter: "blur(14px)",
  border: "1px solid rgba(255,255,255,0.08)",
  borderRadius: 20,
  padding: 24,
  boxShadow: "0 8px 32px rgba(0,0,0,0.36)",
};

const kpiStyle = {
  ...glassCard,
  padding: "20px 24px",
  display: "flex",
  flexDirection: "column",
  gap: 4,
  minWidth: 160,
};

const headerStyle = {
  fontSize: 11,
  fontWeight: 700,
  textTransform: "uppercase",
  letterSpacing: "0.08em",
  color: "#94a3b8",
};

const bigNum = (color = "#06b6d4") => ({
  fontSize: 32,
  fontWeight: 800,
  fontFamily: "'Space Grotesk', sans-serif",
  color,
  lineHeight: 1.1,
});

const subLabel = {
  fontSize: 12,
  color: "#64748b",
};

const pillStyle = (bg, fg = "#fff") => ({
  background: bg,
  color: fg,
  padding: "3px 10px",
  borderRadius: 999,
  fontSize: 11,
  fontWeight: 700,
  display: "inline-flex",
  alignItems: "center",
  gap: 4,
});

/* ─── SVG MINI-CHART COMPONENT ───────────────────────────────────────────── */

function TrendChart({ data, width = 500, height = 180 }) {
  if (!data || !data.labels || data.labels.length === 0) {
    return <div style={{ color: "#64748b", textAlign: "center", padding: 20 }}>No trend data</div>;
  }

  const pad = { top: 20, right: 20, bottom: 30, left: 40 };
  const chartW = width - pad.left - pad.right;
  const chartH = height - pad.top - pad.bottom;

  const maxVal = Math.max(1, ...data.created, ...data.resolved);
  const xStep = chartW / Math.max(1, data.labels.length - 1);

  const toPath = (values, color) => {
    const points = values.map((v, i) => ({
      x: pad.left + i * xStep,
      y: pad.top + chartH - (v / maxVal) * chartH,
    }));
    const d = points.map((p, i) => `${i === 0 ? "M" : "L"} ${p.x} ${p.y}`).join(" ");
    
    // Area fill
    const areaD = d + ` L ${points[points.length - 1].x} ${pad.top + chartH} L ${points[0].x} ${pad.top + chartH} Z`;
    
    return (
      <g key={color}>
        <path d={areaD} fill={color} fillOpacity={0.1} />
        <path d={d} fill="none" stroke={color} strokeWidth={2.5} strokeLinecap="round" strokeLinejoin="round" />
        {points.map((p, i) => (
          <circle key={i} cx={p.x} cy={p.y} r={3} fill={color} stroke="rgba(0,0,0,0.3)" strokeWidth={1} />
        ))}
      </g>
    );
  };

  return (
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} style={{ width: "100%", height: "auto" }}>
      {/* Grid lines */}
      {[0, 0.25, 0.5, 0.75, 1].map(frac => {
        const y = pad.top + chartH * (1 - frac);
        return (
          <g key={frac}>
            <line x1={pad.left} y1={y} x2={width - pad.right} y2={y} stroke="rgba(255,255,255,0.06)" />
            <text x={pad.left - 6} y={y + 4} textAnchor="end" fill="#64748b" fontSize={10}>
              {Math.round(maxVal * frac)}
            </text>
          </g>
        );
      })}
      
      {/* X labels */}
      {data.labels.map((label, i) => (
        <text
          key={i}
          x={pad.left + i * xStep}
          y={height - 8}
          textAnchor="middle"
          fill="#64748b"
          fontSize={10}
        >
          {label}
        </text>
      ))}

      {toPath(data.created, "#06b6d4")}
      {toPath(data.resolved, "#10b981")}
      {toPath(data.escalated, "#f59e0b")}

      {/* Legend */}
      <g transform={`translate(${pad.left + 10}, ${pad.top - 6})`}>
        {[
          { color: "#06b6d4", label: "Created" },
          { color: "#10b981", label: "Resolved" },
          { color: "#f59e0b", label: "Escalated" },
        ].map((item, i) => (
          <g key={i} transform={`translate(${i * 90}, 0)`}>
            <circle cx={0} cy={-2} r={4} fill={item.color} />
            <text x={8} y={2} fill="#94a3b8" fontSize={10}>{item.label}</text>
          </g>
        ))}
      </g>
    </svg>
  );
}

/* ─── CANVAS HEATMAP ─────────────────────────────────────────────────────── */

function HeatmapCanvas({ data, width = 600, height = 200 }) {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || !data) return;

    const ctx = canvas.getContext("2d");
    const cellW = Math.floor((width - 60) / 24);
    const cellH = Math.floor((height - 30) / 7);
    const offsetX = 40;
    const offsetY = 20;

    ctx.clearRect(0, 0, width, height);

    // Draw cells
    for (let day = 0; day < 7; day++) {
      // Day label
      ctx.fillStyle = "#94a3b8";
      ctx.font = "10px Inter, sans-serif";
      ctx.textAlign = "right";
      ctx.fillText(data.dayLabels[day], offsetX - 6, offsetY + day * cellH + cellH / 2 + 3);

      for (let hour = 0; hour < 24; hour++) {
        const val = data.matrix[day][hour];
        const intensity = val / data.maxVal;

        // Color gradient: dark blue → cyan → green → yellow → red
        let r, g, b;
        if (intensity < 0.25) {
          r = 15; g = 23 + intensity * 400; b = 42 + intensity * 600;
        } else if (intensity < 0.5) {
          r = 6; g = 182; b = 212 - (intensity - 0.25) * 400;
        } else if (intensity < 0.75) {
          r = 245 * (intensity - 0.5) * 4; g = 158; b = 11;
        } else {
          r = 239; g = 68; b = 68;
        }

        ctx.fillStyle = `rgba(${Math.round(r)}, ${Math.round(g)}, ${Math.round(b)}, ${Math.max(0.15, intensity)})`;
        ctx.fillRect(offsetX + hour * cellW, offsetY + day * cellH, cellW - 1, cellH - 1);
      }
    }

    // Hour labels
    ctx.fillStyle = "#64748b";
    ctx.font = "9px Inter, sans-serif";
    ctx.textAlign = "center";
    for (let h = 0; h < 24; h += 3) {
      ctx.fillText(`${h}:00`, offsetX + h * cellW + cellW / 2, height - 4);
    }
  }, [data, width, height]);

  return <canvas ref={canvasRef} width={width} height={height} style={{ width: "100%", height: "auto" }} />;
}

/* ─── PROGRESS BAR ───────────────────────────────────────────────────────── */

function ProgressBar({ value, max = 100, color = "#06b6d4", label }) {
  const pct = max > 0 ? Math.round((value / max) * 100) : 0;
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
      {label && <div style={{ fontSize: 12, color: "#94a3b8", minWidth: 80 }}>{label}</div>}
      <div style={{ flex: 1, height: 8, borderRadius: 4, background: "rgba(255,255,255,0.06)" }}>
        <div style={{
          width: `${pct}%`,
          height: "100%",
          borderRadius: 4,
          background: `linear-gradient(90deg, ${color}, ${color}88)`,
          transition: "width 0.5s ease",
        }} />
      </div>
      <div style={{ fontSize: 12, fontWeight: 700, color, minWidth: 36, textAlign: "right" }}>{pct}%</div>
    </div>
  );
}

/* ─── MAIN COMPONENT ─────────────────────────────────────────────────────── */

export default function AnalyticsPanel({ userRole = "analyst" }) {
  const navigate = useNavigate();
  const [issues, setIssues] = useState([]);
  const [usersMap, setUsersMap] = useState({});
  const [loading, setLoading] = useState(true);
  const [timeRange, setTimeRange] = useState(7); // days
  const [filterSeverity, setFilterSeverity] = useState("all");
  const [filterCategory, setFilterCategory] = useState("all");

  const accessLevel = getAccessLevel(userRole);

  // Access denied for students
  if (accessLevel === "none") {
    return (
      <div style={{ padding: 40, textAlign: "center", color: "#94a3b8" }}>
        <h2 style={{ color: "#ef4444" }}>🔒 Access Denied</h2>
        <p>Your role does not have access to analytics.</p>
      </div>
    );
  }

  // Fetch incidents
  useEffect(() => {
    const q = query(collection(db, "issues"), orderBy("createdAt", "desc"));
    const unsub = onSnapshot(q, snap => {
      setIssues(snap.docs.map(d => ({ id: d.id, ...d.data() })));
      setLoading(false);
    }, (error) => {
      console.error("Error fetching incidents:", error);
      setLoading(false);
    });
    return unsub;
  }, []);

  // Fetch users (for full access only) - REAL-TIME
  useEffect(() => {
    if (accessLevel !== "full") return;
    
    const unsubscribe = onSnapshot(
      collection(db, "users"),
      (snap) => {
        const map = {};
        snap.docs.forEach(d => { map[d.id] = d.data(); });
        setUsersMap(map);
        console.log("REALTIME UPDATE: Users map updated", Object.keys(map).length);
      },
      (error) => {
        console.error("Firestore listener error (users):", error);
      }
    );

    return () => unsubscribe();
  }, [accessLevel]);

  // Filter issues
  const filtered = useMemo(() => {
    const now = Date.now();
    const cutoff = now - timeRange * 86400000;
    return issues.filter(issue => {
      // Time filter
      const created = issue.createdAt?.toMillis?.() || issue.createdAt?.seconds * 1000 || 0;
      if (created && created < cutoff) return false;
      // Severity filter
      if (filterSeverity !== "all" && issue.urgency !== filterSeverity) return false;
      // Category filter
      if (filterCategory !== "all" && issue.category !== filterCategory) return false;
      return true;
    });
  }, [issues, timeRange, filterSeverity, filterCategory]);

  // Compute analytics
  const snapshot = useMemo(() => computeFullSnapshot(filtered, usersMap), [filtered, usersMap]);

  // Categories list for filter
  const categories = useMemo(() => {
    const cats = new Set(issues.map(i => i.category).filter(Boolean));
    return ["all", ...Array.from(cats).sort()];
  }, [issues]);

  // Export handlers
  const handleExportCSV = useCallback(() => {
    const csv = exportToCSV(filtered);
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `soc_analytics_${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }, [filtered]);

  const handleExportJSON = useCallback(() => {
    const json = exportToJSON(filtered);
    const blob = new Blob([json], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `soc_analytics_${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }, [filtered]);

  if (loading) {
    return (
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "60vh", color: "#06b6d4" }}>
        <div style={{ textAlign: "center" }}>
          <div style={{ fontSize: 48, marginBottom: 16 }}>📊</div>
          <div style={{ fontWeight: 700, fontSize: 18 }}>Loading Analytics...</div>
        </div>
      </div>
    );
  }

  const { timing, volume, sla, trends, workload, heatmap, categories: catBreakdown } = snapshot;

  return (
    <div style={{ padding: "24px 32px", maxWidth: 1400, margin: "0 auto" }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 28 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          <button
            onClick={() => navigate("/soc-manager")}
            style={{
              padding: "8px 16px",
              borderRadius: 8,
              background: "rgba(255,255,255,0.06)",
              color: "#94a3b8",
              border: "1px solid rgba(255,255,255,0.12)",
              fontSize: 13,
              fontWeight: 600,
              cursor: "pointer",
              transition: "all 0.2s ease"
            }}
            onMouseOver={(e) => {
              e.target.style.background = "rgba(255,255,255,0.1)";
              e.target.style.color = "#fff";
            }}
            onMouseOut={(e) => {
              e.target.style.background = "rgba(255,255,255,0.06)";
              e.target.style.color = "#94a3b8";
            }}
          >
            ← Back to Console
          </button>
          <div>
            <h1 style={{
              fontFamily: "'Space Grotesk', sans-serif",
              fontSize: 28,
              fontWeight: 800,
              background: "linear-gradient(135deg, #06b6d4, #8b5cf6)",
              WebkitBackgroundClip: "text",
              WebkitTextFillColor: "transparent",
              margin: 0,
            }}>
              📊 SOC Analytics
            </h1>
            <p style={{ color: "#64748b", margin: "4px 0 0", fontSize: 13 }}>
              {filtered.length} incidents • {timeRange}d window • Access: {accessLevel.toUpperCase()}
            </p>
          </div>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          {/* Time Range */}
          <select
            value={timeRange}
            onChange={e => setTimeRange(Number(e.target.value))}
            style={{
              padding: "8px 12px", borderRadius: 10,
              background: "rgba(255,255,255,0.06)", color: "#fff",
              border: "1px solid rgba(255,255,255,0.12)", fontSize: 12,
            }}
          >
            <option value={1}>Last 24h</option>
            <option value={7}>Last 7d</option>
            <option value={14}>Last 14d</option>
            <option value={30}>Last 30d</option>
            <option value={90}>Last 90d</option>
          </select>

          {/* Severity Filter */}
          <select
            value={filterSeverity}
            onChange={e => setFilterSeverity(e.target.value)}
            style={{
              padding: "8px 12px", borderRadius: 10,
              background: "rgba(255,255,255,0.06)", color: "#fff",
              border: "1px solid rgba(255,255,255,0.12)", fontSize: 12,
            }}
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          {/* Category Filter */}
          <select
            value={filterCategory}
            onChange={e => setFilterCategory(e.target.value)}
            style={{
              padding: "8px 12px", borderRadius: 10,
              background: "rgba(255,255,255,0.06)", color: "#fff",
              border: "1px solid rgba(255,255,255,0.12)", fontSize: 12,
            }}
          >
            {categories.map(c => (
              <option key={c} value={c}>{c === "all" ? "All Categories" : c}</option>
            ))}
          </select>

          {/* Export */}
          {accessLevel === "full" && (
            <>
              <button onClick={handleExportCSV} style={{
                padding: "8px 14px", borderRadius: 10,
                background: "rgba(16,185,129,0.15)", color: "#10b981",
                border: "1px solid rgba(16,185,129,0.3)", cursor: "pointer",
                fontSize: 12, fontWeight: 700,
              }}>
                📥 CSV
              </button>
              <button onClick={handleExportJSON} style={{
                padding: "8px 14px", borderRadius: 10,
                background: "rgba(139,92,246,0.15)", color: "#8b5cf6",
                border: "1px solid rgba(139,92,246,0.3)", cursor: "pointer",
                fontSize: 12, fontWeight: 700,
              }}>
                📥 JSON
              </button>
            </>
          )}
        </div>
      </div>

      {/* KPI Row */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 16, marginBottom: 24 }}>
        <div style={kpiStyle}>
          <div style={headerStyle}>Total Incidents</div>
          <div style={bigNum()}>{volume.total}</div>
          <div style={subLabel}>{volume.active} active</div>
        </div>
        <div style={kpiStyle}>
          <div style={headerStyle}>Resolution Rate</div>
          <div style={bigNum("#10b981")}>{volume.resolutionRate}%</div>
          <div style={subLabel}>{volume.resolved} resolved</div>
        </div>
        <div style={kpiStyle}>
          <div style={headerStyle}>MTTA</div>
          <div style={bigNum("#f59e0b")}>{timing.mttaLabel}</div>
          <div style={subLabel}>{timing.samplesMTTA} samples</div>
        </div>
        <div style={kpiStyle}>
          <div style={headerStyle}>MTTR</div>
          <div style={bigNum("#ef4444")}>{timing.mttrLabel}</div>
          <div style={subLabel}>{timing.samplesMTTR} samples</div>
        </div>
        <div style={kpiStyle}>
          <div style={headerStyle}>SLA Compliance</div>
          <div style={bigNum(sla.complianceRate >= 90 ? "#10b981" : sla.complianceRate >= 70 ? "#f59e0b" : "#ef4444")}>
            {sla.complianceRate}%
          </div>
          <div style={subLabel}>{sla.breached} breached</div>
        </div>
        <div style={kpiStyle}>
          <div style={headerStyle}>False Positive Rate</div>
          <div style={bigNum("#8b5cf6")}>{volume.falsePositiveRate}%</div>
          <div style={subLabel}>{volume.falsePositives} FPs</div>
        </div>
      </div>

      {/* Trend Chart + SLA Monitor Row */}
      <div style={{ display: "grid", gridTemplateColumns: accessLevel === "full" ? "2fr 1fr" : "1fr", gap: 16, marginBottom: 24 }}>
        <div style={glassCard}>
          <h3 style={{ margin: "0 0 16px", fontSize: 15, fontWeight: 700, color: "#e2e8f0" }}>
            📈 Incident Trends ({timeRange}d)
          </h3>
          <TrendChart data={trends} width={600} height={200} />
        </div>

        {accessLevel === "full" && (
          <div style={glassCard}>
            <h3 style={{ margin: "0 0 16px", fontSize: 15, fontWeight: 700, color: "#e2e8f0" }}>
              🎯 SLA Status
            </h3>
            <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
              <ProgressBar value={sla.compliant} max={sla.compliant + sla.atRisk + sla.breached} color="#10b981" label="Compliant" />
              <ProgressBar value={sla.atRisk} max={sla.compliant + sla.atRisk + sla.breached} color="#f59e0b" label="At Risk" />
              <ProgressBar value={sla.breached} max={sla.compliant + sla.atRisk + sla.breached} color="#ef4444" label="Breached" />
            </div>
            <div style={{ marginTop: 16, padding: "12px 16px", borderRadius: 12, background: sla.breached > 0 ? "rgba(239,68,68,0.1)" : "rgba(16,185,129,0.1)", border: `1px solid ${sla.breached > 0 ? "rgba(239,68,68,0.3)" : "rgba(16,185,129,0.3)"}` }}>
              <div style={{ fontSize: 12, fontWeight: 700, color: sla.breached > 0 ? "#ef4444" : "#10b981" }}>
                {sla.breached > 0 ? `⚠️ ${sla.breached} SLA Breach${sla.breached > 1 ? "es" : ""}` : "✅ All Incidents Within SLA"}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Heatmap + Category Breakdown */}
      {accessLevel !== "minimal" && (
        <div style={{ display: "grid", gridTemplateColumns: accessLevel === "full" ? "1fr 1fr" : "1fr", gap: 16, marginBottom: 24 }}>
          <div style={glassCard}>
            <h3 style={{ margin: "0 0 16px", fontSize: 15, fontWeight: 700, color: "#e2e8f0" }}>
              🔥 Incident Heatmap (Hour × Day)
            </h3>
            <HeatmapCanvas data={heatmap} width={600} height={200} />
          </div>

          <div style={glassCard}>
            <h3 style={{ margin: "0 0 16px", fontSize: 15, fontWeight: 700, color: "#e2e8f0" }}>
              📋 Category Breakdown
            </h3>
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {catBreakdown.slice(0, 8).map(cat => (
                <div key={cat.category} style={{
                  display: "flex", alignItems: "center", gap: 10,
                  padding: "8px 12px", borderRadius: 10,
                  background: "rgba(255,255,255,0.03)",
                }}>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: 13, fontWeight: 600, color: "#e2e8f0" }}>
                      {cat.category}
                    </div>
                    <div style={{ fontSize: 11, color: "#64748b" }}>
                      {cat.resolved} resolved • {cat.fpRate}% FP
                    </div>
                  </div>
                  <div style={{ fontSize: 20, fontWeight: 800, color: "#06b6d4" }}>{cat.count}</div>
                  {cat.avgRiskScore != null && (
                    <span style={pillStyle(getRiskPill(cat.avgRiskScore).bg, getRiskPill(cat.avgRiskScore).color)}>
                      Risk: {cat.avgRiskScore}
                    </span>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Analyst Workload (full access only) */}
      {accessLevel === "full" && workload.length > 0 && (
        <div style={glassCard}>
          <h3 style={{ margin: "0 0 16px", fontSize: 15, fontWeight: 700, color: "#e2e8f0" }}>
            👥 Analyst Workload & Performance
          </h3>
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid rgba(255,255,255,0.08)" }}>
                  {["Analyst", "Level", "Active", "Resolved", "Escalated", "Avg MTTR", "Pressure"].map(h => (
                    <th key={h} style={{ padding: "8px 12px", textAlign: "left", fontSize: 11, fontWeight: 700, color: "#64748b", textTransform: "uppercase" }}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {workload.map(w => (
                  <tr key={w.uid} style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                    <td style={{ padding: "10px 12px", fontWeight: 600, color: "#e2e8f0", fontSize: 13 }}>{w.name}</td>
                    <td style={{ padding: "10px 12px" }}>
                      <span style={pillStyle("#1e40af")}>{w.level}</span>
                    </td>
                    <td style={{ padding: "10px 12px", color: "#f59e0b", fontWeight: 700 }}>{w.active}</td>
                    <td style={{ padding: "10px 12px", color: "#10b981", fontWeight: 700 }}>{w.resolved}</td>
                    <td style={{ padding: "10px 12px", color: "#ef4444", fontWeight: 700 }}>{w.escalated}</td>
                    <td style={{ padding: "10px 12px", color: "#94a3b8", fontSize: 12 }}>{w.avgMTTRLabel}</td>
                    <td style={{ padding: "10px 12px" }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        <div style={{ width: 60, height: 6, borderRadius: 3, background: "rgba(255,255,255,0.06)" }}>
                          <div style={{
                            width: `${w.pressure}%`, height: "100%", borderRadius: 3,
                            background: w.pressure > 70 ? "#ef4444" : w.pressure > 40 ? "#f59e0b" : "#10b981",
                            transition: "width 0.5s ease",
                          }} />
                        </div>
                        <span style={{ fontSize: 11, fontWeight: 700, color: w.pressure > 70 ? "#ef4444" : w.pressure > 40 ? "#f59e0b" : "#10b981" }}>
                          {w.pressure}
                        </span>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Status Breakdown (minimal access) */}
      {accessLevel === "minimal" && (
        <div style={glassCard}>
          <h3 style={{ margin: "0 0 16px", fontSize: 15, fontWeight: 700, color: "#e2e8f0" }}>
            📊 Status Breakdown
          </h3>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(120px, 1fr))", gap: 10 }}>
            {Object.entries(volume.byStatus).map(([status, count]) => (
              <div key={status} style={{
                padding: "12px 16px", borderRadius: 12,
                background: "rgba(255,255,255,0.04)",
                border: "1px solid rgba(255,255,255,0.06)",
              }}>
                <div style={{ fontSize: 22, fontWeight: 800, color: "#06b6d4" }}>{count}</div>
                <div style={{ fontSize: 11, color: "#64748b", textTransform: "capitalize" }}>
                  {status.replace(/_/g, " ")}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
