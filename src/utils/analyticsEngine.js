/**
 * ======================================================================
 * CAMPUS SOC — ANALYTICS ENGINE (Phase 3)
 * ======================================================================
 *
 * Pure computation engine for SOC analytics. No Firestore dependency.
 * Feed it incident arrays and it returns computed metrics.
 *
 * Designed to work with both:
 * 1. Client-side display (AnalyticsPanel reads snapshots)
 * 2. Server-side snapshots (Cloud Function computes + stores)
 * ======================================================================
 */

/* ---------- TIME HELPERS ---------- */

function tsToMs(ts) {
  if (!ts) return 0;
  if (typeof ts === "number") return ts;
  if (ts.toMillis) return ts.toMillis();
  if (ts.seconds) return ts.seconds * 1000;
  if (ts instanceof Date) return ts.getTime();
  if (typeof ts === "string") return new Date(ts).getTime();
  return 0;
}

const MS_HOUR = 3600000;
const MS_DAY  = 86400000;

/* ---------- MTTA / MTTR ---------- */

/**
 * Calculate Mean Time to Acknowledge and Mean Time to Resolve.
 * @param {Object[]} issues - array of incident objects
 * @returns {{ mttaMs: number, mttrMs: number, mttaLabel: string, mttrLabel: string }}
 */
export function computeMTTAMTTR(issues) {
  let totalMTTA = 0, countMTTA = 0;
  let totalMTTR = 0, countMTTR = 0;

  for (const issue of issues) {
    const created = tsToMs(issue.createdAt);
    if (!created) continue;

    // MTTA: time from created → first assignment
    const assigned = tsToMs(issue.assignedAt);
    if (assigned && assigned > created) {
      totalMTTA += assigned - created;
      countMTTA++;
    }

    // MTTR: time from created → resolved
    const resolved = tsToMs(issue.resolvedAt);
    if (resolved && resolved > created) {
      totalMTTR += resolved - created;
      countMTTR++;
    }
  }

  const mttaMs = countMTTA > 0 ? totalMTTA / countMTTA : 0;
  const mttrMs = countMTTR > 0 ? totalMTTR / countMTTR : 0;

  return {
    mttaMs,
    mttrMs,
    mttaLabel: formatDuration(mttaMs),
    mttrLabel: formatDuration(mttrMs),
    samplesMTTA: countMTTA,
    samplesMTTR: countMTTR,
  };
}

/* ---------- VOLUME METRICS ---------- */

/**
 * Compute incident volume statistics.
 */
export function computeVolumeMetrics(issues) {
  const total = issues.length;
  const byStatus = {};
  const byCategory = {};
  const byUrgency = {};

  for (const issue of issues) {
    const s = issue.status || "unknown";
    const c = issue.category || "other";
    const u = issue.urgency || "medium";
    byStatus[s] = (byStatus[s] || 0) + 1;
    byCategory[c] = (byCategory[c] || 0) + 1;
    byUrgency[u] = (byUrgency[u] || 0) + 1;
  }

  const active = issues.filter(i =>
    !["resolved", "false_positive", "risk_accepted"].includes(i.status) && !i.isDeleted
  ).length;

  const resolved = (byStatus.resolved || 0);
  const falsePositives = (byStatus.false_positive || 0);
  const resolutionRate = total > 0 ? Math.round((resolved / total) * 100) : 0;
  const falsePositiveRate = total > 0 ? Math.round((falsePositives / total) * 100) : 0;

  return {
    total, active, resolved, falsePositives,
    resolutionRate, falsePositiveRate,
    byStatus, byCategory, byUrgency,
  };
}

/* ---------- SLA METRICS ---------- */

/**
 * Compute SLA compliance metrics.
 */
export function computeSLAMetrics(issues, slaConfig = { open: 24, assigned: 48 }) {
  let breached = 0;
  let atRisk = 0;
  let compliant = 0;
  const breachedIds = [];
  const atRiskIds = [];

  const now = Date.now();

  for (const issue of issues) {
    if (["resolved", "false_positive", "risk_accepted"].includes(issue.status) || issue.isDeleted) {
      compliant++;
      continue;
    }

    const created = tsToMs(issue.createdAt);
    if (!created) { compliant++; continue; }

    if (issue.status === "open") {
      const deadline = created + slaConfig.open * MS_HOUR;
      if (now > deadline) {
        breached++;
        breachedIds.push(issue.id);
      } else if (deadline - now < 2 * MS_HOUR) {
        atRisk++;
        atRiskIds.push(issue.id);
      } else {
        compliant++;
      }
    } else if (["assigned", "in_progress"].includes(issue.status)) {
      const assignedAt = tsToMs(issue.assignedAt) || created;
      const deadline = assignedAt + slaConfig.assigned * MS_HOUR;
      if (now > deadline) {
        breached++;
        breachedIds.push(issue.id);
      } else if (deadline - now < 2 * MS_HOUR) {
        atRisk++;
        atRiskIds.push(issue.id);
      } else {
        compliant++;
      }
    } else {
      compliant++;
    }
  }

  const total = breached + atRisk + compliant;
  const complianceRate = total > 0 ? Math.round((compliant / total) * 100) : 100;

  return {
    breached, atRisk, compliant,
    complianceRate,
    breachedIds, atRiskIds,
  };
}

/* ---------- TREND DATA ---------- */

/**
 * Generate time-series data for trend charts.
 * Groups incidents by day/hour and returns arrays for plotting.
 */
export function computeTrends(issues, { days = 7 } = {}) {
  const now = Date.now();
  const cutoff = now - days * MS_DAY;

  // Daily buckets
  const dailyBuckets = {};
  for (let d = 0; d < days; d++) {
    const date = new Date(now - d * MS_DAY);
    const key = date.toISOString().slice(0, 10);
    dailyBuckets[key] = { created: 0, resolved: 0, escalated: 0 };
  }

  for (const issue of issues) {
    const created = tsToMs(issue.createdAt);
    if (created < cutoff) continue;

    const key = new Date(created).toISOString().slice(0, 10);
    if (dailyBuckets[key]) {
      dailyBuckets[key].created++;
    }

    const resolved = tsToMs(issue.resolvedAt);
    if (resolved && resolved >= cutoff) {
      const rKey = new Date(resolved).toISOString().slice(0, 10);
      if (dailyBuckets[rKey]) dailyBuckets[rKey].resolved++;
    }

    if (issue.escalated) {
      const escalated = tsToMs(issue.escalatedAt);
      if (escalated && escalated >= cutoff) {
        const eKey = new Date(escalated).toISOString().slice(0, 10);
        if (dailyBuckets[eKey]) dailyBuckets[eKey].escalated++;
      }
    }
  }

  // Convert to sorted arrays
  const sortedKeys = Object.keys(dailyBuckets).sort();
  return {
    labels: sortedKeys.map(k => k.slice(5)), // "MM-DD"
    created:   sortedKeys.map(k => dailyBuckets[k].created),
    resolved:  sortedKeys.map(k => dailyBuckets[k].resolved),
    escalated: sortedKeys.map(k => dailyBuckets[k].escalated),
  };
}

/* ---------- ANALYST WORKLOAD ---------- */

/**
 * Compute per-analyst workload and performance metrics.
 */
export function computeAnalystWorkload(issues, usersMap = {}) {
  const workload = {};

  for (const issue of issues) {
    const analyst = issue.assignedTo;
    if (!analyst) continue;

    if (!workload[analyst]) {
      const userData = usersMap[analyst] || {};
      workload[analyst] = {
        uid: analyst,
        name: userData.name || userData.displayName || userData.email || analyst,
        role: userData.role || "unknown",
        level: userData.analystLevel || "—",
        active: 0,
        resolved: 0,
        escalated: 0,
        totalMTTR: 0,
        mttrCount: 0,
      };
    }

    const entry = workload[analyst];

    if (["resolved", "false_positive", "risk_accepted"].includes(issue.status)) {
      entry.resolved++;

      const created = tsToMs(issue.createdAt);
      const resolved = tsToMs(issue.resolvedAt);
      if (created && resolved && resolved > created) {
        entry.totalMTTR += resolved - created;
        entry.mttrCount++;
      }
    } else if (!issue.isDeleted) {
      entry.active++;
    }

    if (issue.escalated) entry.escalated++;
  }

  // Compute averages and sort
  return Object.values(workload)
    .map(w => ({
      ...w,
      avgMTTR: w.mttrCount > 0 ? w.totalMTTR / w.mttrCount : 0,
      avgMTTRLabel: w.mttrCount > 0 ? formatDuration(w.totalMTTR / w.mttrCount) : "—",
      pressure: computePressure(w.active, w.resolved),
    }))
    .sort((a, b) => b.pressure - a.pressure);
}

/**
 * Compute analyst pressure score (0–100).
 * High active + low resolved = high pressure.
 */
function computePressure(active, resolved) {
  const total = active + resolved;
  if (total === 0) return 0;
  const ratio = active / total;
  return Math.round(Math.min(100, ratio * 100 + active * 5));
}

/* ---------- HEATMAP DATA ---------- */

/**
 * Generate heatmap data: incidents by hour-of-day × day-of-week.
 * Returns a 7×24 matrix.
 */
export function computeHeatmap(issues) {
  // matrix[dayOfWeek][hourOfDay] = count
  const matrix = Array.from({ length: 7 }, () => Array(24).fill(0));
  const dayLabels = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

  for (const issue of issues) {
    const ms = tsToMs(issue.createdAt);
    if (!ms) continue;
    const d = new Date(ms);
    matrix[d.getDay()][d.getHours()]++;
  }

  // Find max for color scaling
  const maxVal = Math.max(1, ...matrix.flat());

  return { matrix, dayLabels, maxVal };
}

/* ---------- CATEGORY BREAKDOWN ---------- */

/**
 * Detailed breakdown by category with MITRE mapping.
 */
export function computeCategoryBreakdown(issues) {
  const categories = {};

  for (const issue of issues) {
    const cat = issue.category || "other";
    if (!categories[cat]) {
      categories[cat] = {
        category: cat,
        count: 0,
        high: 0,
        medium: 0,
        low: 0,
        resolved: 0,
        falsePositive: 0,
        avgRiskScore: 0,
        totalRisk: 0,
        riskCount: 0,
      };
    }
    const entry = categories[cat];
    entry.count++;
    if (issue.urgency === "high" || issue.urgency === "critical") entry.high++;
    else if (issue.urgency === "medium") entry.medium++;
    else entry.low++;

    if (issue.status === "resolved") entry.resolved++;
    if (issue.status === "false_positive") entry.falsePositive++;

    if (issue.riskScore != null) {
      entry.totalRisk += issue.riskScore;
      entry.riskCount++;
    }
  }

  return Object.values(categories).map(c => ({
    ...c,
    avgRiskScore: c.riskCount > 0 ? Math.round(c.totalRisk / c.riskCount) : null,
    fpRate: c.count > 0 ? Math.round((c.falsePositive / c.count) * 100) : 0,
  })).sort((a, b) => b.count - a.count);
}

/* ---------- EXPORT FORMATTERS ---------- */

/**
 * Export analytics data as CSV string.
 */
export function exportToCSV(issues) {
  const headers = [
    "ID", "Title", "Status", "Category", "Urgency",
    "RiskScore", "AssignedTo", "CreatedAt", "ResolvedAt",
    "Escalated", "SLABreached"
  ];

  const rows = issues.map(i => [
    i.id || "",
    `"${(i.title || "").replace(/"/g, '""')}"`,
    i.status || "",
    i.category || "",
    i.urgency || "",
    i.riskScore ?? "",
    i.assignedTo || "",
    i.createdAt ? new Date(tsToMs(i.createdAt)).toISOString() : "",
    i.resolvedAt ? new Date(tsToMs(i.resolvedAt)).toISOString() : "",
    i.escalated ? "Yes" : "No",
    i.slaBreached ? "Yes" : "No",
  ]);

  return [headers.join(","), ...rows.map(r => r.join(","))].join("\n");
}

/**
 * Export analytics data as JSON string.
 */
export function exportToJSON(issues) {
  return JSON.stringify(issues.map(i => ({
    id: i.id,
    title: i.title,
    status: i.status,
    category: i.category,
    urgency: i.urgency,
    riskScore: i.riskScore ?? null,
    assignedTo: i.assignedTo,
    createdAt: i.createdAt ? new Date(tsToMs(i.createdAt)).toISOString() : null,
    resolvedAt: i.resolvedAt ? new Date(tsToMs(i.resolvedAt)).toISOString() : null,
    escalated: i.escalated || false,
  })), null, 2);
}

/* ---------- FULL SNAPSHOT ---------- */

/**
 * Compute a complete analytics snapshot from raw issues.
 * This is what the Cloud Function would store to /analyticsSnapshots/{range}.
 */
export function computeFullSnapshot(issues, usersMap = {}) {
  return {
    computedAt: new Date().toISOString(),
    incidentCount: issues.length,
    timing: computeMTTAMTTR(issues),
    volume: computeVolumeMetrics(issues),
    sla: computeSLAMetrics(issues),
    trends: computeTrends(issues),
    workload: computeAnalystWorkload(issues, usersMap),
    heatmap: computeHeatmap(issues),
    categories: computeCategoryBreakdown(issues),
  };
}

/* ---------- FORMAT HELPERS ---------- */

function formatDuration(ms) {
  if (!ms || ms <= 0) return "0m";
  const totalMin = Math.floor(ms / 60000);
  const h = Math.floor(totalMin / 60);
  const m = totalMin % 60;
  if (h === 0) return `${m}m`;
  if (h >= 24) {
    const d = Math.floor(h / 24);
    const rh = h % 24;
    return `${d}d ${rh}h`;
  }
  return `${h}h ${m}m`;
}
