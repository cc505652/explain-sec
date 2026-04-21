/**
 * ======================================================================
 * CAMPUS SOC — FATIGUE ENGINE (Phase 8)
 * ======================================================================
 *
 * Analyst fatigue detection and prevention system.
 * Pure computation — no Firestore dependency.
 *
 * Factors:
 * - Active incident count
 * - High-urgency incident ratio
 * - Stuck incident count (no progress > 12h)
 * - Consecutive shift hours
 * - Incident-per-hour velocity
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
const STUCK_THRESHOLD_MS = 12 * MS_HOUR;

/* ---------- FATIGUE SCORE COMPUTATION ---------- */

/**
 * Compute fatigue score (0-100) for an analyst.
 *
 * Formula:
 *   fatigue = base
 *     + (activeIncidents * 8)
 *     + (highUrgencyActive * 12)
 *     + (stuckIncidents * 15)
 *     + (velocityBonus)
 *
 * @param {Object} params
 * @param {number} params.activeIncidents  - currently assigned, non-resolved
 * @param {number} params.highUrgencyActive - active with high/critical urgency
 * @param {number} params.stuckIncidents   - no status change in 12h+
 * @param {number} params.incidentsLastHour - new assignments in last hour
 * @param {number} params.shiftHours       - hours since shift start
 * @returns {{ score: number, level: string, color: string, recommendation: string }}
 */
export function computeFatigueScore({
  activeIncidents = 0,
  highUrgencyActive = 0,
  stuckIncidents = 0,
  incidentsLastHour = 0,
  shiftHours = 0,
} = {}) {
  let score = 0;

  // Base load
  score += activeIncidents * 8;

  // High urgency amplifier
  score += highUrgencyActive * 12;

  // Stuck incidents (major fatigue factor)
  score += stuckIncidents * 15;

  // Velocity spike (3+ new/hour = overloaded)
  if (incidentsLastHour >= 5) score += 25;
  else if (incidentsLastHour >= 3) score += 15;
  else if (incidentsLastHour >= 2) score += 5;

  // Long shift penalty
  if (shiftHours > 10) score += 20;
  else if (shiftHours > 8) score += 10;
  else if (shiftHours > 6) score += 5;

  score = Math.min(100, Math.max(0, Math.round(score)));

  let level, color, recommendation;
  if (score >= 80) {
    level = "critical";
    color = "#dc2626";
    recommendation = "🚨 IMMEDIATE ACTION: Redistribute incidents or initiate shift handoff";
  } else if (score >= 60) {
    level = "high";
    color = "#ef4444";
    recommendation = "⚠️ High fatigue: Consider offloading low-priority incidents";
  } else if (score >= 40) {
    level = "elevated";
    color = "#f59e0b";
    recommendation = "📊 Elevated: Monitor workload closely";
  } else if (score >= 20) {
    level = "moderate";
    color = "#3b82f6";
    recommendation = "✅ Normal workload";
  } else {
    level = "low";
    color = "#10b981";
    recommendation = "✅ Healthy workload — capacity available";
  }

  return { score, level, color, recommendation };
}

/* ---------- COMPUTE FATIGUE FOR ALL ANALYSTS ---------- */

/**
 * Compute fatigue metrics for all analysts from incident data.
 *
 * @param {Object[]} issues - all incidents
 * @param {Object} usersMap - { uid: userData }
 * @returns {Object[]} sorted analyst fatigue entries (highest fatigue first)
 */
export function computeTeamFatigue(issues, usersMap = {}) {
  const now = Date.now();
  const analystData = {};

  // Build per-analyst metrics
  for (const issue of issues) {
    if (issue.isDeleted) continue;
    const analyst = issue.assignedTo;
    if (!analyst) continue;

    if (!analystData[analyst]) {
      analystData[analyst] = {
        uid: analyst,
        activeIncidents: 0,
        highUrgencyActive: 0,
        stuckIncidents: 0,
        incidentsLastHour: 0,
        resolved: 0,
        total: 0,
      };
    }

    const entry = analystData[analyst];
    entry.total++;

    const ACTIVE_STATUSES = ["open", "assigned", "in_progress", "confirmed_threat",
      "escalation_pending", "ir_in_progress", "containment_pending"];

    if (ACTIVE_STATUSES.includes(issue.status)) {
      entry.activeIncidents++;

      if (["high", "critical"].includes(issue.urgency)) {
        entry.highUrgencyActive++;
      }

      // Check if stuck
      const lastUpdate = tsToMs(issue.updatedAt) || tsToMs(issue.createdAt);
      if (lastUpdate && (now - lastUpdate) > STUCK_THRESHOLD_MS) {
        entry.stuckIncidents++;
      }

      // Check if assigned in last hour
      const assignedAt = tsToMs(issue.assignedAt);
      if (assignedAt && (now - assignedAt) < MS_HOUR) {
        entry.incidentsLastHour++;
      }
    } else if (["resolved", "false_positive", "risk_accepted"].includes(issue.status)) {
      entry.resolved++;
    }
  }

  // Compute scores and enrich with user data
  return Object.values(analystData)
    .map(entry => {
      const userData = usersMap[entry.uid] || {};
      const fatigue = computeFatigueScore(entry);

      return {
        ...entry,
        name: userData.name || userData.displayName || userData.email || entry.uid,
        email: userData.email || "",
        role: userData.role || "unknown",
        level: userData.analystLevel || "—",
        team: userData.team || "—",
        fatigue,
        efficiency: entry.total > 0
          ? Math.round((entry.resolved / entry.total) * 100)
          : 0,
      };
    })
    .sort((a, b) => b.fatigue.score - a.fatigue.score);
}

/* ---------- TEAM HEALTH SUMMARY ---------- */

/**
 * Compute team-level health metrics.
 */
export function computeTeamHealth(teamFatigue) {
  if (teamFatigue.length === 0) {
    return {
      avgFatigue: 0,
      maxFatigue: 0,
      criticalCount: 0,
      highCount: 0,
      healthStatus: "healthy",
      healthColor: "#10b981",
    };
  }

  const scores = teamFatigue.map(t => t.fatigue.score);
  const avgFatigue = Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);
  const maxFatigue = Math.max(...scores);
  const criticalCount = teamFatigue.filter(t => t.fatigue.level === "critical").length;
  const highCount = teamFatigue.filter(t => t.fatigue.level === "high").length;

  let healthStatus, healthColor;
  if (criticalCount > 0) {
    healthStatus = "critical";
    healthColor = "#dc2626";
  } else if (highCount > 0 || avgFatigue > 60) {
    healthStatus = "stressed";
    healthColor = "#f59e0b";
  } else if (avgFatigue > 35) {
    healthStatus = "moderate";
    healthColor = "#3b82f6";
  } else {
    healthStatus = "healthy";
    healthColor = "#10b981";
  }

  return {
    avgFatigue,
    maxFatigue,
    criticalCount,
    highCount,
    healthStatus,
    healthColor,
    teamSize: teamFatigue.length,
    totalActive: teamFatigue.reduce((sum, t) => sum + t.activeIncidents, 0),
    totalStuck: teamFatigue.reduce((sum, t) => sum + t.stuckIncidents, 0),
  };
}

/* ---------- REDISTRIBUTION SUGGESTIONS ---------- */

/**
 * Suggest incident redistribution from overloaded to available analysts.
 *
 * @param {Object[]} teamFatigue - output of computeTeamFatigue
 * @returns {Object[]} suggestion entries
 */
export function suggestRedistribution(teamFatigue) {
  const overloaded = teamFatigue.filter(t => t.fatigue.score >= 60);
  const available = teamFatigue.filter(t => t.fatigue.score < 30);

  if (overloaded.length === 0 || available.length === 0) return [];

  const suggestions = [];

  for (const analyst of overloaded) {
    const transferCount = Math.max(1, Math.floor(analyst.activeIncidents * 0.3));
    const targets = available
      .filter(a => a.uid !== analyst.uid)
      .sort((a, b) => a.fatigue.score - b.fatigue.score)
      .slice(0, 2);

    if (targets.length > 0) {
      suggestions.push({
        from: { uid: analyst.uid, name: analyst.name, fatigue: analyst.fatigue.score },
        to: targets.map(t => ({ uid: t.uid, name: t.name, fatigue: t.fatigue.score })),
        suggestedTransfers: transferCount,
        reason: `${analyst.name} at ${analyst.fatigue.level} fatigue (${analyst.fatigue.score})`,
      });
    }
  }

  return suggestions;
}
