/**
 * ======================================================================
 * CAMPUS SOC — SLA ENGINE (Phase 5 — Advanced Governance)
 * ======================================================================
 *
 * Centralized SLA computation. Replaces duplicated SLA logic that was
 * scattered across AnalystDashboard, CommandConsole, and ManagerDashboard.
 *
 * Single source of truth for:
 * - SLA deadlines
 * - Breach detection
 * - At-risk detection
 * - Time remaining/elapsed
 * - Display formatting
 * ======================================================================
 */

/* ---------- CONFIG ---------- */

const DEFAULT_SLA_HOURS = {
  open: 24,       // Must be assigned within 24h
  assigned: 48,   // Must start work within 48h
  in_progress: 72, // Must resolve within 72h
};

const MS_HOUR = 3600000;

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

function formatDuration(ms) {
  const abs = Math.abs(ms);
  const totalMin = Math.floor(abs / 60000);
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

/* ---------- CORE SLA COMPUTATION ---------- */

/**
 * Compute full SLA status for an incident.
 *
 * @param {Object} issue - incident document
 * @param {Object} [config] - SLA configuration (hours per status)
 * @returns {Object} SLA display data
 */
export function computeSLA(issue, config = DEFAULT_SLA_HOURS) {
  const now = Date.now();
  const createdMs = tsToMs(issue.createdAt);

  if (!createdMs) {
    return {
      status: "unknown",
      label: "SLA: —",
      color: "#64748b",
      breached: false,
      atRisk: false,
      remainingMs: 0,
      deadlineMs: 0,
      overridden: false,
    };
  }

  // Already resolved / closed states — SLA complete
  const CLOSED_STATES = [
    "resolved", "false_positive", "risk_accepted",
    "pir_pending", "rca_pending", "rca_completed",
  ];
  if (CLOSED_STATES.includes(issue.status) || issue.isDeleted) {
    return {
      status: "complete",
      label: "SLA: Complete",
      color: "#0d47a1",
      breached: issue.slaBreached || false,
      atRisk: false,
      remainingMs: 0,
      deadlineMs: 0,
      overridden: issue.slaOverride || false,
    };
  }

  // SLA override check
  if (issue.slaOverride) {
    return {
      status: "overridden",
      label: `SLA: Overridden`,
      color: "#8b5cf6",
      breached: false,
      atRisk: false,
      remainingMs: 0,
      deadlineMs: 0,
      overridden: true,
      overrideReason: issue.slaOverrideReason || "No reason provided",
    };
  }

  // Calculate deadline based on current status
  let deadlineMs = 0;
  let referenceMs = createdMs;

  if (issue.status === "open") {
    deadlineMs = createdMs + (config.open || 24) * MS_HOUR;
  } else if (issue.status === "assigned") {
    const assignedMs = tsToMs(issue.assignedAt) || createdMs;
    referenceMs = assignedMs;
    deadlineMs = assignedMs + (config.assigned || 48) * MS_HOUR;
  } else if (issue.status === "in_progress" || issue.status === "confirmed_threat") {
    const assignedMs = tsToMs(issue.assignedAt) || createdMs;
    referenceMs = assignedMs;
    deadlineMs = assignedMs + (config.in_progress || 72) * MS_HOUR;
  } else {
    // Other active states (escalation_pending, ir_in_progress, etc.)
    deadlineMs = createdMs + (config.assigned || 48) * MS_HOUR;
  }

  const remainingMs = deadlineMs - now;
  const breached = remainingMs < 0;
  const atRisk = !breached && remainingMs < 2 * MS_HOUR;

  let status, label, color;
  if (breached) {
    status = "breached";
    label = `⚠ BREACHED: ${formatDuration(Math.abs(remainingMs))} ago`;
    color = "#dc2626";
  } else if (atRisk) {
    status = "at_risk";
    label = `⏱ AT RISK: ${formatDuration(remainingMs)} left`;
    color = "#f59e0b";
  } else {
    status = "on_time";
    label = `✓ ${formatDuration(remainingMs)} left`;
    color = "#10b981";
  }

  return {
    status,
    label,
    color,
    breached,
    atRisk,
    remainingMs,
    deadlineMs,
    referenceMs,
    overridden: false,
  };
}

/* ---------- BATCH HELPERS ---------- */

/**
 * Check all incidents and flag SLA breaches.
 * Returns the list of breached incidents.
 */
export function findSLABreaches(issues, config = DEFAULT_SLA_HOURS) {
  return issues
    .filter(i => !i.isDeleted)
    .map(i => ({ ...i, sla: computeSLA(i, config) }))
    .filter(i => i.sla.breached);
}

/**
 * Check all incidents and flag at-risk SLAs.
 */
export function findSLAAtRisk(issues, config = DEFAULT_SLA_HOURS) {
  return issues
    .filter(i => !i.isDeleted)
    .map(i => ({ ...i, sla: computeSLA(i, config) }))
    .filter(i => i.sla.atRisk);
}

/**
 * Calculate SLA compliance rate.
 */
export function computeSLAComplianceRate(issues, config = DEFAULT_SLA_HOURS) {
  const active = issues.filter(i => !i.isDeleted);
  if (active.length === 0) return 100;

  const compliant = active.filter(i => !computeSLA(i, config).breached).length;
  return Math.round((compliant / active.length) * 100);
}

/* ---------- POLICY ENGINE HELPERS ---------- */

/**
 * Check if an incident should be auto-escalated based on policy rules.
 *
 * @param {Object} issue - incident document
 * @param {Object} policies - policy config from /config/policies
 * @returns {{ shouldEscalate: boolean, reason: string }}
 */
export function checkAutoEscalation(issue, policies = {}) {
  if (!policies.autoEscalation?.enabled) {
    return { shouldEscalate: false, reason: "" };
  }

  const sla = computeSLA(issue);

  // Policy: Auto-escalate on SLA breach
  if (sla.breached && policies.autoEscalation.onSLABreach) {
    return {
      shouldEscalate: true,
      reason: `SLA breached: ${sla.label}`,
    };
  }

  // Policy: Auto-escalate critical/high urgency after N hours
  if (policies.autoEscalation.highSeverityHours) {
    const createdMs = tsToMs(issue.createdAt);
    const ageHours = (Date.now() - createdMs) / MS_HOUR;
    const isHighPriority = ["high", "critical"].includes(issue.urgency);

    if (isHighPriority && ageHours > policies.autoEscalation.highSeverityHours && !issue.escalated) {
      return {
        shouldEscalate: true,
        reason: `High severity incident open for ${Math.round(ageHours)}h (threshold: ${policies.autoEscalation.highSeverityHours}h)`,
      };
    }
  }

  return { shouldEscalate: false, reason: "" };
}

/**
 * Validate if an action requires multi-stage approval.
 *
 * @param {string} actionType
 * @param {Object} policies
 * @returns {{ required: boolean, approversNeeded: number }}
 */
export function checkApprovalRequired(actionType, policies = {}) {
  const approvalConfig = policies.approvalChain || {};
  const config = approvalConfig[actionType];

  if (!config || !config.enabled) {
    return { required: false, approversNeeded: 0 };
  }

  return {
    required: true,
    approversNeeded: config.approversNeeded || 1,
    roles: config.approverRoles || ["soc_manager", "admin"],
  };
}

/* ---------- EXPORTS ---------- */

export { DEFAULT_SLA_HOURS, formatDuration };
