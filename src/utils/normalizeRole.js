/**
 * ======================================================================
 * CANONICAL ROLE NORMALIZATION — Single Source of Truth
 * ======================================================================
 *
 * ALL role comparisons across the platform MUST use this module.
 * No other file should define its own role normalization logic.
 *
 * Canonical roles:
 *   soc_l1 | soc_l2 | soc_manager | ir | admin | threat_hunter | student
 *
 * Unknown roles resolve to: null (NEVER pass through raw values)
 * ======================================================================
 */

/* ---------- CANONICAL ROLE SET ---------- */

export const CANONICAL_ROLES = Object.freeze([
  "soc_l1",
  "soc_l2",
  "soc_manager",
  "ir",
  "admin",
  "threat_hunter",
  "student",
]);

/* ---------- DISPLAY LABELS ---------- */

const ROLE_DISPLAY_LABELS = Object.freeze({
  soc_l1: "SOC L1 Analyst",
  soc_l2: "SOC L2 Analyst",
  soc_manager: "SOC Manager",
  ir: "Incident Response",
  admin: "Administrator",
  threat_hunter: "Threat Hunter",
  student: "Reporter",
  system: "Auto-Routed",
  null: "Unassigned",
});

/* ---------- ALIAS MAP ---------- */

const roleAliasMap = Object.freeze({
  // ── soc_l1 ──────────────────────────
  "soc_l1": "soc_l1",
  "socl1": "soc_l1",
  "soc1": "soc_l1",
  "soc_11": "soc_l1",
  "l1": "soc_l1",
  "analyst": "soc_l1",
  "SOC L1": "soc_l1",   // legacy alias

  // ── soc_l2 ──────────────────────────
  "soc_l2": "soc_l2",
  "socl2": "soc_l2",
  "soc2": "soc_l2",
  "soc_12": "soc_l2",
  "l2": "soc_l2",
  "SOC L2": "soc_l2",

  // ── soc_manager ─────────────────────
  "soc_manager": "soc_manager",
  "socmanager": "soc_manager",
  "soc_13": "soc_manager",
  "manager": "soc_manager",
  "SOC Manager": "soc_manager",

  // ── ir ──────────────────────────────
  "ir": "ir",
  "ir_team": "ir",
  "irteam": "ir",
  "incident_response": "ir",
  "incidentresponse": "ir",
  "Incident Response": "ir",
  "IR Team": "ir",

  // ── admin ───────────────────────────
  "admin": "admin",
  "Admin": "admin",
  "Administrator": "admin",

  // ── threat_hunter ───────────────────
  "threat_hunter": "threat_hunter",
  "threathunter": "threat_hunter",
  "Threat Hunter": "threat_hunter",
  "THREAT HUNTER": "threat_hunter",

  // ── student ─────────────────────────
  "student": "student",
  "Student": "student",
  "STUDENT": "student",
});

/* ---------- CORE FUNCTION ---------- */

/**
 * Normalize any role string to its canonical form.
 *
 * Handles: mixed casing, spaces, hyphens, underscores, legacy aliases.
 * Returns `null` for unknown/invalid roles — NEVER returns raw input.
 *
 * @param {*} role - Raw role value
 * @returns {string|null} Canonical role or null
 */
export const normalizeRole = (role) => {
  if (!role || typeof role !== "string") return null;

  const cleaned = role
    .trim()
    .toLowerCase()
    .replace(/[\s-]+/g, "_")
    .replace(/__+/g, "_");

  // Check alias map — returns canonical role or null
  return roleAliasMap[cleaned] ?? null;
};

/* ---------- HELPERS ---------- */

/**
 * Normalize an array of roles.
 * Filters out null results (invalid roles).
 *
 * @param {string[]} roles
 * @returns {string[]} Array of canonical roles
 */
export const normalizeRoles = (roles) => {
  if (!roles || !Array.isArray(roles)) return [];
  return roles.map(normalizeRole).filter(Boolean);
};

/**
 * Check if a role string is already in canonical form.
 *
 * @param {string} role
 * @returns {boolean}
 */
export const isCanonicalRole = (role) => {
  return CANONICAL_ROLES.includes(role);
};

/**
 * Get the display label for a canonical role.
 * Returns the role string itself if not found (graceful degradation).
 *
 * @param {string} canonicalRole
 * @returns {string} Human-readable label
 */
export const getRoleDisplayLabel = (canonicalRole) => {
  if (!canonicalRole || canonicalRole === "null") return ROLE_DISPLAY_LABELS.null;
  return ROLE_DISPLAY_LABELS[canonicalRole] || canonicalRole || ROLE_DISPLAY_LABELS.null;
};

/* ---------- INCIDENT PARTY NORMALIZATION ---------- */

/**
 * Normalize Firestore assignment / escalation targets
 * ("IR Team", UIDs, role ids) to a canonical role key when possible.
 *
 * If the value looks like a UID (20+ alphanumeric chars), it is returned as-is.
 */
export const normalizeIncidentParty = (raw) => {
  if (raw == null || raw === "") return null;
  if (typeof raw === "string") {
    const t = raw.trim();
    if (t === "IR Team" || /^ir[\s_-]?team$/i.test(t)) return "ir";
    // UIDs are long alphanumeric strings — pass through unchanged
    if (/^[a-zA-Z0-9_-]{20,}$/.test(t)) return t;
  }
  return normalizeRole(String(raw));
};