/**
 * ======================================================================
 * CAMPUS SOC — RISK ENGINE (Phase 2 — Incident Intelligence)
 * ======================================================================
 *
 * Centralized risk scoring, attack stage mapping, and confidence
 * computation. Used by both the UI layer and Cloud Functions.
 *
 * Architecture:
 * - Client-side: display-only computations (no writes)
 * - Server-side: socActions.js calls computeRiskScore() before writes
 *
 * All fields are OPTIONAL — old incidents without them still render.
 * ======================================================================
 */

/* ---------- ATTACK STAGES (MITRE ATT&CK Kill Chain) ---------- */

export const ATTACK_STAGES = Object.freeze({
  reconnaissance:          { order: 1, label: "Reconnaissance",          mitre: "TA0043", color: "#64748b" },
  weaponization:           { order: 2, label: "Weaponization",           mitre: "TA0001", color: "#8b5cf6" },
  delivery:                { order: 3, label: "Delivery",                mitre: "TA0001", color: "#3b82f6" },
  exploitation:            { order: 4, label: "Exploitation",            mitre: "TA0002", color: "#f59e0b" },
  installation:            { order: 5, label: "Installation",            mitre: "TA0003", color: "#ef4444" },
  command_and_control:     { order: 6, label: "Command & Control",       mitre: "TA0011", color: "#dc2626" },
  actions_on_objectives:   { order: 7, label: "Actions on Objectives",   mitre: "TA0040", color: "#991b1b" },
});

export const ATTACK_STAGE_OPTIONS = Object.entries(ATTACK_STAGES).map(
  ([key, val]) => ({ value: key, label: val.label, order: val.order })
);

/* ---------- MITRE ATT&CK TECHNIQUE MAPPING ---------- */

export const MITRE_MAPPING = Object.freeze({
  phishing:            { tactic: "TA0006", technique: "T1566",   name: "Phishing" },
  malware:             { tactic: "TA0002", technique: "T1204",   name: "User Execution" },
  account_compromise:  { tactic: "TA0006", technique: "T1110",   name: "Brute Force" },
  network_attack:      { tactic: "TA0007", technique: "T1046",   name: "Network Service Discovery" },
  data_leak:           { tactic: "TA0010", technique: "T1041",   name: "Exfiltration Over C2 Channel" },
  ransomware:          { tactic: "TA0040", technique: "T1486",   name: "Data Encrypted for Impact" },
  insider_threat:      { tactic: "TA0010", technique: "T1567",   name: "Exfiltration Over Web Service" },
  ddos:                { tactic: "TA0040", technique: "T1498",   name: "Network Denial of Service" },
  access:              { tactic: "TA0001", technique: "T1078",   name: "Valid Accounts" },
  network:             { tactic: "TA0007", technique: "T1046",   name: "Network Service Discovery" },
  other:               { tactic: "TA0043", technique: "T1595",   name: "Active Scanning" },
});

/* ---------- URGENCY WEIGHTS ---------- */

const URGENCY_WEIGHTS = Object.freeze({
  critical: 4,
  high:     3,
  medium:   2,
  low:      1,
});

/* ---------- STAGE WEIGHTS (deeper in kill chain = higher risk) ---------- */

const STAGE_WEIGHTS = Object.freeze({
  reconnaissance:        1,
  weaponization:         2,
  delivery:              3,
  exploitation:          4,
  installation:          5,
  command_and_control:   6,
  actions_on_objectives: 7,
});

/* ---------- RISK SCORE COMPUTATION ---------- */

/**
 * Compute a risk score (0-100) from incident attributes.
 *
 * Formula:
 *   riskScore = clamp(0, 100,
 *     (urgencyWeight * 10)
 *     + (stageWeight * 8)
 *     + (confidenceScore * 0.3)
 *     + (escalated ? 10 : 0)
 *     + (slaBreached ? 10 : 0)
 *   )
 *
 * All inputs are optional; defaults produce a score of 20 (low risk).
 *
 * @param {Object} params
 * @param {string} [params.urgency]          - low|medium|high|critical
 * @param {string} [params.attackStage]      - one of ATTACK_STAGES keys
 * @param {number} [params.confidenceScore]  - 0-100
 * @param {boolean} [params.escalated]       - whether incident is escalated
 * @param {boolean} [params.slaBreached]     - whether SLA is breached
 * @returns {{ score: number, level: string, color: string }}
 */
export function computeRiskScore({
  urgency = "medium",
  attackStage = null,
  confidenceScore = 50,
  escalated = false,
  slaBreached = false,
} = {}) {
  const urgencyWeight = URGENCY_WEIGHTS[urgency] || 2;
  const stageWeight   = attackStage ? (STAGE_WEIGHTS[attackStage] || 1) : 1;
  const confidence    = Math.max(0, Math.min(100, confidenceScore));

  let raw =
    urgencyWeight * 10 +
    stageWeight * 8 +
    confidence * 0.3 +
    (escalated ? 10 : 0) +
    (slaBreached ? 10 : 0);

  const score = Math.round(Math.max(0, Math.min(100, raw)));

  let level, color;
  if (score >= 80) {
    level = "critical";
    color = "#dc2626";
  } else if (score >= 60) {
    level = "high";
    color = "#ef4444";
  } else if (score >= 40) {
    level = "medium";
    color = "#f59e0b";
  } else {
    level = "low";
    color = "#22c55e";
  }

  return { score, level, color };
}

/* ---------- CONFIDENCE SCORE ---------- */

/**
 * Estimate confidence based on available evidence and AI classification.
 *
 * @param {Object} params
 * @param {string} [params.aiEngine]       - "rules" | null
 * @param {number} [params.evidenceCount]  - number of attached evidence items
 * @param {boolean} [params.hasMitreMatch] - whether category maps to MITRE
 * @param {boolean} [params.analystConfirmed] - whether analyst confirmed threat
 * @returns {number} 0-100
 */
export function computeConfidenceScore({
  aiEngine = null,
  evidenceCount = 0,
  hasMitreMatch = false,
  analystConfirmed = false,
} = {}) {
  let base = 20; // default baseline

  if (aiEngine === "rules") base += 15;

  base += Math.min(evidenceCount * 10, 30); // max 30 from evidence
  if (hasMitreMatch) base += 10;
  if (analystConfirmed) base += 15;

  return Math.min(100, base);
}

/* ---------- DISPLAY HELPERS ---------- */

/**
 * Get risk level display pill data from a risk score.
 */
export function getRiskPill(score) {
  if (score == null) return { label: "—", bg: "#475569", color: "#fff" };

  if (score >= 80) return { label: "CRITICAL", bg: "#dc2626", color: "#fff" };
  if (score >= 60) return { label: "HIGH",     bg: "#ef4444", color: "#fff" };
  if (score >= 40) return { label: "MEDIUM",   bg: "#f59e0b", color: "#000" };
  return                   { label: "LOW",      bg: "#22c55e", color: "#fff" };
}

/**
 * Get attack stage display data.
 */
export function getAttackStageDisplay(stageKey) {
  if (!stageKey || !ATTACK_STAGES[stageKey]) {
    return { label: "Unknown", color: "#64748b", order: 0 };
  }
  return ATTACK_STAGES[stageKey];
}

/**
 * Get MITRE ATT&CK info for a category.
 */
export function getMitreInfo(category) {
  if (!category) return null;
  return MITRE_MAPPING[category.toLowerCase()] || MITRE_MAPPING["other"] || null;
}

/* ---------- INCIDENT AGING ---------- */

/**
 * Calculate incident age in hours and return aging indicator.
 * @param {Object} createdAt - Firestore timestamp or Date
 * @returns {{ ageHours: number, label: string, color: string }}
 */
export function getIncidentAging(createdAt) {
  if (!createdAt) return { ageHours: 0, label: "Unknown", color: "#64748b" };

  const ms = createdAt.toMillis ? createdAt.toMillis() :
             createdAt.seconds ? createdAt.seconds * 1000 :
             createdAt instanceof Date ? createdAt.getTime() : 0;

  const ageHours = (Date.now() - ms) / (60 * 60 * 1000);

  if (ageHours > 72) return { ageHours, label: "Stale",  color: "#dc2626" };
  if (ageHours > 24) return { ageHours, label: "Aging",  color: "#f59e0b" };
  if (ageHours > 6)  return { ageHours, label: "Active", color: "#3b82f6" };
  return                     { ageHours, label: "Fresh",  color: "#22c55e" };
}

/* ---------- NOISE SCORING ---------- */

/**
 * Score how likely an incident is noise (0 = definitely real, 100 = likely noise).
 *
 * @param {Object} params
 * @param {string} [params.category]
 * @param {string} [params.aiEngine]
 * @param {number} [params.falsePositiveRate] - historical FP rate for category (0-1)
 * @param {number} [params.descriptionLength]
 * @returns {number} 0-100
 */
export function computeNoiseScore({
  category = "other",
  aiEngine = null,
  falsePositiveRate = 0,
  descriptionLength = 0,
} = {}) {
  let noise = 50; // baseline

  // Short descriptions = more likely noise
  if (descriptionLength < 20) noise += 15;
  else if (descriptionLength > 100) noise -= 10;

  // AI engine confidence
  if (aiEngine === "rules") noise -= 5;

  // Historical false positive rate
  noise += Math.round(falsePositiveRate * 30);

  return Math.max(0, Math.min(100, noise));
}

/* ---------- SCHEMA CONSTANTS ---------- */

/**
 * New fields added to the incident schema in Phase 2.
 * All are OPTIONAL — backward compatible with existing incidents.
 */
export const PHASE2_SCHEMA_FIELDS = Object.freeze({
  riskScore:        { type: "number",  default: null,  description: "Computed risk score (0-100)" },
  confidenceScore:  { type: "number",  default: null,  description: "Confidence in classification (0-100)" },
  attackStage:      { type: "string",  default: null,  description: "Kill chain stage" },
  tags:             { type: "array",   default: [],    description: "User-defined tags" },
  affectedAssets:   { type: "array",   default: [],    description: "List of affected assets" },
  timelineEvents:   { type: "array",   default: [],    description: "Custom timeline entries" },
  evidenceList:     { type: "array",   default: [],    description: "Evidence items (files, links, notes)" },
  ownerUid:         { type: "string",  default: null,  description: "Primary owner UID" },
  noiseScore:       { type: "number",  default: null,  description: "Noise probability (0-100)" },
});
