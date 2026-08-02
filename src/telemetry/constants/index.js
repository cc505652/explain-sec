/**
 * ======================================================================
 * EXPLAINSEC PHASE 2 — CENTRAL TELEMETRY CONSTANTS REGISTRY
 * ======================================================================
 * Central source of truth for severities, categories, cluster states,
 * thresholds, engine modes, connector IDs, and rule identifiers.
 * ======================================================================
 */

export const SEVERITIES = {
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
  CRITICAL: "critical"
};

export const CATEGORIES = {
  CREDENTIAL_ACCESS: "credential_access",
  EXECUTION: "execution",
  PERSISTENCE: "persistence",
  PRIVILEGE_ESCALATION: "privilege_escalation",
  DISCOVERY: "discovery",
  LATERAL_MOVEMENT: "lateral_movement",
  COLLECTION: "collection",
  EXFILTRATION: "exfiltration",
  COMMAND_AND_CONTROL: "command_and_control"
};

export const CLUSTER_STATES = {
  OPEN: "OPEN",
  CORRELATING: "CORRELATING",
  QUALIFIED: "QUALIFIED",
  INCIDENT_CREATED: "INCIDENT_CREATED",
  SUPPRESSED: "SUPPRESSED",
  ARCHIVED: "ARCHIVED"
};

export const ENGINE_MODES = {
  TRAINING: "Training",
  NORMAL_ENTERPRISE: "Normal Enterprise",
  HIGH_THREAT: "High Threat",
  RED_TEAM: "Red Team Exercise",
  CHAOS: "Chaos Mode"
};

export const CONNECTOR_IDS = {
  LIVE_GENERATOR: "live_generator",
  SENTRIX_SIEM: "sentrix_siem",
  CSV_IMPORT: "csv_import",
  REST_API: "rest_api",
  SYSLOG: "syslog_receiver",
  WEBHOOK: "webhook_ingress"
};

export const TIME_WINDOWS_MS = {
  WINDOW_60S: 60 * 1000,
  WINDOW_5M: 5 * 60 * 1000,
  WINDOW_10M: 10 * 60 * 1000,
  WINDOW_30M: 30 * 60 * 1000
};

export const QUALIFICATION_THRESHOLDS = {
  MIN_RISK_SCORE: 60,
  MIN_CONFIDENCE: 75,
  SINGLE_CRITICAL_RISK: 90
};
