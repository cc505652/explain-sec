/**
 * ======================================================================
 * ASSIGNMENT HELPER — Standardized assignedTo handling
 * ======================================================================
 *
 * Ensures assignedTo values are deterministic and consistently typed.
 * Separates assignment identity from type from display.
 * ======================================================================
 */

import { normalizeRole, getRoleDisplayLabel, CANONICAL_ROLES } from "./normalizeRole";

/**
 * Standardize assignedTo values for Firestore writes.
 *
 * @param {*} raw - could be UID string, role string, object, null, undefined
 * @returns {{ assignedTo: string|null, assignedToType: "uid"|"role"|null }}
 */
export function normalizeAssignment(raw) {
  if (raw == null || raw === "") {
    return { assignedTo: null, assignedToType: null };
  }

  if (typeof raw !== "string") {
    return { assignedTo: null, assignedToType: null };
  }

  const trimmed = raw.trim();

  // Check if it's a UID (long alphanumeric string)
  if (/^[a-zA-Z0-9_-]{20,}$/.test(trimmed)) {
    return { assignedTo: trimmed, assignedToType: "uid" };
  }

  // Try to normalize as a role
  const normalized = normalizeRole(trimmed);
  if (normalized) {
    return { assignedTo: normalized, assignedToType: "role" };
  }

  // Unknown — treat as UID (could be a short UID or external reference)
  return { assignedTo: trimmed, assignedToType: "uid" };
}

/**
 * Get display label for an assignedTo value.
 *
 * @param {string|null} assignedTo
 * @param {object} usersData - Map of uid → user data (optional)
 * @returns {string}
 */
export function getAssignmentDisplayLabel(assignedTo, usersData = null) {
  if (!assignedTo) return "Unassigned";

  // Check user data first
  if (usersData && usersData[assignedTo]) {
    const user = usersData[assignedTo];
    return user.displayName || user.email || user.name || assignedTo;
  }

  // Check if it's a canonical role
  const normalized = normalizeRole(assignedTo);
  if (normalized) {
    return getRoleDisplayLabel(normalized);
  }

  // Fallback
  if (assignedTo.includes("@")) {
    return assignedTo.split("@")[0];
  }
  return assignedTo;
}

/**
 * Validate incident data before creation.
 * Returns { valid: boolean, errors: string[] }
 *
 * @param {object} data - Incident data to validate
 * @returns {{ valid: boolean, errors: string[] }}
 */
export function validateIncidentCreate(data) {
  const errors = [];

  if (!data.title || typeof data.title !== "string" || data.title.trim().length === 0) {
    errors.push("Title is required");
  }

  if (!data.description || typeof data.description !== "string" || data.description.trim().length === 0) {
    errors.push("Description is required");
  }

  const validUrgencies = ["low", "medium", "high", "critical"];
  if (data.urgency && !validUrgencies.includes(data.urgency)) {
    errors.push(`Invalid urgency: ${data.urgency}. Must be one of: ${validUrgencies.join(", ")}`);
  }

  // assignedTo validation
  if (data.assignedTo) {
    const { assignedTo, assignedToType } = normalizeAssignment(data.assignedTo);
    if (!assignedTo) {
      errors.push(`Invalid assignedTo value: ${data.assignedTo}`);
    }
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}
