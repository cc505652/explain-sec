/**
 * errorHandler.js — Centralized error categorization and formatting
 *
 * Use these helpers to convert raw errors into user-friendly messages
 * and to decide whether an action is retryable.
 */

/**
 * Categorize and format an API/network error for user display.
 * @param {Error|unknown} err - The error thrown by callFunction
 * @param {string} [context]  - Brief description of what was attempted (prepended to message)
 * @returns {string} User-friendly error message
 */
export function handleApiError(err, context = "") {
  const msg   = err?.message || "An unknown error occurred";
  const prefix = context ? `${context}: ` : "";

  // ── Timeout ──────────────────────────────────────────────────────────────
  if (msg.includes("timed out")) {
    return `${prefix}Request timed out. Check your connection and try again.`;
  }

  // ── Network / fetch ───────────────────────────────────────────────────────
  if (/fetch|Network|Failed to fetch/i.test(msg)) {
    return `${prefix}Network error. Check your connection and try again.`;
  }

  // ── Authentication ────────────────────────────────────────────────────────
  if (/unauthorized|not authenticated|auth token/i.test(msg)) {
    return `${prefix}Session expired. Please log in again.`;
  }

  // ── Permissions ───────────────────────────────────────────────────────────
  if (/insufficient|permission|forbidden|Only .+ can/i.test(msg)) {
    return `${prefix}Insufficient permissions for this action.`;
  }

  // ── Conflict / already exists ─────────────────────────────────────────────
  if (/already|conflict/i.test(msg)) {
    return `${prefix}${msg}`;
  }

  // ── Validation errors ─────────────────────────────────────────────────────
  if (/missing|invalid|required|must be/i.test(msg)) {
    return `${prefix}${msg}`;
  }

  // ── Server errors ─────────────────────────────────────────────────────────
  if (/HTTP 5|server error|Internal server/i.test(msg)) {
    return `${prefix}Server error. Please try again in a moment.`;
  }

  // ── Fallback ──────────────────────────────────────────────────────────────
  return `${prefix}${msg}`;
}

/**
 * Determine if an error is retryable (network / timeout).
 * @param {Error|unknown} err
 * @returns {boolean}
 */
export function isRetryableError(err) {
  const msg = err?.message || "";
  return /timed out|fetch|Network|Failed to fetch/i.test(msg);
}

/**
 * Log an error with structured context (always goes to console.error).
 * @param {string}        functionName - Component or function where the error occurred
 * @param {Error|unknown} err
 * @param {Object}        [meta]       - Additional key-value pairs to log
 */
export function logError(functionName, err, meta = {}) {
  console.error(`[ERROR][${functionName}]`, {
    message: err?.message,
    stack:   err?.stack,
    ...meta,
  });
}
