/**
 * Structured Logging Utility for SOC Platform
 * Provides consistent, searchable logs for debugging and audit trails
 */

export const LOG_LEVELS = {
  DEBUG: 'DEBUG',
  INFO: 'INFO',
  WARN: 'WARN',
  ERROR: 'ERROR',
  ACTION: 'ACTION',
  AUTH: 'AUTH',
  DB: 'DB',
  RESPONSE: 'RESPONSE'
};

/**
 * Log a structured message
 * @param {string} level - Log level (DEBUG, INFO, WARN, ERROR, ACTION, AUTH, DB, RESPONSE)
 * @param {string} category - Log category (e.g., 'escalation', 'containment', 'role')
 * @param {string} message - Log message
 * @param {object} data - Additional data to log
 */
export function log(level, category, message, data = {}) {
  const timestamp = new Date().toISOString();
  const logEntry = {
    timestamp,
    level,
    category,
    message,
    ...data
  };

  const prefix = `[${level}] [${category}]`;
  
  switch (level) {
    case LOG_LEVELS.ERROR:
      console.error(prefix, message, data);
      break;
    case LOG_LEVELS.WARN:
      console.warn(prefix, message, data);
      break;
    case LOG_LEVELS.DEBUG:
      console.debug(prefix, message, data);
      break;
    default:
      console.log(prefix, message, data);
  }

  return logEntry;
}

/**
 * Log an action (user-initiated operation)
 * @param {string} category - Action category
 * @param {string} action - Action name
 * @param {object} data - Additional data
 */
export function logAction(category, action, data = {}) {
  return log(LOG_LEVELS.ACTION, category, action, data);
}

/**
 * Log an authentication event
 * @param {string} event - Auth event (e.g., 'login', 'logout', 'role_check')
 * @param {object} data - Additional data
 */
export function logAuth(event, data = {}) {
  return log(LOG_LEVELS.AUTH, 'auth', event, data);
}

/**
 * Log a database operation
 * @param {string} operation - DB operation (e.g., 'read', 'write', 'query')
 * @param {string} collection - Collection name
 * @param {object} data - Additional data
 */
export function logDB(operation, collection, data = {}) {
  return log(LOG_LEVELS.DB, collection, operation, data);
}

/**
 * Log an API response
 * @param {string} endpoint - API endpoint
 * @param {number} status - HTTP status
 * @param {object} data - Additional data
 */
export function logResponse(endpoint, status, data = {}) {
  return log(LOG_LEVELS.RESPONSE, endpoint, `Status: ${status}`, data);
}

/**
 * Log an error with context
 * @param {string} category - Error category
 * @param {Error} error - Error object
 * @param {object} context - Additional context
 */
export function logError(category, error, context = {}) {
  return log(LOG_LEVELS.ERROR, category, error.message, {
    stack: error.stack,
    code: error.code,
    ...context
  });
}
