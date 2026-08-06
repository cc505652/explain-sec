/**
 * Central Event Library Index (MITRE ATT&CK Telemetry Templates)
 */

import { credentialAccessTemplates } from "./credentialAccess.js";
import { executionTemplates } from "./execution.js";
import { persistenceTemplates } from "./persistence.js";
import { privilegeEscalationTemplates } from "./privilegeEscalation.js";
import { discoveryTemplates } from "./discovery.js";
import { lateralMovementTemplates } from "./lateralMovement.js";
import { collectionTemplates } from "./collection.js";
import { exfiltrationTemplates } from "./exfiltration.js";
import { commandAndControlTemplates } from "./commandAndControl.js";

export const EVENT_LIBRARY_BY_TACTIC = {
  credential_access: credentialAccessTemplates,
  execution: executionTemplates,
  persistence: persistenceTemplates,
  privilege_escalation: privilegeEscalationTemplates,
  discovery: discoveryTemplates,
  lateral_movement: lateralMovementTemplates,
  collection: collectionTemplates,
  exfiltration: exfiltrationTemplates,
  command_and_control: commandAndControlTemplates
};

export const ALL_EVENT_TEMPLATES = [
  ...credentialAccessTemplates,
  ...executionTemplates,
  ...persistenceTemplates,
  ...privilegeEscalationTemplates,
  ...discoveryTemplates,
  ...lateralMovementTemplates,
  ...collectionTemplates,
  ...exfiltrationTemplates,
  ...commandAndControlTemplates
];

/**
 * Returns a template by ID or category.
 */
export function getTemplateById(id) {
  if (!id) return null;
  return ALL_EVENT_TEMPLATES.find(t => t.templateId === id || t.mitreTechnique?.id === id) || null;
}

export function getTemplatesByTactic(tactic) {
  return EVENT_LIBRARY_BY_TACTIC[tactic] || [];
}
