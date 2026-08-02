/**
 * ======================================================================
 * EXPLAINSEC PHASE 2 — SECURITY EVENT SCHEMA (v2.0)
 * ======================================================================
 * Standardized telemetry schema for ingested security events across
 * all providers (Live Generator, Sentrix SIEM, CSV, REST API, Syslog, Webhooks).
 * ======================================================================
 */

import { telemetrySessionManager } from "../session/telemetrySessionManager.js";

export const SCHEMA_VERSION = "2.0";

export const SOURCE_ICONS = {
  DefenderForEndpoint: "🛡️",
  CrowdStrikeFalcon: "🦅",
  SentinelOne: "⚡",
  WindowsEventLog: "🪟",
  LinuxSyslog: "🐧",
  PaloAltoFirewall: "🌐",
  FortinetFirewall: "🧱",
  AzureAD: "☁️",
  AWSCloudTrail: "☁️",
  DNSProxy: "🌐",
  EmailSecurity: "📧",
  WebappFirewall: "🛡️",
  SuricataIDS: "🚨",
  Default: "🔍"
};

/**
 * Creates a valid, standardized SecurityEvent object.
 */
export function createSecurityEvent(params = {}) {
  const timestamp = params.timestamp || Date.now();
  const idSuffix = Math.random().toString(36).substring(2, 9);
  
  return {
    schemaVersion: SCHEMA_VERSION,
    eventId: params.eventId || `evt_${timestamp}_${idSuffix}`,
    sessionId: params.sessionId || telemetrySessionManager.getCurrentSessionId() || null,
    timestamp,
    
    // Ingestion Source & Provider Metadata
    source: params.source || "WindowsEventLog",
    sourceIcon: params.sourceIcon || SOURCE_ICONS[params.source] || SOURCE_ICONS.Default,
    provider: params.provider || "Microsoft",
    product: params.product || "Security Event Log",
    connectorId: params.connectorId || "live_generator",
    
    // Categorization & Severity
    category: params.category || "execution",
    severity: params.severity || "low", // low | medium | high | critical
    confidence: params.confidence ?? 80, // 0-100
    
    // Attack Campaign Context
    campaignId: params.campaignId || null,
    campaignName: params.campaignName || null,
    campaignStage: params.campaignStage || null,
    campaignStepIndex: params.campaignStepIndex || null,
    campaignTotalSteps: params.campaignTotalSteps || null,
    
    // Detection Rule Metadata
    detectionRule: params.detectionRule || {
      ruleId: "RULE-GENERIC-001",
      ruleName: "Generic Security Event Detection",
      mitreId: params.mitreTechnique?.id || "T1059",
      threshold: "1 event",
      confidence: params.confidence || 80,
      ruleVersion: "1.0",
      author: "ExplainSec Telemetry Engine"
    },
    
    // MITRE ATT&CK Mapping
    mitreTechnique: params.mitreTechnique || {
      id: "T1059",
      name: "Command and Scripting Interpreter",
      tactic: "Execution"
    },
    
    // Enriched Asset Context
    asset: {
      hostname: params.asset?.hostname || "WORKSTATION-01",
      ip: params.asset?.ip || "192.168.1.50",
      type: params.asset?.type || "endpoint",
      department: params.asset?.department || "General Corporate",
      owner: params.asset?.owner || "Unassigned Staff",
      criticality: params.asset?.criticality || "medium",
      location: params.asset?.location || "Campus Main Building"
    },
    
    // User Context
    user: {
      username: params.user?.username || "user.account",
      domain: params.user?.domain || "CAMPUS",
      userPrincipalName: params.user?.userPrincipalName || "user.account@campus.edu",
      role: params.user?.role || "Corporate User"
    },
    
    // Network Details
    network: params.network || {
      srcIp: params.asset?.ip || "192.168.1.50",
      destIp: "10.0.0.1",
      srcPort: 49152,
      destPort: 443,
      protocol: "TCP"
    },
    
    // Indicator of Compromise (IOC)
    ioc: params.ioc || null,
    
    // Raw Event Payload & Summary
    rawEvent: params.rawEvent || JSON.stringify({ EventID: 4688, Message: "Process Creation" }),
    description: params.description || "Security event observed",
    eventStatus: params.eventStatus || "standardized" // raw | standardized | enriched | classified | correlated | promoted | suppressed
  };
}

/**
 * Validates a SecurityEvent object schema.
 */
export function validateSecurityEvent(event) {
  if (!event || typeof event !== "object") return { valid: false, error: "Event must be an object" };
  if (!event.eventId) return { valid: false, error: "Missing eventId" };
  if (!event.timestamp) return { valid: false, error: "Missing timestamp" };
  if (!event.source) return { valid: false, error: "Missing source" };
  if (!event.category) return { valid: false, error: "Missing category" };
  return { valid: true };
}
