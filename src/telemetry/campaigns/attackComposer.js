/**
 * ======================================================================
 * EXPLAINSEC PHASE 2 — DYNAMIC ATTACK COMPOSER
 * ======================================================================
 * State Machine FSM executing 0 to 5 concurrent attack chains.
 * Attacks advance through FSM states (InitialAccess -> Execution ->
 * CredentialAccess -> Persistence -> Discovery -> Decision ->
 * LateralMovement -> Collection -> Exfiltration).
 *
 * Attacks can be blocked (e.g. Defender blocks script, account locked)
 * or abandoned midway, producing realistic incomplete investigations.
 * ======================================================================
 */

import { ATTACKER_PROFILES } from "./attackerProfiles.js";
import { getTemplateById } from "../eventLibrary/index.js";
import { createSecurityEvent } from "../types/securityEvent.js";

// FSM State Definitions
export const FSM_STATES = [
  "InitialAccess",
  "Execution",
  "CredentialAccess",
  "Persistence",
  "Discovery",
  "LateralMovement",
  "Exfiltration",
  "Terminated"
];

export class AttackComposer {
  constructor(prng) {
    this.prng = prng;
    this.activeChains = [];
    this.chainCounter = 0;
  }

  reset() {
    this.activeChains = [];
    this.chainCounter = 0;
  }

  /**
   * Spawn 0-5 dynamic attack chains based on simulation profile.
   */
  initializeChains(count = 2) {
    this.activeChains = [];
    const profiles = Object.values(ATTACKER_PROFILES);

    for (let i = 0; i < count; i++) {
      const profile = this.prng.choice(profiles);
      const chainId = `chain_${Date.now()}_${++this.chainCounter}`;
      const targetHost = `FINANCE-PC-${String(this.prng.nextInt(10, 99)).padStart(3, "0")}`;
      const targetUser = `user.${this.prng.choice(["smith", "doe", "johnson", "williams", "miller"])}`;

      this.activeChains.push({
        chainId,
        profile,
        targetHost,
        targetUser,
        currentState: "InitialAccess",
        stepIndex: 0,
        status: "active", // active | terminated_blocked | terminated_abandoned | completed
        generatedEvents: [],
        lastStepTime: 0
      });
    }
  }

  /**
   * Advance one active chain by 1 FSM state and return the resulting SecurityEvent.
   * Handles failure and abandonment checks.
   */
  stepNext() {
    // If no active chains exist or all are terminated, spin up a new chain occasionally
    const eligibleChains = this.activeChains.filter(c => c.status === "active");
    if (eligibleChains.length === 0) {
      if (this.activeChains.length < 5) {
        this.initializeChains(1);
      } else {
        return null;
      }
    }

    const chain = this.prng.choice(this.activeChains.filter(c => c.status === "active"));
    if (!chain) return null;

    // Check for failure / abandonment probability
    const rollFailure = this.prng.nextFloat();
    if (rollFailure < chain.profile.failureRate * 0.3) {
      chain.status = "terminated_blocked";
      return this._createBlockedEvent(chain);
    }
    if (rollFailure < chain.profile.abandonmentRate * 0.2) {
      chain.status = "terminated_abandoned";
      return null;
    }

    // Determine state template mapping
    const templateIdMap = {
      InitialAccess: "CRED_PASS_SPRAY_01",
      Execution: "T1059.001",
      CredentialAccess: "T1003.001",
      Persistence: "T1547.001",
      Discovery: "T1046",
      LateralMovement: "T1021.002",
      Exfiltration: "T1041"
    };

    const templateId = templateIdMap[chain.currentState] || "T1059.001";
    const template = getTemplateById(templateId);
    if (!template) {
      this._advanceState(chain);
      return null;
    }

    // Build event enriched with attack chain context
    const securityEvent = createSecurityEvent({
      source: template.source,
      provider: template.provider,
      product: template.product,
      category: template.category,
      severity: template.severity,
      confidence: template.confidence,
      mitreTechnique: template.mitreTechnique,
      detectionRule: template.detectionRule,
      description: `[ATTACKER: ${chain.profile.name}] State (${chain.currentState}): ${template.description}`,
      rawEvent: template.rawEvent,
      ioc: template.ioc || { ip: "198.51.100.45", domain: "c2.malicious-actor.org" },

      campaignId: chain.chainId,
      campaignName: `${chain.profile.name} Activity`,
      campaignStage: chain.currentState,
      campaignStepIndex: chain.stepIndex + 1,
      campaignTotalSteps: 7,

      asset: {
        hostname: chain.targetHost,
        ip: `192.168.1.${this.prng.nextInt(50, 200)}`,
        type: "endpoint",
        department: "Finance Operations",
        owner: chain.targetUser,
        criticality: "high",
        location: "Corporate HQ"
      },

      user: {
        username: chain.targetUser,
        domain: "CAMPUS",
        userPrincipalName: `${chain.targetUser}@campus.edu`,
        role: "Corporate User"
      }
    });

    chain.generatedEvents.push(securityEvent);
    chain.stepIndex++;
    this._advanceState(chain);

    return securityEvent;
  }

  _advanceState(chain) {
    const states = ["InitialAccess", "Execution", "CredentialAccess", "Persistence", "Discovery", "LateralMovement", "Exfiltration"];
    const idx = states.indexOf(chain.currentState);
    if (idx >= 0 && idx < states.length - 1) {
      chain.currentState = states[idx + 1];
    } else {
      chain.status = "completed";
      chain.currentState = "Terminated";
    }
  }

  _createBlockedEvent(chain) {
    return createSecurityEvent({
      source: "DefenderForEndpoint",
      sourceIcon: "🛡️",
      provider: "Microsoft",
      product: "Defender EDR",
      connectorId: "attack_composer",

      category: "execution",
      severity: "high",
      confidence: 90,

      description: `[DEFENDER BLOCKED] Malicious script execution terminated on ${chain.targetHost} (${chain.profile.name})`,
      rawEvent: JSON.stringify({ EventID: 1116, Action: "Blocked", ThreatName: "Trojan:Win32/PowerShell.A" }),

      mitreTechnique: { id: "T1059.001", name: "PowerShell", tactic: "Execution" },
      detectionRule: { ruleId: "DET-DEFENDER-BLOCK", ruleName: "Endpoint Protection Block Event", threshold: "1 event" },

      asset: { hostname: chain.targetHost, ip: "192.168.1.100", type: "endpoint", criticality: "high" },
      user: { username: chain.targetUser, domain: "CAMPUS" }
    });
  }

  getActiveChainsCount() {
    return this.activeChains.filter(c => c.status === "active").length;
  }
}
