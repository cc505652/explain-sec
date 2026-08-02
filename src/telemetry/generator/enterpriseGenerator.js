/**
 * ======================================================================
 * EXPLAINSEC PHASE 2 — DECOUPLED ENTERPRISE TELEMETRY GENERATOR
 * ======================================================================
 * Emits pure enterprise operational background noise (95–98% benign)
 * across 23+ log sources. Has zero knowledge of active attack chains.
 * ======================================================================
 */

import { BENIGN_EVENT_TEMPLATES, ENTERPRISE_PROVIDERS } from "../eventLibrary/enterpriseLogSources.js";
import { getProfileById } from "./simulationProfiles.js";
import { createSecurityEvent } from "../types/securityEvent.js";

export class EnterpriseGenerator {
  constructor(prng) {
    this.prng = prng;
    this.currentProfile = getProfileById("MidEnterprise");
  }

  setProfile(profileId) {
    this.currentProfile = getProfileById(profileId);
  }

  /**
   * Generates a single benign enterprise operational event.
   * @returns {Object} SecurityEvent object
   */
  generateBackgroundEvent() {
    const template = this.prng.choice(BENIGN_EVENT_TEMPLATES);
    const provider = ENTERPRISE_PROVIDERS[template.providerKey] || ENTERPRISE_PROVIDERS.WindowsSecurity;

    const hostNum = this.prng.nextInt(1, this.currentProfile.endpointCount);
    const hostname = `WORKSTATION-${String(hostNum).padStart(3, "0")}`;
    const ipLast = (hostNum % 240) + 10;
    const ip = `192.168.1.${ipLast}`;
    const dept = this.prng.choice(this.currentProfile.departments);
    const userSurname = this.prng.choice(["smith", "doe", "johnson", "williams", "brown", "miller", "davis", "wilson"]);
    const username = `user.${userSurname}`;

    return createSecurityEvent({
      source: provider.source,
      sourceIcon: provider.icon,
      provider: provider.provider,
      product: provider.product,
      connectorId: "enterprise_generator",

      category: template.category,
      severity: template.severity,
      confidence: template.confidence,

      detectionRule: template.detectionRule,
      mitreTechnique: template.mitreTechnique,

      description: template.description,
      rawEvent: template.rawEvent,

      asset: {
        hostname,
        ip,
        type: "endpoint",
        department: dept,
        owner: username,
        criticality: hostNum <= 10 ? "critical" : "medium",
        location: "Corporate HQ"
      },

      user: {
        username,
        domain: this.currentProfile.userDomain,
        userPrincipalName: `${username}@${this.currentProfile.userDomain.toLowerCase()}`,
        role: "Corporate Staff"
      },

      network: {
        srcIp: ip,
        destIp: "10.0.0.1",
        srcPort: 49152 + (hostNum % 1000),
        destPort: 443,
        protocol: "TCP"
      }
    });
  }
}
