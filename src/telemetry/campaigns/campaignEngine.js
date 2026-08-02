/**
 * Campaign Engine & Replay Manager
 */

import { PREBUILT_ATTACK_CAMPAIGNS } from "./attackCampaigns.js";
import { getTemplateById } from "../eventLibrary/index.js";
import { createSecurityEvent } from "../types/securityEvent.js";

export class CampaignEngine {
  constructor(prng) {
    this.prng = prng;
    this.activeCampaign = null;
    this.currentStepIndex = 0;
    this.isReplaying = false;
    this.replaySpeed = 1;
    this.campaignHistory = [];
  }

  reset() {
    this.activeCampaign = null;
    this.currentStepIndex = 0;
    this.isReplaying = false;
    this.campaignHistory = [];
  }

  /**
   * Starts a specified campaign or picks a random pre-built campaign.
   */
  startCampaign(campaignId = null) {
    const scenario = campaignId 
      ? PREBUILT_ATTACK_CAMPAIGNS.find(c => c.campaignId === campaignId)
      : this.prng.choice(PREBUILT_ATTACK_CAMPAIGNS);
      
    if (!scenario) return null;

    const instanceId = `${scenario.campaignId}_${Date.now()}`;
    const targetHost = `FINANCE-PC-0${this.prng.nextInt(10, 99)}`;
    const targetUser = `user.${this.prng.choice(["smith", "doe", "johnson", "williams"])}`;

    this.activeCampaign = {
      instanceId,
      campaignId: scenario.campaignId,
      name: scenario.name,
      threatActor: scenario.threatActor,
      description: scenario.description,
      steps: scenario.steps,
      currentStepIndex: 0,
      totalSteps: scenario.steps.length,
      targetHost,
      targetUser,
      startTime: Date.now(),
      status: "active",
      generatedEvents: []
    };

    this.currentStepIndex = 0;
    return this.activeCampaign;
  }

  /**
   * Advances the active campaign by 1 step and produces a SecurityEvent.
   */
  stepNext() {
    if (!this.activeCampaign || this.activeCampaign.status !== "active") {
      this.startCampaign();
    }

    const campaign = this.activeCampaign;
    const stepDef = campaign.steps[campaign.currentStepIndex];
    if (!stepDef) {
      campaign.status = "completed";
      this.campaignHistory.push({ ...campaign });
      return null;
    }

    const template = getTemplateById(stepDef.templateId);
    if (!template) {
      campaign.currentStepIndex++;
      return null;
    }

    // Build event enriched with campaign context
    const securityEvent = createSecurityEvent({
      source: template.source,
      provider: template.provider,
      product: template.product,
      category: template.category,
      severity: template.severity,
      confidence: template.confidence,
      mitreTechnique: template.mitreTechnique,
      detectionRule: template.detectionRule,
      description: `[CAMPAIGN: ${campaign.name}] Step ${stepDef.stepIndex}/${campaign.totalSteps} (${stepDef.stageName}): ${template.description}`,
      rawEvent: template.rawEvent,
      ioc: template.ioc || null,
      
      campaignId: campaign.instanceId,
      campaignName: campaign.name,
      campaignStage: stepDef.stageName,
      campaignStepIndex: stepDef.stepIndex,
      campaignTotalSteps: campaign.totalSteps,
      
      asset: {
        hostname: campaign.targetHost,
        ip: `192.168.1.${this.prng.nextInt(100, 200)}`,
        type: "endpoint",
        department: "Finance Operations",
        owner: campaign.targetUser,
        criticality: "high",
        location: "Campus HQ"
      },
      user: {
        username: campaign.targetUser,
        domain: "CAMPUS",
        userPrincipalName: `${campaign.targetUser}@campus.edu`,
        role: "Corporate User"
      }
    });

    campaign.generatedEvents.push(securityEvent);
    campaign.currentStepIndex++;

    if (campaign.currentStepIndex >= campaign.totalSteps) {
      campaign.status = "completed";
      this.campaignHistory.push({ ...campaign });
    }

    return securityEvent;
  }

  getActiveCampaignState() {
    return this.activeCampaign ? { ...this.activeCampaign } : null;
  }
}
