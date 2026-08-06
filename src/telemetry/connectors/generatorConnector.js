/**
 * Live Telemetry Generator Connector (Orchestrates Decoupled Generator & Attack Composer)
 */

import { SeededRandom } from "../utils/seededRandom.js";
import { EnterpriseGenerator } from "../generator/enterpriseGenerator.js";
import { AttackComposer } from "../campaigns/attackComposer.js";
import { telemetryOrchestrator } from "../orchestrator/telemetryOrchestrator.js";
import { telemetryBus } from "../telemetryBus.js";
import { telemetrySessionManager } from "../session/telemetrySessionManager.js";
import { memoryClusterRepository } from "../correlator/clusterRepository.js";
import { correlationEngine } from "../correlator/correlationEngine.js";

export class GeneratorConnector {
  constructor() {
    this.prng = new SeededRandom(null);
    this.enterpriseGenerator = new EnterpriseGenerator(this.prng);
    this.attackComposer = new AttackComposer(this.prng);
    
    this.status = "PAUSED"; // RUNNING | PAUSED
    this.simulationProfile = "MidEnterprise"; // SmallOffice | MidEnterprise | Fortune500 | Government | Hospital | University | Bank
    this.simulationMode = "Training"; // Training | Normal Enterprise | High Threat | Red Team Exercise | Chaos Mode
    this.speedMultiplier = 1; // 1 | 2 | 5 | 10
    this.currentSeed = null;
    this.timerId = null;
    this.pauseOnIncident = false;
  }

  get campaignEngine() {
    return {
      getActiveCampaignState: () => this.getActiveCampaignState()
    };
  }

  getActiveCampaignState() {
    if (!this.attackComposer) return null;
    const active = this.attackComposer.activeChains.find(c => c.status === "active");
    if (!active) return null;
    return {
      instanceId: active.chainId,
      name: `${active.profile.name} Activity`,
      threatActor: active.profile.name,
      targetHost: active.targetHost,
      targetUser: active.targetUser,
      currentStepIndex: active.stepIndex,
      totalSteps: 7,
      status: active.status,
      steps: [
        { stepIndex: 1, stageName: "InitialAccess" },
        { stepIndex: 2, stageName: "Execution" },
        { stepIndex: 3, stageName: "CredentialAccess" },
        { stepIndex: 4, stageName: "Persistence" },
        { stepIndex: 5, stageName: "Discovery" },
        { stepIndex: 6, stageName: "LateralMovement" },
        { stepIndex: 7, stageName: "Exfiltration" }
      ]
    };
  }

  setSeed(seed) {
    this.currentSeed = seed;
    this.prng.reset(seed);
    telemetryBus.updateStats({ currentSeed: seed });
  }

  setSimulationProfile(profileId) {
    this.simulationProfile = profileId;
    this.enterpriseGenerator.setProfile(profileId);
    telemetryBus.updateStats({ simulationProfile: profileId });
  }

  setSimulationMode(mode) {
    this.simulationMode = mode;
    telemetryBus.updateStats({ simulationMode: mode });
  }

  setSpeed(multiplier) {
    this.speedMultiplier = multiplier;
    telemetryBus.updateStats({ speedMultiplier: multiplier });
    if (this.status === "RUNNING") {
      this.restartLoop();
    }
  }

  setPauseOnIncident(enabled) {
    this.pauseOnIncident = enabled;
    telemetryBus.updateStats({ pauseOnIncident: enabled });
  }

  start() {
    if (!telemetrySessionManager.getCurrentSessionId()) {
      telemetrySessionManager.startSession(this.simulationMode, this.currentSeed);
    }
    if (this.status === "RUNNING") return;
    this.status = "RUNNING";
    telemetryBus.updateStats({ generatorStatus: "RUNNING" });
    this.restartLoop();
  }

  pause() {
    this.status = "PAUSED";
    if (this.timerId) {
      clearInterval(this.timerId);
      this.timerId = null;
    }
    telemetryBus.updateStats({ generatorStatus: "PAUSED" });
  }

  async newSimulation() {
    this.pause();
    await telemetrySessionManager.newSimulation(this.simulationMode, this.currentSeed);
    memoryClusterRepository.clear();
    correlationEngine.clearSession();
    this.attackComposer.reset();
    telemetryBus.resetSessionStats();
  }

  restartLoop() {
    if (this.timerId) clearInterval(this.timerId);
    
    // Interval based on speed: base 1000ms / speedMultiplier
    const intervalMs = Math.max(100, Math.floor(1000 / this.speedMultiplier));
    
    this.timerId = setInterval(() => {
      if (this.status === "RUNNING") {
        this.tick();
      }
    }, intervalMs);
  }

  tick() {
    let rawEvent = null;
    const noiseRatio = this.enterpriseGenerator.currentProfile.noiseRatio || 0.97;
    const roll = this.prng.nextFloat();

    // Mode-based or probability-based selection between enterprise noise and attack composer
    if (this.simulationMode === "Red Team Exercise" || roll > noiseRatio) {
      rawEvent = this.attackComposer.stepNext();
      if (!rawEvent) {
        // Fallback to enterprise background noise if attack step is idle/blocked
        rawEvent = this.enterpriseGenerator.generateBackgroundEvent();
      }
    } else {
      // Generate pure enterprise background noise
      rawEvent = this.enterpriseGenerator.generateBackgroundEvent();
    }

    if (rawEvent) {
      // Pass raw event into TelemetryOrchestrator central conductor
      telemetryOrchestrator.ingest(rawEvent);

      // Track active attack chains count
      telemetryBus.updateStats({
        activeCampaignsCount: this.attackComposer.getActiveChainsCount()
      });
    }
  }

  stepOnce() {
    this.tick();
  }
}

export const generatorConnector = new GeneratorConnector();
