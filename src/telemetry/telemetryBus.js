/**
 * Central Telemetry Bus & Realtime System Health Metrics Manager
 */

import { telemetrySessionManager } from "./session/telemetrySessionManager.js";

class TelemetryBus {
  constructor() {
    this.listeners = new Map();
    this.liveBuffer = []; // Rolling last 100 events for stream ticker
    this.secCounter = 0;

    this.stats = {
      // Session-scoped counters (reset on New Simulation)
      eventsGenerated: 0,
      incidentsCreated: 0,
      suppressedEvents: 0,
      correlatedClusters: 0,
      qualifiedClusters: 0,

      // Lifetime counters (never reset)
      lifetimeEventsGenerated: 0,
      lifetimeIncidentsCreated: 0,
      lifetimeSuppressedEvents: 0,
      lifetimeCorrelatedClusters: 0,
      lifetimeQualifiedClusters: 0,
      lifetimeSimulationsCompleted: 0,

      // Generator State
      eventsPerSec: 0,
      generatorStatus: "PAUSED",
      activeCampaignsCount: 0,
      feedsActiveCount: 12,
      correlationQueueLength: 0,
      incidentQueueLength: 0,
      simulationMode: "Training",
      speedMultiplier: 1,
      pauseOnIncident: true,
      currentSeed: null,
      currentSessionId: null
    };

    this.syncStatsWithSessionManager();

    // Calculate Events/sec ticker
    if (typeof window !== "undefined") {
      setInterval(() => {
        this.stats.eventsPerSec = this.secCounter;
        this.secCounter = 0;
        this.emit("stats_updated", { ...this.stats });
      }, 1000);
    }
  }

  syncStatsWithSessionManager() {
    const smStats = telemetrySessionManager.getSessionStats();
    this.stats.eventsGenerated = smStats.session.eventsGenerated;
    this.stats.incidentsCreated = smStats.session.incidentsCreated;
    this.stats.suppressedEvents = smStats.session.suppressedEvents;
    this.stats.correlatedClusters = smStats.session.correlatedClusters;
    this.stats.qualifiedClusters = smStats.session.qualifiedClusters;

    this.stats.lifetimeEventsGenerated = smStats.lifetime.eventsGenerated;
    this.stats.lifetimeIncidentsCreated = smStats.lifetime.incidentsCreated;
    this.stats.lifetimeSuppressedEvents = smStats.lifetime.suppressedEvents;
    this.stats.lifetimeCorrelatedClusters = smStats.lifetime.correlatedClusters;
    this.stats.lifetimeQualifiedClusters = smStats.lifetime.qualifiedClusters;
    this.stats.lifetimeSimulationsCompleted = smStats.lifetime.simulationsCompleted;

    this.stats.currentSessionId = telemetrySessionManager.getCurrentSessionId();
  }

  on(event, callback) {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    this.listeners.get(event).add(callback);
    return () => this.off(event, callback);
  }

  off(event, callback) {
    if (this.listeners.has(event)) {
      this.listeners.get(event).delete(callback);
    }
  }

  emit(event, data) {
    if (this.listeners.has(event)) {
      this.listeners.get(event).forEach(cb => {
        try {
          cb(data);
        } catch (err) {
          console.error(`Error in telemetryBus listener for ${event}:`, err);
        }
      });
    }
  }

  publishEvent(securityEvent) {
    this.secCounter++;
    telemetrySessionManager.incrementStat("eventsGenerated");
    telemetrySessionManager.recordEvent(securityEvent);

    this.liveBuffer.push(securityEvent);
    if (this.liveBuffer.length > 100) {
      this.liveBuffer.shift();
    }

    this.syncStatsWithSessionManager();
    this.emit("security_event", securityEvent);
    this.emit("stats_updated", { ...this.stats });
  }

  publishIncident(incident) {
    telemetrySessionManager.incrementStat("incidentsCreated");
    this.syncStatsWithSessionManager();
    this.emit("incident_created", incident);
    this.emit("stats_updated", { ...this.stats });
  }

  updateStats(partialStats) {
    this.stats = { ...this.stats, ...partialStats };
    this.emit("stats_updated", { ...this.stats });
  }

  clearLiveBuffer() {
    this.liveBuffer = [];
    this.syncStatsWithSessionManager();
    this.emit("stats_updated", { ...this.stats });
  }

  resetSessionStats() {
    this.liveBuffer = [];
    this.syncStatsWithSessionManager();
    this.emit("stats_updated", { ...this.stats });
    this.emit("session_cleared", true);
  }

  getStats() {
    this.syncStatsWithSessionManager();
    return { ...this.stats };
  }

  getRecentEvents() {
    return [...this.liveBuffer];
  }
}

export const telemetryBus = new TelemetryBus();
