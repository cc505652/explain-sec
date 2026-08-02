/**
 * ======================================================================
 * EXPLAINSEC PHASE 2 — TELEMETRY SESSION MANAGER
 * ======================================================================
 * Singleton responsible for simulation lifecycle, session-scoped event
 * storage, Firestore-persisted simulation archive, and session/lifetime
 * statistics.
 *
 * Architecture:
 *   Tier 1: liveBuffer (rolling 100)     — managed by telemetryBus
 *   Tier 2: sessionEvents (in-memory)    — managed here
 *   Tier 3: Firestore archive            — persisted on newSimulation()
 *
 * Does NOT touch:
 *   - Firestore `issues` collection
 *   - `incident_timeline` collection
 *   - `audit_log` collection
 *   - Any Phase 1 workflow state
 * ======================================================================
 */

import { db } from "../../firebase.js";
import { collection, addDoc, serverTimestamp, query, orderBy, getDocs, writeBatch, doc } from "firebase/firestore";

// ─── CONSTANTS ───────────────────────────────────────────────────────────────

const SIMULATIONS_COLLECTION = "telemetry_simulations";
const SIM_EVENTS_COLLECTION = "telemetry_simulation_events";
const LIFETIME_STORAGE_KEY = "explainsec_lifetime_stats";
const EVENT_BATCH_SIZE = 50;

// ─── SESSION ID GENERATOR ────────────────────────────────────────────────────

function generateSessionId() {
  const ts = Date.now();
  const suffix = Math.random().toString(36).substring(2, 8);
  return `sim_${ts}_${suffix}`;
}

// ─── LIFETIME STATS PERSISTENCE (localStorage) ──────────────────────────────

function loadLifetimeStats() {
  try {
    const stored = localStorage.getItem(LIFETIME_STORAGE_KEY);
    if (stored) return JSON.parse(stored);
  } catch (_) { /* ignore */ }
  return {
    eventsGenerated: 0,
    incidentsCreated: 0,
    suppressedEvents: 0,
    correlatedClusters: 0,
    qualifiedClusters: 0,
    simulationsCompleted: 0
  };
}

function saveLifetimeStats(lifetime) {
  try {
    localStorage.setItem(LIFETIME_STORAGE_KEY, JSON.stringify(lifetime));
  } catch (_) { /* ignore */ }
}

// ═══════════════════════════════════════════════════════════════════════════════

export class TelemetrySessionManager {
  constructor() {
    this.currentSessionId = null;
    this.sessionStartTime = null;
    this.scenario = "Replay"; // Replay | Enterprise | Chaos
    this.seed = null;

    // Tier 2: Current simulation events (in-memory)
    this.sessionEvents = [];
    this._pendingBatch = []; // Events not yet flushed to Firestore

    // Session-scoped statistics (reset on New Simulation)
    this.session = {
      eventsGenerated: 0,
      incidentsCreated: 0,
      suppressedEvents: 0,
      correlatedClusters: 0,
      qualifiedClusters: 0
    };

    // Lifetime statistics (never reset, persisted to localStorage)
    this.lifetime = loadLifetimeStats();
  }

  // ─── SESSION LIFECYCLE ───────────────────────────────────────────────────

  /**
   * Start a new simulation session.
   * @param {string} [scenario] - Scenario mode (Replay, Enterprise, Chaos)
   * @param {string|null} [seed] - PRNG seed for deterministic replay
   */
  startSession(scenario, seed) {
    this.currentSessionId = generateSessionId();
    this.sessionStartTime = Date.now();
    this.scenario = scenario || this.scenario || "Replay";
    this.seed = seed || null;
    this.sessionEvents = [];
    this._pendingBatch = [];

    // Reset session stats
    this.session = {
      eventsGenerated: 0,
      incidentsCreated: 0,
      suppressedEvents: 0,
      correlatedClusters: 0,
      qualifiedClusters: 0
    };

    return this.currentSessionId;
  }

  /**
   * Archive current session to Firestore, then start a new one.
   * This is the "New Simulation" action.
   */
  async newSimulation(scenario, seed) {
    // 1. Archive current session (if any events exist)
    await this.archiveCurrentSession();

    // 2. Increment lifetime counter
    this.lifetime.simulationsCompleted++;
    saveLifetimeStats(this.lifetime);

    // 3. Start fresh session
    return this.startSession(scenario, seed);
  }

  // ─── ARCHIVE ─────────────────────────────────────────────────────────────

  /**
   * Write current simulation metadata + events to Firestore.
   */
  async archiveCurrentSession() {
    if (!this.currentSessionId) return;
    if (this.sessionEvents.length === 0 && this.session.eventsGenerated === 0) return;

    try {
      // Flush any remaining pending events
      await this.flushEventBatch(true);

      // Write simulation metadata
      await addDoc(collection(db, SIMULATIONS_COLLECTION), {
        sessionId: this.currentSessionId,
        scenario: this.scenario,
        seed: this.seed,
        startedAt: this.sessionStartTime,
        endedAt: Date.now(),
        status: "completed",
        eventCount: this.session.eventsGenerated,
        stats: { ...this.session },
        createdAt: serverTimestamp()
      });
    } catch (err) {
      console.warn("[SESSION MANAGER] Failed to archive simulation to Firestore:", err?.code || err?.message);
    }
  }

  /**
   * Batch-write pending events to Firestore.
   * Called periodically (every EVENT_BATCH_SIZE events) and on archive.
   */
  async flushEventBatch(forceAll = false) {
    const toFlush = forceAll ? [...this._pendingBatch] : this._pendingBatch.splice(0, EVENT_BATCH_SIZE);
    if (toFlush.length === 0) return;

    try {
      const batch = writeBatch(db);
      for (const evt of toFlush) {
        const ref = doc(collection(db, SIM_EVENTS_COLLECTION));
        batch.set(ref, {
          simulationId: this.currentSessionId,
          eventId: evt.eventId,
          event: this._serializeEvent(evt),
          timestamp: evt.timestamp
        });
      }
      await batch.commit();
      if (forceAll) this._pendingBatch = [];
    } catch (err) {
      console.warn("[SESSION MANAGER] Failed to flush event batch:", err?.code || err?.message);
    }
  }

  /**
   * Serialize event for Firestore (remove circular refs / functions).
   */
  _serializeEvent(evt) {
    try {
      return JSON.parse(JSON.stringify(evt));
    } catch (_) {
      return { eventId: evt.eventId, description: evt.description, timestamp: evt.timestamp };
    }
  }

  // ─── EVENT TRACKING ──────────────────────────────────────────────────────

  /**
   * Record an event in the current session.
   */
  recordEvent(event) {
    if (!this.currentSessionId) return;
    this.sessionEvents.push(event);
    this._pendingBatch.push(event);

    // Auto-flush batch when threshold reached
    if (this._pendingBatch.length >= EVENT_BATCH_SIZE) {
      this.flushEventBatch();
    }
  }

  // ─── STATISTICS ──────────────────────────────────────────────────────────

  /**
   * Increment a stat key in both session and lifetime counters.
   */
  incrementStat(key) {
    if (key in this.session) {
      this.session[key]++;
    }
    if (key in this.lifetime) {
      this.lifetime[key]++;
      saveLifetimeStats(this.lifetime);
    }
  }

  getCurrentSessionId() {
    return this.currentSessionId;
  }

  getSessionStats() {
    return {
      session: { ...this.session },
      lifetime: { ...this.lifetime }
    };
  }

  getSessionEvents() {
    return [...this.sessionEvents];
  }

  findEventById(eventId) {
    return this.sessionEvents.find(e => e.eventId === eventId) || null;
  }

  // ─── FIRESTORE ARCHIVE QUERIES ───────────────────────────────────────────

  /**
   * Load all archived simulations from Firestore.
   * @returns {Promise<Array>} Archived simulation metadata sorted by startedAt desc
   */
  async loadArchivedSimulations() {
    try {
      const q = query(
        collection(db, SIMULATIONS_COLLECTION),
        orderBy("startedAt", "desc")
      );
      const snapshot = await getDocs(q);
      return snapshot.docs.map(d => ({ id: d.id, ...d.data() }));
    } catch (err) {
      console.warn("[SESSION MANAGER] Failed to load archived simulations:", err?.code || err?.message);
      return [];
    }
  }

  /**
   * Load events for a specific archived simulation.
   * @param {string} simulationId - Session ID of the archived simulation
   * @returns {Promise<Array>} Events sorted by timestamp
   */
  async loadArchivedEvents(simulationId) {
    try {
      const q = query(
        collection(db, SIM_EVENTS_COLLECTION),
        orderBy("timestamp", "asc")
      );
      const snapshot = await getDocs(q);
      return snapshot.docs
        .map(d => d.data())
        .filter(d => d.simulationId === simulationId)
        .map(d => d.event);
    } catch (err) {
      console.warn("[SESSION MANAGER] Failed to load archived events:", err?.code || err?.message);
      return [];
    }
  }
}

export const telemetrySessionManager = new TelemetrySessionManager();
