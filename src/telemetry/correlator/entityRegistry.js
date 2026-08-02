/**
 * ======================================================================
 * EXPLAINSEC PHASE 2 — ENTITY REGISTRY
 * ======================================================================
 * Central in-memory registry indexing security entities across 8 types:
 *   - Host
 *   - User
 *   - IP
 *   - Hash
 *   - IOC
 *   - Process
 *   - Email
 *   - CloudResource
 *
 * Maps entities to connected events and correlation clusters.
 * ======================================================================
 */

export class EntityRegistry {
  constructor() {
    this.entities = new Map(); // entityKey -> { type, id, name, details, eventIds: [], clusterIds: [] }
  }

  clear() {
    this.entities.clear();
  }

  /**
   * Register or update an entity record.
   */
  registerEntity(type, id, details = {}) {
    if (!type || !id) return null;
    const key = `${type}:${id}`.toLowerCase();

    if (!this.entities.has(key)) {
      this.entities.set(key, {
        key,
        type,
        id,
        name: details.name || id,
        details: { ...details },
        eventIds: new Set(),
        clusterIds: new Set(),
        createdAt: Date.now(),
        updatedAt: Date.now()
      });
    }

    const record = this.entities.get(key);
    record.details = { ...record.details, ...details };
    record.updatedAt = Date.now();
    return record;
  }

  /**
   * Bind an event to an entity key.
   */
  linkEventToEntity(type, id, eventId) {
    const record = this.registerEntity(type, id);
    if (record && eventId) {
      record.eventIds.add(eventId);
    }
  }

  /**
   * Bind a cluster to an entity key.
   */
  linkClusterToEntity(type, id, clusterId) {
    const record = this.registerEntity(type, id);
    if (record && clusterId) {
      record.clusterIds.add(clusterId);
    }
  }

  /**
   * Register all entities present on a SecurityEvent.
   */
  registerEventEntities(event) {
    if (!event || !event.eventId) return;

    // 1. Host Entity
    if (event.asset?.hostname) {
      this.linkEventToEntity("Host", event.asset.hostname, event.eventId);
    }

    // 2. User Entity
    if (event.user?.username) {
      this.linkEventToEntity("User", event.user.username, event.eventId);
    }

    // 3. IP Entities
    if (event.asset?.ip) {
      this.linkEventToEntity("IP", event.asset.ip, event.eventId);
    }
    if (event.network?.destIp) {
      this.linkEventToEntity("IP", event.network.destIp, event.eventId);
    }

    // 4. Process Entity
    if (event.rawEvent && typeof event.rawEvent === "string" && event.rawEvent.includes("NewProcessName")) {
      try {
        const parsed = JSON.parse(event.rawEvent);
        if (parsed.NewProcessName || parsed.Image) {
          const procName = parsed.NewProcessName || parsed.Image;
          this.linkEventToEntity("Process", procName, event.eventId);
        }
      } catch (_) {}
    }

    // 5. IOC Entity
    if (event.ioc?.ip || event.ioc?.domain) {
      const iocVal = event.ioc.ip || event.ioc.domain;
      this.linkEventToEntity("IOC", iocVal, event.eventId);
    }

    // 6. Cloud Resource Entity
    if (event.category === "cloud" && event.asset?.hostname) {
      this.linkEventToEntity("CloudResource", event.asset.hostname, event.eventId);
    }
  }

  getEntity(type, id) {
    const key = `${type}:${id}`.toLowerCase();
    return this.entities.get(key) || null;
  }

  getAllEntities() {
    return Array.from(this.entities.values()).map(e => ({
      ...e,
      eventIds: Array.from(e.eventIds),
      clusterIds: Array.from(e.clusterIds)
    }));
  }
}

export const entityRegistry = new EntityRegistry();
