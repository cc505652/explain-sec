/**
 * ======================================================================
 * EXPLAINSEC PHASE 2 — CLUSTER REPOSITORY
 * ======================================================================
 * Explicit storage repository interface for correlation clusters.
 * ======================================================================
 */

import { CLUSTER_STATES } from "../constants/index.js";

export class ClusterRepository {
  constructor() {
    this.clusters = new Map();
  }

  createCluster(cluster) {
    if (!cluster || !cluster.clusterId) return null;
    const record = {
      ...cluster,
      createdAt: cluster.createdAt || Date.now(),
      updatedAt: Date.now()
    };
    this.clusters.set(cluster.clusterId, record);
    return record;
  }

  findCluster(clusterId) {
    return this.clusters.get(clusterId) || null;
  }

  findById(clusterId) {
    return this.findCluster(clusterId);
  }

  updateCluster(cluster) {
    if (!cluster || !cluster.clusterId) return null;
    const existing = this.clusters.get(cluster.clusterId) || {};
    const updated = {
      ...existing,
      ...cluster,
      updatedAt: Date.now()
    };
    this.clusters.set(cluster.clusterId, updated);
    return updated;
  }

  save(cluster) {
    return this.updateCluster(cluster);
  }

  archiveCluster(clusterId) {
    const cluster = this.findCluster(clusterId);
    if (cluster) {
      cluster.status = CLUSTER_STATES.ARCHIVED;
      cluster.updatedAt = Date.now();
    }
  }

  appendEvent(clusterId, event) {
    const cluster = this.findCluster(clusterId);
    if (cluster && event) {
      if (!cluster.eventIds.includes(event.eventId)) {
        cluster.eventIds.push(event.eventId);
        cluster.events.push(event);
        cluster.eventCount = cluster.events.length;
        cluster.updatedAt = Date.now();
      }
    }
  }

  getActiveClusters() {
    return Array.from(this.clusters.values()).filter(c => 
      c.status === CLUSTER_STATES.OPEN || 
      c.status === CLUSTER_STATES.CORRELATING || 
      c.status === CLUSTER_STATES.QUALIFIED
    );
  }

  findActiveByRuleAndAsset(ruleId, hostname) {
    for (const cluster of this.getActiveClusters()) {
      if (cluster.ruleId === ruleId && cluster.primaryAsset === hostname) {
        return cluster;
      }
    }
    return null;
  }

  findActiveByCampaign(campaignId) {
    for (const cluster of this.getActiveClusters()) {
      if (cluster.campaignId === campaignId) {
        return cluster;
      }
    }
    return null;
  }

  getAll() {
    return Array.from(this.clusters.values());
  }

  clear() {
    this.clusters.clear();
  }
}

export const memoryClusterRepository = new ClusterRepository();
