/**
 * ClusterRepository — Comprehensive Unit Tests
 */
import { test, expect } from '@playwright/test';
import { ClusterRepository } from '../../src/telemetry/correlator/clusterRepository.js';
import { CLUSTER_STATES } from '../../src/telemetry/constants/index.js';
import { buildMockCluster, buildMockEvent } from '../helpers/testFactories.js';

test.describe('ClusterRepository Unit Suite', () => {
  let repo;
  test.beforeEach(() => { repo = new ClusterRepository(); });

  test('1. createCluster stores cluster and returns it', () => {
    const cluster = buildMockCluster({ clusterId: "cluster_001" });
    const stored = repo.createCluster(cluster);
    expect(stored.clusterId).toBe("cluster_001");
    expect(stored.createdAt).toBeDefined();
  });

  test('2. createCluster returns null for null input', () => {
    expect(repo.createCluster(null)).toBeNull();
  });

  test('3. createCluster returns null for missing clusterId', () => {
    expect(repo.createCluster({ ruleId: "r1" })).toBeNull();
  });

  test('4. findCluster returns stored cluster', () => {
    const cluster = buildMockCluster({ clusterId: "cluster_find" });
    repo.createCluster(cluster);
    const found = repo.findCluster("cluster_find");
    expect(found).not.toBeNull();
    expect(found.clusterId).toBe("cluster_find");
  });

  test('5. findCluster returns null for non-existent ID', () => {
    expect(repo.findCluster("nope")).toBeNull();
  });

  test('6. findById is alias for findCluster', () => {
    const cluster = buildMockCluster({ clusterId: "cluster_alias" });
    repo.createCluster(cluster);
    expect(repo.findById("cluster_alias")).not.toBeNull();
  });

  test('7. save updates existing cluster', () => {
    const cluster = buildMockCluster({ clusterId: "cluster_update" });
    repo.createCluster(cluster);
    repo.save({ clusterId: "cluster_update", riskScore: 99 });
    const found = repo.findCluster("cluster_update");
    expect(found.riskScore).toBe(99);
  });

  test('8. updateCluster returns null for null', () => {
    expect(repo.updateCluster(null)).toBeNull();
  });

  test('9. archiveCluster sets status to ARCHIVED', () => {
    const cluster = buildMockCluster({ clusterId: "cluster_arch", status: CLUSTER_STATES.OPEN });
    repo.createCluster(cluster);
    repo.archiveCluster("cluster_arch");
    const found = repo.findCluster("cluster_arch");
    expect(found.status).toBe(CLUSTER_STATES.ARCHIVED);
  });

  test('10. appendEvent adds event to cluster', () => {
    const cluster = buildMockCluster({ clusterId: "cluster_append" });
    cluster.eventIds = ["evt_1"];
    cluster.events = [{ eventId: "evt_1" }];
    cluster.eventCount = 1;
    repo.createCluster(cluster);

    const newEvt = buildMockEvent({ eventId: "evt_2" });
    // Need to set a unique eventId since buildMockEvent auto-generates
    newEvt.eventId = "evt_new_2";
    repo.appendEvent("cluster_append", newEvt);

    const found = repo.findCluster("cluster_append");
    expect(found.eventIds).toContain("evt_new_2");
    expect(found.eventCount).toBe(2);
  });

  test('11. appendEvent deduplicates by eventId', () => {
    const cluster = buildMockCluster({ clusterId: "cluster_dedup" });
    cluster.eventIds = ["evt_dup"];
    cluster.events = [{ eventId: "evt_dup" }];
    cluster.eventCount = 1;
    repo.createCluster(cluster);

    repo.appendEvent("cluster_dedup", { eventId: "evt_dup" });
    const found = repo.findCluster("cluster_dedup");
    expect(found.eventCount).toBe(1);
  });

  test('12. getActiveClusters returns OPEN, CORRELATING, QUALIFIED clusters', () => {
    repo.createCluster(buildMockCluster({ clusterId: "c1", status: CLUSTER_STATES.OPEN }));
    repo.createCluster(buildMockCluster({ clusterId: "c2", status: CLUSTER_STATES.CORRELATING }));
    repo.createCluster(buildMockCluster({ clusterId: "c3", status: CLUSTER_STATES.QUALIFIED }));
    repo.createCluster(buildMockCluster({ clusterId: "c4", status: CLUSTER_STATES.ARCHIVED }));
    repo.createCluster(buildMockCluster({ clusterId: "c5", status: CLUSTER_STATES.SUPPRESSED }));

    const active = repo.getActiveClusters();
    expect(active).toHaveLength(3);
    expect(active.map(c => c.clusterId).sort()).toEqual(["c1", "c2", "c3"]);
  });

  test('13. findActiveByRuleAndAsset matches on ruleId + primaryAsset', () => {
    repo.createCluster(buildMockCluster({ clusterId: "c_match", ruleId: "RULE-X", primaryAsset: "HOST-A", status: CLUSTER_STATES.OPEN }));
    const found = repo.findActiveByRuleAndAsset("RULE-X", "HOST-A");
    expect(found).not.toBeNull();
    expect(found.clusterId).toBe("c_match");
  });

  test('14. findActiveByRuleAndAsset returns null when no match', () => {
    repo.createCluster(buildMockCluster({ clusterId: "c_no", ruleId: "RULE-Y", primaryAsset: "HOST-B", status: CLUSTER_STATES.OPEN }));
    expect(repo.findActiveByRuleAndAsset("RULE-Z", "HOST-B")).toBeNull();
  });

  test('15. findActiveByCampaign matches on campaignId', () => {
    repo.createCluster(buildMockCluster({ clusterId: "c_camp", campaignId: "camp_123", status: CLUSTER_STATES.OPEN }));
    const found = repo.findActiveByCampaign("camp_123");
    expect(found.clusterId).toBe("c_camp");
  });

  test('16. findActiveByCampaign does not match archived clusters', () => {
    repo.createCluster(buildMockCluster({ clusterId: "c_arch_camp", campaignId: "camp_old", status: CLUSTER_STATES.ARCHIVED }));
    expect(repo.findActiveByCampaign("camp_old")).toBeNull();
  });

  test('17. getAll returns every cluster regardless of status', () => {
    repo.createCluster(buildMockCluster({ clusterId: "a1", status: CLUSTER_STATES.OPEN }));
    repo.createCluster(buildMockCluster({ clusterId: "a2", status: CLUSTER_STATES.ARCHIVED }));
    repo.createCluster(buildMockCluster({ clusterId: "a3", status: CLUSTER_STATES.SUPPRESSED }));
    expect(repo.getAll()).toHaveLength(3);
  });

  test('18. clear removes all clusters', () => {
    repo.createCluster(buildMockCluster({ clusterId: "del1" }));
    repo.createCluster(buildMockCluster({ clusterId: "del2" }));
    repo.clear();
    expect(repo.getAll()).toHaveLength(0);
  });
});
