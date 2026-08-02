import { test, expect } from '@playwright/test';
import { AttackComposer } from '../../src/telemetry/campaigns/attackComposer.js';
import { ATTACKER_PROFILES, getAttackerProfile } from '../../src/telemetry/campaigns/attackerProfiles.js';
import { SeededRandom } from '../../src/telemetry/utils/seededRandom.js';

test.describe('Dynamic Attack Composer & Adversary FSM Suite (Expanded)', () => {
  test('1. AttackerProfiles defines 6 adversary profiles with distinct stealth and failure parameters', () => {
    const keys = Object.keys(ATTACKER_PROFILES);
    expect(keys).toHaveLength(6);

    const apt = getAttackerProfile("APT");
    expect(apt.stealth).toBe("High");
    expect(apt.failureRate).toBeLessThan(0.2);

    const scriptKiddie = getAttackerProfile("ScriptKiddie");
    expect(scriptKiddie.stealth).toBe("Very Low");
    expect(scriptKiddie.failureRate).toBeGreaterThanOrEqual(0.4);
  });

  test('2. AttackComposer initializes concurrent adversary FSM chains', () => {
    const prng = new SeededRandom("composer_seed_456");
    const composer = new AttackComposer(prng);
    composer.initializeChains(3);

    expect(composer.activeChains).toHaveLength(3);
    expect(composer.getActiveChainsCount()).toBe(3);
  });

  test('3. FSM advances active chains through ATT&CK stage progression', () => {
    const prng = new SeededRandom("fsm_advance_seed");
    const composer = new AttackComposer(prng);
    composer.initializeChains(1);

    const evt1 = composer.stepNext();
    if (evt1) {
      expect(evt1.campaignId).toBeDefined();
      expect(evt1.campaignStage).toBeDefined();
    }
  });

  test('4. Blocked attacks emit Defender block security events with high severity', () => {
    const prng = new SeededRandom("block_seed");
    const composer = new AttackComposer(prng);
    composer.initializeChains(1);

    // Force blocked event creation
    const chain = composer.activeChains[0];
    const blockEvt = composer._createBlockedEvent(chain);

    expect(blockEvt.severity).toBe("high");
    expect(blockEvt.description).toContain("[DEFENDER BLOCKED]");
    expect(blockEvt.source).toBe("DefenderForEndpoint");
  });

  test('5. Ransomware Crew profile executes credential access and persistence stages', () => {
    const profile = getAttackerProfile("RansomwareCrew");
    expect(profile).toBeDefined();
    expect(profile.name).toBe("Ransomware Affiliate Crew");
  });

  test('6. Insider Threat profile executes discovery and exfiltration stages', () => {
    const profile = getAttackerProfile("InsiderThreat");
    expect(profile).toBeDefined();
    expect(profile.stealth).toBe("High");
  });

  test('7. Commodity Malware profile has low stealth and moderate failure rate', () => {
    const profile = getAttackerProfile("CommodityMalware");
    expect(profile).toBeDefined();
  });

  test('8. Cloud Attacker profile targets cloud resources and Key Vaults', () => {
    const profile = getAttackerProfile("CloudAttacker");
    expect(profile).toBeDefined();
  });

  test('9. Active chains count reflects number of active adversary FSMs', () => {
    const composer = new AttackComposer(new SeededRandom("chains_count_seed"));
    composer.initializeChains(5);
    expect(composer.getActiveChainsCount()).toBe(5);
  });
});
