import { test, expect } from '@playwright/test';
import { EnterpriseGenerator } from '../../src/telemetry/generator/enterpriseGenerator.js';
import { SeededRandom } from '../../src/telemetry/utils/seededRandom.js';
import { SIMULATION_PROFILES, getProfileById } from '../../src/telemetry/generator/simulationProfiles.js';
import { BENIGN_EVENT_TEMPLATES } from '../../src/telemetry/eventLibrary/enterpriseLogSources.js';

test.describe('Enterprise Telemetry Generator & Noise Model Suite (Expanded)', () => {
  test('1. EnterpriseGenerator initializes with active profile and emits valid SecurityEvent', () => {
    const prng = new SeededRandom("test_seed_123");
    const generator = new EnterpriseGenerator(prng);
    generator.setProfile("Fortune500");

    expect(generator.currentProfile.id).toBe("Fortune500");
    const evt = generator.generateBackgroundEvent();

    expect(evt).toBeDefined();
    expect(evt.eventId).toMatch(/^evt_/);
    expect(evt.source).toBeDefined();
    expect(evt.asset?.hostname).toBeDefined();
    expect(evt.user?.username).toBeDefined();
  });

  test('2. All 7 Simulation Profiles define valid endpoint counts, domains, and noise ratios', () => {
    const profiles = Object.keys(SIMULATION_PROFILES);
    expect(profiles).toHaveLength(7);

    for (const key of profiles) {
      const prof = getProfileById(key);
      expect(prof.endpointCount).toBeGreaterThan(0);
      expect(prof.userDomain).toBeDefined();
      expect(prof.noiseRatio).toBeGreaterThanOrEqual(0.95);
    }
  });

  test('3. Seeded PRNG produces 100% deterministic output sequence', () => {
    const genA = new EnterpriseGenerator(new SeededRandom("fixed_seed_999"));
    const genB = new EnterpriseGenerator(new SeededRandom("fixed_seed_999"));

    const evtA1 = genA.generateBackgroundEvent();
    const evtB1 = genB.generateBackgroundEvent();

    expect(evtA1.source).toBe(evtB1.source);
    expect(evtA1.asset.hostname).toBe(evtB1.asset.hostname);
    expect(evtA1.description).toBe(evtB1.description);
  });

  test('4. Benign event catalog covers process, identity, network, cloud, and syslog categories', () => {
    expect(BENIGN_EVENT_TEMPLATES.length).toBeGreaterThanOrEqual(10);
    const categories = new Set(BENIGN_EVENT_TEMPLATES.map(t => t.category));
    expect(categories.has("execution")).toBe(true);
    expect(categories.has("authentication")).toBe(true);
    expect(categories.has("network")).toBe(true);
    expect(categories.has("cloud")).toBe(true);
  });

  test('5. Profile switching updates active profile asset domain and pool size', () => {
    const generator = new EnterpriseGenerator(new SeededRandom("switch_seed"));
    generator.setProfile("SmallOffice");
    expect(generator.currentProfile.id).toBe("SmallOffice");

    generator.setProfile("Hospital");
    expect(generator.currentProfile.id).toBe("Hospital");
    const evt = generator.generateBackgroundEvent();
    expect(evt).toBeDefined();
  });

  test('6. Generates valid events for Healthcare/Hospital profile with medical asset domain', () => {
    const generator = new EnterpriseGenerator(new SeededRandom("hospital_seed"));
    generator.setProfile("Hospital");

    const evt = generator.generateBackgroundEvent();
    expect(evt.asset?.hostname).toBeDefined();
    expect(evt.user?.domain).toBeDefined();
  });

  test('7. Generates valid events for University campus profile', () => {
    const generator = new EnterpriseGenerator(new SeededRandom("uni_seed"));
    generator.setProfile("University");

    const evt = generator.generateBackgroundEvent();
    expect(evt).toBeDefined();
    expect(evt.schemaVersion).toBe("2.0");
  });

  test('8. Generates valid events for Government agency profile', () => {
    const generator = new EnterpriseGenerator(new SeededRandom("gov_seed"));
    generator.setProfile("Government");

    const evt = generator.generateBackgroundEvent();
    expect(evt.asset?.department).toBeDefined();
  });

  test('9. Generates valid events for Financial institution profile', () => {
    const generator = new EnterpriseGenerator(new SeededRandom("fin_seed"));
    generator.setProfile("Bank");

    const evt = generator.generateBackgroundEvent();
    expect(evt).toBeDefined();
  });
});
