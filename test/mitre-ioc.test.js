// Tests: MITRE ATT&CK heatmap, IOC lookup, editable intel, IOCs on cases, state v3.
const { test, beforeEach, after } = require('node:test');
const assert = require('node:assert');
const os = require('os');
const path = require('path');
const fs = require('fs');

process.env.SOCSIM_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'socsim-test-'));

const store = require('../src/store');
const detection = require('../src/detection');
const engine = require('../src/engine');
const gen = require('../src/generator');
const playbooks = require('../src/playbooks');
const cases = require('../src/cases');
const intel = require('../src/intel');
const mitre = require('../src/mitre');
const ioc = require('../src/ioc');

// Intel saves go to a throwaway copy, never to rules/intel.json
const REPO_INTEL = path.join(__dirname, '..', 'rules', 'intel.json');
const repoIntelBefore = fs.readFileSync(REPO_INTEL, 'utf8');
const TMP_INTEL = path.join(process.env.SOCSIM_DATA_DIR, 'intel.json');

beforeEach(() => {
  fs.writeFileSync(TMP_INTEL, repoIntelBefore);
  intel.load(TMP_INTEL);
  store.reset(); detection.loadRules(); playbooks.load();
});
after(() => assert.strictEqual(fs.readFileSync(REPO_INTEL, 'utf8'), repoIntelBefore, 'rules/intel.json must not change'));

function runScenario(key) {
  let ts = Date.now();
  if (gen.scenarios[key].unusualHour) ts = gen.unusualTime(ts);
  const evs = gen.expand(key, ts);
  evs.forEach(engine.ingest);
  return evs;
}

// ---------- MITRE heatmap ----------

test('every rule MITRE tag is in the built-in catalogue', () => {
  for (const r of detection.getRules()) for (const t of mitre.tags(r.mitre)) assert.ok(mitre.find(t), `${r.id}: ${t} not in catalogue`);
  const ids = mitre.catalogue().map(t => t.id);
  assert.ok(ids.includes('T1071.004'));
});

test('heatmap: coverage from enabled rules, gaps, sub-techniques roll up', () => {
  const h = mitre.heatmap();
  const cell = id => h.techniques.find(c => c.id === id);
  assert.strictEqual(cell('T1071').coverage, 3); // R005 + R006 (T1071.004) + R011 (Phase 5 beacon rule)
  assert.deepStrictEqual(cell('T1071').subs.map(s => [s.id, s.rules]), [['T1071.004', 1]]);
  assert.strictEqual(cell('T1110').coverage, 2); // R001 + R009 (T1110.003)
  assert.deepStrictEqual(cell('T1110').subs.map(s => [s.id, s.rules]), [['T1110.003', 1]]);
  assert.strictEqual(cell('T1021').coverage, 1, 'Phase 5 R010 covers Remote Services');
  assert.strictEqual(cell('T1048').coverage, 0, 'Exfiltration over alternative protocol is a deliberate gap');
  assert.ok(h.summary.covered < h.summary.techniques);
  assert.deepStrictEqual(h.other, []);
});

test('heatmap: a disabled rule leaves a gap; unknown IDs go to Other', () => {
  const rules = detection.getRules().map(r => ({ ...r, enabled: r.id === 'R007' ? false : r.enabled }));
  rules.push({ id: 'X1', name: 'custom', enabled: true, mitre: 'T9999.001' });
  const h = mitre.heatmap({ rules, alerts: [] });
  const t1003 = h.techniques.find(c => c.id === 'T1003');
  assert.strictEqual(t1003.coverage, 0);
  assert.strictEqual(t1003.rules[0].enabled, false);
  assert.deepStrictEqual(h.other.map(c => [c.id, c.coverage, c.tactics[0]]), [['T9999', 1, 'Other']]);
});

test('heatmap: alert activity by technique, verdict and time window', () => {
  runScenario('c2_beacon');   // R005 (T1071) + R006 (T1071.004)
  runScenario('cred_dump');   // R007 (T1003)
  const a = store.state.alerts.find(x => x.ruleId === 'R007');
  a.verdict = 'true_positive'; a.status = 'Closed';
  const h = mitre.heatmap({ hours: 24 });
  const cell = id => h.techniques.find(c => c.id === id);
  assert.strictEqual(cell('T1071').alerts.total, 2);
  assert.strictEqual(cell('T1071').subs[0].alerts, 1);
  assert.deepStrictEqual(cell('T1003').alerts, { total: 1, open: 0, true_positive: 1, false_positive: 0, benign: 0 });
  // An alert older than the window is excluded, but counted in "all time"
  a.createdTs -= 48 * 3600e3;
  assert.strictEqual(mitre.heatmap({ hours: 24 }).techniques.find(c => c.id === 'T1003').alerts.total, 0);
  assert.strictEqual(mitre.heatmap({ hours: 0 }).techniques.find(c => c.id === 'T1003').alerts.total, 1);
});

test('mitre filter: a parent technique matches its sub-techniques, not the other way round', () => {
  assert.ok(mitre.matches('T1071.004', 'T1071'));
  assert.ok(mitre.matches('T1071', 't1071'));
  assert.ok(!mitre.matches('T1071', 'T1071.004'));
  assert.ok(!mitre.matches('T1110', 'T1071'));
  assert.ok(mitre.matches(['T1003', 'T1110'], 'T1110'));
});

// ---------- Intel ----------

test('intel rejects anything that is not simulated', () => {
  const ok = JSON.parse(repoIntelBefore);
  const bad = (list, value) => ({ ...ok, [list]: [...ok[list], { value, note: 'x' }] });
  assert.throws(() => intel.validate(bad('badIps', '10.20.30.40')), /192\.0\.2/);
  assert.throws(() => intel.validate(bad('badIps', '203.0.113.300')), /rejected/);
  assert.throws(() => intel.validate(bad('badDomains', 'something.test')), /\.example/);
  assert.throws(() => intel.validate(bad('badHashes', 'ab'.repeat(32))), /48 zeros/);
  assert.throws(() => intel.validate(bad('badIps', ok.badIps[0].value)), /duplicate/);
  assert.throws(() => intel.validate({ ...ok, badDomains: [] }), /non-empty/);
  assert.throws(() => intel.validate([]), /object/);
  assert.throws(() => intel.add('example.com'), /simulated/);
});

test('an IOC added to intel makes the lookup rule fire on new events (saved to the throwaway copy)', () => {
  const ip = '203.0.113.201';
  const ev = () => ({ ts: Date.now(), source: 'firewall', host: 'WS-005', srcIp: '192.0.2.105', dstIp: ip, dstPort: 443, action: 'allow', message: 'Outbound connection allowed', tags: [] });
  engine.ingest(ev());
  assert.deepStrictEqual(store.state.alerts, []);
  intel.add(ip, 'test entry');
  assert.ok(JSON.parse(fs.readFileSync(TMP_INTEL, 'utf8')).badIps.some(x => x.value === ip));
  engine.ingest(ev());
  assert.deepStrictEqual(store.state.alerts.map(a => a.ruleId), ['R005']);
  assert.throws(() => intel.add(ip), /already/);
});

// ---------- IOC lookup ----------

test('classify detects IP / domain / hash and refuses non-simulated values', () => {
  assert.deepStrictEqual(ioc.classify(' 203.0.113.66 '), { type: 'ip', value: '203.0.113.66' });
  assert.deepStrictEqual(ioc.classify('C2-Beacon.example'), { type: 'domain', value: 'c2-beacon.example' });
  assert.strictEqual(ioc.classify(intel.badHashes[0].value).type, 'hash');
  assert.throws(() => ioc.classify('100.64.1.2'), /not a simulated address/);
  assert.throws(() => ioc.classify('example.com'), /not a simulated domain/);
  assert.throws(() => ioc.classify('f'.repeat(64)), /Not a simulated hash/);
  assert.throws(() => ioc.classify('hello world'), /Enter an IP/);
  assert.throws(() => ioc.classify(''), e => e.status === 400);
});

test('lookup after a beacon: intel hit, sightings, related alert and case', () => {
  const evs = runScenario('c2_beacon');
  const ip = evs.find(e => e.dstIp).dstIp;
  const host = evs[0].host;
  const alert = store.state.alerts.find(a => a.ruleId === 'R005');
  const c = cases.escalate(alert.id, null);
  const r = ioc.lookup(ip);
  assert.strictEqual(r.type, 'ip');
  assert.ok(r.intel && /training/.test(r.intel.note));
  assert.strictEqual(r.sightings.count, 4);
  assert.deepStrictEqual(r.sightings.hosts, [{ name: host, count: 4 }]);
  assert.ok(r.sightings.firstTs <= r.sightings.lastTs);
  assert.ok(r.alerts.some(a => a.id === alert.id));
  assert.deepStrictEqual(r.cases.map(x => x.id), [c.id]);
  const d = ioc.lookup(evs[0].domain);
  assert.ok(d.intel);
  assert.ok(d.alerts.some(a => /DNS lookup of known-bad domain/.test(a.title)));
});

test('lookup explains internal and unknown values; extract flags intel hits', () => {
  assert.match(ioc.lookup('192.0.2.10').about, /DC01/);
  assert.match(ioc.lookup('198.51.100.20').about, /normal internet/);
  const r = ioc.lookup('nothing-here.example');
  assert.strictEqual(r.intel, null);
  assert.strictEqual(r.sightings.count, 0);
  const evs = runScenario('cred_dump');
  const found = ioc.extract(evs);
  assert.ok(found.some(x => x.type === 'hash' && x.value === evs[0].fileHash));
  assert.strictEqual(found.find(x => x.type === 'hash').onIntel, !!intel.lookup(evs[0].fileHash));
  const c2 = ioc.extract(runScenario('c2_beacon'));
  assert.ok(c2[0].onIntel, 'intel hits sort first');
});

// ---------- IOCs on cases ----------

test('case IOCs: add, reject duplicates and non-simulated values, timeline, remove, closed case', () => {
  const c = cases.create({ title: 'IOC test' }, 1000);
  assert.deepStrictEqual(c.iocs, []);
  cases.addIoc(c.id, { value: '203.0.113.66', note: 'C2 server' }, 2000);
  assert.deepStrictEqual(c.iocs, [{ type: 'ip', value: '203.0.113.66', note: 'C2 server', addedTs: 2000 }]);
  assert.throws(() => cases.addIoc(c.id, { value: '203.0.113.66' }), /already/);
  assert.throws(() => cases.addIoc(c.id, { value: 'example.com' }), /simulated/);
  assert.ok(cases.timeline(c).some(t => t.kind === 'ioc' && /IOC added/.test(t.text)));
  assert.strictEqual(cases.detail(c.id).iocs[0].onIntel, true);
  assert.strictEqual(ioc.lookup('203.0.113.66').cases[0].hasIoc, true);
  cases.removeIoc(c.id, '203.0.113.66', 3000);
  assert.deepStrictEqual(c.iocs, []);
  assert.throws(() => cases.removeIoc(c.id, '203.0.113.66'), /not found/);
  cases.update(c.id, { summary: 'done', status: 'Closed' });
  assert.throws(() => cases.addIoc(c.id, { value: '203.0.113.66' }), /closed/);
});

// ---------- State v3 ----------

test('a v2 state file migrates to v3, is backed up first, and an existing backup is never overwritten', () => {
  runScenario('cred_dump');
  cases.escalate(store.state.alerts[0].id, null);
  const v2 = JSON.parse(JSON.stringify(store.state));
  v2.version = 2;
  for (const c of v2.cases) delete c.iocs;
  const bak = store.backupFile(2);
  if (fs.existsSync(bak)) fs.unlinkSync(bak);
  fs.writeFileSync(store.file, JSON.stringify(v2));

  store.load();
  assert.strictEqual(store.state.version, store.VERSION); // v2 -> current
  assert.deepStrictEqual(store.state.cases[0].iocs, []);
  assert.strictEqual(JSON.parse(fs.readFileSync(bak, 'utf8')).version, 2);
  const firstBackup = fs.readFileSync(bak, 'utf8');

  fs.writeFileSync(store.file, JSON.stringify({ ...v2, cases: [] }));
  store.load();
  assert.strictEqual(fs.readFileSync(bak, 'utf8'), firstBackup);

  store.save(); store.load(); // a v3 file loads without a new backup
  assert.ok(!fs.existsSync(store.backupFile(3)));
});
