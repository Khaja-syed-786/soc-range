// Tests: core generator, detection rules, alerts, cases, playbooks and state persistence.
const { test, beforeEach } = require('node:test');
const assert = require('node:assert');
const os = require('os');
const path = require('path');
const fs = require('fs');

process.env.SOCSIM_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'socsim-test-'));

const store = require('../src/store');
const detection = require('../src/detection');
const engine = require('../src/engine');
const alerts = require('../src/alerts');
const gen = require('../src/generator');
const playbooks = require('../src/playbooks');
const cases = require('../src/cases');

const EXPECTED_RULE = {
  brute_force: 'R001', new_admin: 'R003', off_hours_login: 'R004', admin_patching: 'R004',
  c2_beacon: 'R005', cred_dump: 'R007', new_starter_account: 'R002', backup_agent_edr: 'R007',
};

beforeEach(() => { store.reset(); detection.loadRules(); playbooks.load(); });

function runScenario(key) {
  let ts = Date.now();
  if (gen.scenarios[key].unusualHour) ts = gen.unusualTime(ts);
  gen.expand(key, ts).forEach(engine.ingest);
  return store.state.alerts.map(a => a.ruleId);
}

for (const [key, rule] of Object.entries(EXPECTED_RULE)) {
  test(`scenario ${key} triggers ${rule}`, () => {
    assert.ok(runScenario(key).includes(rule));
  });
}

test('user_typos (5 failures over 40s) triggers brute force once - a benign case to triage', () => {
  const ids = runScenario('user_typos');
  assert.deepStrictEqual(ids, ['R001']);
});

test('new_admin also raises new-account alert and threshold alerts are merged, not duplicated', () => {
  assert.ok(runScenario('new_admin').includes('R002'));
  store.reset(); detection.loadRules();
  runScenario('brute_force');
  assert.strictEqual(store.state.alerts.filter(a => a.ruleId === 'R001').length, 1);
});

test('office-hour background noise produces no alerts', () => {
  const d = new Date(); d.setDate(d.getDate() + ((8 - d.getDay()) % 7 || 7)); d.setHours(10, 0, 0, 0); // next Monday 10:00
  for (let i = 0; i < 3000; i++) engine.ingest(gen.noise(d.getTime() + i * 1000));
  assert.deepStrictEqual(store.state.alerts.map(a => a.ruleId), []);
});

test('cannot close an alert without a verdict; MTTR computed after close', () => {
  runScenario('cred_dump');
  const a = store.state.alerts[0];
  assert.throws(() => alerts.update(a.id, { status: 'Closed' }), /verdict/);
  alerts.update(a.id, { verdict: 'true_positive' });
  alerts.update(a.id, { status: 'Closed' }, a.createdTs + 120000);
  assert.strictEqual(alerts.stats().mttrSeconds, 120);
});

test('bad rules are rejected', () => {
  assert.throws(() => detection.saveRules([{ id: 'X', type: 'nope', severity: 'high' }]), /type/);
  assert.throws(() => detection.saveRules({}), /array/);
});

test('event cap is enforced', () => {
  for (let i = 0; i < 52000; i++) store.addEvent({ ts: i, source: 'dns' });
  assert.ok(store.state.events.length <= 51000);
});

test('all generated data uses documentation IPs, .example domains and simulated hashes only', () => {
  const evs = gen.seedHistory(Date.now(), 6, 1);
  for (const k of Object.keys(gen.scenarios)) evs.push(...gen.expand(k, Date.now()));
  for (let i = 0; i < 50; i++) evs.push(...gen.expand('cred_dump', Date.now()));
  const ipOk = ip => /^(192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}$/.test(ip);
  for (const e of evs) {
    for (const f of ['srcIp', 'dstIp']) if (e[f]) assert.ok(ipOk(e[f]), `bad IP ${e[f]}`);
    if (e.domain) assert.ok(/\.example$/.test(e.domain), `bad domain ${e.domain}`);
    if (e.fileHash) assert.ok(/^0{48}[0-9a-f]{16}$/.test(e.fileHash), `bad hash ${e.fileHash}`);
  }
  assert.ok(evs.some(e => e.fileHash), 'cred_dump events carry a simulated hash');
});

test('state saves to and loads from the data dir', () => {
  runScenario('cred_dump');
  store.save();
  assert.ok(fs.existsSync(path.join(process.env.SOCSIM_DATA_DIR, 'state.json')));
  const n = store.state.alerts.length;
  store.state.alerts = [];
  store.load();
  assert.strictEqual(store.state.alerts.length, n);
});

// ---------- Phase 2: playbooks and cases ----------

test('every rule has a playbook and it auto-attaches to new alerts', () => {
  for (const r of detection.getRules()) assert.ok(playbooks.forRule(r.id), `no playbook for ${r.id}`);
  runScenario('brute_force');
  const a = store.state.alerts.find(x => x.ruleId === 'R001');
  assert.strictEqual(a.playbook.id, 'PB-BRUTE');
  assert.strictEqual(a.playbook.steps.length, playbooks.get('PB-BRUTE').steps.length);
});

test('playbook step check and note persist and are logged', () => {
  runScenario('cred_dump');
  const a = store.state.alerts[0];
  playbooks.updateStep(a.id, 0, { done: true, note: 'checked EDR' }, 1000);
  assert.deepStrictEqual(a.playbook.steps[0], { done: true, note: 'checked EDR', doneTs: 1000 });
  assert.ok(a.history.some(h => /Playbook done/.test(h.text)));
  assert.throws(() => playbooks.updateStep(a.id, 99, { done: true }), /step/);
});

test('escalate creates a case; second alert joins; an alert cannot be in two cases', () => {
  runScenario('new_admin');
  const [a1, a2] = store.state.alerts;
  const c = cases.escalate(a1.id, null);
  assert.strictEqual(c.status, 'Detection');
  assert.strictEqual(a1.caseId, c.id);
  assert.strictEqual(a1.status, 'Investigating');
  cases.escalate(a2.id, c.id);
  assert.deepStrictEqual(c.alertIds, [a1.id, a2.id]);
  assert.strictEqual(c.severity, 'critical'); // highest of linked alerts
  assert.throws(() => cases.escalate(a1.id, null), /already in case/);
});

test('case timeline is time-ordered and has events, alerts, notes and status entries', () => {
  runScenario('brute_force');
  const a = store.state.alerts[0];
  const c = cases.escalate(a.id, null, a.createdTs + 1000);
  cases.addNote(c.id, 'analyst', 'looking', a.createdTs + 2000);
  cases.update(c.id, { status: 'Analysis' }, a.createdTs + 3000);
  const tl = cases.timeline(c);
  for (let i = 1; i < tl.length; i++) assert.ok(tl[i].ts >= tl[i - 1].ts);
  assert.deepStrictEqual(new Set(tl.map(t => t.kind)), new Set(['event', 'alert', 'note', 'status']));
});

test('closing a case needs a summary and closes its alerts', () => {
  runScenario('cred_dump');
  const a = store.state.alerts[0];
  const c = cases.escalate(a.id, null);
  assert.throws(() => cases.update(c.id, { status: 'Closed' }), /summary/);
  assert.throws(() => cases.update(c.id, { status: 'Nope' }), /status/);
  cases.update(c.id, { summary: 'Contained; credentials reset.', status: 'Closed' });
  assert.strictEqual(c.status, 'Closed');
  assert.strictEqual(a.status, 'Closed');
  assert.strictEqual(a.verdict, 'true_positive');
});

test('a v1 state file loads, gets cases, and old alerts get playbooks', () => {
  runScenario('brute_force');
  const v1 = JSON.parse(JSON.stringify(store.state));
  v1.version = 1; delete v1.cases; delete v1.nextCaseId;
  for (const a of v1.alerts) { delete a.playbook; delete a.caseId; }
  fs.writeFileSync(store.file, JSON.stringify(v1));
  store.load();
  assert.strictEqual(store.state.version, store.VERSION); // v1 -> current
  assert.deepStrictEqual(store.state.cases, []);
  assert.strictEqual(store.state.nextCaseId, 1);
  assert.strictEqual(playbooks.attachMissing(), 1);
  assert.strictEqual(store.state.alerts[0].playbook.id, 'PB-BRUTE');
});
