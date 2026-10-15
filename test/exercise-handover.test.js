// Tests: scenario mode with scoring, shift handover, analyst-editable severity, state v4.
const { test, beforeEach, after } = require('node:test');
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
const intel = require('../src/intel');
const exercise = require('../src/exercise');
const handover = require('../src/handover');
const C = require('../src/company');

// Tests only read the repo's rule files; they must not change
const REPO_FILES = ['rules.json', 'playbooks.json', 'intel.json', 'scoring.json'].map(f => path.join(__dirname, '..', 'rules', f));
const before = REPO_FILES.map(f => fs.readFileSync(f, 'utf8'));
after(() => REPO_FILES.forEach((f, i) => assert.strictEqual(fs.readFileSync(f, 'utf8'), before[i], `${f} must not change`)));

beforeEach(() => {
  store.reset();
  engine.clearPending();
  Object.assign(store.state, { exercises: [], handovers: [], handoverDraft: '' });
  store.state.generator.autoScenarios = true;
  detection.loadRules(); playbooks.load();
});

// Start an exercise and deliver all of its events at once
function startEx(scenario, now = Date.now(), minutes = 15) {
  exercise.start({ scenario, minutes }, now);
  engine.releaseDue(Infinity);
  exercise.tick(now);
  return store.state.exercise;
}
const crit = (card, key) => card.criteria.find(c => c.key === key);
// Today at the given hour: keeps logon-based scenarios out of R004's night window (00:00-05:59)
const dayTs = (h = 10) => { const d = new Date(); d.setHours(h, 0, 0, 0); return d.getTime(); };
const SEVS = ['low', 'medium', 'high', 'critical'];

// ---------- answer keys and new scenarios ----------

test('every scenario has a well-formed answer key that matches its expected verdict', () => {
  const ruleIds = detection.getRules().map(r => r.id);
  for (const [key, s] of Object.entries(gen.scenarios)) {
    for (let i = 0; i < 5; i++) {
      const a = s.answer(engine.plan(key));
      assert.ok(alerts.VERDICTS.includes(a.verdict), `${key}: verdict`);
      assert.strictEqual(a.verdict, s.expected, `${key}: answer matches expected`);
      assert.ok(a.severities === 'not_raised' || (a.severities.length && a.severities.every(x => SEVS.includes(x))), `${key}: severities`);
      assert.ok(['required', 'optional', 'never'].includes(a.case), `${key}: case`);
      assert.ok(a.rules.length && a.rules.every(r => ruleIds.includes(r)), `${key}: rules`);
      assert.ok(a.explain.length > 20 && a.clues.length >= 2, `${key}: explanation`);
      if (a.verdict !== 'true_positive') assert.strictEqual(a.case, 'never', `${key}: non-incidents need no case`);
    }
  }
  const nonIncidents = Object.values(gen.scenarios).filter(s => s.expected !== 'true_positive');
  assert.ok(nonIncidents.length >= 4, 'enough benign / false-positive scenarios to practise not over-escalating');
});

test('brute force answer depends on whether a logon succeeded', () => {
  let seen = new Set();
  for (let i = 0; i < 60 && seen.size < 2; i++) {
    const evs = engine.plan('brute_force');
    const a = gen.scenarios.brute_force.answer(evs);
    const success = evs.some(e => e.eventId === 4624);
    assert.deepStrictEqual([a.severities, a.case], success ? [['critical'], 'required'] : [['high'], 'optional']);
    seen.add(success);
  }
  assert.strictEqual(seen.size, 2);
});

test('new_starter_account raises only R002 and carries a change reference', () => {
  const evs = gen.expand('new_starter_account', Date.now());
  evs.forEach(e => engine.ingest(e));
  assert.deepStrictEqual(store.state.alerts.map(a => a.ruleId), ['R002']);
  assert.match(evs[0].changeRef, /^CHG-\d{5}$/);
  assert.ok(C.users.find(u => u.name === evs[0].user).isAdmin);
});

test('backup_agent_edr raises R007 with a simulated hash that is not on the intel list', () => {
  for (let i = 0; i < 20; i++) {
    const [e] = gen.expand('backup_agent_edr', Date.now());
    assert.ok(intel.isSimHash(e.fileHash) && !intel.lookup(e.fileHash));
    assert.strictEqual(e.user, 'svc_backup');
  }
  gen.expand('backup_agent_edr', Date.now()).forEach(e => engine.ingest(e));
  assert.deepStrictEqual(store.state.alerts.map(a => a.ruleId), ['R007']);
});

// ---------- analyst-editable severity, raisedTs ----------

test('alert severity can be changed by the analyst; the rule severity is kept', () => {
  gen.expand('cred_dump', Date.now()).forEach(e => engine.ingest(e));
  const a = store.state.alerts[0];
  alerts.update(a.id, { severity: 'high' }, 1000);
  assert.strictEqual(a.severity, 'high');
  assert.strictEqual(a.ruleSeverity, 'critical');
  assert.ok(a.history.some(h => h.text === 'Severity: critical -> high'));
  assert.throws(() => alerts.update(a.id, { severity: 'extreme' }), /severity/);
});

test('a late log raises an alert with an old createdTs but raisedTs = when it arrived', () => {
  const now = Date.now();
  engine.inject('off_hours_login', now);
  const a = store.state.alerts.find(x => x.ruleId === 'R004');
  assert.ok(a.createdTs < now);
  assert.strictEqual(a.raisedTs, now);
});

// ---------- exercise lifecycle ----------

test('a random exercise hides the scenario; injected events carry no scenario tag', () => {
  const t0 = Date.now();
  exercise.start({ scenario: 'random' }, t0);
  const cur = exercise.current(t0);
  assert.strictEqual(cur.running, true);
  assert.strictEqual(cur.name, null);
  for (const k of ['key', 'answer', 'eventIds', 'eventCount']) assert.ok(!(k in cur), `current() must not expose ${k}`);
  const json = JSON.stringify(cur);
  for (const k of Object.keys(gen.scenarios)) assert.ok(!json.includes(k));
  engine.releaseDue(Infinity); exercise.tick(t0);
  const ex = store.state.exercise;
  const ids = new Set(ex.eventIds);
  const evs = store.state.events.filter(e => ids.has(e.id));
  assert.strictEqual(evs.length, ex.eventCount);
  assert.ok(evs.every(e => !e.tags.some(t => t.startsWith('scenario:'))));
  assert.strictEqual(exercise.current().minutes, exercise.scoring().defaultMinutes);
});

test('a picked exercise shows its name; bad input and a second exercise are refused', () => {
  assert.throws(() => exercise.start({ scenario: 'nope' }), /Unknown scenario/);
  assert.throws(() => exercise.start({ scenario: 'cred_dump', minutes: 7 }), /Time limit/);
  exercise.start({ scenario: 'cred_dump', minutes: 10 });
  assert.strictEqual(exercise.current().name, gen.scenarios.cred_dump.name);
  assert.throws(() => exercise.start({ scenario: 'cred_dump' }), /already running/);
  assert.throws(() => exercise.submit() && exercise.submit(), /No exercise/);
});

test('auto-scenarios are paused during an exercise and restored afterwards', () => {
  store.state.generator.autoScenarios = true;
  startEx('cred_dump');
  assert.strictEqual(store.state.generator.autoScenarios, false);
  exercise.submit();
  assert.strictEqual(store.state.generator.autoScenarios, true);
  store.state.generator.autoScenarios = false;
  startEx('cred_dump');
  exercise.abandon();
  assert.strictEqual(store.state.generator.autoScenarios, false);
});

test('an exercise never merges into an alert that is already open for the same entity', () => {
  const admins = C.users.filter(u => u.isAdmin);
  const blocked = admins.slice(0, 2).map(u => u.name);
  for (let i = 0; i < 5; i++) {
    store.reset(); engine.clearPending();
    blocked.forEach((name, j) => store.state.alerts.push({ id: 900 + j, ruleId: 'R004', key: name, status: 'New', severity: 'medium',
      relatedEventIds: [], notes: [], history: [], lastEventTs: Date.now(), createdTs: Date.now(), raisedTs: Date.now() }));
    const ex = startEx('admin_patching');
    const [a] = exercise.exerciseAlerts(ex);
    assert.ok(a && !blocked.includes(a.key), `exercise alert should be for a free admin, got ${a && a.key}`);
    exercise.abandon();
  }
});

test('a scenario whose rule is disabled cannot be picked, and random never chooses it', () => {
  detection.getRules().find(r => r.id === 'R007').enabled = false;
  assert.throws(() => exercise.start({ scenario: 'cred_dump' }), /R007 is disabled/);
  for (let i = 0; i < 25; i++) {
    exercise.start({ scenario: 'random' });
    const rec = exercise.abandon();
    assert.ok(!['cred_dump', 'backup_agent_edr'].includes(rec.key), `random picked ${rec.key}`);
    engine.clearPending();
  }
});

test('the exercise is auto-submitted at the deadline', () => {
  const t0 = Date.now();
  startEx('cred_dump', t0, 10);
  exercise.tick(t0 + 9 * 60e3);
  assert.ok(store.state.exercise);
  exercise.tick(t0 + 10 * 60e3);
  assert.strictEqual(store.state.exercise, null);
  const [rec] = exercise.history();
  assert.strictEqual(rec.outcome, 'timeout');
  assert.strictEqual(typeof rec.score, 'number');
  assert.strictEqual(rec.headline, 'Unfinished'); // nothing was done
});

test('after a restart, an exercise that lost drip-fed events is marked interrupted; a complete one carries on', () => {
  const t0 = Date.now();
  exercise.start({ scenario: 'c2_beacon' }, t0); // only the first event is due now
  exercise.tick(t0);
  assert.ok(store.state.exercise.eventIds.length < store.state.exercise.eventCount);
  const rec = exercise.resume(t0 + 1000);
  assert.strictEqual(rec.outcome, 'interrupted');
  assert.strictEqual(rec.score, null);
  engine.clearPending();
  startEx('new_starter_account', t0);
  assert.strictEqual(exercise.resume(t0 + 1000), null);
  assert.ok(store.state.exercise);
});

test('score history survives a reset of the simulated data', () => {
  startEx('cred_dump');
  exercise.submit();
  startEx('cred_dump');
  store.reset();
  assert.strictEqual(store.state.exercises.length, 1);
  assert.strictEqual(store.state.exercise, null);
});

// ---------- scoring ----------

test('a perfect run on a two-alert incident scores 100', () => {
  const t0 = Date.now();
  const ex = startEx('new_admin', t0);
  const list = exercise.exerciseAlerts(ex);
  assert.deepStrictEqual(list.map(a => a.ruleId).sort(), ['R002', 'R003']);
  for (const a of list) alerts.update(a.id, { assignee: 'analyst1', status: 'Investigating' }, t0 + 60e3);
  const c = cases.create({ alertIds: list.map(a => a.id), owner: 'analyst1' }, t0 + 70e3);
  assert.strictEqual(c.severity, 'critical');
  for (const a of list) a.playbook.steps.forEach((s, i) => playbooks.updateStep(a.id, i, { done: true }, t0 + 90e3));
  cases.addNote(c.id, 'analyst1', 'Account created and made admin with no change ticket.', t0 + 100e3);
  alerts.addNote(list[0].id, 'analyst1', 'The creating admin says it was not them.', t0 + 110e3);
  cases.update(c.id, { summary: 'Unauthorised admin account removed; creator credentials reset.', status: 'Closed' }, t0 + 300e3);
  const r = exercise.submit(t0 + 400e3);
  assert.strictEqual(r.score, 100, JSON.stringify(r.criteria.filter(x => x.status !== 'got' && x.status !== 'n/a')));
  assert.strictEqual(r.headline, 'Correct call');
  assert.strictEqual(crit(r, 'linked').given, '2/2 in one case');
  assert.strictEqual(store.state.exercise, null);
  assert.strictEqual(exercise.get(r.id).score, 100);
});

test('splitting related alerts across cases loses the linking marks', () => {
  const t0 = Date.now();
  const ex = startEx('c2_beacon', t0);
  const [a1, a2] = exercise.exerciseAlerts(ex);
  cases.escalate(a1.id, null, t0 + 10e3);
  cases.escalate(a2.id, null, t0 + 20e3);
  const r = exercise.submit(t0 + 60e3);
  assert.strictEqual(crit(r, 'linked').credit, 0.5);
  assert.strictEqual(crit(r, 'escalation').credit, 1);
});

test('a benign scenario escalated as a true positive is "Over-escalated"', () => {
  const t0 = Date.now();
  const ex = startEx('admin_patching', t0);
  const [a] = exercise.exerciseAlerts(ex);
  alerts.update(a.id, { verdict: 'true_positive', severity: 'critical' }, t0 + 30e3);
  cases.escalate(a.id, null, t0 + 40e3);
  const r = exercise.submit(t0 + 60e3);
  assert.strictEqual(r.headline, 'Over-escalated');
  assert.strictEqual(crit(r, 'verdict').credit, 0);
  assert.strictEqual(crit(r, 'escalation').credit, 0);
  assert.strictEqual(crit(r, 'severity').credit, 0, 'raising severity on a non-incident is marked down');
});

test('a benign scenario handled well scores high without a case', () => {
  const t0 = dayTs();
  const ex = startEx('user_typos', t0);
  const [a] = exercise.exerciseAlerts(ex);
  alerts.update(a.id, { status: 'Investigating', assignee: 'analyst2' }, t0 + 80e3);
  a.playbook.steps.forEach((s, i) => playbooks.updateStep(a.id, i, { done: true }));
  alerts.addNote(a.id, 'analyst2', 'Failures came from the user\'s own PC, then success.', t0 + 100e3);
  playbooks.updateStep(a.id, 2, { note: 'User confirmed by phone they mistyped it.' });
  alerts.update(a.id, { verdict: 'benign', severity: 'low' }, t0 + 110e3);
  alerts.update(a.id, { status: 'Closed' }, t0 + 120e3);
  const r = exercise.submit(t0 + 130e3);
  assert.strictEqual(r.headline, 'Correct call');
  assert.strictEqual(r.score, 100);
  assert.strictEqual(crit(r, 'linked').credit, null);
});

test('a true positive closed as benign is a "Missed incident"', () => {
  const t0 = Date.now();
  const ex = startEx('cred_dump', t0);
  const [a] = exercise.exerciseAlerts(ex);
  alerts.update(a.id, { verdict: 'benign' }, t0 + 30e3);
  alerts.update(a.id, { status: 'Closed' }, t0 + 40e3);
  const r = exercise.submit(t0 + 50e3);
  assert.strictEqual(r.headline, 'Missed incident');
  assert.strictEqual(crit(r, 'verdict').credit, 0);
  assert.strictEqual(crit(r, 'escalation').credit, 0);
});

test('benign vs false positive mix-up gets half marks', () => {
  for (const [verdict, credit, headline] of [['benign', 0.5, 'Partly right'], ['false_positive', 1, 'Correct call']]) {
    const t0 = Date.now();
    const ex = startEx('backup_agent_edr', t0);
    const [a] = exercise.exerciseAlerts(ex);
    alerts.update(a.id, { verdict }, t0 + 30e3);
    alerts.update(a.id, { status: 'Closed' }, t0 + 40e3);
    const r = exercise.submit(t0 + 50e3);
    assert.strictEqual(crit(r, 'verdict').credit, credit);
    assert.strictEqual(r.headline, headline);
  }
});

test('MTTA for a late-log alert counts from when it appeared, not from last night', () => {
  const t0 = Date.now();
  const ex = startEx('off_hours_login', t0);
  const [a] = exercise.exerciseAlerts(ex);
  assert.ok(a.createdTs < t0);
  alerts.update(a.id, { status: 'Investigating' }, t0 + 30e3);
  const r = exercise.submit(t0 + 60e3);
  assert.strictEqual(r.actions.mttaSeconds, 30);
  assert.strictEqual(crit(r, 'mtta').credit, 1);
  assert.strictEqual(crit(r, 'mttr').credit, 0, 'never closed');
});

test('slow responses lose time marks gradually', () => {
  const t0 = Date.now();
  const ex = startEx('cred_dump', t0, 60); // critical: MTTA target 120 s, zero at 360 s
  const [a] = exercise.exerciseAlerts(ex);
  alerts.update(a.id, { status: 'Investigating' }, t0 + 240e3);
  const r = exercise.submit(t0 + 300e3);
  assert.strictEqual(crit(r, 'mtta').credit, 0.5);
});

test('submitting before any alert appeared scores 0 with an explanation', () => {
  const t0 = Date.now();
  exercise.start({ scenario: 'c2_beacon' }, t0);
  store.state.alerts = []; // as if the first event had not tripped a rule yet
  const r = exercise.submit(t0 + 1000);
  assert.strictEqual(r.score, 0);
  assert.strictEqual(r.headline, 'No alert yet');
  assert.match(r.reason, /No alert/);
});

test('scoring.json is validated', () => {
  const ok = exercise.loadScoring();
  assert.throws(() => exercise.validateScoring({ ...ok, weights: { ...ok.weights, verdict: -1 } }), /weights.verdict/);
  assert.throws(() => exercise.validateScoring({ ...ok, targetsSeconds: { ...ok.targetsSeconds, low: {} } }), /targetsSeconds.low/);
  assert.throws(() => exercise.validateScoring({ ...ok, defaultMinutes: 7 }), /defaultMinutes/);
  assert.throws(() => exercise.validateScoring([]), /object/);
});

// ---------- shift handover ----------

test('handover report: window, severity counts, cases, IOCs, MTTA/MTTR and watch list', () => {
  const now = dayTs(12);
  const t = now - 2 * 3600e3;
  const beacon = gen.expand('c2_beacon', t);
  beacon.forEach(e => engine.ingest(e));
  gen.expand('cred_dump', t + 600e3).forEach(e => engine.ingest(e));
  gen.expand('new_starter_account', now - 20 * 3600e3).forEach(e => engine.ingest(e)); // before the window, still open
  const fpTimes = [t + 1000e3, t + 2000e3, t + 3000e3];
  for (const ts of fpTimes) gen.expand('user_typos', ts).forEach(e => engine.ingest(e));
  const by = id => store.state.alerts.filter(a => a.ruleId === id);
  const [r5] = by('R005'); const [r6] = by('R006'); const [r7] = by('R007');
  assert.strictEqual(by('R001').length, 3);

  alerts.update(r5.id, { status: 'Investigating' }, r5.raisedTs + 120e3);             // MTTA 120 s
  const c = cases.escalate(r5.id, null, t + 400e3);                                   // case with no owner
  alerts.update(r6.id, { verdict: 'true_positive' }, t + 600e3);
  alerts.update(r6.id, { status: 'Closed' }, r6.raisedTs + 600e3);                    // TP closed without a case: 600 s
  for (const a of by('R001')) {
    alerts.update(a.id, { verdict: 'false_positive' }, a.raisedTs + 60e3);
    alerts.update(a.id, { status: 'Closed' }, a.raisedTs + 60e3);                     // 60 s each
  }

  const r = handover.report({ fromTs: now - 8 * 3600e3, toTs: now, now });
  assert.deepStrictEqual(r.alerts.totals, { new: 6, open: 3, closed: 4 });
  assert.deepStrictEqual(r.alerts.new, { critical: 1, high: 5, medium: 0, low: 0 });
  assert.strictEqual(r.alerts.open.medium, 1); // the 20 h old R002
  assert.deepStrictEqual(r.alerts.closedByVerdict, { true_positive: 1, false_positive: 3, benign: 0 });
  assert.deepStrictEqual(r.cases.open.map(x => [x.id, x.status, x.owner]), [[c.id, 'Detection', '']]);
  assert.strictEqual(r.mttaSeconds, Math.round((120 + 600 + 60 * 3) / 5));
  assert.strictEqual(r.mttrSeconds, Math.round((600 + 60 * 3) / 4));

  const ip = beacon.find(e => e.dstIp).dstIp;
  const ipRow = r.iocs.find(x => x.value === ip);
  assert.ok(ipRow && ipRow.intel && ipRow.sightings === 4 && ipRow.alertIds.includes(r5.id));
  const has = re => r.watch.some(w => re.test(w.text));
  assert.ok(r.watch.some(w => w.level === 'high' && w.link.type === 'alert' && w.link.id === r7.id), 'critical alert still New');
  assert.ok(has(/waiting more than 4 h/), 'aging alerts');
  assert.ok(has(new RegExp(`Case #${c.id} .* has no owner`)));
  assert.ok(has(new RegExp(`Host ${beacon[0].host} appears in \\d+ alerts`)));
  assert.ok(has(new RegExp(`${ip.replace(/\./g, '\\.')} is on the intel list .* not recorded on any case`)));
  assert.ok(has(new RegExp(`#${r6.id} .* closed as a true positive without a case`)));
  assert.ok(has(/Rule R001 produced 3 false positives/));

  // Recording the IP on the case moves it off the watch list
  cases.addIoc(c.id, { value: ip, note: 'C2 server' }, now);
  const r2 = handover.report({ fromTs: now - 8 * 3600e3, toTs: now, now });
  assert.deepStrictEqual(r2.iocs.find(x => x.value === ip).cases, [c.id]);
  assert.ok(!r2.watch.some(w => w.text.includes(`${ip} is on the intel list`)));

  // A narrower window leaves the earlier alerts out
  const r3 = handover.report({ fromTs: now - 1800e3, toTs: now, now });
  assert.strictEqual(r3.alerts.totals.new, 0);
  assert.throws(() => handover.report({ fromTs: now, toTs: now - 1 }), /window/);
});

test('handover notes: draft, save with a frozen report, list, survives reset', () => {
  const now = Date.now();
  handover.saveDraft('half-written');
  assert.strictEqual(store.state.handoverDraft, 'half-written');
  assert.throws(() => handover.save({ analyst: 'mallory' }), /Unknown analyst/);
  const h = handover.save({ analyst: 'analyst2', notes: 'Keep an eye on WS-005', fromTs: now - 8 * 3600e3, toTs: now }, now);
  assert.strictEqual(store.state.handoverDraft, '');
  assert.strictEqual(h.snapshot.fromTs, now - 8 * 3600e3);
  assert.ok(Array.isArray(h.snapshot.watch));
  const [first] = handover.list();
  assert.strictEqual(first.id, h.id);
  assert.ok(!('snapshot' in first));
  assert.strictEqual(handover.get(h.id).notes, 'Keep an eye on WS-005');
  assert.strictEqual(handover.previous().id, h.id);
  store.reset();
  assert.strictEqual(store.state.handovers.length, 1);
});

// ---------- state v4 ----------

test('a v3 state file migrates to v4, is backed up first, and the backup is never overwritten', () => {
  gen.expand('cred_dump', Date.now()).forEach(e => engine.ingest(e));
  const v3 = JSON.parse(JSON.stringify(store.state));
  v3.version = 3;
  for (const k of ['exercise', 'exercises', 'nextExerciseId', 'handovers', 'nextHandoverId', 'handoverDraft']) delete v3[k];
  for (const a of v3.alerts) { delete a.raisedTs; delete a.ruleSeverity; }
  const bak = store.backupFile(3);
  if (fs.existsSync(bak)) fs.unlinkSync(bak);
  fs.writeFileSync(store.file, JSON.stringify(v3));

  store.load();
  assert.strictEqual(store.state.version, 4);
  const a = store.state.alerts[0];
  assert.strictEqual(a.raisedTs, a.createdTs);
  assert.strictEqual(a.ruleSeverity, a.severity);
  assert.ok(Array.isArray(store.state.exercises) && Array.isArray(store.state.handovers));
  assert.strictEqual(store.state.exercise, null);
  assert.strictEqual(JSON.parse(fs.readFileSync(bak, 'utf8')).version, 3);
  const firstBackup = fs.readFileSync(bak, 'utf8');

  fs.writeFileSync(store.file, JSON.stringify({ ...v3, alerts: [] }));
  store.load();
  assert.strictEqual(fs.readFileSync(bak, 'utf8'), firstBackup);
  store.save(); store.load();
  assert.ok(!fs.existsSync(store.backupFile(4)));
});
