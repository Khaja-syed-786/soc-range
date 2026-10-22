// Tests: phishing (R008), password spraying (R009), lateral movement (R010), beacon behaviour (R011), external logon (R012),
// mail + change log sources, and the "doing nothing earns no severity/escalation marks" scoring fix.
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
const intel = require('../src/intel');
const exercise = require('../src/exercise');
const cases = require('../src/cases');
const mitre = require('../src/mitre');
const ioc = require('../src/ioc');
const C = require('../src/company');

// Tests only read the repo's rule files; they must not change
const REPO_FILES = ['rules.json', 'playbooks.json', 'intel.json', 'scoring.json'].map(f => path.join(__dirname, '..', 'rules', f));
const before = REPO_FILES.map(f => fs.readFileSync(f, 'utf8'));
after(() => REPO_FILES.forEach((f, i) => assert.strictEqual(fs.readFileSync(f, 'utf8'), before[i], `${f} must not change`)));

const fresh = () => { store.reset(); engine.clearPending(); detection.loadRules(); };
beforeEach(() => {
  fresh();
  Object.assign(store.state, { exercises: [], handovers: [], handoverDraft: '' });
  store.state.generator.autoScenarios = true;
  playbooks.load();
});

// Today at the given hour: keeps logon-based scenarios out of R004's night window (00:00-05:59)
const dayTs = (h = 10) => { const d = new Date(); d.setHours(h, 0, 0, 0); return d.getTime(); };
const run = (key, ts = dayTs()) => { const evs = engine.plan(key, ts); evs.forEach(e => engine.ingest(e)); return evs; };
const ruleIds = () => [...new Set(store.state.alerts.map(a => a.ruleId))].sort();
const rule = id => detection.getRules().find(r => r.id === id);
const ev = (ts, f) => ({ ts, source: 'winsec', tags: [], ...f });
let nextId = 1;
const feed = list => list.map(e => { e.id = nextId++; return detection.evaluate(e); }).flat();
const NEW = ['phishing_link', 'newsletter_click', 'password_spray', 'lateral_movement', 'admin_maintenance', 'beacon_unlisted'];

// ---------- rule engine ----------

test('the four new rules load with their MITRE tags', () => {
  const want = { R008: ['match', 'T1566'], R009: ['threshold', 'T1110.003'], R010: ['threshold', 'T1021'], R011: ['beacon', 'T1071'] };
  for (const [id, [type, tag]] of Object.entries(want)) {
    assert.strictEqual(rule(id).type, type);
    assert.strictEqual(rule(id).mitre, tag);
  }
  assert.strictEqual(rule('R009').distinct, 'user');
  assert.strictEqual(rule('R010').distinct, 'host');
});

test('validator rejects bad distinct and incomplete beacon rules', () => {
  const base = detection.getRules();
  const withRule = r => [...base, { id: 'X1', enabled: true, severity: 'low', groupBy: 'host', ...r }];
  assert.throws(() => detection.saveRules(withRule({ type: 'threshold', count: 2, windowSeconds: 60, distinct: 5 })), /distinct/);
  assert.throws(() => detection.saveRules(withRule({ type: 'beacon', count: 6, windowSeconds: 60, maxJitter: 0.1, minIntervalSeconds: 10 })), /per/);
  assert.throws(() => detection.saveRules(withRule({ type: 'beacon', count: 2, windowSeconds: 60, per: 'dstIp', maxJitter: 0.1, minIntervalSeconds: 10 })), /count/);
  assert.throws(() => detection.saveRules(withRule({ type: 'beacon', count: 6, windowSeconds: 60, per: 'dstIp', maxJitter: 2, minIntervalSeconds: 10 })), /maxJitter/);
  assert.throws(() => detection.saveRules(withRule({ type: 'beacon', count: 6, windowSeconds: 60, per: 'dstIp', maxJitter: 0.1 })), /minIntervalSeconds/);
});

test('distinct threshold counts different users, not raw failures', () => {
  const t = dayTs();
  const ip = '203.0.113.120';
  // 6 failures for ONE user from one IP: R001 fires, R009 must not
  let hits = feed(Array.from({ length: 6 }, (_, i) => ev(t + i * 1000, { eventId: 4625, user: 'one.user', srcIp: ip, host: 'DC01' })));
  assert.ok(hits.some(h => h.rule.id === 'R001'));
  assert.ok(!hits.some(h => h.rule.id === 'R009'));
  fresh();
  // 5 different users, one failure each: R009 fires on the 5th, R001 never
  hits = feed(Array.from({ length: 5 }, (_, i) => ev(t + i * 1000, { eventId: 4625, user: `u${i}`, srcIp: ip, host: 'DC01' })));
  const r9 = hits.filter(h => h.rule.id === 'R009');
  assert.strictEqual(r9.length, 1);
  assert.strictEqual(r9[0].key, ip);
  assert.strictEqual(r9[0].eventIds.length, 5);
  assert.ok(!hits.some(h => h.rule.id === 'R001'));
});

test('beacon rule fires on regular intervals only', () => {
  const t = dayTs();
  const fw = (ts, dstIp = '203.0.113.210', host = 'WS-005') => ({ ts, source: 'firewall', host, dstIp, action: 'allow', tags: [] });
  const r11 = list => feed(list).filter(h => h.rule.id === 'R011');
  // Regular: every 60 s +/- 1 s -> fires at the 6th
  const regular = [0, 60, 121, 180, 241, 300].map(s => fw(t + s * 1000));
  const hits = r11(regular);
  assert.strictEqual(hits.length, 1);
  assert.strictEqual(hits[0].key, 'WS-005');
  assert.deepStrictEqual(hits[0].eventIds, regular.map(e => e.id));
  fresh();
  assert.strictEqual(r11([0, 60, 120, 180, 240].map(s => fw(t + s * 1000))).length, 0, 'five is not enough');
  fresh();
  assert.strictEqual(r11([0, 20, 110, 130, 250, 300].map(s => fw(t + s * 1000))).length, 0, 'irregular gaps');
  fresh();
  assert.strictEqual(r11([0, 20, 40, 60, 80, 100].map(s => fw(t + s * 1000))).length, 0, 'faster than minIntervalSeconds');
  fresh();
  assert.strictEqual(r11([0, 60, 120, 180, 240, 300].map((s, i) => fw(t + s * 1000, `203.0.113.${210 + i}`))).length, 0, 'different IPs');
  fresh();
  assert.strictEqual(r11([0, 60, 120, 180, 240, 300].map(s => ({ ...fw(t + s * 1000), action: 'deny' }))).length, 0, 'blocked traffic');
});

// ---------- scenarios ----------

test('every scenario raises exactly the rules its answer key names (old and new)', () => {
  for (const key of Object.keys(gen.scenarios)) {
    for (let i = 0; i < 8; i++) {
      fresh();
      const evs = run(key);
      assert.deepStrictEqual(ruleIds(), [...gen.scenarios[key].answer(evs).rules].sort(), `${key} run ${i}`);
    }
  }
});

test('phishing_link: with credentials submitted, a later logon from a new IP raises R012, not part of the R008 alert', () => {
  const seen = new Set();
  for (let i = 0; i < 60 && seen.size < 2; i++) {
    fresh();
    const evs = run('phishing_link');
    const a = gen.scenarios.phishing_link.answer(evs);
    const submit = evs.find(e => e.action === 'form_submit');
    const logon = evs.find(e => e.eventId === 4624);
    const fwIp = evs.find(e => e.source === 'firewall').dstIp;
    seen.add(!!submit);
    assert.ok(!intel.lists.badIps.has(fwIp) && fwIp.startsWith('203.0.113.'));
    if (!submit) {
      assert.ok(!logon);
      assert.deepStrictEqual([a.severities, a.case], [['high'], 'optional']);
      continue;
    }
    assert.ok(logon, 'a logon follows the form submit');
    assert.strictEqual(logon.user, evs[1].user);
    assert.ok(logon.srcIp.startsWith('203.0.113.') && logon.srcIp !== fwIp && !intel.lists.badIps.has(logon.srcIp));
    const gap = (logon.ts - submit.ts) / 1000;
    assert.ok(gap >= 180 && gap <= 300, `logon ${gap}s after submit`);
    const withLogon = store.state.alerts.filter(x => x.relatedEventIds.includes(logon.id));
    assert.deepStrictEqual(withLogon.map(x => x.ruleId), ['R012'], 'only R012 alerts on the logon');
    assert.ok(!withLogon[0].relatedEventIds.includes(evs[1].id), 'the R012 alert holds the logon, not the click');
    assert.deepStrictEqual(a.rules, ['R008', 'R012']);
    assert.deepStrictEqual([a.severities, a.case], [['critical'], 'required']);
    assert.ok(a.clues.some(c => c.includes(logon.srcIp) && /R012/.test(c) && /Log Search/.test(c)), 'clues point to the logon');
  }
  assert.strictEqual(seen.size, 2, 'both variants occur');
  assert.ok(playbooks.forRule('R008').steps.some(s => /logons from new IPs after the click/i.test(s.title)));
});

test('phishing and newsletter differ in the clues an analyst can see', () => {
  const p = run('phishing_link');
  fresh();
  const n = run('newsletter_click');
  assert.strictEqual(p[0].spf, 'fail');
  assert.strictEqual(n[0].spf, 'pass');
  assert.ok(p[0].recipients <= 3 && n[0].recipients >= 25);
  assert.ok(C.benignExternalIps.includes(n.find(e => e.source === 'firewall').dstIp));
  assert.ok(!n.some(e => e.action === 'form_submit' || e.eventId === 4624));
  for (const e of [p[1], n[1]]) assert.ok(e.domainAgeDays <= 30);
});

test('password_spray: one IP, many users, one failure each; R001 stays silent', () => {
  const seen = new Set();
  for (let i = 0; i < 60 && seen.size < 2; i++) {
    fresh();
    const evs = run('password_spray');
    const fails = evs.filter(e => e.eventId === 4625);
    assert.strictEqual(new Set(evs.map(e => e.srcIp)).size, 1);
    assert.strictEqual(new Set(fails.map(e => e.user)).size, fails.length, 'one failure per user');
    assert.ok(fails.length >= 8);
    assert.ok(!store.state.alerts.some(a => a.ruleId === 'R001'));
    const ok = evs.some(e => e.eventId === 4624);
    seen.add(ok);
    assert.deepStrictEqual(gen.scenarios.password_spray.answer(evs).severities, ok ? ['critical'] : ['high']);
  }
  assert.strictEqual(seen.size, 2);
});

test('lateral_movement vs admin_maintenance: source PC, role and change ticket', () => {
  for (let i = 0; i < 10; i++) {
    fresh();
    const lat = run('lateral_movement');
    const u = C.users.find(x => x.name === lat[0].user);
    assert.ok(!u.isAdmin);
    assert.notStrictEqual(C.hosts.find(h => h.ip === lat[0].srcIp).name, u.pc, 'hops from someone else\'s PC');
    assert.ok(lat.every(e => e.logonType === 3 && e.host !== u.pc));
    assert.ok(!lat.some(e => e.source === 'change'));

    fresh();
    const adm = run('admin_maintenance');
    const [chg, ...logons] = adm;
    const a = C.users.find(x => x.name === logons[0].user);
    assert.ok(a.isAdmin);
    assert.strictEqual(chg.source, 'change');
    assert.match(chg.changeRef, /^CHG-\d{5}$/);
    assert.ok(chg.ts < logons[0].ts, 'ticket approved before the work');
    assert.deepStrictEqual([...chg.hosts].sort(), logons.map(e => e.host).sort());
    assert.ok(logons.every(e => e.srcIp === C.hostByName[a.pc].ip && !('changeRef' in e)), 'ticket is a change event, not a logon field');
  }
});

test('beacon_unlisted: an IP on no intel list, caught by behaviour only', () => {
  for (let i = 0; i < 10; i++) {
    fresh();
    const evs = run('beacon_unlisted');
    assert.strictEqual(evs.length, 6);
    assert.strictEqual(new Set(evs.map(e => e.dstIp)).size, 1);
    assert.ok(!intel.lists.badIps.has(evs[0].dstIp));
    assert.deepStrictEqual(ruleIds(), ['R011']);
  }
});

test('new scenarios use simulated IPs and .example domains only', () => {
  for (const key of NEW) {
    for (let i = 0; i < 10; i++) {
      for (const e of gen.expand(key, dayTs())) {
        for (const f of ['srcIp', 'dstIp']) if (e[f]) assert.ok(intel.isSimIp(e[f]), `${key} ${f} ${e[f]}`);
        for (const f of ['domain', 'urlDomain', 'senderDomain']) if (e[f]) assert.ok(intel.isSimDomain(e[f]), `${key} ${f} ${e[f]}`);
        if (e.sender) assert.ok(e.sender.endsWith('.example'));
      }
    }
  }
});

test('a day of noise at the default rate has mail and change events but raises none of R008-R012', () => {
  const start = new Date(2026, 8, 30).getTime(); // a Wednesday, so office-hour mail noise exists
  const sources = {};
  let id = 1;
  for (let t = start; t < start + 24 * 3600e3; t += 1000) {
    const e = gen.noise(t); e.id = id++;
    sources[e.source] = (sources[e.source] || 0) + 1;
    if (e.action === 'link_click') assert.ok(e.domainAgeDays > 30, 'noise clicks only go to established domains');
    for (const h of detection.evaluate(e)) assert.ok(!['R008', 'R009', 'R010', 'R011', 'R012'].includes(h.rule.id), `${h.rule.id} fired on noise`);
  }
  assert.ok(sources.mail > 0 && sources.change > 0);
});

test('playbooks attach to the new rules; MITRE has T1110.003; IOC lookup sees mail domains', () => {
  for (const [key, pb] of [['phishing_link', 'PB-PHISH'], ['password_spray', 'PB-SPRAY'], ['lateral_movement', 'PB-LATERAL'], ['beacon_unlisted', 'PB-BEACON-PATTERN'], ['external_logon', 'PB-EXTLOGON']]) {
    fresh();
    run(key);
    assert.strictEqual(store.state.alerts[0].playbook.id, pb, key);
  }
  assert.ok(mitre.catalogue().some(t => t.id === 'T1110.003'));
  fresh();
  const evs = run('phishing_link');
  const r = ioc.lookup(evs[0].senderDomain);
  assert.ok(r.sightings.sources.some(s => s.name === 'mail'));
  assert.ok(r.alerts.some(a => a.title === rule('R008').name));
});

// ---------- R012: successful logon from an internet address ----------

test('R012 is a high-severity match rule for T1078 on successful logons from 203.0.113.x', () => {
  const r = rule('R012');
  assert.deepStrictEqual([r.type, r.severity, r.mitre, r.enabled, r.groupBy], ['match', 'high', 'T1078', true, 'user']);
  assert.ok(mitre.catalogue().some(t => t.id === 'T1078'));
  assert.strictEqual(detection.getRules().length, 12);
});

test('R012 fires on a 4624 from 203.0.113.x and on nothing else', () => {
  const t0 = dayTs();
  const base = { host: 'DC01', user: 'jdoe', logonType: 3, action: 'success' };
  const hit = list => list.filter(h => h.rule.id === 'R012').length;
  assert.strictEqual(hit(feed([ev(t0, { ...base, eventId: 4624, srcIp: '203.0.113.50' })])), 1, 'internet success');
  assert.strictEqual(hit(feed([ev(t0, { ...base, eventId: 4624, srcIp: '192.0.2.105' })])), 0, 'company address');
  assert.strictEqual(hit(feed([ev(t0, { ...base, eventId: 4625, srcIp: '203.0.113.50', action: 'failure' })])), 0, 'failure');
  assert.strictEqual(hit(feed([ev(t0, { ...base, eventId: 4672, srcIp: '203.0.113.50' })])), 0, 'other event id');
  assert.strictEqual(hit(feed([{ ...ev(t0, { ...base, eventId: 4624, srcIp: '203.0.113.50' }), source: 'firewall' }])), 0, 'other source');
});

test('external_logon: one 4624 from an unlisted internet IP raises exactly R012 with PB-EXTLOGON', () => {
  const types = new Set();
  for (let i = 0; i < 40; i++) {
    fresh();
    const evs = run('external_logon');
    assert.strictEqual(evs.length, 1);
    const [e] = evs;
    types.add(e.logonType);
    assert.ok(e.eventId === 4624 && e.srcIp.startsWith('203.0.113.') && !intel.lists.badIps.has(e.srcIp));
    assert.ok(C.servers.some(s => s.name === e.host) && C.users.some(u => u.name === e.user));
    assert.deepStrictEqual(ruleIds(), ['R012']);
    assert.strictEqual(store.state.alerts[0].playbook.id, 'PB-EXTLOGON');
    const a = gen.scenarios.external_logon.answer(evs);
    assert.deepStrictEqual([a.verdict, a.severities, a.case, a.rules], ['true_positive', ['high', 'critical'], 'required', ['R012']]);
    assert.ok(a.explain.includes(e.user) && a.explain.includes(e.srcIp) && a.clues.some(c => c.includes(e.srcIp)));
  }
  assert.deepStrictEqual([...types].sort((a, b) => a - b), [3, 10], 'both logon types occur');
});

test('the logon that succeeds in a takeover scenario now raises R012 as well', () => {
  const hasLogon = evs => evs.some(e => e.eventId === 4624);
  for (const key of ['brute_force', 'password_spray', 'phishing_link']) {
    const seen = new Set();
    for (let i = 0; i < 200 && seen.size < 2; i++) {
      fresh();
      const evs = run(key);
      const logon = evs.find(e => e.eventId === 4624);
      const a = gen.scenarios[key].answer(evs);
      seen.add(!!logon);
      const r12 = store.state.alerts.filter(x => x.ruleId === 'R012');
      if (logon) {
        assert.strictEqual(r12.length, 1, `${key}: one R012 alert`);
        assert.ok(r12[0].relatedEventIds.includes(logon.id));
        assert.ok(a.rules.includes('R012'), `${key}: the answer key lists R012`);
      } else {
        assert.strictEqual(r12.length, 0, `${key}: no logon, no R012`);
        assert.ok(!a.rules.includes('R012'));
      }
    }
    assert.strictEqual(seen.size, 2, `${key}: both variants occur`);
    assert.ok(hasLogon([{ eventId: 4624 }]));
  }
});

test('an exercise on external_logon: a true positive, rated critical and escalated, earns full marks', () => {
  const t0 = dayTs();
  const ex = startEx('external_logon', t0);
  const list = exercise.exerciseAlerts(ex);
  assert.deepStrictEqual(list.map(a => a.ruleId), ['R012']);
  alerts.update(list[0].id, { verdict: 'true_positive', severity: 'critical', status: 'Investigating', assignee: 'analyst1' }, t0 + 30e3);
  cases.escalate(list[0].id, null, t0 + 40e3);
  const r = exercise.submit(t0 + 60e3);
  for (const k of ['verdict', 'severity', 'escalation']) assert.strictEqual(crit(r, k).credit, 1, k);
});

// ---------- scoring fix ----------

function startEx(scenario, now) {
  exercise.start({ scenario, minutes: 15 }, now);
  engine.releaseDue(Infinity);
  exercise.tick(now);
  return store.state.exercise;
}
const crit = (card, key) => card.criteria.find(c => c.key === key);

test('doing nothing on a benign scenario earns no severity or escalation points', () => {
  const t0 = dayTs();
  startEx('user_typos', t0);
  assert.ok(exercise.exerciseAlerts(store.state.exercise).every(a => !a.ackTs));
  const card = exercise.submit(t0 + 60e3);
  for (const k of ['severity', 'escalation']) {
    assert.strictEqual(crit(card, k).credit, 0, k);
    assert.strictEqual(crit(card, k).points, 0, k);
    assert.match(crit(card, k).why, /acknowledged/);
  }
  assert.ok(card.score <= 20, `idle score ${card.score}`);
});

test('acknowledging the alert restores severity and escalation points on a benign scenario', () => {
  const t0 = dayTs();
  const ex = startEx('user_typos', t0);
  for (const a of exercise.exerciseAlerts(ex)) alerts.update(a.id, { status: 'Investigating', assignee: 'analyst1' }, t0 + 30e3);
  const card = exercise.submit(t0 + 60e3);
  assert.strictEqual(crit(card, 'severity').credit, 1);
  assert.strictEqual(crit(card, 'escalation').credit, 1);
});

test('escalating a true positive still counts as acknowledging it', () => {
  const t0 = dayTs();
  const ex = startEx('beacon_unlisted', t0);
  const card0 = exercise.score(ex);
  assert.strictEqual(crit(card0, 'escalation').credit, 0);
  const cases = require('../src/cases');
  const [a] = exercise.exerciseAlerts(ex);
  cases.escalate(a.id, null, t0 + 30e3);
  const card = exercise.submit(t0 + 60e3);
  assert.strictEqual(crit(card, 'escalation').credit, 1);
  assert.strictEqual(crit(card, 'severity').credit, 1);
});
