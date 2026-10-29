// Tests: the optional AI Triage Copilot, against a mocked Ollama (no real network).
const { test, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');
const os = require('os');
const path = require('path');
const fs = require('fs');

process.env.SOCSIM_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'socsim-ai-test-'));

const config = require('../src/config');
const store = require('../src/store');
const detection = require('../src/detection');
const engine = require('../src/engine');
const gen = require('../src/generator');
const playbooks = require('../src/playbooks');
const cases = require('../src/cases');
const copilot = require('../src/ai/copilot');

const defaults = { ...config.aiCopilot };
const GOOD = {
  summary: 'Many failed logons for one account from an outside address, then a success.',
  mitre: { tactic: 'Credential Access', techniqueId: 'T1110', assessment: 'confirms', note: 'Matches the rule.' },
  severity: { level: 'high', justification: 'A success followed the failures.' },
  nextSteps: ['Open the events in Log Search', 'Look up the source IP in IOC Lookup', 'Check related alerts for the same user'],
  draftNote: 'Brute force against the account, followed by a successful logon. Needs containment review.',
};

// A stand-in for Ollama's /api/chat. `calls` records every request so tests can inspect (or count) them.
let calls;
const reply = (content, { status = 200 } = {}) => async (url, opts) => {
  calls.push({ url, opts, body: JSON.parse(opts.body) });
  return { ok: status < 400, status, text: async () => String(content), json: async () => ({ message: { content } }) };
};
const use = fn => copilot.setFetch(fn);
const sentData = () => JSON.parse(calls[0].body.messages[1].content.match(/<data>\n([\s\S]*)\n<\/data>/)[1]);

// The brute_force scenario ends in a successful logon 40% of the time (chance(0.4) in the generator), and that logon
// also raises R012 for the same source IP. Pin the outcome so every run builds the same alerts: drop any random
// success, or add one when a test asks for it.
function alertId({ success = false } = {}) {
  const evs = gen.expand('brute_force', Date.now()).filter(e => e.eventId !== 4624);
  if (success) {
    const last = evs[evs.length - 1];
    evs.push({ ...last, ts: last.ts + 3000, eventId: 4624, action: 'success', message: 'An account was successfully logged on' });
  }
  evs.forEach(engine.ingest);
  return store.state.alerts.find(a => a.ruleId === 'R001').id;
}

beforeEach(() => {
  store.reset(); detection.loadRules(); playbooks.load();
  calls = [];
  Object.assign(config.aiCopilot, defaults, { enabled: true });
  use(reply(JSON.stringify(GOOD)));
});
afterEach(() => { store.state.exercise = null; Object.assign(config.aiCopilot, defaults); });

// ---- config ----

test('config.json ships with the copilot off and the documented defaults', () => {
  const raw = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'config.json'), 'utf8')).aiCopilot;
  assert.deepStrictEqual(raw, { enabled: false, ollamaUrl: 'http://127.0.0.1:11434', model: 'llama3.2', timeoutMs: 60000 });
  assert.strictEqual(defaults.enabled, false);
  assert.strictEqual(defaults.allowInExercises, false);
});

test('missing aiCopilot settings fall back to the defaults (off)', () => {
  assert.deepStrictEqual(config.parseAiCopilot(undefined), { enabled: false, ollamaUrl: 'http://127.0.0.1:11434',
    model: 'llama3.2', timeoutMs: 60000, allowInExercises: false });
});

test('only loopback Ollama addresses are accepted', () => {
  for (const url of ['http://127.0.0.1:11434', 'http://localhost:11434', 'http://[::1]:11434', 'http://127.0.0.2:9', 'http://127.1:11434']) {
    assert.doesNotThrow(() => config.parseAiCopilot({ ollamaUrl: url }), url);
  }
  assert.strictEqual(config.parseAiCopilot({ ollamaUrl: 'http://localhost:11434/' }).ollamaUrl, 'http://localhost:11434');
  for (const url of ['http://192.168.1.5:11434', 'http://10.0.0.2', 'http://0.0.0.0:11434', 'https://ollama.example.com',
    'http://localhost.evil.com:11434', 'http://127.0.0.1@evil.com', 'http://user:pw@localhost:11434',
    'ftp://127.0.0.1', 'file:///etc/passwd', 'not a url', 'http://[::]:11434']) {
    assert.throws(() => config.parseAiCopilot({ ollamaUrl: url }), /aiCopilot\.ollamaUrl/, url);
  }
});

test('the startup error names the setting and the address it refused', () => {
  assert.throws(() => config.parseAiCopilot({ ollamaUrl: 'http://203.0.113.7:11434' }),
    /must be a plain http\(s\) address on this machine[\s\S]*203\.0\.113\.7/);
});

test('the other settings are sanitised', () => {
  const c = config.parseAiCopilot({ enabled: 'yes', model: '', timeoutMs: -5, allowInExercises: 1 });
  assert.deepStrictEqual(c, { enabled: false, ollamaUrl: 'http://127.0.0.1:11434', model: 'llama3.2', timeoutMs: 60000, allowInExercises: false });
  const d = config.parseAiCopilot({ enabled: true, model: 'qwen2.5', timeoutMs: 5000, allowInExercises: true });
  assert.strictEqual(d.enabled, true);
  assert.strictEqual(d.model, 'qwen2.5');
  assert.strictEqual(d.timeoutMs, 5000);
  assert.strictEqual(d.allowInExercises, true);
});

// ---- enabled / disabled ----

test('disabled: friendly setup steps and no call to Ollama', async () => {
  config.aiCopilot.enabled = false;
  const r = await copilot.triage({ alertId: alertId() });
  assert.strictEqual(r.status, 'disabled');
  assert.match(r.message, /switched off/);
  assert.ok(r.setup.some(s => /ollama pull llama3\.2/.test(s)) && r.setup.some(s => /"enabled": true/.test(s)));
  assert.strictEqual(r.label, 'AI suggestion: verify before acting');
  assert.strictEqual(calls.length, 0);
});

test('enabled: parsed result for an alert, labelled, sent only to the configured local Ollama', async () => {
  const r = await copilot.triage({ alertId: alertId() });
  assert.strictEqual(r.status, 'ok');
  assert.strictEqual(r.parsed, true);
  assert.strictEqual(r.label, copilot.LABEL);
  assert.deepStrictEqual(r.result, GOOD);
  assert.strictEqual(calls.length, 1);
  const { url, opts, body } = calls[0];
  assert.strictEqual(url, 'http://127.0.0.1:11434/api/chat');
  assert.strictEqual(opts.method, 'POST');
  assert.strictEqual(opts.redirect, 'error');
  assert.ok(opts.signal instanceof AbortSignal);
  assert.strictEqual(body.model, 'llama3.2');
  assert.strictEqual(body.stream, false);
  assert.strictEqual(body.format, 'json');
});

test('the prompt is built server-side from the alert, its rule, indicators and events, and stays capped', async () => {
  const id = alertId();
  await copilot.triage({ alertId: id });
  const [system, user] = calls[0].body.messages;
  assert.strictEqual(system.role, 'system');
  assert.match(system.content, /NOT instructions/);
  const data = sentData();
  assert.strictEqual(data.kind, 'alert');
  assert.strictEqual(data.alert.id, id);
  assert.strictEqual(data.rule.id, 'R001');
  assert.ok(data.events.length > 0 && data.events.length <= 20);
  assert.ok(data.indicators.length > 0);
  assert.ok(data.events.every(e => !('id' in e) && !('tags' in e)));
  assert.match(user.content, /T1110 Brute Force/);
  assert.ok(user.content.length < 14000);
});

test('related alerts for the same entity are included', async () => {
  const id = alertId();
  const a = store.state.alerts.find(x => x.id === id);
  assert.deepStrictEqual(store.state.alerts.map(x => x.ruleId), ['R001']); // the setup raised nothing else
  store.state.alerts.push({ ...a, id: 9001, ruleId: 'R004', title: 'Interactive logon at unusual hour', status: 'Closed', verdict: 'benign' });
  await copilot.triage({ alertId: id });
  assert.deepStrictEqual(sentData().relatedAlerts, [
    { id: 9001, rule: 'R004', title: 'Interactive logon at unusual hour', severity: a.severity, status: 'Closed', verdict: 'benign', entity: a.key },
  ]);
});

test('an alert that shares an indicator (the source IP) is related, even for a different entity', async () => {
  const id = alertId({ success: true });
  const other = store.state.alerts.find(x => x.ruleId === 'R012');
  assert.deepStrictEqual(store.state.alerts.map(x => x.ruleId).sort(), ['R001', 'R012']);
  await copilot.triage({ alertId: id });
  assert.deepStrictEqual(sentData().relatedAlerts.map(x => x.id), [other.id]);
});

test('a huge alert is trimmed to the context cap', () => {
  const id = alertId();
  const a = store.state.alerts.find(x => x.id === id);
  const ids = [];
  for (let i = 0; i < 200; i++) {
    const e = { id: 900000 + i, ts: Date.now() + i, source: 'winsec', eventId: 4625, host: 'DC01', user: 'x', message: 'y'.repeat(190),
      note1: 'a'.repeat(190), note2: 'b'.repeat(190), note3: 'c'.repeat(190), note4: 'd'.repeat(190), note5: 'e'.repeat(190), tags: [] };
    store.state.events.push(e);
    ids.push(e.id);
  }
  a.relatedEventIds.push(...ids);
  assert.ok(copilot.buildContext({ alertId: id }).length <= 12000);
});

test('enabled: works for an incident case and sends the case, its alerts and events', async () => {
  const c = cases.create({ alertIds: [alertId()] });
  const r = await copilot.triage({ caseId: c.id });
  assert.strictEqual(r.parsed, true);
  const data = sentData();
  assert.strictEqual(data.kind, 'case');
  assert.strictEqual(data.case.id, c.id);
  assert.strictEqual(data.alerts.length, 1);
  assert.ok(data.events.length > 0);
});

test('the configured model and address are used', async () => {
  Object.assign(config.aiCopilot, { model: 'qwen2.5', ollamaUrl: 'http://localhost:9999' });
  await copilot.triage({ alertId: alertId() });
  assert.strictEqual(calls[0].url, 'http://localhost:9999/api/chat');
  assert.strictEqual(calls[0].body.model, 'qwen2.5');
});

test('nothing is saved: the alert and the store are untouched after a triage', async () => {
  const id = alertId();
  const before = JSON.stringify(store.state.alerts);
  await copilot.triage({ alertId: id });
  assert.strictEqual(JSON.stringify(store.state.alerts), before);
});

// ---- bad requests ----

test('rejects a missing, doubled or unknown id', async () => {
  const id = alertId();
  await assert.rejects(copilot.triage({}), { status: 400 });
  await assert.rejects(copilot.triage({ alertId: id, caseId: 1 }), { status: 400 });
  await assert.rejects(copilot.triage({ alertId: 'abc' }), { status: 400 });
  await assert.rejects(copilot.triage({ alertId: 99999 }), { status: 404, message: 'Alert not found' });
  await assert.rejects(copilot.triage({ caseId: 99999 }), { status: 404, message: 'Case not found' });
  assert.strictEqual(calls.length, 0);
});

// ---- Ollama problems ----

test('Ollama not running: a friendly message with the setup steps', async () => {
  use(async () => { throw Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNREFUSED' } }); });
  const r = await copilot.triage({ alertId: alertId() });
  assert.strictEqual(r.status, 'unavailable');
  assert.match(r.message, /Could not reach Ollama at http:\/\/127\.0\.0\.1:11434/);
  assert.strictEqual(r.setup.length, 3);
});

test('model not pulled (404) tells the analyst which model to pull', async () => {
  use(reply('model "llama3.2" not found', { status: 404 }));
  const r = await copilot.triage({ alertId: alertId() });
  assert.strictEqual(r.status, 'unavailable');
  assert.match(r.message, /ollama pull llama3\.2/);
});

test('an Ollama error status is reported as unavailable', async () => {
  use(reply('boom', { status: 500 }));
  const r = await copilot.triage({ alertId: alertId() });
  assert.strictEqual(r.status, 'unavailable');
  assert.match(r.message, /500/);
});

test('a timeout is reported', async () => {
  config.aiCopilot.timeoutMs = 25;
  // AbortSignal.timeout() does not keep the event loop alive, and on Node 22 nothing else does here, so hold it open.
  const keepAlive = setTimeout(() => {}, 5000);
  use((url, opts) => new Promise((resolve, reject) => opts.signal.addEventListener('abort', () => reject(opts.signal.reason))));
  let r;
  try { r = await copilot.triage({ alertId: alertId() }); } finally { clearTimeout(keepAlive); }
  assert.strictEqual(r.status, 'timeout');
  assert.match(r.message, /did not answer within/);
  assert.match(r.message, /timeoutMs/);
});

// ---- replies ----

test('invalid JSON falls back to the raw text', async () => {
  use(reply('I think this is a brute force attack.'));
  const r = await copilot.triage({ alertId: alertId() });
  assert.strictEqual(r.status, 'ok');
  assert.strictEqual(r.parsed, false);
  assert.strictEqual(r.raw, 'I think this is a brute force attack.');
  assert.strictEqual(r.label, copilot.LABEL);
});

test('raw text is capped', async () => {
  use(reply('z'.repeat(20000)));
  const r = await copilot.triage({ alertId: alertId() });
  assert.ok(r.raw.length < 8100);
});

test('JSON that does not fit the shape falls back to raw text', () => {
  const bad = [
    {}, [], 'text', { ...GOOD, summary: '' }, { ...GOOD, draftNote: 5 }, { ...GOOD, mitre: null },
    { ...GOOD, mitre: { ...GOOD.mitre, techniqueId: 'banana' } }, { ...GOOD, mitre: { ...GOOD.mitre, tactic: '' } },
    { ...GOOD, severity: { level: 'urgent', justification: 'x' } }, { ...GOOD, severity: { level: 'high' } },
    { ...GOOD, nextSteps: ['one', 'two'] }, { ...GOOD, nextSteps: 'do things' },
  ];
  for (const b of bad) assert.strictEqual(copilot.parseReply(JSON.stringify(b)), null, JSON.stringify(b).slice(0, 60));
  assert.strictEqual(copilot.parseReply(''), null);
  assert.strictEqual(copilot.parseReply(undefined), null);
  assert.strictEqual(copilot.parseReply('{ broken'), null);
  assert.strictEqual(copilot.parseReply('null'), null);
});

test('replies wrapped in code fences or chatter are still parsed, and the result is normalised', () => {
  const fenced = '```json\n' + JSON.stringify(GOOD) + '\n```';
  assert.deepStrictEqual(copilot.parseReply(fenced), GOOD);
  assert.deepStrictEqual(copilot.parseReply('Sure! Here you go: ' + JSON.stringify(GOOD) + ' Hope it helps.'), GOOD);
  const loose = { ...GOOD, mitre: { tactic: ' Credential Access ', techniqueId: 't1110.003', assessment: 'REFINES' },
    severity: { level: 'HIGH', justification: ' ok ' }, nextSteps: [...GOOD.nextSteps, 'four', 'five', 'six', 7] };
  const p = copilot.parseReply(JSON.stringify(loose));
  assert.strictEqual(p.mitre.techniqueId, 'T1110.003');
  assert.strictEqual(p.mitre.assessment, 'refines');
  assert.strictEqual(p.mitre.tactic, 'Credential Access');
  assert.strictEqual(p.severity.level, 'high');
  assert.strictEqual(p.nextSteps.length, 5);
});

// ---- scored exercises ----

test('locked out while a scored exercise is running', async () => {
  const id = alertId();
  store.state.exercise = { id: 1 };
  assert.strictEqual(copilot.availability().lockedByExercise, true);
  await assert.rejects(copilot.triage({ alertId: id }), { status: 403, message: /switched off during scored exercises/ });
  assert.strictEqual(calls.length, 0);
});

test('the lockout applies even while the copilot is disabled, and allowInExercises lifts it', async () => {
  const id = alertId();
  store.state.exercise = { id: 1 };
  config.aiCopilot.enabled = false;
  await assert.rejects(copilot.triage({ alertId: id }), { status: 403 });
  config.aiCopilot.allowInExercises = true;
  assert.strictEqual(copilot.availability().lockedByExercise, false);
  config.aiCopilot.enabled = true;
  assert.strictEqual((await copilot.triage({ alertId: id })).status, 'ok');
});

// ---- guard: no IOC lookups for internal addresses or the alert's own host ----

test('isInternalIp: private, loopback, link-local, 0.x and the company network are internal; the internet ranges are not', () => {
  for (const ip of ['10.0.0.1', '172.16.0.1', '172.31.255.254', '192.168.1.1', '127.0.0.1', '169.254.10.10', '0.0.0.0', '192.0.2.127'])
    assert.strictEqual(copilot.isInternalIp(ip), true, ip);
  for (const ip of ['203.0.113.77', '198.51.100.20', '8.8.8.8', '172.15.0.1', '172.32.0.1', '192.0.3.1', '300.1.1.1', 'not an ip', '1.2.3'])
    assert.strictEqual(copilot.isInternalIp(ip), false, ip);
});

test('guard: drops an IOC lookup that only names internal addresses', () => {
  const steps = ['Log Search: failed logons for the user', 'IOC Lookup: check if 192.0.2.127 is on any threat intelligence list',
    'Run an IOC lookup on 10.1.2.3 and 192.168.0.9', 'Review the related alerts'];
  assert.deepStrictEqual(copilot.guardNextSteps(steps), ['Log Search: failed logons for the user', 'Review the related alerts',
    'Log Search: other events for the same host and user around the time of the alert']);
});

test('guard: keeps external lookups, steps that name no address, and non-IOC steps that mention internal addresses', () => {
  const steps = ['IOC Lookup: 203.0.113.77', 'Look up the source IP in IOC Lookup', 'Log Search: everything from 192.0.2.127',
    'Check 198.51.100.20 against the threat intel list'];
  assert.deepStrictEqual(copilot.guardNextSteps(steps), steps);
});

test('guard: a step that mixes internal and external indicators is rewritten to the external ones', () => {
  const hash = '0'.repeat(48) + 'fa4e000000000001';
  const steps = ['IOC Lookup: 192.0.2.124 and 203.0.113.229', `Check ${hash} and trade-show-updates.example in threat intel from 192.0.2.119`,
    'Review the related alerts', 'Open the playbook'];
  assert.deepStrictEqual(copilot.guardNextSteps(steps), ['IOC Lookup: 203.0.113.229', `IOC Lookup: trade-show-updates.example, ${hash}`,
    'Review the related alerts', 'Open the playbook']);
});

test('guard: an IOC lookup for the alert\'s own host or localhost is removed, but another host is fine', () => {
  const hosts = new Set(['ws-024']);
  const steps = ['IOC Lookup: WS-024', 'Threat intel check for ws-024.', 'IOC lookup for localhost', 'IOC Lookup: WS-0245 history', 'Open Log Search',
    'Check related alerts'];
  assert.deepStrictEqual(copilot.guardNextSteps(steps, hosts), ['IOC Lookup: WS-0245 history', 'Open Log Search', 'Check related alerts']);
});

test('guard: always leaves 3 to 5 steps', () => {
  assert.strictEqual(copilot.guardNextSteps(['IOC Lookup: 192.0.2.1', 'IOC Lookup: 10.0.0.1', 'IOC Lookup: 127.0.0.1']).length, 3);
  assert.strictEqual(copilot.guardNextSteps(Array.from({ length: 5 }, (_, i) => `Step ${i}`)).length, 5);
  assert.strictEqual(copilot.guardNextSteps(Array.from({ length: 8 }, (_, i) => `Step ${i}`)).length, 5);
});

test('triage applies the guard: no IOC lookup for the alert\'s own host or internal addresses', async () => {
  const id = alertId();
  const a = store.state.alerts.find(x => x.id === id);
  const host = store.state.events.find(e => a.relatedEventIds.includes(e.id)).host;
  assert.ok(host);
  use(reply(JSON.stringify({ ...GOOD, nextSteps: [`IOC Lookup: ${host}`, 'Check if 192.0.2.127 is on any threat intelligence list',
    'Look up 203.0.113.77 in IOC Lookup', 'Check related alerts', 'Open Log Search for the user'] })));
  const r = await copilot.triage({ alertId: id });
  assert.deepStrictEqual(r.result.nextSteps, ['Look up 203.0.113.77 in IOC Lookup', 'Check related alerts', 'Open Log Search for the user']);
});
