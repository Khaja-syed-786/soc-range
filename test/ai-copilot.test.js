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
const mitre = require('../src/mitre');
const ioc = require('../src/ioc');
const intel = require('../src/intel');
const engine = require('../src/engine');
const gen = require('../src/generator');
const playbooks = require('../src/playbooks');
const cases = require('../src/cases');
const copilot = require('../src/ai/copilot');

const defaults = { ...config.aiCopilot };
// What the model sends back (the shape REPLY_SCHEMA asks for), and what parseReply turns it into
const GOOD = {
  summary: 'Many failed logons for one account from an outside address, then a success.',
  mitre: { tactic: 'Credential Access', techniqueId: 'T1110', techniqueName: 'Brute Force' },
  severity: 'high',
  severityReason: 'A success followed the failures.',
  nextSteps: ['Open the events in Log Search', 'Look up the source IP in IOC Lookup', 'Check related alerts for the same user'],
  draftNote: 'Brute force against the account, followed by a successful logon. Needs containment review.',
};
const parsed = (assessment = 'none', tacticSource = 'ATT&CK map') => ({
  summary: GOOD.summary,
  mitre: { tactic: 'Credential Access', techniqueId: 'T1110', name: 'Brute Force', assessment, source: 'model', tacticSource },
  severity: { level: 'high', justification: GOOD.severityReason },
  nextSteps: GOOD.nextSteps,
  draftNote: GOOD.draftNote,
});

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
  assert.deepStrictEqual(r.result, parsed('confirms', 'detection rule')); // the brute force rule is tagged T1110
  assert.strictEqual(calls.length, 1);
  const { url, opts, body } = calls[0];
  assert.strictEqual(url, 'http://127.0.0.1:11434/api/chat');
  assert.strictEqual(opts.method, 'POST');
  assert.strictEqual(opts.redirect, 'error');
  assert.ok(opts.signal instanceof AbortSignal);
  assert.strictEqual(body.model, 'llama3.2');
  assert.strictEqual(body.stream, false);
  assert.deepStrictEqual(body.format, copilot.REPLY_SCHEMA);
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
    { ...GOOD, mitre: { ...GOOD.mitre, techniqueId: 'banana' } }, { ...GOOD, mitre: { ...GOOD.mitre, techniqueId: 'T1190', tactic: '' } },
    { ...GOOD, severity: 'urgent' }, { ...GOOD, severityReason: '' }, { ...GOOD, severity: undefined },
    { ...GOOD, severity: { level: 'urgent', justification: 'x' } }, { ...GOOD, severity: { level: 'high' }, severityReason: undefined },
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
  assert.deepStrictEqual(copilot.parseReply(fenced), parsed());
  assert.deepStrictEqual(copilot.parseReply('Sure! Here you go: ' + JSON.stringify(GOOD) + ' Hope it helps.'), parsed());
  const loose = { ...GOOD, mitre: { tactic: ' credential access ', techniqueId: 't1110.003', techniqueName: ' Password Spraying ' },
    severity: 'HIGH', severityReason: ' ok ', nextSteps: [...GOOD.nextSteps, 'four', 'five', 'six', 7] };
  const p = copilot.parseReply(JSON.stringify(loose));
  assert.strictEqual(p.mitre.techniqueId, 'T1110.003');
  assert.strictEqual(p.mitre.name, 'Password Spraying');
  assert.strictEqual(p.mitre.tactic, 'Credential Access');
  assert.strictEqual(p.severity.level, 'high');
  assert.strictEqual(p.severity.justification, 'ok');
  assert.strictEqual(p.nextSteps.length, 5);
});

test('an older reply with a severity object is still accepted', () => {
  const old = { ...GOOD, severity: { level: 'critical', justification: 'Old shape.' }, severityReason: undefined };
  assert.deepStrictEqual(copilot.parseReply(JSON.stringify(old)).severity, { level: 'critical', justification: 'Old shape.' });
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
  assert.strictEqual(copilot.guardNextSteps(Array.from({ length: 5 }, (_, i) => `Check item number ${i}`)).length, 5);
  assert.strictEqual(copilot.guardNextSteps(Array.from({ length: 8 }, (_, i) => `Check item number ${i}`)).length, 5);
});

// ---- junk next steps ----

const FIRST_FALLBACK = 'Log Search: other events for the same host and user around the time of the alert';

test('isJunkStep: empty, very short and template-placeholder steps are junk; real steps are not', () => {
  for (const s of ['', '   ', 'abc', 'Log it', 'Open it', '%draftNote', ' %step', 'Check %draftNote now', '{{next_step}}', 'Do {{this}} first',
    '<placeholder>', 'Look at <step> on the host', null, undefined, 5, {}])
    assert.strictEqual(copilot.isJunkStep(s), true, String(s));
  for (const s of ['Open Log Search', 'Review related alerts', 'Check domainAgeDays < 30 for the domain', '50% of the hosts are affected',
    'Check whether 5 > 3 holds', 'IOC Lookup: 203.0.113.77'])
    assert.strictEqual(copilot.isJunkStep(s), false, s);
});

test('guard: junk steps and duplicates are dropped, and the list is topped up with the existing fallback', () => {
  const steps = ['Open Log Search for the user', 'open  log search for the user.', '%draftNote', '', 'x', '{{next}}', '<step>', 'Check related alerts'];
  assert.deepStrictEqual(copilot.guardNextSteps(steps), ['Open Log Search for the user', 'Check related alerts', FIRST_FALLBACK]);
});

test('guard: nothing usable left means three fallback steps, and a fallback is never added twice', () => {
  const none = copilot.guardNextSteps(['%a', '', 'no', '{{b}}']);
  assert.strictEqual(none.length, 3);
  assert.strictEqual(new Set(none.map(s => s.toLowerCase())).size, 3);
  assert.strictEqual(none[0], FIRST_FALLBACK);
  const withOne = copilot.guardNextSteps([FIRST_FALLBACK, '%x']);
  assert.strictEqual(withOne.length, 3);
  assert.strictEqual(new Set(withOne).size, 3);
  assert.strictEqual(withOne[0], FIRST_FALLBACK);
});

test('guard: steps that become identical after an IOC rewrite are collapsed', () => {
  const steps = ['IOC Lookup: 192.0.2.1 and 203.0.113.5', 'IOC lookup: 10.0.0.1 and 203.0.113.5', 'Check related alerts', 'Open the playbook'];
  assert.deepStrictEqual(copilot.guardNextSteps(steps), ['IOC Lookup: 203.0.113.5', 'Check related alerts', 'Open the playbook']);
});

test('triage drops junk and duplicate steps from the model\'s reply', async () => {
  use(reply(JSON.stringify({ ...GOOD, nextSteps: ['Open Log Search for the user', '%draftNote', 'Check related alerts', 'check related alerts',
    'Look up 203.0.113.77 in IOC Lookup'] })));
  const r = await copilot.triage({ alertId: alertId() });
  assert.strictEqual(r.parsed, true);
  assert.deepStrictEqual(r.result.nextSteps, ['Open Log Search for the user', 'Check related alerts', 'Look up 203.0.113.77 in IOC Lookup']);
});

test('triage tops up to three steps when the model gave mostly junk', async () => {
  use(reply(JSON.stringify({ ...GOOD, nextSteps: ['Open Log Search for the user', '%draftNote', '{{step}}'] })));
  const r = await copilot.triage({ alertId: alertId() });
  assert.strictEqual(r.result.nextSteps.length, 3);
  assert.deepStrictEqual(r.result.nextSteps.slice(0, 2), ['Open Log Search for the user', FIRST_FALLBACK]);
});

// ---- the model's text is untrusted: nothing may backtrack on it (CodeQL js/polynomial-redos) ----

const within = (ms, fn) => {
  const t0 = Date.now();
  const out = fn();
  const took = Date.now() - t0;
  assert.ok(took < ms, `took ${took} ms`);
  return out;
};
const HUGE = 300000;

test('stripFences removes a code fence and nothing else', () => {
  assert.strictEqual(copilot.stripFences('```json\n{"a":1}\n```'), '{"a":1}');
  assert.strictEqual(copilot.stripFences('```\n{"a":1}\n```'), '{"a":1}');
  assert.strictEqual(copilot.stripFences('  ```json {"a":1}```  '), '{"a":1}');
  assert.strictEqual(copilot.stripFences('  {"a":1}  \n'), '{"a":1}');
  assert.strictEqual(copilot.stripFences('```'), '');
  assert.strictEqual(copilot.stripFences('```json'), '');
  assert.strictEqual(copilot.stripFences('text ``` more'), 'text ``` more');
  assert.strictEqual(copilot.stripFences('```JSON\n{}\n```'), 'JSON\n{}'); // only a lower-case "json" is a language tag
  assert.strictEqual(copilot.stripFences(null), '');
  assert.strictEqual(copilot.stripFences(undefined), '');
});

test('jsonSpan runs from the first { to the last }', () => {
  assert.strictEqual(copilot.jsonSpan('Sure! {"a":{"b":1}} Hope it helps'), '{"a":{"b":1}}');
  assert.strictEqual(copilot.jsonSpan('{{a}}'), '{{a}}');
  for (const t of ['no braces', '', '} {', '{', '}', '}{']) assert.strictEqual(copilot.jsonSpan(t), null, t);
});

test('stepKey ignores case, spacing and trailing punctuation only', () => {
  assert.strictEqual(copilot.stepKey('  Check   Related ALERTS. '), 'check related alerts');
  assert.strictEqual(copilot.stepKey('Check alerts ; , !'), 'check alerts');
  assert.strictEqual(copilot.stepKey('a.b.c'), 'a.b.c');
  assert.strictEqual(copilot.stepKey('...'), '');
});

test('huge replies are handled in linear time', () => {
  const ws = ' '.repeat(HUGE);
  for (const text of [ws + 'x', '```' + ws, ws + '```', '```json' + ws + '```', '{'.repeat(HUGE), '{'.repeat(HUGE) + '}'.repeat(10),
    '}'.repeat(HUGE), '`'.repeat(HUGE), 'a'.repeat(HUGE), '\n'.repeat(HUGE)])
    assert.strictEqual(within(2000, () => copilot.parseReply(text)), null, text.slice(0, 12));
  // a valid reply inside a fence with a lot of whitespace around it still parses
  const big = within(2000, () => copilot.parseReply('```json' + ws + JSON.stringify(GOOD) + ws + '```'));
  assert.strictEqual(big.summary, GOOD.summary);
  assert.strictEqual(within(2000, () => copilot.stripFences(ws + '```json' + ws + '{}' + ws + '```' + ws)), '{}');
});

test('huge steps and claims are handled in linear time', () => {
  const punct = '. ; , ! '.repeat(HUGE / 8);
  const first = 'Check the related alerts' + punct, open = '<' + 'a'.repeat(HUGE), braces = '{{'.repeat(HUGE / 2);
  const steps = within(2000, () => copilot.guardNextSteps([first, 'check the related alerts', 'Open the playbook', open, braces, '%' + 'x'.repeat(HUGE)]));
  // the repeat is dropped, the % one is a placeholder; an unclosed < or {{ is just text, however long
  assert.deepStrictEqual(steps, [first, 'Open the playbook', open, braces]);
  const hit = [{ type: 'ip', value: '203.0.113.66', note: '' }];
  const found = within(2000, () => copilot.findContradictions({ summary: 'ok. '.repeat(HUGE / 4) + 'This is a false positive' }, hit));
  assert.deepStrictEqual(found, [{ field: 'summary', claim: 'false positive' }]);
  within(2000, () => copilot.findContradictions({ summary: 'a.'.repeat(HUGE / 2), draftNote: '1.2.3.4 '.repeat(HUGE / 8) }, hit));
});

// ---- verified intel facts ----
// Scenarios whose alerts have an indicator that is on the simulator's intel list (c2_beacon: an IP and a domain; cred_dump: a hash),
// and ones that do not (backup_agent_edr, user_typos).

function alertFor(scenario, ruleId) {
  gen.expand(scenario, Date.now()).forEach(engine.ingest);
  const a = store.state.alerts.find(x => x.ruleId === ruleId);
  assert.ok(a, `${scenario} -> ${ruleId}`);
  return a;
}
const eventOf = a => store.state.events.find(e => e.id === a.relatedEventIds[0]);
const factFor = value => `Verified: ${value} is on the threat-intel list (${ioc.lookup(value).intel.note})`;
const answer = over => use(reply(JSON.stringify({ ...GOOD, ...over })));

test('verified facts: an IP on the intel list is stated with the list\'s own note', async () => {
  const a = alertFor('c2_beacon', 'R005');
  const ip = eventOf(a).dstIp;
  const r = await copilot.triage({ alertId: a.id });
  assert.deepStrictEqual(r.verified.facts, [factFor(ip)]);
  assert.match(r.verified.facts[0], /^Verified: 203\.0\.113\.\d+ is on the threat-intel list \(.+\)$/);
  assert.deepStrictEqual(r.verified.intel, [{ type: 'ip', value: ip, note: ioc.lookup(ip).intel.note }]);
  assert.strictEqual(r.verified.warning, null);
  assert.deepStrictEqual(r.verified.contradictions, []);
});

test('verified facts: a domain and a hash on the intel list are found too', async () => {
  const d = alertFor('c2_beacon', 'R006');
  const domain = eventOf(d).domain;
  assert.ok(domain.endsWith('.example'));
  assert.deepStrictEqual((await copilot.triage({ alertId: d.id })).verified.facts, [factFor(domain)]);
  // cred_dump uses a listed hash only 70% of the time, so pin one that is on the list
  gen.expand('cred_dump', Date.now()).map(e => ({ ...e, fileHash: intel.badHashes[0].value })).forEach(engine.ingest);
  const h = store.state.alerts.find(a => a.ruleId === 'R007');
  assert.ok(h);
  const hash = eventOf(h).fileHash;
  assert.strictEqual(hash, intel.badHashes[0].value);
  const r = await copilot.triage({ alertId: h.id });
  assert.deepStrictEqual(r.verified.facts, [factFor(hash)]);
  assert.strictEqual(r.verified.intel[0].type, 'hash');
});

test('verified facts: the AI is not asked, and the lookup is read-only', async () => {
  const a = alertFor('c2_beacon', 'R005');
  const before = JSON.stringify(store.state.alerts);
  use(reply(JSON.stringify(GOOD)));
  await copilot.triage({ alertId: a.id });
  assert.strictEqual(JSON.stringify(store.state.alerts), before);
  assert.ok(!calls[0].body.messages.some(m => m.content.includes('Verified:')));
});

test('an indicator on the intel list raises severity to at least high', async () => {
  const a = alertFor('c2_beacon', 'R005');
  for (const level of ['low', 'medium']) {
    answer({ severity: level });
    const r = await copilot.triage({ alertId: a.id });
    assert.deepStrictEqual([r.result.severity.level, r.result.severity.raisedFrom], ['high', level], level);
    assert.strictEqual(r.result.severity.justification, GOOD.severityReason); // the AI's own reason is kept
  }
  answer({ severity: 'high' });
  assert.deepStrictEqual((await copilot.triage({ alertId: a.id })).result.severity, { level: 'high', justification: GOOD.severityReason });
  answer({ severity: 'critical' });
  assert.deepStrictEqual((await copilot.triage({ alertId: a.id })).result.severity, { level: 'critical', justification: GOOD.severityReason });
});

test('no indicator on the intel list: no facts, no warning, severity untouched, even if the AI says false positive', async () => {
  for (const [scenario, rule] of [['backup_agent_edr', 'R007'], ['user_typos', 'R001']]) {
    store.reset(); detection.loadRules(); playbooks.load();
    const a = alertFor(scenario, rule);
    answer({ severity: 'low', summary: 'This is a false positive.', draftNote: 'The hash is not on any threat intel list, so a false positive.' });
    const r = await copilot.triage({ alertId: a.id });
    assert.deepStrictEqual(r.verified, { facts: [], intel: [], warning: null, contradictions: [] }, scenario);
    assert.deepStrictEqual(r.result.severity, { level: 'low', justification: GOOD.severityReason }, scenario);
  }
});

test('the AI saying false positive, or not on the list, is flagged when an indicator IS on the list', async () => {
  const a = alertFor('c2_beacon', 'R005');
  const W = copilot.CONTRADICTION_WARNING;
  assert.strictEqual(W, 'AI claim contradicts verified intel. Trust the verified facts.');
  answer({ summary: 'This is likely a false positive.' });
  let r = await copilot.triage({ alertId: a.id });
  assert.strictEqual(r.verified.warning, W);
  assert.deepStrictEqual(r.verified.contradictions, [{ field: 'summary', claim: 'false positive' }]);
  assert.strictEqual(r.verified.facts.length, 1);
  answer({ severityReason: 'The IP address is not on the threat-intel list.' });
  r = await copilot.triage({ alertId: a.id });
  assert.deepStrictEqual(r.verified.contradictions, [{ field: 'severityReason', claim: 'not on the intel list' }]);
  answer({ draftNote: 'Not listed in any intel feed. Probably a false-positive.' });
  r = await copilot.triage({ alertId: a.id });
  assert.deepStrictEqual(r.verified.contradictions, [{ field: 'draftNote', claim: 'not on the intel list' }, { field: 'draftNote', claim: 'false positive' }]);
  answer({});
  r = await copilot.triage({ alertId: a.id });
  assert.strictEqual(r.verified.warning, null); // a reply that agrees with the intel list gets no warning
});

test('findContradictions: what counts and what does not', () => {
  const hit = [{ type: 'ip', value: '203.0.113.66', note: 'x' }];
  const flagged = text => copilot.findContradictions({ f: text }, hit).map(c => c.claim);
  for (const t of ['This is a false positive.', 'Likely a False-Positive', 'The IP is not on the threat-intel list.', 'Not on any threat intel list',
    'It is not listed in the intel feed', 'The address is on no intel list.', 'The IP 203.0.113.66 is not on the threat-intel list.',
    'The domain is not in the intel list'])
    assert.ok(flagged(t).length > 0, t);
  for (const t of ['It is unlikely to be a false positive.', 'This is not a false positive.', 'A false positive is ruled out.', 'We can rule out a false positive.',
    'The IP is on the threat-intel list.', 'The IP 203.0.113.229 is not on any threat intel list.', 'No additional intel is needed.',
    'There is no further intel on the source.', 'Nothing here is not on the radar.', '', 'a'.repeat(50)])
    assert.deepStrictEqual(flagged(t), [], t);
  assert.deepStrictEqual(copilot.findContradictions({ f: 'This is a false positive.' }, []), []); // nothing on the list, nothing to contradict
  // a sentence naming an off-list indicator is not about the listed one, but one that names the listed one is
  assert.deepStrictEqual(flagged('203.0.113.229 is not on the intel list. 203.0.113.66 is not on the intel list.'), ['not on the intel list']);
  assert.deepStrictEqual(flagged('The IP 203.0.113.66 was seen. It is not on the threat-intel list.'), ['not on the intel list']);
});

test('an unparsed reply still gets the verified facts, and its raw text is checked', async () => {
  const a = alertFor('c2_beacon', 'R005');
  use(reply('Probably a false positive, nothing to see here.'));
  const r = await copilot.triage({ alertId: a.id });
  assert.strictEqual(r.parsed, false);
  assert.strictEqual(r.verified.facts.length, 1);
  assert.strictEqual(r.verified.warning, copilot.CONTRADICTION_WARNING);
  assert.deepStrictEqual(r.verified.contradictions, [{ field: 'raw', claim: 'false positive' }]);
});

test('for a case, every alert\'s indicators are checked and severity is raised', async () => {
  const bad = alertFor('c2_beacon', 'R005');
  const quiet = alertFor('user_typos', 'R001');
  const c = cases.create({ alertIds: [quiet.id, bad.id] });
  answer({ severity: 'low' });
  const r = await copilot.triage({ caseId: c.id });
  assert.deepStrictEqual(r.verified.facts, [factFor(eventOf(bad).dstIp)]);
  assert.deepStrictEqual([r.result.severity.level, r.result.severity.raisedFrom], ['high', 'low']);
});

test('triage answers that are not an AI result carry no verified facts', async () => {
  config.aiCopilot.enabled = false;
  assert.strictEqual((await copilot.triage({ alertId: alertFor('c2_beacon', 'R005').id })).verified, undefined);
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

// ---- structured outputs: the schema sent to Ollama ----

test('the reply schema is sent as "format" with streaming off, and matches the shape we parse', async () => {
  await copilot.triage({ alertId: alertId() });
  const { body } = calls[0];
  assert.strictEqual(body.stream, false);
  const s = body.format;
  assert.strictEqual(typeof s, 'object');
  assert.deepStrictEqual(s, copilot.REPLY_SCHEMA);
  assert.strictEqual(s.type, 'object');
  assert.deepStrictEqual(s.required, ['summary', 'mitre', 'severity', 'severityReason', 'nextSteps', 'draftNote']);
  assert.deepStrictEqual(Object.keys(s.properties), s.required);
  assert.strictEqual(s.properties.summary.type, 'string');
  assert.strictEqual(s.properties.severityReason.type, 'string');
  assert.strictEqual(s.properties.draftNote.type, 'string');
  assert.deepStrictEqual(s.properties.severity, { type: 'string', enum: ['low', 'medium', 'high', 'critical'] });
  assert.deepStrictEqual(s.properties.nextSteps, { type: 'array', items: { type: 'string' }, minItems: 3, maxItems: 5 });
  assert.deepStrictEqual(s.properties.mitre.required, ['tactic', 'techniqueId', 'techniqueName']);
  assert.deepStrictEqual(Object.keys(s.properties.mitre.properties), ['tactic', 'techniqueId', 'techniqueName']);
  // the model can only pick one of the 14 ATT&CK Enterprise tactics
  assert.deepStrictEqual(s.properties.mitre.properties.tactic, { type: 'string', enum: copilot.ATTACK_TACTICS });
  assert.deepStrictEqual(s.properties.mitre.properties.tactic.enum, ['Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
    'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection',
    'Command and Control', 'Exfiltration', 'Impact']);
});

test('a reply that follows the schema parses, so the schema and parseReply agree', () => {
  const sample = { summary: 's', mitre: { tactic: 'Execution', techniqueId: 'T1059', techniqueName: 'x' }, severity: 'low',
    severityReason: 'r', nextSteps: ['a', 'b', 'c'], draftNote: 'n' };
  assert.deepStrictEqual(Object.keys(sample), copilot.REPLY_SCHEMA.required);
  assert.ok(copilot.parseReply(JSON.stringify(sample)));
});

test('the prompt asks for the same keys and lists the 14 ATT&CK tactics', async () => {
  await copilot.triage({ alertId: alertId() });
  const system = calls[0].body.messages[0].content;
  assert.strictEqual(copilot.ATTACK_TACTICS.length, 14);
  for (const t of copilot.ATTACK_TACTICS) assert.ok(system.includes(t), t);
  for (const k of ['techniqueName', 'severityReason', 'nextSteps', 'draftNote']) assert.ok(system.includes(k), k);
  assert.ok(!system.includes('justification'));
});

// ---- MITRE validation and the fallback to the rule's own mapping ----

const withMitre = mitre => JSON.stringify({ ...GOOD, mitre });
const FROM_RULE_T1110 = { tactic: 'Credential Access', techniqueId: 'T1110', name: 'Brute Force', assessment: 'rule', source: 'detection rule',
  tacticSource: 'detection rule' };
const mitreOf = (m, rule) => copilot.parseReply(withMitre(m), rule)?.mitre;

test("a valid technique ID is kept and judged against the rule's mapping", () => {
  const m = (techniqueId, tactic = 'Credential Access') => mitreOf({ tactic, techniqueId, techniqueName: 'N' }, 'T1110');
  assert.deepStrictEqual(m('T1110'), { tactic: 'Credential Access', techniqueId: 'T1110', name: 'N', assessment: 'confirms', source: 'model',
    tacticSource: 'detection rule' });
  assert.strictEqual(m('T1110.003').assessment, 'refines');    // a sub-technique of the rule's technique
  assert.strictEqual(m('T1003').assessment, 'differs');        // a different technique
  assert.strictEqual(m('t1003', ' impact ').techniqueId, 'T1003'); // case and spaces are normalised
  assert.strictEqual(m(' t1003 ', ' impact ').source, 'model');
  assert.strictEqual(copilot.parseReply(withMitre(GOOD.mitre)).mitre.assessment, 'none'); // no rule mapping to compare with
});

test("the model's tactic is not trusted: a technique that is the rule's (or shares its parent) gets the rule's tactic", () => {
  const wrong = 'Reconnaissance';
  const from = (techniqueId, rule) => mitreOf({ tactic: wrong, techniqueId, techniqueName: 'x' }, rule);
  assert.deepStrictEqual([from('T1110', 'T1110').tactic, from('T1110', 'T1110').tacticSource], ['Credential Access', 'detection rule']);
  assert.deepStrictEqual([from('T1566.001', 'T1566').tactic, from('T1566.001', 'T1566').tacticSource], ['Initial Access', 'detection rule']); // child of the rule's
  assert.deepStrictEqual([from('T1110', 'T1110.003').tactic, from('T1110', 'T1110.003').tacticSource], ['Credential Access', 'detection rule']); // parent of it
  assert.deepStrictEqual([from('T1071', ['T1003', 'T1071.004']).tactic, from('T1071', ['T1003', 'T1071.004']).tacticSource],
    ['Command and Control', 'detection rule']);                                                              // any of the rule's tags
});

test("any other technique in the built-in ATT&CK map gets the map's tactic, whatever the model said", () => {
  const from = (techniqueId, tactic, rule = 'T1110') => mitreOf({ tactic, techniqueId, techniqueName: 'x' }, rule);
  for (const tactic of copilot.ATTACK_TACTICS) {
    const m = from('T1071', tactic);
    assert.deepStrictEqual([m.tactic, m.tacticSource, m.techniqueId, m.source], ['Command and Control', 'ATT&CK map', 'T1071', 'model'], tactic);
  }
  assert.strictEqual(from('T1071.004', 'Execution').tactic, 'Command and Control'); // a sub-technique uses its parent's entry
  assert.strictEqual(from('T1003', 'not a tactic').tactic, 'Credential Access');   // an invalid model tactic no longer matters
  assert.strictEqual(from('T1003', null).tacticSource, 'ATT&CK map');
  assert.strictEqual(from('T1078', 'Impact', null).tactic, 'Initial Access');       // several tactics: the first listed
  assert.strictEqual(from('T1003', 'Impact', null).tacticSource, 'ATT&CK map');     // and with no rule mapping at all
});

test("every technique the shipped rules use is in the ATT&CK map", () => {
  const used = new Set(detection.getRules().flatMap(r => mitre.tags(r.mitre)));
  assert.ok(used.size >= 8);
  for (const id of used) {
    const m = mitreOf({ tactic: 'Impact', techniqueId: id, techniqueName: 'x' }, 'T9999');
    assert.strictEqual(m.tacticSource, 'ATT&CK map', id);
    assert.notStrictEqual(m.tactic, 'Impact', id);
  }
});

test('a technique that is neither the rule\'s nor in the map keeps the model\'s tactic, labelled AI-suggested', () => {
  for (const tactic of copilot.ATTACK_TACTICS) {
    const m = mitreOf({ tactic: ` ${tactic.toLowerCase()} `, techniqueId: 'T1190', techniqueName: 'Exploit Public-Facing Application' }, 'T1110');
    assert.deepStrictEqual([m.tactic, m.tacticSource, m.techniqueId, m.source], [tactic, 'AI-suggested', 'T1190', 'model'], tactic);
  }
  assert.strictEqual(mitreOf({ tactic: 'Impact', techniqueId: 'T1190' }).tacticSource, 'AI-suggested'); // no rule mapping either
});

test('an invalid technique ID falls back to the rule\'s mapping, marked "detection rule"', () => {
  for (const techniqueId of ['banana', 'T11', 'T1110.3', 'T1110.0034', '1110', '', 'T1110/T1003', 'TA0006', null, 1110, {}]) {
    const p = copilot.parseReply(withMitre({ ...GOOD.mitre, techniqueId }), 'T1110');
    assert.deepStrictEqual(p.mitre, FROM_RULE_T1110, String(techniqueId));
  }
});

test("an invalid tactic no longer matters when the technique is known: the technique is kept and the tactic derived", () => {
  for (const tactic of ['T1110', 'Brute Force', 'OS Credential Dumping', 'Hacking', 'Command & Control', '', null, 7]) {
    const m = mitreOf({ tactic, techniqueId: 'T1003', techniqueName: 'OS Credential Dumping' }, 'T1110');
    assert.deepStrictEqual(m, { tactic: 'Credential Access', techniqueId: 'T1003', name: 'OS Credential Dumping', assessment: 'differs',
      source: 'model', tacticSource: 'ATT&CK map' }, String(tactic));
  }
});

test("an unknown technique with no valid tactic of its own falls back to the rule's mapping", () => {
  for (const tactic of ['nope', '', null, 7])
    assert.deepStrictEqual(mitreOf({ tactic, techniqueId: 'T1190', techniqueName: 'x' }, 'T1110'), FROM_RULE_T1110, String(tactic));
  assert.strictEqual(mitreOf({ tactic: 'nope', techniqueId: 'T1190', techniqueName: 'x' }, 'T9999'), undefined); // nothing to fall back to
});

test("the fallback uses the rule's own technique name and first tactic", () => {
  const bad = { tactic: 'nope', techniqueId: 'nope', techniqueName: 'x' };
  assert.deepStrictEqual(copilot.parseReply(withMitre(bad), 'T1071.004').mitre,
    { tactic: 'Command and Control', techniqueId: 'T1071.004', name: 'Application Layer Protocol: DNS', assessment: 'rule', source: 'detection rule',
      tacticSource: 'detection rule' });
  assert.deepStrictEqual(copilot.parseReply(withMitre(bad), ['t1078', 'T1110']).mitre,
    { tactic: 'Initial Access', techniqueId: 'T1078', name: 'Valid Accounts', assessment: 'rule', source: 'detection rule',
      tacticSource: 'detection rule' });
});

test('an invalid mapping with no usable rule mapping to fall back to is not parsed', () => {
  const bad = { tactic: 'nope', techniqueId: 'nope', techniqueName: 'x' };
  for (const rule of [undefined, null, '', [], 'T9999', 'banana']) assert.strictEqual(copilot.parseReply(withMitre(bad), rule), null, String(rule));
});

test("triage: a bad MITRE answer is replaced by the alert's own mapping and marked", async () => {
  use(reply(withMitre({ tactic: 'T1110', techniqueId: 'banana', techniqueName: 'Brute Force' })));
  const r = await copilot.triage({ alertId: alertId() });
  assert.strictEqual(r.parsed, true);
  assert.deepStrictEqual(r.result.mitre, FROM_RULE_T1110);
  assert.strictEqual(r.result.severity.level, 'high'); // the rest of the reply is untouched
  assert.deepStrictEqual(r.result.nextSteps, GOOD.nextSteps);
});

test("triage: a good MITRE answer is kept and marked as the model's", async () => {
  const r = await copilot.triage({ alertId: alertId() });
  assert.strictEqual(r.result.mitre.source, 'model');
  assert.strictEqual(r.result.mitre.assessment, 'confirms');
  assert.strictEqual(r.result.mitre.tacticSource, 'detection rule');
});

test("triage: a wrong tactic from the model is replaced by the one derived from the rule's technique", async () => {
  use(reply(withMitre({ tactic: 'Lateral Movement', techniqueId: 'T1110', techniqueName: 'Brute Force' })));
  const r = await copilot.triage({ alertId: alertId() });
  assert.deepStrictEqual([r.result.mitre.tactic, r.result.mitre.tacticSource, r.result.mitre.techniqueId],
    ['Credential Access', 'detection rule', 'T1110']);
});

test('triage: a technique other than the rule\'s gets its tactic from the ATT&CK map', async () => {
  use(reply(withMitre({ tactic: 'Execution', techniqueId: 'T1071', techniqueName: 'Application Layer Protocol' })));
  const r = await copilot.triage({ alertId: alertId() }); // a T1110 alert
  assert.deepStrictEqual([r.result.mitre.tactic, r.result.mitre.tacticSource, r.result.mitre.assessment],
    ['Command and Control', 'ATT&CK map', 'differs']);
});

test("triage for a case falls back to the mapping of the case's most severe alert", async () => {
  const low = alertId();
  gen.expand('cred_dump', Date.now()).forEach(engine.ingest);
  const critical = store.state.alerts.find(a => a.ruleId === 'R007');
  assert.ok(critical);
  const c = cases.create({ alertIds: [low, critical.id] });
  use(reply(withMitre({ tactic: 'nope', techniqueId: 'nope', techniqueName: 'x' })));
  const r = await copilot.triage({ caseId: c.id });
  assert.deepStrictEqual(r.result.mitre,
    { tactic: 'Credential Access', techniqueId: 'T1003', name: 'OS Credential Dumping', assessment: 'rule', source: 'detection rule',
      tacticSource: 'detection rule' });
});
