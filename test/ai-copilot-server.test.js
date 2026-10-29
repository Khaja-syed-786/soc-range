// Tests: the AI Copilot over HTTP (POST /api/ai/triage), with the server started in-process and Ollama mocked.
const { test, before, after, beforeEach } = require('node:test');
const assert = require('node:assert');
const os = require('os');
const path = require('path');
const fs = require('fs');

process.env.SOCSIM_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'socsim-ai-server-test-'));
const config = require('../src/config');
config.port = 0;
const copilot = require('../src/ai/copilot');

const GOOD = {
  summary: 'Failed logons then a success.',
  mitre: { tactic: 'Credential Access', techniqueId: 'T1110', assessment: 'confirms', note: 'Matches.' },
  severity: { level: 'high', justification: 'Success after failures.' },
  nextSteps: ['Open Log Search', 'Look up the IP', 'Check related alerts'],
  draftNote: 'Brute force then success.',
};
let ollamaCalls;

let srv, base;
before(async () => {
  const warn = console.warn;
  console.warn = () => {};
  try { srv = require('../server'); } finally { console.warn = warn; }
  if (!srv.server.listening) await new Promise(resolve => srv.server.once('listening', resolve));
  base = `http://127.0.0.1:${srv.server.address().port}`;
});
after(() => new Promise(resolve => srv.close(resolve)));
beforeEach(() => {
  ollamaCalls = 0;
  config.aiCopilot.enabled = false;
  config.aiCopilot.allowInExercises = false;
  copilot.setFetch(async () => {
    ollamaCalls++;
    return { ok: true, status: 200, text: async () => '', json: async () => ({ message: { content: JSON.stringify(GOOD) } }) };
  });
});

const post = (p, body, headers = { 'X-SocSim': '1' }) =>
  fetch(base + p, { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body) });
const firstAlertId = async () => (await (await fetch(base + '/api/alerts')).json())[0].id;

test('/api/meta tells the UI whether the copilot is on, without exposing the Ollama address', async () => {
  const meta = await (await fetch(base + '/api/meta')).json();
  assert.deepStrictEqual(meta.aiCopilot, { enabled: false, allowInExercises: false });
  config.aiCopilot.enabled = true;
  assert.strictEqual((await (await fetch(base + '/api/meta')).json()).aiCopilot.enabled, true);
});

test('off by default: a friendly answer, and Ollama is never called', async () => {
  const res = await post('/api/ai/triage', { alertId: await firstAlertId() });
  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.status, 'disabled');
  assert.ok(body.setup.length >= 3);
  assert.strictEqual(ollamaCalls, 0);
});

test('needs the X-SocSim header like every other state-changing call', async () => {
  const res = await post('/api/ai/triage', { alertId: 1 }, {});
  assert.strictEqual(res.status, 403);
  assert.strictEqual(ollamaCalls, 0);
});

test('enabled: triage of an alert and of a case', async () => {
  config.aiCopilot.enabled = true;
  const alertId = await firstAlertId();
  const a = await (await post('/api/ai/triage', { alertId })).json();
  assert.strictEqual(a.status, 'ok');
  assert.strictEqual(a.parsed, true);
  assert.strictEqual(a.label, 'AI suggestion: verify before acting');
  const kase = await (await post('/api/cases', { alertIds: [alertId] })).json();
  const c = await (await post('/api/ai/triage', { caseId: kase.id })).json();
  assert.strictEqual(c.parsed, true);
  assert.strictEqual(ollamaCalls, 2);
});

test('bad requests: 400 without an id, 404 for an unknown alert or case', async () => {
  config.aiCopilot.enabled = true;
  assert.strictEqual((await post('/api/ai/triage', {})).status, 400);
  assert.strictEqual((await fetch(base + '/api/ai/triage', { method: 'POST', headers: { 'X-SocSim': '1' } })).status, 400);
  assert.strictEqual((await post('/api/ai/triage', { alertId: 987654 })).status, 404);
  assert.strictEqual((await post('/api/ai/triage', { caseId: 987654 })).status, 404);
  assert.strictEqual(ollamaCalls, 0);
});

test('Ollama down: still a 200 with a friendly message, and the rest of the API keeps working', async () => {
  config.aiCopilot.enabled = true;
  copilot.setFetch(async () => { throw new TypeError('fetch failed'); });
  const body = await (await post('/api/ai/triage', { alertId: await firstAlertId() })).json();
  assert.strictEqual(body.status, 'unavailable');
  assert.strictEqual((await fetch(base + '/api/stats')).status, 200);
});

test('a scored exercise locks the copilot out unless allowInExercises is set', async () => {
  config.aiCopilot.enabled = true;
  const alertId = await firstAlertId();
  assert.strictEqual((await post('/api/exercise/start', { scenario: 'brute_force' })).status, 200);
  try {
    const locked = await post('/api/ai/triage', { alertId });
    assert.strictEqual(locked.status, 403);
    assert.match((await locked.json()).error, /scored exercises/);
    assert.strictEqual(ollamaCalls, 0);
    config.aiCopilot.allowInExercises = true;
    assert.strictEqual((await (await post('/api/ai/triage', { alertId })).json()).status, 'ok');
  } finally {
    await post('/api/exercise/abandon', {});
  }
});
