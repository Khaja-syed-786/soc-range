// Tests: the HTTP API in server.js, started in-process on a random free port with a throwaway data folder.
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const os = require('os');
const path = require('path');
const fs = require('fs');

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'socsim-server-test-'));
process.env.SOCSIM_DATA_DIR = dataDir;
const config = require('../src/config');
config.port = 0; // let the OS pick a free port so the test never clashes with a running copy

let srv, base;
const warnings = [];
before(async () => {
  const warn = console.warn;
  console.warn = (...args) => { warnings.push(args.join(' ')); };
  try { srv = require('../server'); } finally { console.warn = warn; }
  if (!srv.server.listening) await new Promise(resolve => srv.server.once('listening', resolve));
  base = `http://127.0.0.1:${srv.server.address().port}`;
});
after(() => new Promise(resolve => srv.close(resolve)));

const get = p => fetch(base + p);
const send = (method, p, body, headers = { 'X-SocSim': '1' }) =>
  fetch(base + p, { method, headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body) });

test('listens on loopback only, with no startup warning', () => {
  assert.strictEqual(srv.server.address().address, '127.0.0.1');
  assert.deepStrictEqual(warnings, []);
});

test('serves the analyst console', async () => {
  const res = await get('/');
  assert.strictEqual(res.status, 200);
  assert.match(res.headers.get('content-type'), /text\/html/);
  assert.match(await res.text(), /<html/i);
});

test('startup seeds simulated history and the generator is running', async () => {
  const g = await (await get('/api/generator')).json();
  assert.deepStrictEqual(Object.keys(g).sort(), ['autoScenarios', 'rate', 'running']);
  assert.strictEqual(g.running, true);
  const ev = await (await get('/api/events?size=5')).json();
  assert.ok(ev.total > 1000, `expected seeded history, got ${ev.total} events`);
  assert.strictEqual(ev.events.length, 5);
});

test('state-changing calls without the X-SocSim header are refused (CSRF guard)', async () => {
  const res = await send('POST', '/api/generator', { running: false }, {});
  assert.strictEqual(res.status, 403);
  assert.strictEqual((await (await get('/api/generator')).json()).running, true);
});

test('generator settings are validated and applied', async () => {
  const badRate = await send('POST', '/api/generator', { rate: 50 });
  assert.strictEqual(badRate.status, 400);
  assert.match((await badRate.json()).error, /between 0.1 and 20/);
  const ok = await (await send('POST', '/api/generator', { rate: 2, autoScenarios: false })).json();
  assert.strictEqual(ok.rate, 2);
  assert.strictEqual(ok.autoScenarios, false);
});

test('injecting a scenario raises the expected alert, visible through the API', async () => {
  const res = await send('POST', '/api/generator/inject', { scenario: 'cred_dump' });
  assert.strictEqual(res.status, 200);
  assert.ok((await res.json()).injected);
  const list = await (await get('/api/alerts?severity=critical')).json();
  const a = list.find(x => x.ruleId === 'R007');
  assert.ok(a, 'R007 alert expected after cred_dump');
  const detail = await (await get(`/api/alerts/${a.id}`)).json();
  assert.strictEqual(detail.ruleId, 'R007');
  const unknown = await send('POST', '/api/generator/inject', { scenario: 'no_such_scenario' });
  assert.strictEqual(unknown.status, 400);
});

test('events can be filtered by source', async () => {
  const { events } = await (await get('/api/events?source=dns&size=20')).json();
  assert.ok(events.length > 0);
  assert.ok(events.every(e => e.source === 'dns'));
});

test('IOC lookup refuses real-looking addresses and answers for simulated ones', async () => {
  const real = await get('/api/ioc?value=8.8.8.8');
  assert.strictEqual(real.status, 400);
  assert.match((await real.json()).error, /not a simulated address/);
  const sim = await get('/api/ioc?value=203.0.113.10');
  assert.strictEqual(sim.status, 200);
  assert.strictEqual((await sim.json()).type, 'ip');
});

test('cases: create from an alert, read it back, 404 for a missing case', async () => {
  const [a] = (await (await get('/api/alerts')).json()).filter(x => !x.caseId);
  const created = await (await send('POST', '/api/cases', { alertIds: [a.id], title: 'API test case' })).json();
  assert.ok(created.id);
  const detail = await (await get(`/api/cases/${created.id}`)).json();
  assert.strictEqual(detail.title, 'API test case');
  assert.strictEqual((await get('/api/cases/99999')).status, 404);
});

test('metadata lists every scenario and the MITRE catalogue', async () => {
  const meta = await (await get('/api/meta')).json();
  assert.ok(meta.scenarios.some(s => s.key === 'brute_force'));
  assert.ok(meta.mitre.length > 0);
  assert.strictEqual(meta.dataFile, path.join(dataDir, 'state.json'));
});

test('reset clears alerts and cases, reseeds history and saves state to the data folder', async () => {
  const res = await send('POST', '/api/reset', {});
  assert.deepStrictEqual(await res.json(), { ok: true });
  assert.deepStrictEqual(await (await get('/api/cases')).json(), []);
  assert.ok((await (await get('/api/events?size=1')).json()).total > 1000);
  assert.ok(fs.existsSync(path.join(dataDir, 'state.json')));
});
