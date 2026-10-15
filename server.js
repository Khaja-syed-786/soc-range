// SOC Training Simulator — local only (127.0.0.1). All data is simulated.

const express = require('express');
const path = require('path');
const config = require('./src/config');
const store = require('./src/store');
const detection = require('./src/detection');
const alerts = require('./src/alerts');
const engine = require('./src/engine');
const gen = require('./src/generator');
const C = require('./src/company');
const intel = require('./src/intel');
const playbooks = require('./src/playbooks');
const cases = require('./src/cases');
const mitre = require('./src/mitre');
const ioc = require('./src/ioc');
const exercise = require('./src/exercise');
const handover = require('./src/handover');

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));
// Block cross-site writes from other browser tabs: state-changing calls need a custom header
// (browsers can't send one cross-origin without a CORS preflight, which we never approve).
app.use('/api', (req, res, next) => {
  if (req.method !== 'GET' && req.get('X-SocSim') !== '1') return res.status(403).json({ error: 'Missing X-SocSim header' });
  next();
});

const wrap = fn => (req, res) => {
  try { res.json(fn(req, res)); }
  catch (e) { res.status(e.status || 400).json({ error: e.message }); }
};

app.get('/api/meta', wrap(() => ({
  users: C.users.map(u => u.name).concat(C.serviceAccounts).sort(),
  hosts: C.hosts.map(h => h.name),
  analysts: C.analysts,
  statuses: alerts.STATUSES,
  verdicts: alerts.VERDICTS,
  severities: detection.SEVERITIES,
  caseStatuses: cases.STATUSES,
  casePhases: cases.PHASES,
  scenarios: Object.entries(gen.scenarios).map(([key, s]) => ({ key, name: s.name })),
  dataFile: store.file,
  mitre: mitre.catalogue(),
  exerciseMinutes: exercise.scoring().timeLimitsMinutes,
  exerciseDefaultMinutes: exercise.scoring().defaultMinutes,
  exerciseCriteria: exercise.CRITERIA.map(key => ({ key, label: exercise.LABELS[key] })),
})));

app.get('/api/stats', wrap(() => alerts.stats()));

app.get('/api/alerts', wrap(req => {
  const { status, severity, assignee, mitre: technique } = req.query;
  return store.state.alerts
    .filter(a => (!status || a.status === status) && (!severity || a.severity === severity) &&
      (!assignee || a.assignee === assignee) && (!technique || mitre.matches(a.mitre, technique)))
    .sort((a, b) => (a.status === 'Closed') - (b.status === 'Closed') ||
      alerts.SEV_RANK[b.severity] - alerts.SEV_RANK[a.severity] || b.createdTs - a.createdTs)
    .slice(0, 500);
}));

app.get('/api/alerts/:id', wrap(req => {
  const a = store.state.alerts.find(x => x.id === Number(req.params.id));
  if (!a) throw Object.assign(new Error('Alert not found'), { status: 404 });
  const ids = new Set(a.relatedEventIds);
  const events = store.state.events.filter(e => ids.has(e.id));
  return { ...a, events, iocs: ioc.extract(events) };
}));

app.patch('/api/alerts/:id', wrap(req => alerts.update(Number(req.params.id), req.body || {})));
app.post('/api/alerts/:id/notes', wrap(req =>
  alerts.addNote(Number(req.params.id), req.body.author, req.body.text)));

app.patch('/api/alerts/:id/playbook/:step', wrap(req =>
  playbooks.updateStep(Number(req.params.id), Number(req.params.step), req.body || {})));
app.post('/api/alerts/:id/escalate', wrap(req => cases.escalate(Number(req.params.id), (req.body || {}).caseId)));

app.get('/api/playbooks', wrap(() => playbooks.all()));
app.put('/api/playbooks', wrap(req => { const r = playbooks.save(req.body); playbooks.attachMissing(); return r; }));

app.get('/api/cases', wrap(req => cases.list().filter(c => !req.query.status || c.status === req.query.status)));
app.get('/api/cases/:id', wrap(req => cases.detail(Number(req.params.id))));
app.post('/api/cases', wrap(req => cases.create(req.body || {})));
app.patch('/api/cases/:id', wrap(req => cases.update(Number(req.params.id), req.body || {})));
app.post('/api/cases/:id/notes', wrap(req => cases.addNote(Number(req.params.id), req.body.author, req.body.text)));
app.post('/api/cases/:id/alerts', wrap(req => cases.addAlerts(Number(req.params.id), (req.body || {}).alertIds)));
app.post('/api/cases/:id/iocs', wrap(req => cases.addIoc(Number(req.params.id), req.body || {})));
app.delete('/api/cases/:id/iocs/:value', wrap(req => cases.removeIoc(Number(req.params.id), req.params.value)));

// MITRE ATT&CK heatmap (hours=0 means all time)
app.get('/api/mitre', wrap(req => mitre.heatmap({ hours: Math.max(0, Number(req.query.hours) || 0) })));

// IOC lookup: local data only, never contacts anything
app.get('/api/ioc', wrap(req => ioc.lookup(req.query.value)));
app.get('/api/intel', wrap(() => intel.all()));
app.put('/api/intel', wrap(req => intel.save(req.body)));
app.post('/api/intel', wrap(req => intel.add((req.body || {}).value, (req.body || {}).note)));

// Scenario mode (the running exercise never reveals its scenario until it is scored)
app.get('/api/exercise', wrap(() => exercise.current()));
app.post('/api/exercise/start', wrap(req => exercise.start(req.body || {})));
app.post('/api/exercise/submit', wrap(() => exercise.submit()));
app.post('/api/exercise/abandon', wrap(() => exercise.abandon('Abandoned by the analyst')));
app.get('/api/exercises', wrap(() => exercise.history()));
app.get('/api/exercises/:id', wrap(req => exercise.get(Number(req.params.id))));

// Shift handover (window: ?hours=N, or ?from=&to= in ms)
app.get('/api/handover', wrap(req => {
  const { from, to, hours } = req.query;
  const toTs = to ? Number(to) : Date.now();
  const fromTs = from ? Number(from) : toTs - (Number(hours) || handover.DEFAULT_HOURS) * 3600e3;
  return { ...handover.report({ fromTs, toTs }), draft: store.state.handoverDraft, previous: handover.previous() };
}));
app.get('/api/handovers', wrap(() => handover.list()));
app.get('/api/handovers/:id', wrap(req => handover.get(Number(req.params.id))));
app.post('/api/handovers', wrap(req => handover.save(req.body || {})));
app.put('/api/handover/draft', wrap(req => handover.saveDraft((req.body || {}).notes)));

app.get('/api/events', wrap(req => {
  const q = req.query;
  const from = q.from ? Number(q.from) : 0;
  const to = q.to ? Number(q.to) : Infinity;
  const kw = (q.q || '').toLowerCase();
  const ids = q.ids ? new Set(String(q.ids).split(',').map(Number)) : null;
  const page = Math.max(0, Number(q.page) || 0);
  const size = Math.min(500, Number(q.size) || 100);
  const out = [];
  const evs = store.state.events;
  for (let i = evs.length - 1; i >= 0; i--) { // newest first
    const e = evs[i];
    if (e.ts < from || e.ts > to) continue;
    if (ids && !ids.has(e.id)) continue;
    if (q.host && e.host !== q.host) continue;
    if (q.user && e.user !== q.user && e.targetUser !== q.user) continue;
    if (q.eventId && e.eventId !== Number(q.eventId)) continue;
    if (q.source && e.source !== q.source) continue;
    if (kw && !JSON.stringify(e).toLowerCase().includes(kw)) continue;
    out.push(e);
  }
  return { total: out.length, page, size, events: out.slice(page * size, page * size + size) };
}));

app.get('/api/rules', wrap(() => detection.getRules()));
app.put('/api/rules', wrap(req => detection.saveRules(req.body)));

app.get('/api/generator', wrap(() => store.state.generator));
app.post('/api/generator', wrap(req => {
  const g = store.state.generator;
  const { running, rate, autoScenarios } = req.body || {};
  if (autoScenarios === true && !g.autoScenarios && exercise.running())
    throw new Error('Auto-scenarios stay off while an exercise is running (they are switched back on afterwards)');
  if (typeof running === 'boolean') g.running = running;
  if (typeof autoScenarios === 'boolean') g.autoScenarios = autoScenarios;
  if (rate !== undefined) {
    const r = Number(rate);
    if (!(r >= 0.1 && r <= 20)) throw new Error('Rate must be between 0.1 and 20 events/second');
    g.rate = r;
  }
  store.markDirty();
  return g;
}));
app.post('/api/generator/inject', wrap(req => {
  if (exercise.running()) throw new Error('An exercise is running. Submit or abandon it before injecting scenarios.');
  return { injected: engine.inject(req.body.scenario) };
}));

app.post('/api/reset', wrap(() => {
  if (exercise.running()) exercise.abandon('State was reset');
  engine.clearPending();
  store.reset();
  detection.loadRules();
  engine.seedIfEmpty();
  store.save();
  return { ok: true };
}));

// ---- startup ----
detection.loadRules();
playbooks.load();
const loaded = store.load();
const attached = playbooks.attachMissing();
if (attached) console.log(`Attached playbooks to ${attached} existing alerts`);
const resumed = exercise.resume();
if (resumed) console.log(`Exercise #${resumed.id} ended at startup: ${resumed.outcome}`);
if (engine.seedIfEmpty()) console.log('Seeded 24h of simulated history');
store.markDirty();
store.save();
engine.start();
const saveTimer = setInterval(() => {
  try { store.save(); } catch (e) { console.error('Save failed:', e.message); }
}, config.saveIntervalSeconds * 1000);

const server = app.listen(config.port, config.host, () => {
  console.log(`SOC Simulator on http://${config.host}:${config.port}  (state: ${store.file}${loaded ? ', restored' : ''})`);
});

function shutdown() {
  engine.stop();
  clearInterval(saveTimer);
  try { store.save(); console.log('State saved'); } catch (e) { console.error('Save failed:', e.message); }
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 2000).unref();
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
process.on('SIGBREAK', shutdown);
// Graceful stop endpoint used by stop.ps1 (localhost only, since we bind to 127.0.0.1)
app.post('/api/shutdown', (req, res) => { res.json({ ok: true }); setImmediate(shutdown); });
