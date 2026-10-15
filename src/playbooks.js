// Playbooks: step-by-step checklists (rules/playbooks.json). One auto-attaches to each alert from its rule.

const fs = require('fs');
const path = require('path');
const store = require('./store');

const FILE = path.join(__dirname, '..', 'rules', 'playbooks.json');
let playbooks = [];

function load() {
  playbooks = validate(JSON.parse(fs.readFileSync(FILE, 'utf8')));
  return playbooks;
}

function save(list) {
  const v = validate(list);
  fs.writeFileSync(FILE, JSON.stringify(v, null, 2) + '\n');
  playbooks = v;
  return playbooks;
}

function validate(list) {
  if (!Array.isArray(list)) throw new Error('Playbooks must be a JSON array');
  const ids = new Set();
  for (const p of list) {
    if (!p.id || ids.has(p.id)) throw new Error(`Missing or duplicate playbook id: ${p.id}`);
    ids.add(p.id);
    if (!p.name) throw new Error(`${p.id}: name required`);
    if (!Array.isArray(p.ruleIds)) throw new Error(`${p.id}: ruleIds must be an array`);
    if (!Array.isArray(p.steps) || !p.steps.length || p.steps.some(s => !s || !s.title))
      throw new Error(`${p.id}: steps must be a non-empty array of {title, help}`);
  }
  return list;
}

const get = id => playbooks.find(p => p.id === id);
const forRule = ruleId => playbooks.find(p => p.ruleIds.includes(ruleId));

// Attach a fresh run to an alert (no-op if the rule has no playbook or one is attached)
function attach(alert) {
  if (alert.playbook) return;
  const pb = forRule(alert.ruleId);
  if (!pb) return;
  alert.playbook = { id: pb.id, steps: pb.steps.map(() => ({ done: false, note: '', doneTs: null })) };
}

// For alerts saved by older versions (before playbooks existed)
function attachMissing() {
  let n = 0;
  for (const a of store.state.alerts) if (!a.playbook) { attach(a); if (a.playbook) n++; }
  if (n) store.markDirty();
  return n;
}

function updateStep(alertId, idx, patch, now = Date.now()) {
  const a = store.state.alerts.find(x => x.id === alertId);
  if (!a) throw Object.assign(new Error('Alert not found'), { status: 404 });
  if (!a.playbook) throw new Error('This alert has no playbook');
  const step = a.playbook.steps[idx];
  if (!step) throw new Error('Bad step number');
  const title = get(a.playbook.id)?.steps[idx]?.title || `Step ${idx + 1}`;
  if ('note' in patch) step.note = String(patch.note || '').slice(0, 4000);
  if ('done' in patch && Boolean(patch.done) !== step.done) {
    step.done = Boolean(patch.done);
    step.doneTs = step.done ? now : null;
    a.history.push({ ts: now, text: `Playbook ${step.done ? 'done' : 'reopened'}: ${title}` });
  }
  store.markDirty();
  return a;
}

const all = () => playbooks;

module.exports = { load, save, all, get, forRule, attach, attachMissing, updateStep };
