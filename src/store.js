// In-memory state, persisted to <dataDir>/state.json every N seconds (if changed) and on shutdown.

const fs = require('fs');
const path = require('path');
const config = require('./config');

const file = path.join(config.dataDir, 'state.json');
const VERSION = 4;
const backupFile = v => path.join(config.dataDir, `state.v${v}.bak`);

const state = {
  version: VERSION,
  nextEventId: 1,
  nextAlertId: 1,
  nextCaseId: 1,
  events: [],
  alerts: [],
  cases: [],
  generator: { running: true, rate: config.defaultRate, autoScenarios: true },
  // The running exercise (null when none), score history and shift handovers.
  // History is about the analyst, not the simulated data, so reset() keeps it.
  exercise: null,
  exercises: [],
  nextExerciseId: 1,
  handovers: [],
  nextHandoverId: 1,
  handoverDraft: '',
};
let dirty = false;

function load() {
  try {
    const loaded = JSON.parse(fs.readFileSync(file, 'utf8'));
    const from = loaded.version || 1;
    // Before upgrading an older file, keep a copy of it (never overwrite an existing backup)
    if (from < VERSION && !fs.existsSync(backupFile(from))) fs.copyFileSync(file, backupFile(from));
    Object.assign(state, loaded);
    // v1 -> v2: cases added (playbook runs are attached by playbooks.attachMissing)
    if (!Array.isArray(state.cases)) state.cases = [];
    if (!state.nextCaseId) state.nextCaseId = state.cases.reduce((m, c) => Math.max(m, c.id), 0) + 1;
    // v2 -> v3: indicators (IOCs) recorded on cases
    for (const c of state.cases) if (!Array.isArray(c.iocs)) c.iocs = [];
    // v3 -> v4: exercises, handovers; alerts get raisedTs (when it appeared in the queue) and ruleSeverity
    if (state.exercise === undefined) state.exercise = null;
    if (!Array.isArray(state.exercises)) state.exercises = [];
    if (!state.nextExerciseId) state.nextExerciseId = state.exercises.reduce((m, x) => Math.max(m, x.id), 0) + 1;
    if (!Array.isArray(state.handovers)) state.handovers = [];
    if (!state.nextHandoverId) state.nextHandoverId = state.handovers.reduce((m, x) => Math.max(m, x.id), 0) + 1;
    if (typeof state.handoverDraft !== 'string') state.handoverDraft = '';
    for (const a of state.alerts) {
      if (a.raisedTs == null) a.raisedTs = a.createdTs;
      if (!a.ruleSeverity) a.ruleSeverity = a.severity;
    }
    if (from < VERSION) { state.version = VERSION; dirty = true; }
    return true;
  } catch (e) {
    if (e.code !== 'ENOENT') console.error(`Could not read ${file}: ${e.message} — starting fresh`);
    return false;
  }
}

function save() {
  if (!dirty) return;
  fs.mkdirSync(config.dataDir, { recursive: true });
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(state));
  fs.renameSync(tmp, file);
  dirty = false;
}

function addEvent(ev) {
  ev.id = state.nextEventId++;
  state.events.push(ev);
  // Trim in chunks so we don't shift the array on every insert
  if (state.events.length > config.eventCap + 1000) state.events.splice(0, state.events.length - config.eventCap);
  dirty = true;
  return ev;
}

function reset() {
  state.nextEventId = 1;
  state.nextAlertId = 1;
  state.events = [];
  state.alerts = [];
  state.nextCaseId = 1;
  state.cases = [];
  state.exercise = null; // exercise/handover history is kept
  dirty = true;
}

const markDirty = () => { dirty = true; };

module.exports = { state, load, save, addEvent, reset, markDirty, file, backupFile, VERSION };
