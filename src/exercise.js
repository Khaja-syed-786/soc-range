// Scenario mode: inject a scenario (hidden unless picked), let the analyst work it like any other
// alert, then score the result against the scenario's answer key (generator.js `answer`).
// Weights and time targets live in rules/scoring.json.

const fs = require('fs');
const path = require('path');
const store = require('./store');
const gen = require('./generator');
const engine = require('./engine');
const detection = require('./detection');
const { SEV_RANK } = require('./alerts');

const FILE = path.join(__dirname, '..', 'rules', 'scoring.json');
const CRITERIA = ['verdict', 'severity', 'escalation', 'linked', 'mtta', 'mttr', 'playbook', 'notes'];
const LABELS = {
  verdict: 'Verdict', severity: 'Severity', escalation: 'Escalation decision', linked: 'Related alerts in one case',
  mtta: 'Time to acknowledge (MTTA)', mttr: 'Time to resolve (MTTR)', playbook: 'Playbook steps', notes: 'Investigation notes',
};
const VERDICT_LABEL = { true_positive: 'true positive', false_positive: 'false positive', benign: 'benign' };
const HISTORY_CAP = 200;
const MAX_TRIES = 20;

let cfg = null;
let refs = []; // the running exercise's event objects; each gets an id once it is stored

function validateScoring(c) {
  if (!c || typeof c !== 'object' || Array.isArray(c)) throw new Error('Scoring must be a JSON object');
  for (const k of CRITERIA) if (!(c.weights?.[k] >= 0)) throw new Error(`weights.${k} must be a number >= 0`);
  for (const s of Object.keys(SEV_RANK)) {
    for (const m of ['mtta', 'mttr']) if (!(c.targetsSeconds?.[s]?.[m] > 0)) throw new Error(`targetsSeconds.${s}.${m} must be > 0`);
  }
  if (!(c.noteMinChars >= 0) || !(c.notesForFull >= 1)) throw new Error('noteMinChars must be >= 0 and notesForFull >= 1');
  if (!Array.isArray(c.timeLimitsMinutes) || !c.timeLimitsMinutes.length || c.timeLimitsMinutes.some(m => !(m > 0)))
    throw new Error('timeLimitsMinutes must be a non-empty list of minutes');
  if (!c.timeLimitsMinutes.includes(c.defaultMinutes)) throw new Error('defaultMinutes must be one of timeLimitsMinutes');
  return c;
}

function loadScoring(f = FILE) {
  cfg = validateScoring(JSON.parse(fs.readFileSync(f, 'utf8')));
  return cfg;
}
const scoring = () => cfg || loadScoring();

const fmt = s => (s < 60 ? `${Math.round(s)}s` : s < 3600 ? `${Math.round(s / 60)}m` : `${(s / 3600).toFixed(1)}h`);
const avg = xs => (xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : null);
const maxSev = list => list.reduce((m, s) => (SEV_RANK[s] > SEV_RANK[m] ? s : m), 'low');

// ---------- starting ----------

const rulesFor = key => gen.scenarios[key].answer(engine.plan(key)).rules;
const disabledRules = ids => ids.filter(id => !detection.getRules().some(r => r.id === id && r.enabled));

// Rebuild until no open alert exists for the same rule + entity. Otherwise de-duplication would
// fold the exercise's events into an old alert.
function planFresh(key, ruleIds, now) {
  const rules = detection.getRules().filter(r => ruleIds.includes(r.id));
  const open = new Set(store.state.alerts.filter(a => a.status !== 'Closed').map(a => `${a.ruleId}|${a.key}`));
  let events;
  for (let i = 0; i < MAX_TRIES; i++) {
    events = engine.plan(key, now);
    const clash = rules.some(r => events.some(e => detection.matches(e, r.filter) &&
      open.has(`${r.id}|${String(e[r.groupBy || 'host'] ?? '-')}`)));
    if (!clash) break;
  }
  return events;
}

function start({ scenario = 'random', minutes } = {}, now = Date.now()) {
  if (store.state.exercise) throw new Error('An exercise is already running. Submit or abandon it first.');
  const c = scoring();
  const mins = minutes == null || minutes === '' ? c.defaultMinutes : Number(minutes);
  if (!c.timeLimitsMinutes.includes(mins)) throw new Error(`Time limit must be one of ${c.timeLimitsMinutes.join(', ')} minutes`);
  let key = scenario;
  const mode = scenario === 'random' ? 'random' : 'chosen';
  if (mode === 'random') {
    const ok = Object.keys(gen.scenarios).filter(k => !disabledRules(rulesFor(k)).length);
    if (!ok.length) throw new Error('Every scenario depends on a disabled rule. Enable rules on the Rules page.');
    key = ok[Math.floor(Math.random() * ok.length)];
  } else {
    if (!gen.scenarios[key]) throw new Error(`Unknown scenario: ${key}`);
    const off = disabledRules(rulesFor(key));
    if (off.length) throw new Error(`Rule ${off.join(', ')} is disabled, so this scenario could never raise an alert. Enable it on the Rules page or pick another scenario.`);
  }
  const events = planFresh(key, rulesFor(key), now);
  for (const e of events) e.tags = []; // nothing on the events gives the scenario away
  const g = store.state.generator;
  store.state.exercise = {
    id: store.state.nextExerciseId++, key, name: gen.scenarios[key].name, mode, minutes: mins,
    startedTs: now, deadlineTs: now + mins * 60e3, eventCount: events.length, eventIds: [],
    answer: gen.scenarios[key].answer(events), prevAutoScenarios: g.autoScenarios,
  };
  g.autoScenarios = false; // no other scenarios while the exercise runs; background noise continues
  refs = events;
  engine.release(events, now);
  sync();
  store.markDirty();
  return current(now);
}

// What the UI may see while it runs: no scenario key, answer or event ids (unless picked from the list)
function current(now = Date.now()) {
  const ex = store.state.exercise;
  if (!ex) return { running: false };
  return { running: true, id: ex.id, mode: ex.mode, name: ex.mode === 'chosen' ? ex.name : null, minutes: ex.minutes,
    startedTs: ex.startedTs, deadlineTs: ex.deadlineTs, remainingMs: Math.max(0, ex.deadlineTs - now) };
}

// Record the ids of exercise events that have been stored so far
function sync() {
  const ex = store.state.exercise;
  if (!ex) return;
  const ids = refs.filter(e => e.id).map(e => e.id);
  if (ids.length > ex.eventIds.length) { ex.eventIds = ids; store.markDirty(); }
}

function tick(now = Date.now()) {
  sync();
  const ex = store.state.exercise;
  if (ex && now >= ex.deadlineTs) finish('timeout', now);
}
engine.onTick(tick);

// At startup: drip-fed events are only kept in memory, so an exercise that had not received all
// of them cannot be scored fairly.
function resume(now = Date.now()) {
  refs = [];
  const ex = store.state.exercise;
  if (!ex) return null;
  if (ex.eventIds.length < ex.eventCount) return finish('interrupted', now, 'The server restarted before all of the scenario\'s events had arrived.');
  if (now >= ex.deadlineTs) return finish('timeout', now);
  return null;
}

// ---------- finishing ----------

function exerciseAlerts(ex) {
  const ids = new Set(ex.eventIds);
  return store.state.alerts.filter(a => a.relatedEventIds.some(id => ids.has(id)));
}

const alertSummary = list => list.map(a => ({ id: a.id, ruleId: a.ruleId, title: a.title, key: a.key, severity: a.severity,
  ruleSeverity: a.ruleSeverity || a.severity, status: a.status, verdict: a.verdict, caseId: a.caseId }));

function finish(outcome, now = Date.now(), reason = '') {
  const ex = store.state.exercise;
  if (!ex) throw new Error('No exercise is running');
  sync();
  const scored = outcome === 'submitted' || outcome === 'timeout';
  const card = scored ? score(ex)
    : { score: null, headline: outcome === 'abandoned' ? 'Abandoned' : 'Interrupted', criteria: [], alerts: alertSummary(exerciseAlerts(ex)), actions: null };
  const rec = { id: ex.id, key: ex.key, name: ex.name, mode: ex.mode, minutes: ex.minutes, startedTs: ex.startedTs,
    endedTs: now, outcome, reason, answer: ex.answer, eventIds: ex.eventIds, ...card };
  store.state.exercises.push(rec);
  if (store.state.exercises.length > HISTORY_CAP) store.state.exercises.splice(0, store.state.exercises.length - HISTORY_CAP);
  store.state.generator.autoScenarios = ex.prevAutoScenarios;
  store.state.exercise = null;
  refs = [];
  store.markDirty();
  return rec;
}

const submit = (now = Date.now()) => finish('submitted', now);
const abandon = (reason = '', now = Date.now()) => finish('abandoned', now, reason);

// ---------- scoring ----------

function score(ex) {
  const c = scoring();
  const ans = ex.answer;
  const list = exerciseAlerts(ex);
  if (!list.length) {
    return { score: 0, headline: 'No alert yet', criteria: [], alerts: [], actions: null,
      reason: 'No alert from this exercise had appeared when it ended. Some scenarios take a minute or two to trip their rule.' };
  }
  const incident = ans.verdict === 'true_positive';
  const crit = [];
  const add = (key, credit, given, expected, why) => crit.push({
    key, label: LABELS[key], max: c.weights[key], credit,
    points: credit == null ? 0 : Math.round(c.weights[key] * credit * 10) / 10,
    status: credit == null ? 'n/a' : credit >= 1 ? 'got' : credit > 0 ? 'partial' : 'missed', given, expected, why,
  });

  // Verdict: benign and false positive are close cousins (both "not an incident"), so a mix-up gets half
  const credits = list.map(a => (a.verdict === ans.verdict ? 1
    : a.verdict && a.verdict !== 'true_positive' && !incident ? 0.5 : 0));
  const vCredit = avg(credits);
  const verdicts = list.map(a => a.verdict);
  const given = [...new Set(verdicts.map(v => VERDICT_LABEL[v] || 'none'))].join(', ');
  const exp = VERDICT_LABEL[ans.verdict];
  let why;
  if (vCredit === 1) why = ans.explain;
  else if (verdicts.every(v => !v)) why = `No verdict set. ${ans.explain}`;
  else if (incident) why = `This was a real incident. ${ans.explain}`;
  else if (verdicts.includes('true_positive')) why = `This was not an incident. ${ans.explain}`;
  else if (ans.verdict === 'false_positive') why = `Close. The activity is allowed AND the rule matched something it should not have, which makes it a false positive (tune the rule). ${ans.explain}`;
  else why = `Close. The rule worked as designed and the activity really happened; it is simply allowed, which makes it benign rather than a false positive. ${ans.explain}`;
  add('verdict', vCredit, given, exp, why);

  // Severity and escalation only count when the analyst took the alert on (Investigating, escalated or
  // closed). Otherwise doing nothing on a non-incident would earn "didn't raise it" / "didn't open a case".
  const acked = list.some(a => a.ackTs);
  const NOT_ACKED = 'No alert from this exercise was acknowledged (set to Investigating, escalated or closed), so there was no decision to mark. Doing nothing is not a decision.';

  // Severity: the case's severity if escalated, otherwise the highest alert severity
  const caseIds = [...new Set(list.map(a => a.caseId).filter(Boolean))];
  const theCases = caseIds.map(id => store.state.cases.find(x => x.id === id)).filter(Boolean);
  const rated = theCases.length ? maxSev(theCases.map(x => x.severity)) : maxSev(list.map(a => a.severity));
  const ruleMax = maxSev(list.map(a => a.ruleSeverity || a.severity));
  const notRaised = ans.severities === 'not_raised';
  const accepted = notRaised ? Object.keys(SEV_RANK).filter(s => SEV_RANK[s] <= SEV_RANK[ruleMax]) : ans.severities;
  const sevOk = accepted.includes(rated);
  const where = theCases.length ? ' (case severity)' : '';
  add('severity', acked && sevOk ? 1 : 0, rated + where, notRaised ? `${ruleMax} or lower` : accepted.join(' / '),
    !acked ? NOT_ACKED : notRaised
      ? (sevOk ? 'Not an incident, and you did not inflate the severity.'
        : `You raised it to ${rated}, above what the rule set (${ruleMax}). Inflating non-incidents buries the real ones.`)
      : sevOk ? `${rated} fits how bad this incident is.`
        : SEV_RANK[rated] < Math.min(...accepted.map(s => SEV_RANK[s]))
          ? `You rated it ${rated}; it should be ${accepted.join(' or ')}. Under-rating a real incident delays the response. ${ans.clues[ans.clues.length - 1] || ''}`
          : `You rated it ${rated}; ${accepted.join(' or ')} is enough for this incident.`);

  // Escalation
  const escalated = caseIds.length > 0;
  const escGiven = escalated ? `case #${caseIds.join(', #')}` : 'no case';
  if (ans.case === 'optional') {
    add('escalation', null, escGiven, 'either', 'Either is fine here: the attack did not succeed, so a case is optional.');
  } else if (ans.case === 'required') {
    add('escalation', escalated ? 1 : 0, escGiven, 'open a case', escalated
      ? 'Right: a real incident with impact needs a case for coordinated response.'
      : 'This needed an incident case: real impact needs an owner, a timeline and the NIST phases.');
  } else {
    add('escalation', !escalated && acked ? 1 : 0, escGiven, 'no case', escalated
      ? 'Over-escalated: this was not an incident, so a case was not needed. Close the alert with good notes instead.'
      : acked ? 'Right: no case is needed for activity that is allowed.' : NOT_ACKED);
  }

  // Related alerts in one case (only when there are several and a case is expected)
  const n = list.length;
  if (n >= 2 && ans.case !== 'never' && (ans.case === 'required' || escalated)) {
    const counts = {};
    for (const a of list) if (a.caseId) counts[a.caseId] = (counts[a.caseId] || 0) + 1;
    const [bestId, best = 0] = Object.entries(counts).sort((x, y) => y[1] - x[1])[0] || [];
    const main = store.state.cases.find(x => x.id === Number(bestId));
    const unrelated = main ? main.alertIds.filter(id => !list.some(a => a.id === id)).length : 0;
    add('linked', best / n, `${best}/${n} in one case`, `${n}/${n} in one case`, best === n
      ? `All ${n} alerts are in case #${bestId}, so its timeline tells one story.${unrelated ? ` (It also holds ${unrelated} unrelated alert(s). That is not marked down, but keep cases focused.)` : ''}`
      : `${n} alerts came from this one activity, but only ${best} are in the same case. Use "Escalate to case" and pick the existing case for the others.`);
  } else {
    add('linked', null, `${n} alert${n > 1 ? 's' : ''}`, '-', n < 2 ? 'Only one alert, so nothing to link.' : 'No case expected, so nothing to link.');
  }

  // MTTA / MTTR, measured from when each alert appeared in the queue (late logs have an old createdTs)
  const visible = a => Math.max(a.raisedTs ?? a.createdTs, ex.startedTs);
  const timeCredit = (secs, target) => (secs == null ? 0 : secs <= target ? 1 : secs >= 3 * target ? 0 : 1 - (secs - target) / (2 * target));
  for (const [key, field, verb, how] of [['mtta', 'ackTs', 'acknowledged', 'set it to Investigating or escalate it'],
    ['mttr', 'closedTs', 'closed', 'give a verdict and close it, or close its case']]) {
    const secs = list.map(a => (a[field] ? Math.max(0, (a[field] - visible(a)) / 1000) : null));
    const target = c.targetsSeconds[ruleMax][key];
    const measured = secs.filter(s => s != null);
    const missing = secs.length - measured.length;
    const m = avg(measured);
    const credit = avg(list.map((a, i) => timeCredit(secs[i], c.targetsSeconds[a.ruleSeverity || a.severity][key])));
    add(key, credit, m == null ? `not ${verb}` : `${fmt(m)} average`, `<= ${fmt(target)} for ${ruleMax}`,
      (missing ? `${missing} alert${missing > 1 ? 's were' : ' was'} never ${verb} (${how}). ` : '') +
      (m == null ? '' : m <= target ? `Within the ${fmt(target)} target.` : `Slower than the ${fmt(target)} target; marks drop to zero at ${fmt(3 * target)}.`));
  }

  // Playbook steps
  const steps = list.flatMap(a => a.playbook?.steps || []);
  const done = steps.filter(s => s.done).length;
  add('playbook', steps.length ? done / steps.length : null, `${done}/${steps.length} steps`, `${steps.length}/${steps.length}`,
    !steps.length ? 'No playbook for these alerts.' : done === steps.length ? 'Every step done.'
      : `${done} of ${steps.length} steps done. The playbook is how you make sure nothing is skipped.`);

  // Notes written during the exercise (alert notes, step notes, case notes, case summary)
  const good = t => String(t || '').trim().length >= c.noteMinChars;
  let notes = 0;
  for (const a of list) {
    notes += a.notes.filter(x => x.ts >= ex.startedTs && good(x.text)).length;
    notes += (a.playbook?.steps || []).filter(s => good(s.note)).length;
  }
  for (const x of theCases) notes += x.notes.filter(y => y.ts >= ex.startedTs && good(y.text)).length + (good(x.summary) ? 1 : 0);
  add('notes', Math.min(1, notes / c.notesForFull), `${notes} note${notes === 1 ? '' : 's'}`, `${c.notesForFull}+ notes`,
    notes >= c.notesForFull ? 'The next analyst (and the auditor) can follow what you checked and found.'
      : `Notes count when they are at least ${c.noteMinChars} characters. Write down what you checked and what you found.`);

  const applicable = crit.filter(x => x.credit != null);
  const max = applicable.reduce((s, x) => s + x.max, 0);
  const earned = applicable.reduce((s, x) => s + x.max * x.credit, 0);
  const escCredit = crit.find(x => x.key === 'escalation').credit;
  const headline = incident && verdicts.some(v => v && v !== 'true_positive') ? 'Missed incident'
    : !incident && (verdicts.includes('true_positive') || escalated) ? 'Over-escalated'
      : vCredit === 1 && escCredit !== 0 ? 'Correct call'
        : verdicts.every(v => !v) ? 'Unfinished' : 'Partly right';
  const meanSecs = f => avg(list.filter(a => a[f]).map(a => Math.max(0, (a[f] - visible(a)) / 1000)));
  return {
    score: max ? Math.round((earned / max) * 100) : 0, headline, criteria: crit, alerts: alertSummary(list),
    actions: { verdicts, severity: rated, caseIds, mttaSeconds: meanSecs('ackTs'), mttrSeconds: meanSecs('closedTs'),
      stepsDone: done, stepsTotal: steps.length, notes },
  };
}

// ---------- history ----------

const history = () => [...store.state.exercises].reverse();
function get(id) {
  const x = store.state.exercises.find(e => e.id === id);
  if (!x) throw Object.assign(new Error('Exercise not found'), { status: 404 });
  return x;
}

module.exports = { start, current, submit, abandon, tick, resume, score, history, get, loadScoring, validateScoring,
  scoring, exerciseAlerts, running: () => !!store.state.exercise, CRITERIA, LABELS };
