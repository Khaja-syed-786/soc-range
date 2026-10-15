// Shift handover: a summary of a time window (default the last 8 hours) and a watch list for the
// next analyst. Saved handovers keep a frozen copy of the report next to the analyst's notes.

const store = require('./store');
const C = require('./company');
const ioc = require('./ioc');
const intel = require('./intel');
const { SEV_RANK } = require('./alerts');

const SEVS = ['critical', 'high', 'medium', 'low'];
const DEFAULT_HOURS = 8;
const OLD_ALERT_HOURS = 4;   // open longer than this -> watch list
const FP_TUNING = 3;         // this many FPs from one rule in the window -> tuning candidate
const LIST_CAP = 5;          // max items of one kind on the watch list
const IOC_CAP = 15;
const HANDOVER_CAP = 100;
const IOC_FIELDS = ['srcIp', 'dstIp', 'domain', 'urlDomain', 'senderDomain', 'fileHash'];

const visible = a => a.raisedTs ?? a.createdTs; // when it appeared in the queue
const bySev = list => Object.fromEntries(SEVS.map(s => [s, list.filter(a => a.severity === s).length]));
const avgSecs = xs => (xs.length ? Math.round(xs.reduce((s, x) => s + x, 0) / xs.length / 1000) : null);
const hours = ms => `${(ms / 3600e3).toFixed(1)} h`;

function report({ fromTs, toTs, now = Date.now() } = {}) {
  toTs = toTs == null || toTs === '' ? now : Number(toTs);
  fromTs = fromTs == null || fromTs === '' ? toTs - DEFAULT_HOURS * 3600e3 : Number(fromTs);
  if (!Number.isFinite(fromTs) || !Number.isFinite(toTs) || fromTs >= toTs) throw new Error('The window must start before it ends');
  const inWin = ts => ts != null && ts >= fromTs && ts <= toTs;
  const all = store.state.alerts;
  const newA = all.filter(a => inWin(visible(a)));
  const openA = all.filter(a => visible(a) <= toTs && (a.closedTs == null || a.closedTs > toTs));
  const closedA = all.filter(a => inWin(a.closedTs));
  const closedByVerdict = { true_positive: 0, false_positive: 0, benign: 0 };
  for (const a of closedA) if (a.verdict) closedByVerdict[a.verdict]++;

  // Open cases (open at the end of the window)
  const alertById = new Map(all.map(a => [a.id, a]));
  const openCaseObjs = store.state.cases.filter(c => c.createdTs <= toTs && (c.closedTs == null || c.closedTs > toTs))
    .sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || a.createdTs - b.createdTs);
  const openCases = openCaseObjs.map(c => {
    const steps = c.alertIds.map(id => alertById.get(id)).filter(Boolean).flatMap(a => a.playbook?.steps || []);
    return { id: c.id, title: c.title, severity: c.severity, status: c.status, owner: c.owner, alertCount: c.alertIds.length,
      stepsDone: steps.filter(s => s.done).length, stepsTotal: steps.length, iocCount: c.iocs.length, createdTs: c.createdTs,
      lastUpdateTs: Math.max(c.createdTs, ...c.history.map(h => h.ts), ...c.notes.map(n => n.ts)) };
  });

  // Key IOCs: recorded on open cases, plus intel-listed indicators from this shift's alerts
  const found = new Map();
  const entry = (type, value) => {
    if (!found.has(value)) found.set(value, { type, value, intel: intel.lookup(value)?.note || null, cases: [], alertIds: [], sightings: 0 });
    return found.get(value);
  };
  for (const c of openCaseObjs) for (const x of c.iocs) entry(x.type, x.value).cases.push(c.id);
  const evById = new Map(store.state.events.map(e => [e.id, e]));
  for (const a of new Set([...newA, ...openA])) {
    const evs = a.relatedEventIds.map(id => evById.get(id)).filter(Boolean);
    for (const x of ioc.extract(evs)) {
      if (!x.onIntel) continue;
      const e = entry(x.type, x.value);
      if (!e.alertIds.includes(a.id)) e.alertIds.push(a.id);
    }
  }
  for (const ev of store.state.events) {
    if (!inWin(ev.ts)) continue;
    for (const v of new Set(IOC_FIELDS.map(f => ev[f]))) if (v && found.has(v)) found.get(v).sightings++;
  }
  const iocs = [...found.values()]
    .sort((a, b) => !!b.intel - !!a.intel || b.cases.length - a.cases.length || b.sightings - a.sightings)
    .slice(0, IOC_CAP).map(x => ({ ...x, alertIds: x.alertIds.slice(0, 10) }));

  // Shift MTTA / MTTR: alerts acknowledged / closed inside the window
  const acked = all.filter(a => inWin(a.ackTs));

  return {
    fromTs, toTs, generatedTs: now,
    alerts: { new: bySev(newA), open: bySev(openA), closed: bySev(closedA), closedByVerdict,
      totals: { new: newA.length, open: openA.length, closed: closedA.length } },
    cases: { open: openCases, opened: store.state.cases.filter(c => inWin(c.createdTs)).length,
      closed: store.state.cases.filter(c => inWin(c.closedTs)).length },
    iocs,
    mttaSeconds: avgSecs(acked.map(a => a.ackTs - visible(a))), ackCount: acked.length,
    mttrSeconds: avgSecs(closedA.map(a => a.closedTs - visible(a))), closeCount: closedA.length,
    watch: watchList({ toTs, newA, openA, closedA, openCases, found }),
  };
}

// Things the next analyst should keep an eye on. Each item: { level: high|medium|info, text, link }
function watchList({ toTs, newA, openA, closedA, openCases, found }) {
  const out = [];
  const push = (level, text, link) => out.push({ level, text, link });
  const sevThenAge = (a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || visible(a) - visible(b);

  const untouched = openA.filter(a => a.status === 'New' && SEV_RANK[a.severity] >= SEV_RANK.high).sort(sevThenAge);
  for (const a of untouched.slice(0, LIST_CAP)) push('high', `#${a.id} ${a.title} (${a.key}) is ${a.severity} and nobody has picked it up yet`, { type: 'alert', id: a.id });
  if (untouched.length > LIST_CAP) push('high', `${untouched.length - LIST_CAP} more critical/high alerts are still New`, { type: 'alerts', status: 'New' });

  const old = openA.filter(a => visible(a) < toTs - OLD_ALERT_HOURS * 3600e3);
  if (old.length) {
    const oldest = old.reduce((m, a) => (visible(a) < visible(m) ? a : m));
    push('medium', `${old.length} open alert${old.length > 1 ? 's have' : ' has'} been waiting more than ${OLD_ALERT_HOURS} h (oldest: #${oldest.id}, ${hours(toTs - visible(oldest))})`, { type: 'alert', id: oldest.id });
  }

  for (const c of openCases) {
    if (!c.owner) push('high', `Case #${c.id} ${c.title} has no owner`, { type: 'case', id: c.id });
    if (['Containment', 'Eradication'].includes(c.status)) push('high', `Case #${c.id} is in ${c.status}: response actions are under way, check they finish`, { type: 'case', id: c.id });
  }

  // Hosts / users that show up in several of this shift's alerts
  const evById = new Map(store.state.events.map(e => [e.id, e]));
  const counts = {};
  for (const a of newA) {
    const ev = evById.get(a.relatedEventIds[0]);
    if (!ev) continue;
    for (const [kind, v] of [['host', ev.host], ['user', ev.user]]) if (v) counts[`${kind}|${v}`] = (counts[`${kind}|${v}`] || 0) + 1;
  }
  Object.entries(counts).filter(([, n]) => n >= 2).sort((a, b) => b[1] - a[1]).slice(0, LIST_CAP).forEach(([k, n]) => {
    const [kind, name] = k.split('|');
    push('medium', `${kind === 'host' ? 'Host' : 'User'} ${name} appears in ${n} alerts this shift`, { type: 'search', [kind]: name });
  });

  const onCases = new Set(store.state.cases.flatMap(c => c.iocs.map(x => x.value)));
  [...found.values()].filter(x => x.intel && x.sightings && !onCases.has(x.value)).sort((a, b) => b.sightings - a.sightings)
    .slice(0, LIST_CAP).forEach(x => push('medium', `${x.type.toUpperCase()} ${x.value} is on the intel list and was seen ${x.sightings} times, but is not recorded on any case`, { type: 'ioc', value: x.value }));

  closedA.filter(a => a.verdict === 'true_positive' && !a.caseId).slice(0, LIST_CAP)
    .forEach(a => push('medium', `#${a.id} ${a.title} was closed as a true positive without a case. Was a response needed?`, { type: 'alert', id: a.id }));

  const fps = {};
  for (const a of closedA) if (a.verdict === 'false_positive') fps[a.ruleId] = (fps[a.ruleId] || 0) + 1;
  Object.entries(fps).filter(([, n]) => n >= FP_TUNING)
    .forEach(([id, n]) => push('info', `Rule ${id} produced ${n} false positives this shift: a tuning candidate`, { type: 'rule', id }));
  return out;
}

function save({ fromTs, toTs, analyst, notes } = {}, now = Date.now()) {
  if (analyst && !C.analysts.includes(analyst)) throw new Error('Unknown analyst');
  const snapshot = report({ fromTs, toTs, now });
  const h = { id: store.state.nextHandoverId++, createdTs: now, analyst: analyst || '', fromTs: snapshot.fromTs, toTs: snapshot.toTs,
    notes: String(notes || '').slice(0, 8000), snapshot };
  store.state.handovers.push(h);
  if (store.state.handovers.length > HANDOVER_CAP) store.state.handovers.splice(0, store.state.handovers.length - HANDOVER_CAP);
  store.state.handoverDraft = '';
  store.markDirty();
  return h;
}

function saveDraft(notes) {
  store.state.handoverDraft = String(notes || '').slice(0, 8000);
  store.markDirty();
  return { draft: store.state.handoverDraft };
}

const list = () => [...store.state.handovers].reverse().map(({ snapshot, ...h }) => h);
function get(id) {
  const h = store.state.handovers.find(x => x.id === id);
  if (!h) throw Object.assign(new Error('Handover not found'), { status: 404 });
  return h;
}
const previous = () => {
  const h = store.state.handovers[store.state.handovers.length - 1];
  return h ? (({ snapshot, ...rest }) => rest)(h) : null;
};

module.exports = { report, save, saveDraft, list, get, previous, DEFAULT_HOURS };
