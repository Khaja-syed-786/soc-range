// Incident cases: group alerts, follow the NIST IR lifecycle, build a merged timeline.

const store = require('./store');
const C = require('./company');
const { SEV_RANK } = require('./alerts');
const ioc = require('./ioc');
const intel = require('./intel');

const PHASES = ['Detection', 'Analysis', 'Containment', 'Eradication', 'Recovery', 'Post-incident'];
const STATUSES = [...PHASES, 'Closed'];
const SEVERITIES = Object.keys(SEV_RANK);

const notFound = what => Object.assign(new Error(`${what} not found`), { status: 404 });

function find(id) {
  const c = store.state.cases.find(x => x.id === id);
  if (!c) throw notFound('Case');
  return c;
}

function findAlert(id) {
  const a = store.state.alerts.find(x => x.id === id);
  if (!a) throw notFound(`Alert ${id}`);
  return a;
}

function linkAlert(c, a, now) {
  if (a.caseId === c.id) return;
  if (a.caseId) throw new Error(`Alert ${a.id} is already in case #${a.caseId}`);
  a.caseId = c.id;
  c.alertIds.push(a.id);
  if (SEV_RANK[a.severity] > SEV_RANK[c.severity]) c.severity = a.severity;
  if (a.status === 'New') { a.status = 'Investigating'; a.ackTs = a.ackTs || now; }
  a.history.push({ ts: now, text: `Escalated to case #${c.id}` });
  c.history.push({ ts: now, text: `Alert #${a.id} added: ${a.title}` });
}

function create({ alertIds = [], title, owner } = {}, now = Date.now()) {
  const list = alertIds.map(id => findAlert(Number(id)));
  for (const a of list) if (a.caseId) throw new Error(`Alert ${a.id} is already in case #${a.caseId}`);
  if (owner && !C.analysts.includes(owner)) throw new Error('Unknown owner');
  const first = list[0];
  const c = {
    id: store.state.nextCaseId++,
    title: String(title || (first ? `${first.title} (${first.key})` : 'New incident')).slice(0, 200),
    severity: 'low',
    owner: owner || first?.assignee || '',
    status: 'Detection',
    alertIds: [],
    notes: [],
    iocs: [],
    history: [{ ts: now, text: 'Case opened' }],
    summary: '',
    createdTs: now,
    closedTs: null,
  };
  store.state.cases.push(c);
  list.forEach(a => linkAlert(c, a, now));
  store.markDirty();
  return c;
}

function addAlerts(id, alertIds, now = Date.now()) {
  const c = find(id);
  if (c.status === 'Closed') throw new Error('Case is closed');
  const list = (alertIds || []).map(x => findAlert(Number(x)));
  list.forEach(a => linkAlert(c, a, now));
  store.markDirty();
  return c;
}

// Escalate one alert: into an existing case if caseId given, else a new case
function escalate(alertId, caseId, now = Date.now()) {
  return caseId ? addAlerts(Number(caseId), [alertId], now) : create({ alertIds: [alertId] }, now);
}

function update(id, patch, now = Date.now()) {
  const c = find(id);
  if ('title' in patch) {
    if (!String(patch.title || '').trim()) throw new Error('Title required');
    c.title = String(patch.title).slice(0, 200);
  }
  if ('summary' in patch) c.summary = String(patch.summary || '').slice(0, 8000);
  if ('owner' in patch && patch.owner !== c.owner) {
    if (patch.owner && !C.analysts.includes(patch.owner)) throw new Error('Unknown owner');
    c.owner = patch.owner || '';
    c.history.push({ ts: now, text: `Owner: ${c.owner || 'nobody'}` });
  }
  if ('severity' in patch && patch.severity !== c.severity) {
    if (!SEVERITIES.includes(patch.severity)) throw new Error('Bad severity');
    c.history.push({ ts: now, text: `Severity: ${c.severity} -> ${patch.severity}` });
    c.severity = patch.severity;
  }
  if ('status' in patch && patch.status !== c.status) {
    if (!STATUSES.includes(patch.status)) throw new Error('Bad status');
    if (patch.status === 'Closed') {
      if (!c.summary.trim()) throw new Error('Write a final summary before closing the case');
      for (const aid of c.alertIds) {
        const a = store.state.alerts.find(x => x.id === aid);
        if (!a || a.status === 'Closed') continue;
        if (!a.verdict) { a.verdict = 'true_positive'; a.history.push({ ts: now, text: 'Verdict: true_positive (case closed)' }); }
        a.status = 'Closed'; a.ackTs = a.ackTs || now; a.closedTs = now;
        a.history.push({ ts: now, text: `Status: Closed (case #${c.id} closed)` });
      }
    }
    c.history.push({ ts: now, text: `Phase: ${c.status} -> ${patch.status}` });
    c.status = patch.status;
    c.closedTs = c.status === 'Closed' ? now : null;
  }
  store.markDirty();
  return c;
}

function addNote(id, author, text, now = Date.now()) {
  const c = find(id);
  if (!text || !String(text).trim()) throw new Error('Note text required');
  c.notes.push({ ts: now, author: author || 'analyst', text: String(text).slice(0, 4000) });
  store.markDirty();
  return c;
}

// Indicators of compromise recorded on the case (simulated values only, checked by ioc.classify)
function addIoc(id, { value, note } = {}, now = Date.now()) {
  const c = find(id);
  if (c.status === 'Closed') throw new Error('Case is closed');
  const { type, value: v } = ioc.classify(value);
  if (c.iocs.some(x => x.value === v)) throw new Error(`${v} is already on this case`);
  c.iocs.push({ type, value: v, note: String(note || '').slice(0, 500), addedTs: now });
  c.history.push({ ts: now, kind: 'ioc', text: `IOC added: ${type} ${v}${note ? ` (${String(note).slice(0, 100)})` : ''}` });
  store.markDirty();
  return c;
}

function removeIoc(id, value, now = Date.now()) {
  const c = find(id);
  if (c.status === 'Closed') throw new Error('Case is closed');
  const v = String(value || '').trim().toLowerCase();
  const i = c.iocs.findIndex(x => x.value === v);
  if (i < 0) throw notFound('IOC');
  c.iocs.splice(i, 1);
  c.history.push({ ts: now, kind: 'ioc', text: `IOC removed: ${v}` });
  store.markDirty();
  return c;
}

// Merged, time-ordered view: events + alert creation + notes + case history
function timeline(c) {
  const out = [];
  const alerts = c.alertIds.map(id => store.state.alerts.find(a => a.id === id)).filter(Boolean);
  const evIds = new Set(alerts.flatMap(a => a.relatedEventIds));
  for (const e of store.state.events) if (evIds.has(e.id)) out.push({ ts: e.ts, kind: 'event', text: e.message, event: e });
  for (const a of alerts) {
    out.push({ ts: a.createdTs, kind: 'alert', text: `Alert #${a.id}: ${a.title} (${a.key})`, alertId: a.id, severity: a.severity });
    for (const n of a.notes) out.push({ ts: n.ts, kind: 'note', text: `[alert #${a.id}] ${n.text}`, author: n.author });
  }
  for (const n of c.notes) out.push({ ts: n.ts, kind: 'note', text: n.text, author: n.author });
  for (const h of c.history) out.push({ ts: h.ts, kind: h.kind || 'status', text: h.text });
  return out.sort((a, b) => a.ts - b.ts);
}

function detail(id) {
  const c = find(id);
  const alerts = c.alertIds.map(aid => store.state.alerts.find(a => a.id === aid)).filter(Boolean);
  const iocs = c.iocs.map(x => ({ ...x, onIntel: !!intel.lookup(x.value) })); // intel may have changed since added
  return { ...c, iocs, alerts, timeline: timeline(c) };
}

function list() {
  return [...store.state.cases].sort((a, b) => (a.status === 'Closed') - (b.status === 'Closed') ||
    SEV_RANK[b.severity] - SEV_RANK[a.severity] || b.createdTs - a.createdTs);
}

module.exports = { create, addAlerts, escalate, update, addNote, addIoc, removeIoc, timeline, detail, list, PHASES, STATUSES };
