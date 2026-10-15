// Alert queue: create/merge alerts from rule hits, triage updates, dashboard stats.

const store = require('./store');
const C = require('./company');
const playbooks = require('./playbooks');

const STATUSES = ['New', 'Investigating', 'Closed'];
const VERDICTS = ['true_positive', 'false_positive', 'benign'];
const SEV_RANK = { low: 1, medium: 2, high: 3, critical: 4 };

// nowTs = event time. wallTs = when the alert actually appeared in the queue (differs for late logs,
// e.g. last night's logon arriving now). Seeded history passes no wallTs.
function raise(hit, nowTs, wallTs = nowTs) {
  const { rule, key, eventIds, firstEventTs } = hit;
  const suppressMs = (rule.suppressSeconds || 600) * 1000;
  const existing = store.state.alerts.find(a => a.ruleId === rule.id && a.key === key &&
    a.status !== 'Closed' && nowTs - a.lastEventTs <= suppressMs);
  if (existing) {
    const set = new Set(existing.relatedEventIds);
    eventIds.forEach(id => set.add(id));
    existing.relatedEventIds = [...set];
    existing.lastEventTs = nowTs;
    existing.count = existing.relatedEventIds.length;
    store.markDirty();
    return null;
  }
  const alert = {
    id: store.state.nextAlertId++,
    ruleId: rule.id,
    title: rule.name,
    description: rule.description,
    severity: rule.severity,
    ruleSeverity: rule.severity, // what the rule said; `severity` can be changed by the analyst
    mitre: rule.mitre,
    key,
    status: 'New',
    assignee: '',
    verdict: null,
    relatedEventIds: [...eventIds],
    count: eventIds.length,
    notes: [],
    firstEventTs,
    lastEventTs: nowTs,
    createdTs: nowTs,
    raisedTs: Math.max(nowTs, wallTs),
    ackTs: null,
    closedTs: null,
    history: [{ ts: nowTs, text: 'Alert created' }], // for future shift handover report
    caseId: null,
    playbook: null,
  };
  playbooks.attach(alert);
  store.state.alerts.push(alert);
  store.markDirty();
  return alert;
}

function update(id, patch, now = Date.now()) {
  const a = store.state.alerts.find(x => x.id === id);
  if (!a) throw Object.assign(new Error('Alert not found'), { status: 404 });
  if ('assignee' in patch) {
    if (patch.assignee && !C.analysts.includes(patch.assignee)) throw new Error('Unknown assignee');
    a.assignee = patch.assignee || '';
    a.history.push({ ts: now, text: `Assigned to ${a.assignee || 'nobody'}` });
  }
  if ('verdict' in patch) {
    if (patch.verdict !== null && !VERDICTS.includes(patch.verdict)) throw new Error('Bad verdict');
    a.verdict = patch.verdict;
    a.history.push({ ts: now, text: `Verdict: ${a.verdict || 'none'}` });
  }
  if ('severity' in patch && patch.severity !== a.severity) {
    if (!SEV_RANK[patch.severity]) throw new Error('Bad severity');
    a.history.push({ ts: now, text: `Severity: ${a.severity} -> ${patch.severity}` });
    a.severity = patch.severity;
  }
  if ('status' in patch) {
    if (!STATUSES.includes(patch.status)) throw new Error('Bad status');
    if (patch.status === 'Closed' && !a.verdict) throw new Error('Set a verdict before closing');
    a.status = patch.status;
    if (patch.status !== 'New' && !a.ackTs) a.ackTs = now;
    a.closedTs = patch.status === 'Closed' ? now : null;
    a.history.push({ ts: now, text: `Status: ${a.status}` });
  }
  store.markDirty();
  return a;
}

function addNote(id, author, text, now = Date.now()) {
  const a = store.state.alerts.find(x => x.id === id);
  if (!a) throw Object.assign(new Error('Alert not found'), { status: 404 });
  if (!text || !String(text).trim()) throw new Error('Note text required');
  a.notes.push({ ts: now, author: author || 'analyst', text: String(text).slice(0, 4000) });
  store.markDirty();
  return a;
}

function stats(now = Date.now()) {
  const alerts = store.state.alerts;
  const bySeverity = { low: 0, medium: 0, high: 0, critical: 0 };
  const byStatus = { New: 0, Investigating: 0, Closed: 0 };
  const byVerdict = { true_positive: 0, false_positive: 0, benign: 0 };
  const hosts = {}, users = {};
  let ttd = 0, ttdN = 0, ttr = 0, ttrN = 0;
  const hours = Array(24).fill(0);
  const hourStart = now - 24 * 3600e3;

  const evById = new Map();
  for (const e of store.state.events) evById.set(e.id, e);

  for (const a of alerts) {
    bySeverity[a.severity]++;
    byStatus[a.status]++;
    if (a.verdict) byVerdict[a.verdict]++;
    ttd += a.createdTs - a.firstEventTs; ttdN++;
    if (a.closedTs) { ttr += a.closedTs - a.createdTs; ttrN++; }
    if (a.createdTs >= hourStart) hours[Math.min(23, Math.floor((a.createdTs - hourStart) / 3600e3))]++;
    const ev = evById.get(a.relatedEventIds[0]);
    if (ev) {
      if (ev.host) hosts[ev.host] = (hosts[ev.host] || 0) + 1;
      if (ev.user) users[ev.user] = (users[ev.user] || 0) + 1;
    }
  }
  const top = o => Object.entries(o).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([name, count]) => ({ name, count }));
  return {
    total: alerts.length,
    open: byStatus.New + byStatus.Investigating,
    closed: byStatus.Closed,
    bySeverity, byStatus, byVerdict,
    topHosts: top(hosts), topUsers: top(users),
    alertsPerHour: hours.map((count, i) => ({ ts: hourStart + i * 3600e3, count })),
    mttdSeconds: ttdN ? Math.round(ttd / ttdN / 1000) : null,
    mttrSeconds: ttrN ? Math.round(ttr / ttrN / 1000) : null,
    eventCount: store.state.events.length,
    openCases: store.state.cases.filter(c => c.status !== 'Closed').length,
  };
}

module.exports = { raise, update, addNote, stats, STATUSES, VERDICTS, SEV_RANK };
