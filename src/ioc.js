// IOC lookup: classify an indicator (IP / domain / file hash) and look it up in LOCAL data only —
// the fake intel list and stored events. Never contacts anything; non-simulated values are refused.

const store = require('./store');
const intel = require('./intel');
const C = require('./company');

const FIELDS = { ip: ['srcIp', 'dstIp'], domain: ['domain', 'urlDomain', 'senderDomain'], hash: ['fileHash'] };
const bad = msg => Object.assign(new Error(msg), { status: 400 });

// -> { type, value } or throws a 400 explaining what is accepted
function classify(raw) {
  const v = String(raw ?? '').trim().toLowerCase();
  if (!v) throw bad('Enter an IP address, a domain name or a SHA-256 file hash');
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) {
    if (!intel.isSimIp(v)) throw bad(`${v} is not a simulated address. Only 192.0.2.x, 198.51.100.x and 203.0.113.x exist here; this simulator never looks up real addresses.`);
    return { type: 'ip', value: v };
  }
  if (/^[0-9a-f]{64}$/.test(v)) {
    if (!intel.isSimHash(v)) throw bad('Not a simulated hash. Simulated hashes start with 48 zeros; real file hashes are never looked up here.');
    return { type: 'hash', value: v };
  }
  if (/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(v)) {
    if (!intel.isSimDomain(v)) throw bad(`${v} is not a simulated domain. Only *.example domains exist here; real domains are never looked up.`);
    return { type: 'domain', value: v };
  }
  throw bad('Enter an IP address, a domain name or a SHA-256 file hash');
}

// Plain-words context for the indicator, from the fake company data
function about(type, value) {
  if (type === 'ip') {
    if (value.startsWith('192.0.2.')) {
      const h = C.hosts.find(x => x.ip === value);
      return h ? `Internal address of ${h.name} (${h.role || 'workstation'})` : 'Internal address (no known host)';
    }
    if (value.startsWith('198.51.100.')) return 'External address in the normal internet range';
    return 'External address in the range this simulator uses for suspicious actors';
  }
  if (type === 'domain') {
    if (value.endsWith('.corp.example')) return 'Internal company domain';
    if (C.benignDomains.includes(value)) return 'Known business domain (seen in normal traffic)';
    return 'Not one of the known business domains';
  }
  return 'File hash (SHA-256) reported by the endpoint agent';
}

function lookup(raw) {
  const { type, value } = classify(raw);
  const fields = FIELDS[type];
  const hosts = {}, users = {}, sources = {};
  const ids = new Set();
  let first = null, last = null;
  const latest = [];
  const evs = store.state.events;
  for (let i = evs.length - 1; i >= 0; i--) { // newest first
    const e = evs[i];
    if (!fields.some(f => e[f] === value)) continue;
    ids.add(e.id);
    if (last === null) last = e.ts;
    first = e.ts;
    if (e.host) hosts[e.host] = (hosts[e.host] || 0) + 1;
    if (e.user) users[e.user] = (users[e.user] || 0) + 1;
    sources[e.source] = (sources[e.source] || 0) + 1;
    if (latest.length < 20) latest.push(e);
  }
  const top = o => Object.entries(o).sort((a, b) => b[1] - a[1]).map(([name, count]) => ({ name, count }));
  const alerts = store.state.alerts
    .filter(a => a.key === value || a.relatedEventIds.some(id => ids.has(id)))
    .map(a => ({ id: a.id, title: a.title, severity: a.severity, status: a.status, verdict: a.verdict, caseId: a.caseId, createdTs: a.createdTs }))
    .sort((a, b) => b.createdTs - a.createdTs);
  const caseIds = new Set(alerts.map(a => a.caseId).filter(Boolean));
  for (const c of store.state.cases) if ((c.iocs || []).some(x => x.value === value)) caseIds.add(c.id);
  const cases = store.state.cases.filter(c => caseIds.has(c.id))
    .map(c => ({ id: c.id, title: c.title, status: c.status, severity: c.severity, hasIoc: (c.iocs || []).some(x => x.value === value) }));
  return {
    type, value,
    about: about(type, value),
    intel: intel.lookup(value),
    sightings: { count: ids.size, firstTs: first, lastTs: last, hosts: top(hosts), users: top(users), sources: top(sources), latest },
    alerts, cases,
  };
}

// Indicators found in a set of events (for the alert detail panel)
function extract(events) {
  const out = new Map();
  for (const e of events) {
    for (const [type, fields] of Object.entries(FIELDS)) {
      for (const f of fields) {
        const v = e[f];
        if (v && !out.has(v)) out.set(v, { type, value: v, onIntel: !!intel.lookup(v) });
      }
    }
  }
  return [...out.values()].sort((a, b) => b.onIntel - a.onIntel);
}

module.exports = { classify, lookup, extract, about };
