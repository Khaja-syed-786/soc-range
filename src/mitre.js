// MITRE ATT&CK heatmap: a small built-in catalogue (public technique IDs and names only) and
// per-technique detection coverage (enabled rules) and alert activity.
// Techniques with no rule are included on purpose so the heatmap shows coverage gaps.

const store = require('./store');
const detection = require('./detection');

const TACTICS = [
  { id: 'TA0001', name: 'Initial Access' },
  { id: 'TA0002', name: 'Execution' },
  { id: 'TA0003', name: 'Persistence' },
  { id: 'TA0004', name: 'Privilege Escalation' },
  { id: 'TA0005', name: 'Defense Evasion' },
  { id: 'TA0006', name: 'Credential Access' },
  { id: 'TA0007', name: 'Discovery' },
  { id: 'TA0008', name: 'Lateral Movement' },
  { id: 'TA0011', name: 'Command and Control' },
  { id: 'TA0010', name: 'Exfiltration' },
];

// A technique can belong to several tactics (it then shows in each column, as on the ATT&CK matrix)
const TECHNIQUES = [
  { id: 'T1566', name: 'Phishing', tactics: ['TA0001'] },
  { id: 'T1078', name: 'Valid Accounts', tactics: ['TA0001', 'TA0003', 'TA0004', 'TA0005'] },
  { id: 'T1059', name: 'Command and Scripting Interpreter', tactics: ['TA0002'] },
  { id: 'T1136', name: 'Create Account', tactics: ['TA0003'] },
  { id: 'T1098', name: 'Account Manipulation', tactics: ['TA0003', 'TA0004'] },
  { id: 'T1027', name: 'Obfuscated Files or Information', tactics: ['TA0005'] },
  { id: 'T1070', name: 'Indicator Removal', tactics: ['TA0005'] },
  { id: 'T1110', name: 'Brute Force', tactics: ['TA0006'], subs: [{ id: 'T1110.003', name: 'Password Spraying' }] },
  { id: 'T1003', name: 'OS Credential Dumping', tactics: ['TA0006'] },
  { id: 'T1087', name: 'Account Discovery', tactics: ['TA0007'] },
  { id: 'T1021', name: 'Remote Services', tactics: ['TA0008'] },
  { id: 'T1071', name: 'Application Layer Protocol', tactics: ['TA0011'], subs: [{ id: 'T1071.004', name: 'DNS' }] },
  { id: 'T1048', name: 'Exfiltration Over Alternative Protocol', tactics: ['TA0010'] },
];

const byId = Object.fromEntries(TECHNIQUES.map(t => [t.id, t]));

// Rule/alert `mitre` may be a string or a list of IDs
const tags = x => (Array.isArray(x) ? x : x ? [x] : []).map(s => String(s).trim().toUpperCase()).filter(Boolean);
const parentOf = id => id.split('.')[0];

const find = id => byId[parentOf(String(id || '').trim().toUpperCase())] || null;

// Does an alert/rule tag match a technique filter? A parent matches its sub-techniques.
function matches(mitre, id) {
  const want = String(id || '').trim().toUpperCase();
  return tags(mitre).some(t => t === want || (!want.includes('.') && parentOf(t) === want));
}

function heatmap({ rules = detection.getRules(), alerts = store.state.alerts, hours = 0, now = Date.now() } = {}) {
  const since = hours > 0 ? now - hours * 3600e3 : -Infinity;
  const cells = new Map();
  const cell = id => {
    if (!cells.has(id)) {
      const t = byId[id];
      cells.set(id, { id, name: t ? t.name : 'Not in built-in catalogue', tactics: t ? t.tactics : ['Other'],
        subs: (t?.subs || []).map(s => ({ ...s, rules: 0, alerts: 0 })), rules: [], coverage: 0,
        alerts: { total: 0, open: 0, true_positive: 0, false_positive: 0, benign: 0 } });
    }
    return cells.get(id);
  };
  TECHNIQUES.forEach(t => cell(t.id));
  // Count a sub-technique hit (it also counts toward the parent cell)
  const bumpSub = (c, t, field) => {
    if (t === c.id) return;
    let s = c.subs.find(x => x.id === t);
    if (!s) { s = { id: t, name: '', rules: 0, alerts: 0 }; c.subs.push(s); }
    s[field]++;
  };

  // Each rule/alert counts once per parent technique, even if tagged with parent and sub
  for (const r of rules) {
    const seen = new Set();
    for (const t of new Set(tags(r.mitre))) {
      const c = cell(parentOf(t));
      if (r.enabled) bumpSub(c, t, 'rules');
      if (seen.has(c.id)) continue;
      seen.add(c.id);
      c.rules.push({ id: r.id, name: r.name, enabled: !!r.enabled, technique: t });
      if (r.enabled) c.coverage++;
    }
  }
  for (const a of alerts) {
    if (a.createdTs < since) continue;
    const seen = new Set();
    for (const t of new Set(tags(a.mitre))) {
      const c = cell(parentOf(t));
      bumpSub(c, t, 'alerts');
      if (seen.has(c.id)) continue;
      seen.add(c.id);
      c.alerts.total++;
      if (a.status !== 'Closed') c.alerts.open++;
      if (a.verdict) c.alerts[a.verdict]++;
    }
  }
  const all = [...cells.values()];
  const known = all.filter(c => byId[c.id]);
  return {
    hours, since: hours > 0 ? since : null,
    tactics: TACTICS,
    techniques: known,
    other: all.filter(c => !byId[c.id]),
    summary: { techniques: known.length, covered: known.filter(c => c.coverage > 0).length,
      withAlerts: all.filter(c => c.alerts.total > 0).length },
  };
}

const catalogue = () => TECHNIQUES.flatMap(t => [{ id: t.id, name: t.name }, ...(t.subs || []).map(s => ({ id: s.id, name: `${t.name}: ${s.name}` }))]);

module.exports = { TACTICS, TECHNIQUES, find, matches, heatmap, catalogue, tags };
