// Rule engine. Rule types: match, threshold (optionally counting distinct values), lookup, beacon
// (see rules/rules.json and README).

const fs = require('fs');
const path = require('path');
const intel = require('./intel');

const RULES_FILE = path.join(__dirname, '..', 'rules', 'rules.json');
const TYPES = ['match', 'threshold', 'lookup', 'beacon'];
const SEVERITIES = ['low', 'medium', 'high', 'critical'];

let rules = [];
const windows = new Map(); // `${ruleId}|${key}` -> [{ts,id}]

function loadRules() {
  rules = validate(JSON.parse(fs.readFileSync(RULES_FILE, 'utf8')));
  windows.clear();
  return rules;
}

function saveRules(newRules) {
  const v = validate(newRules);
  fs.writeFileSync(RULES_FILE, JSON.stringify(v, null, 2) + '\n');
  rules = v;
  windows.clear();
  return rules;
}

function validate(list) {
  if (!Array.isArray(list)) throw new Error('Rules must be a JSON array');
  const ids = new Set();
  for (const r of list) {
    if (!r.id || ids.has(r.id)) throw new Error(`Missing or duplicate rule id: ${r.id}`);
    ids.add(r.id);
    if (!TYPES.includes(r.type)) throw new Error(`${r.id}: type must be one of ${TYPES.join(', ')}`);
    if (!SEVERITIES.includes(r.severity)) throw new Error(`${r.id}: severity must be one of ${SEVERITIES.join(', ')}`);
    if (r.filter && typeof r.filter !== 'object') throw new Error(`${r.id}: filter must be an object`);
    if (r.type === 'threshold' && !(r.count > 0 && r.windowSeconds > 0))
      throw new Error(`${r.id}: threshold rules need count and windowSeconds`);
    if (r.distinct != null && (typeof r.distinct !== 'string' || !r.distinct))
      throw new Error(`${r.id}: distinct must be a field name, e.g. "user"`);
    if (r.type === 'beacon') {
      if (!(r.count >= 3 && r.windowSeconds > 0)) throw new Error(`${r.id}: beacon rules need count (3 or more) and windowSeconds`);
      if (!r.per || typeof r.per !== 'string') throw new Error(`${r.id}: beacon rules need per (the field that must repeat, e.g. "dstIp")`);
      if (!(r.maxJitter > 0 && r.maxJitter <= 1)) throw new Error(`${r.id}: beacon rules need maxJitter between 0 and 1`);
      if (!(r.minIntervalSeconds >= 0)) throw new Error(`${r.id}: beacon rules need minIntervalSeconds >= 0`);
    }
    if (r.type === 'lookup' && (!r.field || !intel.lists[r.list]))
      throw new Error(`${r.id}: lookup rules need field and list (${Object.keys(intel.lists).join(', ')})`);
  }
  return list;
}

// Derived fields available to filters
function fieldValue(ev, field) {
  if (field === 'hour') return new Date(ev.ts).getHours();
  return ev[field];
}

function matchValue(actual, cond) {
  if (Array.isArray(cond)) return cond.includes(actual);
  if (cond && typeof cond === 'object') {
    if ('between' in cond) return actual >= cond.between[0] && actual <= cond.between[1];
    if ('not' in cond) return !matchValue(actual, cond.not);
    if ('gte' in cond && !(actual >= cond.gte)) return false;
    if ('lte' in cond && !(actual <= cond.lte)) return false;
    if ('contains' in cond) return String(actual ?? '').toLowerCase().includes(String(cond.contains).toLowerCase());
    return true;
  }
  return actual === cond;
}

function matches(ev, filter = {}) {
  for (const [f, cond] of Object.entries(filter)) if (!matchValue(fieldValue(ev, f), cond)) return false;
  return true;
}

// Evaluate one event. Returns list of hits: {rule, key, eventIds, firstEventTs}
function evaluate(ev) {
  const hits = [];
  for (const r of rules) {
    if (!r.enabled || !matches(ev, r.filter)) continue;
    const key = String(fieldValue(ev, r.groupBy || 'host') ?? '-');
    if (r.type === 'match') {
      hits.push({ rule: r, key, eventIds: [ev.id], firstEventTs: ev.ts });
    } else if (r.type === 'lookup') {
      if (intel.lists[r.list].has(ev[r.field])) hits.push({ rule: r, key, eventIds: [ev.id], firstEventTs: ev.ts });
    } else if (r.type === 'threshold') {
      const wk = `${r.id}|${key}`;
      const win = (windows.get(wk) || []).filter(x => ev.ts - x.ts <= r.windowSeconds * 1000);
      win.push({ ts: ev.ts, id: ev.id, val: r.distinct ? String(fieldValue(ev, r.distinct) ?? '-') : null });
      windows.set(wk, win);
      const n = r.distinct ? new Set(win.map(x => x.val)).size : win.length;
      if (n >= r.count) hits.push({ rule: r, key, eventIds: win.map(x => x.id), firstEventTs: win[0].ts });
    } else if (r.type === 'beacon') {
      // Same entity -> same `per` value, at regular intervals: jitter = std dev / mean of the gaps
      const wk = `${r.id}|${key}|${fieldValue(ev, r.per) ?? '-'}`;
      const win = (windows.get(wk) || []).filter(x => ev.ts - x.ts <= r.windowSeconds * 1000);
      win.push({ ts: ev.ts, id: ev.id });
      windows.set(wk, win.slice(-r.count));
      if (win.length >= r.count) {
        const last = win.slice(-r.count);
        const gaps = last.slice(1).map((x, i) => (x.ts - last[i].ts) / 1000);
        const mean = gaps.reduce((a, b) => a + b, 0) / gaps.length;
        const sd = Math.sqrt(gaps.reduce((a, g) => a + (g - mean) ** 2, 0) / gaps.length);
        if (mean > 0 && mean >= r.minIntervalSeconds && sd / mean <= r.maxJitter)
          hits.push({ rule: r, key, eventIds: last.map(x => x.id), firstEventTs: last[0].ts });
      }
    }
  }
  return hits;
}

const getRules = () => rules;

module.exports = { loadRules, saveRules, getRules, evaluate, matches, SEVERITIES };
