// Fake threat-intel list, stored in rules/intel.json (editable). Every entry must be simulated:
// IPs from the documentation ranges, domains under *.example, hashes with 48 leading zeros.
// Lists are updated in place so detection and the generator always see the current entries.

const fs = require('fs');
const path = require('path');

const DEFAULT_FILE = path.join(__dirname, '..', 'rules', 'intel.json');
const LISTS = ['badIps', 'badDomains', 'badHashes'];

const SIM_IP = /^(192\.0\.2|198\.51\.100|203\.0\.113)\.(\d{1,3})$/;
const SIM_DOMAIN = /^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+example$/;
const SIM_HASH = /^0{48}[0-9a-f]{16}$/; // obviously artificial SHA-256, can never match a real file

const isSimIp = v => { const m = SIM_IP.exec(v); return !!m && Number(m[2]) <= 255; };
const isSimDomain = v => v.length <= 253 && SIM_DOMAIN.test(v);
const isSimHash = v => SIM_HASH.test(v);
const CHECK = {
  badIps: [isSimIp, 'IPs must be in 192.0.2.x, 198.51.100.x or 203.0.113.x'],
  badDomains: [isSimDomain, 'domains must end in .example'],
  badHashes: [isSimHash, 'hashes must be 64 hex characters starting with 48 zeros (simulated)'],
};

const badIps = [];
const badDomains = [];
const badHashes = [];
const all = { badIps, badDomains, badHashes };
const lists = { badIps: new Set(), badDomains: new Set(), badHashes: new Set() };
let file = DEFAULT_FILE;

function validate(data) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('Intel must be a JSON object with badIps, badDomains and badHashes');
  const out = {};
  for (const name of LISTS) {
    const list = data[name];
    if (!Array.isArray(list) || !list.length) throw new Error(`${name} must be a non-empty array`);
    const seen = new Set();
    out[name] = list.map(x => {
      const value = String(x?.value ?? '').trim().toLowerCase();
      const [ok, msg] = CHECK[name];
      if (!ok(value)) throw new Error(`${name}: "${value}" rejected: ${msg}`);
      if (seen.has(value)) throw new Error(`${name}: duplicate ${value}`);
      seen.add(value);
      return { value, note: String(x.note || '').slice(0, 200) };
    });
  }
  return out;
}

function apply(v) {
  for (const name of LISTS) {
    all[name].splice(0, all[name].length, ...v[name]);
    lists[name].clear();
    v[name].forEach(x => lists[name].add(x.value));
  }
}

// Load from a file (default rules/intel.json). Later saves go to the same file.
function load(f = DEFAULT_FILE) {
  const v = validate(JSON.parse(fs.readFileSync(f, 'utf8')));
  file = f;
  apply(v);
  return all;
}

function save(data) {
  const v = validate(data);
  fs.writeFileSync(file, JSON.stringify(v, null, 2) + '\n');
  apply(v);
  return all;
}

// Which list a value belongs in, or null if it isn't a simulated IP/domain/hash
function listFor(value) {
  const v = String(value || '').trim().toLowerCase();
  return LISTS.find(name => CHECK[name][0](v)) || null;
}

// Add one entry (from the IOC lookup page)
function add(value, note) {
  const v = String(value || '').trim().toLowerCase();
  const name = listFor(v);
  if (!name) throw new Error('Only simulated IPs, .example domains and simulated hashes can be added');
  if (lists[name].has(v)) throw new Error(`${v} is already on the intel list`);
  return save({ ...all, [name]: [...all[name], { value: v, note: String(note || 'Added by analyst (training)') }] });
}

function lookup(value) {
  const v = String(value || '').trim().toLowerCase();
  return [...badIps, ...badDomains, ...badHashes].find(x => x.value === v) || null;
}

load();

module.exports = { badIps, badDomains, badHashes, lists, all: () => all, load, save, add, validate, lookup, listFor,
  isSimIp, isSimDomain, isSimHash };
