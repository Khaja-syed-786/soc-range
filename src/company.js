// Fake company "Contoso-Sim" — all names, hosts and IPs are made up.
// Internal IPs use 192.0.2.0/24 (documentation range), external benign 198.51.100.0/24,
// known-bad (fake intel) 203.0.113.0/24.

const FIRST = ['Alex', 'Sam', 'Jordan', 'Taylor', 'Casey', 'Riley', 'Morgan', 'Jamie', 'Avery', 'Quinn',
  'Drew', 'Reese', 'Skyler', 'Parker', 'Rowan', 'Emerson', 'Finley', 'Hayden', 'Kendall', 'Logan',
  'Peyton', 'Sage', 'Blake', 'Cameron', 'Dakota'];
const LAST = ['Reed', 'Lane', 'Hart', 'Stone', 'Brooks', 'Fox', 'Gray', 'Wells', 'Shaw', 'Cole'];
const DEPTS = ['Sales', 'Finance', 'HR', 'Engineering', 'Marketing', 'Operations', 'IT'];

const users = [];
for (let i = 0; i < 50; i++) {
  const first = FIRST[i % FIRST.length];
  const last = LAST[Math.floor(i / 5) % LAST.length];
  const dept = i < 4 ? 'IT' : DEPTS[i % (DEPTS.length - 1)];
  users.push({
    name: `${first[0].toLowerCase()}${last.toLowerCase()}${i < 25 ? '' : i}`,
    display: `${first} ${last}`,
    dept,
    isAdmin: i < 4,           // first 4 users are IT admins
    pc: null,
  });
}

const pcs = [];
for (let i = 1; i <= 30; i++) {
  pcs.push({ name: `WS-${String(i).padStart(3, '0')}`, ip: `192.0.2.${100 + i}`, type: 'workstation' });
}
// Assign PCs: first 30 users get their own PC, others share (hot desks)
users.forEach((u, i) => { u.pc = pcs[i % pcs.length].name; });

const servers = [
  { name: 'DC01', ip: '192.0.2.10', type: 'server', role: 'Domain Controller' },
  { name: 'FS01', ip: '192.0.2.11', type: 'server', role: 'File Server' },
  { name: 'SQL01', ip: '192.0.2.12', type: 'server', role: 'Database' },
  { name: 'WEB01', ip: '192.0.2.13', type: 'server', role: 'Intranet Web' },
  { name: 'MAIL01', ip: '192.0.2.14', type: 'server', role: 'Mail' },
];

const serviceAccounts = ['svc_backup', 'svc_sql', 'svc_web'];
const analysts = ['analyst1', 'analyst2', 'analyst3', 'lead'];

const benignDomains = ['news.example', 'mail.example', 'cdn.example', 'updates.example', 'crm.example',
  'docs.example', 'weather.example', 'video.example', 'search.example', 'payroll.example',
  'intranet.corp.example', 'files.corp.example'];
const benignExternalIps = Array.from({ length: 40 }, (_, i) => `198.51.100.${10 + i}`);

const hosts = [...pcs, ...servers];
const hostByName = Object.fromEntries(hosts.map(h => [h.name, h]));

module.exports = {
  users, pcs, servers, hosts, hostByName, serviceAccounts, analysts,
  benignDomains, benignExternalIps,
  officeHours: { start: 7, end: 19 },
};
