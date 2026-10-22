// Simulated event generator: background noise + injected suspicious scenarios.
// All data is invented. No real tools, malware names or command lines.

const C = require('./company');
const intel = require('./intel');

const pick = a => a[Math.floor(Math.random() * a.length)];
const chance = p => Math.random() < p;
const rint = (lo, hi) => lo + Math.floor(Math.random() * (hi - lo + 1));

const WIN_MSG = {
  4624: 'An account was successfully logged on',
  4625: 'An account failed to log on',
  4672: 'Special privileges assigned to new logon',
  4720: 'A user account was created',
  4732: 'A member was added to a security-enabled local group',
};
const BENIGN_PROCS = ['winword.exe', 'excel.exe', 'outlook.exe', 'chrome.exe', 'teams.exe',
  'explorer.exe', 'notepad.exe', 'acrord32.exe', 'onedrive.exe', 'svchost.exe'];

function isOfficeHour(ts) {
  const d = new Date(ts);
  const h = d.getHours();
  const wd = d.getDay();
  return wd >= 1 && wd <= 5 && h >= C.officeHours.start && h < C.officeHours.end;
}

function win(ts, eventId, f) {
  return { ts, source: 'winsec', eventId, message: WIN_MSG[eventId], tags: [], ...f };
}

// ---------- Background noise ----------
function noise(ts) {
  const office = isOfficeHour(ts);
  const u = pick(C.users);
  const host = C.hostByName[u.pc];
  const r = Math.random();

  if (!office) {
    // Off hours: mostly server/service activity, little user activity
    if (r < 0.35) {
      const svc = pick(C.serviceAccounts);
      const srv = pick(C.servers);
      return win(ts, 4624, { host: srv.name, user: svc, srcIp: srv.ip, logonType: 5, action: 'success' });
    }
    if (r < 0.65) return firewall(ts, pick(C.servers));
    if (r < 0.95) return dns(ts, pick(C.servers), 'SYSTEM');
    return edrBenign(ts, pick(C.servers), 'SYSTEM');
  }

  if (r < 0.22) {
    const target = chance(0.7) ? host : pick(C.servers);
    return win(ts, 4624, { host: target.name, user: u.name, srcIp: host.ip,
      logonType: target.type === 'server' ? 3 : 2, action: 'success' });
  }
  if (r < 0.25) {
    // Normal typo: single failure
    return win(ts, 4625, { host: host.name, user: u.name, srcIp: host.ip, logonType: 2,
      action: 'failure', reason: 'Bad password' });
  }
  if (r < 0.28 && u.isAdmin) {
    return win(ts, 4672, { host: pick(C.servers).name, user: u.name, srcIp: host.ip, action: 'success' });
  }
  if (r < 0.5) return firewall(ts, host);
  if (r < 0.82) return dns(ts, host, u.name);
  if (r < 0.87) return mailDelivered(ts, u);
  if (r < 0.89) return mailClick(ts, u, host);
  if (r < 0.892) return changeTicket(ts);
  return edrBenign(ts, host, u.name);
}

// Mail gateway: delivered mail and clicks on links in mail (the gateway rewrites links, so it sees clicks)
const MAIL_SUBJECTS = ['Weekly team update', 'Invoice for September', 'Meeting notes', 'Your order has shipped',
  'Agenda for Thursday', 'Updated project plan', 'Training reminder', 'Holiday rota'];
function mailDelivered(ts, u) {
  const d = pick(C.benignDomains);
  const sender = `${pick(['info', 'team', 'noreply', 'accounts', 'office'])}@${d}`;
  const subject = pick(MAIL_SUBJECTS);
  return { ts, source: 'mail', host: 'MAIL01', user: u.name, action: 'delivered', sender, senderDomain: d,
    subject, urlDomain: d, spf: 'pass', recipients: rint(1, 20), message: `Email delivered from ${sender}: "${subject}"`, tags: [] };
}
function mailClick(ts, u, host) {
  const d = pick(C.benignDomains);
  return { ts, source: 'mail', host: host.name, user: u.name, srcIp: host.ip, action: 'link_click', urlDomain: d,
    domainAgeDays: rint(400, 6000), message: `Email link clicked: ${d}`, tags: [] };
}

// Change tickets from the IT service-management system (ITSM). Approved work has one; attackers don't.
const CHANGE_SUMMARIES = ['Monthly patching', 'Disk cleanup', 'Certificate renewal', 'Backup job reconfiguration', 'Service restart after update'];
const changeRef = () => `CHG-${rint(30000, 39999)}`;
function changeTicket(ts) {
  const srv = pick(C.servers);
  const admin = pick(C.users.filter(u => u.isAdmin));
  const ref = changeRef();
  const summary = `${pick(CHANGE_SUMMARIES)} on ${srv.name}`;
  return { ts, source: 'change', host: 'ITSM', user: admin.name, action: 'approved', changeRef: ref, approver: 'it-manager',
    hosts: [srv.name], windowMinutes: 120, summary, message: `Change ${ref} approved: ${summary} (window: 2 hours)`, tags: [] };
}

// A 203.0.113.x address that is not on the intel list (so only behaviour-based rules can catch it)
function unlistedIp(lo, hi, avoid = []) {
  for (let i = 0; i < 200; i++) {
    const ip = `203.0.113.${rint(lo, hi)}`;
    if (!intel.lists.badIps.has(ip) && !avoid.includes(ip)) return ip;
  }
  throw new Error('No unlisted 203.0.113.x address left in range');
}
const sample = (arr, n) => [...arr].sort(() => Math.random() - 0.5).slice(0, n);
// The fake company has a few users who share a login name; the newer scenarios avoid them so that
// "one failure per user" and "the user's own PC" stay unambiguous.
const uniqueUsers = C.users.filter(u => C.users.filter(x => x.name === u.name).length === 1);
const minsBetween = (a, b) => Math.round((b.ts - a.ts) / 60000);

function firewall(ts, host) {
  const blocked = chance(0.08);
  return {
    ts, source: 'firewall', host: host.name, srcIp: host.ip, dstIp: pick(C.benignExternalIps),
    dstPort: pick([443, 443, 443, 80, 53, 123]), action: blocked ? 'deny' : 'allow',
    message: blocked ? 'Outbound connection blocked by policy' : 'Outbound connection allowed', tags: [],
  };
}

function dns(ts, host, user) {
  const domain = pick(C.benignDomains);
  return { ts, source: 'dns', host: host.name, user, srcIp: host.ip, domain, action: 'query',
    message: `DNS query for ${domain}`, tags: [] };
}

function edrBenign(ts, host, user) {
  const proc = pick(BENIGN_PROCS);
  return { ts, source: 'edr', host: host.name, user, process: proc, action: 'process_start',
    severity: 'info', message: `Process started: ${proc}`, tags: [] };
}

// ---------- Injected scenarios ----------
// Each returns [{offsetMs, event}] so live mode can drip them out and seed mode can timestamp them.
// `expected` is the one-word verdict. `answer(events)` is the full answer key used by scenario mode
// (src/exercise.js): { verdict, severities, case, rules, explain, clues }.
//   severities: accepted list, or 'not_raised' = anything up to the rule's own severity (non-incidents)
//   case: 'required' | 'optional' | 'never'
const scenarios = {
  brute_force: {
    name: 'Brute force against a user account',
    expected: 'true_positive',
    answer(evs) {
      const success = evs.some(e => e.eventId === 4624);
      const ip = evs[0].srcIp;
      return success
        ? { verdict: 'true_positive', severities: ['critical'], case: 'required', rules: ['R001', 'R012'],
          explain: `Many failed logons from ${ip}, in the range used by suspicious actors, then a successful logon from the same address: the attacker guessed the password and got in.`,
          clues: [`The source ${ip} is external (203.0.113.x), not the user's own PC`, 'A 4624 success followed the burst of 4625 failures', 'A logon that succeeded means an account takeover: raise to critical and open a case'] }
        : { verdict: 'true_positive', severities: ['high'], case: 'optional', rules: ['R001'],
          explain: `Many failed logons from ${ip}, in the range used by suspicious actors. No logon succeeded, so the attack failed, but it was a real attack.`,
          clues: [`The source ${ip} is external (203.0.113.x), not the user's own PC`, 'No 4624 success followed, so the account was not taken over', 'Blocking the IP and closing the alert is enough; a case is optional'] };
    },
    build() {
      const u = pick(C.users);
      const target = chance(0.5) ? C.hostByName[u.pc] : C.hostByName.DC01;
      const src = chance(0.5) ? '203.0.113.77' : `203.0.113.${rint(1, 60)}`;
      const n = rint(6, 15);
      const out = [];
      for (let i = 0; i < n; i++) {
        out.push({ offsetMs: i * rint(2000, 8000), event: win(0, 4625, {
          host: target.name, user: u.name, srcIp: src, logonType: 3, action: 'failure',
          reason: 'Bad password', tags: ['scenario:brute_force'] }) });
      }
      if (chance(0.4)) {
        const last = out[out.length - 1].offsetMs;
        out.push({ offsetMs: last + 3000, event: win(0, 4624, {
          host: target.name, user: u.name, srcIp: src, logonType: 3, action: 'success',
          tags: ['scenario:brute_force'] }) });
      }
      return out;
    },
  },
  user_typos: {
    name: 'User repeatedly mistypes password (benign)',
    expected: 'benign',
    answer: () => ({ verdict: 'benign', severities: 'not_raised', case: 'never', rules: ['R001'],
      explain: 'Five failures from the user\'s own PC, typed at the keyboard, then a success a minute later: a person who mistyped their password. The rule worked correctly, the activity is allowed.',
      clues: ['The source IP is the user\'s own workstation (192.0.2.x), not an external address', 'Logon type 2 = at the keyboard', 'A success followed shortly after from the same PC'] }),
    build() {
      const u = pick(C.users);
      const host = C.hostByName[u.pc];
      const out = [];
      for (let i = 0; i < 5; i++) {
        out.push({ offsetMs: i * 10000, event: win(0, 4625, { host: host.name, user: u.name,
          srcIp: host.ip, logonType: 2, action: 'failure', reason: 'Bad password', tags: ['scenario:user_typos'] }) });
      }
      out.push({ offsetMs: 60000, event: win(0, 4624, { host: host.name, user: u.name, srcIp: host.ip,
        logonType: 2, action: 'success', tags: ['scenario:user_typos'] }) });
      return out;
    },
  },
  new_admin: {
    name: 'New account created and added to Administrators',
    expected: 'true_positive',
    answer: evs => ({ verdict: 'true_positive', severities: ['critical'], case: 'required', rules: ['R002', 'R003'],
      explain: `Account ${evs[0].targetUser} was created and 15 seconds later added to Administrators, with no change ticket. That is how attackers keep full control of a network.`,
      clues: ['4720 (account created) then 4732 (added to Administrators) for the same account', 'No changeRef on the events: no approved change covers it', 'Two alerts, one story: put both in the same case'] }),
    build() {
      const actor = pick(C.users.filter(u => u.isAdmin));
      const acct = `${pick(['helpdesk', 'support', 'temp', 'admin'])}_${rint(10, 99)}`;
      const t = 'scenario:new_admin';
      return [
        { offsetMs: 0, event: win(0, 4720, { host: 'DC01', user: actor.name, targetUser: acct, srcIp: '192.0.2.10', action: 'success', tags: [t] }) },
        { offsetMs: 15000, event: win(0, 4732, { host: 'DC01', user: actor.name, targetUser: acct, group: 'Administrators', srcIp: '192.0.2.10', action: 'success', tags: [t] }) },
      ];
    },
  },
  off_hours_login: {
    name: 'Interactive login at an unusual hour',
    expected: 'true_positive',
    unusualHour: true,
    answer: evs => ({ verdict: 'true_positive', severities: ['medium', 'high'], case: 'required', rules: ['R004'],
      explain: `${evs[0].user} is not in IT and logged on at the keyboard of ${evs[0].host} in the middle of the night. With no maintenance planned, treat it as stolen credentials until the user confirms.`,
      clues: ['The user is not an IT admin', 'Logon type 2 (at the keyboard) between 00:00 and 05:59', 'It arrived as a late log: the alert time is last night, but it only just appeared'] }),
    build() {
      const u = pick(C.users.filter(x => !x.isAdmin));
      const host = C.hostByName[u.pc];
      return [{ offsetMs: 0, event: win(0, 4624, { host: host.name, user: u.name, srcIp: host.ip,
        logonType: 2, action: 'success', tags: ['scenario:off_hours_login'] }) }];
    },
  },
  admin_patching: {
    name: 'IT admin logs in late for planned patching (benign)',
    expected: 'benign',
    unusualHour: true,
    answer: evs => ({ verdict: 'benign', severities: 'not_raised', case: 'never', rules: ['R004'],
      explain: `${evs[0].user} is one of the IT admins, logging on to their own PC late at night: planned patching work. The rule fired correctly, but the activity is allowed.`,
      clues: ['The user is an IT admin (one of the first four users)', 'Logon from their own workstation, not a server or external IP', 'Nothing suspicious happened after the logon'] }),
    build() {
      const u = pick(C.users.filter(x => x.isAdmin));
      const host = C.hostByName[u.pc];
      return [{ offsetMs: 0, event: win(0, 4624, { host: host.name, user: u.name, srcIp: host.ip,
        logonType: 2, action: 'success', tags: ['scenario:admin_patching'] }) }];
    },
  },
  c2_beacon: {
    name: 'Workstation beacons to a known-bad IP/domain',
    expected: 'true_positive',
    answer: evs => ({ verdict: 'true_positive', severities: ['high', 'critical'], case: 'required', rules: ['R005', 'R006'],
      explain: `${evs[0].host} looked up ${evs[0].domain} and then connected to ${evs[1].dstIp} every minute. Both are on the threat-intel list: the PC is talking to its controller (C2).`,
      clues: ['The DNS lookup and the IP are both on the intel list', 'Connections repeat at a regular interval (beaconing)', 'Two alerts (DNS + firewall) from one host: put both in the same case'] }),
    build() {
      const host = pick(C.pcs);
      const ip = pick(intel.badIps).value;
      const domain = pick(intel.badDomains).value;
      const t = 'scenario:c2_beacon';
      const out = [{ offsetMs: 0, event: { ts: 0, source: 'dns', host: host.name, user: 'SYSTEM',
        srcIp: host.ip, domain, action: 'query', message: `DNS query for ${domain}`, tags: [t] } }];
      for (let i = 0; i < 4; i++) {
        out.push({ offsetMs: 2000 + i * 60000, event: { ts: 0, source: 'firewall', host: host.name,
          srcIp: host.ip, dstIp: ip, dstPort: 443, action: 'allow',
          message: 'Outbound connection allowed', tags: [t] } });
      }
      return out;
    },
  },
  cred_dump: {
    name: 'EDR: suspicious credential dumping tool',
    expected: 'true_positive',
    answer: evs => ({ verdict: 'true_positive', severities: ['critical'], case: 'required', rules: ['R007'],
      explain: `The endpoint agent saw a credential dumping tool on ${evs[0].host}. Every password used on that host may be stolen: isolate it and reset credentials.`,
      clues: ['EDR action "detected" with a tool name that is not normal software', 'Check the hash in IOC Lookup: even if it is not on the list, the behaviour is the evidence', 'Who was logged on to the host? Their credentials are at risk'] }),
    build() {
      const host = chance(0.5) ? pick(C.pcs) : pick(C.servers);
      const u = pick(C.users);
      // Simulated hash: usually on the intel list, sometimes not (not on the list != safe)
      const fileHash = chance(0.7) ? pick(intel.badHashes).value : fakeHash();
      return [{ offsetMs: 0, event: { ts: 0, source: 'edr', host: host.name, user: u.name,
        process: 'unknown_tool.exe', fileHash, action: 'detected', severity: 'high',
        message: 'Suspicious credential dumping tool detected (simulated)', tags: ['scenario:cred_dump'] } }];
    },
  },
  new_starter_account: {
    name: 'IT admin creates an account for a new starter (benign)',
    expected: 'benign',
    answer: evs => ({ verdict: 'benign', severities: 'not_raised', case: 'never', rules: ['R002'],
      explain: `${evs[0].user} (IT) created ${evs[0].targetUser} under approved change ${evs[0].changeRef}, and the account was not added to any admin group: a normal new-starter request.`,
      clues: [`The event carries an approved change reference (${evs[0].changeRef})`, 'The creator is an IT admin', 'No 4732: the account was not made an administrator (compare with the new-admin attack)'] }),
    build() {
      const actor = pick(C.users.filter(u => u.isAdmin));
      const acct = `${pick(['k', 'm', 't', 'l', 'n'])}${pick(['nash', 'ford', 'pike', 'vale', 'moss'])}${rint(10, 99)}`;
      return [{ offsetMs: 0, event: win(0, 4720, { host: 'DC01', user: actor.name, targetUser: acct,
        srcIp: C.hostByName[actor.pc].ip, action: 'success', changeRef: `CHG-${rint(20000, 29999)}`,
        tags: ['scenario:new_starter_account'] }) }];
    },
  },
  backup_agent_edr: {
    name: 'EDR flags the backup agent reading protected memory (false positive)',
    expected: 'false_positive',
    answer: evs => ({ verdict: 'false_positive', severities: 'not_raised', case: 'never', rules: ['R007'],
      explain: `The detection on ${evs[0].host} is the company's own backup agent, run by svc_backup during the backup job. The rule's logic matched something it should not have: a false positive. Tune the rule (an exception for the signed backup agent).`,
      clues: ['Process backup_agent.exe signed by the backup vendor, run by the svc_backup service account', 'The hash is not on the intel list and nothing else happened on the host', 'Benign vs false positive: the activity is allowed AND the rule was wrong to call it credential dumping, so false positive'] }),
    build() {
      const host = pick(C.servers.filter(s => ['SQL01', 'FS01'].includes(s.name)));
      return [{ offsetMs: 0, event: { ts: 0, source: 'edr', host: host.name, user: 'svc_backup',
        process: 'backup_agent.exe', signer: 'Example Backup Vendor (simulated)', fileHash: fakeHash(),
        action: 'detected', severity: 'medium', message: 'Backup agent read protected memory (simulated)',
        tags: ['scenario:backup_agent_edr'] } }];
    },
  },

  // ---------- Phishing, spraying, lateral movement, beacons ----------
  phishing_link: {
    name: 'Phishing email: user clicks a link to a new lookalike site',
    expected: 'true_positive',
    answer(evs) {
      const [mail, click] = evs;
      const submit = evs.find(e => e.action === 'form_submit');
      const logon = evs.find(e => e.eventId === 4624);
      const base = [`Sender ${mail.sender} failed SPF and the domain ${mail.senderDomain} is ${click.domainAgeDays} day(s) old`,
        `Urgent password subject sent to only ${mail.recipients} recipient(s): targeted, not a newsletter`,
        'The link went to a 203.0.113.x address that is not on the intel list: not on the list does not mean safe'];
      return submit
        ? { verdict: 'true_positive', severities: ['critical'], case: 'required', rules: ['R008', 'R012'],
          explain: `${click.user} clicked a phishing link and typed their password into the fake page on ${click.urlDomain}. ${minsBetween(submit, logon)} minutes later someone logged on as ${click.user} from ${logon.srcIp}, an address never seen before: the account is taken over.`,
          clues: [...base, `A form_submit event shows the password was entered on the fake page`,
            `Search Log Search for the user: a 4624 logon to ${logon.host} from new IP ${logon.srcIp} came after the click. R012 flags it, but only Log Search shows it followed the click`,
            'Stolen password used from a new IP: raise to critical, reset the password and open a case'] }
        : { verdict: 'true_positive', severities: ['high'], case: 'optional', rules: ['R008'],
          explain: `${click.user} clicked a link in a phishing email to ${click.urlDomain}, a days-old lookalike site. No credentials were submitted and no logon from a new IP followed, so the attack did not succeed yet.`,
          clues: [...base, 'No form_submit and no logon from a new 203.0.113.x IP after the click',
            'Block the domain, purge the email from other mailboxes and warn the user; a case is optional'] };
    },
    build() {
      const u = pick(uniqueUsers.filter(x => !x.isAdmin));
      const pc = C.hostByName[u.pc];
      const domain = pick(['account-verify-desk.example', 'mailbox-quota-alert.example', 'payroll-docs-share.example', 'secure-signin-check.example']);
      const age = rint(1, 6);
      const ip = unlistedIp(151, 199);
      const sender = `it-helpdesk@${domain}`;
      const t = 'scenario:phishing_link';
      const clickAt = rint(30, 120) * 1000;
      const out = [
        { offsetMs: 0, event: { ts: 0, source: 'mail', host: 'MAIL01', user: u.name, action: 'delivered', sender, displayName: 'IT Helpdesk',
          senderDomain: domain, subject: 'Action required: your mailbox password expires today', urlDomain: domain, spf: 'fail',
          recipients: rint(1, 3), message: `Email delivered from ${sender}: "Action required: your mailbox password expires today"`, tags: [t] } },
        { offsetMs: clickAt, event: { ts: 0, source: 'mail', host: pc.name, user: u.name, srcIp: pc.ip, action: 'link_click',
          urlDomain: domain, domainAgeDays: age, message: `Email link clicked: ${domain}`, tags: [t] } },
        { offsetMs: clickAt + 1000, event: { ts: 0, source: 'dns', host: pc.name, user: u.name, srcIp: pc.ip, domain, action: 'query',
          message: `DNS query for ${domain}`, tags: [t] } },
        { offsetMs: clickAt + 2000, event: { ts: 0, source: 'firewall', host: pc.name, srcIp: pc.ip, dstIp: ip, dstPort: 443,
          action: 'allow', message: 'Outbound connection allowed', tags: [t] } },
      ];
      if (chance(0.5)) {
        const submitAt = clickAt + rint(20, 60) * 1000;
        out.push({ offsetMs: submitAt, event: { ts: 0, source: 'mail', host: pc.name, user: u.name, srcIp: pc.ip, action: 'form_submit',
          urlDomain: domain, message: `Credentials form submitted on ${domain}`, tags: [t] } });
        // The attacker uses the password from a new address. R012 alerts on it; linking it to the click is the analyst's job.
        out.push({ offsetMs: submitAt + rint(180, 300) * 1000, event: win(0, 4624, { host: 'MAIL01', user: u.name,
          srcIp: unlistedIp(151, 199, [ip]), logonType: 3, action: 'success', tags: [t] }) });
      }
      return out;
    },
  },
  newsletter_click: {
    name: 'User clicks a link in a newsletter from a new domain (benign)',
    expected: 'benign',
    answer: evs => ({ verdict: 'benign', severities: 'not_raised', case: 'never', rules: ['R008'],
      explain: `${evs[1].user} clicked a link in a marketing newsletter from ${evs[0].senderDomain}. The domain really is new (${evs[1].domainAgeDays} days), so the rule worked, but the mail is a legitimate bulk newsletter: benign.`,
      clues: [`SPF passed and the mail went to ${evs[0].recipients} people with an unsubscribe link: bulk marketing, not targeted`,
        'The link went to a normal internet address (198.51.100.x)', 'No credentials form, no new logons, nothing else happened afterwards'] }),
    build() {
      const u = pick(uniqueUsers);
      const pc = C.hostByName[u.pc];
      const domain = pick(['weekly-digest-news.example', 'events-roundup.example', 'trade-show-updates.example']);
      const sender = `news@${domain}`;
      const subject = 'This week: industry roundup and upcoming webinars';
      const t = 'scenario:newsletter_click';
      const clickAt = rint(30, 120) * 1000;
      return [
        { offsetMs: 0, event: { ts: 0, source: 'mail', host: 'MAIL01', user: u.name, action: 'delivered', sender, senderDomain: domain,
          subject, urlDomain: domain, spf: 'pass', listUnsubscribe: true, recipients: rint(25, 45),
          message: `Email delivered from ${sender}: "${subject}"`, tags: [t] } },
        { offsetMs: clickAt, event: { ts: 0, source: 'mail', host: pc.name, user: u.name, srcIp: pc.ip, action: 'link_click',
          urlDomain: domain, domainAgeDays: rint(8, 25), message: `Email link clicked: ${domain}`, tags: [t] } },
        { offsetMs: clickAt + 1000, event: { ts: 0, source: 'dns', host: pc.name, user: u.name, srcIp: pc.ip, domain, action: 'query',
          message: `DNS query for ${domain}`, tags: [t] } },
        { offsetMs: clickAt + 2000, event: { ts: 0, source: 'firewall', host: pc.name, srcIp: pc.ip, dstIp: pick(C.benignExternalIps),
          dstPort: 443, action: 'allow', message: 'Outbound connection allowed', tags: [t] } },
      ];
    },
  },
  password_spray: {
    name: 'Password spraying from one external address',
    expected: 'true_positive',
    answer(evs) {
      const ip = evs[0].srcIp;
      const tried = new Set(evs.map(e => e.user)).size;
      const ok = evs.find(e => e.eventId === 4624);
      const base = [`One source (${ip}) failed against ${tried} different users, about once each`,
        'Each user has only one failure, so the brute-force rule (5 per user) never fires: that is the point of spraying'];
      return ok
        ? { verdict: 'true_positive', severities: ['critical'], case: 'required', rules: ['R009', 'R012'],
          explain: `${ip} tried one password against ${tried} accounts on ${evs[0].host} and it worked for ${ok.user}: an account was taken over.`,
          clues: [...base, `A 4624 success for ${ok.user} from the same IP: reset that password, raise to critical and open a case`] }
        : { verdict: 'true_positive', severities: ['high'], case: 'optional', rules: ['R009'],
          explain: `${ip} tried one password against ${tried} accounts on ${evs[0].host}. No logon succeeded, but it was a real attack.`,
          clues: [...base, 'No 4624 success from that IP: block it and close the alert; a case is optional'] };
    },
    build() {
      const ip = unlistedIp(100, 140);
      const victims = sample(uniqueUsers, rint(8, 15));
      const t = 'scenario:password_spray';
      const out = [];
      let at = 0;
      for (const u of victims) {
        out.push({ offsetMs: at, event: win(0, 4625, { host: 'DC01', user: u.name, srcIp: ip, logonType: 3,
          action: 'failure', reason: 'Bad password', tags: [t] }) });
        at += rint(15, 40) * 1000;
      }
      if (chance(0.35)) {
        out.push({ offsetMs: at, event: win(0, 4624, { host: 'DC01', user: pick(victims).name, srcIp: ip, logonType: 3,
          action: 'success', tags: [t] }) });
      }
      return out;
    },
  },
  lateral_movement: {
    name: 'Stolen account hops across several workstations',
    expected: 'true_positive',
    answer: evs => ({ verdict: 'true_positive', severities: ['high', 'critical'], case: 'required', rules: ['R010'],
      explain: `${evs[0].user} (not IT) logged on over the network to ${evs.length} other workstations from ${C.hosts.find(h => h.ip === evs[0].srcIp).name}, which is not their own PC. With no change ticket, this is an attacker spreading with a stolen account.`,
      clues: [`The user is not an IT admin and their own PC is ${C.users.find(u => u.name === evs[0].user).pc}`,
        'Logon type 3 (over the network) to several workstations a few minutes apart', 'No change ticket in the change log covers this',
        'Isolate the source PC and reset the account; one case for the whole spread'] }),
    build() {
      const u = pick(uniqueUsers.filter(x => !x.isAdmin));
      const src = pick(C.pcs.filter(p => p.name !== u.pc));
      const targets = sample(C.pcs.filter(p => p.name !== u.pc && p.name !== src.name), 4);
      return targets.map((h, i) => ({ offsetMs: i * rint(60, 150) * 1000, event: win(0, 4624, { host: h.name, user: u.name,
        srcIp: src.ip, logonType: 3, action: 'success', tags: ['scenario:lateral_movement'] }) }));
    },
  },
  admin_maintenance: {
    name: 'IT admin installs an update on several PCs under a change ticket (benign)',
    expected: 'benign',
    answer: evs => ({ verdict: 'benign', severities: 'not_raised', case: 'never', rules: ['R010'],
      explain: `${evs[1].user} (IT) logged on over the network to ${evs.length - 1} workstations from their own PC. Change ${evs[0].changeRef}, approved ${minsBetween(evs[0], evs[1])} minutes earlier, covers exactly these hosts. The rule fired correctly; the work is planned.`,
      clues: [`Search the change log (source "change") for ${evs[0].changeRef}: it lists ${evs[0].hosts.join(', ')}`,
        'The user is an IT admin and the logons come from their own PC', 'The logons fall inside the change window; nothing else happened on those PCs'] }),
    build() {
      const admin = pick(uniqueUsers.filter(x => x.isAdmin));
      const pc = C.hostByName[admin.pc];
      const targets = sample(C.pcs.filter(p => p.name !== pc.name), rint(4, 5));
      const ref = changeRef();
      const summary = `Install printer driver update on ${targets.map(h => h.name).join(', ')}`;
      const t = 'scenario:admin_maintenance';
      return [
        { offsetMs: -20 * 60e3, event: { ts: 0, source: 'change', host: 'ITSM', user: admin.name, action: 'approved', changeRef: ref,
          approver: 'it-manager', hosts: targets.map(h => h.name), windowMinutes: 120, summary,
          message: `Change ${ref} approved: ${summary} (window: 2 hours)`, tags: [t] } },
        ...targets.map((h, i) => ({ offsetMs: i * rint(90, 180) * 1000, event: win(0, 4624, { host: h.name, user: admin.name,
          srcIp: pc.ip, logonType: 3, action: 'success', tags: [t] }) })),
      ];
    },
  },
  external_logon: {
    name: 'Successful logon from an internet address',
    expected: 'true_positive',
    answer(evs) {
      const e = evs[0];
      const how = e.logonType === 10 ? 'Remote Desktop (logon type 10)' : 'over the network (logon type 3)';
      return { verdict: 'true_positive', severities: ['high', 'critical'], case: 'required', rules: ['R012'],
        explain: `${e.user} logged on to ${e.host} ${how} from ${e.srcIp}, an internet address and not a company one. The password was accepted, so someone outside the company is using this account.`,
        clues: [`The source ${e.srcIp} is in 203.0.113.x, the internet range; company addresses are 192.0.2.x`,
          'A 4624 is a successful logon: the credentials were accepted',
          `${e.user} normally works from ${C.users.find(u => u.name === e.user).pc}, not from the internet`,
          'No failed logons came first, so this is not guessing: the attacker already had the password (phishing, reuse or a leak)',
          'Reset the password, end the session, block the address and open a case'] };
    },
    build() {
      const u = pick(uniqueUsers.filter(x => !x.isAdmin));
      const host = pick(C.servers);
      return [{ offsetMs: 0, event: win(0, 4624, { host: host.name, user: u.name, srcIp: unlistedIp(201, 250),
        logonType: chance(0.5) ? 10 : 3, action: 'success', tags: ['scenario:external_logon'] }) }];
    },
  },
  beacon_unlisted: {
    name: 'Workstation beacons to an address that is on no intel list',
    expected: 'true_positive',
    answer: evs => ({ verdict: 'true_positive', severities: ['high', 'critical'], case: 'required', rules: ['R011'],
      explain: `${evs[0].host} connected to ${evs[0].dstIp} ${evs.length} times about once a minute. The IP is on no intel list, but software checking in on a timer is how malware talks to its controller.`,
      clues: [`Connections from one host to ${evs[0].dstIp} at near-identical intervals (beaconing)`,
        'The IP is not on the intel list, so the known-bad IP rule (R005) stayed quiet: behaviour caught it',
        'No DNS lookup before it: the software connects straight to an IP', 'Isolate the host, add the IP to the intel list and to a case'] }),
    build() {
      const host = pick(C.pcs);
      const ip = unlistedIp(200, 249);
      let at = 0;
      return Array.from({ length: 6 }, (_, i) => {
        if (i) at += 60000 + rint(-2000, 2000);
        return { offsetMs: at, event: { ts: 0, source: 'firewall', host: host.name, srcIp: host.ip, dstIp: ip, dstPort: 443,
          action: 'allow', message: 'Outbound connection allowed', tags: ['scenario:beacon_unlisted'] } };
      });
    },
  },
};

// Obviously artificial SHA-256 (48 zeros + 16 random hex) — never matches a real file
function fakeHash() {
  let h = '';
  for (let i = 0; i < 16; i++) h += Math.floor(Math.random() * 16).toString(16);
  return '0'.repeat(48) + h;
}

// Pick a time for an "unusual hour" scenario (between 01:00 and 04:59) on the given day
function unusualTime(baseTs) {
  const d = new Date(baseTs);
  d.setHours(rint(1, 4), rint(0, 59), rint(0, 59), 0);
  return d.getTime();
}

// Expand a scenario into timestamped events starting at startTs
function expand(key, startTs) {
  const s = scenarios[key];
  if (!s) throw new Error(`Unknown scenario: ${key}`);
  return s.build().map(({ offsetMs, event }) => ({ ...event, ts: startTs + offsetMs }));
}

// Build 24h of history (lower rate so it fits under the event cap) with scenarios sprinkled in
function seedHistory(nowTs, hours = 24, perSecond = 0.2) {
  const start = nowTs - hours * 3600e3;
  const events = [];
  const step = 1000 / perSecond;
  for (let t = start; t < nowTs; t += step * (0.5 + Math.random())) events.push(noise(Math.round(t)));
  const keys = Object.keys(scenarios);
  for (let i = 0; i < Math.max(10, keys.length); i++) {
    const key = keys[i % keys.length];
    let ts = start + Math.random() * (hours - 1) * 3600e3;
    if (scenarios[key].unusualHour) {
      ts = unusualTime(ts);
      if (ts < start) ts += 24 * 3600e3;
      if (ts > nowTs - 3600e3) ts -= 24 * 3600e3;
    }
    events.push(...expand(key, Math.round(ts)));
  }
  return events.filter(e => e.ts <= nowTs).sort((a, b) => a.ts - b.ts);
}

module.exports = { noise, scenarios, expand, seedHistory, isOfficeHour, unusualTime };
