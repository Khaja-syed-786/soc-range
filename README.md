# SOC Training Simulator

A practice Security Operations Center that runs entirely on your PC at **http://127.0.0.1:5000**.
It generates a live stream of security logs for a fictional company, detects attacks in that stream with a small
SIEM rule engine, and gives you an analyst console to triage alerts, run incident cases and practise scored exercises.

I built it to learn and demonstrate the day-to-day work of a SOC analyst (detection, triage, incident response,
threat-intel pivoting and shift handover) without needing a real network, real logs or commercial tooling.

> **Simulated data only.** Every log, user, host, IP address, domain, file hash and "attack" is made up by the
> built-in generator. IPs come only from the documentation ranges `192.0.2.0/24`, `198.51.100.0/24` and
> `203.0.113.0/24`, and domains end in the reserved `.example` TLD. The app reads no real logs, makes no
> outbound network calls and refuses real-looking IPs, domains and hashes in its lookups. It contains no real
> malware or attack tooling.

## Overview

A self-contained Security Operations Center training range: a fake company produces a live stream of Windows,
firewall, DNS, EDR, mail and change-ticket logs. A small SIEM engine detects attacks in that stream, and an analyst
console takes each alert through triage, incident cases, threat-intel pivots, scored exercises and shift handover.
Everything is simulated and runs on one machine with a single runtime dependency (Express).

### Features

| Area | In this project |
|---|---|
| Detection engineering | 11 JSON rules across 4 rule types: single-event match, threshold (raw or distinct-value counts), intel lookup and beacon (interval regularity). Each rule is tuned against background noise, and a soak test checks the false-positive rate |
| SOC triage | Alert queue with assignee, status, verdict (TP / FP / benign), analyst-adjustable severity and alert de-duplication |
| Incident response | Cases that follow the NIST SP 800-61 lifecycle, a merged timeline, IOCs on cases and per-rule playbooks |
| Threat intelligence | IOC lookup and pivoting over local data, an editable intel list, MITRE ATT&CK coverage and activity heatmap |
| Analyst training | 15 scenarios (attacks plus benign and false-positive look-alikes), each with a computed answer key, and scoring on verdict, severity, escalation, MTTA/MTTR, playbook use and notes |
| Operations | Shift-handover report with an auto-generated watch list and print-to-PDF |
| Safe-by-design engineering | Binds to 127.0.0.1 only; documentation-range IPs and `*.example` domains only; validators refuse real-looking IPs, domains and hashes; no outbound calls; CSRF header on state changes |

### Detection rules

| ID | Detects | Type | MITRE |
|---|---|---|---|
| R001 | Brute force: 5+ failures for one user in 2 min | threshold | T1110 |
| R002 | New user account created | match | T1136 |
| R003 | Account added to Administrators | match | T1098 |
| R004 | Interactive logon at 00:00–05:59 | match | T1078 |
| R005 | Connection to an intel-listed IP | lookup | T1071 |
| R006 | DNS lookup of an intel-listed domain | lookup | T1071.004 |
| R007 | EDR credential-dumping behaviour | match | T1003 |
| R008 | Email link clicked to a domain under 30 days old | match | T1566 |
| R009 | Password spraying: one source, 5+ distinct users | threshold (distinct) | T1110.003 |
| R010 | Lateral movement: one account, 3+ workstations over the network | threshold (distinct) | T1021 |
| R011 | Beacon: 6 regular connections to the same IP | beacon | T1071 |

### Built in phases

| Phase | Added |
|---|---|
| 1 | Event generator, rule engine, alert queue, log search, dashboard (MTTD/MTTR) |
| 2 | Incident cases (NIST phases), timeline, playbooks |
| 3 | MITRE ATT&CK heatmap, IOC lookup, editable threat-intel list |
| 4 | Scored exercise mode with answer keys, shift handover |
| 5 | Phishing, password spraying, lateral movement and beacon-behaviour detections; `mail` and `change` log sources |

### Architecture

```
generator.js --events--> store.js (in memory, saved to %LOCALAPPDATA%) --> detection.js (rules/*.json)
                                                                              |
     public/ (vanilla JS UI)  <--  server.js (Express, 127.0.0.1)  <--  alerts / cases / playbooks /
                                                                        ioc / mitre / exercise / handover
```

### Tech stack

- **Node.js 22+** and **Express 4** (the only runtime dependency)
- Plain HTML, CSS and JavaScript front end: no framework, no build step, no CDN
- JSON files for detection rules, playbooks, threat intel and scoring, editable without code changes
- **77 automated tests** with the built-in `node:test` runner (see [Tests](#tests))

### Screenshots

All screenshots show simulated data only.

| Dashboard | Alert Queue |
|---|---|
| ![Dashboard with KPIs, severity mix and alerts per hour](docs/screenshots/dashboard.png) | ![Alert Queue with simulated alerts](docs/screenshots/alerts.png) |
| **Log Search** | **MITRE ATT&CK coverage** |
| ![Log Search over simulated events](docs/screenshots/search.png) | ![MITRE ATT&CK detection coverage heatmap](docs/screenshots/mitre.png) |
| **IOC Lookup** | **Shift handover** |
| ![IOC Lookup and the fake threat-intel list](docs/screenshots/ioc.png) | ![Shift handover report with watch list](docs/screenshots/handover.png) |

## Getting started

Requires **Node.js 22 or later**.

```bash
git clone https://github.com/Khaja-syed-786/soc-sim.git
cd soc-sim
npm install
npm start
```

Then open **http://127.0.0.1:5000**. On first start the simulator seeds 24 hours of history so the dashboard is
not empty. On Windows you can also use the helper scripts:

```
start.cmd      (or .\start.ps1)  - installs deps on first run, starts in background, opens browser
stop.cmd       (or .\stop.ps1)   - saves state and stops
```

State (events, alerts, notes) is saved to `%LOCALAPPDATA%\SocSim\state.json` every 30 seconds and on
shutdown. To change the location, set `"dataDir"` in `config.json` (or the `SOCSIM_DATA_DIR` environment
variable). Logs from the background server go to the same folder.

Other settings in `config.json`: `eventCap` (default 50,000, about one day at the default rate),
`defaultRate` (1 event/second), `scenarioEveryMinutes` (how often attacks are auto-injected).

## Tests

The project has **77 automated tests** using Node's built-in test runner. They need no extra packages and no
network access.

```bash
npm test
```

| File | Covers |
|---|---|
| `test/core.test.js` | Event generator, detection rules, alert queue and triage, cases, playbooks, state persistence and upgrades |
| `test/mitre-ioc.test.js` | MITRE ATT&CK coverage and activity heatmap, IOC lookup, editable intel list, IOCs on cases |
| `test/exercise-handover.test.js` | Scenario mode and scoring, answer keys, MTTA/MTTR, shift handover |
| `test/advanced-detections.test.js` | Phishing, password spraying, lateral movement and beacon detections, and a false-positive soak test |

## The fake company

* 50 users (the first 4 are IT admins), 30 workstations `WS-001`…`WS-030`, 5 servers:
  `DC01` (domain controller), `FS01` (files), `SQL01` (database), `WEB01` (intranet), `MAIL01` (mail).
* Office hours are Mon–Fri 07:00–19:00. Outside those hours there's mostly server and service-account activity.
* IPs: internal = `192.0.2.x`, normal internet = `198.51.100.x`, "bad guys" = `203.0.113.x`.
  These are special ranges reserved for documentation and are never real hosts. Domains all end in `.example`.

## Screens

| Screen | What you do there |
|---|---|
| **Dashboard** | See the overall picture: open alerts, severity mix, trends, MTTD/MTTR |
| **Alert Queue** | Triage: pick an alert, assign it, investigate, give a verdict, close it |
| **Log Search** | Hunt through raw events by time, host, user, event ID, keyword |
| **Rules** | Read and edit the detection rules (JSON) |
| **Generator** | Speed up/pause the noise, inject an attack scenario on demand, reset |

---

## SOC concepts in plain words

### What is a SOC?
A Security Operations Center is the team (and the room full of screens) that watches a company's
computers 24/7 for signs of attack. Analysts look at **alerts**, decide which ones are real, and
start the response when something bad is happening.

### Events and logs
An **event** is one record of something that happened: "user X logged on to PC Y at 10:02".
Computers produce thousands per hour. Collected together they're **logs**. This simulator creates four kinds:

| Source | What it records |
|---|---|
| `winsec` | Windows Security log (logons, account changes) |
| `firewall` | Network connections allowed or blocked at the edge |
| `dns` | Which domain names computers looked up (like a phone book lookup) |
| `edr` | The endpoint agent on each PC (EDR = Endpoint Detection & Response), which watches programs running |

### Windows Event IDs you'll see

| ID | Meaning | Why analysts care |
|---|---|---|
| **4624** | Successful logon | Who got in, where, from where. *Logon type 2* = at the keyboard, *3* = over the network, *5* = a service |
| **4625** | Failed logon | One is a typo. Lots in a row is someone guessing passwords |
| **4672** | Special (admin) privileges given to a logon | Admin activity should be rare and expected |
| **4720** | A user account was created | Attackers create accounts so they can get back in later |
| **4732** | Member added to a local security group | Being added to *Administrators* = full control of the machine |

### SIEM and detection rules
A **SIEM** (Security Information and Event Management) gathers all the logs in one place and runs
**detection rules** over them. When a rule matches, it creates an **alert**. This app is a tiny SIEM.

Rules live in `rules/rules.json`. There are three types:

* **match**: one event is enough. *"Someone was added to Administrators."*
* **threshold**: count matching events per user/host inside a time window. *"5+ failed logons for the same user in 2 minutes."*
* **lookup**: check a field against a threat-intel list. *"Connection to an IP on the bad list."*

Rule fields:

| Field | Meaning |
|---|---|
| `filter` | Field/value pairs an event must have, e.g. `{"source":"winsec","eventId":4625}`. A value can be a list (any of), or `{"between":[a,b]}`, `{"not":x}`, `{"gte":n}`, `{"lte":n}`, `{"contains":"text"}`. The virtual field `hour` is the hour of the event (0–23) |
| `groupBy` | What the rule counts or groups by (`user`, `host`, `targetUser`…). This becomes the alert's *entity* |
| `count`, `windowSeconds` | For threshold rules |
| `field`, `list` | For lookup rules (`badIps` or `badDomains`) |
| `suppressSeconds` | While an alert for the same rule and entity is still open, new matches are added to it instead of creating duplicates. This is **alert de-duplication** and it stops "alert storms" |
| `severity`, `mitre` | Copied onto the alert |

Try it: change R001's `count` to 3, save, and watch more brute-force alerts appear (and more false positives).
That's the core trade-off of detection engineering: **catch more vs. get buried in noise**.

### Alerts and triage
**Triage** means sorting alerts quickly: *is this real, how bad is it, who handles it?* A typical flow:

1. Take the newest **critical/high** alert and set it to **Investigating** with yourself as **assignee**.
2. Read the related events. Open them in Log Search and look at what else that user/host did around that time.
3. Write **notes**: what you checked, what you found. The next analyst (or the auditor) depends on them.
4. Give a **verdict** and **Close** it.

### Severity
How bad it would be if the alert is real: **low → medium → high → critical**. It decides what you look at first.

### Verdicts: true positive, false positive, benign
* **True positive (TP)**: the rule fired and it really is malicious. *Escalate / respond.*
* **False positive (FP)**: the rule fired but it was wrong. The logic matched something it shouldn't have. *Tune the rule.*
* **Benign**: the rule worked correctly, the activity really happened, but it's allowed.
  e.g. an IT admin logging on at 2 a.m. for planned patching. *Document it and maybe add an exception.*

Tracking verdicts tells you which rules are worth keeping.

### MITRE ATT&CK
A free public catalogue of attacker techniques, each with an ID. Tagging alerts with them gives everyone a
shared language and shows which kinds of attacks you can detect. Tags used here:

| ID | Technique | In this sim |
|---|---|---|
| T1110 | Brute Force | many failed logons |
| T1136 | Create Account | 4720 |
| T1098 | Account Manipulation | added to Administrators |
| T1078 | Valid Accounts | stolen password used at odd hours |
| T1071 / T1071.004 | Application Layer Protocol (C2), DNS | malware talking to its controller |
| T1003 | OS Credential Dumping | EDR sees a password-stealing tool |

(The MITRE link in an alert opens the public website in *your browser*. The app itself never connects out.)

### Threat intel and IOCs
**Threat intelligence** is shared knowledge about attackers. **IOCs** (Indicators of Compromise) are concrete
clues like bad IP addresses, domains or file hashes. The fake intel list is on the Generator page (`src/intel.js`).

### C2 (Command and Control) and beaconing
Malware on an infected PC "phones home" to the attacker's server at regular intervals to get instructions.
Regular repeated connections to the same outside IP are called **beaconing**.

### MTTD and MTTR
* **MTTD (Mean Time To Detect)**: average time from the *first suspicious event* to the *alert*. Lower = better rules.
  For a brute force it's the time it took to reach 5 failures.
* **MTTR (Mean Time To Respond)**: average time from *alert created* to *alert closed*. Lower = faster analysts.
  It only counts closed alerts, so close some and watch it change.

### Noise
Most events are completely normal: people logging on, browsing, opening Word. Finding the few bad ones in all
that **noise** is the real job.

---

## Practice scenarios (Generator → "Inject a scenario now")

| Scenario | What to look for | Expected verdict |
|---|---|---|
| Brute force | Burst of 4625 from a `203.0.113.x` IP. Did a 4624 **success** follow? That means the attacker got in | True positive |
| User mistypes password | 5 failures from the user's *own* PC IP, then a success | Benign |
| New account + Administrators | 4720 then 4732 on DC01. Was there a change ticket? (There never is, here.) | True positive |
| Unusual-hour logon (normal user) | Keyboard logon at 01:00–05:00 by a non-IT user | True positive |
| Admin late-night patching | Same alert, but the user is an IT admin | Benign |
| Beacon to known-bad IP | DNS lookup of a bad domain, then repeated connections every minute | True positive |
| Credential dumping tool | EDR detection on a host. Check who was logged on there | True positive |

Tip: for any alert, open its events in Log Search, then clear the `ids` filter and search the same **host**
or **user** to see what happened before and after.

## Project layout

```
server.js            Express API + static UI (binds to 127.0.0.1 only)
config.json          settings (data dir, port, cap, rate)
rules/rules.json     detection rules
src/company.js       fake users/hosts
src/generator.js     background noise + scenarios, each with an answer key
src/detection.js     rule engine
src/alerts.js        alert queue, triage, stats
src/engine.js        generator → store → detection → alerts, live loop
src/store.js         in-memory state + JSON persistence
src/intel.js         fake threat intel
src/cases.js         incident cases (NIST lifecycle), timeline
src/playbooks.js     per-rule playbooks
src/mitre.js         ATT&CK catalogue, coverage + activity heatmap
src/ioc.js           indicator classification and lookup
src/exercise.js      scored scenario mode
src/handover.js      shift handover report
rules/*.json         rules, playbooks, threat intel, scoring weights
public/              UI (vanilla JS, no CDN)
test/                node:test tests (77)
```

---

## Incident cases and playbooks

New screen: **Cases** (top nav, with a badge showing open cases). The Alert Queue detail panel now also
shows a **playbook checklist** and an **Escalate to case** control.

New files:

```
rules/playbooks.json playbook checklists (editable JSON, like rules.json)
src/playbooks.js     load/validate playbooks, auto-attach to alerts, step updates
src/cases.js         incident cases, NIST phases, merged timeline
```

The state file is now `version: 2` (adds `cases`, `nextCaseId`, and `playbook`/`caseId` on each alert).
Old v1 state files are upgraded automatically on start; existing alerts get their playbook attached.

### Alerts vs. incident cases

An **alert** is one signal from one rule: "5 failed logons for anna.k". Most alerts are triaged and closed
on their own, often as false positives or benign.

An **incident case** is what you open when alerts point to a *real* security incident that needs
coordinated work. One attack usually sets off several rules. For example, password guessing (R001), then
an off-hours logon (R004), then a new admin account (R003). A case puts all of those alerts in one place, with:

- **One timeline**: every related event, alert, note and case update in time order, so you can see the
  attack's story ("guessing at 02:10, success at 02:14, account created at 02:20").
- **Owner**: one analyst is responsible for the case end to end.
- **Severity**: starts at the highest severity of its alerts; you can raise or lower it.
- **Status**: the NIST lifecycle phase the response is in (see below).
- **Final summary**: what happened, impact, root cause, actions taken and lessons learned. You must write it
  before you can close the case.

**When to escalate:** escalate an alert when it is (or might be) a true positive *and* needs more than a
quick fix. Examples: an attacker got in, a host needs isolating, more than one alert involves the same
user/host, or other teams need to be involved. Don't escalate obvious false positives. Close them as alerts.

In this simulator an alert can belong to **one** case. Closing a case closes its open alerts too
(verdict `true_positive` unless you set a different verdict first).

### The NIST incident response lifecycle

NIST (the US National Institute of Standards and Technology) publishes guidance on handling incidents
(SP 800-61). It describes a lifecycle most SOCs follow. The simulator uses these phases as the case
status, shown as the clickable stepper at the top of a case:

| Phase | Question it answers | What you do (examples from the simulator) |
|---|---|---|
| **1. Detection** | Is something happening? | An alert fires and you escalate it. The case starts here. |
| **2. Analysis** | What exactly happened, and how bad is it? | Read the timeline, search logs for the user/host, check intel, work the playbook steps, add other related alerts to the case. |
| **3. Containment** | How do we stop it spreading? | Lock the account, isolate the host, block the bad IP/domain. Short-term actions to limit damage. |
| **4. Eradication** | How do we remove the cause? | Remove the unauthorised admin account, clean or rebuild the host, remove the tool. |
| **5. Recovery** | How do we get back to normal safely? | Restore the host to service, re-enable the user with a new password, watch for the attacker coming back. |
| **6. Post-incident** | What did we learn? | Write the final summary: root cause, what worked, what to improve (new rule? faster escalation?). Then close the case. |

Real incidents are not always linear. You may find a second infected host during Recovery and go back to
Analysis/Containment. That is why the stepper lets you move to any phase. Every change is recorded in the
case timeline, so the history stays honest.

(NIST's newer revision groups these into broader functions, but the six phases above are still the
standard way to learn incident handling.)

### Playbooks

A **playbook** (or runbook) is a step-by-step checklist for a type of alert. It makes sure every analyst
checks the same things in the same order, even at 3 a.m., and it is how new analysts learn what "good
triage" looks like.

Each rule has a playbook, and it **attaches automatically** when the alert is created:

| Playbook | Rules |
|---|---|
| Brute force / password guessing | R001 |
| New or newly privileged account | R002, R003 |
| Off-hours interactive logon | R004 |
| Connection to known-bad IP or domain (beacon) | R005, R006 |
| Suspicious tool detected by EDR | R007 |

In the alert detail panel each step has:

- a **checkbox**: tick it when the step is done (the time is recorded and the step goes into the alert
  history);
- a **help line** explaining why the step matters;
- a **note box** for what you found ("user confirmed by phone", "IP only seen on this host"). It saves when
  you click out of the box.

The progress bar (e.g. `3/6`) also shows next to each alert inside a case, so the case owner can see which
alerts still need work.

#### Editing playbooks

Playbooks are plain JSON in `rules/playbooks.json`:

```json
{
  "id": "PB-BRUTE",
  "name": "Brute force / password guessing",
  "ruleIds": ["R001"],
  "steps": [ { "title": "Check whether any logon succeeded", "help": "Why this matters..." } ]
}
```

`ruleIds` lists the rules that use this playbook. If you add a rule in `rules.json`, add its ID to a playbook
(or create a new playbook) and restart. Alerts that already exist keep the steps they started with. Step
progress is stored by step number, so if you reorder steps, existing alerts will show ticks against the
wrong steps.

### Try it

1. **Generator** → *Inject a scenario now* → pick the brute-force (or new-admin) scenario.
2. **Alert Queue** → click the new alert. Work the **Playbook** steps: tick a few and write step notes.
3. Click **Escalate to case** (leave "New case" selected). The alert moves to *Investigating*.
4. Open a second related alert and escalate it into the **same** case by picking it from the dropdown.
5. **Cases** → click the case. Read the **Timeline**, click an event entry to see its raw JSON, set an
   **Owner**, and step through the phases: Analysis → Containment → … → Post-incident.
6. Write the **Final summary** and click **Close case**.

---

## MITRE ATT&CK heatmap and IOC lookup

New screens: **MITRE** (the heatmap) and **IOC Lookup** (top nav). Also new:

- The Alert Queue has a **technique filter**.
- Each alert lists its **Indicators** (IPs, domains and hashes from its events) as clickable links.
- Each case has an **Indicators of compromise** list.

New files:

```
src/mitre.js         built-in ATT&CK catalogue (IDs and names only), coverage + activity heatmap
src/ioc.js           classify and look up an indicator in local data (intel list + stored events)
rules/intel.json     the fake threat-intel list (editable; moved out of src/intel.js)
test/mitre-ioc.test.js  tests for this part
```

The state file is now `version: 3`. It adds `iocs` to each case. Older state files are upgraded automatically
on start. Before an upgrade, the old file is copied to `state.v<old version>.bak` in the same folder. An
existing backup is never overwritten.

The `cred_dump` scenario's EDR detection now carries a `fileHash`. Like everything else it is simulated:
every hash in this simulator starts with 48 zeros, so it can never match a real file.

### Tactics and techniques

MITRE ATT&CK has two levels that matter here:

- A **tactic** is the attacker's *goal* at that step: *Initial Access* (get in), *Persistence* (stay in),
  *Credential Access* (steal passwords), *Command and Control* (remote control), *Exfiltration* (take data out),
  and so on. Tactics are the **columns** of the heatmap, roughly in the order an attack unfolds.
- A **technique** is *how* they do it, e.g. **T1110 Brute Force**. A **sub-technique** is a more specific
  variant, e.g. **T1071.004** is *Application Layer Protocol* over **DNS**. Sub-techniques count toward their parent.

Some techniques serve several goals. For example, *Valid Accounts* (T1078) lets an attacker get in, stay in,
gain privileges *and* blend in, so it appears in four columns, just like on the real ATT&CK matrix.

The catalogue in `src/mitre.js` is a small subset: the techniques the rules use, plus a few that **no rule
covers**, so you can see what gaps look like. If you tag a rule with an ID that isn't in the catalogue, it
appears in an **Other** column instead of disappearing.

### Reading the heatmap

The switch at the top gives two views of the same grid:

| View | Number in each cell | Question it answers |
|---|---|---|
| **Detection coverage** | Enabled rules that detect the technique (green) | *Could we see this attack at all?* |
| **Alert activity** | Alerts in the last 24 h / 7 days / all time (red) | *What are attackers (or false positives) actually doing?* |

A **dashed** cell is a **coverage gap**: no enabled rule detects that technique. An attacker using it would go
unseen. Finding and closing gaps is a big part of detection engineering. A SOC lead uses this map to decide
which rule to write next.

Things to notice:

- **Coverage is not the same as quality.** One rule on a technique turns the cell green, but that rule may only
  catch the clumsiest version of the attack.
- **Activity is not the same as danger.** A bright red cell might be all false positives. Click it: the detail
  panel splits the alerts into TP / FP / benign / open. Lots of FPs on one technique means that rule needs tuning.
- Disabling a rule in **Rules** (`"enabled": false`) turns its cell into a gap straight away.

Click any cell to see the rules that cover it, its sub-techniques, and an alert breakdown. **Show all alerts for …**
opens the Alert Queue filtered to that technique.

### IOCs and the IOC Lookup

An **IOC** (Indicator of Compromise) is a concrete clue left by an attack. The simulator has three kinds:

| Type | Example | Where it shows up |
|---|---|---|
| IP address | `203.0.113.66` | firewall `dstIp`, logon `srcIp` |
| Domain | `c2-beacon.example` | DNS queries |
| File hash (SHA-256) | `000…fa4e000000000001` | EDR detections (`fileHash`) |

Type or paste one into **IOC Lookup**. It answers four questions, using **only data inside the simulator**.
The app never contacts any outside service. Values that aren't simulated (an IP outside the three
documentation ranges, a domain not ending in `.example`, a hash without the 48 zeros) are refused.

1. **Is it on the threat intel list?** And what does the intel note say?
2. **What is it?** An internal address is mapped to its host (`192.0.2.10` is `DC01`). `198.51.100.x` is normal
   internet. `203.0.113.x` is the range suspicious actors use in this sim.
3. **Sightings:** how many stored events mention it, first and last seen, which hosts and users touched it, and the
   latest events. Click a host or user to **pivot** to Log Search.
4. **Related alerts and cases** (click to open them).

"Not on the intel list" does **not** mean safe. Intel only knows what someone has already reported. About a
third of the simulated hashes are deliberately *not* on the list. The sightings and the context still tell you
it's bad.

**Pivoting** means following one clue to the next: alert → IP → the other hosts that talked to that IP → what those
hosts did next. It's how one alert turns into the full picture of an incident.

### Editing the threat intel list

The right side of IOC Lookup shows `rules/intel.json`, with three lists: `badIps`, `badDomains` and `badHashes`.
Each entry is `{ "value": ..., "note": ... }`. Edit it there, or click **Add to intel list** on a lookup
result. When you save, every entry is checked: IPs must be in `192.0.2.x` / `198.51.100.x` / `203.0.113.x`,
domains must end in `.example`, hashes must be simulated, and no list may be empty. A bad entry is rejected
with a message.

Rules R005 and R006 (`lookup` rules) use the new list for **new** events immediately. Alerts that already exist
don't change. A lookup rule can also use `"list": "badHashes"` with `"field": "fileHash"` if you want to
write a hash rule yourself.

### IOCs on a case

In a case, **Indicators of compromise** records the IPs, domains and hashes that belong to the incident, each
with a short note on why it matters. Add them from the case panel, or with **Add to case** on a lookup result.
Each addition or removal appears in the case timeline (kind *IOC*). A red-edged IOC is on the intel list.
This is the list you'd hand to the network team to block, or share with other SOCs.

### Try it: MITRE heatmap

1. Open **MITRE**. In **Detection coverage**, count the dashed cells, e.g. *Remote Services* (Lateral Movement)
   and *Exfiltration Over Alternative Protocol*. These are your blind spots.
2. Click **T1071 Application Layer Protocol**. It is covered by two rules, R005 (T1071) and R006 (its DNS
   sub-technique T1071.004).
3. Switch to **Alert activity** and pick **Last 24 hours**. Which tactic is busiest?
4. **Generator** → inject *Workstation beacons to a known-bad IP/domain* two or three times. Back on **MITRE**,
   the Command and Control cell gets darker (the page refreshes every 5 s).
5. Click the cell, then **Show all alerts for T1071 in the Alert Queue**. Close one as *false positive* and
   another as *true positive*, then come back. The breakdown in the detail panel changes.
6. **Rules** → set R007 `"enabled": false` → Save. On **MITRE** → *Detection coverage*, *OS Credential Dumping*
   is now a gap. Set it back to `true` afterwards.

### Try it: IOC Lookup

1. Open **IOC Lookup** and click the example `203.0.113.66`. It's on the intel list (*Fake C2 server*). Check its
   sightings, hosts and related alerts.
2. Look up `192.0.2.10`. It's internal (DC01), not on any list, with lots of normal sightings. Context matters.
3. Try a real-world-looking address such as `100.64.1.2`. The lookup refuses it and explains why.
4. **Generator** → inject *EDR: suspicious credential dumping tool*. In the **Alert Queue**, open the new R007
   alert and click its **Hash** indicator. If it's red it's on the intel list. If not, notice that the alert is
   still critical: no intel hit doesn't mean safe.
5. Escalate that alert to a case. Back on the lookup result, pick the case and click **Add to case**, with a note
   like "dumping tool seen on this host". Open **Cases** and see it under *Indicators of compromise* and in
   the timeline.
6. Look up a new suspicious address such as `203.0.113.201`. It has no sightings and isn't on the list. Click
   **Add to intel list**. From now on, any firewall event to that IP fires R005, and the beacon scenario may
   pick it as its target.
7. From a lookup result, click a **host** under Sightings to pivot into Log Search and see what that host did
   around the same time.

---

## Scenario mode with scoring, and the shift handover

New screens: **Exercise** and **Handover** (top nav). Also new:

- The Alert Queue detail panel has a **Severity** select. You can raise or lower what the rule set; the rule's own
  severity is kept and shown as "(rule said …)".
- Two new practice scenarios that are *not* incidents (see the table below).
- While an exercise runs, an **EXERCISE mm:ss left** banner with a **Submit** button sits in the header on every screen.

New files:

```
src/exercise.js      scenario mode: start, hide, track, auto-submit, score, history
src/handover.js      shift handover report, watch list, saved handovers
rules/scoring.json   scoring weights, MTTA/MTTR targets per severity, time limits (editable JSON)
test/exercise-handover.test.js  tests for this part
```

The state file is now `version: 4`. It adds the running exercise, the score history, saved handovers and the
handover draft, and gives each alert `raisedTs` (when it appeared in the queue) and `ruleSeverity`. Older files are
upgraded on start and copied to `state.v3.bak` first (an existing backup is never overwritten).
**Reset everything** keeps your score history and saved handovers: they are about you, not the simulated data.

### Scenario mode (Exercise screen)

1. Pick **Random (hidden)** or a named scenario, and a time limit (10, 15, 30 or 60 minutes). Click **Start**.
2. The simulator injects the scenario into the live noise. In random mode nothing tells you which one it is:
   the events carry no scenario tag, and the API does not reveal it until you are scored.
   Auto-scenarios are paused and manual injection is off until the exercise ends, so the only new attack is yours.
3. Work it like any real alert: acknowledge it, work the playbook, pivot in Log Search and IOC Lookup, write notes,
   set the verdict and severity, and open a case **only if it is a real incident**. Then close it.
4. Click **Submit**. At 00:00 it is submitted for you. The **scorecard** shows what you got right, what you missed and
   why, then reveals the scenario, its clues and the alerts it raised.

#### How you are scored

| Criterion | Points | Full marks when… |
|---|---|---|
| Verdict | 25 | Every alert from the scenario has the right verdict. Mixing up *benign* and *false positive* gets half |
| Severity | 10 | The case severity (or the highest alert severity if there is no case) is in the accepted range. For non-incidents you only lose marks for **raising** it |
| Escalation | 15 | You opened a case when one was needed, and **didn't** when it wasn't |
| Related alerts in one case | 10 | When one attack raised several alerts, they are all in the **same** case |
| MTTA | 10 | You acknowledged each alert (Investigating, or escalated) within the target for its severity |
| MTTR | 10 | You closed each alert (or its case) within the target |
| Playbook | 10 | All playbook steps ticked |
| Notes | 10 | At least two useful notes (20+ characters): alert notes, step notes, case notes or the case summary |

Criteria that don't apply (for example "linking" when there is only one alert) are left out and the score is scaled
to 100. Time marks fall gradually from full at the target to zero at three times the target. Targets and weights are
in `rules/scoring.json`:

| Severity | MTTA target | MTTR target |
|---|---|---|
| critical | 2 min | 10 min |
| high | 5 min | 15 min |
| medium | 10 min | 20 min |
| low | 15 min | 30 min |

The headline sums up the call you made:

- **Correct call**: right verdict and right escalation decision.
- **Over-escalated**: you treated a non-incident as an attack (true positive verdict, or a case). This wastes the
  team's time and trains people to ignore escalations.
- **Missed incident**: you closed a real attack as benign or false positive. This is the most serious mistake.
- **Partly right** / **Unfinished**: somewhere in between, or no verdict set yet.

#### MTTA, and why times start when the alert appears

**MTTA (Mean Time To Acknowledge)** is the average time from an alert appearing to someone taking it on. It is the
first number a SOC lead looks at: an alert nobody has picked up is an alert nobody is handling. MTTR (see Phase 1)
measures how long it took to finish.

Both are measured from when the alert **appeared in the queue** (`raisedTs`), not from its event time. That matters
for "late log" scenarios: an off-hours logon from 03:00 last night only reaches the SIEM now, so its alert *time* is
last night, but you could not have acted on it before it arrived.

#### Answer keys

Each scenario in `src/generator.js` has an `answer(events)` function that returns the expected verdict, accepted
severities, whether a case is required, optional or not wanted, the rules it should trip, an explanation and the clues.
It is computed from the generated events, so a brute force that *succeeded* expects a different answer from one that
didn't.

| Scenario | Verdict | Severity | Case |
|---|---|---|---|
| Brute force, no logon succeeded | True positive | high | optional |
| Brute force, a logon succeeded | True positive | critical | required |
| User mistypes password | Benign | not raised | no |
| New account + Administrators | True positive | critical | required, both alerts in one case |
| Unusual-hour logon (normal user) | True positive | medium or high | required |
| Admin late-night patching | Benign | not raised | no |
| Beacon to known-bad IP/domain | True positive | high or critical | required, both alerts in one case |
| Credential dumping tool | True positive | critical | required |
| **New:** IT admin creates a new-starter account | Benign | not raised | no |
| **New:** EDR flags the backup agent | False positive | not raised | no |

The two new ones in plain words:

- **New-starter account**: R002 fires, but the 4720 event carries an approved change reference (`CHG-nnnnn`), the
  creator is an IT admin, and the account is *not* added to Administrators. Compare it with the new-admin attack,
  which never has a change reference.
- **Backup agent**: R007 fires on `backup_agent.exe`, signed by the backup vendor and run by the `svc_backup`
  service account, with a hash that is not on the intel list. The activity is allowed, *and* the rule was wrong to call
  it credential dumping: that is a **false positive** (the fix is a rule exception), not merely benign.

If a scenario's rule is disabled on the Rules page, that scenario can't be picked and random mode skips it.
If the server restarts while an exercise is still receiving its events, the exercise is recorded as *interrupted* and
not scored. (The answer key is stored in `state.json` while the exercise runs. Peeking only cheats yourself.)

#### Progress

Below the scorecard: a history of every exercise (click one to see its scorecard again), a chart of your last 30
scores, and your average marks per criterion, weakest first. That tells you what to practise next.

### Shift handover (Handover screen)

A SOC runs 24/7 in shifts. The **handover** is how the outgoing analyst tells the incoming one what is going on, so
nothing is dropped between shifts. The screen builds it for a time window (default **last 8 hours**; 12 h, 24 h or a
custom window can be picked):

- **Alerts by severity**: new in the window, still open at the end of it, and closed in it (with the verdict split).
- **Open cases** with their NIST phase, owner, playbook progress and last update.
- **Key IOCs**: indicators recorded on open cases, plus intel-listed indicators seen in this shift's alerts, with
  sightings in the window.
- **Shift MTTA / MTTR**: for alerts acknowledged or closed inside the window.
- **Watch list**, generated from the data. Each item links to the alert, case, IOC or search:
  - critical/high alerts that nobody has picked up yet
  - alerts open for more than 4 hours
  - cases with no owner, and cases in Containment or Eradication (actions still under way)
  - hosts or users that appear in two or more of this shift's alerts
  - intel-listed IOCs that were seen but are not recorded on any case
  - alerts closed as true positive without a case ("was a response needed?")
  - rules that produced three or more false positives (tuning candidates)

**My handover notes**: write what is still going on, what you already did and what the next shift should do first.
The draft is saved when you click out of the box. **Save handover** stores your notes together with a frozen copy of
the report. The next time anyone opens the screen, the **previous handover** is shown at the top. That is the first
thing the incoming analyst reads. Saved handovers are listed at the bottom; click one to see its frozen report.

**Print / Save as PDF** uses the browser's own print dialog (choose *Save as PDF* as the printer to get a file). The
print view drops the menus and buttons, prints black on white, shows your notes as text, and marks the report as
simulated training data. No extra libraries.

### Try it: an exercise

1. **Exercise** → *Random (hidden)*, 15 min → **Start**.
2. **Alert Queue**: find the new alert(s). Some arrive as late logs and sort lower than you expect.
3. Set it to **Investigating** with yourself as assignee. Work the playbook and write a note or two.
4. Decide: real attack or not? Set **Verdict** and **Severity**. Only for a real incident, **Escalate to case**, and
   escalate any related alerts into the *same* case.
5. Close the alert (or the case), then click **Submit** in the header.
6. Read the scorecard's *Why* column, then try again, perhaps picking one of the benign scenarios on purpose to practise
   **not** escalating.

### Try it: a handover

1. Close a few alerts and leave a case open without an owner.
2. **Handover** → *Last 8 hours*. Read the watch list: the unowned case is on it.
3. Write a few lines in **My handover notes**, choose your analyst name and click **Save handover**.
4. Click **Print / Save as PDF** and save it as a PDF.
5. Reload the screen: your handover now shows at the top as the *previous handover*.

---

## Phishing, password spraying, lateral movement and beacon behaviour

Four new rules (R008–R011), two new log sources, six new practice scenarios and four new playbooks. Also a scoring
fix: in an exercise, **doing nothing no longer earns Severity or Escalation marks**.

Changed files: `src/detection.js` (two new rule features), `src/generator.js` (new noise and scenarios),
`rules/rules.json`, `rules/playbooks.json`, `src/exercise.js` (scoring fix), and small changes to `src/mitre.js`, `src/ioc.js`,
`src/handover.js` and the UI. New file: `test/advanced-detections.test.js`. The state file stays `version: 4`, so no upgrade is needed.

Phase 5 changes a few things that earlier sections describe. The rule engine now has **four** rule types, not three.
Log Search has **six** sources, not four. **Remote Services** (T1021) is no longer a gap on the MITRE heatmap
(*Exfiltration Over Alternative Protocol* still is).

### New log sources

| Source | What it records |
|---|---|
| `mail` | The mail gateway: `delivered` (sender, sender domain, subject, SPF result, recipient count, link domain), `link_click` (the gateway rewrites links, so it sees clicks, with the link domain's age in days) and `form_submit` (a password typed into a web form reached from a mail link) |
| `change` | Approved change tickets from the IT service-management system (host `ITSM`): `changeRef`, who asked, the hosts covered, the time window and a summary |

A **change ticket** is the record that some work was planned and approved. When an alert looks like an attacker but is
really IT doing their job, the ticket is what proves it. Search Log Search with source `change` (or the `CHG-` number as
a keyword). Some ordinary tickets appear in the background noise, so finding *a* ticket is not enough: it has to cover
**these hosts at this time**.

### New rule features

**Distinct counting** (`"distinct": "<field>"` on a threshold rule): count *different values* of a field instead of
raw events. R009 counts distinct **users** per source IP, and R010 counts distinct **hosts** per user.

**Beacon rules** (`"type": "beacon"`): look for the same thing repeating on a timer.

| Field | Meaning |
|---|---|
| `groupBy` | The entity the alert is about (R011: `host`) |
| `per` | The field that must stay the same (R011: `dstIp`) |
| `count`, `windowSeconds` | How many repeats, within how long (R011: 6 within 15 minutes) |
| `maxJitter` | How regular the gaps must be: standard deviation divided by the average gap. 0 = perfectly regular. R011: 0.05 (a 60 s beacon may wobble by about 3 s) |
| `minIntervalSeconds` | Ignore patterns faster than this (R011: 45) |

### The new detections in plain words

#### Phishing (R008, T1566)
**Phishing** is an email that tricks someone into clicking a link or opening a file, usually to steal a password. Phishing
sites are almost always **brand new**: attackers register a lookalike domain days before the campaign. R008 fires when
someone clicks an email link to a domain less than 30 days old. A legitimate newsletter that recently changed domain
trips it too, so read the email: SPF result, how many people got it, what it asks for.

**SPF** (Sender Policy Framework) lets a domain list the servers allowed to send its mail. "SPF fail" means the email
did not come from where it claims, a classic sign of spoofing.

#### Password spraying (R009, T1110.003)
Brute force tries **many passwords against one account**, which trips lockouts and R001. **Spraying** turns that
around: **one or two common passwords against many accounts**, so each account sees only one failure. R001 never fires.
You catch it by counting *different users* failing from the *same source*.

#### Lateral movement (R010, T1021)
After getting into one PC, attackers **move sideways** to others, looking for admin passwords and valuable data.
**Remote Services** means using normal remote logons to do it. Ordinary staff almost never log on over the network
(logon type 3) to other people's workstations. IT admins do, as part of planned work, and that is what the change log is for.

#### Beacon behaviour (R011, T1071)
R005 catches C2 traffic only if the IP is already **on the intel list**. R011 catches the **behaviour**: software checking in on a
timer. That works for a brand-new controller nobody has reported yet. Detecting by behaviour instead of by indicator is
how SOCs catch what intel hasn't seen.

**Tuning note:** at the default rate (1 event/s) the background noise never trips R011. At the maximum rate (20
events/s) random server traffic occasionally lines up into a regular-looking pattern, so expect an odd false positive.
That is the detection-engineering trade-off from Phase 1 again: loosen `maxJitter` and you catch sloppier beacons, plus
more noise.

### New scenarios and answer keys

All use the Phase 4 `answer(events)` format and can be injected from **Generator** or picked in **Exercise**.

| Scenario | What to look for | Verdict | Severity | Case |
|---|---|---|---|---|
| Phishing email, no password entered | SPF fail, urgent password subject, 1–3 recipients, days-old domain, link to an unlisted 203.0.113.x | True positive | high | optional |
| Phishing email, password entered | As above plus a `form_submit`, then **a 4624 logon for the same user from a new 203.0.113.x IP 3–5 minutes later**. That logon raises **no alert**: you have to find it by searching the user in Log Search | True positive | critical | required |
| Newsletter link on a new domain | SPF pass, 25+ recipients, unsubscribe link, link to normal internet, nothing afterwards | Benign | not raised | no |
| Password spray, nothing succeeded | One external IP, 8–15 users, one failure each, R001 silent | True positive | high | optional |
| Password spray, one account guessed | As above, plus a 4624 success from the same IP | True positive | critical | required |
| Stolen account hops across PCs | Non-IT user, type-3 logons to 4 workstations from a PC that is not theirs, no change ticket | True positive | high or critical | required |
| IT admin maintenance under a change ticket | IT admin, from their own PC, to exactly the hosts listed in a `CHG-` ticket approved 20 minutes earlier | Benign | not raised | no |
| Beacon to an unlisted IP | One PC to one 203.0.113.x every ~60 s, on no intel list, no DNS lookup first, R005 silent | True positive | high or critical | required |

The lesson running through all of these: **"not on the intel list" is not the same as "safe"**, and **the alert is
where the investigation starts, not where it ends**. The most important event in the phishing scenario has no alert.

### Scoring fix: no marks for doing nothing

Before, an exercise on a benign scenario submitted without touching the alert scored full Severity ("you didn't raise
it") and Escalation ("you didn't open a case") marks. Now both criteria give **0** unless at least one of the exercise's
alerts was **acknowledged**: set to Investigating, escalated to a case, or closed. The scorecard says so in the *Why*
column. Escalation that is *optional* (a failed attack) is still left out of the score either way.

### Try it

1. **Generator** → inject *Phishing email: user clicks a link to a new lookalike site*. In the **Alert Queue**, open the
   R008 alert and work **PB-PHISH**.
2. **Log Search** → source `mail`, user = the alert's user. Read the delivered email: sender, SPF, recipients.
3. Same user, Event ID `4624`, last hour. If the user submitted the form, a logon to MAIL01 from a 203.0.113.x address
   appears a few minutes later. Look that IP up in **IOC Lookup**: never seen before, on no list. Raise the alert to
   *critical* and escalate.
4. Inject *IT admin installs an update on several PCs under a change ticket*. Open the R010 alert, then search source
   `change`. Does the ticket list the same hosts? Close it as **benign** with the change number in your note.
5. Inject *Workstation beacons to an address that is on no intel list* and wait about 5 minutes for the 6th
   connection. Open the R011 alert's events and compare the times. Then **Add to intel list** from IOC Lookup: from now
   on any connection to that IP also trips R005.
6. **Exercise** → pick *User clicks a link in a newsletter from a new domain (benign)* and submit without touching
   anything. Severity and Escalation now show 0. Run it again, acknowledge the alert, close it as benign and compare.
7. **MITRE** → *Detection coverage*: Phishing, Remote Services and Brute Force (with the Password Spraying
   sub-technique) are now covered.

---

## License

[MIT](LICENSE). This is a personal learning and portfolio project. All data is simulated.
