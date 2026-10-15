# SOC concepts in plain words

[← Back to README](../README.md) · [All guides](README.md)

## What is a SOC?
A Security Operations Center is the team (and the room full of screens) that watches a company's
computers 24/7 for signs of attack. Analysts look at **alerts**, decide which ones are real, and
start the response when something bad is happening.

## Events and logs
An **event** is one record of something that happened: "user X logged on to PC Y at 10:02".
Computers produce thousands per hour. Collected together they're **logs**. This simulator creates six kinds:

| Source | What it records |
|---|---|
| `winsec` | Windows Security log (logons, account changes) |
| `firewall` | Network connections allowed or blocked at the edge |
| `dns` | Which domain names computers looked up (like a phone book lookup) |
| `edr` | The endpoint agent on each PC (EDR = Endpoint Detection & Response), which watches programs running |
| `mail` | The mail gateway: delivered emails, link clicks and form submissions |
| `change` | Change tickets, so planned admin work can be told apart from an attack |

## Windows Event IDs you'll see

| ID | Meaning | Why analysts care |
|---|---|---|
| **4624** | Successful logon | Who got in, where, from where. *Logon type 2* = at the keyboard, *3* = over the network, *5* = a service |
| **4625** | Failed logon | One is a typo. Lots in a row is someone guessing passwords |
| **4672** | Special (admin) privileges given to a logon | Admin activity should be rare and expected |
| **4720** | A user account was created | Attackers create accounts so they can get back in later |
| **4732** | Member added to a local security group | Being added to *Administrators* = full control of the machine |

## SIEM and detection rules
A **SIEM** (Security Information and Event Management) gathers all the logs in one place and runs
**detection rules** over them. When a rule matches, it creates an **alert**. This app is a tiny SIEM.

Rules live in `rules/rules.json`. There are four types:

* **match**: one event is enough. *"Someone was added to Administrators."*
* **threshold**: count matching events per user/host inside a time window. *"5+ failed logons for the same user in 2 minutes."*
* **lookup**: check a field against a threat-intel list. *"Connection to an IP on the bad list."*
* **beacon**: look for connections that repeat at a regular interval. *"Six connections to the same IP, one every 60 seconds."* See [Advanced detections](advanced-detections.md#rule-features).

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

## Alerts and triage
**Triage** means sorting alerts quickly: *is this real, how bad is it, who handles it?* A typical flow:

1. Take the newest **critical/high** alert and set it to **Investigating** with yourself as **assignee**.
2. Read the related events. Open them in Log Search and look at what else that user/host did around that time.
3. Write **notes**: what you checked, what you found. The next analyst (or the auditor) depends on them.
4. Give a **verdict** and **Close** it.

## Severity
How bad it would be if the alert is real: **low → medium → high → critical**. It decides what you look at first.

## Verdicts: true positive, false positive, benign
* **True positive (TP)**: the rule fired and it really is malicious. *Escalate / respond.*
* **False positive (FP)**: the rule fired but it was wrong. The logic matched something it shouldn't have. *Tune the rule.*
* **Benign**: the rule worked correctly, the activity really happened, but it's allowed.
  e.g. an IT admin logging on at 2 a.m. for planned patching. *Document it and maybe add an exception.*

Tracking verdicts tells you which rules are worth keeping.

## MITRE ATT&CK
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

## Threat intel and IOCs
**Threat intelligence** is shared knowledge about attackers. **IOCs** (Indicators of Compromise) are concrete
clues like bad IP addresses, domains or file hashes. The fake intel list is on the Generator page (`src/intel.js`).

## C2 (Command and Control) and beaconing
Malware on an infected PC "phones home" to the attacker's server at regular intervals to get instructions.
Regular repeated connections to the same outside IP are called **beaconing**.

## MTTD and MTTR
* **MTTD (Mean Time To Detect)**: average time from the *first suspicious event* to the *alert*. Lower = better rules.
  For a brute force it's the time it took to reach 5 failures.
* **MTTR (Mean Time To Respond)**: average time from *alert created* to *alert closed*. Lower = faster analysts.
  It only counts closed alerts, so close some and watch it change.

## Noise
Most events are completely normal: people logging on, browsing, opening Word. Finding the few bad ones in all
that **noise** is the real job.
