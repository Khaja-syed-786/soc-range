# User guide

[← Back to README](../README.md) · [All guides](README.md)

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
| **Cases** | Run an incident through the NIST lifecycle: owner, timeline, IOCs, playbook ([guide](incident-cases-and-playbooks.md)) |
| **Log Search** | Hunt through raw events by time, host, user, event ID, keyword |
| **IOC Lookup** | Look up an IP, domain or hash in the fake intel list and stored events ([guide](mitre-and-ioc.md)) |
| **MITRE** | ATT&CK detection coverage and alert-activity heatmap ([guide](mitre-and-ioc.md)) |
| **Exercise** | Scored scenario mode with answer keys ([guide](exercises-and-handover.md)) |
| **Handover** | End-of-shift report with an auto-generated watch list ([guide](exercises-and-handover.md)) |
| **Rules** | Read and edit the detection rules (JSON) |
| **Generator** | Speed up/pause the noise, inject an attack scenario on demand, reset |

## Settings and saved state

State (events, alerts, notes) is saved to `%LOCALAPPDATA%\SocSim\state.json` every 30 seconds and on
shutdown. To change the location, set `"dataDir"` in `config.json` (or the `SOCSIM_DATA_DIR` environment
variable). Logs from the background server go to the same folder.

Other settings in `config.json`: `eventCap` (default 50,000, about one day at the default rate),
`defaultRate` (1 event/second), `scenarioEveryMinutes` (how often attacks are auto-injected).

## Practice scenarios (Generator → "Inject a scenario now")

| Scenario | What to look for | Expected verdict |
|---|---|---|
| Brute force | Burst of 4625 from a `203.0.113.x` IP. Did a 4624 **success** follow? That means the attacker got in | True positive |
| User mistypes password | 5 failures from the user's *own* PC IP, then a success | Benign |
| New account + Administrators | 4720 then 4732 on DC01. Was there a change ticket? (None in this attack.) | True positive |
| Admin adds an existing user to Administrators | A lone 4732 on DC01 by an IT admin, for an existing employee, with an approved `CHG-` change reference. No 4720 first | Benign |
| Unusual-hour logon (normal user) | Keyboard logon at 01:00–05:00 by a non-IT user | True positive |
| Admin late-night patching | Same alert, but the user is an IT admin | Benign |
| Beacon to known-bad IP | DNS lookup of a bad domain, then repeated connections every minute | True positive |
| Credential dumping tool | EDR detection on a host. Check who was logged on there | True positive |
| IT admin creates an account for a new starter (benign) | R002 fires on a 4720 made by an IT admin that carries an approved `CHG-` change reference. No 4732 follows, so the account was not made an administrator (compare with *New account + Administrators*) | Benign |
| EDR flags the backup agent reading protected memory (false positive) | R007 fires on `backup_agent.exe`, run by the `svc_backup` service account and signed by the backup vendor. The hash is not on the intel list and nothing else happened on the host. The activity is allowed, but the rule was wrong to call it credential dumping, so it is a false positive (the fix is a rule exception), not merely benign | False positive |
| Logon from the internet | One successful 4624 on a server from a `203.0.113.x` IP (R012). No failures first: the attacker already had the password | True positive |

Tip: for any alert, open its events in Log Search, then clear the `ids` filter and search the same **host**
or **user** to see what happened before and after.

More scenarios (phishing, password spraying, lateral movement, beacons) are described in
[Advanced detections](advanced-detections.md#scenarios-and-answer-keys), and the benign look-alikes used for
scoring in [Exercises and handover](exercises-and-handover.md).
