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
| New account + Administrators | 4720 then 4732 on DC01. Was there a change ticket? (There never is, here.) | True positive |
| Unusual-hour logon (normal user) | Keyboard logon at 01:00–05:00 by a non-IT user | True positive |
| Admin late-night patching | Same alert, but the user is an IT admin | Benign |
| Beacon to known-bad IP | DNS lookup of a bad domain, then repeated connections every minute | True positive |
| Credential dumping tool | EDR detection on a host. Check who was logged on there | True positive |

Tip: for any alert, open its events in Log Search, then clear the `ids` filter and search the same **host**
or **user** to see what happened before and after.

More scenarios (phishing, password spraying, lateral movement, beacons) are described in
[Advanced detections](advanced-detections.md#scenarios-and-answer-keys), and the benign look-alikes used for
scoring in [Exercises and handover](exercises-and-handover.md).
