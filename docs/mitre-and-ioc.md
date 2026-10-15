# MITRE ATT&CK heatmap and IOC lookup

[← Back to README](../README.md) · [All guides](README.md)

Screens: **MITRE** (the heatmap) and **IOC Lookup** (top nav). Also:

- The Alert Queue has a **technique filter**.
- Each alert lists its **Indicators** (IPs, domains and hashes from its events) as clickable links.
- Each case has an **Indicators of compromise** list.

Files:

```
src/mitre.js         built-in ATT&CK catalogue (IDs and names only), coverage + activity heatmap
src/ioc.js           classify and look up an indicator in local data (intel list + stored events)
rules/intel.json     the fake threat-intel list (editable; moved out of src/intel.js)
test/mitre-ioc.test.js  tests
```

The `cred_dump` scenario's EDR detection carries a `fileHash`. Like everything else it is simulated:
every hash in this simulator starts with 48 zeros, so it can never match a real file.

## Tactics and techniques

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

## Reading the heatmap

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

## IOCs and the IOC Lookup

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

## Editing the threat intel list

The right side of IOC Lookup shows `rules/intel.json`, with three lists: `badIps`, `badDomains` and `badHashes`.
Each entry is `{ "value": ..., "note": ... }`. Edit it there, or click **Add to intel list** on a lookup
result. When you save, every entry is checked: IPs must be in `192.0.2.x` / `198.51.100.x` / `203.0.113.x`,
domains must end in `.example`, hashes must be simulated, and no list may be empty. A bad entry is rejected
with a message.

Rules R005 and R006 (`lookup` rules) use the new list for **new** events immediately. Alerts that already exist
don't change. A lookup rule can also use `"list": "badHashes"` with `"field": "fileHash"` if you want to
write a hash rule yourself.

## IOCs on a case

In a case, **Indicators of compromise** records the IPs, domains and hashes that belong to the incident, each
with a short note on why it matters. Add them from the case panel, or with **Add to case** on a lookup result.
Each addition or removal appears in the case timeline (kind *IOC*). A red-edged IOC is on the intel list.
This is the list you'd hand to the network team to block, or share with other SOCs.

## Try it: MITRE heatmap

1. Open **MITRE**. In **Detection coverage**, count the dashed cells, e.g. *Exfiltration Over Alternative Protocol* (Exfiltration)
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

## Try it: IOC Lookup

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
