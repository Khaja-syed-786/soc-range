# Phishing, password spraying, lateral movement and beacon behaviour

[← Back to README](../README.md) · [All guides](README.md)

Four rules (R008–R011), two log sources (`mail` and `change`), six practice scenarios and four playbooks that go
beyond the basics, plus a scoring rule: in an exercise, **doing nothing earns no Severity or Escalation marks**.

Files: `src/detection.js` (rule features), `src/generator.js` (noise and scenarios), `rules/rules.json`,
`rules/playbooks.json`, `src/exercise.js` (scoring). Tests: `test/advanced-detections.test.js`.

## Log sources

| Source | What it records |
|---|---|
| `mail` | The mail gateway: `delivered` (sender, sender domain, subject, SPF result, recipient count, link domain), `link_click` (the gateway rewrites links, so it sees clicks, with the link domain's age in days) and `form_submit` (a password typed into a web form reached from a mail link) |
| `change` | Approved change tickets from the IT service-management system (host `ITSM`): `changeRef`, who asked, the hosts covered, the time window and a summary |

A **change ticket** is the record that some work was planned and approved. When an alert looks like an attacker but is
really IT doing their job, the ticket is what proves it. Search Log Search with source `change` (or the `CHG-` number as
a keyword). Some ordinary tickets appear in the background noise, so finding *a* ticket is not enough: it has to cover
**these hosts at this time**.

## Rule features

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

## The detections in plain words

### Phishing (R008, T1566)
**Phishing** is an email that tricks someone into clicking a link or opening a file, usually to steal a password. Phishing
sites are almost always **brand new**: attackers register a lookalike domain days before the campaign. R008 fires when
someone clicks an email link to a domain less than 30 days old. A legitimate newsletter that recently changed domain
trips it too, so read the email: SPF result, how many people got it, what it asks for.

**SPF** (Sender Policy Framework) lets a domain list the servers allowed to send its mail. "SPF fail" means the email
did not come from where it claims, a classic sign of spoofing.

### Password spraying (R009, T1110.003)
Brute force tries **many passwords against one account**, which trips lockouts and R001. **Spraying** turns that
around: **one or two common passwords against many accounts**, so each account sees only one failure. R001 never fires.
You catch it by counting *different users* failing from the *same source*.

### Lateral movement (R010, T1021)
After getting into one PC, attackers **move sideways** to others, looking for admin passwords and valuable data.
**Remote Services** means using normal remote logons to do it. Ordinary staff almost never log on over the network
(logon type 3) to other people's workstations. IT admins do, as part of planned work, and that is what the change log is for.

### Beacon behaviour (R011, T1071)
R005 catches C2 traffic only if the IP is already **on the intel list**. R011 catches the **behaviour**: software checking in on a
timer. That works for a brand-new controller nobody has reported yet. Detecting by behaviour instead of by indicator is
how SOCs catch what intel hasn't seen.

**Tuning note:** at the default rate (1 event/s) the background noise never trips R011. At the maximum rate (20
events/s) random server traffic occasionally lines up into a regular-looking pattern, so expect an odd false positive.
That is the classic detection-engineering trade-off (see [Noise](soc-concepts.md#noise)): loosen `maxJitter` and you catch sloppier beacons, plus
more noise.

## Scenarios and answer keys

All use the same `answer(events)` format as the other scenarios ([answer keys](exercises-and-handover.md#answer-keys)) and can be injected from **Generator** or picked in **Exercise**.

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

## Scoring: no marks for doing nothing

Before, an exercise on a benign scenario submitted without touching the alert scored full Severity ("you didn't raise
it") and Escalation ("you didn't open a case") marks. Now both criteria give **0** unless at least one of the exercise's
alerts was **acknowledged**: set to Investigating, escalated to a case, or closed. The scorecard says so in the *Why*
column. Escalation that is *optional* (a failed attack) is still left out of the score either way.

## Try it

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
