# Scenario mode with scoring, and the shift handover

[← Back to README](../README.md) · [All guides](README.md)

Screens: **Exercise** and **Handover** (top nav). Also:

- The Alert Queue detail panel has a **Severity** select. You can raise or lower what the rule set; the rule's own
  severity is kept and shown as "(rule said …)".
- Two practice scenarios that are *not* incidents (see the table below).
- While an exercise runs, an **EXERCISE mm:ss left** banner with a **Submit** button sits in the header on every screen.

Files:

```
src/exercise.js      scenario mode: start, hide, track, auto-submit, score, history
src/handover.js      shift handover report, watch list, saved handovers
rules/scoring.json   scoring weights, MTTA/MTTR targets per severity, time limits (editable JSON)
test/exercise-handover.test.js  tests
```

**Reset everything** keeps your score history and saved handovers: they are about you, not the simulated data.

## Scenario mode (Exercise screen)

1. Pick **Random (hidden)** or a named scenario, and a time limit (10, 15, 30 or 60 minutes). Click **Start**.
2. The simulator injects the scenario into the live noise. In random mode nothing tells you which one it is:
   the events carry no scenario tag, and the API does not reveal it until you are scored.
   Auto-scenarios are paused and manual injection is off until the exercise ends, so the only new attack is yours.
3. Work it like any real alert: acknowledge it, work the playbook, pivot in Log Search and IOC Lookup, write notes,
   set the verdict and severity, and open a case **only if it is a real incident**. Then close it.
4. Click **Submit**. At 00:00 it is submitted for you. The **scorecard** shows what you got right, what you missed and
   why, then reveals the scenario, its clues and the alerts it raised.

### How you are scored

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

### MTTA, and why times start when the alert appears

**MTTA (Mean Time To Acknowledge)** is the average time from an alert appearing to someone taking it on. It is the
first number a SOC lead looks at: an alert nobody has picked up is an alert nobody is handling. MTTR (see [SOC concepts](soc-concepts.md#mttd-and-mttr))
measures how long it took to finish.

Both are measured from when the alert **appeared in the queue** (`raisedTs`), not from its event time. That matters
for "late log" scenarios: an off-hours logon from 03:00 last night only reaches the SIEM now, so its alert *time* is
last night, but you could not have acted on it before it arrived.

### Answer keys

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
| Admin adds an existing user to Administrators (approved change) | Benign | not raised | no |
| Unusual-hour logon (normal user) | True positive | medium or high | required |
| Admin late-night patching | Benign | not raised | no |
| Beacon to known-bad IP/domain | True positive | high or critical | required, both alerts in one case |
| Credential dumping tool | True positive | critical | required |
| Logon from the internet | True positive | high or critical | required |
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

### Progress

Below the scorecard: a history of every exercise (click one to see its scorecard again), a chart of your last 30
scores, and your average marks per criterion, weakest first. That tells you what to practise next.

## Shift handover (Handover screen)

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

## Try it: an exercise

1. **Exercise** → *Random (hidden)*, 15 min → **Start**.
2. **Alert Queue**: find the new alert(s). Some arrive as late logs and sort lower than you expect.
3. Set it to **Investigating** with yourself as assignee. Work the playbook and write a note or two.
4. Decide: real attack or not? Set **Verdict** and **Severity**. Only for a real incident, **Escalate to case**, and
   escalate any related alerts into the *same* case.
5. Close the alert (or the case), then click **Submit** in the header.
6. Read the scorecard's *Why* column, then try again, perhaps picking one of the benign scenarios on purpose to practise
   **not** escalating.

## Try it: a handover

1. Close a few alerts and leave a case open without an owner.
2. **Handover** → *Last 8 hours*. Read the watch list: the unowned case is on it.
3. Write a few lines in **My handover notes**, choose your analyst name and click **Save handover**.
4. Click **Print / Save as PDF** and save it as a PDF.
5. Reload the screen: your handover now shows at the top as the *previous handover*.
