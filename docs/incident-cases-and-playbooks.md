# Incident cases and playbooks

[← Back to README](../README.md) · [All guides](README.md)

Screen: **Cases** (top nav, with a badge showing open cases). The Alert Queue detail panel also
shows a **playbook checklist** and an **Escalate to case** control.

Files:

```
rules/playbooks.json playbook checklists (editable JSON, like rules.json)
src/playbooks.js     load/validate playbooks, auto-attach to alerts, step updates
src/cases.js         incident cases, NIST phases, merged timeline
```



## Alerts vs. incident cases

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

## The NIST incident response lifecycle

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

## Playbooks

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

### Editing playbooks

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

## Try it

1. **Generator** → *Inject a scenario now* → pick the brute-force (or new-admin) scenario.
2. **Alert Queue** → click the new alert. Work the **Playbook** steps: tick a few and write step notes.
3. Click **Escalate to case** (leave "New case" selected). The alert moves to *Investigating*.
4. Open a second related alert and escalate it into the **same** case by picking it from the dropdown.
5. **Cases** → click the case. Read the **Timeline**, click an event entry to see its raw JSON, set an
   **Owner**, and step through the phases: Analysis → Containment → … → Post-incident.
6. Write the **Final summary** and click **Close case**.
