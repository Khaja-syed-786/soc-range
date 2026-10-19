# Architecture

[← Back to README](../README.md) · [All guides](README.md)

## Data flow

```
generator.js --events--> store.js (in memory, saved to %LOCALAPPDATA%) --> detection.js (rules/*.json)
                                                                              |
     public/ (vanilla JS UI)  <--  server.js (Express, 127.0.0.1)  <--  alerts / cases / playbooks /
                                                                        ioc / mitre / exercise / handover
```

## Project layout

```
server.js            Express API + static UI (127.0.0.1 by default; the Docker image sets SOCSIM_HOST=0.0.0.0
                     and compose.yaml publishes the port on 127.0.0.1 only)
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
test/                node:test tests (102)
```

## Saved state

State lives in one JSON file (`%LOCALAPPDATA%\SocSim\state.json` by default, see [settings](user-guide.md#settings-and-saved-state)).
The file carries a `version` number (currently 4). Older files are upgraded automatically on start, and the old
file is first copied to `state.v<old version>.bak` in the same folder (an existing backup is never overwritten).
**Reset everything** keeps your score history and saved handovers: they are about you, not the simulated data.

## Development history

| Phase | Added |
|---|---|
| 1 | Event generator, rule engine, alert queue, log search, dashboard (MTTD/MTTR) |
| 2 | Incident cases (NIST phases), timeline, playbooks |
| 3 | MITRE ATT&CK heatmap, IOC lookup, editable threat-intel list |
| 4 | Scored exercise mode with answer keys, shift handover |
| 5 | Phishing, password spraying, lateral movement and beacon-behaviour detections; `mail` and `change` log sources |
