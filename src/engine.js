// Pipeline: generator -> store -> detection -> alerts. Also runs the live loop.

const store = require('./store');
const gen = require('./generator');
const detection = require('./detection');
const alerts = require('./alerts');
const config = require('./config');

let pending = [];   // scenario events waiting for their time
let timer = null;
let lastScenarioTs = Date.now();
const tickHooks = []; // called every second with `now` (e.g. exercise deadline)

// wallTs = when the event reached the SIEM (later than ev.ts for late logs)
function ingest(ev, wallTs = ev.ts) {
  store.addEvent(ev);
  for (const hit of detection.evaluate(ev)) alerts.raise(hit, ev.ts, wallTs);
}

function seedIfEmpty() {
  if (store.state.events.length) return false;
  for (const ev of gen.seedHistory(Date.now())) ingest(ev);
  return true;
}

// Timestamped events for a scenario injected now. "Unusual hour" scenarios arrive as a late log
// from the most recent night (01:00-04:59), so the hour rule can see them.
function plan(key, now = Date.now()) {
  const s = gen.scenarios[key];
  if (!s) throw new Error(`Unknown scenario: ${key}`);
  let ts = now;
  if (s.unusualHour) {
    ts = gen.unusualTime(now);
    if (ts > now) ts -= 24 * 3600e3;
  }
  return gen.expand(key, ts);
}

// Events already in the past go in now; the rest drip out in tick()
function release(events, now = Date.now()) {
  for (const ev of events) {
    if (ev.ts <= now) ingest(ev, now);
    else pending.push(ev);
  }
  pending.sort((a, b) => a.ts - b.ts);
}

function releaseDue(now = Date.now()) {
  while (pending.length && pending[0].ts <= now) ingest(pending.shift());
}

function inject(key, now = Date.now()) {
  release(plan(key, now), now);
  return gen.scenarios[key].name;
}

function tick() {
  const g = store.state.generator;
  const now = Date.now();
  releaseDue(now);
  for (const fn of tickHooks) {
    try { fn(now); } catch (e) { console.error('Tick hook failed:', e.message); }
  }
  if (!g.running) return;
  // Emit `rate` events per second, spread across the elapsed second
  const n = Math.floor(g.rate) + (Math.random() < g.rate % 1 ? 1 : 0);
  for (let i = 0; i < n; i++) ingest(gen.noise(now - 999 + Math.floor((i + 1) * 1000 / (n + 1))));
  if (g.autoScenarios && now - lastScenarioTs > config.scenarioEveryMinutes * 60e3 * (0.5 + Math.random())) {
    lastScenarioTs = now;
    inject(pickScenario());
  }
}

function pickScenario() {
  const keys = Object.keys(gen.scenarios);
  return keys[Math.floor(Math.random() * keys.length)];
}

function start() { if (!timer) timer = setInterval(tick, 1000); }
function stop() { clearInterval(timer); timer = null; }
const onTick = fn => tickHooks.push(fn);
const clearPending = () => { pending = []; };
const pendingCount = () => pending.length;

module.exports = { ingest, seedIfEmpty, plan, release, releaseDue, inject, tick, start, stop, onTick, clearPending, pendingCount };
