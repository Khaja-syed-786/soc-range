// Tests: the live loop in src/engine.js (tick, rate, scenario drip-feed, auto-scenarios, tick hooks, start/stop).
const { test, beforeEach } = require('node:test');
const assert = require('node:assert');
const os = require('os');
const path = require('path');
const fs = require('fs');

process.env.SOCSIM_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'socsim-engine-test-'));

const store = require('../src/store');
const detection = require('../src/detection');
const engine = require('../src/engine');
const gen = require('../src/generator');
const config = require('../src/config');

beforeEach(() => {
  engine.stop();
  engine.clearPending();
  store.reset();
  detection.loadRules();
  Object.assign(store.state.generator, { running: true, rate: 1, autoScenarios: false });
});

test('seedIfEmpty fills an empty store with 24h of history once', () => {
  assert.strictEqual(engine.seedIfEmpty(), true);
  const n = store.state.events.length;
  assert.ok(n > 1000, `expected seeded history, got ${n}`);
  const span = store.state.events[n - 1].ts - store.state.events[0].ts;
  assert.ok(span > 20 * 3600e3, 'history should cover most of a day');
  assert.strictEqual(engine.seedIfEmpty(), false);
  assert.strictEqual(store.state.events.length, n);
});

test('tick emits floor(rate) events, plus one more with probability rate % 1', t => {
  store.state.generator.rate = 3.5;
  t.mock.method(Math, 'random', () => 0.9); // 0.9 >= 0.5: no extra event
  engine.tick();
  assert.strictEqual(store.state.events.length, 3);
  Math.random.mock.mockImplementation(() => 0.1); // 0.1 < 0.5: one extra event
  engine.tick();
  assert.strictEqual(store.state.events.length, 3 + 4);
});

test('tick spreads its events across the previous second', t => {
  const now = 1_800_000_000_000;
  t.mock.method(Date, 'now', () => now);
  store.state.generator.rate = 4;
  engine.tick();
  const ts = store.state.events.map(e => e.ts);
  assert.strictEqual(ts.length, 4);
  assert.ok(ts.every(x => x > now - 1000 && x <= now), 'events fall in (now-1s, now]');
  assert.deepStrictEqual([...ts].sort((a, b) => a - b), ts, 'in time order');
  assert.strictEqual(new Set(ts).size, 4, 'not all at the same instant');
});

test('a paused generator emits no noise, but scenario events still drip out on time', t => {
  const now = Date.now();
  store.state.generator.running = false;
  const events = engine.plan('brute_force', now + 60e3); // entirely in the future
  engine.release(events, now);
  assert.strictEqual(engine.pendingCount(), events.length);
  assert.strictEqual(store.state.events.length, 0);

  t.mock.method(Date, 'now', () => now + 3600e3);
  engine.tick();
  assert.strictEqual(engine.pendingCount(), 0);
  assert.strictEqual(store.state.events.length, events.length, 'only the scenario events, no noise');
  assert.ok(store.state.alerts.some(a => a.ruleId === 'R001'));
});

test('auto-scenarios inject a scenario once the interval has passed, and not before', t => {
  const keys = Object.keys(gen.scenarios);
  t.mock.method(Math, 'random', () => 0); // picks the first scenario; interval factor 0.5
  const original = config.scenarioEveryMinutes;
  t.after(() => { config.scenarioEveryMinutes = original; });

  store.state.generator.rate = 0; // isolate the scenario path from noise
  store.state.generator.autoScenarios = true;
  config.scenarioEveryMinutes = 1e6; // far in the future
  engine.tick();
  assert.strictEqual(store.state.events.length + engine.pendingCount(), 0);

  config.scenarioEveryMinutes = 0; // due now
  const start = Date.now();
  t.mock.method(Date, 'now', () => start + 1000);
  engine.tick();
  const expected = gen.expand(keys[0], start).length;
  assert.strictEqual(store.state.events.length + engine.pendingCount(), expected);

  engine.tick(); // same timestamp: the interval restarted, so nothing new
  assert.strictEqual(store.state.events.length + engine.pendingCount(), expected);
});

test('tick hooks run every tick and a failing hook is logged, not fatal', t => {
  // Hooks can't be removed, so these only act during this test
  let active = true;
  t.after(() => { active = false; });
  const seen = [];
  engine.onTick(now => { if (active) seen.push(now); });
  engine.onTick(() => { if (active) throw new Error('boom'); });
  const errors = [];
  t.mock.method(console, 'error', (...args) => errors.push(args.join(' ')));
  store.state.generator.running = false;
  engine.tick();
  engine.tick();
  assert.strictEqual(seen.length, 2);
  assert.deepStrictEqual(errors, ['Tick hook failed: boom', 'Tick hook failed: boom']);
});

test('start runs tick every second until stop; start twice does not double the timer', t => {
  t.mock.timers.enable({ apis: ['setInterval'] });
  store.state.generator.rate = 1;
  t.mock.method(Math, 'random', () => 0.99);
  engine.start();
  engine.start();
  t.mock.timers.tick(3000);
  assert.strictEqual(store.state.events.length, 3);
  engine.stop();
  t.mock.timers.tick(3000);
  assert.strictEqual(store.state.events.length, 3);
});

test('inject rejects unknown scenarios', () => {
  assert.throws(() => engine.inject('no_such_scenario'), /Unknown scenario/);
});
