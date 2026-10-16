// Tests: the listen address in src/config.js (SOCSIM_HOST) and the non-loopback startup warning.
const { test, afterEach } = require('node:test');
const assert = require('node:assert');

const CONFIG = require.resolve('../src/config');
const original = process.env.SOCSIM_HOST;

// config.js reads the environment once, when it is first required, so load a fresh copy each time
function loadConfig(host) {
  if (host === undefined) delete process.env.SOCSIM_HOST;
  else process.env.SOCSIM_HOST = host;
  delete require.cache[CONFIG];
  return require(CONFIG);
}

afterEach(() => {
  if (original === undefined) delete process.env.SOCSIM_HOST;
  else process.env.SOCSIM_HOST = original;
  delete require.cache[CONFIG];
});

test('listens on 127.0.0.1 when SOCSIM_HOST is not set', () => {
  assert.strictEqual(loadConfig(undefined).host, '127.0.0.1');
});

test('an empty SOCSIM_HOST falls back to 127.0.0.1', () => {
  assert.strictEqual(loadConfig('').host, '127.0.0.1');
});

test('SOCSIM_HOST overrides the listen address', () => {
  assert.strictEqual(loadConfig('0.0.0.0').host, '0.0.0.0');
});

test('loopback addresses are recognised', () => {
  const { isLoopback } = loadConfig(undefined);
  for (const h of ['127.0.0.1', '127.0.0.2', '127.255.255.254', '::1', 'localhost']) {
    assert.strictEqual(isLoopback(h), true, h);
  }
  for (const h of ['0.0.0.0', '::', '192.168.1.10', '10.0.0.5', '128.0.0.1', '127.0.0', 'localhost.example']) {
    assert.strictEqual(isLoopback(h), false, h);
  }
});

test('no warning for loopback, a clear warning naming the address otherwise', () => {
  const { hostWarning } = loadConfig(undefined);
  assert.strictEqual(hostWarning('127.0.0.1'), null);
  assert.strictEqual(hostWarning('::1'), null);
  const w = hostWarning('0.0.0.0');
  assert.match(w, /^WARNING: listening on 0\.0\.0\.0, which is not a loopback address/);
  assert.match(w, /no login/);
  assert.match(w, /Unset SOCSIM_HOST/);
  assert.match(hostWarning('192.168.1.10'), /listening on 192\.168\.1\.10/);
});
