// Settings from config.json. dataDir "" means %LOCALAPPDATA%\SocSim (local disk).
// Override with env SOCSIM_DATA_DIR. Listen address: env SOCSIM_HOST, default 127.0.0.1.

const fs = require('fs');
const path = require('path');
const os = require('os');

const cfg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'config.json'), 'utf8'));
const defaultDir = path.join(process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local'), 'SocSim');

// Loopback addresses: 127.0.0.0/8, ::1 and localhost
const isLoopback = host => host === 'localhost' || host === '::1' || /^127(\.\d{1,3}){3}$/.test(host);

// The startup warning server.js prints when the listen address is not loopback, or null
const hostWarning = host => isLoopback(host) ? null :
  `WARNING: listening on ${host}, which is not a loopback address. The API has no login, so anyone who can ` +
  'reach this address can read and change the simulator. This is meant only for the Docker image, where ' +
  'compose.yaml publishes the port on 127.0.0.1 of the host only. Unset SOCSIM_HOST to listen on 127.0.0.1.';

module.exports = {
  // Loopback by default, so `npm start` is reachable from this PC only. Only the Docker image sets
  // SOCSIM_HOST=0.0.0.0, because a published port can only reach a server that listens on the container's
  // own network interface; compose.yaml then publishes it on the host's 127.0.0.1 only, so the host side
  // stays loopback-only. Any non-loopback value makes server.js print a warning at startup.
  host: process.env.SOCSIM_HOST || '127.0.0.1',
  port: cfg.port || 5000,
  dataDir: process.env.SOCSIM_DATA_DIR || cfg.dataDir || defaultDir,
  eventCap: cfg.eventCap || 50000,
  saveIntervalSeconds: cfg.saveIntervalSeconds || 30,
  defaultRate: cfg.defaultRate || 1,
  scenarioEveryMinutes: cfg.scenarioEveryMinutes || 4,
  isLoopback,
  hostWarning,
};

require('./demo-uncovered'); // DEMO
