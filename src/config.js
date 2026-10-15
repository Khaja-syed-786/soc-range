// Settings from config.json. dataDir "" means %LOCALAPPDATA%\SocSim (local disk).
// Override with env SOCSIM_DATA_DIR.

const fs = require('fs');
const path = require('path');
const os = require('os');

const cfg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'config.json'), 'utf8'));
const defaultDir = path.join(process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local'), 'SocSim');

module.exports = {
  host: '127.0.0.1', // never change: local only
  port: cfg.port || 5000,
  dataDir: process.env.SOCSIM_DATA_DIR || cfg.dataDir || defaultDir,
  eventCap: cfg.eventCap || 50000,
  saveIntervalSeconds: cfg.saveIntervalSeconds || 30,
  defaultRate: cfg.defaultRate || 1,
  scenarioEveryMinutes: cfg.scenarioEveryMinutes || 4,
};
