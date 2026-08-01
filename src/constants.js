'use strict';

const path = require('path');
const os = require('os');

const APP_NAME = 'SysGuard';
const APP_VERSION = '1.0.2';

// Data directory: overridable via env (used by Electron to point at its userData dir)
function dataDir() {
  if (process.env.SYSGUARD_DATA_DIR) return process.env.SYSGUARD_DATA_DIR;
  return path.join(os.homedir(), '.sysguard');
}

const DIRS = {
  root: dataDir(),
  reports: path.join(dataDir(), 'reports'),
};

const DEFAULT_SETTINGS = {
  refreshIntervalMs: 1500,        // monitor poll interval
  historyPoints: 300,             // chart history length
  theme: 'dark',                  // 'dark' | 'light'
  openReportAfterGenerate: true,
  externalChecks: true,           // public IP / geo / DNS checks (need internet)
  minSeverityInReport: 'low',     // lowest severity included in reports
  schedules: [
    {
      id: 'sched-daily',
      label: 'Daily security report',
      enabled: true,
      type: 'daily',              // daily | weekly | interval | startup
      time: '09:00',              // HH:MM (daily/weekly)
      day: 1,                     // 0=Sun..6=Sat (weekly)
      everyHours: 6,              // interval
      include: 'full',            // full | security | diagnostics
      format: 'html',             // html | md | pdf
    },
    {
      id: 'sched-weekly',
      label: 'Weekly deep audit',
      enabled: false,
      type: 'weekly',
      time: '18:00',
      day: 0,
      everyHours: 6,
      include: 'full',
      format: 'pdf',
    },
  ],
  expectedCountry: '',            // if set, flag public IP in other countries
};

const SEVERITIES = { critical: 25, high: 12, medium: 6, low: 2, info: 0 };
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

// High-confidence suspicious process name fragments (miners, RATs, stealers...)
const SUSPICIOUS_PROCESS_PATTERNS = [
  // miners
  'xmrig', 'miner', 'cpuminer', 'nicehash', 'lolminer', 't-rex', 'nbminer',
  'kryptex', 'phoenixminer', 'nanominer', 'ethminer', 'cgminer', 'bfgminer',
  'claymore', 'wildrig', 'teamredminer', 'gminer', 'srbminer', 'zerominer',
  'qubic', 'xmr', 'monero', 'nheqminer', 'minerd',
  // RATs / remote access trojans
  'njrat', 'darkcomet', 'imrat', 'xrat', 'remcos', 'asyncrat', 'quasar',
  'hworm', 'netwire', 'poisonivy', 'gh0st', 'mimikatz', 'njrat', 'servstart',
  // stealers / banking trojans
  'redline', 'raccoon', 'vidar', 'azorult', 'lokibot', 'emotet', 'trickbot',
  'qakbot', 'stealer', 'iceid', 'smoke', 'formbook', 'agenttesla',
  // keyloggers
  'keylog', 'ardamax', 'refog', 'spyrix', 'spyagent',
  // misc malicious helpers
  'backdoor', 'trojan', 'botnet', 'cryptolocker', 'ransom',
];

// Directories where a running executable is highly suspicious
const SUSPICIOUS_PATH_FRAGMENTS = [
  '/tmp/', '/dev/shm', '/var/tmp', '/run/user', '$recycle.bin',
  '\\windows\\temp\\', '\\temp\\', '/appdata/local/temp',
];

// Well-known services that should usually not be exposed on all interfaces
const EXPOSED_PORT_NOTES = {
  21: 'FTP (cleartext credentials)',
  23: 'Telnet (cleartext, insecure)',
  25: 'SMTP mail server',
  135: 'Windows RPC',
  137: 'NetBIOS name service',
  138: 'NetBIOS datagram',
  139: 'NetBIOS session (SMB legacy)',
  445: 'SMB file sharing (EternalBlue family)',
  1433: 'Microsoft SQL Server',
  3306: 'MySQL',
  3389: 'RDP (brute-force target)',
  5432: 'PostgreSQL',
  5900: 'VNC (often no encryption)',
  6379: 'Redis (unauthenticated RCE risk)',
  27017: 'MongoDB (unauthenticated exposure risk)',
  9200: 'Elasticsearch (exposure risk)',
  11211: 'Memcached (DDoS amplification)',
};

module.exports = {
  APP_NAME,
  APP_VERSION,
  DIRS,
  DEFAULT_SETTINGS,
  SEVERITIES,
  SEVERITY_ORDER,
  SUSPICIOUS_PROCESS_PATTERNS,
  SUSPICIOUS_PATH_FRAGMENTS,
  EXPOSED_PORT_NOTES,
};
