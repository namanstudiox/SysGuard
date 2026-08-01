'use strict';

const os = require('os');
const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const si = require('systeminformation');
const { run } = require('./diagnostics');
const netcheck = require('./netcheck');
const { SEVERITIES, SEVERITY_ORDER, SUSPICIOUS_PROCESS_PATTERNS,
        SUSPICIOUS_PATH_FRAGMENTS, EXPOSED_PORT_NOTES } = require('./constants');

const isWin = process.platform === 'win32';

let _idc = 0;
function finding(category, severity, title, detail, recommendation, evidence = []) {
  return {
    id: `f-${Date.now()}-${_idc++}`,
    category, severity, title,
    detail: detail || '',
    recommendation: recommendation || '',
    evidence: (evidence || []).slice(0, 8),
  };
}

function grade(score) {
  if (score >= 90) return 'A+';
  if (score >= 80) return 'A';
  if (score >= 70) return 'B';
  if (score >= 60) return 'C';
  if (score >= 50) return 'D';
  return 'F';
}

// Ports
async function listeningPorts() {
  const out = [];
  let raw = '';
  if (isWin) {
    const r = await run('netstat', ['-ano', '-p', 'tcp'], 20000);
    if (!r.ok) return out;
    raw = r.out;
    const pidNames = {};
    const pr = await run('powershell', ['-NoProfile', '-NonInteractive', '-Command',
      'Get-Process | Select-Object Id,ProcessName | ConvertTo-Json -Compress'], 20000);
    if (pr.ok && pr.out.trim()) {
      try {
        const list = JSON.parse(pr.out.trim());
        (Array.isArray(list) ? list : [list]).forEach((p) => { if (p && p.Id) pidNames[String(p.Id)] = p.ProcessName; });
      } catch { /* ignore */ }
    }
    for (const line of raw.split('\n')) {
      const m = line.match(/^\s*TCP\s+(\S+):(\d+)\s+\S+\s+LISTENING\s+(\d+)\s*$/i);
      if (!m) continue;
      const pid = m[3];
      out.push({ proto: 'tcp', addr: m[1], port: parseInt(m[2], 10), pid, name: pidNames[pid] || null });
    }
  } else {
    let r = await run('ss', ['-tuln'], 15000);
    let headerSeen = false;
    if (r.ok) {
      for (const line of r.out.split('\n')) {
        if (!headerSeen) { headerSeen = line.trim().startsWith('Netid') || line.trim().startsWith('State'); continue; }
        const parts = line.trim().split(/\s+/);
        if (parts.length < 5) continue;
        const proto = parts[0].toLowerCase();
        const local = parts[4]; // e.g. 0.0.0.0:22  or [::]:80
        const m = local.match(/^\[?([^\]]*)\]?:(\d+)$/);
        if (!m) continue;
        const port = parseInt(m[2], 10);
        const addr = m[1] === '*' ? '0.0.0.0' : m[1];
        out.push({ proto, addr, port, pid: null, name: null });
      }
    } else {
      r = await run('netstat', ['-tuln'], 15000);
      if (r.ok) {
        for (const line of r.out.split('\n')) {
          const m = line.match(/^\s*(tcp|tcp6|udp|udp6)\s+\d+\s+\d+\s+(\S+):(\d+)\s+\S+/i);
          if (!m) continue;
          const addr = m[2] === '*' || m[2] === '::' ? '0.0.0.0' : m[2];
          out.push({ proto: m[1].toLowerCase().replace(/6$/, ''), addr, port: parseInt(m[3], 10), pid: null, name: null });
        }
      }
    }
    // enrich with pid/name via systeminformation (works without root on Linux)
    try {
      const conns = await si.networkConnections();
      const byPort = new Map();
      (Array.isArray(conns) ? conns : []).forEach((c) => {
        if (c && c.localPort && c.pid) byPort.set(`${c.localPort}`, { pid: c.pid, name: c.process || null });
      });
      out.forEach((p) => { const e = byPort.get(String(p.port)); if (e) { p.pid = e.pid; p.name = e.name; } });
    } catch { /* best effort */ }
  }
  // dedupe identical listeners
  const seen = new Set();
  return out.filter((p) => {
    const k = `${p.proto}|${p.addr}|${p.port}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

// Services
async function runningServices
() {
  if (isWin) {
    const r = await run('powershell', ['-NoProfile', '-NonInteractive', '-Command',
      'Get-CimInstance Win32_Service | Select-Object Name,DisplayName,StartMode,State,PathName | ConvertTo-Json -Compress'], 45000);
    if (!r.ok || !r.out.trim()) return { list: [], source: 'cim' };
    try {
      const list = JSON.parse(r.out.trim());
      const arr = Array.isArray(list) ? list : [list];
      return { list: arr.map((s) => ({ name: s.Name, display: s.DisplayName, startMode: s.StartMode, state: s.State, path: s.PathName })), source: 'win32_service' };
    } catch { return { list: [], source: 'cim-parse-error' }; }
  }
  const r = await run('systemctl', ['list-units', '--type=service', '--state=running', '--no-legend', '--no-pager'], 20000);
  if (!r.ok) return { list: [], source: 'unavailable' };
  const list = r.out.split('\n').filter(Boolean).map((l) => l.trim().split(/\s+/)[0]).filter((n) => n && n.endsWith('.service'));
  return { list: list.map((n) => ({ name: n, display: n.replace(/\.service$/, '') })), source: 'systemd' };
}

async function enabledServices() {
  if (isWin) {
    const r = await run('powershell', ['-NoProfile', '-NonInteractive', '-Command',
      'Get-CimInstance Win32_Service | Where-Object { $_.StartMode -eq "Auto" } | Select-Object Name,DisplayName,PathName | ConvertTo-Json -Compress'], 45000);
    if (!r.ok || !r.out.trim()) return { list: [], source: 'cim' };
    try {
      const list = JSON.parse(r.out.trim());
      const arr = Array.isArray(list) ? list : [list];
      return { list: arr.map((s) => ({ name: s.Name, display: s.DisplayName, path: s.PathName })), source: 'win32_service' };
    } catch { return { list: [], source: 'cim-parse-error' }; }
  }
  const r = await run('systemctl', ['list-unit-files', '--type=service', '--state=enabled', '--no-legend', '--no-pager'], 20000);
  if (!r.ok) return { list: [], source: 'unavailable' };
  const list = r.out.split('\n').filter(Boolean).map((l) => l.trim().split(/\s+/)[0]).filter((n) => n && n.endsWith('.service'));
  return { list: list.map((n) => ({ name: n, display: n.replace(/\.service$/, '') })), source: 'systemd' };
}

// Startup items
async function startupItems
() {
  const items = [];
  if (isWin) {
    const keys = [
      'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
      'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
      'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
      'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
      'HKLM\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run',
    ];
    for (const k of keys) {
      const r = await run('reg', ['query', k], 8000);
      if (!r.ok) continue;
      for (const line of r.out.split('\n')) {
        const m = line.match(/^\s*(\S+)\s+REG_[A-Z_]+\s+(.+)$/);
        if (m) items.push({ name: m[1], value: m[2].trim(), location: k });
      }
    }
    const sf = await run('powershell', ['-NoProfile', '-NonInteractive', '-Command',
      'Get-ChildItem "$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name'], 10000);
    if (sf.ok) sf.out.split('\n').map((s) => s.trim()).filter(Boolean).forEach((n) => items.push({ name: n, value: '', location: 'Startup folder' }));
  } else {
    const dirs = [
      path.join(os.homedir(), '.config', 'autostart'),
      '/etc/xdg/autostart',
      path.join(os.homedir(), '.config', 'systemd', 'user'),
    ];
    for (const d of dirs) {
      try {
        const names = await fsp.readdir(d);
        for (const n of names) {
          if (n.endsWith('.desktop') || n.endsWith('.service')) items.push({ name: n, value: '', location: d });
        }
      } catch { /* dir missing */ }
    }
    const r = await run('systemctl', ['--user', 'list-unit-files', '--state=enabled', '--no-legend', '--no-pager'], 10000);
    if (r.ok) r.out.split('\n').map((l) => l.trim().split(/\s+/)[0]).filter(Boolean).forEach((n) => items.push({ name: n, value: '', location: 'systemd (user)' }));
  }
  return items;
}

// Firewall
async function firewallStatus
() {
  if (isWin) {
    const r = await run('netsh', ['advfirewall', 'show', 'allprofiles', 'state'], 15000);
    if (!r.ok) return { available: false, active: null, detail: 'netsh unavailable' };
    const onCount = (r.out.match(/State\s+ON/i) || []).length;
    const offCount = (r.out.match(/State\s+OFF/i) || []).length;
    return { available: true, active: onCount > 0 && offCount === 0, detail: r.out.split('\n').map((l) => l.trim()).filter(Boolean).slice(0, 12) };
  }
  const ufw = await run('ufw', ['status'], 8000);
  if (ufw.ok && /Status:\s*active/i.test(ufw.out)) return { available: true, active: true, tool: 'ufw' };
  if (ufw.ok && /Status:\s*inactive/i.test(ufw.out)) {
    // still verify raw iptables/nftables rules
    const raw = await rawPacketFilterActive();
    return { available: true, active: raw, tool: 'ufw-inactive', note: raw ? 'UFW inactive but raw iptables/nft rules exist' : 'UFW inactive' };
  }
  const fwcmd = await run('firewall-cmd', ['--state'], 8000);
  if (fwcmd.ok && fwcmd.out.trim().toLowerCase() === 'running') return { available: true, active: true, tool: 'firewalld' };
  const raw = await rawPacketFilterActive();
  return { available: raw.available, active: raw.active, tool: raw.tool || 'raw' };
}

async function rawPacketFilterActive() {
  const nft = await run('nft', ['list', 'ruleset'], 8000);
  if (nft.ok && nft.out.trim().length > 20) return { available: true, active: true, tool: 'nftables' };
  const ipt = await run('iptables', ['-S'], 8000);
  if (ipt.ok) {
    const rules = ipt.out.split('\n').filter((l) => l.trim() && !l.trim().startsWith('-P')).length;
    return { available: true, active: rules > 0, tool: 'iptables' };
  }
  return { available: false, active: null, tool: 'none' };
}

// Updates
async function pendingUpdates
() {
  if (isWin) {
    // Best-effort: query the Microsoft.Update COM searcher
    const ps = [
      'try {',
      '$s = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()',
      '$r = $s.Search("IsInstalled=0 and IsHidden=0")',
      'Write-Output ("COUNT=" + $r.Updates.Count)',
      '} catch { Write-Output "COUNT=unknown" }',
    ].join(' ');
    const r = await run('powershell', ['-NoProfile', '-NonInteractive', '-Command', ps], 90000);
    const m = r.ok ? r.out.match(/COUNT=(\d+|unknown)/) : null;
    if (!m) return { available: false, detail: 'Windows Update query failed (may require elevated rights or blocked service)' };
    const count = m[1] === 'unknown' ? null : parseInt(m[1], 10);
    const hotfix = await run('powershell', ['-NoProfile', '-NonInteractive', '-Command',
      'Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1 -ExpandProperty InstalledOn'], 30000);
    return {
      available: true, count, lastHotfix: hotfix.ok ? hotfix.out.trim() : null,
      detail: count == null ? 'Update service not responding' : `${count} update(s) applicable`,
    };
  }
  // Linux package manager

s
  if (fs.existsSync('/usr/bin/apt-get') || fs.existsSync('/usr/bin/apt')) {
    const sim = await run('apt-get', ['-s', 'upgrade'], 90000);
    if (sim.ok) {
      const inst = sim.out.split('\n').filter((l) => l.startsWith('Inst '));
      const sec = inst.filter((l) => /security/i.test(l));
      return {
        available: true, count: inst.length, securityCount: sec.length,
        detail: `${inst.length} upgradable, ${sec.length} from security repos (as of last 'apt update')`,
      };
    }
    return { available: false, detail: 'apt simulation failed' };
  }
  if (fs.existsSync('/usr/bin/dnf') || fs.existsSync('/usr/bin/yum')) {
    const tool = fs.existsSync('/usr/bin/dnf') ? 'dnf' : 'yum';
    const r = await run(tool, ['check-update', '--security'], 90000);
    // exit 100 => updates available; 0 => none
    const lines = r.out.split('\n').filter((l) => l.trim() && !l.trim().startsWith('Last metadata') && !l.trim().startsWith('Updating')).length;
    return { available: true, count: r.ok ? null : null, securityCount: r.ok ? null : lines, detail: `dnf check-update --security: ${r.ok ? 'no security updates listed' : `${lines} security update line(s)`}` };
  }
  return { available: false, detail: 'No supported package manager found' };
}

// Processes & connections
async function suspiciousProcesses
() {
  const findings = [];
  const procs = await si.processes().catch(() => ({ list: [] }));
  const list = Array.isArray(procs.list) ? procs.list : [];
  const conns = await si.networkConnections().catch(() => []);

  const connByPid = new Map();
  (Array.isArray(conns) ? conns : []).forEach((c) => {
    if (!c || !c.pid) return;
    if (!connByPid.has(c.pid)) connByPid.set(c.pid, []);
    connByPid.get(c.pid).push(c);
  });

  const reported = new Set();

  for (const p of list) {
    if (!p || !p.name) continue;
    const lower = `${p.name} ${p.command || ''}`.toLowerCase();
    const matched = SUSPICIOUS_PROCESS_PATTERNS.find((pat) => lower.includes(pat));
    const pathSuspicious = SUSPICIOUS_PATH_FRAGMENTS.some((f) => {
      const hay = `${p.path || ''} ${p.command || ''}`.toLowerCase();
      return hay.includes(f.toLowerCase());
    });
    if (matched && !reported.has(p.name)) {
      reported.add(p.name);
      findings.push(finding('Processes', 'critical',
        `Potentially malicious process detected: ${p.name}`,
        `Process "${p.name}" (PID ${p.pid}) matches known malware/miner signature "${matched}".`,
        'Investigate immediately. Verify the process, terminate it and run an antivirus scan. Use "kill" from the Monitor tab if you are certain.',
        [p.command || p.path || p.name]));
    } else if (pathSuspicious && !reported.has(`path:${p.pid}`)) {
      reported.add(`path:${p.pid}`);
      findings.push(finding('Processes', 'high',
        `Process running from suspicious location: ${p.name}`,
        `PID ${p.pid} is executing from a temp / writable location (${p.path || p.command || 'unknown'}).`,
        'Binaries in temp directories are a common malware pattern. Verify the executable and move trusted software to a permanent install location.',
        [p.path || p.command]));
    }
  }

  // outbound connections to unusual ports (not 80/443/53/853)
  const unusualOutbound = [];
  for (const c of (Array.isArray(conns) ? conns : [])) {
    if (!c || !c.peerPort || c.localPort) continue;
    if (!netcheck.isPrivateIp(c.peerAddress || '')) {
      if (![80, 443, 53, 853, 22, 123, 993, 995, 587, 465, 5222, 5228, 1194, 3478, 4500].includes(c.peerPort)) {
        unusualOutbound.push(`${c.process || `pid ${c.pid}`} -> ${c.peerAddress}:${c.peerPort}`);
      }
    }
  }
  if (unusualOutbound.length) {
    findings.push(finding('Processes', 'low',
      `${unusualOutbound.length} outbound connection(s) to non-standard ports`,
      'Some processes maintain connections to external hosts on unusual ports (P2P, tunneling, custom protocols).',
      'Review the listed connections. If unexpected, block them with a firewall rule.',
      unusualOutbound.slice(0, 8)));
  }

  // heavy CPU consumers
  const heavy = list
    .filter((p) => p && typeof p.cpu === 'number' && p.cpu > 60 && !['Idle'].includes(p.name))
    .sort((a, b) => b.cpu - a.cpu).slice(0, 5);
  if (heavy.length) {
    findings.push(finding('Processes', 'low',
      `${heavy.length} process(es) consuming high CPU right now`,
      heavy.map((p) => `${p.name} (PID ${p.pid}) — ${p.cpu.toFixed(1)}% CPU`).join('; '),
      'High CPU is not always malicious — check whether these are expected workloads. Watch for sustained usage.',
      heavy.map((p) => `${p.name} (PID ${p.pid}) — ${p.cpu.toFixed(1)}% CPU`)));
  }
  return findings;
}

// Accounts & policy
async function accountsAndPolicy
() {
  const findings = [];
  if (isWin) {
    const admins = await run('powershell', ['-NoProfile', '-NonInteractive', '-Command',
      'net localgroup administrators | Select-Object -Skip 4'], 20000);
    const adminList = admins.ok ? admins.out.split('\n').map((l) => l.trim()).filter((l) => l && !/command completed/i.test(l)) : [];
    if (adminList.length > 4) {
      findings.push(finding('Accounts & Policy', 'medium',
        `${adminList.length} accounts in the Administrators group`,
        'Every admin account is a potential entry point if its credentials are compromised.',
        'Review membership and remove accounts that do not require administrator rights.', adminList));
    }
    const guest = await run('powershell', ['-NoProfile', '-NonInteractive', '-Command',
      'Get-LocalUser | Where-Object { $_.Name -match "Guest" -and $_.Enabled } | Select-Object -ExpandProperty Name'], 20000);
    if (guest.ok && guest.out.trim()) {
      findings.push(finding('Accounts & Policy', 'medium', 'Guest account is enabled', 'An enabled guest account allows anonymous local logon.', 'Disable the Guest account.', [guest.out.trim()]));
    }
    const uac = await run('reg', ['query', 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System', '/v', 'EnableLUA'], 8000);
    if (uac.ok && /EnableLUA\s+REG_DWORD\s+0x0/i.test(uac.out)) {
      findings.push(finding('Accounts & Policy', 'high', 'UAC is disabled', 'User Account Control is turned off, so programs run with full privileges silently.', 'Re-enable UAC (set EnableLUA to 1) and restart.', ['EnableLUA=0']));
    }
    const autoUpd = await run('reg', ['query', 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\AU', '/v', 'NoAutoUpdate'], 8000);
    if (autoUpd.ok && /NoAutoUpdate\s+REG_DWORD\s+0x1/i.test(autoUpd.out)) {
      findings.push(finding('Accounts & Policy', 'medium', 'Windows automatic updates are disabled', 'NoAutoUpdate=1 means the machine will not install updates automatically.', 'Enable automatic updates in Windows Update settings.', ['NoAutoUpdate=1']));
    }
    const defender = await run('powershell', ['-NoProfile', '-NonInteractive', '-Command',
      'try { $d = Get-MpComputerStatus; "RTP=" + $d.RealTimeProtectionEnabled } catch { "RTP=unknown" }'], 40000);
    if (defender.ok && /RTP=False/i.test(defender.out)) {
      findings.push(finding('Accounts & Policy', 'high', 'Windows Defender real-time protection is off', 'Real-time antivirus protection is disabled.', 'Re-enable real-time protection in Windows Security.', ['RealTimeProtectionEnabled=False']));
    }
    const netAcct = await run('net', ['accounts'], 15000);
    const m = netAcct.ok ? netAcct.out.match(/Maximum password age\s*:\s*(\d+)/i) : null;
    if (m && parseInt(m[1], 10) > 90) {
      findings.push(finding('Accounts & Policy', 'medium', `Maximum password age is ${m[1]} days`, 'Passwords can be used far longer than recommended (90 days).', 'Set a shorter maximum password age via Local Security Policy.', [`Max password age: ${m[1]} days`]));
    }
  } else {
    // Linux
    try {
      const passwd = await fsp.readFile('/etc/passwd', 'utf8');
      const users = passwd.split('\n').filter(Boolean).map((l) => l.split(':'));
      const shellUsers = users.filter((u) => u[6] && /(ba|z|k|fi)?sh$/.test(u[6]) && !['nologin', 'false', 'sync'].includes(u[6]));
      const rootUsers = users.filter((u) => u[2] === '0' && u[0] !== 'root');
      if (rootUsers.length) {
        findings.push(finding('Accounts & Policy', 'critical', `${rootUsers.length} non-root account(s) with UID 0`, 'Accounts with UID 0 have root privileges.', 'Investigate and remove these accounts or change their UIDs.', rootUsers.map((u) => u[0])));
      }
      if (shellUsers.length > 20) {
        findings.push(finding('Accounts & Policy', 'low', `${shellUsers.length} user accounts have login shells`, 'Many interactive accounts increase the attack surface.', 'Disable shells for accounts that do not need interactive logon.', shellUsers.slice(0, 8).map((u) => u[0])));
      }
    } catch { /* passwd unreadable */ }
    try {
      const group = await fsp.readFile('/etc/group', 'utf8');
      const sudoLine = group.split('\n').find((l) => l.startsWith('sudo:') || l.startsWith('wheel:'));
      const members = sudoLine ? sudoLine.split(':')[3].split(',').filter(Boolean) : [];
      if (members.length > 5) {
        findings.push(finding('Accounts & Policy', 'medium', `${members.length} accounts in sudo group`, 'Every sudo account can escalate to root.', 'Review sudo group membership.', members));
      }
    } catch { /* group unreadable */ }
    try {
      const ld = await fsp.readFile('/etc/login.defs', 'utf8');
      const mMax = ld.match(/^\s*PASS_MAX_DAYS\s+(\d+)/m);
      const mMin = ld.match(/^\s*PASS_MIN_LEN\s+(\d+)/m);
      if (mMax && parseInt(mMax[1], 10) > 90) findings.push(finding('Accounts & Policy', 'medium', `Password max age is ${mMax[1]} days`, 'Recommended maximum password age is ≤ 90 days.', 'Lower PASS_MAX_DAYS in /etc/login.defs.', [`PASS_MAX_DAYS=${mMax[1]}`]));
      if (mMin && parseInt(mMin[1], 10) < 8) findings.push(finding('Accounts & Policy', 'medium', `Minimum password length is ${mMin[1]}`, 'Short passwords are easy to brute-force.', 'Raise PASS_MIN_LEN to 8+ in /etc/login.defs.', [`PASS_MIN_LEN=${mMin[1]}`]));
    } catch { /* login.defs unreadable */ }
    try {
      const ssh = await fsp.readFile('/etc/ssh/sshd_config', 'utf8');
      const clean = ssh.split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
      const rootLogin = clean.find((l) => /^PermitRootLogin\s+yes/i.test(l));
      if (rootLogin) findings.push(finding('Accounts & Policy', 'high', 'SSH root login is enabled', 'PermitRootLogin yes allows direct root over SSH.', 'Set PermitRootLogin to prohibit-password or no.', [rootLogin]));
      const pwAuth = clean.find((l) => /^PasswordAuthentication\s+yes/i.test(l));
      if (pwAuth) findings.push(finding('Accounts & Policy', 'low', 'SSH password authentication enabled', 'Key-based auth is more resistant to brute force.', 'Consider disabling PasswordAuthentication in favour of keys.', [pwAuth]));
    } catch { /* no sshd_config */ }
  }
  return findings;
}

// Open ports exposure analysis
function portFindings
(ports) {
  const findings = [];
  const exposed = ports.filter((p) => p.addr === '0.0.0.0' || p.addr === '::' || p.addr === '*');
  const total = ports.length;
  if (total === 0) {
    findings.push(finding('Open Ports', 'info', 'No listening TCP ports found', 'No local services are accepting TCP connections.', ''));
  } else {
    findings.push(finding('Open Ports', 'info', `${total} listening port(s)`, 'List of services currently accepting connections on this machine.', 'Review the list; close ports you do not need.', ports.map((p) => `${p.port} (${p.proto}) ${p.addr}${p.name ? ' — ' + p.name : ''}`).slice(0, 10)));
  }
  const risky = exposed.filter((p) => EXPOSED_PORT_NOTES[p.port]);
  if (risky.length) {
    findings.push(finding('Open Ports', 'medium',
      `${risky.length} risky service(s) exposed on all interfaces`,
      risky.map((p) => `${EXPOSED_PORT_NOTES[p.port]} (port ${p.port})`).join('; ') + '. These services listen on every interface, so any device on the network can reach them.',
      'Restrict the bind address to localhost/trusted interfaces, or filter with the firewall.'));
  }
  if (exposed.length && !risky.length) {
    findings.push(finding('Open Ports', 'low', `${exposed.length} port(s) bound to all interfaces`, 'These are reachable by other devices on the local network.', 'Confirm each service needs network exposure.', exposed.slice(0, 8).map((p) => `${p.port} ${p.proto}`)));
  }
  return findings;
}

// Main scan
async function runSecurityScan
(opts = {}) {
  const t0 = Date.now();
  const { externalChecks = true, expectedCountry = '' } = opts;
  const findings = [];
  _idc = 0;

  const [ports, svcRunning, svcEnabled, startup, firewall, updates, procFindings, acctFindings] = await Promise.all([
    listeningPorts().catch(() => []),
    runningServices().catch(() => ({ list: [], source: 'unavailable' })),
    enabledServices().catch(() => ({ list: [], source: 'unavailable' })),
    startupItems().catch(() => []),
    firewallStatus().catch(() => ({ available: false, active: null })),
    pendingUpdates().catch(() => ({ available: false, detail: 'update check failed' })),
    suspiciousProcesses().catch(() => []),
    accountsAndPolicy().catch(() => []),
  ]);

  findings.push(...portFindings(ports));

  // Services
  if (svcEnabled.list.length) {
    findings.push(finding('Services & Startup', 'info',
      `${svcEnabled.list.length} auto-start service(s)`,
      'Services configured to start automatically at boot.',
      'Disable any service you do not recognize or need.', svcEnabled.list.slice(0, 10).map((s) => s.name)));
  }
  const weirdSvc = svcEnabled.list.filter((s) => {
    const p = (s.path || '').toLowerCase();
    return SUSPICIOUS_PATH_FRAGMENTS.some((f) => p.includes(f.toLowerCase()));
  });
  if (weirdSvc.length) {
    findings.push(finding('Services & Startup', 'high',
      `${weirdSvc.length} auto-start service(s) run from suspicious paths`,
      'Services launching from temp/writable locations are a classic persistence technique.',
      'Inspect these services and remove any that are not expected.', weirdSvc.map((s) => `${s.name} → ${s.path}`)));
  }
  if (svcRunning.list.length === 0 && svcRunning.source !== 'unavailable') {
    findings.push(finding('Services & Startup', 'info', 'No running services detected', 'The service query returned no running services.', ''));
  }

  // Startup items
  if (startup.length) {
    findings.push(finding('Services & Startup', 'info',
      `${startup.length} startup entrie(s)`,
      'Programs that launch automatically when you log in.',
      'Review startup items for anything you do not recognize.', startup.slice(0, 10).map((s) => `${s.name}${s.location ? '  [' + s.location + ']' : ''}`)));
    const weirdStart = startup.filter((s) => {
      const v = `${s.value} ${s.name}`.toLowerCase();
      return SUSPICIOUS_PATH_FRAGMENTS.some((f) => v.includes(f.toLowerCase()));
    });
    if (weirdStart.length) {
      findings.push(finding('Services & Startup', 'high',
        `${weirdStart.length} startup item(s) from suspicious locations`,
        'Startup entries pointing into temp folders are often malware persistence.',
        'Remove the entries and scan the files.', weirdStart.map((s) => `${s.name} → ${s.value}`)));
    }
  } else {
    findings.push(finding('Services & Startup', 'info', 'No startup entries found', 'Nothing is set to auto-start at logon.', ''));
  }

  // Firewall
  if (!firewall.available) {
    findings.push(finding('Firewall', 'high', 'Firewall status could not be determined',
      'The firewall could not be inspected (missing tools or permission).',
      'Verify manually that a firewall is active. Install ufw/firewalld or check Windows Defender Firewall.'));
  } else if (firewall.active === false) {
    findings.push(finding('Firewall', 'critical', 'No active firewall detected',
      firewall.note ? `Details: ${firewall.note}` : 'The host firewall appears to be off.',
      'Enable the firewall immediately (ufw enable / firewalld start / Windows Defender Firewall on).'));
  } else {
    findings.push(finding('Firewall', 'info', 'Firewall is active', `Active firewall detected${firewall.tool ? ` (${firewall.tool})` : ''}.`, ''));
  }

  // Updates
  if (!updates.available) {
    findings.push(finding('Updates & Patching', 'medium', 'Could not check for pending updates', updates.detail || 'The update check failed.', 'Check for updates manually.'));
  } else if (updates.count && updates.count > 0) {
    const sec = updates.securityCount || 0;
    findings.push(finding('Updates & Patching', sec > 0 ? 'high' : 'medium',
      `${updates.count} update(s) pending${sec > 0 ? `, ${sec} security-related` : ''}`,
      updates.detail,
      'Install pending updates as soon as possible, especially security updates.',
      [updates.detail]));
  } else {
    findings.push(finding('Updates & Patching', 'info', 'System appears up to date', updates.detail, ''));
  }

  findings.push(...procFindings);
  findings.push(...acctFindings);

  // Network checks
  let network = null;
  if (externalChecks) {
    const [pub, dns] = await Promise.all([netcheck.getPublicIp(), netcheck.checkDnsReachability()]);
    const geo = pub.ok ? await netcheck.getGeo(pub.ip) : { ok: false };
    const nat = netcheck.natStatus(ports.map((p) => p.addr).filter((a) => a && a !== '0.0.0.0' && a !== '::').concat(localIps()), pub.ip);
    const vpn = netcheck.classifyVpn(geo);
    network = { publicIp: pub.ok ? pub.ip : null, geo: geo.ok ? geo : null, nat, vpn, dns };
    if (!pub.ok) {
      findings.push(finding('Network', 'low', 'Could not determine public IP', pub.error, 'Check internet connectivity.', [pub.error]));
    } else {
      if (expectedCountry && geo.ok && geo.countryCode !== expectedCountry) {
        findings.push(finding('Network', 'medium', `Public IP is in ${geo.country} (expected ${expectedCountry})`,
          'The public IP geolocation differs from the expected country — possible VPN or unexpected egress.',
          'Verify your VPN status and egress location.', [`${geo.country} (${geo.countryCode}), ISP: ${geo.isp || 'unknown'}`]));
      } else {
        findings.push(finding('Network', 'info', `Public IP: ${pub.ip}${geo.ok ? ` — ${geo.country}` : ''}`,
          geo.ok ? `ISP: ${geo.isp || 'unknown'} · ${geo.city || ''} ${geo.region || ''}` : '',
          ''));
      }
      if (vpn.vpnish) {
        findings.push(finding('Network', 'low', 'Public IP looks like a VPN / hosting / proxy endpoint',
          vpn.reason,
          'Fine for privacy, but verify this is expected for your network.', [geo.org || geo.isp]));
      }
      findings.push(finding('Network', 'info', `NAT status: ${nat.behindNAT === false ? 'directly exposed' : (nat.behindNAT ? 'behind NAT' : 'unknown')}`,
        nat.note, ''));
    }
    findings.push(finding('Network', dns ? 'info' : 'high', `DNS resolvability to 8.8.8.8: ${dns ? 'OK' : 'FAILED'}`,
      dns ? 'Outbound UDP/53 reachable.' : 'Could not reach a public DNS resolver — internet egress may be blocked or broken.',
      dns ? '' : 'Check your network/DNS configuration.'));
  } else {
    findings.push(finding('Network', 'info', 'External network checks disabled', 'Public IP / VPN / DNS checks were skipped per settings.', ''));
  }

  // Score
  const score = Math.max(0, Math.min(100, 100 - findings.reduce((acc, f) => acc + (SEVERITIES[f.severity] || 0), 0)));
  const summary = {};
  for (const s of SEVERITY_ORDER) summary[s] = findings.filter((f) => f.severity === s).length;

  // category rollup
  const cats = new Map();
  for (const f of findings) {
    if (!cats.has(f.category)) cats.set(f.category, { name: f.category, count: 0, deductions: 0, severities: {} });
    const c = cats.get(f.category);
    c.count += 1;
    c.deductions += SEVERITIES[f.severity] || 0;
    c.severities[f.severity] = (c.severities[f.severity] || 0) + 1;
  }

  return {
    ok: true,
    generatedAt: new Date().toISOString(),
    durationMs: Date.now() - t0,
    host: os.hostname(),
    score,
    grade: grade(score),
    summary,
    categories: [...cats.values()].sort((a, b) => b.deductions - a.deductions),
    findings,
    ports,
    services: { running: svcRunning.list.length, enabled: svcEnabled.list.length, source: svcEnabled.source },
    startupCount: startup.length,
    firewall,
    updates,
    network,
  };
}

function localIps() {
  const ifs = os.networkInterfaces();
  const out = [];
  for (const k of Object.keys(ifs || {})) {
    for (const a of ifs[k] || []) if (a && a.family === 'IPv4') out.push(a.address);
  }
  return out;
}

const CHECK_DESCRIPTIONS = [
  { key: 'Open Ports', title: 'Open ports & exposed services', icon: '🔌' },
  { key: 'Services & Startup', title: 'Auto-start services & startup items', icon: '⚙️' },
  { key: 'Firewall', title: 'Firewall status', icon: '🛡️' },
  { key: 'Updates & Patching', title: 'Pending updates & patching', icon: '📦' },
  { key: 'Processes', title: 'Suspicious processes & connections', icon: '🧬' },
  { key: 'Accounts & Policy', title: 'Accounts & security policy', icon: '👤' },
  { key: 'Network', title: 'Public IP, VPN & DNS checks', icon: '🌐' },
];

module.exports = { runSecurityScan, listeningPorts, CHECK_DESCRIPTIONS };
