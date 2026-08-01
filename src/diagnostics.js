'use strict';

const os = require('os');
const { execFile } = require('child_process');
const si = require('systeminformation');

const { APP_NAME, APP_VERSION } = require('./constants');

function fmtBytes(n) {
  if (n == null || isNaN(n)) return '—';
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  let i = 0;
  let v = Number(n);
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${units[i]}`;
}

function run(cmd, args, timeout = 15000) {
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout, windowsHide: true, maxBuffer: 8 * 1024 * 1024 },
      (err, stdout) => resolve({ ok: !err, out: String(stdout || '') }));
  });
}

async function safe(label, fn) {
  try { return { label, ok: true, data: await fn() }; }
  catch (e) { return { label, ok: false, error: String(e && e.message || e) }; }
}

async function collectSoftware() {
  const res = { count: 0, source: 'unknown', top: [], sample: [] };
  try {
    if (process.platform === 'win32') {
      const ps = [
        'Get-ItemProperty',
        'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,',
        'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,',
        'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',
        '| Where-Object { $_.DisplayName } | Select-Object DisplayName,DisplayVersion,Publisher',
        '| Sort-Object DisplayName -Unique | ConvertTo-Json -Compress',
      ].join(' ');
      const r = await run('powershell', ['-NoProfile', '-NonInteractive', '-Command', ps], 45000);
      if (r.ok && r.out.trim()) {
        const list = JSON.parse(r.out.trim());
        const arr = Array.isArray(list) ? list : [list];
        res.count = arr.length;
        res.source = 'Windows registry';
        res.sample = arr.map((a) => a.DisplayName).filter(Boolean).slice(0, 60);
        res.top = res.sample.slice(0, 15);
      }
    } else {
      const [dpkg, rpm] = await Promise.all([
        run('dpkg-query', ['-W', '-f=${Package}\t${Version}\n'], 20000),
        run('rpm', ['-qa', '--qf=%{NAME}\t%{VERSION}\n'], 20000),
      ]);
      if (dpkg.ok && dpkg.out.trim()) {
        const rows = dpkg.out.trim().split('\n').map((l) => l.split('\t')[0]).filter(Boolean);
        res.count = rows.length;
        res.source = 'dpkg';
        res.sample = rows.slice(0, 60);
        res.top = rows.slice(0, 15);
      } else if (rpm.ok && rpm.out.trim()) {
        const rows = rpm.out.trim().split('\n').map((l) => l.split('\t')[0]).filter(Boolean);
        res.count = rows.length;
        res.source = 'rpm';
        res.sample = rows.slice(0, 60);
        res.top = rows.slice(0, 15);
      } else {
        res.source = 'unavailable';
      }
    }
  } catch { res.source = 'unavailable'; }
  return res;
}

async function collectMounts() {
  try {
    const [fsSize, block] = await Promise.all([si.fsSize(), si.blockDevices()]);
    const blockByDev = {};
    for (const b of block) {
      if (!b || !b.name) continue;
      blockByDev[b.name.toLowerCase()] = blockByDev[b.name.toLowerCase()] || {};
      if (b.label) blockByDev[b.name.toLowerCase()].label = b.label;
      if (b.model) blockByDev[b.name.toLowerCase()].model = b.model;
      if (b.serial) blockByDev[b.name.toLowerCase()].serial = b.serial;
      if (b.fsType) blockByDev[b.name.toLowerCase()].fsType = b.fsType;
    }
    return (Array.isArray(fsSize) ? fsSize : []).map((m) => {
      const dev = (m.fs || '').toLowerCase();
      const extra = blockByDev[dev] || {};
      return {
        mount: m.mount, fs: m.fs, type: m.type, size: m.size, used: m.used,
        usePct: m.use, label: extra.label || null, model: extra.model || null,
      };
    });
  } catch { return []; }
}

async function collectNetworkInterfaces() {
  try {
    const ifs = await si.networkInterfaces();
    return (Array.isArray(ifs) ? ifs : []).map((n) => ({
      iface: n.iface, ifaceName: n.ifaceName, ip4: n.ip4, ip6: n.ip6,
      mac: n.mac, internal: n.internal, virtual: n.virtual, operstate: n.operstate,
      type: n.type, duplex: n.duplex, mtu: n.mtu, speed: n.speed,
      default: n.default || false,
    }));
  } catch { return []; }
}

/**
 * Full system diagnostics snapshot. Every section is best-effort:
 * missing tools / permissions degrade to { ok:false } instead of crashing.
 */
async function collectDiagnostics() {
  const [
    system, osi, cpu, cache, mem, memLayout, gfx, disks, mounts, net, batt, usb, sw, temps,
  ] = await Promise.all([
    safe('system', () => si.system()),
    safe('osInfo', () => si.osInfo()),
    safe('cpu', () => si.cpu()),
    safe('cpuCache', () => si.cpuCache()),
    safe('mem', () => si.mem()),
    safe('memLayout', () => si.memLayout()),
    safe('graphics', () => si.graphics()),
    safe('diskLayout', () => si.diskLayout()),
    collectMounts(),
    collectNetworkInterfaces(),
    safe('battery', () => si.battery()),
    safe('usb', () => si.usb()),
    collectSoftware(),
    safe('temps', () => si.cpuTemperature()),
  ]);

  const memNow = mem.ok ? mem.data : {};
  const up = os.uptime();

  return {
    generatedAt: new Date().toISOString(),
    app: { name: APP_NAME, version: APP_VERSION },
    host: {
      hostname: osi.ok ? osi.data.hostname : os.hostname(),
      platform: osi.ok ? osi.data.platform : process.platform,
      distro: osi.ok ? osi.data.distro : 'unknown',
      release: osi.ok ? osi.data.release : '',
      codename: osi.ok ? osi.data.codename : '',
      kernel: osi.ok ? osi.data.kernel : os.release(),
      arch: osi.ok ? osi.data.arch : process.arch,
      uefi: osi.ok ? osi.data.uefi : null,
      virtual: system.ok ? system.data.virtual : null,
      virtualHost: system.ok ? system.data.virtualHost : null,
      manufacturer: system.ok ? system.data.manufacturer : '',
      model: system.ok ? system.data.model : '',
      serial: system.ok ? system.data.serial : '',
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || 'unknown',
      locale: Intl.DateTimeFormat().resolvedOptions().locale || 'unknown',
      uptimeSec: up,
      bootTime: new Date(Date.now() - up * 1000).toISOString(),
      user: os.userInfo().username || 'unknown',
    },
    cpu: {
      ok: cpu.ok,
      manufacturer: cpu.ok ? cpu.data.manufacturer : null,
      brand: cpu.ok ? cpu.data.brand : null,
      speed: cpu.ok ? cpu.data.speed : null,
      speedMin: cpu.ok ? cpu.data.speedMin : null,
      speedMax: cpu.ok ? cpu.data.speedMax : null,
      cores: cpu.ok ? cpu.data.cores : os.cpus().length,
      physicalCores: cpu.ok ? cpu.data.physicalCores : null,
      processors: cpu.ok ? cpu.data.processors : null,
      virtualization: cpu.ok ? cpu.data.virtualization : null,
      cache: cache.ok ? cache.data : null,
    },
    memory: {
      total: memNow.total || null,
      active: memNow.active || null,
      available: memNow.available || null,
      swapTotal: memNow.swapTotal || null,
      modules: (memLayout.ok && Array.isArray(memLayout.data) ? memLayout.data : []).map((m) => ({
        manufacturer: m.manufacturer, type: m.type, formFactor: m.formFactor,
        clockSpeed: m.clockSpeed, size: m.size, partNum: m.partNum, serialNum: m.serialNum,
      })),
    },
    graphics: (gfx.ok && gfx.data.controllers ? gfx.data.controllers : []).map((g) => ({
      vendor: g.vendor, model: g.model, vram: g.vram, driverVersion: g.driverVersion,
      bus: g.bus, name: g.name,
    })),
    disks: (disks.ok && Array.isArray(disks.data) ? disks.data : []).map((d) => ({
      device: d.device, type: d.type, name: d.name, vendor: d.vendor,
      size: d.size, smartStatus: d.smartStatus, firmwareRev: d.firmwareRev, serialNum: d.serialNum,
    })),
    mounts,
    network: net,
    battery: batt.ok ? batt.data : null,
    usb: (usb.ok && Array.isArray(usb.data) ? usb.data : []).map((u) => ({
      bus: u.bus, device: u.device, name: u.name, type: u.type, manufacturer: u.manufacturer,
    })),
    software: sw,
    temps: temps.ok ? temps.data : null,
    load: await safe('load', () => si.currentLoad()),
  };
}

module.exports = { collectDiagnostics, fmtBytes, run };
