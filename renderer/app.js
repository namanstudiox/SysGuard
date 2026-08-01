'use strict';

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => [...document.querySelectorAll(sel)];

const IC = (n, cls = '') => `<svg class="ic ${cls}" aria-hidden="true"><use href="#i-${n}"/></svg>`;

const PAL = {
  cpu: '#5aa2ff', ram: '#4cc38a', swap: '#d9a441',
  rx: '#3fc1e0', tx: '#a78bfa', read: '#a78bfa', write: '#4cc38a', peak: '#e08a3c',
};

const state = {
  info: null,
  settings: null,
  last: null,
  diag: null,
  secResult: null,
  secCat: 'all', secSev: 'all',
  history: [],
  paused: false,
  uptimeBase: null,
  uptimeAt: null,
};

function fmtBytes(n) {
  if (n == null || isNaN(n)) return '—';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0, v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)} ${u[i]}`;
}
function fmtRate(n) { return n == null ? '—' : (n >= 1024 ? `${(n / 1024).toFixed(1)} MB/s` : `${Math.round(n)} KB/s`); }
function fmtUptime(sec) {
  sec = Math.max(0, Math.floor(sec));
  const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
  const p = [];
  if (d) p.push(`${d}d`); if (h) p.push(`${h}h`); if (m) p.push(`${m}m`);
  p.push(`${sec % 60}s`);
  return p.join(' ');
}
function fmtTime(iso) { try { return new Date(iso).toLocaleString(); } catch { return iso; } }
function esc(s) {
  return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
const bandOf = (pct) => (pct == null ? '' : pct >= 85 ? 'crit' : pct >= 70 ? 'warn' : '');

function toast(title, sub, type = 'ok', ms = 5200) {
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  const icon = type === 'err' ? 'i-alert' : type === 'warn' ? 'i-info' : 'i-check';
  el.innerHTML = `${IC(icon)}<div><div class="toast-title"></div>${sub ? '<div class="toast-sub"></div>' : ''}</div>`;
  el.querySelector('.toast-title').textContent = title;
  if (sub) el.querySelector('.toast-sub').textContent = sub;
  $('#toastWrap').appendChild(el);
  setTimeout(() => { el.style.opacity = '0'; el.style.transition = 'opacity .4s'; setTimeout(() => el.remove(), 400); }, ms);
}

function confirmAction(title, text, onYes) {
  $('#confirmTitle').textContent = title;
  $('#confirmText').textContent = text;
  $('#confirmOverlay').classList.remove('hidden');
  const close = () => $('#confirmOverlay').classList.add('hidden');
  $('#confirmYes').onclick = () => { close(); onYes(); };
  $('#confirmNo').onclick = close;
}

function switchTab(name) {
  $$('.nav-item').forEach((b) => b.classList.toggle('active', b.dataset.tab === name));
  $$('.tab').forEach((t) => t.classList.toggle('active', t.id === `tab-${name}`));
  if (name === 'system' && !state.diag) scanSystem();
  if (name === 'security') loadHistory('sec');
  if (name === 'reports') { loadHistory('rep'); refreshNextInfo(); }
  if (name === 'monitor') refreshProcesses();
}
$$('.nav-item').forEach((b) => b.addEventListener('click', () => switchTab(b.dataset.tab)));

function initCharts() {
  const maxP = state.settings.historyPoints || 300;
  const pct = (v) => `${Math.round(v)}%`;
  const rate = (v) => (v >= 1024 ? `${(v / 1024).toFixed(1)}M` : `${Math.round(v)}K`);

  state.charts = {
    cpuRam: new Charts.LineChart($('#cCpuRam'), { maxPoints: Math.min(maxP, 180), yFormat: pct, yMax: 100, series: [{ color: PAL.cpu }, { color: PAL.ram }] }),
    net: new Charts.LineChart($('#cNet'), { maxPoints: Math.min(maxP, 180), yFormat: rate, series: [{ color: PAL.rx }, { color: PAL.tx }] }),
    diskIo: new Charts.LineChart($('#cDiskIo'), { maxPoints: Math.min(maxP, 180), yFormat: rate, series: [{ color: PAL.read }, { color: PAL.write }] }),
    mCpu: new Charts.LineChart($('#mCpu'), { maxPoints: maxP, yFormat: pct, yMax: 100, series: [{ color: PAL.cpu }, { color: PAL.peak }] }),
    mMem: new Charts.LineChart($('#mMem'), { maxPoints: maxP, yFormat: pct, yMax: 100, series: [{ color: PAL.ram }, { color: PAL.swap }] }),
    mNet: new Charts.LineChart($('#mNet'), { maxPoints: maxP, yFormat: rate, series: [{ color: PAL.rx }, { color: PAL.tx }] }),
    mDisk: new Charts.LineChart($('#mDisk'), { maxPoints: maxP, yFormat: rate, series: [{ color: PAL.read }, { color: PAL.write }] }),
  };
  Object.values(state.charts).forEach((c) => { Charts.register(c); c.draw(); });

  state.sparks = {
    cpu: new Charts.Sparkline($('#spCpu'), PAL.cpu),
    ram: new Charts.Sparkline($('#spRam'), PAL.ram),
    disk: new Charts.Sparkline($('#spDisk'), '#a78bfa'),
    temp: new Charts.Sparkline($('#spTemp'), '#3fc1e0'),
  };
  state.sparks.cpu._max = 100; state.sparks.ram._max = 100; state.sparks.disk._max = 100; state.sparks.temp._max = 100;

  state.gaugeSec = new Charts.Gauge($('#secRing'), {
    label: 'security score',
    bands: [{ upTo: 0.8, color: '#4cc38a' }, { upTo: 0.6, color: '#d9a441' }, { upTo: 0.4, color: '#e08a3c' }, { upTo: 1, color: '#e5534b' }],
  });
  Charts.register(state.gaugeSec);
}

function applyPayload(p) {
  const peak = p.cpu && p.cpu.perCpu && p.cpu.perCpu.length ? Math.max(...p.cpu.perCpu) : null;
  state.charts.cpuRam.pushAll([p.cpu.load, p.mem.usedPct]);
  state.charts.net.pushAll([(p.net.rx || 0) / 1024, (p.net.tx || 0) / 1024]);
  state.charts.diskIo.pushAll([(p.disk.io && p.disk.io.read) || 0, (p.disk.io && p.disk.io.write) || 0]);
  state.charts.mCpu.pushAll([p.cpu.load, peak]);
  state.charts.mMem.pushAll([p.mem.usedPct, p.mem.swapPct]);
  state.charts.mNet.pushAll([(p.net.rx || 0) / 1024, (p.net.tx || 0) / 1024]);
  state.charts.mDisk.pushAll([(p.disk.io && p.disk.io.read) || 0, (p.disk.io && p.disk.io.write) || 0]);

  state.sparks.cpu.push(p.cpu.load == null ? 0 : p.cpu.load);
  state.sparks.ram.push(p.mem.usedPct == null ? 0 : p.mem.usedPct);
  state.sparks.disk.push(p.disk.maxUse == null ? 0 : p.disk.maxUse);
  const t = p.temp ? (p.temp.main != null ? p.temp.main : p.temp.max) : null;
  state.sparks.temp.push(t == null ? 0 : t);

  Object.values(state.charts).forEach((c) => c.draw());
}

function onTick(p) {
  state.last = p;

  // sidebar mini
  $('#miniCpu').textContent = p.cpu.load == null ? '—' : `${Math.round(p.cpu.load)}%`;
  $('#miniRam').textContent = p.mem.usedPct == null ? '—' : `${Math.round(p.mem.usedPct)}%`;
  $('#miniNet').textContent = `↓${fmtBytes(p.net.rx)}/s`;

  // KPI tiles
  const cpuPct = p.cpu.load;
  const ramPct = p.mem.usedPct;
  const diskPct = p.disk.maxUse;
  const temp = p.temp ? (p.temp.main != null ? p.temp.main : p.temp.max) : null;

  $('#kpiCpuV').textContent = cpuPct == null ? '—' : `${Math.round(cpuPct)}%`;
  $('#kpiCpuV').className = `kpi-value cpu ${bandOf(cpuPct)}`;
  $('#kpiCpuTag').textContent = p.cpu.perCpu.length ? `${p.cpu.perCpu.length} cores` : '—';
  $('#kpiCpuS').textContent = p.cpu.avgLoad != null ? `load ${Number(p.cpu.avgLoad).toFixed(2)}` : '—';

  $('#kpiRamV').textContent = ramPct == null ? '—' : `${Math.round(ramPct)}%`;
  $('#kpiRamV').className = `kpi-value ram ${bandOf(ramPct)}`;
  $('#kpiRamTag').textContent = p.mem.total ? fmtBytes(p.mem.total) : '—';
  $('#kpiRamS').textContent = p.mem.used != null ? `${fmtBytes(p.mem.used)} used` : '—';

  $('#kpiDiskV').textContent = diskPct == null ? '—' : `${Math.round(diskPct)}%`;
  $('#kpiDiskV').className = `kpi-value disk ${bandOf(diskPct)}`;
  const topDisk = p.disk.disks.find((d) => d.usePct != null);
  $('#kpiDiskTag').textContent = topDisk ? `${topDisk.mount} ${Math.round(topDisk.usePct)}%` : '—';
  $('#kpiDiskS').textContent = p.disk.disks.length ? p.disk.disks.map((d) => `${d.mount} ${d.usePct == null ? '?' : Math.round(d.usePct) + '%'}`).join(' · ') : '—';

  $('#kpiTempV').textContent = temp == null ? '—' : `${Math.round(temp)}°`;
  $('#kpiTempV').className = `kpi-value temp ${bandOf(temp)}`;
  $('#kpiTempTag').textContent = p.temp && p.temp.max ? `max ${Math.round(p.temp.max)}°` : 'no sensor';
  $('#kpiTempS').textContent = p.temp && p.temp.max ? `max ${Math.round(p.temp.max)}°C` : 'no temperature sensors';

  // info strip
  $('#ovLoad').textContent = p.cpu.avgLoad != null ? Number(p.cpu.avgLoad).toFixed(2) : '—';
  $('#ovBattery').innerHTML = p.battery ? `${esc(p.battery.percent)}%${p.battery.charging ? ` ${IC('zap')}` : ''}` : '—';

  // chart legends
  const lg = (id, v) => { const el = $(id); if (el) el.textContent = v; };
  lg('#lgCpu', cpuPct == null ? '—' : Math.round(cpuPct) + '%');
  lg('#lgRam', ramPct == null ? '—' : Math.round(ramPct) + '%');
  lg('#lgRx', fmtRate(p.net.rx));
  lg('#lgTx', fmtRate(p.net.tx));
  lg('#lgRead', fmtRate(p.disk.io && p.disk.io.read));
  lg('#lgWrite', fmtRate(p.disk.io && p.disk.io.write));
  lg('#lgMCpu', cpuPct == null ? '—' : Math.round(cpuPct) + '%');
  lg('#lgMPeak', peakNow(p) == null ? '—' : Math.round(peakNow(p)) + '%');
  lg('#lgMRam', ramPct == null ? '—' : Math.round(ramPct) + '%');
  lg('#lgMSwap', p.mem.swapPct == null ? '—' : Math.round(p.mem.swapPct) + '%');
  lg('#lgMRx', fmtRate(p.net.rx));
  lg('#lgMTx', fmtRate(p.net.tx));
  lg('#lgMRead', fmtRate(p.disk.io && p.disk.io.read));
  lg('#lgMWrite', fmtRate(p.disk.io && p.disk.io.write));

  applyPayload(p);
  if (state.last && state.last.cpu && state.last.cpu.perCpu && state.last.cpu.perCpu.length) renderCores(state.last.cpu.perCpu);
}

function peakNow(p) { return p.cpu && p.cpu.perCpu && p.cpu.perCpu.length ? Math.max(...p.cpu.perCpu) : null; }

function startUptime() {
  if (!state.uptimeBase) return;
  setInterval(() => {
    $('#ovUptime').textContent = fmtUptime(state.uptimeBase + Math.floor((Date.now() - state.uptimeAt) / 1000));
    $('#sbUptime').textContent = 'up ' + fmtUptime(state.uptimeBase + Math.floor((Date.now() - state.uptimeAt) / 1000));
  }, 1000);
}

$('#ovRunScan').addEventListener('click', () => { switchTab('security'); runSecurityScan(); });
$('#ovExport').addEventListener('click', () => generateReportNow('full', 'html'));
$('#ovScoreGo').addEventListener('click', () => switchTab('security'));

async function scanSystem() {
  const btn = $('#sysScanBtn');
  btn.disabled = true;
  btn.innerHTML = `${IC('refresh')}Scanning…`;
  $('#sysStatus').textContent = 'Collecting system information…';
  try {
    const d = await window.sysguard.diagFull();
    state.diag = d;
    renderDiagnostics(d);
    $('#sysStatus').textContent = `Inventory collected ${new Date(d.generatedAt).toLocaleString()}. Export to save as a report.`;
    if (state.uptimeBase == null) { state.uptimeBase = d.host.uptimeSec; state.uptimeAt = Date.now(); startUptime(); }
  } catch (e) {
    $('#sysStatus').textContent = `Scan failed: ${e.message}`;
    toast('System scan failed', String(e.message || e), 'err');
  } finally {
    btn.disabled = false;
    btn.innerHTML = `${IC('refresh')}Scan system`;
  }
}
$('#sysScanBtn').addEventListener('click', scanSystem);
$('#sysExport').addEventListener('click', () => generateReportNow('diagnostics', 'html'));

function sysCard(title, inner, icon) {
  return `<div class="card sys-card"><h3>${IC(icon || 'info')}${title}</h3>${inner}</div>`;
}
function kv(...rows) {
  return `<div class="kv">${rows.map(([k, v]) => `<div><span class="k">${k}</span><span class="v">${v}</span></div>`).join('')}</div>`;
}
function renderDiagnostics(d) {
  const h = d.host, cpu = d.cpu, mem = d.memory;
  let html = '';
  html += sysCard('System', kv(
    ['Hostname', esc(h.hostname)], ['OS', esc(h.distro)],
    ['Release', esc(h.release)], ['Kernel', esc(h.kernel)],
    ['Arch', esc(h.arch)], ['Platform', esc(h.platform)],
    ['Model', esc(h.manufacturer + ' ' + h.model)], ['Serial', esc(h.serial)],
    ['Virtual', h.virtual ? `Yes (${esc(h.virtualHost || '?')})` : 'No'], ['Firmware', h.uefi ? 'UEFI' : 'Legacy'],
    ['Timezone', esc(h.timezone)], ['Locale', esc(h.locale)],
    ['Uptime', fmtUptime(h.uptimeSec)], ['Booted', fmtTime(h.bootTime)],
    ['User', esc(h.user)],
  ), 'monitor');
  html += sysCard('CPU', cpu.ok ? kv(
    ['Brand', esc(cpu.manufacturer + ' ' + cpu.brand)],
    ['Cores', `${cpu.cores} threads / ${cpu.physicalCores} physical`],
    ['Speed', `${cpu.speed} GHz (max ${cpu.speedMax} GHz)`],
    ['Sockets', cpu.processors], ['Virtualization', cpu.virtualization || 'n/a'],
    ['Cache', cpu.cache ? `L1 ${fmtBytes(cpu.cache.l1d)} · L2 ${fmtBytes(cpu.cache.l2)} · L3 ${fmtBytes(cpu.cache.l3)}` : 'n/a'],
  ) : '<p class="muted small">unavailable</p>', 'cpu');
  html += sysCard('Memory', kv(
    ['Total', fmtBytes(mem.total)], ['In use', fmtBytes(mem.active)],
    ['Available', fmtBytes(mem.available)], ['Swap', fmtBytes(mem.swapTotal)],
  ) + (mem.modules.length ? `<h3 style="margin-top:14px;color:var(--text-3)">Modules · ${mem.modules.length}</h3><table class="sys-table"><tr><th>Type</th><th>Size</th><th>Speed</th><th>Mfr</th></tr>${mem.modules.map((m) => `<tr><td>${esc(m.type)}</td><td>${fmtBytes(m.size)}</td><td>${esc(m.clockSpeed)} MHz</td><td>${esc(m.manufacturer)}</td></tr>`).join('')}</table>` : ''), 'memory');
  if (d.graphics && d.graphics.length) {
    html += sysCard('Graphics', `<table class="sys-table"><tr><th>Model</th><th>VRAM</th><th>Driver</th></tr>${d.graphics.map((g) => `<tr><td>${esc(g.model)}</td><td>${fmtBytes(g.vram)}</td><td>${esc(g.driverVersion)}</td></tr>`).join('')}</table>`, 'monitor');
  }
  if (d.disks && d.disks.length) {
    html += sysCard('Physical disks', `<table class="sys-table"><tr><th>Device</th><th>Name</th><th>Type</th><th>Size</th><th>SMART</th></tr>${d.disks.map((k) => `<tr><td><code>${esc(k.device)}</code></td><td>${esc(k.name)}</td><td>${esc(k.type)}</td><td>${fmtBytes(k.size)}</td><td class="${String(k.smartStatus || '').toLowerCase().includes('ok') ? 'ok' : 'warn'}">${esc(k.smartStatus || 'n/a')}</td></tr>`).join('')}</table>`, 'hdd');
  }
  if (d.mounts && d.mounts.length) {
    html += sysCard('Mounted volumes', `<table class="sys-table"><tr><th>Mount</th><th>Device</th><th>Used</th><th>Use</th></tr>${d.mounts.map((m) => `<tr><td>${esc(m.mount)}</td><td><code>${esc(m.fs)}</code></td><td>${fmtBytes(m.used)} / ${fmtBytes(m.size)}</td><td>${m.usePct}%</td></tr>`).join('')}</table>`, 'hdd');
  }
  if (d.network && d.network.length) {
    html += sysCard('Network adapters', `<table class="sys-table"><tr><th>Iface</th><th>Type</th><th>IP</th><th>MAC</th><th>Speed</th></tr>${d.network.map((n) => `<tr><td>${esc(n.iface)}${n.default ? ' <span class="ok">default</span>' : ''}</td><td>${esc(n.type || '')}</td><td>${esc(n.ip4 || n.ip6 || '')}</td><td>${esc(n.mac)}</td><td>${n.speed ? n.speed + ' Mbps' : '—'}</td></tr>`).join('')}</table>`, 'globe');
  }
  if (d.battery && d.battery.hasBattery) {
    html += sysCard('Battery', kv(['Charge', d.battery.percent + '%'], ['Status', d.battery.isCharging ? 'Charging' : 'On battery']), 'battery');
  }
  if (d.usb && d.usb.length) {
    html += sysCard(`USB devices · ${d.usb.length}`, `<ul style="padding-left:16px;font-size:12px;color:var(--text-2)">${d.usb.slice(0, 16).map((u) => `<li>${esc(u.name || 'Unknown device')}${u.manufacturer ? ' — ' + esc(u.manufacturer) : ''}</li>`).join('')}</ul>`, 'info');
  }
  if (d.software && d.software.count) {
    html += sysCard(`Installed software · ${d.software.count}`, `<p class="muted small">via ${esc(d.software.source)}</p><ul style="padding-left:16px;font-size:11.5px;color:var(--text-2);columns:2">${d.software.sample.slice(0, 40).map((s) => `<li>${esc(s)}</li>`).join('')}</ul>`, 'file');
  }
  if (d.temps && (d.temps.main || d.temps.max)) {
    html += sysCard('Temperatures', kv(['Main', d.temps.main ? d.temps.main + ' °C' : 'n/a'], ['Max', d.temps.max ? d.temps.max + ' °C' : 'n/a']), 'thermo');
  }
  $('#sysContent').innerHTML = html;
}

const INTERVALS = [['500', '0.5s'], ['1000', '1s'], ['1500', '1.5s'], ['3000', '3s'], ['5000', '5s']];
$('#monInterval').addEventListener('click', (e) => {
  const btn = e.target.closest('button');
  if (!btn) return;
  $$('#monInterval button').forEach((b) => b.classList.remove('active'));
  btn.classList.add('active');
  const ms = parseInt(btn.dataset.v, 10);
  window.sysguard.monitor.start(ms);
  toast('Monitor interval', `${ms} ms`, 'ok', 2500);
});

$('#monPause').addEventListener('click', async (e) => {
  state.paused = !state.paused;
  const b = e.currentTarget;
  if (state.paused) {
    await window.sysguard.monitor.stop();
    b.innerHTML = `${IC('play')}Resume`;
    $('#sbMon').className = 'sb-dot paused';
    toast('Monitoring paused', '', 'warn', 2500);
  } else {
    await window.sysguard.monitor.start(state.settings.refreshIntervalMs);
    b.innerHTML = `${IC('pause')}Pause`;
    $('#sbMon').className = 'sb-dot ok';
    toast('Monitoring resumed', '', 'ok', 2500);
  }
});

async function refreshProcesses() {
  try {
    const res = await window.sysguard.processes();
    state.procCounts = { all: res.all, running: res.running, blocked: res.blocked };
    state.procs = res.list;
    $('#ovProcs').textContent = res.all || '—';
    $('#ovThreads').textContent = (res.running || 0) + (res.blocked || 0);
    if ($('#tab-monitor').classList.contains('active')) renderProcesses();
  } catch { /* transient */ }
}
let procTimer = setInterval(refreshProcesses, 4000);

function renderProcesses() {
  const q = ($('#procSearch').value || '').toLowerCase();
  const list = (state.procs || []).filter((p) => !q || `${p.name} ${p.pid}`.toLowerCase().includes(q));
  const tbody = $('#procTable tbody');
  $('#procCount').textContent = `${list.length} of ${(state.procs || []).length}`;
  tbody.innerHTML = list.slice(0, 250).map((p) => `
    <tr>
      <td class="num mono">${p.pid}</td>
      <td>${esc(p.name)}</td>
      <td class="num pct-cell">${typeof p.cpu === 'number' ? p.cpu.toFixed(1) : '—'}</td>
      <td class="num pct-cell">${typeof p.mem === 'number' ? p.mem.toFixed(1) : '—'}</td>
      <td>${esc(p.user || '')}</td>
      <td class="cmd" title="${esc(p.command || '')}">${esc(p.command || '')}</td>
      <td><button class="btn small danger kill-btn" data-pid="${p.pid}" data-name="${esc(p.name)}">Kill</button></td>
    </tr>`).join('');
  tbody.querySelectorAll('.kill-btn').forEach((b) => b.addEventListener('click', () => {
    confirmAction(`Kill process ${b.dataset.name} (PID ${b.dataset.pid})?`, 'The process will be terminated immediately. Unsaved work in it will be lost.', async () => {
      const r = await window.sysguard.killProcess(b.dataset.pid);
      if (r.ok) { toast('Process terminated', `${b.dataset.name} (${b.dataset.pid})`, 'ok'); setTimeout(refreshProcesses, 800); }
      else toast('Could not kill process', r.error || 'permission denied?', 'err');
    });
  }));
}
$('#procSearch').addEventListener('input', renderProcesses);

function renderCores(perCpu) {
  if (!perCpu || !perCpu.length) return;
  const avg = Math.round(perCpu.reduce((a, b) => a + b, 0) / perCpu.length);
  $('#coreStats').textContent = `${perCpu.length} cores · avg ${avg}%`;
  $('#coreGrid').innerHTML = perCpu.map((v, i) => `
    <div class="core-row">
      <span class="core-name">c${i}</span>
      <div class="core-bar"><div class="core-fill ${v >= 80 ? 'hot' : ''}" style="width:${Math.min(100, v)}%"></div></div>
      <span class="core-pct">${Math.round(v)}%</span>
    </div>`).join('');
}

const SCAN_PHASES = [
  'Collecting system data', 'Open ports & exposed services', 'Services & startup items',
  'Firewall & pending updates', 'Processes & connections', 'Accounts & policy',
  'Network posture (IP · geo · DNS)', 'Building score',
];

async function runSecurityScan() {
  $('#secEmpty').classList.add('hidden');
  $('#secResult').classList.add('hidden');
  $('#scanOverlay').classList.remove('hidden');
  $('#scanTitle').textContent = 'Running security audit';
  $('#scanSub').textContent = 'local checks + network posture';
  const list = $('#scanChecklist');
  list.innerHTML = SCAN_PHASES.map((p, i) => `<li class="${i === 0 ? 'active' : ''}">${i === 0 ? IC('refresh') : IC('dot')}<span>${p}</span></li>`).join('');
  let phase = 0;

  const iv = setInterval(() => {
    if (phase >= SCAN_PHASES.length - 1) return;
    const cur = list.children[phase];
    if (cur) { cur.classList.remove('active'); cur.classList.add('done'); cur.innerHTML = `${IC('check')}<span>${SCAN_PHASES[phase]}</span>`; }
    phase += 1;
    const next = list.children[phase];
    if (next) { next.classList.add('active'); next.innerHTML = `${IC('refresh')}<span>${SCAN_PHASES[phase]}</span>`; }
  }, 500);

  try {
    const scan = await window.sysguard.scanSecurity({ externalChecks: state.settings.externalChecks });
    list.querySelectorAll('li').forEach((li, i) => {
      if (i < phase || !li.classList.contains('done')) { li.classList.remove('active'); li.classList.add('done'); li.innerHTML = `${IC('check')}<span>${SCAN_PHASES[i]}</span>`; }
    });
    await window.sysguard.report.saveScan(scan);
    loadHistory('sec');
    renderScan(scan);
    $('#secTime').textContent = fmtTime(scan.generatedAt);
    $('#ovScore').textContent = scan.score;
    toast('Audit complete', `Score ${scan.score}/100 (${scan.grade}) · ${scan.findings.length} findings`, scan.score >= 70 ? 'ok' : (scan.score >= 50 ? 'warn' : 'err'));
  } catch (e) {
    toast('Security scan failed', String(e.message || e), 'err');
  } finally {
    clearInterval(iv);
    setTimeout(() => $('#scanOverlay').classList.add('hidden'), 350);
  }
}
$('#secScanBtn').addEventListener('click', runSecurityScan);

function renderScan(scan) {
  state.secResult = scan;
  $('#secResult').classList.remove('hidden');

  state.gaugeSec.set(scan.score / 100, String(scan.score));
  $('#secGrade').textContent = scan.grade;

  const chips = ['critical', 'high', 'medium', 'low', 'info'].map((s) =>
    `<div class="chip ${s}"><span class="chip-n">${scan.summary[s] || 0}</span><span class="chip-l">${s}</span></div>`).join('');
  $('#secChips').innerHTML = chips;

  const n = scan.network;
  let netLine = '';
  if (n) {
    const geo = n.geo && n.geo.ok ? `${esc(n.geo.country)} · ${esc(n.geo.isp || 'n/a')}` : 'geo unknown';
    netLine = `Public IP <b>${n.publicIp || '—'}</b> (${geo}) &nbsp;·&nbsp; ${n.nat ? esc(n.nat.note) : 'NAT unknown'} &nbsp;·&nbsp; DNS 8.8.8.8 <b>${n.dns ? 'reachable' : 'NOT reachable'}</b>`;
  } else netLine = 'External checks disabled in Settings.';
  $('#secMeta').innerHTML =
    `${scan.findings.length} findings · ${scan.ports.length} listening ports · ${scan.services.enabled} auto-start services · ${scan.startupCount} startup entries · ${(scan.durationMs / 1000).toFixed(1)}s<br>${netLine}`;

  // nav badge
  const nb = $('#navScore');
  nb.textContent = scan.grade;
  nb.className = `nav-score ${String(scan.grade).toLowerCase().replace('+', '')}`;
  nb.classList.remove('hidden');

  // severity filter pills
  const sevOrder = [['all', 'All'], ['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low'], ['info', 'Info']];
  $('#secSevPills').innerHTML = sevOrder.map(([v, label]) =>
    `<button class="pill sev-${v} ${state.secSev === v ? 'active' : ''}" data-v="${v}">${label}</button>`).join('');

  // category pills
  $('#secCatPills').innerHTML = `<button class="pill ${state.secCat === 'all' ? 'active' : ''}" data-v="all">All categories</button>` +
    scan.categories.map((c) => `<button class="pill ${state.secCat === c.name ? 'active' : ''}" data-v="${esc(c.name)}">${esc(c.name)}<span class="pc">${c.count}</span></button>`).join('');

  renderFindings();
}

$('#secSevPills').addEventListener('click', (e) => {
  const b = e.target.closest('.pill');
  if (!b) return;
  state.secSev = b.dataset.v;
  $('#secSevPills').querySelectorAll('.pill').forEach((p) => p.classList.toggle('active', p === b));
  renderFindings();
});
$('#secCatPills').addEventListener('click', (e) => {
  const b = e.target.closest('.pill');
  if (!b) return;
  state.secCat = b.dataset.v;
  $('#secCatPills').querySelectorAll('.pill').forEach((p) => p.classList.toggle('active', p === b));
  renderFindings();
});

function renderFindings() {
  const scan = state.secResult;
  if (!scan) return;
  const groups = new Map();
  for (const f of scan.findings) {
    if (state.secSev !== 'all' && f.severity !== state.secSev) continue;
    if (state.secCat !== 'all' && f.category !== state.secCat) continue;
    if (!groups.has(f.category)) groups.set(f.category, []);
    groups.get(f.category).push(f);
  }
  if (!groups.size) { $('#secFindings').innerHTML = '<p class="muted small">No findings match the current filters.</p>'; return; }
  let html = '';
  for (const [cat, items] of groups) {
    html += `<div class="fcat"><h3>${esc(cat)}<span class="fc">${items.length}</span></h3>`;
    for (const f of items) {
      html += `<div class="finding ${esc(f.severity)}">
        <div class="finding-head"><span class="badge ${esc(f.severity)}">${esc(f.severity)}</span><span class="finding-title">${esc(f.title)}</span></div>
        ${f.detail ? `<p class="finding-detail">${esc(f.detail)}</p>` : ''}
        ${f.recommendation ? `<p class="finding-rec">${IC('bulb')}<span>${esc(f.recommendation)}</span></p>` : ''}
        ${f.evidence && f.evidence.length ? `<ul class="finding-evidence">${f.evidence.map((ev) => `<li><code>${esc(ev)}</code></li>`).join('')}</ul>` : ''}
      </div>`;
    }
    html += '</div>';
  }
  $('#secFindings').innerHTML = html;
}

$('#secExport').addEventListener('click', () => generateReportNow('security', 'html'));
$('#secExportPdf').addEventListener('click', () => generateReportNow('security', 'pdf'));

async function loadHistory(which) {
  try { state.history = await window.sysguard.report.list(); } catch { state.history = []; }
  if (which === 'sec') renderSecHistory();
  if (which === 'rep') renderRepHistory();
}

function renderSecHistory() {
  const box = $('#secHistory');
  const mine = state.history.filter((h) => h.type === 'security' || h.type === 'full');
  if (!mine.length) { box.innerHTML = '<p class="muted small">No saved audits yet — run one and it appears here.</p>'; return; }
  box.innerHTML = mine.slice(0, 12).map((h) => `
    <div class="history-item" data-path="${esc(h.path)}" data-format="${esc(h.format)}">
      <div class="history-score ${h.score != null && h.score < 70 ? 'warn' : 'ok'}">${h.score != null ? h.score : '—'}</div>
      <div style="flex:1">
        <div class="h-time">${fmtTime(h.createdAt)}</div>
        <div class="h-sub">${h.format === 'scan' ? 'saved audit' : h.format.toUpperCase() + ' report'} · ${h.type}${h.findings ? ' · ' + h.findings + ' findings' : ''}</div>
      </div>
      <button class="btn small ghost hist-open">${IC('external')}Open</button>
    </div>`).join('');
  box.querySelectorAll('.history-item').forEach((el) => el.addEventListener('click', (e) => {
    if (e.target.closest('.hist-open')) {
      const p = el.dataset.path, fmt = el.dataset.format;
      if (fmt === 'scan') loadScan(p);
      else window.sysguard.report.open(p);
    }
  }));
}

async function loadScan(p) {
  const scan = await window.sysguard.report.loadScan(p);
  if (!scan) { toast('Could not load audit', p, 'err'); return; }
  switchTab('security');
  $('#secEmpty').classList.add('hidden');
  renderScan(scan);
  $('#secTime').textContent = fmtTime(scan.generatedAt);
  toast('Loaded audit from history', `${scan.score}/100 (${scan.grade})`, 'ok');
}

function renderRepHistory() {
  const tbody = $('#repTable tbody');
  const items = state.history.filter((h) => h.format !== 'scan');
  if (!items.length) { tbody.innerHTML = '<tr><td colspan="7" class="muted">No reports yet — generate one above.</td></tr>'; return; }
  tbody.innerHTML = items.slice(0, 50).map((h) => `
    <tr>
      <td class="num">${fmtTime(h.createdAt)}</td>
      <td>${esc(h.type)}</td>
      <td class="mono">${esc(h.format)}</td>
      <td class="num mono">${h.score != null ? h.score : '—'}</td>
      <td class="mono">${esc(h.grade || '—')}</td>
      <td class="num mono">${h.findings != null ? h.findings : '—'}</td>
      <td style="white-space:nowrap">
        <button class="btn small ghost" data-a="open" data-p="${esc(h.path)}">${IC('external')}Open</button>
        <button class="btn small ghost" data-a="reveal" data-p="${esc(h.path)}">${IC('folder')}Folder</button>
        <button class="btn small danger" data-a="del" data-p="${esc(h.path)}" data-id="${esc(h.id)}">${IC('trash')}</button>
      </td>
    </tr>`).join('');
  tbody.querySelectorAll('button[data-a]').forEach((b) => b.addEventListener('click', async () => {
    const a = b.dataset.a, p = b.dataset.p, id = b.dataset.id;
    if (a === 'open') window.sysguard.report.open(p);
    else if (a === 'reveal') window.sysguard.report.reveal(p);
    else if (a === 'del') {
      await window.sysguard.report.remove(id);
      toast('Report deleted', '', 'warn');
      loadHistory('rep'); loadHistory('sec');
    }
  }));
}

async function generateReportNow(include, format) {
  $('#scanOverlay').classList.remove('hidden');
  $('#scanTitle').textContent = `Generating ${format.toUpperCase()} report`;
  $('#scanSub').textContent = 'collecting data · running checks · writing file';
  $('#scanChecklist').innerHTML = '<li class="active">' + IC('refresh') + '<span>Assembling report…</span></li>';
  try {
    const entry = await window.sysguard.report.generate({ include, format });
    toast('Report generated', entry.path, 'ok');
    loadHistory('rep'); loadHistory('sec');
  } catch (e) {
    toast('Report generation failed', String(e.message || e), 'err');
  } finally {
    setTimeout(() => $('#scanOverlay').classList.add('hidden'), 350);
  }
}

$('#repGenerate').addEventListener('click', () => {
  const scope = document.querySelector('input[name="repScope"]:checked').value;
  generateReportNow(scope, $('#repFormat button.active').dataset.v);
});
$('#repFormat').addEventListener('click', (e) => {
  const b = e.target.closest('button');
  if (!b) return;
  $$('#repFormat button').forEach((x) => x.classList.remove('active'));
  b.classList.add('active');
});

function renderSchedules() {
  const box = $('#schedList');
  const list = state.settings.schedules || [];
  box.innerHTML = list.map((s, i) => `
    <div class="sched-row" data-i="${i}">
      <div class="sched-head">
        <label class="switch" title="enabled"><input type="checkbox" class="s-en" ${s.enabled ? 'checked' : ''}><span></span></label>
        <input class="input sched-name s-name" value="${esc(s.label)}" placeholder="Schedule name">
        <button class="btn small ghost sched-del">${IC('trash')}</button>
      </div>
      <div class="sched-fields">
        <div class="seg s-type">
          <button data-v="daily" class="${s.type === 'daily' ? 'active' : ''}">Daily</button>
          <button data-v="weekly" class="${s.type === 'weekly' ? 'active' : ''}">Weekly</button>
          <button data-v="interval" class="${s.type === 'interval' ? 'active' : ''}">N hrs</button>
          <button data-v="startup" class="${s.type === 'startup' ? 'active' : ''}">Startup</button>
        </div>
        <input type="time" class="input s-time" value="${esc(s.time || '09:00')}" ${['daily', 'weekly'].includes(s.type) ? '' : 'hidden'}>
        <div class="seg s-day" ${s.type === 'weekly' ? '' : 'hidden'}>
          ${['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].map((d, di) => `<button data-v="${di}" class="${s.day === di ? 'active' : ''}">${d}</button>`).join('')}
        </div>
        <div class="s-hours-wrap" style="display:inline-flex;align-items:center;gap:5px" ${s.type === 'interval' ? '' : 'hidden'}>
          <span class="muted small">every</span>
          <input type="number" class="input s-hours" min="1" max="168" value="${esc(s.everyHours || 6)}" style="width:62px">
          <span class="muted small">h</span>
        </div>
        <div class="seg s-include">
          <button data-v="full" class="${s.include === 'full' ? 'active' : ''}">Full</button>
          <button data-v="security" class="${s.include === 'security' ? 'active' : ''}">Sec</button>
          <button data-v="diagnostics" class="${s.include === 'diagnostics' ? 'active' : ''}">Diag</button>
        </div>
        <div class="seg s-format">
          <button data-v="html" class="${s.format === 'html' ? 'active' : ''}">HTML</button>
          <button data-v="md" class="${s.format === 'md' ? 'active' : ''}">MD</button>
          <button data-v="pdf" class="${s.format === 'pdf' ? 'active' : ''}">PDF</button>
        </div>
      </div>
      <div class="sched-next"></div>
    </div>`).join('');

  box.querySelectorAll('.sched-row').forEach((row) => {
    const i = Number(row.dataset.i);
    const base = state.settings.schedules[i];
    const refreshVis = () => {
      const type = row.querySelector('.s-type button.active').dataset.v;
      row.querySelector('.s-time').hidden = !['daily', 'weekly'].includes(type);
      row.querySelector('.s-day').hidden = type !== 'weekly';
      row.querySelector('.s-hours-wrap').hidden = type !== 'interval';
      updateNext();
    };
    const collect = () => ({
      id: base.id,
      label: row.querySelector('.s-name').value.trim() || 'Scheduled report',
      enabled: row.querySelector('.s-en').checked,
      type: row.querySelector('.s-type button.active').dataset.v,
      time: row.querySelector('.s-time').value || '09:00',
      day: Number(row.querySelector('.s-day button.active').dataset.v),
      everyHours: Math.min(168, Math.max(1, Number(row.querySelector('.s-hours').value) || 6)),
      include: row.querySelector('.s-include button.active').dataset.v,
      format: row.querySelector('.s-format button.active').dataset.v,
    });
    const updateNext = () => {
      const spec = collect();
      const next = nextRunPreview(spec);
      row.querySelector('.sched-next').textContent = next ? `next run → ${fmtTime(next)}` : 'disabled';
    };
    row.querySelector('.s-type').addEventListener('click', (e) => {
      const b = e.target.closest('button'); if (!b) return;
      row.querySelectorAll('.s-type button').forEach((x) => x.classList.remove('active'));
      b.classList.add('active');
      refreshVis();
    });
    row.querySelector('.s-day').addEventListener('click', (e) => {
      const b = e.target.closest('button'); if (!b) return;
      row.querySelectorAll('.s-day button').forEach((x) => x.classList.remove('active'));
      b.classList.add('active');
      updateNext();
    });
    row.querySelector('.s-include').addEventListener('click', (e) => {
      const b = e.target.closest('button'); if (!b) return;
      row.querySelectorAll('.s-include button').forEach((x) => x.classList.remove('active'));
      b.classList.add('active');
    });
    row.querySelector('.s-format').addEventListener('click', (e) => {
      const b = e.target.closest('button'); if (!b) return;
      row.querySelectorAll('.s-format button').forEach((x) => x.classList.remove('active'));
      b.classList.add('active');
    });
    row.querySelector('.s-time').addEventListener('input', updateNext);
    row.querySelector('.s-name').addEventListener('input', updateNext);
    row.querySelector('.s-hours').addEventListener('input', updateNext);
    row.querySelector('.s-en').addEventListener('change', updateNext);
    row.querySelector('.sched-del').addEventListener('click', () => {
      state.settings.schedules.splice(i, 1);
      renderSchedules(); refreshNextInfo();
    });
    refreshVis();
  });
  refreshNextInfo();
}

function nextRunPreview(spec) {
  const now = new Date();
  if (!spec.enabled) return null;
  if (spec.type === 'daily') {
    const [h, m] = spec.time.split(':').map(Number);
    const d = new Date(now); d.setHours(h, m, 0, 0);
    if (d <= now) d.setDate(d.getDate() + 1);
    return d.toISOString();
  }
  if (spec.type === 'weekly') {
    const [h, m] = spec.time.split(':').map(Number);
    const d = new Date(now); d.setHours(h, m, 0, 0);
    let delta = (spec.day - d.getDay() + 7) % 7;
    if (delta === 0 && d <= now) delta = 7;
    d.setDate(d.getDate() + delta);
    return d.toISOString();
  }
  if (spec.type === 'interval') return new Date(now.getTime() + spec.everyHours * 3600000).toISOString();
  return new Date(now.getTime() + 60000).toISOString();
}

function collectAllSchedules() {
  return [...$('#schedList').querySelectorAll('.sched-row')].map((row, i) => {
    const base = state.settings.schedules[i];
    return {
      id: base.id,
      label: row.querySelector('.s-name').value.trim() || 'Scheduled report',
      enabled: row.querySelector('.s-en').checked,
      type: row.querySelector('.s-type button.active').dataset.v,
      time: row.querySelector('.s-time').value || '09:00',
      day: Number(row.querySelector('.s-day button.active').dataset.v),
      everyHours: Math.min(168, Math.max(1, Number(row.querySelector('.s-hours').value) || 6)),
      include: row.querySelector('.s-include button.active').dataset.v,
      format: row.querySelector('.s-format button.active').dataset.v,
    };
  });
}

$('#schedAdd').addEventListener('click', () => {
  state.settings.schedules.push({ id: `sched-${Date.now()}`, label: 'New schedule', enabled: true, type: 'daily', time: '09:00', day: 1, everyHours: 6, include: 'full', format: 'html' });
  renderSchedules();
});
$('#schedSave').addEventListener('click', async () => {
  try {
    const saved = await window.sysguard.scheduler.save(collectAllSchedules());
    state.settings.schedules = saved;
    renderSchedules();
    toast('Schedules saved', `${saved.filter((s) => s.enabled).length} active schedule(s)`, 'ok');
  } catch (e) { toast('Could not save schedules', String(e.message || e), 'err'); }
});

async function refreshNextInfo() {
  try {
    const list = await window.sysguard.scheduler.next();
    const enabled = list.filter((s) => s.enabled);
    $('#schedNextInfo').textContent = enabled.length
      ? enabled.map((s) => `${s.label}: ${s.next ? fmtTime(s.next) : 'soon'}`).join(' · ')
      : 'No active schedules.';
  } catch { /* ignore */ }
}

function populateSettings() {
  const s = state.settings;
  $('#setInterval').value = s.refreshIntervalMs;
  $('#setHistory').value = s.historyPoints;
  $('#setTheme button[data-v="' + s.theme + '"]')?.classList.add('active');
  $('#setOpen').checked = s.openReportAfterGenerate;
  $('#setExternal').checked = s.externalChecks;
  $('#setCountry').value = s.expectedCountry || '';
  $('#setDataDir').textContent = state.info ? state.info.dataDir : '';
  $('#setVersion').textContent = state.info ? `${state.info.name} v${state.info.version} · ${state.info.platform} ${state.info.arch}` : '';
  applyTheme(s.theme);
}

function applyTheme(theme) {
  document.body.className = theme === 'light' ? 'light' : 'dark';
  Object.values(state.charts || {}).forEach((c) => c.draw());
  Object.values(state.sparks || {}).forEach((c) => c.draw());
  if (state.gaugeSec) state.gaugeSec.draw();
}
$('#setTheme').addEventListener('click', (e) => {
  const b = e.target.closest('button');
  if (!b) return;
  $$('#setTheme button').forEach((x) => x.classList.remove('active'));
  b.classList.add('active');
  applyTheme(b.dataset.v);
});

$('#setSave').addEventListener('click', async () => {
  const partial = {
    refreshIntervalMs: Math.max(500, parseInt($('#setInterval').value, 10) || 1500),
    historyPoints: Math.max(60, Math.min(900, parseInt($('#setHistory').value, 10) || 300)),
    theme: $('#setTheme button.active').dataset.v,
    openReportAfterGenerate: $('#setOpen').checked,
    externalChecks: $('#setExternal').checked,
    expectedCountry: ($('#setCountry').value || '').trim().toUpperCase().slice(0, 2),
  };
  try {
    const saved = await window.sysguard.settings.save(partial);
    state.settings = saved;
    toast('Settings saved', 'Applied immediately', 'ok');
  } catch (e) { toast('Could not save settings', String(e.message || e), 'err'); }
});

window.sysguard.onMenuScan(() => { switchTab('security'); runSecurityScan(); });
window.sysguard.onMenuReport(() => { switchTab('reports'); generateReportNow('full', 'html'); });
window.sysguard.scheduler.onRan((info) => {
  toast('Scheduled report generated', `${info.schedule} — ${info.path}`, 'ok', 7000);
  loadHistory('rep'); loadHistory('sec');
});

setInterval(() => { $('#sbClock').textContent = new Date().toLocaleTimeString(); }, 1000);

(async function init() {
  try {
    [state.info, state.settings] = await Promise.all([window.sysguard.appInfo(), window.sysguard.settings.get()]);
  } catch (e) {
    toast('Failed to contact main process', String(e.message || e), 'err');
    return;
  }
  $('#appVer').textContent = 'v' + state.info.version;
  $('#sbKernel').textContent = `${state.info.platform} ${state.info.arch}`;
  $('#sbData').textContent = `data: ${state.info.dataDir}`;

  initCharts();
  applyTheme(state.settings.theme);
  populateSettings();
  loadHistory('rep'); loadHistory('sec');
  renderSchedules();

  window.sysguard.monitor.onTick(onTick);
  const hist = await window.sysguard.monitor.history(180000);
  if (hist && hist.length) {
    hist.forEach((p) => applyPayload(p));
    onTick(hist[hist.length - 1]);
  } else {
    onTick({ t: Date.now(), cpu: { load: null, perCpu: [], avgLoad: null }, mem: { usedPct: null, used: null, total: null, swapPct: null }, net: { rx: 0, tx: 0 }, disk: { maxUse: null, disks: [], io: {} }, temp: { main: null, max: null }, battery: null });
  }
  await window.sysguard.monitor.start(state.settings.refreshIntervalMs);
  refreshProcesses();
  // sync the interval control with the saved setting
  const ivBtn = document.querySelector(`#monInterval button[data-v="${state.settings.refreshIntervalMs}"]`);
  if (ivBtn) {
    $$('#monInterval button').forEach((b) => b.classList.remove('active'));
    ivBtn.classList.add('active');
  }
})();
