'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { APP_NAME, APP_VERSION, DIRS, SEVERITY_ORDER } = require('./constants');
const { fmtBytes } = require('./diagnostics');

function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function niceTime(iso) {
  try { return new Date(iso).toLocaleString(); } catch { return iso; }
}

function severityClass(s) { return s || 'info'; }

// Build the report data object
async function buildReportData(include = 'full', diag, scan) {
  const base = {
    app: { name: APP_NAME, version: APP_VERSION },
    generatedAt: new Date().toISOString(),
    host: os.hostname(),
    user: os.userInfo().username || 'unknown',
    platform: `${process.platform} ${process.arch}`,
    include,
  };
  if (include === 'full' || include === 'diagnostics') base.diagnostics = diag;
  if (include === 'full' || include === 'security') base.security = scan;
  return base;
}

// HTML
function scoreRing(score, grade) {
  const r = 54, c = 2 * Math.PI * r;
  const pct = Math.max(0, Math.min(100, score || 0));
  const dash = (pct / 100) * c;
  const color = pct >= 80 ? '#34d399' : pct >= 60 ? '#fbbf24' : pct >= 40 ? '#fb923c' : '#f87171';
  return `
  <div class="ring-wrap">
    <svg viewBox="0 0 140 140" width="150" height="150">
      <circle cx="70" cy="70" r="${r}" fill="none" stroke="rgba(148,163,184,.18)" stroke-width="12"/>
      <circle cx="70" cy="70" r="${r}" fill="none" stroke="${color}" stroke-width="12"
        stroke-linecap="round" stroke-dasharray="${dash} ${c}" transform="rotate(-90 70 70)"/>
      <text x="70" y="64" text-anchor="middle" class="ring-score" fill="#e2e8f0">${score}</text>
      <text x="70" y="86" text-anchor="middle" class="ring-grade" fill="${color}">${esc(grade)}</text>
    </svg>
    <div class="ring-caption">Security score</div>
  </div>`;
}

function findingsHtml(security) {
  if (!security || !security.findings) return '';
  const groups = new Map();
  for (const f of security.findings) {
    if (!groups.has(f.category)) groups.set(f.category, []);
    groups.get(f.category).push(f);
  }
  let html = '';
  for (const [cat, items] of groups) {
    html += `<h3 class="cat">${esc(cat)} <span class="cat-count">${items.length}</span></h3><div class="cards">`;
    for (const f of items) {
      html += `
      <div class="finding ${severityClass(f.severity)}">
        <div class="finding-head">
          <span class="badge ${severityClass(f.severity)}">${esc(f.severity)}</span>
          <span class="finding-title">${esc(f.title)}</span>
        </div>
        ${f.detail ? `<p class="finding-detail">${esc(f.detail)}</p>` : ''}
        ${f.recommendation ? `<p class="finding-rec"><strong>Recommendation:</strong> ${esc(f.recommendation)}</p>` : ''}
        ${f.evidence && f.evidence.length ? `<ul class="evidence">${f.evidence.map((e) => `<li><code>${esc(e)}</code></li>`).join('')}</ul>` : ''}
      </div>`;
    }
    html += '</div>';
  }
  return html;
}

function kvTable(rows) {
  return `<table class="kv"><tbody>${rows.map(([k, v]) => `<tr><th>${esc(k)}</th><td>${esc(v)}</td></tr>`).join('')}</tbody></table>`;
}

function diagHtml(d) {
  if (!d) return '';
  let html = '<h2 class="sec">System</h2>';
  html += kvTable([
    ['Hostname', d.host.hostname],
    ['OS', `${d.host.distro} ${d.host.release} ${d.host.codename ? '(' + d.host.codename + ')' : ''}`.trim()],
    ['Platform / Arch', `${d.host.platform} / ${d.host.arch}`],
    ['Kernel', d.host.kernel],
    ['Uptime', fmtUptime(d.host.uptimeSec)],
    ['Boot time', niceTime(d.host.bootTime)],
    ['Manufacturer / Model', `${d.host.manufacturer} ${d.host.model}`.trim()],
    ['Virtual machine', d.host.virtual ? `Yes (${d.host.virtualHost || 'unknown hypervisor'})` : 'No'],
    ['User', d.host.user],
    ['Timezone', d.host.timezone],
  ]);

  html += '<h2 class="sec">CPU</h2>';
  if (d.cpu.ok) {
    html += kvTable([
      ['Brand', `${d.cpu.manufacturer} ${d.cpu.brand}`.trim()],
      ['Cores', `${d.cpu.cores} threads / ${d.cpu.physicalCores} physical cores`],
      ['Speed', `${d.cpu.speed} GHz (max ${d.cpu.speedMax} GHz)`],
      ['Virtualization', d.cpu.virtualization ? 'Supported' : 'Not exposed'],
    ]);
  } else {
    html += '<p class="muted">CPU details unavailable</p>';
  }

  html += '<h2 class="sec">Memory</h2>';
  html += kvTable([
    ['Total', fmtBytes(d.memory.total)],
    ['In use', fmtBytes(d.memory.active)],
    ['Available', fmtBytes(d.memory.available)],
    ['Swap', fmtBytes(d.memory.swapTotal)],
  ]);
  if (d.memory.modules && d.memory.modules.length) {
    html += '<h4>Memory modules</h4><table class="data"><thead><tr><th>Type</th><th>Size</th><th>Speed</th><th>Manufacturer</th></tr></thead><tbody>';
    for (const m of d.memory.modules) {
      html += `<tr><td>${esc(m.type)}</td><td>${fmtBytes(m.size)}</td><td>${esc(m.clockSpeed)} MHz</td><td>${esc(m.manufacturer)}</td></tr>`;
    }
    html += '</tbody></table>';
  }

  if (d.graphics && d.graphics.length) {
    html += '<h2 class="sec">Graphics</h2><table class="data"><thead><tr><th>Model</th><th>Vendor</th><th>VRAM</th><th>Driver</th></tr></thead><tbody>';
    for (const g of d.graphics) html += `<tr><td>${esc(g.model)}</td><td>${esc(g.vendor)}</td><td>${fmtBytes(g.vram)}</td><td>${esc(g.driverVersion)}</td></tr>`;
    html += '</tbody></table>';
  }

  if (d.disks && d.disks.length) {
    html += '<h2 class="sec">Physical disks</h2><table class="data"><thead><tr><th>Device</th><th>Name</th><th>Type</th><th>Size</th><th>SMART</th></tr></thead><tbody>';
    for (const k of d.disks) html += `<tr><td><code>${esc(k.device)}</code></td><td>${esc(k.name)}</td><td>${esc(k.type)}</td><td>${fmtBytes(k.size)}</td><td class="${String(k.smartStatus || '').toLowerCase().includes('ok') ? 'ok' : 'warn'}">${esc(k.smartStatus || 'n/a')}</td></tr>`;
    html += '</tbody></table>';
  }

  if (d.mounts && d.mounts.length) {
    html += '<h2 class="sec">Mounted volumes</h2><table class="data"><thead><tr><th>Mount</th><th>Device</th><th>Type</th><th>Used</th><th>Use %</th></tr></thead><tbody>';
    for (const m of d.mounts) html += `<tr><td>${esc(m.mount)}</td><td><code>${esc(m.fs)}</code></td><td>${esc(m.type)}</td><td>${fmtBytes(m.used)} / ${fmtBytes(m.size)}</td><td>${m.usePct}%</td></tr>`;
    html += '</tbody></table>';
  }

  if (d.network && d.network.length) {
    html += '<h2 class="sec">Network adapters</h2><table class="data"><thead><tr><th>Interface</th><th>Type</th><th>IP</th><th>MAC</th><th>Speed</th></tr></thead><tbody>';
    for (const n of d.network) html += `<tr><td>${esc(n.iface)}${n.default ? ' <span class="tag-default">default</span>' : ''}</td><td>${esc(n.type || '')}</td><td>${esc(n.ip4 || n.ip6 || '')}</td><td>${esc(n.mac)}</td><td>${n.speed ? n.speed + ' Mbps' : '—'}</td></tr>`;
    html += '</tbody></table>';
  }

  if (d.battery && d.battery.hasBattery) {
    html += '<h2 class="sec">Battery</h2>';
    html += kvTable([['Charge', `${d.battery.percent}%`], ['Status', d.battery.isCharging ? 'Charging' : 'On battery'], ['Remaining', fmtUptime(d.battery.timeRemaining)]]);
  }

  if (d.usb && d.usb.length) {
    html += '<h2 class="sec">USB devices</h2><ul class="evidence">';
    for (const u of d.usb.slice(0, 20)) html += `<li><code>${esc(u.name || 'Unknown device')}</code>${u.manufacturer ? ' — ' + esc(u.manufacturer) : ''}</li>`;
    html += '</ul>';
  }

  if (d.software && d.software.count > 0) {
    html += '<h2 class="sec">Installed software</h2>';
    html += `<p class="muted">${d.software.count} packages via ${esc(d.software.source)} (showing first ${Math.min(d.software.sample.length, 30)})</p><ul class="evidence">`;
    for (const s of d.software.sample.slice(0, 30)) html += `<li><code>${esc(s)}</code></li>`;
    html += '</ul>';
  }

  if (d.temps && (d.temps.main || (d.temps.max))) {
    html += '<h2 class="sec">Temperatures</h2>';
    html += kvTable([['Main', d.temps.main ? d.temps.main + ' °C' : 'n/a'], ['Max', d.temps.max ? d.temps.max + ' °C' : 'n/a']]);
  }
  return html;
}

function fmtUptime(sec) {
  if (sec == null || isNaN(sec)) return '—';
  const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
  const parts = [];
  if (d) parts.push(`${d}d`); if (h) parts.push(`${h}h`); if (m || !parts.length) parts.push(`${m}m`);
  return parts.join(' ');
}

function renderHTML(data, theme = 'dark') {
  const dark = theme === 'dark';
  const pal = dark
    ? { bg: '#0b1220', panel: '#111a2e', panel2: '#0f172a', text: '#e2e8f0', muted: '#94a3b8', border: '#1e293b', accent: '#38bdf8' }
    : { bg: '#f1f5f9', panel: '#ffffff', panel2: '#f8fafc', text: '#0f172a', muted: '#64748b', border: '#e2e8f0', accent: '#0284c7' };
  const s = data.security;

  let securityBlock = '';
  if (s) {
    securityBlock = `
    <div class="score-row">${scoreRing(s.score, s.grade)}
      <div class="summary-chips">
        ${SEVERITY_ORDER.filter((x) => x !== 'info').map((sev) => `
          <div class="chip ${sev}"><span class="chip-n">${s.summary[sev] || 0}</span><span class="chip-l">${sev}</span></div>`).join('')}
        <div class="chip info"><span class="chip-n">${s.summary.info || 0}</span><span class="chip-l">info</span></div>
      </div>
    </div>
    <p class="muted">Scan completed in ${(s.durationMs / 1000).toFixed(1)}s · ${s.findings.length} findings · ${s.ports.length} listening port(s) · ${s.services.enabled} auto-start service(s)</p>
    ${findingsHtml(s)}`;
  }

  const css = `
  :root{--bg:${pal.bg};--surface:${pal.panel};--surface2:${pal.panel2};--text:${pal.text};--muted:${pal.muted};--border:${pal.border};--accent:${pal.accent}}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--text);font-family:-apple-system,'Segoe UI Variable','Segoe UI',Roboto,Ubuntu,sans-serif;font-size:14px;line-height:1.55;-webkit-font-smoothing:antialiased}
  .wrap{max-width:940px;margin:0 auto;padding:32px 36px 64px}
  header{display:flex;align-items:center;gap:14px;padding:20px 0 22px;border-bottom:1px solid var(--border);margin-bottom:24px}
  .logo{width:42px;height:42px;border-radius:10px;background:linear-gradient(135deg,#0e1c33,#12263a);border:1px solid #24405e;color:#7cb8ff;display:flex;align-items:center;justify-content:center;flex:none}
  .logo svg{width:21px;height:21px}
  h1{font-size:21px;margin:0;letter-spacing:-.01em}
  .sub{color:var(--muted);font-size:12.5px;margin-top:2px}
  .meta{display:flex;gap:6px 18px;flex-wrap:wrap;margin:14px 0 4px;font-size:12px;color:var(--muted)}
  .meta b{color:var(--text);font-weight:600;font-family:ui-monospace,'Cascadia Code',Consolas,monospace}
  .meta span{white-space:nowrap}
  h2.sec{font-size:12px;margin:36px 0 12px;padding-bottom:7px;border-bottom:1px solid var(--border);color:var(--accent);text-transform:uppercase;letter-spacing:.6px;font-weight:650}
  h3.cat{font-size:11px;margin:26px 0 10px;text-transform:uppercase;letter-spacing:.65px;color:var(--muted);font-weight:650}
  .cat-count{font-family:ui-monospace,Consolas,monospace;background:var(--surface2);border:1px solid var(--border);border-radius:999px;padding:1px 8px;font-size:10.5px;margin-left:6px}
  .cards{display:flex;flex-direction:column;gap:9px}
  .finding{background:var(--surface);border:1px solid var(--border);border-left:3px solid var(--border);border-radius:9px;padding:12px 14px}
  .finding.critical{border-left-color:#e5534b}.finding.high{border-left-color:#e08a3c}.finding.medium{border-left-color:#d9a441}.finding.low{border-left-color:#a8b23f}.finding.info{border-left-color:#3fc1e0}
  .finding-head{display:flex;align-items:center;gap:10px}
  .badge{font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.7px;padding:2px 8px;border-radius:999px;border:1px solid}
  .badge.critical{color:#e5534b;border-color:rgba(229,83,75,.4);background:rgba(229,83,75,.08)}
  .badge.high{color:#e08a3c;border-color:rgba(224,138,60,.4);background:rgba(224,138,60,.08)}
  .badge.medium{color:#d9a441;border-color:rgba(217,164,65,.4);background:rgba(217,164,65,.08)}
  .badge.low{color:#8a9230;border-color:rgba(168,178,63,.4);background:rgba(168,178,63,.08)}
  .badge.info{color:#2a9dbb;border-color:rgba(63,193,224,.4);background:rgba(63,193,224,.08)}
  .finding-title{font-weight:600;font-size:13px}
  .finding-detail{color:var(--muted);margin:7px 0 4px;font-size:12.5px;line-height:1.6}
  .finding-rec{font-size:12.5px;margin:5px 0 0}
  .evidence{margin:7px 0 0;padding-left:2px;list-style:none;display:flex;flex-direction:column;gap:3px;color:var(--muted);font-size:11.5px}
  .evidence li::before{content:'';display:inline-block;width:4px;height:4px;border-radius:50%;background:var(--border);margin-right:8px;vertical-align:middle}
  .evidence code{background:var(--surface2);border:1px solid var(--border);border-radius:4px;padding:1px 6px;font-family:ui-monospace,'Cascadia Code',Consolas,monospace;font-size:11px}
  .score-row{display:flex;gap:30px;align-items:center;flex-wrap:wrap;background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:22px 26px}
  .ring-wrap{text-align:center}
  .ring-score{font-size:32px;font-weight:700;font-family:ui-monospace,Consolas,monospace}
  .ring-grade{font-size:16px;font-weight:700}
  .ring-caption{color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.8px;margin-top:2px}
  .summary-chips{display:flex;gap:9px;flex-wrap:wrap}
  .chip{border-radius:9px;padding:9px 14px;text-align:center;min-width:64px;border:1px solid var(--border);background:var(--surface2)}
  .chip-n{display:block;font-size:19px;font-weight:700;font-variant-numeric:tabular-nums;font-family:ui-monospace,Consolas,monospace}
  .chip.critical .chip-n{color:#e5534b}.chip.high .chip-n{color:#e08a3c}.chip.medium .chip-n{color:#d9a441}.chip.low .chip-n{color:#8a9230}.chip.info .chip-n{color:#2a9dbb}
  .chip-l{font-size:9px;text-transform:uppercase;letter-spacing:.6px;color:var(--muted)}
  table.kv{width:100%;border-collapse:collapse;background:var(--surface);border:1px solid var(--border);border-radius:9px;overflow:hidden}
  table.kv th,table.kv td{text-align:left;padding:7px 14px;font-size:12.5px}
  table.kv th{width:30%;color:var(--muted);font-weight:600;border-right:1px solid var(--border);background:var(--surface2);font-size:11.5px}
  table.kv td{border-top:1px solid var(--border)}
  table.kv tr:first-child td{border-top:none}
  table.data{width:100%;border-collapse:collapse;background:var(--surface);border:1px solid var(--border);border-radius:9px;font-size:12px}
  table.data th,table.data td{padding:6px 12px;text-align:left;border-bottom:1px solid var(--border)}
  table.data th{color:var(--muted);background:var(--surface2);text-transform:uppercase;font-size:10px;letter-spacing:.5px}
  table.data code{font-family:ui-monospace,Consolas,monospace;background:var(--surface2);border:1px solid var(--border);border-radius:4px;padding:0 5px}
  .ok{color:#3f9d6f;font-weight:600}.warn{color:#b8860b;font-weight:600}
  h4{margin:14px 0 6px;color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.5px}
  .muted{color:var(--muted);font-size:12.5px}
  .tag-default{font-size:10px;color:#3f9d6f;background:rgba(63,157,111,.12);border:1px solid rgba(63,157,111,.3);border-radius:999px;padding:0 7px;font-weight:600}
  footer{margin-top:44px;padding-top:16px;border-top:1px solid var(--border);color:var(--muted);font-size:11.5px;display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px}
  @media print{body{background:#fff}.finding{break-inside:avoid}}
  `;

  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>${APP_NAME} report — ${esc(data.host)}</title>
<meta name="viewport" content="width=device-width,initial-scale=1"><style>${css}</style></head>
<body><div class="wrap">
  <header>
    <div class="logo"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2.8 4.5 5.6v5.4c0 5 3.2 8.6 7.5 10.2 4.3-1.6 7.5-5.2 7.5-10.2V5.6L12 2.8z"/></svg></div>
    <div><h1>${APP_NAME} — System Report</h1>
    <div class="sub">${data.include === 'full' ? 'Full diagnostics + security audit' : data.include === 'security' ? 'Security audit' : 'Diagnostics inventory'}</div></div>
  </header>
  <div class="meta">
    <span>host <b>${esc(data.host)}</b></span><span>user <b>${esc(data.user)}</b></span><span>platform <b>${esc(data.platform)}</b></span>
    <span>generated <b>${esc(niceTime(data.generatedAt))}</b></span><span>${APP_NAME} <b>v${APP_VERSION}</b></span>
  </div>
  ${securityBlock}
  ${data.diagnostics ? diagHtml(data.diagnostics) : ''}
  <footer><span>Generated automatically by ${APP_NAME} v${APP_VERSION}</span><span>${esc(niceTime(data.generatedAt))}</span></footer>
</div></body></html>`;
}

// Markdown
function renderMarkdown(data) {
  const L = [];
  L.push(`# ${APP_NAME} — System Report`);
  L.push('');
  L.push(`**Host:** ${data.host}  ·  **User:** ${data.user}  ·  **Platform:** ${data.platform}  ·  **Generated:** ${niceTime(data.generatedAt)}`);
  L.push('');
  const s = data.security;
  if (s) {
    L.push('## Security Score');
    L.push('');
    L.push(`**${s.score}/100 (${s.grade})** — ${s.findings.length} findings · ${s.ports.length} listening ports · ${s.services.enabled} auto-start services · scan in ${(s.durationMs / 1000).toFixed(1)}s`);
    L.push('');
    L.push('| Severity | Count |');
    L.push('| --- | --- |');
    for (const sev of SEVERITY_ORDER) L.push(`| ${sev} | ${s.summary[sev] || 0} |`);
    L.push('');
    L.push('## Findings');
    L.push('');
    const groups = new Map();
    for (const f of s.findings) {
      if (!groups.has(f.category)) groups.set(f.category, []);
      groups.get(f.category).push(f);
    }
    for (const [cat, items] of groups) {
      L.push(`### ${cat} (${items.length})`);
      L.push('');
      for (const f of items) {
        L.push(`- **[${f.severity.toUpperCase()}]** ${f.title}`);
        if (f.detail) L.push(`  - ${f.detail}`);
        if (f.recommendation) L.push(`  - **Fix:** ${f.recommendation}`);
        for (const e of f.evidence) L.push(`  - \`${e}\``);
      }
      L.push('');
    }
    if (s.network) {
      const n = s.network;
      L.push('## Network');
      L.push('');
      L.push(`- Public IP: ${n.publicIp || 'unknown'}${n.geo && n.geo.ok ? ` (${n.geo.country}, ISP: ${n.geo.isp || 'n/a'})` : ''}`);
      L.push(`- NAT: ${n.nat ? n.nat.note : 'unknown'}`);
      L.push(`- DNS 8.8.8.8: ${n.dns ? 'reachable' : 'NOT reachable'}`);
      L.push('');
    }
  }
  const d = data.diagnostics;
  if (d) {
    L.push('## System');
    L.push('');
    L.push(`- **Hostname:** ${d.host.hostname}`);
    L.push(`- **OS:** ${d.host.distro} ${d.host.release} (${d.host.platform} ${d.host.arch})`);
    L.push(`- **Kernel:** ${d.host.kernel}`);
    L.push(`- **Uptime:** ${fmtUptime(d.host.uptimeSec)}`);
    L.push(`- **Model:** ${d.host.manufacturer} ${d.host.model}`);
    L.push(`- **Virtual:** ${d.host.virtual ? 'Yes (' + (d.host.virtualHost || '?') + ')' : 'No'}`);
    L.push('');
    if (d.cpu.ok) {
      L.push('### CPU');
      L.push('');
      L.push(`- ${d.cpu.manufacturer} ${d.cpu.brand}`);
      L.push(`- ${d.cpu.cores} threads / ${d.cpu.physicalCores} physical cores @ ${d.cpu.speed} GHz (max ${d.cpu.speedMax} GHz)`);
      L.push('');
    }
    L.push('### Memory');
    L.push('');
    L.push(`- Total: ${fmtBytes(d.memory.total)} · In use: ${fmtBytes(d.memory.active)} · Available: ${fmtBytes(d.memory.available)}`);
    L.push('');
    if (d.disks && d.disks.length) {
      L.push('### Disks');
      L.push('');
      L.push('| Device | Name | Type | Size | SMART |');
      L.push('| --- | --- | --- | --- | --- |');
      for (const k of d.disks) L.push(`| ${k.device} | ${k.name || ''} | ${k.type} | ${fmtBytes(k.size)} | ${k.smartStatus || 'n/a'} |`);
      L.push('');
    }
    if (d.mounts && d.mounts.length) {
      L.push('| Mount | Device | Used | Use % |');
      L.push('| --- | --- | --- | --- |');
      for (const m of d.mounts) L.push(`| ${m.mount} | ${m.fs} | ${fmtBytes(m.used)} / ${fmtBytes(m.size)} | ${m.usePct}% |`);
      L.push('');
    }
    if (d.network && d.network.length) {
      L.push('### Network adapters');
      L.push('');
      for (const n of d.network) L.push(`- **${n.iface}** — ${n.ip4 || n.ip6 || 'no IP'} (${n.type || '?'}${n.speed ? ', ' + n.speed + ' Mbps' : ''})`);
      L.push('');
    }
    if (d.software && d.software.count) L.push(`### Software\n\n${d.software.count} packages (${d.software.source})`);
  }
  L.push('');
  L.push(`---`);
  L.push(`*Generated automatically by ${APP_NAME} v${APP_VERSION} on ${niceTime(data.generatedAt)}.*`);
  return L.join('\n');
}

// Writers
function safeName(s) {
  return String(s || 'host').replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 40);
}

function writeReport(data, format, dir = DIRS.reports) {
  if (!['html', 'md', 'pdf'].includes(format)) format = 'html'; // whitelist
  fs.mkdirSync(dir, { recursive: true });
  const stamp = new Date(data.generatedAt).toISOString().replace(/[:T]/g, '-').slice(0, 19);
  const base = `${safeName(data.host)}-${data.include}-${stamp}`;
  const ext = format === 'md' ? 'md' : format === 'pdf' ? 'pdf' : 'html';
  const file = path.join(dir, `${base}.${ext}`);
  if (format === 'html') fs.writeFileSync(file, renderHTML(data));
  else if (format === 'md') fs.writeFileSync(file, renderMarkdown(data));
  else fs.writeFileSync(file, renderHTML(data)); // PDF gets rendered via printToPDF in main
  return file;
}

module.exports = { buildReportData, renderHTML, renderMarkdown, writeReport, fmtUptime };
