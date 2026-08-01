'use strict';
// Headless diagnostics test — prints a summary of the machine's inventory.
process.env.SYSGUARD_DATA_DIR = require('path').join(process.cwd(), '.test-data');

const { collectDiagnostics, fmtBytes } = require('../src/diagnostics');

(async () => {
  const t0 = Date.now();
  console.log('Collecting full diagnostics…\n');
  const d = await collectDiagnostics();

  const h = d.host;
  console.log('=== System ===');
  console.log(`hostname: ${h.hostname}  platform: ${h.platform} ${h.arch}`);
  console.log(`os: ${h.distro} ${h.release} (${h.codename || '-'})  kernel: ${h.kernel}`);
  console.log(`model: ${h.manufacturer} ${h.model}  virtual: ${h.virtual} ${h.virtualHost || ''}`);
  console.log(`uptime: ${Math.floor(h.uptimeSec / 3600)}h  tz: ${h.timezone}`);

  console.log('\n=== CPU ===');
  if (d.cpu.ok) {
    console.log(`${d.cpu.manufacturer} ${d.cpu.brand}`);
    console.log(`${d.cpu.cores} threads / ${d.cpu.physicalCores} physical @ ${d.cpu.speed}GHz (max ${d.cpu.speedMax}GHz)`);
  } else console.log('n/a');

  console.log('\n=== Memory ===');
  console.log(`total: ${fmtBytes(d.memory.total)}  active: ${fmtBytes(d.memory.active)}  modules: ${d.memory.modules.length}`);
  d.memory.modules.slice(0, 2).forEach((m) => console.log(`  ${m.type} ${fmtBytes(m.size)} ${m.clockSpeed}MHz ${m.manufacturer}`));

  console.log('\n=== Disks ===');
  d.disks.forEach((k) => console.log(`  ${k.device}  ${k.name || '?'}  ${k.type}  ${fmtBytes(k.size)}  SMART: ${k.smartStatus}`));
  console.log('mounts:');
  d.mounts.forEach((m) => console.log(`  ${m.mount}  ${m.fs}  ${m.usePct}% used  ${fmtBytes(m.used)}/${fmtBytes(m.size)}`));

  console.log('\n=== Graphics ===');
  (d.graphics.length ? d.graphics : [{ model: '(none detected)' }]).forEach((g) => console.log(`  ${g.model}  ${g.vram ? fmtBytes(g.vram) : ''}  ${g.driverVersion || ''}`));

  console.log('\n=== Network ===');
  d.network.forEach((n) => console.log(`  ${n.iface}${n.default ? ' *' : ''}  ${n.ip4 || n.ip6 || '-'}  ${n.mac}  ${n.speed ? n.speed + 'Mbps' : ''}  ${n.type || ''}`));

  console.log('\n=== Battery ===');
  console.log(`  ${d.battery ? `${d.battery.percent}% ${d.battery.isCharging ? '(charging)' : ''}` : 'no battery'}`);

  console.log('\n=== Software ===');
  console.log(`  ${d.software.count} packages (${d.software.source})  e.g. ${d.software.top.slice(0, 5).join(', ')}`);

  console.log('\n=== USB ===');
  console.log(`  ${d.usb.length} devices`);

  console.log(`\n=== Temps ===`);
  console.log(`  ${d.temps && d.temps.main ? d.temps.main + ' °C' : 'no sensors'}`);

  console.log(`\nCompleted in ${Date.now() - t0} ms`);
})().catch((e) => { console.error(e); process.exit(1); });
