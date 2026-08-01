'use strict';
// Headless security scan test — prints findings + score.
process.env.SYSGUARD_DATA_DIR = require('path').join(process.cwd(), '.test-data');

const { runSecurityScan } = require('../src/security');

(async () => {
  console.log('Running full security scan (external checks ON)…\n');
  const scan = await runSecurityScan({ externalChecks: true, expectedCountry: '' });

  console.log(`SCORE: ${scan.score}/100 (${scan.grade})  —  ${scan.findings.length} findings in ${(scan.durationMs / 1000).toFixed(1)}s`);
  console.log(`SUMMARY: ${JSON.stringify(scan.summary)}`);
  console.log(`PORTS: ${scan.ports.length} listening · SERVICES: ${scan.services.running} running / ${scan.services.enabled} enabled · STARTUP: ${scan.startupCount}`);
  console.log(`FIREWALL: ${JSON.stringify(scan.firewall)}`);
  console.log(`UPDATES: ${JSON.stringify(scan.updates)}`);
  if (scan.network) {
    console.log(`NETWORK: ip=${scan.network.publicIp} geo=${scan.network.geo && scan.network.geo.ok ? scan.network.geo.country : '?'} nat=${scan.network.nat && scan.network.nat.behindNAT} dns=${scan.network.dns}`);
  }
  console.log('\nFINDINGS:');
  for (const f of scan.findings) {
    console.log(`  [${f.severity.toUpperCase().padEnd(8)}] (${f.category}) ${f.title}`);
    f.evidence.slice(0, 3).forEach((e) => console.log(`         ↳ ${String(e).slice(0, 120)}`));
  }
  console.log('\nCATEGORIES:');
  scan.categories.forEach((c) => console.log(`  ${c.name}: ${c.count} finding(s), -${c.deductions} pts`));
})().catch((e) => { console.error(e); process.exit(1); });
