'use strict';
// Headless report generation test — writes sample HTML + Markdown reports.
process.env.SYSGUARD_DATA_DIR = require('path').join(process.cwd(), '.test-data');

const path = require('path');
const { collectDiagnostics } = require('../src/diagnostics');
const { runSecurityScan } = require('../src/security');
const { buildReportData, renderHTML, renderMarkdown } = require('../src/report');

const outDir = path.join(__dirname, '..', 'sample-reports');
require('fs').mkdirSync(outDir, { recursive: true });

(async () => {
  console.log('Collecting diagnostics + security scan…');
  const [diag, scan] = await Promise.all([
    collectDiagnostics(),
    runSecurityScan({ externalChecks: true, expectedCountry: '' }),
  ]);
  const data = await buildReportData('full', diag, scan);

  const htmlDark = renderHTML(data, 'dark');
  const htmlLight = renderHTML(data, 'light');
  const md = renderMarkdown(data);

  require('fs').writeFileSync(path.join(outDir, 'sample-report-dark.html'), htmlDark);
  require('fs').writeFileSync(path.join(outDir, 'sample-report-light.html'), htmlLight);
  require('fs').writeFileSync(path.join(outDir, 'sample-report.md'), md);

  console.log(`HTML (dark): ${htmlDark.length} bytes`);
  console.log(`HTML (light): ${htmlLight.length} bytes`);
  console.log(`Markdown: ${md.length} bytes`);
  console.log(`Written to ${outDir}`);
})().catch((e) => { console.error(e); process.exit(1); });
