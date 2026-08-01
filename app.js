'use strict';

const { app, BrowserWindow, ipcMain, shell, Menu, Tray, nativeImage } = require('electron');
const path = require('path');
const fs = require('fs');

// Linux sandbox detection. The setuid chrome-sandbox helper is required when
// unprivileged user namespaces are restricted (AppArmor on Ubuntu 23.10+),
// and it can't run inside AppImages at all (FUSE mounts strip setuid).
// If we can't use the sandbox, fall back to --no-sandbox so the app actually
// opens. The renderer keeps its isolation (webPreferences.sandbox +
// contextIsolation) and all IPC is validated in main regardless.
function linuxSandboxUsable() {
  if (process.platform !== 'linux') return true;
  // AppImage: the setuid helper can't work — FUSE mounts strip setuid, and
  // extract-and-run can't chown to root. Detect via the AppRun marker that
  // sits next to the binary in both cases.
  if (process.env.APPIMAGE || fs.existsSync(path.join(path.dirname(process.execPath), 'AppRun'))) return false;
  try {
    const helper = path.join(path.dirname(process.execPath), 'chrome-sandbox');
    const st = fs.statSync(helper);
    if ((st.mode & 0o4000) !== 0 && st.uid === 0) return true;
  } catch { /* helper missing — check user namespaces below */ }
  try {
    const { spawnSync } = require('child_process');
    return spawnSync('unshare', ['--user', 'true'], { timeout: 3000 }).status === 0;
  } catch {
    return false;
  }
}
// Relaunch instead of appendSwitch: the Chromium zygote reads the sandbox
// flag before any JS runs, so a JS-appended switch is ignored and the app
// dies on restricted systems (AppArmor userns blocks, AppImages). Relaunching
// with --no-sandbox on the real command line is the only reliable way.
const sandboxRelanchKey = 'sysguard-relaunched-nosandbox';
if (
  process.platform === 'linux' &&
  !process.env.SYSGUARD_ENABLE_SANDBOX &&
  !process.argv.includes('--no-sandbox') &&
  !process.env[sandboxRelanchKey] &&
  !linuxSandboxUsable()
) {
  process.env[sandboxRelanchKey] = '1';
  app.relaunch({ args: process.argv.slice(1).concat(['--no-sandbox']) });
  // Give the new process time to start before we exit — with FUSE-mounted
  // AppImages the runtime unmounts when the first process ends, and this
  // head start keeps the relaunched instance safely running from the mount.
  setTimeout(() => app.exit(0), 1500);
}

// A GPU-process crash at startup also surfaces as an instant "closed
// unexpectedly" on some hardware/driver combos. Relaunch once with hardware
// acceleration off instead of dying silently.
let relaunchedWithoutGpu = false;
app.on('child-process-gone', (_e, details) => {
  if (details.type === 'GPU' && !relaunchedWithoutGpu && !process.argv.includes('--disable-gpu')) {
    relaunchedWithoutGpu = true;
    app.relaunch({ args: process.argv.slice(1).concat(['--disable-gpu']) });
    app.exit(0);
  }
});

// Keep the data dir outside the packaged app so reports survive updates
// (an external SYSGUARD_DATA_DIR override is respected for testing)
if (!process.env.SYSGUARD_DATA_DIR) {
  try {
    process.env.SYSGUARD_DATA_DIR = app.getPath('userData');
  } catch {
  }
}

const si = require('systeminformation');
const store = require('./src/store');
const { collectDiagnostics } = require('./src/diagnostics');
const monitor = require('./src/monitor');
const { runSecurityScan, CHECK_DESCRIPTIONS } = require('./src/security');
const { buildReportData, renderHTML, writeReport } = require('./src/report');
const { Scheduler } = require('./src/scheduler');
const { APP_NAME, APP_VERSION } = require('./src/constants');

const isWin = process.platform === 'win32';
let mainWindow = null;
let tray = null;
let scheduler = null;

app.setAppUserModelId('com.sysguard.app');
const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.show();
      mainWindow.focus();
    }
  });
}

function createWindow() {
  const icon = path.join(__dirname, 'assets', 'icon.png');
  mainWindow = new BrowserWindow({
    width: 1240,
    height: 820,
    minWidth: 980,
    minHeight: 640,
    title: `${APP_NAME} — System Diagnostics & Security`,
    backgroundColor: '#0b1220',
    icon: fs.existsSync(icon) ? icon : undefined,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,   // renderer sandboxed; preload only uses contextBridge/ipcRenderer
    },
  });

  // Never let the window navigate away from the bundled UI.
  mainWindow.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  mainWindow.webContents.on('will-navigate', (e) => e.preventDefault());

  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));
  mainWindow.on('closed', () => { mainWindow = null; });
  return mainWindow;
}

function setupMenu() {
  const isMac = process.platform === 'darwin';
  const template = [
    ...(isMac ? [{ role: 'appMenu' }] : []),
    {
      label: 'File',
      submenu: [
        { label: 'Run security scan now', accelerator: 'CmdOrCtrl+Shift+S', click: () => mainWindow && mainWindow.webContents.send('menu:scan') },
        { label: 'Generate full report', accelerator: 'CmdOrCtrl+Shift+R', click: () => mainWindow && mainWindow.webContents.send('menu:report') },
        { type: 'separator' },
        isMac ? { role: 'close' } : { role: 'quit' },
      ],
    },
    {
      label: 'View',
      submenu: [
        { role: 'reload' },
        { role: 'toggleDevTools' },
        { type: 'separator' },
        { role: 'resetZoom' }, { role: 'zoomIn' }, { role: 'zoomOut' },
        { type: 'separator' },
        { role: 'togglefullscreen' },
      ],
    },
    {
      label: 'Help',
      submenu: [
        { label: 'About ' + APP_NAME, click: () => showAbout() },
      ],
    },
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

function showAbout() {
  require('electron').dialog.showMessageBox(mainWindow, {
    type: 'info',
    title: 'About ' + APP_NAME,
    message: APP_NAME + ' v' + APP_VERSION,
    detail: 'Full system diagnostics · real-time monitoring · automated security reports.\n\nRuns on Windows and Linux.\nData directory: ' + app.getPath('userData'),
  });
}

function setupTray() {
  try {
    const iconPath = path.join(__dirname, 'assets', 'icon.png');
    const img = nativeImage.createFromPath(iconPath).resize({ width: 16, height: 16 });
    tray = new Tray(img);
    tray.setToolTip(`${APP_NAME} — monitoring & security`);
    tray.setContextMenu(Menu.buildFromTemplate([
      { label: 'Show ' + APP_NAME, click: () => { mainWindow.show(); mainWindow.focus(); } },
      { label: 'Run security scan', click: () => mainWindow && mainWindow.webContents.send('menu:scan') },
      { type: 'separator' },
      { label: 'Quit', click: () => app.quit() },
    ]));
    tray.on('click', () => { if (mainWindow) { mainWindow.show(); mainWindow.focus(); } });
  } catch { /* tray unavailable on some Linux setups — non-fatal */ }
}

function startMonitor(intervalMs) {
  monitor.removeAllListeners('tick');
  monitor.on('tick', (payload) => {
    if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('monitor:tick', payload);
  });
  monitor.start(intervalMs || store.settings.refreshIntervalMs);
}

async function generatePdfFromHtml(html) {
  const tmpFile = path.join(app.getPath('temp'), `sysguard-pdf-${Date.now()}.html`);
  fs.writeFileSync(tmpFile, html, 'utf8');
  const win = new BrowserWindow({ show: false, webPreferences: { sandbox: true } });
  try {
    await win.loadFile(tmpFile);
    const data = await win.webContents.printToPDF({
      pageSize: 'A4',
      printBackground: true,
      margins: { marginType: 'default' },
    });
    return data;
  } finally {
    win.destroy();
    try { fs.unlinkSync(tmpFile); } catch { /* ignore */ }
  }
}

async function generateReport({ include = 'full', format = 'html', quiet = false } = {}) {
  const ALLOWED_INCLUDE = ['full', 'security', 'diagnostics'];
  const ALLOWED_FORMAT = ['html', 'md', 'pdf'];
  if (!ALLOWED_INCLUDE.includes(include)) include = 'full';
  if (!ALLOWED_FORMAT.includes(format)) format = 'html';
  const diag = include === 'full' || include === 'diagnostics' ? await collectDiagnostics() : null;
  const scan = include === 'full' || include === 'security' ? await runSecurityScan({
    externalChecks: store.settings.externalChecks,
    expectedCountry: store.settings.expectedCountry,
  }) : null;
  const data = await buildReportData(include, diag, scan);
  let filePath;
  if (format === 'pdf') {
    const html = renderHTML(data, store.settings.theme);
    const pdf = await generatePdfFromHtml(html);
    const stamp = new Date().toISOString().replace(/[:T]/g, '-').slice(0, 19);
    const base = `${String(data.host).replace(/[^a-zA-Z0-9._-]/g, '_')}-${include}-${stamp}`;
    filePath = path.join(app.getPath('userData'), 'reports', `${base}.pdf`);
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, pdf);
  } else {
    filePath = writeReport(data, format);
  }
  const entry = {
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    type: include,
    format,
    path: filePath,
    score: scan ? scan.score : null,
    grade: scan ? scan.grade : null,
    findings: scan ? scan.findings.length : 0,
    createdAt: new Date().toISOString(),
  };
  store.addHistory(entry);
  if (store.settings.openReportAfterGenerate && !quiet) shell.openPath(filePath);
  return entry;
}

function reportsDir() {
  return path.join(app.getPath('userData'), 'reports');
}

function isSafeReportPath(p) {
  if (typeof p !== 'string' || !p) return false;
  const base = path.resolve(reportsDir());
  const resolved = path.resolve(p);
  return resolved === base || resolved.startsWith(base + path.sep);
}

function registerIpc() {
  ipcMain.handle('app:info', () => ({
    name: APP_NAME, version: APP_VERSION, platform: process.platform, arch: process.arch,
    dataDir: app.getPath('userData'), checks: CHECK_DESCRIPTIONS,
  }));

  ipcMain.handle('diag:full', () => collectDiagnostics());

  ipcMain.handle('monitor:start', (_e, ms) => { startMonitor(ms); return true; });
  ipcMain.handle('monitor:stop', () => { monitor.stop(); return true; });
  ipcMain.handle('monitor:history', (_e, msAgo) => monitor.historySince(msAgo || 120000));

  ipcMain.handle('processes:list', async () => {
    const p = await si.processes().catch(() => ({ list: [], all: 0, running: 0, blocked: 0 }));
    return {
      all: p.all || (Array.isArray(p.list) ? p.list.length : 0),
      running: p.running || 0,
      blocked: p.blocked || 0,
      list: (Array.isArray(p.list) ? p.list : []).map((x) => ({
        pid: x.pid, name: x.name, cpu: x.cpu, mem: x.mem,
        command: (x.command || '').slice(0, 160), user: x.user, state: x.state,
      })),
    };
  });

  ipcMain.handle('process:kill', async (_e, pid) => {
    pid = parseInt(pid, 10);
    if (!pid || pid <= 0) return { ok: false, error: 'invalid pid' };
    try {
      if (isWin) {
        const { execFile } = require('child_process');
        await new Promise((res, rej) => execFile('taskkill', ['/PID', String(pid), '/T', '/F'], { windowsHide: true }, (err) => err ? rej(err) : res()));
      } else {
        process.kill(pid, 'SIGKILL');
      }
      return { ok: true };
    } catch (e) {
      return { ok: false, error: String(e.message || e) };
    }
  });

  ipcMain.handle('sec:scan', (_e, opts) => runSecurityScan({
    externalChecks: opts && opts.externalChecks != null ? opts.externalChecks : store.settings.externalChecks,
    expectedCountry: store.settings.expectedCountry,
  }));

  ipcMain.handle('report:generate', (_e, opts) => generateReport(opts));
  ipcMain.handle('report:list', () => store.history);
  ipcMain.handle('report:open', (_e, p) => {
    if (!isSafeReportPath(p)) return { ok: false, error: 'path not allowed' };
    shell.openPath(p);
    return { ok: true };
  });
  ipcMain.handle('report:reveal', (_e, p) => {
    if (!isSafeReportPath(p)) return { ok: false, error: 'path not allowed' };
    shell.showItemInFolder(p);
    return { ok: true };
  });
  ipcMain.handle('report:delete', (_e, id) => {
    const entry = store.history.find((h) => h.id === id);
    if (!entry) return false;
    if (!isSafeReportPath(entry.path)) return false; // refuse to unlink files outside the reports dir
    return store.deleteHistory(id);
  });

  // persist a finished scan to history (so it can be revisited later)
  ipcMain.handle('sec:save', (_e, scan) => {
    if (!scan || !scan.generatedAt) return null;
    const stamp = new Date(scan.generatedAt).toISOString().replace(/[:T]/g, '-').slice(0, 19);
    const host = String(scan.host || 'host').replace(/[^a-zA-Z0-9._-]/g, '_');
    const file = path.join(app.getPath('userData'), 'reports', `scan-${host}-${stamp}.json`);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, JSON.stringify(scan, null, 2));
    const entry = {
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      type: 'security', format: 'scan', path: file,
      score: scan.score, grade: scan.grade, findings: scan.findings.length,
      createdAt: new Date().toISOString(),
    };
    store.addHistory(entry);
    return entry;
  });
  ipcMain.handle('sec:load', (_e, p) => {
    if (!isSafeReportPath(p)) return null;
    try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return null; }
  });

  ipcMain.handle('sched:save', (_e, schedules) => {
    store.saveSchedules(schedules);
    if (scheduler) { scheduler.stop(); scheduler = createScheduler(); }
    return store.settings.schedules;
  });
  ipcMain.handle('sched:next', () => {
    const now = new Date();
    return (store.settings.schedules || []).map((s) => ({
      id: s.id, label: s.label, enabled: s.enabled, type: s.type,
      next: s.enabled ? scheduler.nextRun(s, now) : null,
      lastRun: store.getLastRun(s.id),
    }));
  });

  ipcMain.handle('settings:get', () => store.settings);
  ipcMain.handle('settings:save', (_e, partial) => {
    const saved = store.saveSettings(partial);
    if (partial && typeof partial.refreshIntervalMs === 'number') startMonitor(partial.refreshIntervalMs);
    return saved;
  });

}

function createScheduler() {
  const s = new Scheduler(store);
  s.on('due', async (spec, iso) => {
    try {
      const entry = await generateReport({ include: spec.include || 'full', format: spec.format || 'html', quiet: true });
      store.markScheduleRun(spec.id, iso);
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('sched:ran', { schedule: spec.label, path: entry.path, score: entry.score, grade: entry.grade });
        if (store.settings.openReportAfterGenerate) shell.openPath(entry.path);
      }
    } catch (e) {
      console.error('Scheduled report failed:', e);
    } finally {
      s.complete(spec.id);
    }
  });
  s.start();
  return s;
}

app.whenReady().then(() => {
  store.load();
  createWindow();
  setupMenu();
  setupTray();
  registerIpc();
  startMonitor(store.settings.refreshIntervalMs);
  scheduler = createScheduler();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });

  // Screenshot mode: SYSGUARD_SCREENSHOT=<dir> — capture every tab and exit.
  // Used for UI verification (e.g. under xvfb). Not part of normal operation.
  if (process.env.SYSGUARD_SCREENSHOT) {
    captureTabsForReview(process.env.SYSGUARD_SCREENSHOT).catch((e) => { console.error(e); app.exit(1); });
  }
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('before-quit', () => {
  monitor.stop();
  if (scheduler) scheduler.stop();
});

module.exports = { generateReport };

async function captureTabsForReview(outDir) {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const wc = mainWindow.webContents;
  await new Promise((resolve) => {
    const iv = setInterval(() => { if (!wc.isLoading()) { clearInterval(iv); resolve(); } }, 200);
    setTimeout(resolve, 20000);
  });
  await sleep(6000);
  fs.mkdirSync(outDir, { recursive: true });

  const tabs = ['overview', 'system', 'monitor', 'security', 'reports', 'settings'];
  for (const tab of tabs) {
    await wc.executeJavaScript(`document.querySelector('.nav-item[data-tab="${tab}"]').click(); true`);
    if (tab === 'system') await sleep(8000);   // let the inventory scan finish
    if (tab === 'monitor') await sleep(3500);
    if (tab === 'security') {
      await sleep(600);
      await wc.executeJavaScript(`document.getElementById('secScanBtn').click(); true`);
      await sleep(22000);                      // full audit incl. network checks
    }
    if (tab === 'reports' || tab === 'settings') await sleep(1500);
    await sleep(1200);
    const img = await wc.capturePage();
    fs.writeFileSync(path.join(outDir, `${tab}.png`), img.toPNG());
    console.log('captured', tab);
  }
  app.exit(0);
}

