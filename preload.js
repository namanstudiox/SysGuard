'use strict';

const { contextBridge, ipcRenderer } = require('electron');

/** Minimal, typed bridge exposed to the renderer as window.sysguard. */
contextBridge.exposeInMainWorld('sysguard', {
  appInfo: () => ipcRenderer.invoke('app:info'),

  diagFull: () => ipcRenderer.invoke('diag:full'),

  monitor: {
    start: (ms) => ipcRenderer.invoke('monitor:start', ms),
    stop: () => ipcRenderer.invoke('monitor:stop'),
    history: (msAgo) => ipcRenderer.invoke('monitor:history', msAgo),
    onTick: (cb) => ipcRenderer.on('monitor:tick', (_e, payload) => cb(payload)),
  },

  processes: () => ipcRenderer.invoke('processes:list'),
  killProcess: (pid) => ipcRenderer.invoke('process:kill', pid),

  scanSecurity: (opts) => ipcRenderer.invoke('sec:scan', opts || {}),

  report: {
    generate: (opts) => ipcRenderer.invoke('report:generate', opts || {}),
    list: () => ipcRenderer.invoke('report:list'),
    open: (p) => ipcRenderer.invoke('report:open', p),
    reveal: (p) => ipcRenderer.invoke('report:reveal', p),
    remove: (id) => ipcRenderer.invoke('report:delete', id),
    saveScan: (scan) => ipcRenderer.invoke('sec:save', scan),
    loadScan: (p) => ipcRenderer.invoke('sec:load', p),
  },

  scheduler: {
    save: (schedules) => ipcRenderer.invoke('sched:save', schedules),
    next: () => ipcRenderer.invoke('sched:next'),
    onRan: (cb) => ipcRenderer.on('sched:ran', (_e, info) => cb(info)),
  },

  settings: {
    get: () => ipcRenderer.invoke('settings:get'),
    save: (partial) => ipcRenderer.invoke('settings:save', partial),
  },

  onMenuScan: (cb) => ipcRenderer.on('menu:scan', () => cb()),
  onMenuReport: (cb) => ipcRenderer.on('menu:report', () => cb()),
});
