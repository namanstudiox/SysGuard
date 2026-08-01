'use strict';

const fs = require('fs');
const path = require('path');
const { DIRS, DEFAULT_SETTINGS } = require('./constants');

/** Tiny atomic JSON store. Data survives in ~/.sysguard (or app userData). */
class Store {
  constructor() {
    this.settings = { ...DEFAULT_SETTINGS, schedules: JSON.parse(JSON.stringify(DEFAULT_SETTINGS.schedules)) };
    this.history = [];
    this.lastRuns = {}; // scheduleId -> ISO timestamp of last execution
    this._loaded = false;
  }

  _ensureDirs() {
    fs.mkdirSync(DIRS.reports, { recursive: true });
  }

  _read(file, fallback) {
    try {
      return JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch {
      return fallback;
    }
  }

  _write(file, data) {
    this._ensureDirs();
    const tmp = `${file}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
    fs.renameSync(tmp, file);
  }

  load() {
    this._ensureDirs();
    const s = this._read(path.join(DIRS.root, 'settings.json'), null);
    if (s) {
      this.settings = { ...DEFAULT_SETTINGS, ...s };
      // keep schedule defaults if missing, and preserve schedule list
      if (!Array.isArray(this.settings.schedules)) {
        this.settings.schedules = JSON.parse(JSON.stringify(DEFAULT_SETTINGS.schedules));
      }
    }
    this.history = this._read(path.join(DIRS.reports, 'history.json'), []);
    this.lastRuns = this._read(path.join(DIRS.root, 'last-runs.json'), {});
    this._loaded = true;
    return this;
  }

  saveSettings(partial) {
    this.settings = { ...this.settings, ...partial };
    this._write(path.join(DIRS.root, 'settings.json'), this.settings);
    return this.settings;
  }

  saveSchedules(schedules) {
    this.settings.schedules = schedules;
    this._write(path.join(DIRS.root, 'settings.json'), this.settings);
    return schedules;
  }

  addHistory(entry) {
    this.history.unshift(entry);
    if (this.history.length > 200) this.history = this.history.slice(0, 200);
    this._write(path.join(DIRS.reports, 'history.json'), this.history);
    return entry;
  }

  deleteHistory(id) {
    const idx = this.history.findIndex((h) => h.id === id);
    if (idx >= 0) {
      const [removed] = this.history.splice(idx, 1);
      try { fs.unlinkSync(removed.path); } catch { /* file may already be gone */ }
      this._write(path.join(DIRS.reports, 'history.json'), this.history);
      return true;
    }
    return false;
  }

  markScheduleRun(id, isoTime) {
    this.lastRuns[id] = isoTime;
    this._write(path.join(DIRS.root, 'last-runs.json'), this.lastRuns);
  }

  getLastRun(id) {
    return this.lastRuns[id] || null;
  }
}

module.exports = new Store();
