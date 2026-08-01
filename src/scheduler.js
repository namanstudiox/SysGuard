'use strict';

const { EventEmitter } = require('events');

/** Lightweight report scheduler — no cron dependency. */
class Scheduler extends EventEmitter {
  constructor(store, opts = {}) {
    super();
    this.store = store;
    this.timer = null;
    this.intervalMs = opts.intervalMs || 30000;
    this._inFlight = new Set(); // schedule ids currently generating a report
  }

  start() {
    if (this.timer) return;
    this.timer = setInterval(() => this.check(), this.intervalMs);
    // fire a check soon after start (handles 'startup' schedules)
    setTimeout(() => this.check(true), 1500);
  }

  stop() {
    if (this.timer) { clearInterval(this.timer); this.timer = null; }
  }

  /** @returns ISO string of the next run time for a schedule, or null if not scheduled. */
  nextRun(spec, now = new Date()) {
    const lastRun = this.store.getLastRun(spec.id);
    switch (spec.type) {
      case 'daily': {
        const [h, m] = (spec.time || '09:00').split(':').map(Number);
        const d = new Date(now); d.setHours(h, m, 0, 0);
        if (d <= now) d.setDate(d.getDate() + 1);
        return d.toISOString();
      }
      case 'weekly': {
        const [h, m] = (spec.time || '09:00').split(':').map(Number);
        const day = (spec.day != null ? spec.day : 0);
        const d = new Date(now); d.setHours(h, m, 0, 0);
        let delta = (day - d.getDay() + 7) % 7;
        if (delta === 0 && d <= now) delta = 7;
        d.setDate(d.getDate() + delta);
        return d.toISOString();
      }
      case 'interval': {
        const hours = Math.max(0.5, spec.everyHours || 6);
        if (!lastRun) {
          const d = new Date(now); d.setMinutes(d.getMinutes() + 1);
          return d.toISOString();
        }
        return new Date(new Date(lastRun).getTime() + hours * 3600 * 1000).toISOString();
      }
      case 'startup':
        return now.toISOString();
      default:
        return null;
    }
  }

  isDue(spec, now = new Date()) {
    const lastRun = this.store.getLastRun(spec.id);
    if (spec.type === 'interval' && !lastRun) {
      // first run fires shortly after the app starts, then every N hours
      return true;
    }
    if (spec.type === 'startup') {
      // run once per app launch
      return !lastRun || new Date(lastRun).getTime() < Date.now() - 60000;
    }
    const next = this.nextRun(spec, now);
    if (!next) return false;
    return new Date(next).getTime() <= now.getTime();
  }

  check(allowStartup = false) {
    const now = new Date();
    for (const spec of (this.store.settings.schedules || [])) {
      if (!spec.enabled) continue;
      if (this._inFlight.has(spec.id)) continue; // already generating
      if (spec.type === 'startup' && !allowStartup) continue;
      if (this.isDue(spec, now)) {
        this._inFlight.add(spec.id);
        this.emit('due', spec, now.toISOString());
      }
    }
  }

  complete(id) {
    this._inFlight.delete(id);
  }
}

module.exports = { Scheduler };
