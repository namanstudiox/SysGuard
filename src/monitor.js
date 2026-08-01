'use strict';

const { EventEmitter } = require('events');
const si = require('systeminformation');

/** Real-time sampling engine. Polls at a configurable interval and emits 'tick'. */
class Monitor extends EventEmitter {
  constructor() {
    super();
    this.timer = null;
    this.intervalMs = 1500;
    this.history = [];          // rolling payload history (for chart redraws)
    this.maxHistory = 300;
    this.last = null;
    this._defaultIfaces = [];
  }

  async _discoverInterfaces() {
    try {
      const ifs = await si.networkInterfaces();
      this._defaultIfaces = (Array.isArray(ifs) ? ifs : [])
        .filter((i) => !i.internal)
        .map((i) => i.iface);
    } catch { this._defaultIfaces = []; }
  }

  start(intervalMs = 1500) {
    if (this.timer) this.stop();
    this.intervalMs = Math.max(500, intervalMs);
    this._discoverInterfaces();
    this._tick();
    this.timer = setInterval(() => this._tick(), this.intervalMs);
    return this;
  }

  stop() {
    if (this.timer) { clearInterval(this.timer); this.timer = null; }
  }

  get isRunning() { return !!this.timer; }

  async _tick() {
    try {
      const t = Date.now();
      const to = (p, ms = 6000) => Promise.race([
        Promise.resolve().then(p),              // also catch synchronous throws
        new Promise((r) => setTimeout(() => r(null), ms)),
      ]).catch(() => null);
      const [load, mem, netStats, fsSize, disksIO, temps, batt] = await Promise.all([
        to(() => si.currentLoad()),
        to(() => si.mem()),
        to(() => si.networkStats()),
        to(() => si.fsSize(), 4000),
        to(() => si.disksIO()),
        to(() => si.cpuTemperature()),
        to(() => si.battery()),
      ]);
      if (Array.isArray(fsSize) === false) fsSize = [];

      const cpuAvg = load ? load.currentLoad : null;
      const perCpu = load && Array.isArray(load.cpus) ? load.cpus : [];

      const memPct = mem && mem.total ? Math.round(((mem.total - mem.available) / mem.total) * 1000) / 10 : null;
      const swapPct = mem && mem.swapTotal ? Math.round((mem.swapUsed / mem.swapTotal) * 1000) / 10 : null;

      let rx = 0, tx = 0;
      if (Array.isArray(netStats)) {
        for (const s of netStats) {
          if (!s) continue;
          if (this._defaultIfaces.length && !this._defaultIfaces.includes(s.iface)) continue;
          rx += s.rx_sec || 0;
          tx += s.tx_sec || 0;
        }
      }

      let diskMax = null;
      const disks = (Array.isArray(fsSize) ? fsSize : []).map((d) => {
        if (d && typeof d.use === 'number') diskMax = Math.max(diskMax || 0, d.use);
        return { mount: d ? d.mount : '?', usePct: d && typeof d.use === 'number' ? d.use : null };
      });

      const io = {
        read: disksIO && disksIO.rIO_sec ? disksIO.rIO_sec : null,
        write: disksIO && disksIO.wIO_sec ? disksIO.wIO_sec : null,
      };

      let tempMain = null, tempMax = null;
      if (temps) {
        const val = temps.main || (temps.cpu && temps.cpu.main) || null;
        tempMain = typeof val === 'number' && val > 0 ? val : null;
        if (temps.max && temps.max > 0) tempMax = temps.max;
      }

      const payload = {
        t,
        cpu: {
          load: cpuAvg == null ? null : Math.round(cpuAvg * 10) / 10,
          perCpu: perCpu.map((c) => Math.round(c.load * 10) / 10),
          avgLoad: load && load.avgLoad ? load.avgLoad : null,
        },
        mem: { usedPct: memPct, used: mem ? mem.active : null, total: mem ? mem.total : null, swapPct: swapPct },
        net: { rx: Math.round(rx), tx: Math.round(tx) },
        disk: { maxUse: diskMax == null ? null : Math.round(diskMax), disks, io },
        temp: { main: tempMain, max: tempMax },
        battery: batt ? { percent: batt.percent, charging: batt.isCharging } : null,
      };

      this.history.push(payload);
      if (this.history.length > this.maxHistory) this.history.shift();
      this.last = payload;
      this.emit('tick', payload);
    } catch { /* keep monitor alive across transient errors */ }
  }

  /** Full rolling history, used when a chart tab is (re)opened. */
  historySince(msAgo) {
    const cutoff = Date.now() - msAgo;
    return this.history.filter((p) => p.t >= cutoff);
  }
}

module.exports = new Monitor();
