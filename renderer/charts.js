'use strict';

const Charts = (() => {
  const cssVar = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  const clamp = (v, a, b) => Math.max(a, Math.min(b, v));

  function setupCanvas(canvas) {
    const dpr = Math.min(2, window.devicePixelRatio || 1);
    const rect = canvas.getBoundingClientRect();
    const w = Math.max(10, Math.round(rect.width * dpr));
    const h = Math.max(10, Math.round(rect.height * dpr));
    if (canvas.width !== w || canvas.height !== h) { canvas.width = w; canvas.height = h; }
    const ctx = canvas.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    return { ctx, w: w / dpr, h: h / dpr };
  }

  function hexToRgb(hex) {
    const m = hex.replace('#', '');
    if (m.length === 3) return { r: parseInt(m[0] + m[0], 16), g: parseInt(m[1] + m[1], 16), b: parseInt(m[2] + m[2], 16) };
    if (m.length === 6) return { r: parseInt(m.slice(0, 2), 16), g: parseInt(m.slice(2, 4), 16), b: parseInt(m.slice(4, 6), 16) };
    return null;
  }
  const rgba = (hex, a) => {
    const c = hexToRgb(hex);
    return c ? `rgba(${c.r},${c.g},${c.b},${a})` : hex;
  };

  function niceCeil(v) {
    if (v <= 0) return 1;
    const p = Math.pow(10, Math.floor(Math.log10(v)));
    const n = v / p;
    return (n <= 1 ? p : n <= 2 ? 2 * p : n <= 5 ? 5 * p : 10 * p);
  }

  class LineChart {
    /**
     * @param {HTMLCanvasElement} canvas
     * @param {object} opts { maxPoints, series:[{color, fill}], yFormat, yMax }
     */
    constructor(canvas, opts = {}) {
      this.cv = canvas;
      this.maxPoints = opts.maxPoints || 240;
      this.yFormat = opts.yFormat || ((v) => String(Math.round(v * 10) / 10));
      this.yMax = opts.yMax || null;
      this.series = (opts.series || []).map((s) => ({ color: s.color, fill: s.fill !== false, data: [] }));
      this._lastVal = new Map();
      this.draw();
    }

    push(si, v) {
      if (v == null || isNaN(v)) this.series[si].data.push(null);
      else this.series[si].data.push(v);
      if (this.series[si].data.length > this.maxPoints) this.series[si].data.shift();
      if (v != null) this._lastVal.set(si, v);
    }

    pushAll(values) { values.forEach((v, i) => this.push(i, v)); }

    setData(si, arr) {
      this.series[si].data = (arr || []).slice(-this.maxPoints);
      const last = this.series[si].data.filter((v) => v != null).pop();
      if (last != null) this._lastVal.set(si, last);
    }

    clear() { this.series.forEach((s) => { s.data = []; }); this._lastVal.clear(); this.draw(); }

    lastVal(si) { return this._lastVal.get(si); }

    _maxValue() {
      if (this.yMax != null) return this.yMax;
      let max = 0;
      for (const s of this.series) for (const v of s.data) if (v != null && v > max) max = v;
      return niceCeil(max || 1);
    }

    draw() {
      const { ctx, w, h } = setupCanvas(this.cv);
      ctx.clearRect(0, 0, w, h);
      const padL = 34, padR = 8, padT = 8, padB = 14;
      const pw = w - padL - padR, ph = h - padT - padB;
      if (pw <= 0 || ph <= 0) return;
      const max = this._maxValue();

      // grid + y labels
      ctx.font = '9.5px "JetBrains Mono", monospace';
      ctx.textBaseline = 'middle';
      const ticks = 4;
      for (let i = 0; i <= ticks; i++) {
        const val = (max / ticks) * i;
        const y = padT + ph - (ph / ticks) * i;
        ctx.strokeStyle = cssVar('--border');
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(padL, Math.round(y) + 0.5);
        ctx.lineTo(w - padR, Math.round(y) + 0.5);
        ctx.stroke();
        ctx.fillStyle = cssVar('--text-3');
        ctx.textAlign = 'right';
        ctx.fillText(this.yFormat(val), padL - 7, y);
      }

      // series
      const step = this.maxPoints > 1 ? pw / (this.maxPoints - 1) : pw;
      this.series.forEach((s, si) => {
        const data = s.data;
        const count = data.length;
        if (!count) return;
        // build point list (only non-null)
        const pts = [];
        for (let i = 0; i < count; i++) {
          const v = data[i];
          if (v == null) continue;
          const x = padL + pw - (count - 1 - i) * step;
          const y = padT + ph - clamp(v / max, 0, 1) * ph;
          pts.push([x, y]);
        }
        if (pts.length < 2) return;

        // area
        if (s.fill) {
          const grad = ctx.createLinearGradient(0, padT, 0, padT + ph);
          grad.addColorStop(0, rgba(s.color, 0.16));
          grad.addColorStop(1, rgba(s.color, 0));
          ctx.beginPath();
          ctx.moveTo(pts[0][0], padT + ph);
          pts.forEach(([x, y]) => ctx.lineTo(x, y));
          ctx.lineTo(pts[pts.length - 1][0], padT + ph);
          ctx.closePath();
          ctx.fillStyle = grad;
          ctx.fill();
        }
        // line
        ctx.beginPath();
        pts.forEach(([x, y], i) => { if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y); });
        ctx.strokeStyle = s.color;
        ctx.lineWidth = 1.6;
        ctx.lineJoin = 'round';
        ctx.lineCap = 'round';
        ctx.stroke();

        // end dot
        const [lx, ly] = pts[pts.length - 1];
        ctx.beginPath();
        ctx.arc(lx, ly, 2.6, 0, Math.PI * 2);
        ctx.fillStyle = s.color;
        ctx.fill();
        ctx.beginPath();
        ctx.arc(lx, ly, 5.5, 0, Math.PI * 2);
        ctx.strokeStyle = rgba(s.color, 0.25);
        ctx.lineWidth = 1.5;
        ctx.stroke();
      });
    }
  }

  class Sparkline {
    constructor(canvas, color) {
      this.cv = canvas;
      this.color = color || cssVar('--accent');
      this.data = [];
      this.maxPoints = 90;
      this._max = 100;
    }

    setData(arr) { this.data = (arr || []).slice(-this.maxPoints); this.draw(); }
    push(v) { this.data.push(v); if (this.data.length > this.maxPoints) this.data.shift(); this.draw(); }
    clear() { this.data = []; this.draw(); }

    draw() {
      const { ctx, w, h } = setupCanvas(this.cv);
      ctx.clearRect(0, 0, w, h);
      if (this.data.length < 2) return;
      const max = this._max > 0 ? this._max : Math.max(...this.data, 1);
      const n = this.data.length;
      const x0 = 1, x1 = w - 1, y0 = h - 2, y1 = 2;

      // area
      const grad = ctx.createLinearGradient(0, y1, 0, y0);
      grad.addColorStop(0, rgba(this.color, 0.22));
      grad.addColorStop(1, rgba(this.color, 0.02));
      ctx.beginPath();
      ctx.moveTo(x0, y0);
      this.data.forEach((v, i) => {
        const x = x0 + (x1 - x0) * (i / (n - 1));
        const y = y0 - (y0 - y1) * clamp(v / max, 0, 1);
        ctx.lineTo(x, y);
      });
      ctx.lineTo(x1, y0);
      ctx.closePath();
      ctx.fillStyle = grad;
      ctx.fill();

      // line
      ctx.beginPath();
      this.data.forEach((v, i) => {
        const x = x0 + (x1 - x0) * (i / (n - 1));
        const y = y0 - (y0 - y1) * clamp(v / max, 0, 1);
        if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
      });
      ctx.strokeStyle = this.color;
      ctx.lineWidth = 1.4;
      ctx.lineJoin = 'round';
      ctx.stroke();
    }
  }

  class Gauge {
    /**
     * @param {HTMLCanvasElement} canvas
     * @param {object} opts { bands: [{upTo, color}], label }
     */
    constructor(canvas, opts = {}) {
      this.cv = canvas;
      this.value = 0;   // 0..1
      this.text = '—';
      this.label = opts.label || '';
      this.bands = opts.bands || [{ upTo: 1, color: cssVar('--accent') }];
      this._color = null;
      this.draw();
    }

    set(value, text) {
      this.value = clamp(value == null ? 0 : value, 0, 1);
      this.text = text != null ? String(text) : `${Math.round(this.value * 100)}`;
      this.draw();
    }

    _colorFor(frac) {
      if (this._color) return this._color;
      for (const b of this.bands) if (frac <= b.upTo) return b.color;
      return this.bands[this.bands.length - 1].color;
    }

    draw() {
      const { ctx, w, h } = setupCanvas(this.cv);
      ctx.clearRect(0, 0, w, h);
      if (w < 24 || h < 24) return; // hidden or zero-size canvas
      const cx = w / 2, cy = h / 2;
      const r = Math.max(8, Math.min(w, h) / 2 - 13);
      const start = 0.75 * Math.PI;
      const sweep = 1.5 * Math.PI;
      const frac = clamp(this.value, 0, 1);

      ctx.lineCap = 'round';

      // track
      ctx.strokeStyle = cssVar('--surface-3');
      ctx.lineWidth = 11;
      ctx.beginPath();
      ctx.arc(cx, cy, r, start, start + sweep);
      ctx.stroke();

      // ticks at 0 / 25 / 50 / 75 / 100
      ctx.strokeStyle = cssVar('--border-2');
      ctx.lineWidth = 1.5;
      for (let i = 0; i <= 4; i++) {
        const a = start + sweep * (i / 4);
        ctx.beginPath();
        ctx.moveTo(cx + Math.cos(a) * (r - 9), cy + Math.sin(a) * (r - 9));
        ctx.lineTo(cx + Math.cos(a) * (r - 3.5), cy + Math.sin(a) * (r - 3.5));
        ctx.stroke();
      }

      // value arc
      const color = this._colorFor(frac);
      if (frac > 0.005) {
        const grad = ctx.createLinearGradient(cx - r, cy - r, cx + r, cy + r);
        grad.addColorStop(0, color);
        grad.addColorStop(1, rgba(color, 0.72));
        ctx.strokeStyle = grad;
        ctx.lineWidth = 11;
        ctx.beginPath();
        ctx.arc(cx, cy, r, start, start + sweep * frac);
        ctx.stroke();
      }

      // text
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillStyle = cssVar('--text-1');
      ctx.font = '700 30px "JetBrains Mono", monospace';
      ctx.fillText(this.text, cx, cy - 2);
      if (this.label) {
        ctx.fillStyle = cssVar('--text-3');
        ctx.font = '600 9.5px Inter, sans-serif';
        ctx.fillText(this.label.toUpperCase(), cx, cy + 20);
      }
    }
  }

  /* resize handling */
  const registry = [];
  let timer = null;
  window.addEventListener('resize', () => {
    if (timer) return;
    timer = setTimeout(() => { timer = null; registry.forEach((c) => c.draw()); }, 120);
  });

  return { LineChart, Sparkline, Gauge, register: (c) => registry.push(c), setupCanvas };
})();
