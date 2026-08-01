'use strict';

const net = require('net');

const IPIFY = 'https://api.ipify.org';
// ip-api free tier is HTTP-only (HTTPS requires a paid plan). It only returns
// non-sensitive geo data (country/ISP); no IP is sent beyond the lookup itself.
const IPAPI = 'http://ip-api.com/json/';

const PRIVATE_RANGES = [
  ['10.', '0.0.0.0/8'],
  ['192.168.', '192.168.0.0/16'],
  ['172.', '172.16.0.0/12'],
  ['100.', '100.64.0.0/10'],
];

// Providers/orgs commonly associated with VPN, hosting or anonymity services
const VPNISH_KEYWORDS = ['vpn', 'tor', 'anon', 'proxy', 'hosting', 'datacenter', 'cloud',
  'ovh', 'digitalocean', 'linode', 'hetzner', 'scaleway', 'vultr', 'akamai', 'leaseweb'];

function isPrivateIp(ip) {
  if (!ip) return false;
  if (ip.startsWith('127.') || ip === '::1') return true;
  if (ip.startsWith('10.') || ip.startsWith('192.168.')) return true;
  if (ip.startsWith('172.')) {
    const parts = ip.split('.');
    const second = parseInt(parts[1], 10);
    if (!isNaN(second) && second >= 16 && second <= 31) return true;
  }
  return ip.startsWith('100.') || ip.startsWith('169.254.');
}

async function fetchText(url, timeoutMs = 10000) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: ctrl.signal });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return (await res.text()).trim();
  } finally {
    clearTimeout(timer);
  }
}

/** Public (WAN) IP address. */
async function getPublicIp() {
  try {
    const ip = await fetchText(IPIFY);
    if (!ip || !/^[\d.]+$/.test(ip)) throw new Error('bad ip');
    return { ok: true, ip };
  } catch {
    return { ok: false, ip: null, error: 'Could not reach public IP service (offline or blocked)' };
  }
}

/** Lightweight geolocation / ISP info for an IP. */
async function getGeo(ip) {
  try {
    const raw = await fetchText(`${IPAPI}${encodeURIComponent(ip)}`, 8000);
    const j = JSON.parse(raw);
    if (j.status !== 'success') return { ok: false, error: j.message || 'geo failed' };
    return {
      ok: true,
      country: j.country, countryCode: j.countryCode, region: j.regionName,
      city: j.city, isp: j.isp, org: j.org, as: j.as, lat: j.lat, lon: j.lon,
      proxy: !!j.proxy, hosting: !!j.hosting, mobile: !!j.mobile,
    };
  } catch {
    return { ok: false, error: 'Geolocation lookup failed' };
  }
}

/** Whether the public IP looks like a VPN / datacenter / anonymity endpoint. */
function classifyVpn(geo) {
  if (!geo || !geo.ok) return { vpnish: false, reason: null };
  const haystack = `${geo.org || ''} ${geo.isp || ''} ${geo.as || ''}`.toLowerCase();
  const hits = VPNISH_KEYWORDS.filter((k) => haystack.includes(k));
  return {
    vpnish: hits.length > 0 || geo.proxy || geo.hosting,
    reason: hits.length ? `org/ISP keywords: ${hits.join(', ')}` : (geo.proxy ? 'proxy flag' : 'hosting flag'),
  };
}

/** Can we reach a public DNS resolver on 53/UDP? (basic connectivity check) */
function checkDnsReachability(host = '8.8.8.8', port = 53) {
  return new Promise((resolve) => {
    const sock = net.createConnection({ host, port });
    const timer = setTimeout(() => { sock.destroy(); resolve(false); }, 5000);
    sock.once('connect', () => { clearTimeout(timer); sock.destroy(); resolve(true); });
    sock.once('error', () => { clearTimeout(timer); sock.destroy(); resolve(false); });
  });
}

/** Detect whether this machine is behind NAT (typical home/router setup). */
function natStatus(localIps, publicIp) {
  if (!publicIp) return { behindNAT: null, note: 'Public IP unknown' };
  if (isPrivateIp(publicIp)) return { behindNAT: true, note: 'Public IP is a private address — direct inbound exposure is unlikely' };
  const hasLocalPrivate = (localIps || []).some((ip) => isPrivateIp(ip));
  const direct = (localIps || []).includes(publicIp);
  if (direct) return { behindNAT: false, note: 'Public IP matches a local interface — this machine appears directly exposed to the internet' };
  if (hasLocalPrivate) return { behindNAT: true, note: 'Public IP differs from local (private) addresses — traffic is likely NATed; inbound port forwarding required to reach this host' };
  return { behindNAT: null, note: 'Could not determine NAT status' };
}

module.exports = {
  getPublicIp, getGeo, classifyVpn, checkDnsReachability, natStatus, isPrivateIp, PRIVATE_RANGES,
};
