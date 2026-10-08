import dns from 'node:dns/promises';
import net from 'node:net';

const PRIVATE_V4 = [
  /^10\./,
  /^127\./,
  /^169\.254\./,
  /^192\.168\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^0\./,
  /^224\./,
  /^240\./
];

function isPrivateIp(ip) {
  if (net.isIPv4(ip)) return PRIVATE_V4.some((rule) => rule.test(ip));
  if (net.isIPv6(ip)) {
    const value = ip.toLowerCase();
    return value === '::1' ||
      value === '::' ||
      value.startsWith('fc') ||
      value.startsWith('fd') ||
      value.startsWith('fe8') ||
      value.startsWith('fe9') ||
      value.startsWith('fea') ||
      value.startsWith('feb');
  }
  return true;
}

export async function assertPublicTarget(url) {
  const hostname = url.hostname.toLowerCase();

  if (hostname === 'localhost' || hostname.endsWith('.local')) {
    throw new Error('Private, local, and loopback targets are not allowed.');
  }

  if (net.isIP(hostname)) {
    if (isPrivateIp(hostname)) {
      throw new Error('Private, local, and loopback targets are not allowed.');
    }
    return;
  }

  const records = await dns.lookup(hostname, { all: true, verbatim: true });
  if (!records.length || records.some((record) => isPrivateIp(record.address))) {
    throw new Error('Target resolves to a private or unsupported network address.');
  }
}

function timeoutSignal(ms) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  return { controller, timer };
}

export async function safeFetch(input, options = {}, timeout = 9000) {
  let current = new URL(input);
  const originalHostname = current.hostname.toLowerCase();
  let sensitiveHeadersAllowed = true;

  for (let hop = 0; hop < 5; hop += 1) {
    await assertPublicTarget(current);
    const state = timeoutSignal(timeout);

    try {
      const headers = {
        'user-agent': 'InspectorQA/0.1 (+authorized non-destructive checks)',
        ...(options.headers || {})
      };

      if (!sensitiveHeadersAllowed || current.hostname.toLowerCase() !== originalHostname) {
        delete headers.authorization;
        delete headers.Authorization;
        delete headers.cookie;
        delete headers.Cookie;
        delete headers['proxy-authorization'];
        delete headers['Proxy-Authorization'];
      }

      const response = await fetch(current, {
        ...options,
        redirect: 'manual',
        headers,
        signal: state.controller.signal
      });

      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get('location');
        if (!location) return response;
        const next = new URL(location, current);
        if (next.hostname.toLowerCase() !== current.hostname.toLowerCase()) {
          sensitiveHeadersAllowed = false;
        }
        current = next;
        continue;
      }

      return response;
    } finally {
      clearTimeout(state.timer);
    }
  }

  throw new Error('Too many redirects.');
}
