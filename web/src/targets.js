// Pulls lookup targets out of whatever is pasted into the Targets box: a
// clean list, a bulleted list, a log line, an alert, a web page. Clean input
// is taken as typed; anything else is searched for IP addresses, URLs, AS
// numbers and domains, defanged indicators ("hxxp", "[.]") included.

import { TLDS } from './tlds.js';

// File extensions that are also top-level domains: "README.md" or
// "setup.py" in prose is a file, not a host. A URL naming such a host is
// still taken.
const FILE_LIKE_TLDS = new Set(['md', 'sh', 'py', 'pl', 'rs', 'zip', 'mov', 'so', 'ps', 'ai', 'cc', 'java', 'scot']);

const OCTET = '(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)';
const IPV4 = new RegExp(`(?<![\\d.])${OCTET}(?:\\.${OCTET}){3}(?!\\d|\\.\\d)`, 'g');
const IPV6_CANDIDATE = /(?<![\w:.])(?:[0-9a-f]{0,4}:){2,7}(?:[0-9a-f]{0,4}|(?:\d{1,3}\.){3}\d{1,3})(?![\w:])/gi;
const URL_RE = /\b(?:https?|ftp):\/\/[^\s<>"'`)\]}|\\^]+/gi;
const ASN_RE = /\bASN?[ -]?(\d{1,10})\b/g;
const DOMAIN_RE = /(?<![\w@.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}(?![\w-]|\.[a-z0-9])/gi;
// What a single clean entry may look like: an address, a URL, an ASN or
// bare number, or a host name (any name: internal ones are allowed here).
const CLEAN_ENTRY = /^(?:[a-z][a-z0-9+.-]*:\/\/\S+|\[?[0-9a-f:.]+\]?(?::\d+)?|AS\d+|\d+|[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?)*\.?(?::\d+)?)$/i;

// refang undoes the usual ways of defanging an indicator.
export function refang(text) {
  return text
    .replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)/gi, '.')
    .replace(/\[:\]/g, ':')
    .replace(/\[:\/\/\]/g, '://')
    .replace(/\bhxxp(s?):\/\//gi, 'http$1://')
    .replace(/\bfxp:\/\//gi, 'ftp://');
}

function isIPv6(s) {
  if (!s.includes(':') || !/[0-9a-f]/i.test(s) || /^:+$/.test(s)) return false;
  try {
    new URL(`http://[${s}]/`);
    return true;
  } catch {
    return false;
  }
}

function isDomain(host) {
  const labels = host.toLowerCase().replace(/\.$/, '').split('.');
  if (labels.length < 2) return false;
  const tld = labels[labels.length - 1];
  return TLDS.has(tld);
}

function urlHost(u) {
  try {
    const h = new URL(u).hostname.replace(/^\[|\]$/g, '');
    return h || null;
  } catch {
    return null;
  }
}

// cleanList returns the entries of text when every line (or comma-separated
// piece) is one target on its own, after bullets and quotes; otherwise null.
function cleanList(text) {
  const pieces = text
    .split(/[\n,;]+/)
    .map((s) => s.trim().replace(/^(?:[-*•>+]\s*|\d+[.)]\s+)/, '').replace(/^["'`([]+|["'`)\]]+$/g, '').trim())
    .filter(Boolean);
  if (!pieces.length) return [];
  return pieces.every((p) => CLEAN_ENTRY.test(p)) ? pieces : null;
}

// extractTargets returns the targets in text, in the order they appear,
// each once, and whether they had to be searched for (the text was not a
// clean list).
export function extractTargets(text) {
  text = refang(text || '');
  const clean = cleanList(text);
  if (clean) return { targets: dedupe(clean), extracted: false };

  const found = []; // [index, target]
  let rest = text.replace(URL_RE, (m, idx) => {
    const host = urlHost(m.replace(/[.,;:!?]+$/, ''));
    if (host) found.push([idx, host]);
    return ' '.repeat(m.length);
  });
  rest = rest.replace(IPV4, (m, idx) => {
    found.push([idx, m]);
    return ' '.repeat(m.length);
  });
  rest = rest.replace(IPV6_CANDIDATE, (m, idx) => {
    if (isIPv6(m)) {
      found.push([idx, m]);
      return ' '.repeat(m.length);
    }
    return m;
  });
  for (const m of rest.matchAll(ASN_RE)) {
    const n = Number(m[1]);
    if (n > 0 && n <= 4294967295) found.push([m.index, `AS${n}`]);
  }
  for (const m of rest.matchAll(DOMAIN_RE)) {
    const host = m[0].replace(/\.$/, '');
    const labels = host.toLowerCase().split('.');
    if (!isDomain(host)) continue;
    if (labels.length === 2 && FILE_LIKE_TLDS.has(labels[1])) continue;
    found.push([m.index, host]);
  }
  found.sort((a, b) => a[0] - b[0]);
  return { targets: dedupe(found.map((f) => f[1])), extracted: true };
}

function dedupe(list) {
  const seen = new Set();
  const out = [];
  for (const t of list) {
    const k = t.toLowerCase();
    if (!seen.has(k)) {
      seen.add(k);
      out.push(t);
    }
  }
  return out;
}

