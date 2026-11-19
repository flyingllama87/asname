// Facts about an address block written as a CIDR prefix (27.32.75.64/27,
// 2001:db8::/32) or a start-end range (192.0.2.10 – 192.0.2.20), for the
// tooltip on a block and the address its link looks up.

const V4_BITS = 32n;
const V6_BITS = 128n;

function parseV4(s) {
  const parts = s.split('.');
  if (parts.length !== 4) return null;
  let n = 0n;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p) || Number(p) > 255) return null;
    n = (n << 8n) | BigInt(p);
  }
  return n;
}

function parseV6(s) {
  if (!s.includes(':')) return null;
  let head = s;
  let tail = '';
  const dbl = s.indexOf('::');
  if (dbl >= 0) {
    head = s.slice(0, dbl);
    tail = s.slice(dbl + 2);
    if (tail.includes('::')) return null;
  }
  const groups = (x) => (x === '' ? [] : x.split(':'));
  let h = groups(head);
  let t = groups(tail);
  // An IPv4 tail (::ffff:192.0.2.1) is two groups.
  const last = t.length ? t : h;
  if (last.length && last[last.length - 1].includes('.')) {
    const v4 = parseV4(last[last.length - 1]);
    if (v4 === null) return null;
    last.splice(last.length - 1, 1, (v4 >> 16n).toString(16), (v4 & 0xffffn).toString(16));
  }
  const missing = 8 - h.length - t.length;
  if (dbl < 0 ? missing !== 0 : missing < 1) return null;
  const all = [...h, ...Array(dbl < 0 ? 0 : missing).fill('0'), ...t];
  let n = 0n;
  for (const g of all) {
    if (!/^[0-9a-f]{1,4}$/i.test(g)) return null;
    n = (n << 16n) | BigInt(parseInt(g, 16));
  }
  return n;
}

function parseAddr(s) {
  const v4 = parseV4(s);
  if (v4 !== null) return { n: v4, bits: V4_BITS };
  const v6 = parseV6(s);
  if (v6 !== null) return { n: v6, bits: V6_BITS };
  return null;
}

function formatV4(n) {
  return [24n, 16n, 8n, 0n].map((sh) => ((n >> sh) & 0xffn).toString()).join('.');
}

// formatV6 writes the shortest form: the longest run of two or more zero
// groups becomes "::".
function formatV6(n) {
  const g = [];
  for (let sh = 112n; sh >= 0n; sh -= 16n) g.push(Number((n >> sh) & 0xffffn));
  let best = -1;
  let bestLen = 1;
  for (let i = 0; i < 8; ) {
    if (g[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && g[j] === 0) j++;
    if (j - i > bestLen) [best, bestLen] = [i, j - i];
    i = j;
  }
  const hex = g.map((x) => x.toString(16));
  if (best < 0) return hex.join(':');
  return `${hex.slice(0, best).join(':')}::${hex.slice(best + bestLen).join(':')}`;
}

const fmt = (n, bits) => (bits === V4_BITS ? formatV4(n) : formatV6(n));

// count writes a number of addresses in full, or as a power of two when it
// would be too long to read.
function count(n) {
  if (n < 10n ** 15n) return Number(n).toLocaleString('en-AU');
  return `2^${n.toString(2).length - 1}`;
}

// parseBlock reads "a.b.c.d/len", "v6/len" or "start – end" (any dash).
export function parseBlock(text) {
  const s = String(text || '').trim();
  const range = s.split(/\s*[–—-]\s*/);
  if (range.length === 2 && !s.includes('/')) {
    const a = parseAddr(range[0]);
    const b = parseAddr(range[1]);
    if (!a || !b || a.bits !== b.bits || b.n < a.n) return null;
    return { bits: a.bits, first: a.n, last: b.n };
  }
  const [addr, lenText] = s.split('/');
  const a = parseAddr(addr);
  if (!a) return null;
  const len = lenText === undefined ? a.bits : BigInt(lenText);
  if (lenText !== undefined && (!/^\d{1,3}$/.test(lenText) || len > a.bits)) return null;
  const hostBits = a.bits - len;
  const size = 1n << hostBits;
  const first = (a.n >> hostBits) << hostBits;
  return { bits: a.bits, len, first, last: first + size - 1n, given: a.n };
}

// firstUsable is the address a click on the block looks up: for a prefix
// with room for it (IPv4 up to /30, IPv6 up to /126), the one after the
// network address; for a point-to-point prefix or a range, the first.
export function firstUsable(text) {
  const b = parseBlock(text);
  if (!b) return '';
  const skipNetwork = b.len !== undefined && b.bits - b.len >= 2n;
  return fmt(skipNetwork ? b.first + 1n : b.first, b.bits);
}

// blockFacts is the tooltip for a block: its size and boundaries, and for
// IPv4 its broadcast address and masks.
export function blockFacts(text) {
  const b = parseBlock(text);
  if (!b) return '';
  const v4 = b.bits === V4_BITS;
  const size = b.last - b.first + 1n;
  const lines = [];
  if (b.len === undefined) {
    lines.push(`${count(size)} address${size === 1n ? '' : 'es'} (a registry range, not one prefix)`);
    lines.push(`First: ${fmt(b.first, b.bits)}`, `Last: ${fmt(b.last, b.bits)}`);
    return lines.join('\n');
  }
  const hostBits = b.bits - b.len;
  if (v4) {
    const usable = hostBits >= 2n ? size - 2n : size;
    lines.push(`${count(size)} address${size === 1n ? '' : 'es'}${hostBits >= 2n ? `, ${count(usable)} usable hosts` : ''}`);
    if (hostBits === 0n) lines.push('A single address');
    else if (hostBits === 1n) lines.push('A point-to-point link (RFC 3021): both addresses usable');
    else {
      lines.push(`Network: ${fmt(b.first, b.bits)}`, `Broadcast: ${fmt(b.last, b.bits)}`);
      lines.push(`Usable: ${fmt(b.first + 1n, b.bits)} – ${fmt(b.last - 1n, b.bits)}`);
    }
    const mask = ((1n << V4_BITS) - 1n) ^ ((1n << hostBits) - 1n);
    lines.push(`Netmask: ${formatV4(mask)}`, `Wildcard (ACL) mask: ${formatV4(mask ^ 0xffffffffn)}`);
    if (b.len < 24n) lines.push(`${count(1n << (24n - b.len))} /24 networks`);
  } else {
    lines.push(`${count(size)} address${size === 1n ? '' : 'es'}`);
    lines.push(`First: ${fmt(b.first, b.bits)}`, `Last: ${fmt(b.last, b.bits)}`);
    if (b.len < 64n) lines.push(`${count(1n << (64n - b.len))} /64 subnets (one per LAN or customer)`);
    else if (b.len === 64n) lines.push('One /64: a single LAN or customer');
    else if (b.len === 127n) lines.push('A point-to-point link (RFC 6164)');
  }
  if (b.given !== b.first) lines.push(`Not aligned: ${fmt(b.given, b.bits)}/${b.len} is inside ${fmt(b.first, b.bits)}/${b.len}`);
  return lines.join('\n');
}
