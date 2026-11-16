// What the Search page's copy buttons put on the clipboard. Each takes the
// rows in the order the page shows them.

// prefixKey orders prefixes IPv4 first, by number, then IPv6.
function prefixKey(p) {
  const [addr, len = '0'] = p.split('/');
  const v4 = addr.split('.');
  if (v4.length === 4 && !addr.includes(':')) {
    return [0, v4.reduce((n, x) => n * 256 + Number(x), 0), Number(len)];
  }
  // IPv6: expand to 8 groups so text order is address order.
  const [head, tail = ''] = addr.toLowerCase().split('::');
  const h = head ? head.split(':') : [];
  const t = tail ? tail.split(':') : [];
  const groups = addr.includes('::') ? [...h, ...Array(8 - h.length - t.length).fill('0'), ...t] : h;
  return [1, groups.map((g) => g.padStart(4, '0')).join(':'), Number(len)];
}

function comparePrefixes(a, b) {
  const x = prefixKey(a);
  const y = prefixKey(b);
  for (let i = 0; i < 3; i++) {
    if (x[i] < y[i]) return -1;
    if (x[i] > y[i]) return 1;
  }
  return 0;
}

const announced = (b) => b.asn && b.asn !== 'N/A';

// asnList is the ASNs whose names matched, once each. The ASNs announcing
// the matching netblocks are left out: they are often a data centre or a
// cloud (Equinix, Amazon), not the organisation searched for.
export function asnList(asns) {
  const out = [];
  const seen = new Set();
  for (const a of asns) {
    const k = String(a.asn).toUpperCase();
    if (!seen.has(k)) {
      seen.add(k);
      out.push(k.startsWith('AS') ? k : `AS${k}`);
    }
  }
  return out;
}

// prefixList is every prefix on the page, once each, sorted: the matching
// ASNs' announced prefixes and the matching netblocks' CIDRs.
export function prefixList(asns, blocks) {
  const set = new Set();
  for (const a of asns) {
    for (const p of [...(a.ipv4_prefixes || []), ...(a.ipv6_prefixes || [])]) set.add(p);
  }
  for (const b of blocks) for (const c of b.cidrs || []) set.add(c);
  return [...set].sort(comparePrefixes);
}

const blockRange = (b) => (b.cidrs?.length ? b.cidrs : [`${b.range_start} - ${b.range_end}`]);
const asnRep = (a) => {
  const r = a.reputation;
  if (!r) return '';
  return r.summary || '';
};
const announcedBy = (b) => (announced(b) ? `${b.asn} ${b.as_name || ''}`.trim() : 'Not announced');

// columns describe each table: heading, and the cell for a row (a netblock's
// range cell may be several lines).
function asnColumns(fuzzy) {
  return [
    ...(fuzzy ? [['Match', (a) => a.match || '']] : []),
    ['ASN', (a) => a.asn],
    ['Name', (a) => a.name],
    ['Country', (a) => a.country || ''],
    ['Prefixes', (a) => String((a.ipv4_prefixes?.length || 0) + (a.ipv6_prefixes?.length || 0))],
    ['Reputation', asnRep],
  ];
}

function blockColumns(fuzzy) {
  return [
    ...(fuzzy ? [['Match', (b) => b.match || '']] : []),
    ['Range', blockRange],
    ['Network', (b) => b.netname || ''],
    ['Organisation', (b) => b.org || ''],
    ['Announced by', announcedBy],
    ['Country', (b) => b.country || ''],
  ];
}

// textTable lays rows out in aligned columns; a cell with several lines
// (a range of several CIDRs) continues on the lines below.
function textTable(cols, rows) {
  const cells = rows.map((r) => cols.map(([, get]) => [].concat(get(r) ?? '').map(String)));
  const widths = cols.map(([h], i) => Math.max(h.length, ...cells.map((c) => Math.max(...c[i].map((l) => l.length)))));
  const line = (vals) =>
    vals
      .map((v, i) => (i === vals.length - 1 ? v : v.padEnd(widths[i])))
      .join('  ')
      .trimEnd();
  const out = [line(cols.map(([h]) => h))];
  for (const c of cells) {
    const height = Math.max(...c.map((x) => x.length));
    for (let k = 0; k < height; k++) out.push(line(c.map((x) => x[k] || '')));
  }
  return out.join('\n');
}

// tableText is both tables as the page shows them, as aligned plain text.
export function tableText({ query, country, asns, blocks, fuzzy, showASNs, showBlocks, asnCount, blockCount }) {
  const parts = [`Search: ${query}${country ? ` (${country})` : ''}`];
  if (showASNs) {
    parts.push(`AS names (${asnCount ?? asns.length})`);
    parts.push(asns.length ? textTable(asnColumns(fuzzy), asns) : 'None.');
  }
  if (showBlocks) {
    parts.push(`Netblocks (${blockCount ?? blocks.length})`);
    parts.push(blocks.length ? textTable(blockColumns(fuzzy), blocks) : 'None.');
  }
  return parts.join('\n\n') + '\n';
}

const csvCell = (v) => {
  const s = String(v ?? '');
  return /[",\n\r]/.test(s) || /^[=+\-@\t]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};

// csvText is one sheet holding both tables, a row per ASN or netblock.
export function csvText({ asns, blocks, fuzzy }) {
  const head = ['type', ...(fuzzy ? ['match'] : []), 'asn', 'as_name', 'range', 'network', 'organisation', 'country', 'prefixes', 'reputation'];
  const rows = [head];
  for (const a of asns) {
    rows.push(['asn', ...(fuzzy ? [a.match || ''] : []), a.asn, a.name, '', '', '', a.country || '', asnColumns(false)[3][1](a), asnRep(a)]);
  }
  for (const b of blocks) {
    rows.push([
      'netblock',
      ...(fuzzy ? [b.match || ''] : []),
      announced(b) ? b.asn : '',
      announced(b) ? b.as_name || '' : '',
      blockRange(b).join(' '),
      b.netname || '',
      b.org || '',
      b.country || '',
      '',
      '',
    ]);
  }
  return rows.map((r) => r.map(csvCell).join(',')).join('\r\n') + '\r\n';
}
