// The Explore tab's filters as URL parameters, and what its copy buttons
// copy.

// FILTER_KEYS are the explore filters, as /v1/explore and the page's URL
// name them.
export const FILTER_KEYS = ['len', 'family', 'country', 'as_country', 'asn', 'tag', 'reputation', 'min_ipsum', 'min_listed_pct', 'sort', 'limit', 'offset'];

export const DEFAULT_FILTERS = {
  len: '',
  family: 'any',
  country: '',
  as_country: '',
  asn: '',
  tag: [],
  reputation: '',
  min_ipsum: '',
  min_listed_pct: '',
  sort: 'address',
  limit: 500,
  offset: 0,
};

// REPUTATIONS are the reputation filter's choices.
export const REPUTATIONS = [
  ['', 'Any'],
  ['listed', 'Listed anywhere'],
  ['clean', 'Not listed'],
  ['drop', 'Spamhaus DROP (all of it)'],
  ['drop-inside', 'Spamhaus DROP (any of it)'],
  ['asn-drop', 'Origin AS on ASN-DROP'],
  ['firehol2', 'FireHOL L2: attacks, 48 h'],
  ['firehol3', 'FireHOL L3: attacks, 30 d'],
];

export const SORTS = [
  ['address', 'Address'],
  ['size', 'Largest first'],
  ['listed', 'Most listed addresses'],
  ['share', 'Highest listed share'],
];

// toParams turns filters into query parameters, leaving out defaults.
export function toParams(f) {
  const p = new URLSearchParams();
  for (const k of FILTER_KEYS) {
    const v = f[k];
    if (k === 'tag') {
      if (v.length) p.set('tag', v.join(','));
    } else if (v !== '' && v != null && String(v) !== String(DEFAULT_FILTERS[k])) {
      p.set(k, String(v));
    }
  }
  return p;
}

export function fromParams(p) {
  const f = { ...DEFAULT_FILTERS, tag: [] };
  for (const k of FILTER_KEYS) {
    const v = p.get(k);
    if (v == null) continue;
    if (k === 'tag') f.tag = v.split(',').filter(Boolean);
    else if (k === 'limit' || k === 'offset') f[k] = Math.max(0, parseInt(v, 10) || DEFAULT_FILTERS[k]);
    else f[k] = v;
  }
  return f;
}

// repText is a prefix's reputation in words, as the table shows it.
export function repText(r) {
  const rep = r.reputation || {};
  const parts = [];
  if (rep.spamhaus_drop) parts.push(`Spamhaus DROP${rep.sbl?.length ? ` ${rep.sbl.join(' ')}` : ''}`);
  else if (rep.spamhaus_drop_inside) parts.push(`contains Spamhaus DROP${rep.sbl?.length ? ` ${rep.sbl.join(' ')}` : ''}`);
  if (rep.spamhaus_asn_drop) parts.push('origin AS on ASN-DROP');
  if (rep.firehol_level2) parts.push('FireHOL L2');
  else if (rep.firehol_level3) parts.push('FireHOL L3');
  if (rep.listed_ips) {
    const share = r.addresses ? ` (${fmtPct(rep.listed_share_pct)})` : '';
    parts.push(`${rep.listed_ips.toLocaleString()} listed${share}${rep.max_ipsum ? `, IPsum max ${rep.max_ipsum}` : ''}`);
  }
  return parts.join('; ');
}

export function fmtPct(p) {
  if (p >= 10) return `${p.toFixed(0)}%`;
  if (p >= 0.1) return `${p.toFixed(2)}%`;
  if (p > 0) return '<0.1%';
  return '0%';
}

export function fmtCount(n) {
  if (n >= 1e9) return `${(n / 1e9).toFixed(2)} billion`;
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)} million`;
  return n.toLocaleString();
}

const csvCell = (v) => {
  const s = String(v ?? '');
  return /[",\n\r]/.test(s) || /^[=+\-@\t]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};

export function exploreCSV(rows) {
  const head = ['prefix', 'addresses', 'asn', 'as_name', 'country', 'as_country', 'tags', 'spamhaus_drop', 'contains_drop', 'sbl', 'asn_drop', 'firehol_level2', 'firehol_level3', 'listed_ips', 'listed_share_pct', 'max_ipsum'];
  const out = [head];
  for (const r of rows) {
    const rep = r.reputation || {};
    out.push([
      r.prefix,
      r.addresses || '',
      r.asn,
      r.as_name,
      r.country,
      r.as_country,
      (r.tags || []).join(' '),
      rep.spamhaus_drop ? 'yes' : '',
      rep.spamhaus_drop_inside ? 'yes' : '',
      (rep.sbl || []).join(' '),
      rep.spamhaus_asn_drop ? 'yes' : '',
      rep.firehol_level2 ? 'yes' : '',
      rep.firehol_level3 ? 'yes' : '',
      rep.listed_ips || 0,
      rep.listed_share_pct ? rep.listed_share_pct.toFixed(4) : 0,
      rep.max_ipsum || 0,
    ]);
  }
  return out.map((r) => r.map(csvCell).join(',')).join('\r\n') + '\r\n';
}

// exploreTable is the rows as aligned text.
export function exploreTable(rows, title) {
  const cols = [
    ['Prefix', (r) => r.prefix],
    ['AS', (r) => `${r.asn} ${r.as_name || ''}`.trim()],
    ['Country', (r) => r.country || ''],
    ['Tags', (r) => (r.tags || []).join(', ')],
    ['Reputation', repText],
  ];
  const cells = rows.map((r) => cols.map(([, get]) => String(get(r) ?? '')));
  const widths = cols.map(([h], i) => Math.max(h.length, ...cells.map((c) => c[i].length)));
  const line = (vals) =>
    vals
      .map((v, i) => (i === vals.length - 1 ? v : v.padEnd(widths[i])))
      .join('  ')
      .trimEnd();
  return [title, '', line(cols.map(([h]) => h)), ...cells.map(line)].join('\n') + '\n';
}
