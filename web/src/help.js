// Plain-language explanations for someone new to this: what each field,
// tag and number means, and what a result suggests doing. The wording
// follows the README's descriptions of each source; it is advice for
// triage, not a verdict.

// ---------- fields ----------

export const FIELD_HELP = {
  asn: `The Autonomous System (AS) that announces this address on the internet: the network that routes traffic to it,
    and the name it registered. That is usually a hosting company, ISP or cloud, not the person or business using
    the address. Click the AS number to see everything that network announces.`,
  countryRIR: `The country recorded by the regional internet registry (RIR: ARIN, RIPE NCC, APNIC, LACNIC or AFRINIC)
    when it handed out the block. It is about paperwork, not where the device is; compare it with City.`,
  countryNetblock: `The country the block's own registration names. It differs from "Allocated in" when a block was
    carved out of a larger allocation and registered somewhere else, which is common when space is sold or leased.`,
  allocatedIn: `The country of the larger block the RIR originally allocated, which this one was carved from.`,
  countryASN: `The country in the AS's registered name.`,
  city: `Where DB-IP's free geolocation database places the address. It is an estimate: often right to the city for
    home broadband, often wrong for VPNs, mobile networks and cloud servers, which can appear anywhere.`,
  netblock: `The registry record for the specific block the address is in: the organisation it is assigned to, its
    network name (netname), and when it was registered. This is often the actual customer, where ASN is only the
    network carrying the traffic. A recently registered block deserves a closer look.`,
  category: `What kind of network or address this is. Tags with a colon (cloud:aws, vpn:nordvpn, leased:ipxo) and
    tor-exit are about this address itself, from lists the providers publish. Tags without one (hosting, isp, vpn,
    cdn...) describe the network operator as a whole, so "vpn" on 8.8.8.8 means Google runs VPNs somewhere, not that
    this address is one.`,
  reputation: `Whether public blocklists name this address, and what they say about its whole network (ASN). Being
    listed is evidence, not proof; how strong depends on the list.`,
  rdns: `The hostname the address's owner set for it (its PTR record). It can hint at a role (mail server, VPN,
    dynamic home broadband pool) but the owner chooses it freely, so it proves nothing.`,
  prefixes: `The address blocks this AS announces: the space it says it routes. How big a network is matters when
    judging how many of its addresses are listed.`,
  sources: `Where each answer came from. "Offline" sources are databases asname downloaded earlier (see the
    Databases tab for how old they are); "live" ones were asked just now.`,
};

export const CONTROL_HELP = {
  rdns: `Also look up each address's hostname (PTR record) in DNS. This makes a DNS query per address, so the
    address's DNS servers may see it.`,
  online: `Ask the internet for what the offline databases lack: the registry (ARIN, LACNIC...) for netblocks the
    offline index cannot name (over RDAP or, if that fails, whois) and for AS numbers too new for the offline names
    list (over RDAP); and RIPEstat for an AS's prefixes. The address or
    AS number is sent to those services, and registries rate-limit these queries, so leave it off unless you need it.`,
  fuzzy: `Also find names that match ignoring spaces and punctuation ("colo crossing" finds COLOCROSSING), or word by
    word in any order, leaving out company suffixes and expanding abbreviations ("univ of mississippi" finds
    "Mississippi State University"). Exact matches come first. Search never goes online, fuzzy or not.`,
  limit: `The most AS names, and separately the most netblocks, to show.`,
  maxAge: `How old a database may get before asname downloads a fresh copy. Shorter means fresher data and more
    downloads; blocklists change daily, registry data slowly.`,
  ipv6: `Whether the AS database includes IPv6 routes. Off, IPv6 addresses show no ASN. On adds about 25 MB to each
    ASN update and takes effect at the next one.`,
};

export const SOURCES_HELP = {
  section: `Everything asname knows comes from these public sources, downloaded when a database is updated and then
    used offline. Click a source to open it. A database built without one of its sources (Failed) still answers, but
    knows less: for example, without PeeringDB fewer networks are labelled ISP or content.`,
  result: `Used: read in the last update, with how many entries it gave. Not used: not needed (an earlier archive
    worked) or its condition was not met. Failed: could not be downloaded or read; the database was built without it,
    and Retry incomplete tries again. Not recorded: the last update predates per-source results.`,
  vpnLists: `Which list each vpn:<provider> tag comes from. A provider's own list is read at update time; gluetun's
    copies are only as fresh as the gluetun project's last refresh, shown here. An address on a VPN list was a VPN
    server when that list was made.`,
};

export const COLUMN_HELP = {
  prefixes: `How many address blocks the AS announces. 0 means it announces none: it may be unused, or used only
    inside another network.`,
  asnReputation: `Blocklist hits across the AS's address space; see a single address's card for what the numbers mean.`,
  match: `How the name matched: exact (contains what you typed), compact (ignoring spaces and punctuation) or words
    (every word you typed starts a word of the name, in any order).`,
  status: `Loaded: in use for lookups. On disk: present but not loaded (restart or update to load it). Not present:
    an optional database not built yet. Stale: older than the refresh age. Incomplete: the last update could not
    read one of its sources, so the previous data was kept for that part.`,
};

// ---------- tags ----------

const VPN_NAMES = {
  'private-internet-access': 'Private Internet Access',
  nordvpn: 'NordVPN',
  mullvad: 'Mullvad',
  surfshark: 'Surfshark',
  ivpn: 'IVPN',
  airvpn: 'AirVPN',
  windscribe: 'Windscribe',
  privadovpn: 'PrivadoVPN',
  protonvpn: 'ProtonVPN',
  expressvpn: 'ExpressVPN',
  cyberghost: 'CyberGhost',
  ipvanish: 'IPVanish',
  purevpn: 'PureVPN',
};

const titleCase = (s) => s.replace(/(^|[-_ ])(\w)/g, (_, sep, c) => (sep ? ' ' : '') + c.toUpperCase());
export const vpnName = (id) => VPN_NAMES[id] || titleCase(id);
const CLOUD_NAMES = { aws: 'AWS', gcp: 'Google Cloud', digitalocean: 'DigitalOcean', cloudflare: 'Cloudflare', oracle: 'Oracle Cloud', linode: 'Linode (Akamai)', vultr: 'Vultr', fastly: 'Fastly' };
export const cloudName = (id) => CLOUD_NAMES[id] || titleCase(id);
const BROKER_NAMES = { ipxo: 'IPXO', prefixbroker: 'PrefixBroker' };
const brokerName = (id) => BROKER_NAMES[id] || titleCase(id);

const OPERATOR_TAGS = {
  hosting: 'the operator sells servers or virtual machines (a hosting provider)',
  isp: 'the operator is a broadband ISP serving homes and businesses',
  mobile: 'the operator runs a mobile network',
  vpn: 'the operator is associated with a VPN service somewhere in its network',
  cdn: 'the operator runs a content delivery network',
  content: 'the operator mainly serves its own content or services',
  transit: 'the operator carries other networks’ traffic (a transit provider)',
  enterprise: 'the operator is a business running its own network',
  education: 'the operator is a university or research network',
  government: 'the operator is a government body',
  'non-profit': 'the operator is a non-profit',
  'network-services': 'the operator provides network services such as DNS or monitoring',
  'route-server': 'the operator runs an internet exchange route server or collector',
  satellite: 'the operator is a satellite internet provider',
  personal: 'the AS belongs to an individual',
  anycast: 'the address is anycast: the same address is served from many places at once',
};

// categoryTagHelp explains one category tag.
export function categoryTagHelp(tag) {
  const [kind, value] = tag.includes(':') ? tag.split(/:(.*)/) : [tag, ''];
  if (tag === 'tor-exit') {
    return 'Tor exit node: traffic from here comes from an anonymous Tor user, not from whoever runs the address. The Tor Project publishes this list.';
  }
  if (tag === 'anonymised-holder') {
    return 'The registry record withholds the name of the organisation holding this block, so you cannot tell from it who uses the address.';
  }
  if (kind === 'vpn' && value) {
    return `A ${vpnName(value)} VPN server, from the provider's published server list. Traffic comes from one of its customers, not the provider, and the real user is elsewhere.`;
  }
  if (kind === 'cloud' && value) {
    return `Inside ${cloudName(value)}'s published address ranges: a server or service hosted there, run by one of its customers.`;
  }
  if (kind === 'leased' && value) {
    return `Rented out through the IP leasing broker ${brokerName(value)}. Whoever uses it now may change often and may not be who the registry lists.`;
  }
  if (OPERATOR_TAGS[tag]) return `About the network, not this address: ${OPERATOR_TAGS[tag]}.`;
  return 'A classification of the network or address.';
}

// reputationTagHelp explains one blocklist entry, as `asname` names them.
export function reputationTagHelp(entry) {
  const [list, detail] = entry.split(/:(.*)/);
  switch (list) {
    case 'spamhaus-drop':
      return `Inside a Spamhaus DROP ("Don't Route Or Peer") block${detail ? ` (record ${detail})` : ''}: space that is hijacked or run by criminals. Spamhaus recommends dropping all traffic to and from it. This is a strong signal.`;
    case 'ipsum': {
      const n = Number(detail);
      return `IPsum aggregates 30+ public threat feeds; ${n} of them name this address. Its author suggests 3 or more as a blocking threshold, so ${n >= 3 ? 'this is above it' : 'on its own this is a weak signal: corroborate it'}.`;
    }
    case 'firehol-level2':
      return 'FireHOL level 2: reported attacking within the last 48 hours.';
    case 'firehol-level3':
      return 'FireHOL level 3: reported attacking within the last 30 days.';
  }
  return 'A public blocklist names this address.';
}

// asnReputationHelp explains the summary of an AS's blocklist hits.
export function asnReputationHelp(r) {
  const parts = [];
  if (r.spamhaus_asn_drop) {
    parts.push('Spamhaus ASN-DROP: Spamhaus considers the whole network to be operated by or for criminals. This is the strongest single signal.');
  }
  if (r.drop_prefixes) parts.push(`${r.drop_prefixes} of the blocks it announces are on Spamhaus DROP.`);
  if (r.listed_ips) {
    const share = r.listed_share_pct != null ? ` That is ${fmtPct(r.listed_share_pct)} of its announced IPv4 space.` : '';
    parts.push(`${r.listed_ips} of its addresses are named by IPsum or FireHOL.${share} Every large network has some listed addresses, so judge by the share, not the count: Google has hundreds listed, about 0.01%.`);
  }
  if (r.max_lists) parts.push(`"max ${r.max_lists} lists": its worst address is named by ${r.max_lists} IPsum feeds.`);
  if (!parts.length) parts.push('No blocklist names any address in this network.');
  return parts.join(' ');
}

function fmtPct(p) {
  if (p >= 10) return `${p.toFixed(0)}%`;
  if (p >= 1) return `${p.toFixed(1)}%`;
  if (p >= 0.01) return `${p.toFixed(2)}%`;
  return 'under 0.01%';
}

// ---------- what a result means ----------

const ONE_YEAR_MS = 365 * 24 * 3600 * 1000;

// findings turns a lookup result into plain-language points, worst first.
// Each is {level: 'high'|'medium'|'info'|'ok', text}.
export function findings(r, loaded = {}) {
  const out = [];
  const add = (level, text) => out.push({ level, text });
  const rep = r.reputation || {};
  const lists = rep.lists || [];
  const asnRep = rep.asn;
  const tags = r.category?.tags || [];
  const isASN = !r.ip;
  const asn = r.asn?.asn_string || 'this network';

  // Blocklists
  const drop = lists.find((l) => l.startsWith('spamhaus-drop'));
  if (drop) add('high', 'In a Spamhaus DROP block: hijacked or criminal-operated space. Block it, and treat any traffic to or from it as hostile.');
  if (asnRep?.spamhaus_asn_drop) {
    add('high', `The whole network (${asn}) is on Spamhaus ASN-DROP: Spamhaus considers it run by or for criminals. Treat traffic from any of its addresses as hostile.`);
  }
  if (lists.includes('firehol-level2')) add('high', 'Reported attacking within the last 48 hours (FireHOL level 2).');
  const ipsum = lists.find((l) => l.startsWith('ipsum:'));
  if (ipsum) {
    const n = Number(ipsum.split(':')[1]);
    if (n >= 3) add('high', `Named by ${n} public threat feeds (IPsum); 3 or more is the suggested blocking threshold.`);
    else add('medium', `Named by ${n} public threat feed${n === 1 ? '' : 's'} (IPsum). A weak signal on its own: look for corroboration in your logs.`);
  }
  if (lists.includes('firehol-level3') && !lists.includes('firehol-level2')) add('medium', 'Reported attacking within the last 30 days (FireHOL level 3).');
  if (asnRep && !asnRep.spamhaus_asn_drop && asnRep.drop_prefixes) {
    const n = asnRep.drop_prefixes;
    add('medium', `${asn} announces ${n} block${n === 1 ? '' : 's'} on Spamhaus DROP${drop ? '' : ', though not the one this address is in'}: it carries some criminal-operated space, which says something about who it accepts as customers.`);
  }
  if (asnRep && !asnRep.spamhaus_asn_drop && asnRep.listed_share_pct >= 1) {
    add('medium', `${fmtPct(asnRep.listed_share_pct)} of ${asn}'s address space is on blocklists, which is high: the network tolerates or attracts abuse.`);
  }

  // What the address is
  if (tags.includes('tor-exit')) add('medium', 'A Tor exit node: the traffic came from an anonymous Tor user, not from whoever runs this address. You cannot trace the user through it.');
  for (const t of tags.filter((t) => t.startsWith('vpn:'))) {
    add('medium', `A ${vpnName(t.slice(4))} VPN server: the real user is elsewhere, and the provider rarely says who.`);
  }
  for (const t of tags.filter((t) => t.startsWith('leased:'))) {
    add('medium', `Leased through ${brokerName(t.slice(7))}, an IP leasing broker: the space is rented out, so whoever uses it may change often and may not be who the registry lists. Leased space is popular with abusers.`);
  }
  if (tags.includes('anonymised-holder')) add('medium', 'The registry hides who holds this block.');
  if (r.netblock?.created) {
    const created = Date.parse(r.netblock.created);
    if (!Number.isNaN(created) && Date.now() - created < ONE_YEAR_MS) {
      add('medium', `The block was registered recently (${r.netblock.created}). Newly registered space is used for abuse more often than long-held space; it deserves a closer look.`);
    }
  }
  for (const t of tags.filter((t) => t.startsWith('cloud:'))) {
    add('info', `Hosted at ${cloudName(t.slice(6))}: a server or service run by one of its customers, not a person at home. Report abuse to ${cloudName(t.slice(6))}, who know the customer.`);
  }
  if (r.asn?.announced === false) {
    add('info', 'Not announced on the internet: private, reserved or unused space. Traffic that claims to come from it is internal or spoofed.');
  }

  // What kind of network, unless the address itself is classified
  if (!tags.some((t) => t.includes(':') || t === 'tor-exit')) {
    if (tags.includes('isp') || tags.includes('mobile')) {
      add('info', `${tags.includes('mobile') ? 'A mobile' : 'A broadband'} network, so probably a real person's connection. Such addresses are shared or reassigned over time, so tie activity to a time as well as the address.`);
    } else if (tags.includes('hosting')) {
      add('info', 'A hosting network: probably a server rather than a person. The netblock owner, if shown, is often the customer running it.');
    }
  }

  if (!isASN && loaded.reputation && !lists.length && !asnRep?.spamhaus_asn_drop) {
    add('ok', 'No blocklist names this address.');
  } else if (isASN && loaded.reputation && asnRep && !asnRep.spamhaus_asn_drop && !asnRep.drop_prefixes && !(asnRep.listed_share_pct >= 1)) {
    add('ok', 'Not a notably abused network.');
  }
  const order = { high: 0, medium: 1, info: 2, ok: 3 };
  return out.sort((a, b) => order[a.level] - order[b.level]);
}

// whereIs reconciles the three places a result names (the block's own
// registration, the RIR allocation it was carved from, and DB-IP's
// geolocation) into one plain answer, or says why there is none.
export function whereIs(r) {
  if (!r.ip) return null;
  const rir = r.country?.name || r.country?.code || '';
  const nb = r.netblock?.country;
  const reg = nb?.name || nb?.code || rir;
  const city = r.city?.present ? r.city.name : '';
  const geo = city ? city.split(',').pop().trim() : '';
  const tags = r.category?.tags || [];
  const movable = tags.includes('tor-exit') || tags.some((t) => t.startsWith('vpn:') || t.startsWith('cloud:'));
  const history = nb && rir && nb.code !== r.country?.code ? ` ${rir} is only where the larger block it was carved from was first allocated, which is common when space is sold or leased.` : '';
  if (!reg && !geo) return null;
  if (!geo) return `Registered in ${reg}; there is no geolocation to compare.${history}`;
  if (!reg) return `Geolocated to ${city}; there is no registration to compare.`;
  if (geo === reg) {
    const caveat = movable ? ' As a VPN, Tor or cloud address, though, the person behind it can be anywhere.' : '';
    return `Probably ${reg}: the block is registered there and geolocates to ${city}.${history}${caveat}`;
  }
  return `Unclear: registered in ${reg}, but geolocated to ${city}.${history} For home broadband, trust the geolocation; for servers, VPNs and cloud, neither says where the person behind it is.`;
}

// summaryText is a result as plain text for a ticket: the command line's
// card, then what it means.
export function summaryText(r, loaded) {
  const lines = [];
  if (r.text) lines.push(r.text.trimEnd());
  const where = whereIs(r);
  const points = findings(r, loaded);
  if (where || points.length) {
    lines.push('', 'What this means:');
    if (where) lines.push(`  Where: ${where}`);
    for (const f of points) lines.push(`  - ${f.text}`);
  }
  return lines.join('\n') + '\n';
}
