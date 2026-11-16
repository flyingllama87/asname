// The glossary: the networking and threat-intelligence terms the page uses,
// each with where to read more. The kinds of network come from help.js, so
// the glossary and the (i)s say the same thing.

import { OPERATOR_TAGS, RANGE_TAGS } from './help.js';

const wiki = (title) => ['Wikipedia', `https://en.wikipedia.org/wiki/${title}`];

// GLOSSARY is [{section, intro?, terms: [{term, aka?, body, links?}]}].
export const GLOSSARY = [
  {
    section: 'Addresses and routing',
    terms: [
      {
        term: 'IP address',
        body: 'The number that identifies a machine (or a NAT gateway in front of many) on the internet. IPv4 addresses are 32 bits, written 192.0.2.1; IPv6 addresses are 128 bits, written 2001:db8::1.',
        links: [wiki('IP_address')],
      },
      {
        term: 'Prefix',
        aka: 'CIDR block, subnet, route',
        body: 'A run of consecutive addresses written as a start and a length: 192.0.2.0/24 is the 256 addresses from 192.0.2.0 to 192.0.2.255. The smaller the number after the slash, the bigger the block: a /8 holds 16.7 million IPv4 addresses, a /16 65,536, a /24 256, a /32 one.',
        links: [wiki('Classless_Inter-Domain_Routing')],
      },
      {
        term: 'Autonomous System (AS)',
        aka: 'network',
        body: 'A network run by one organisation with one routing policy: an ISP, a cloud, a university, a large company. The internet is some 80,000 of them connected to each other.',
        links: [wiki('Autonomous_system_(Internet)')],
      },
      {
        term: 'ASN',
        aka: 'AS number',
        body: 'The number identifying an Autonomous System, written AS13335. Registries assign them, so an ASN identifies the operator: everything it announces is its network.',
        links: [wiki('Autonomous_system_(Internet)#Assignment')],
      },
      {
        term: 'AS name',
        body: 'The short handle and organisation the AS is registered under, such as "CLOUDFLARENET - Cloudflare, Inc., US". The trailing code is the country the AS is registered in.',
      },
      {
        term: 'BGP',
        aka: 'Border Gateway Protocol',
        body: 'The protocol networks use to tell each other which prefixes they can reach. When a network starts sending a prefix to its neighbours it "announces" it.',
        links: [wiki('Border_Gateway_Protocol')],
      },
      {
        term: 'Announced prefix',
        aka: 'origin AS, carried by',
        body: 'A prefix an AS announces in BGP, and so carries traffic for. The AS that first announces it is its origin AS: the network the address is on. asname reads the announcements from RouteViews or RIPE RIS routing table dumps.',
        links: [['RouteViews', 'https://www.routeviews.org/'], ['RIPE RIS', 'https://www.ripe.net/analyse/internet-measurements/routing-information-service-ris/']],
      },
      {
        term: 'Not announced',
        body: 'Registered address space no network currently announces. Traffic claiming to come from it is spoofed, or the space was announced recently or briefly.',
      },
      {
        term: 'Reverse DNS',
        aka: 'PTR record',
        body: 'The hostname an address\'s owner has set for it. It can hint at a role (mail, VPN, a home broadband pool) but the owner writes what they like, so it proves nothing.',
        links: [wiki('Reverse_DNS_lookup')],
      },
      {
        term: 'Anycast',
        body: 'One address served from many places at once; each user reaches the nearest. DNS resolvers and CDNs use it, so such an address has no single location.',
        links: [wiki('Anycast')],
      },
      {
        term: 'CGNAT',
        aka: 'carrier-grade NAT',
        body: 'An ISP sharing one public address among many subscribers at once. The address alone does not identify anyone: the ISP needs the source port and the exact time.',
        links: [wiki('Carrier-grade_NAT')],
      },
    ],
  },
  {
    section: 'Registries and their records',
    terms: [
      {
        term: 'IANA',
        body: 'The Internet Assigned Numbers Authority, which hands blocks of addresses and AS numbers to the five regional registries.',
        links: [['iana.org', 'https://www.iana.org/numbers']],
      },
      {
        term: 'RIR',
        aka: 'Regional Internet Registry',
        body: 'The five organisations that allocate addresses and ASNs and keep the records of who holds them: ARIN (North America), RIPE NCC (Europe, the Middle East, Central Asia), APNIC (Asia-Pacific), LACNIC (Latin America and the Caribbean) and AFRINIC (Africa).',
        links: [wiki('Regional_Internet_registry'), ['ARIN', 'https://www.arin.net/'], ['RIPE NCC', 'https://www.ripe.net/'], ['APNIC', 'https://www.apnic.net/'], ['LACNIC', 'https://www.lacnic.net/'], ['AFRINIC', 'https://afrinic.net/']],
      },
      {
        term: 'Delegation files',
        aka: 'registry country',
        body: 'Each RIR\'s daily list of the blocks it has handed out and the country of each holder. asname\'s Country comes from these: where the holder registered the block, which is not always where its addresses are used.',
        links: [['NRO statistics', 'https://www.nro.net/about/rirs/statistics/']],
      },
      {
        term: 'Netblock',
        aka: 'inetnum, inet6num, NetRange',
        body: 'A registry record for a range of addresses: who holds it, its netname, when it was registered. Big allocations contain smaller assignments to customers, so the most specific record names the actual user. asname builds its netblock database from the RIRs\' bulk whois dumps.',
        links: [['RIPE database', 'https://apps.db.ripe.net/docs/RPSL-Object-Types/Descriptions-of-Primary-Objects/#description-of-the-inetnum-object']],
      },
      {
        term: 'Netname',
        body: 'The short name the holder gave a netblock, such as GOOGLE-DNS or AT-NESSUS-20190411. Free text: it often says what the range is for (DSL, MOBILE, CGNAT, HOSTING), which is what asname\'s range tags read.',
      },
      {
        term: 'Organisation',
        aka: 'org, holder',
        body: 'The company or person a netblock or AS is registered to. "Registered to" on a card is the most specific netblock\'s organisation; "Carried by" is the AS announcing it.',
      },
      {
        term: 'Allocation and assignment',
        body: 'An allocation is a block an RIR gives a provider to hand out; an assignment is a part of it given to one customer. A customer\'s assignment is often named after the customer, not the provider, so search by the provider\'s AS number to see them all.',
      },
      {
        term: 'whois',
        body: 'The old text protocol for asking a registry who holds an address or an AS. Online lookups use it when RDAP is unavailable.',
        links: [wiki('WHOIS')],
      },
      {
        term: 'RDAP',
        body: 'The Registration Data Access Protocol: whois\'s JSON successor. Online lookups ask the registry over RDAP for blocks the offline netblock database lacks (most ARIN and LACNIC space).',
        links: [wiki('Registration_Data_Access_Protocol')],
      },
      {
        term: 'IP leasing',
        aka: 'leased space',
        body: 'Address space its holder rents out through a broker. The user changes often and is not who the registry lists, which abusers like.',
        links: [['IPXO', 'https://www.ipxo.com/']],
      },
    ],
  },
  {
    section: 'Location',
    terms: [
      {
        term: 'Geolocation',
        body: 'An estimate of where an address is used, built by commercial providers from measurements and reports. Countries are usually right; cities are a guess, and VPNs, mobile networks and anycast defeat it.',
        links: [wiki('Internet_geolocation')],
      },
      {
        term: 'GeoLite2',
        body: 'MaxMind\'s free city database. asname shows it beside DB-IP: two independent estimates that agree are worth more than either.',
        links: [['MaxMind', 'https://dev.maxmind.com/geoip/geolite2-free-geolocation-data']],
      },
      {
        term: 'DB-IP',
        body: 'DB-IP\'s free city database, the other location estimate.',
        links: [['db-ip.com', 'https://db-ip.com/db/lite.php']],
      },
      {
        term: 'Geofeed',
        aka: 'RFC 8805',
        body: 'A file a network publishes saying where its own ranges are, linked from its registry records (RFC 9092). asname uses one only inside the ranges that name it. Usually the best answer; but some VPN and proxy providers publish where they want their exits to appear, so asname flags a geofeed both estimates contradict.',
        links: [['RFC 8805', 'https://datatracker.ietf.org/doc/html/rfc8805'], ['RFC 9092', 'https://datatracker.ietf.org/doc/html/rfc9092']],
      },
    ],
  },
  {
    section: 'Reputation and blocklists',
    terms: [
      {
        term: 'Blocklist',
        aka: 'blacklist, threat feed',
        body: 'A published list of addresses or networks seen attacking, spamming or run by criminals. A listing is evidence, not proof: lists differ in how they decide and how long they keep an entry.',
        links: [wiki('Domain_Name_System_blocklist')],
      },
      {
        term: 'Spamhaus',
        body: 'A non-profit that tracks spam and cybercrime and publishes widely used blocklists.',
        links: [['spamhaus.org', 'https://www.spamhaus.org/'], wiki('The_Spamhaus_Project')],
      },
      {
        term: 'Spamhaus DROP',
        aka: 'Don\'t Route Or Peer',
        body: 'Prefixes hijacked or run entirely by criminals; no legitimate traffic should come from them. A prefix wholly on DROP is hostile; a large prefix containing a DROP block (common at big carriers) is not.',
        links: [['Spamhaus DROP', 'https://www.spamhaus.org/blocklists/do-not-route-or-peer/']],
      },
      {
        term: 'Spamhaus ASN-DROP',
        body: 'Whole Autonomous Systems Spamhaus considers run by or for criminals. Everything such a network announces is suspect.',
        links: [['Spamhaus ASN-DROP', 'https://www.spamhaus.org/blocklists/do-not-route-or-peer/']],
      },
      {
        term: 'SBL',
        aka: 'Spamhaus Block List record',
        body: 'The record ID (SBL123456) behind a DROP listing: Spamhaus\'s evidence for it, worth reading before acting.',
        links: [['Spamhaus SBL', 'https://www.spamhaus.org/blocklists/spamhaus-blocklist/']],
      },
      {
        term: 'FireHOL',
        body: 'A project that combines many public blocklists into levels. Level 1 is the safest to block outright; level 2 is addresses reported attacking in the last 48 hours; level 3 in the last 30 days.',
        links: [['FireHOL IP lists', 'https://iplists.firehol.org/']],
      },
      {
        term: 'IPsum',
        body: 'A daily list of addresses with how many of some 30 public threat feeds name each. One feed is a weak signal; three or more is the usual threshold for blocking.',
        links: [['IPsum on GitHub', 'https://github.com/stamparm/ipsum']],
      },
      {
        term: 'Listed share',
        body: 'The share of a network\'s or prefix\'s IPv4 addresses on IPsum or FireHOL. A high share means the network tolerates or attracts abuse; a single listed address in a large network means little.',
      },
      {
        term: 'Tor exit node',
        body: 'A relay where Tor traffic leaves for the internet. Traffic from one comes from an anonymous Tor user, not from whoever runs the relay; it cannot be traced further.',
        links: [['Tor Project', 'https://www.torproject.org/'], wiki('Tor_(network)')],
      },
      {
        term: 'VPN',
        body: 'A service that relays its customers\' traffic through its own servers, hiding where they are. The provider rarely says who a customer was.',
        links: [wiki('Virtual_private_network')],
      },
    ],
  },
  {
    section: 'Data sources',
    terms: [
      {
        term: 'PeeringDB',
        body: 'A database where networks describe themselves, including what kind of network they are; one source of the kinds of network.',
        links: [['peeringdb.com', 'https://www.peeringdb.com/']],
      },
      {
        term: 'bgp.tools',
        body: 'A routing data service whose tags (hosting, VPN, Tor, anycast...) are another source of the kinds of network.',
        links: [['bgp.tools', 'https://bgp.tools/']],
      },
    ],
  },
];

// TAG_GLOSSARY is the kinds of network a prefix, a block or an AS can be
// tagged with.
export function tagGlossary() {
  const op = Object.entries(OPERATOR_TAGS).map(([tag, what]) => ({ term: tag, body: `${what[0].toUpperCase()}${what.slice(1)}. A tag on the AS: it describes the network, not each address in it.` }));
  const range = Object.entries(RANGE_TAGS).map(([tag, what]) => ({
    term: `range:${tag}`,
    body: `Inferred by asname from the block's netname: ${what.replace(/\s+/g, ' ')}`,
  }));
  const special = [
    { term: 'cloud:<provider>', body: 'Inside a cloud provider\'s published ranges (AWS, Google Cloud, Oracle, DigitalOcean, Linode, Vultr, Cloudflare, Fastly): a server one of its customers runs.' },
    { term: 'vpn:<provider>', body: 'On a VPN provider\'s published server list: one of its customers\' traffic, not the provider\'s.' },
    { term: 'tor-exit', body: 'On the Tor Project\'s list of exit nodes.' },
    { term: 'leased:<broker>', body: 'Rented out through an IP leasing broker.' },
    { term: 'anonymised-holder', body: 'The registry record withholds who holds the block.' },
  ];
  return { section: 'Kinds of network (tags)', intro: 'Tags say what kind of network an address is on. Filled tags come from published lists; outlined ones are inferred by asname from names, and say so.', terms: [...special, ...op, ...range].sort((a, b) => a.term.localeCompare(b.term)) };
}
