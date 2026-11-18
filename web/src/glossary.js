// The glossary: the networking and threat-intelligence terms the page uses.
// Each term has a one-line definition, what it means in an investigation
// (attribution, blocking, false positives, who to contact) and the
// technical detail under it, with where to read more. The kinds of network
// come from help.js, so the glossary and the (i)s say the same thing.

import { OPERATOR_TAGS, RANGE_TAGS } from './help.js';

const wiki = (title, label = 'Wikipedia') => [label, `https://en.wikipedia.org/wiki/${title}`];
const rfc = (n) => [`RFC ${n}`, `https://datatracker.ietf.org/doc/html/rfc${n}`];

// GLOSSARY is [{section, intro?, terms: [{term, aka?, body, practice?,
// detail?, links?}]}]: body is the definition, practice what it means in an
// investigation, detail how it works.
export const GLOSSARY = [
  {
    section: 'Addresses and routing',
    terms: [
      {
        term: 'IP address',
        body: 'The number that identifies a machine, or the gateway in front of many, on the internet. IPv4 addresses are 32 bits (192.0.2.1); IPv6 addresses are 128 bits (2001:db8::1).',
        practice: [
          'The address in your log is the last hop that talked to you. A NAT gateway, proxy, VPN, Tor exit, CDN or load balancer may stand in front of the real machine: check the kind of network before you attribute.',
          'Addresses change hands. Home broadband addresses change daily to monthly; cloud addresses pass to a new customer within minutes of release. Attribute an address at a time, never forever.',
          'Track IPv6 users by their /64, not the full address: devices rotate the last 64 bits for privacy.',
        ],
        detail: [
          'Never on the internet: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (private, RFC 1918), 100.64.0.0/10 (CGNAT), 127.0.0.0/8 (loopback), 169.254.0.0/16 (link-local). One of these as a source at your edge is spoofed or a misconfiguration.',
          'Documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32) appear in examples only.',
        ],
        links: [wiki('IP_address'), ['IANA special-purpose registry', 'https://www.iana.org/assignments/iana-ipv4-special-registry/']],
      },
      {
        term: 'Prefix',
        aka: 'CIDR block, subnet, route',
        body: 'A run of consecutive addresses written as a start and a length: 192.0.2.0/24 is the 256 addresses 192.0.2.0 to 192.0.2.255.',
        practice: [
          'Block the narrowest prefix that covers the threat. Blocking a /16 to stop one host takes out 65,536 addresses, most of them innocent.',
          'Search and Explore copy prefixes ready for a firewall or a SIEM query.',
        ],
        detail: [
          'Addresses in a prefix: 2^(32 − length) for IPv4. /8 = 16.7 million, /16 = 65,536, /24 = 256, /32 = one address.',
          'A /24 is the smallest IPv4 prefix most networks accept in BGP; a /48 the smallest IPv6. A /64 is one IPv6 LAN; a home customer usually gets a /56 or /48.',
          'When prefixes overlap, routers use the most specific (longest) match.',
        ],
        links: [wiki('Classless_Inter-Domain_Routing')],
      },
      {
        term: 'Autonomous System (AS)',
        aka: 'network',
        body: 'A network run by one organisation with one routing policy: an ISP, a cloud, a university, a large company. Over 70,000 of them make up the internet.',
        practice: [
          'The AS tells you whose network carries the traffic, not who sent it: a cloud\'s AS carries thousands of customers. "Registered to" (the netblock) is the better answer to who.',
          'The network\'s abuse contact is in its registry record; report to the most specific party first (the netblock holder), then the network.',
        ],
        links: [wiki('Autonomous_system_(Internet)')],
      },
      {
        term: 'ASN',
        aka: 'AS number',
        body: 'The number identifying an Autonomous System, written AS13335.',
        practice: [
          'Pivot on it: look up the ASN for its prefixes and reputation, Explore with Origin AS for each prefix\'s blocklist hits, and Search for the AS number for every registry netblock under it, customers included.',
          'Blocking a whole ASN catches criminal hosts that rotate addresses (that is what Spamhaus ASN-DROP is for), but blocking a cloud or an ISP\'s ASN blocks all their customers.',
        ],
        detail: [
          'ASNs are 16-bit (up to 65535) or 32-bit (up to 4,294,967,295). 64512–65534 and 4200000000–4294967294 are private and never seen on the internet; AS0 means "no one may originate this".',
        ],
        links: [wiki('Autonomous_system_(Internet)#Assignment')],
      },
      {
        term: 'AS name',
        body: 'The handle and organisation an AS is registered under, such as "CLOUDFLARENET - Cloudflare, Inc., US". The trailing code is the country it is registered in.',
        practice: [
          'The handle often identifies the business better than the legal name (AMAZON-02, GOOGLE-CLOUD-PLATFORM).',
          'The operator chooses it and rarely updates it: after a sale or a rebrand the old name can stay for years.',
        ],
      },
      {
        term: 'BGP',
        aka: 'Border Gateway Protocol',
        body: 'The protocol networks use to tell each other which prefixes they can reach. A network that starts routing a prefix "announces" it.',
        practice: [
          'Routes change: a prefix can move to another network after a sale, a lease or a hijack. asname shows the routing table at its last update (see Databases); for a fast-moving incident, check a live source such as bgp.tools.',
          'A hijack is someone announcing space they do not hold, usually briefly, to send spam or attacks from clean-looking addresses. Spamhaus DROP lists hijacked prefixes.',
        ],
        detail: [
          'RPKI lets holders publish which AS may originate their prefixes (ROAs); networks increasingly drop announcements that contradict them.',
        ],
        links: [wiki('Border_Gateway_Protocol'), wiki('Resource_Public_Key_Infrastructure', 'RPKI')],
      },
      {
        term: 'Announced prefix',
        aka: 'origin AS, carried by',
        body: 'A prefix an AS announces in BGP. The AS that originates the announcement is the network the address is on.',
        practice: [
          'When the origin AS is not the netblock\'s holder, the holder is that network\'s customer, the space is leased, or (rarely) it is hijacked. A recent registration or a leased tag makes the last two likelier.',
        ],
        detail: ['asname reads the announcements from RouteViews or RIPE RIS routing table dumps; the most specific announcement wins.'],
        links: [['RouteViews', 'https://www.routeviews.org/'], ['RIPE RIS', 'https://www.ripe.net/analyse/internet-measurements/routing-information-service-ris/']],
      },
      {
        term: 'Not announced',
        body: 'Registered address space no network currently announces.',
        practice: [
          'Nothing can reply to it, so a completed TCP connection from it is impossible now: either the log is older than the routing data, or the space was announced briefly (a hijack). UDP and SYN floods from unannounced space are spoofed.',
        ],
        detail: ['Unannounced and unallocated space is called bogon space; most networks filter it at their border.'],
        links: [wiki('Bogon_filtering')],
      },
      {
        term: 'Bogon',
        aka: 'unallocated space',
        body: 'Address space no registry has handed out, plus the reserved blocks. asname marks it from Team Cymru\'s full bogon lists, which follow the registries\' allocations.',
        practice: [
          'Not announced and a bogon: nobody holds it, so traffic from it is spoofed.',
          'Announced and a bogon: someone is routing space they were never given. That is squatting or a hijack, used for spam and attacks; treat it as hostile.',
          'Not announced but not a bogon: allocated to someone who does not route it publicly. It may be used inside a private network.',
        ],
        detail: ['Team Cymru refreshes the lists every few hours; asname\'s copy is as old as its category database. A block allocated since then can still show as a bogon.'],
        links: [['Team Cymru bogon reference', 'https://www.team-cymru.com/bogon-reference'], wiki('Bogon_filtering')],
      },
      {
        term: 'Special-purpose address',
        body: 'A block IANA sets aside for something other than ordinary addressing: private use (10/8, 172.16/12, 192.168/16), carrier-grade NAT (100.64/10), loopback, link-local, documentation (192.0.2/24, 2001:db8::/32), benchmarking, NAT64 (64:ff9b::/96), multicast and others.',
        practice: [
          'Most are not reachable on the internet. In your own logs they are internal hosts; in a report from outside they are a misconfiguration or spoofing.',
          'Documentation ranges (192.0.2/24, 198.51.100/24, 203.0.113/24, 2001:db8::/32, 3fff::/20) appear in examples and test data, never in real traffic.',
          '100.64/10 is a carrier\'s CGNAT space: you see it on your own router\'s WAN when behind CGNAT, never as a public source.',
        ],
        detail: ['asname carries a copy of IANA\'s two special-purpose registries (RFC 6890), with each block\'s RFC and whether it is globally reachable.'],
        links: [['IANA IPv4 special-purpose registry', 'https://www.iana.org/assignments/iana-ipv4-special-registry/'], ['IANA IPv6 special-purpose registry', 'https://www.iana.org/assignments/iana-ipv6-special-registry/'], rfc(6890)],
      },
      {
        term: 'Reverse DNS',
        aka: 'PTR record, rDNS',
        body: 'The hostname the holder of an address has set for it.',
        practice: [
          'Good hints: "dyn", "dsl", "pool", "cust", "cpe" mean residential; "mail", "smtp" a mail server; "vpn", "tor-exit" are self-declared. ISP-generated names often encode the address and region.',
          'Proves nothing on its own: whoever controls the block writes what they like, including "google.com". Forward-confirm: resolve the name and check it gives back the same address.',
        ],
        detail: ['PTR records live under in-addr.arpa (IPv4) and ip6.arpa (IPv6), delegated to the block\'s holder. Forward-confirmed reverse DNS is called FCrDNS.'],
        links: [wiki('Reverse_DNS_lookup'), wiki('Forward-confirmed_reverse_DNS', 'FCrDNS')],
      },
      {
        term: 'Anycast',
        body: 'One address served from many places at once; each user reaches the nearest.',
        practice: [
          'Geolocation and traceroute cannot say where an anycast service is: the same address is many machines.',
          'Blocking one blocks a global service (1.1.1.1, 8.8.8.8, a CDN edge). Anycast resolvers in your DNS logs are normal.',
        ],
        detail: ['The same prefix is announced from many locations; BGP delivers each user to the closest.'],
        links: [wiki('Anycast')],
      },
      {
        term: 'CDN',
        aka: 'content delivery network, edge server',
        body: 'A network of servers around the world that serve a site\'s content from the one nearest each user: Akamai, Cloudflare, CloudFront, Fastly and others.',
        practice: [
          'Looking up a hostname behind a CDN tells you about the CDN\'s edge server, not the site: the address depends on who asks, and another resolver gets another one. asname flags it as "Served by".',
          'Big CDNs put caches inside ISPs, so a CDN-fronted site can resolve to an address registered to your own ISP (an Akamai cache inside Vodafone, say).',
          'Traffic from CDN addresses to you is the CDN fetching from your origin or relaying a client: the real client is in X-Forwarded-For or a similar header. Blocking a CDN address blocks every site behind it.',
        ],
        detail: [
          'Sites join a CDN by a CNAME to the CDN\'s name (www.nsa.gov → nsa.gov.edgekey.net, Akamai) or by moving their DNS to it (nsa.gov\'s name servers are Akamai\'s akam.net). The CDN\'s DNS then answers with the edge nearest the resolver.',
          'To find the site\'s operator, use the domain\'s registration (whois or RDAP for the domain), its certificate, or its mail and name-server records, not the address.',
        ],
        links: [wiki('Content_delivery_network'), ['Akamai: edge platform', 'https://www.akamai.com/why-akamai/global-infrastructure']],
      },
      {
        term: 'CGNAT',
        aka: 'carrier-grade NAT',
        body: 'An ISP sharing one public IPv4 address among many subscribers at once, often hundreds, because IPv4 has run out. Standard on mobile networks and increasingly on cheap broadband.',
        practice: [
          'The public address alone identifies no one. To name a subscriber the ISP needs the source port and the exact time, to the second, with the time zone. Make sure your logs keep source ports.',
          'Blocking or rate-limiting a CGNAT address hits every subscriber behind it, and blocklists list CGNAT addresses for other people\'s behaviour.',
          'Many unrelated users behind one address looks like credential stuffing or account sharing when it is neither.',
        ],
        detail: [
          'Behind CGNAT your router\'s WAN address is in 100.64.0.0/10 (the shared address space, RFC 6598) or sometimes 10.x, not the address websites see. If the two differ, you are behind CGNAT.',
          'Nothing outside can connect in: port forwarding and UPnP open only your router\'s NAT, not the ISP\'s.',
          'Ways round it: IPv6 (no NAT), a public IPv4 from the ISP (often paid), or an outbound tunnel: Tailscale or WireGuard meshes (NAT traversal, falling back to relays such as Tailscale\'s DERP), Cloudflare Tunnel, ngrok, or a reverse proxy on a rented server.',
          'ISPs give each subscriber a block of ports and log the mappings; RFC 6302 asks internet-facing servers to log source ports for this reason.',
        ],
        links: [wiki('Carrier-grade_NAT'), rfc(6598), rfc(6302), ['Tailscale: how NAT traversal works', 'https://tailscale.com/blog/how-nat-traversal-works']],
      },
      {
        term: 'NAT64 and DNS64',
        body: 'How an IPv6-only network, which includes most mobile carriers, reaches IPv4-only sites. The resolver (DNS64) answers a name that has no IPv6 address with a made-up one: the site\'s IPv4 address in the last 32 bits of the carrier\'s NAT64 prefix. The carrier\'s translator (NAT64) then forwards the traffic over IPv4.',
        practice: [
          'A made-up address belongs to the carrier, so a registry lookup of it names the carrier: on Vodafone Australia\'s mobile network nsa.gov resolves to 2405:6e00:64::172e:2f6c, which is Vodafone\'s, and slashdot.org to 2405:6e00:64::6812:4d7. asname spots these and looks up the IPv4 address inside instead (172e:2f6c is 23.46.47.108).',
          'A NAT64 address in your own logs is a customer of the network that owns the prefix reaching an IPv4 host. Read the last 32 bits as an IPv4 address to see which host.',
          'Resolve on a tethered phone or a mobile hotspot and you are on DNS64 too. If a site seems to belong to your carrier, this is why.',
        ],
        detail: [
          'The well-known prefix 64:ff9b::/96 (RFC 6052) means NAT64 on any network; carriers often use a prefix of their own. A host learns its network\'s prefix by resolving ipv4only.arpa (RFC 7050), whose IPv4 addresses 192.0.0.170 and .171 come back inside the prefix. asname does the same.',
          'DNS64 makes up an address only when the name has no AAAA record, so a made-up address also tells you the site has no IPv6 of its own.',
          'Phones on these networks run 464XLAT (CLAT): the phone translates IPv4 apps to IPv6 itself, so tethered laptops and old apps still work. To the world the phone appears on the carrier\'s NAT64 IPv4 pool, a CGNAT-like shared address.',
        ],
        links: [wiki('NAT64'), wiki('DNS64'), rfc(6052), rfc(6147), rfc(7050), wiki('IPv6_transition_mechanism#464XLAT')],
      },
    ],
  },
  {
    section: 'Registries and their records',
    terms: [
      {
        term: 'IANA',
        body: 'The Internet Assigned Numbers Authority: hands blocks of addresses and AS numbers to the five regional registries, and keeps the lists of special-purpose ranges.',
        practice: ['A special-purpose range (documentation, benchmarking 198.18.0.0/15, private) as a source at your edge means spoofing or a misconfiguration, not an attacker you can trace.'],
        links: [['iana.org', 'https://www.iana.org/numbers']],
      },
      {
        term: 'RIR',
        aka: 'Regional Internet Registry',
        body: 'The five organisations that allocate addresses and ASNs and keep the records of who holds them: ARIN (North America), RIPE NCC (Europe, the Middle East, Central Asia), APNIC (Asia-Pacific), LACNIC (Latin America and the Caribbean) and AFRINIC (Africa).',
        practice: [
          'The RIR is where the holder\'s record and abuse contact live, and whose rules apply to a complaint.',
          'asname\'s offline records are thinner for ARIN (bulk data needs an agreement) and LACNIC (no bulk dump); turn on Online lookups to ask them directly.',
        ],
        detail: ['Space moves between RIRs on transfer, so the RIR is not a reliable guide to location either.'],
        links: [wiki('Regional_Internet_registry'), ['ARIN', 'https://www.arin.net/'], ['RIPE NCC', 'https://www.ripe.net/'], ['APNIC', 'https://www.apnic.net/'], ['LACNIC', 'https://www.lacnic.net/'], ['AFRINIC', 'https://afrinic.net/']],
      },
      {
        term: 'Delegation files',
        aka: 'registry country',
        body: 'Each RIR\'s daily list of the blocks it has handed out and the country of each holder. asname\'s Country comes from these.',
        practice: [
          'Answers "which jurisdiction holds this block", not "where is the user". A multinational\'s US-registered block can be used on any continent; compare it with Location.',
        ],
        links: [['NRO statistics', 'https://www.nro.net/about/rirs/statistics/']],
      },
      {
        term: 'Netblock',
        aka: 'inetnum, inet6num, NetRange',
        body: 'A registry record for a range of addresses: who holds it, its netname, when it was registered. Big allocations contain smaller assignments to customers.',
        practice: [
          'The most specific netblock is the best answer to "who uses this address", often a customer of the network. If it is a business or a public body, it may be a victim (a compromised machine): contact it before the network\'s abuse desk.',
          'A recently registered block is more often used for abuse than long-held space.',
          'Records go stale: holders rarely update them after a sale or a reorganisation.',
        ],
        detail: ['RIPE, APNIC and AFRINIC call them inetnum and inet6num, ARIN NetRange. Their status (ALLOCATED PA, ASSIGNED PA, ASSIGNED PI...) says whether the holder is a provider or an end user.'],
        links: [['RIPE: inetnum', 'https://apps.db.ripe.net/docs/RPSL-Object-Types/Descriptions-of-Primary-Objects/#description-of-the-inetnum-object']],
      },
      {
        term: 'Netname',
        body: 'The short name the holder gave a netblock, such as GOOGLE-DNS or AT-NESSUS-20190411.',
        practice: [
          'Free text, unverified, but revealing: DSL, POOL, DYN, FTTH mean home broadband; LTE, MOB, GPRS mobile; CGN or CGNAT shared addresses; HOSTING, VPS, DC servers. asname\'s range: tags come from these words.',
        ],
      },
      {
        term: 'Organisation',
        aka: 'org, holder',
        body: 'The company or person a netblock or AS is registered to.',
        practice: [
          '"Registered to" on a card is the most specific netblock\'s organisation; "Carried by" is the network announcing it. They differ for customers, leased space and cloud tenants, which is normal.',
        ],
      },
      {
        term: 'Allocation and assignment',
        body: 'An allocation is a block an RIR gives a provider to hand out; an assignment is part of one given to a single customer.',
        practice: [
          'A customer\'s assignment is named after the customer, so searching the provider\'s name misses it. Search for the provider\'s AS number to list every netblock inside its routes.',
        ],
      },
      {
        term: 'whois',
        body: 'The old text protocol for asking a registry who holds an address, a domain or an AS.',
        practice: ['Output differs by registry and is rate-limited; the abuse contact is usually an "abuse-mailbox" or "OrgAbuseEmail" line. Online lookups use it when RDAP is unavailable.'],
        detail: ['TCP port 43; each registry runs its own server and refers onwards.'],
        links: [wiki('WHOIS')],
      },
      {
        term: 'RDAP',
        body: 'The Registration Data Access Protocol: whois\'s structured JSON successor.',
        practice: ['Online lookups ask over RDAP for blocks the offline netblock database lacks (most ARIN and LACNIC space). The query reveals to the registry which address you looked up.'],
        detail: ['HTTPS and JSON, with standard fields and redirects to the right registry (RFC 9082, 9083).'],
        links: [wiki('Registration_Data_Access_Protocol'), rfc(9083)],
      },
      {
        term: 'IP leasing',
        aka: 'leased space',
        body: 'Address space its holder rents out through a broker.',
        practice: [
          'The registry names the landlord, not the tenant, and the tenant changes often. Abuse reports go to the broker, who passes them on.',
          'Proxy, VPN and bulk-mail operators use a lot of it; with a recent registration it deserves a closer look.',
        ],
        links: [['IPXO', 'https://www.ipxo.com/']],
      },
    ],
  },
  {
    section: 'Location',
    terms: [
      {
        term: 'Geolocation',
        body: 'An estimate of where an address is used, built by commercial providers from network measurements, registry data and reports.',
        practice: [
          'The country is usually right for fixed broadband; the city is a guess.',
          'Mobile addresses locate to the carrier\'s gateway, often another city. VPN, hosting and cloud addresses locate to the server, not the person.',
          'Check for VPN, mobile and cloud before calling it "impossible travel".',
        ],
        links: [wiki('Internet_geolocation')],
      },
      {
        term: 'GeoLite2',
        body: 'MaxMind\'s free city database, one of two independent location estimates asname shows.',
        practice: ['When GeoLite2 and DB-IP agree, trust the country; when they disagree, treat the location as unknown, as the card says.'],
        links: [['MaxMind', 'https://dev.maxmind.com/geoip/geolite2-free-geolocation-data']],
      },
      {
        term: 'DB-IP',
        body: 'DB-IP\'s free city database, the other location estimate.',
        links: [['db-ip.com', 'https://db-ip.com/db/lite.php']],
      },
      {
        term: 'iCloud Private Relay',
        body: 'Apple\'s relay for Safari and other traffic from iPhones, iPads and Macs whose owners pay for iCloud+. The site sees an address of the relay\'s, run on Akamai, Cloudflare or Fastly, not the user\'s.',
        practice: [
          'Many corporate and personal Apple devices show up this way: an iCloud Private Relay address is a person on an Apple device, not a server.',
          'Apple publishes each egress range with the region its users are in, and keeps them in that region, so the location is roughly right, unlike a VPN\'s.',
          'The address is shared by many users and Apple will not identify one. Do not block the ranges for one user\'s behaviour.',
        ],
        links: [['Apple: prepare your network for Private Relay', 'https://developer.apple.com/support/prepare-your-network-for-icloud-private-relay/'], ['Egress ranges', 'https://mask-api.icloud.com/egress-ip-ranges.csv']],
      },
      {
        term: 'Geofeed',
        aka: 'RFC 8805',
        body: 'A file a network publishes saying where its own ranges are, linked from its registry records.',
        practice: [
          'From an ISP it is usually the best answer there is.',
          'Some VPN and proxy providers publish where they want their exits to appear, not where they are: asname flags a geofeed both estimates contradict.',
        ],
        detail: ['asname uses a feed only inside the ranges whose registry records name it (RFC 9092), so a network cannot place someone else\'s space.'],
        links: [rfc(8805), rfc(9092)],
      },
    ],
  },
  {
    section: 'Reputation and blocklists',
    terms: [
      {
        term: 'Blocklist',
        aka: 'blacklist, threat feed',
        body: 'A published list of addresses or networks seen attacking, spamming, or run by criminals.',
        practice: [
          'Evidence, not proof. Ask which list, how fresh, and for what. One list is a weak signal; several, plus your own logs, a strong one.',
          'False positives come from shared addresses (CGNAT, VPN, Tor, cloud): the listing may be for someone else, and cloud addresses pass to new customers within minutes.',
        ],
        links: [wiki('Domain_Name_System_blocklist')],
      },
      {
        term: 'Spamhaus',
        body: 'A non-profit that tracks spam and cybercrime and publishes some of the most widely used blocklists.',
        links: [['spamhaus.org', 'https://www.spamhaus.org/'], wiki('The_Spamhaus_Project')],
      },
      {
        term: 'Spamhaus DROP',
        aka: 'Don\'t Route Or Peer',
        body: 'Prefixes hijacked or run entirely by criminals.',
        practice: [
          'Designed to be dropped outright at the firewall: no legitimate traffic should come from them. Traffic to or from one deserves an incident, not a ticket.',
          'In Explore, "all of it" is a prefix wholly on DROP; "any of it" a large prefix containing a DROP block, common at big carriers, which is not itself hostile.',
        ],
        links: [['Spamhaus DROP', 'https://www.spamhaus.org/blocklists/do-not-route-or-peer/']],
      },
      {
        term: 'Spamhaus ASN-DROP',
        body: 'Whole Autonomous Systems Spamhaus considers run by or for criminals.',
        practice: ['Treat everything the network announces as hostile, including addresses no list names yet: such networks rotate addresses to stay ahead of the lists.'],
        links: [['Spamhaus ASN-DROP', 'https://www.spamhaus.org/blocklists/do-not-route-or-peer/']],
      },
      {
        term: 'SBL',
        aka: 'Spamhaus Block List record',
        body: 'The record ID (SBL123456) behind a DROP listing.',
        practice: ['Spamhaus\'s evidence for the listing: read it before escalating, and quote it in reports.'],
        links: [['Spamhaus SBL', 'https://www.spamhaus.org/blocklists/spamhaus-blocklist/']],
      },
      {
        term: 'FireHOL',
        body: 'A project that combines many public blocklists into levels.',
        practice: [
          'Level 1 is meant to be safe to block outright. Level 2: reported attacking in the last 48 hours. Level 3: in the last 30 days. Higher levels catch more and mislead more.',
        ],
        links: [['FireHOL IP lists', 'https://iplists.firehol.org/']],
      },
      {
        term: 'IPsum',
        body: 'A daily list of suspicious addresses with how many of some 30 public threat feeds name each.',
        practice: ['The count is the signal: 1–2 feeds corroborate other evidence; 3 or more is the usual blocking threshold.'],
        links: [['IPsum on GitHub', 'https://github.com/stamparm/ipsum']],
      },
      {
        term: 'Listed share',
        body: 'The share of a network\'s or prefix\'s IPv4 addresses on IPsum or FireHOL.',
        practice: [
          'A high share means the network tolerates or attracts abuse, as bulletproof hosts do, or (for an ISP) has many infected customers. One listed address in a large network means little.',
        ],
      },
      {
        term: 'Tor exit node',
        body: 'A relay where Tor traffic leaves for the internet.',
        practice: [
          'The traffic comes from an anonymous Tor user, not from whoever runs the relay, and cannot be traced further. Do not report the operator for it.',
          'Block Tor if your service has no reason to accept it. Exits change hourly; asname\'s list is as old as its last update.',
        ],
        links: [['Tor Project', 'https://www.torproject.org/'], ['Tor exit list', 'https://check.torproject.org/torbulkexitlist'], wiki('Tor_(network)')],
      },
      {
        term: 'Botnet C2',
        aka: 'command and control',
        body: 'A server that infected machines contact for orders. abuse.ch\'s Feodo Tracker lists the C2 servers of banking and loader malware families (QakBot, Emotet, Dridex and others) with the family each serves.',
        practice: [
          'An internal host talking to a C2 is almost certainly infected: isolate it and find the malware family\'s other indicators.',
          'Block C2 addresses outright; they have no legitimate use. They often sit on rented cloud servers, so check the date: a cloud address may have passed to an innocent customer since.',
        ],
        detail: ['C2IntelFeeds lists attack frameworks\' C2 servers (mostly Cobalt Strike) found by scanning for their fingerprints, keeping those verified in the last 30 days. ThreatFox, with an abuse.ch key, adds the last week\'s reported malware infrastructure by family.'],
        links: [['Feodo Tracker', 'https://feodotracker.abuse.ch/'], ['ThreatFox', 'https://threatfox.abuse.ch/'], ['C2IntelFeeds', 'https://github.com/drb-ra/C2IntelFeeds'], wiki('Botnet')],
      },
      {
        term: 'Internet scanner',
        body: 'A service that probes every address on the internet, for research (universities, Shadowserver) or to sell attack-surface data (Censys, Shodan and many others). asname marks the ranges they publish, from the MISP warninglists.',
        practice: [
          'Hits from a known scanner are background noise, not someone targeting you. Do not spend an investigation on them.',
          'But what it found about you is now searchable: look yourself up on the scanner\'s site to see what it saw.',
          'Attackers use scanners too, from ordinary hosting; an unlisted address scanning you is not innocent just because scanning is common.',
        ],
        links: [['MISP warninglists', 'https://github.com/MISP/misp-warninglists'], ['Shadowserver', 'https://www.shadowserver.org/']],
      },
      {
        term: 'Sinkhole',
        body: 'An address that researchers, a registrar or the police point a seized malicious domain at, to cut the malware off and count its victims.',
        practice: [
          'A device of yours talking to a sinkhole is infected with whatever used the domain: find out which domain it looked up.',
          'The sinkhole itself is harmless; whoever runs it may already be notifying victims, including you.',
        ],
        links: [wiki('DNS_sinkhole'), ['MISP warninglists', 'https://github.com/MISP/misp-warninglists']],
      },
      {
        term: 'VPN',
        body: 'A service that relays its customers\' traffic through its own servers, hiding where they are.',
        practice: [
          'The user is elsewhere, and many customers share each server: blocking one blocks them all.',
          'Commercial providers rarely hold records of who used an address; legal process seldom yields a name.',
        ],
        links: [wiki('Virtual_private_network')],
      },
    ],
  },
  {
    section: 'Data sources',
    terms: [
      {
        term: 'MISP warninglists',
        body: 'Lists, maintained by the MISP threat-sharing project, of addresses that look suspicious but are not: scanners, crawlers, public DNS resolvers, sinkholes, cloud and service ranges. asname reads its IP lists into scanner:, crawler:, service:, cloud: and other tags.',
        practice: ['A warninglist hit is a reason to stop before raising an alert, not a reason to trust the traffic: anyone can rent a cloud server.'],
        links: [['github.com/MISP/misp-warninglists', 'https://github.com/MISP/misp-warninglists']],
      },
      {
        term: 'PeeringDB',
        body: 'A database where networks describe themselves: what kind of network they are, where they connect, and how to reach their engineers.',
        practice: ['Its contacts often reach a network\'s engineers when the abuse desk does not answer.'],
        links: [['peeringdb.com', 'https://www.peeringdb.com/']],
      },
      {
        term: 'bgp.tools',
        body: 'A routing data service with live routes, network relationships and tags (hosting, VPN, Tor, anycast...).',
        practice: ['Use it for the live picture during an incident: who announces a prefix right now, and since when.'],
        links: [['bgp.tools', 'https://bgp.tools/']],
      },
    ],
  },
];

// TAG_PRACTICE is what each tag means in an investigation.
const TAG_PRACTICE = {
  hosting: 'Traffic comes from a server, not a person. A person "logging in" from hosting space is usually using a VPN, a proxy or a bot. Report abuse to the hosting provider, who can identify its customer.',
  isp: 'Usually a real person at home or in a small office. Addresses are often dynamic, so attribution needs the exact time; block narrowly.',
  mobile: 'Phones and mobile routers, almost always behind CGNAT: shared, changing addresses that geolocate to the carrier\'s gateway.',
  vpn: 'Some of this network is VPN servers. Check whether this address is one (a vpn:<provider> tag) before assuming.',
  cdn: 'Traffic from a CDN is the CDN fetching from you or relaying a client: look for the real client in X-Forwarded-For or similar. Blocking a CDN breaks the sites behind it.',
  content: 'A big service\'s own addresses (mail, crawlers, apps). Usually legitimate; verify a crawler by forward-confirmed reverse DNS.',
  transit: 'Carries other networks\' traffic. Abuse from its space usually starts at a customer: the most specific netblock names them.',
  enterprise: 'A company\'s own staff and systems. An attack from here usually means a compromised machine: they will want to know.',
  education: 'Many users and open networks: compromised machines are common, and so is legitimate research scanning.',
  government: 'A public body\'s own systems. Attack traffic usually means compromise; notify through their CERT or abuse contact.',
  finance: 'A bank or insurer\'s own systems. Attack traffic usually means compromise; they will want to know quickly.',
  healthcare: 'A health provider\'s own systems. Attack traffic usually means compromise.',
  'non-profit': 'A non-profit\'s own network. Small teams: attack traffic usually means compromise.',
  'network-services': 'DNS, monitoring and measurement services. Probes from them are often legitimate monitoring or research; check their published ranges.',
  'route-server': 'Internet exchange infrastructure. It should never send you application traffic.',
  satellite: 'Satellite internet such as Starlink: users roam, geolocation is poor and CGNAT is common.',
  personal: 'One person\'s network: few users, so attribution is easier, but expect home labs, self-hosted VPNs and personal scanners.',
  anycast: 'The address is served from many places: no single location, and blocking it blocks a global service.',
};

const SPECIAL_TAGS = [
  { term: 'cloud:<provider>', body: 'Inside a cloud or CDN provider\'s published ranges (AWS, Azure, Google Cloud, Oracle, IBM, Alibaba, Huawei, Tencent, Hetzner, OVH, DigitalOcean, Linode, Vultr, Akamai, Cloudflare, Fastly and others): a server one of its customers runs.', practice: 'Report to the cloud\'s abuse team, who can identify the customer. Addresses pass to new customers within minutes, so act on fresh evidence only.' },
  { term: 'vpn:<provider>', body: 'On a VPN provider\'s published server list.', practice: 'The real user is elsewhere and shares the address with the provider\'s other customers.' },
  { term: 'tor-exit', body: 'On the Tor Project\'s list of exit nodes.', practice: 'An anonymous Tor user, untraceable; see Tor exit node above.' },
  { term: 'leased:<broker>', body: 'Rented out through an IP leasing broker.', practice: 'The registry names the landlord; report through the broker. See IP leasing above.' },
  { term: 'scanner:<name>', body: 'A known internet scanner\'s published range (MISP warninglists).', practice: 'Background noise, not a targeted attack; see Internet scanner above.' },
  { term: 'crawler:<name>', body: 'A search or AI crawler\'s published range: Googlebot, GPTBot.', practice: 'A bot fetching pages. Something claiming to be Googlebot from elsewhere is not.' },
  { term: 'service:<name>', body: 'A service\'s published addresses: Zscaler, Microsoft 365, GitHub, Salesforce, a Cisco Umbrella block page, big mail providers.', practice: 'Zscaler means a corporate user behind its proxy; an Umbrella block page means a DNS filter refused the name.' },
  { term: 'relay:icloud', body: 'An Apple iCloud Private Relay egress.', practice: 'A person on an Apple device, roughly where Apple says; see iCloud Private Relay above.' },
  { term: 'public-dns', body: 'A DNS resolver that answers anyone (MISP warninglists).', practice: 'Normal as a destination on port 53; as a source of floods, a reflector in a DNS amplification attack.' },
  { term: 'sinkhole', body: 'A known sinkhole for seized malicious domains.', practice: 'A device talking to it is probably infected; see Sinkhole above.' },
  { term: 'parking', body: 'A domain-parking service.', practice: 'The domain is parked, not a working site.' },
  { term: 'bogon', body: 'Unallocated or reserved space (Team Cymru).', practice: 'Spoofed if unannounced, hijacked if announced; see Bogon above.' },
  { term: 'anonymised-holder', body: 'The registry record withholds who holds the block.', practice: 'Contact the network carrying it instead; the holder cannot be reached directly.' },
];

const RANGE_PRACTICE = {
  broadband: 'A person at home: dynamic addresses, attribute by exact time.',
  mobile: 'A phone behind CGNAT: shared addresses; the ISP needs port and time.',
  cgnat: 'Shared by many subscribers: never block it for one user\'s behaviour.',
  hosting: 'A server in an otherwise non-hosting network: a machine, not a person.',
};

// tagGlossary is the kinds of network a prefix, a block or an AS can be
// tagged with.
// glossaryTerm names the glossary entry explaining a tag or blocklist entry
// as the page shows it ("hosting", "cloud:aws", "spamhaus-drop:SBL1",
// "Spamhaus ASN-DROP", "leased:ipxo"), or '' when there is none.
export function glossaryTerm(tag) {
  const t = String(tag || '');
  const [kind] = t.split(':');
  const lists = {
    'spamhaus-drop': 'Spamhaus DROP',
    ipsum: 'IPsum',
    'firehol-level2': 'FireHOL',
    'firehol-level3': 'FireHOL',
    feodo: 'Botnet C2',
    c2intel: 'Botnet C2',
    threatfox: 'Botnet C2',
  };
  if (lists[kind]) return lists[kind];
  const labels = [
    [/^Spamhaus ASN-DROP|^ASN-DROP/, 'Spamhaus ASN-DROP'],
    [/^Spamhaus DROP|^Contains DROP/, 'Spamhaus DROP'],
    [/^FireHOL/, 'FireHOL'],
    [/^C2 · /, 'Botnet C2'],
  ];
  for (const [re, term] of labels) if (re.test(t)) return term;
  const terms = tagGlossary().terms.map((x) => x.term);
  if (terms.includes(t)) return t;
  const family = `${kind}:<`;
  return terms.find((x) => x.startsWith(family)) || '';
}

export function tagGlossary() {
  const op = Object.entries(OPERATOR_TAGS).map(([tag, what]) => ({
    term: tag,
    body: `${what[0].toUpperCase()}${what.slice(1)}. A tag on the network, not each address in it.`,
    practice: TAG_PRACTICE[tag] ? [TAG_PRACTICE[tag]] : undefined,
  }));
  const range = Object.entries(RANGE_TAGS).map(([tag, what]) => ({
    term: `range:${tag}`,
    body: `Inferred by asname from the block's netname: ${what.replace(/\s+/g, ' ')}`,
    practice: RANGE_PRACTICE[tag] ? [RANGE_PRACTICE[tag]] : undefined,
  }));
  const special = SPECIAL_TAGS.map((t) => ({ ...t, practice: [t.practice] }));
  return {
    section: 'Kinds of network (tags)',
    intro: 'What kind of network an address is on. Filled tags come from published lists; outlined ones are inferred by asname from names, and say so.',
    terms: [...special, ...op, ...range].sort((a, b) => a.term.localeCompare(b.term)),
  };
}
