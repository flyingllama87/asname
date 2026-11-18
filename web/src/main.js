// The asname web UI: lookups, searches and database updates against the
// local asname REST API. Everything is rendered with lit's html templates,
// which escape every value; nothing from the API is ever parsed as HTML
// (org and network names come from public registries, so they are untrusted).

import '@ibm/plex-sans/css/ibm-plex-sans-default.min.css';
import '@ibm/plex-mono/css/ibm-plex-mono-default.min.css';
import './styles.scss';

// Only the elements the page uses; each index.js pulls in a whole family.
import '@carbon/web-components/es/components/ui-shell/header.js';
import '@carbon/web-components/es/components/ui-shell/header-name.js';
import '@carbon/web-components/es/components/ui-shell/header-global-action.js';
import '@carbon/web-components/es/components/tabs/tabs.js';
import '@carbon/web-components/es/components/tabs/tab.js';
import '@carbon/web-components/es/components/button/button.js';
import '@carbon/web-components/es/components/textarea/textarea.js';
import '@carbon/web-components/es/components/text-input/text-input.js';
import '@carbon/web-components/es/components/toggle/toggle.js';
import '@carbon/web-components/es/components/checkbox/checkbox.js';
import '@carbon/web-components/es/components/select/select.js';
import '@carbon/web-components/es/components/select/select-item.js';
import '@carbon/web-components/es/components/number-input/number-input.js';
import '@carbon/web-components/es/components/notification/inline-notification.js';
import '@carbon/web-components/es/components/notification/actionable-notification.js';
import '@carbon/web-components/es/components/notification/actionable-notification-button.js';
import '@carbon/web-components/es/components/tag/tag.js';
import '@carbon/web-components/es/components/inline-loading/inline-loading.js';
import '@carbon/web-components/es/components/modal/modal.js';
import '@carbon/web-components/es/components/modal/modal-header.js';
import '@carbon/web-components/es/components/modal/modal-heading.js';
import '@carbon/web-components/es/components/modal/modal-close-button.js';
import '@carbon/web-components/es/components/modal/modal-body.js';
import '@carbon/web-components/es/components/modal/modal-footer.js';
import '@carbon/web-components/es/components/modal/modal-footer-button.js';
import '@carbon/web-components/es/components/data-table/table.js';
import '@carbon/web-components/es/components/data-table/table-head.js';
import '@carbon/web-components/es/components/data-table/table-header-row.js';
import '@carbon/web-components/es/components/data-table/table-header-cell.js';
import '@carbon/web-components/es/components/data-table/table-body.js';
import '@carbon/web-components/es/components/data-table/table-row.js';
import '@carbon/web-components/es/components/data-table/table-cell.js';
import '@carbon/web-components/es/components/radio-button/radio-button-group.js';
import '@carbon/web-components/es/components/radio-button/radio-button.js';
import CDSToggletip from '@carbon/web-components/es/components/toggle-tip/toggletip.js';
import '@carbon/web-components/es/components/accordion/accordion.js';
import '@carbon/web-components/es/components/accordion/accordion-item.js';
import '@carbon/web-components/es/components/combo-box/combo-box.js';
import '@carbon/web-components/es/components/combo-box/combo-box-item.js';
import '@carbon/web-components/es/components/multi-select/multi-select.js';
import '@carbon/web-components/es/components/multi-select/multi-select-item.js';

import { iconLoader } from '@carbon/web-components/es/globals/internal/icon-loader.js';
import Asleep20 from '@carbon/icons/es/asleep/20.js';
import Light20 from '@carbon/icons/es/light/20.js';
import Settings20 from '@carbon/icons/es/settings/20.js';
import Help16 from '@carbon/icons/es/help/16.js';

import { html, nothing, render } from 'lit';

// Carbon's toggletip, with autoalign, scrolls its button to the middle of
// the screen whenever it re-renders, open or not, so a page full of (i)s
// jumps to the last one drawn. Place it only while open, without scrolling.
{
  const place = CDSToggletip.prototype.updated;
  CDSToggletip.prototype.updated = function (...args) {
    if (!this.open) return;
    const button = this._toggletipButton;
    if (button) button.scrollIntoView = () => {};
    try {
      place.apply(this, args);
    } finally {
      if (button) delete button.scrollIntoView;
    }
  };
}
import { api, ApiError, getApiBase, setApiBase } from './api.js';
import { extractTargets } from './targets.js';
import { COUNTRIES, countryName } from './countries.js';
import { asnList, csvText, prefixList, tableText } from './searchcopy.js';
import { GLOSSARY, LABEL_TERMS, glossaryMentions, glossaryTerm, sourceTerms, tagGlossary } from './glossary.js';
import {
  DEFAULT_FILTERS,
  REPUTATIONS,
  SORTS,
  exploreCSV,
  exploreTable,
  fmtCount,
  fmtPct,
  fromParams,
  toParams,
} from './explore.js';
import {
  asnReputationHelp,
  categoryTagHelp,
  COLUMN_HELP,
  CONTROL_HELP,
  FIELD_HELP,
  findings,
  reputationTagHelp,
  summaryText,
  whereIs,
  whoIs,
  blockOwner,
  SOURCES_HELP,
} from './help.js';

const THEME_KEY = 'asname.theme';

// Preferences saved in this browser from Settings: the address family every
// screen starts with ('any', 'v4' or 'v6'), and whether lookups ask for
// reverse DNS by default.
const PREFS_KEY = 'asname.prefs';
const FAMILY_NAMES = { any: 'IPv4 and IPv6', v4: 'IPv4 only', v6: 'IPv6 only' };
function loadPrefs() {
  const prefs = { family: 'v4', rdns: false };
  try {
    const saved = JSON.parse(localStorage.getItem(PREFS_KEY) || '{}');
    if (FAMILY_NAMES[saved.family]) prefs.family = saved.family;
    prefs.rdns = !!saved.rdns;
  } catch {}
  return prefs;
}
function savePrefs(prefs) {
  try {
    localStorage.setItem(PREFS_KEY, JSON.stringify(prefs));
  } catch {}
}
const prefs = loadPrefs();
DEFAULT_FILTERS.family = prefs.family;
const PREFIX_PREVIEW = 50;

// Rough download sizes, shown for optional databases not yet built.
const SIZE_HINTS = {
  city: '~125 MB download',
  netblock: '~370 MB of RIR whois dumps',
  category: '~3 MB',
  reputation: '~10 MB',
};

// Where each field of a lookup comes from, as `asname -p` prints them.
const SRC = {
  rib: 'BGP RIB dump (RouteViews or RIPE RIS), offline',
  asNames: 'RIPE NCC AS names list (asn.txt), offline',
  rir: 'RIR delegation stats (ARIN, RIPE NCC, APNIC, LACNIC, AFRINIC), offline',
  cityOf: (who) => (who === 'DB-IP' ? 'DB-IP City Lite geolocation, offline' : `${who} City geolocation, offline`),
  geofeed: "The network's own RFC 8805 geofeed, named by its registry range, offline",
  netblock: 'RIR WHOIS dumps, offline',
  netblockCountry: 'Netblock registration in RIR WHOIS dumps (RIPE NCC, APNIC, AFRINIC), offline',
  whois: 'Live WHOIS (IANA referral to the RIR)',
  rdap: 'Live RDAP (IANA bootstrap to the RIR)',
  online: 'Live RDAP, or WHOIS if RDAP fails',
  category: 'Cloud provider ranges (incl. Azure Service Tags), Tor exits, VPN server lists, iCloud Private Relay, MISP warninglists, Team Cymru bogons, bgp.tools tags, PeeringDB, offline',
  relay: 'Apple iCloud Private Relay egress ranges, offline',
  special: 'IANA special-purpose address registries (RFC 6890), built in',
  inferredName: "asname's rules on words in the AS name (inferrules.yaml), offline",
  inferredList: "asname's list of well-known networks (inferrules.yaml), offline",
  inferredNetname: "asname's rules on the registry netname (inferrules.yaml), offline",
  rdns: 'Live DNS PTR query',
  rep: 'Spamhaus DROP and ASN-DROP, IPsum, FireHOL level 2 and 3, abuse.ch Feodo Tracker and ThreatFox, C2IntelFeeds, offline',
  ripeStat: 'Live RIPEstat announced-prefixes API',
};

// Refresh ages offered on the Databases tab, in hours; 0 is never.
const MAX_AGE_CHOICES = [
  [24, '1 day'],
  [72, '3 days'],
  [168, '7 days'],
  [336, '14 days'],
  [720, '30 days (default)'],
  [1440, '60 days'],
  [2160, '90 days'],
  [0, 'Never'],
];

const state = {
  tab: 'lookup',
  theme: initialTheme(),
  status: null,
  statusError: '',
  lookup: {
    input: '',
    rdns: prefs.rdns,
    online: null, // null: the server's default
    loading: false,
    error: '',
    results: [],
    errors: [],
    ran: '',
    asked: { rdns: false, online: false },
    showAll: {},
    copied: '',
    // extracted says how many targets were found in pasted text that was
    // not a plain list, for the note under the box.
    extracted: 0,
  },
  search: {
    q: '',
    scope: 'all',
    limit: 500,
    family: prefs.family,
    loading: false,
    error: '',
    data: null,
    fuzzy: false,
    ranFuzzy: false,
    // country is a two-letter code, or '' for worldwide.
    country: '',
    sort: { asns: null, blocks: null },
    copied: '',
  },
  db: { selected: new Set(), busy: false, error: '', notice: '', saving: '', settingsError: '', openSources: new Set() },
  settings: { open: false, base: getApiBase(), testing: false, result: null, family: prefs.family, rdns: prefs.rdns },
  api: { open: false, copied: '' },
  help: { open: false },
  glossary: { filter: '', focus: '' },
  // gpanel is the glossary side panel: the entries opened, newest last.
  gpanel: { stack: [] },
  explore: { f: { ...DEFAULT_FILTERS, tag: [] }, loading: false, error: '', data: null, allTags: [], copied: '', ran: '' },
};

let lookupAbort = null;
let searchAbort = null;
let pollTimer = null;
let wasRunning = false;

// ---------- theme ----------

function initialTheme() {
  try {
    const saved = localStorage.getItem(THEME_KEY);
    if (saved === 'light' || saved === 'dark') return saved;
  } catch {
    // Storage blocked: follow the system.
  }
  return window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function applyTheme() {
  const root = document.documentElement;
  root.classList.toggle('cds--g100', state.theme === 'dark');
  root.classList.toggle('cds--white', state.theme !== 'dark');
  root.style.colorScheme = state.theme;
}

function toggleTheme() {
  state.theme = state.theme === 'dark' ? 'light' : 'dark';
  try {
    localStorage.setItem(THEME_KEY, state.theme);
  } catch {
    // The choice lasts for this page only.
  }
  applyTheme();
  update();
}

// ---------- routing ----------
// #/lookup?q=…  #/search?q=…  #/databases  #/api (the API panel over Lookup)

function parseHash() {
  const raw = location.hash.replace(/^#\/?/, '');
  const [path, query = ''] = raw.split('?');
  const tab = ['lookup', 'search', 'explore', 'databases', 'glossary'].includes(path) ? path : 'lookup';
  const p = new URLSearchParams(query);
  return {
    tab,
    q: p.get('q') || '',
    fuzzy: p.get('fuzzy') === '1',
    country: (p.get('country') || '').toUpperCase(),
    panel: path === 'api' || path === 'help' ? path : '',
    params: p,
  };
}

function go(hash) {
  if (location.hash === hash) route();
  else location.hash = hash;
}

function route() {
  const { tab, q, fuzzy, country, panel, params } = parseHash();
  state.tab = tab;
  if (panel === 'api') state.api.open = true;
  if (panel === 'help') state.help.open = true;
  if (tab === 'lookup' && q) {
    state.lookup.input = q;
    runLookup(q);
  } else if (tab === 'search' && q) {
    state.search.q = q;
    state.search.fuzzy = fuzzy;
    state.search.country = country;
    runSearch();
  } else if (tab === 'glossary' && !params.get('t')) {
    state.glossary.focus = '';
  } else if (tab === 'glossary' && params.get('t')) {
    focusGlossary(params.get('t'));
    return;
  } else if (tab === 'explore') {
    const x = state.explore;
    x.f = fromParams(params);
    const key = toParams(x.f).toString();
    if (key !== x.ran || !x.data) runExplore();
  }
  update();
}

// ---------- API calls ----------

function errorText(err) {
  return err instanceof ApiError ? err.message : String(err?.message || err);
}

function targetsOf(text) {
  return extractTargets(text).targets;
}

// onlineAvailable reports which online lookups this server allows.
function onlineAvailable() {
  const o = state.status?.online;
  return { whois: !!o?.whois_available, prefixes: !!o?.prefixes_available };
}

// onlineOn is whether the Online lookups toggle is on: the user's choice,
// or the server's default until they make one.
function onlineOn() {
  if (state.lookup.online !== null) return state.lookup.online;
  const o = state.status?.online;
  return !!(o?.whois_default || o?.prefixes_default);
}

async function runLookup(text) {
  const targets = targetsOf(text);
  const l = state.lookup;
  if (!targets.length) return;
  lookupAbort?.abort();
  lookupAbort = new AbortController();
  const { signal } = lookupAbort;
  const avail = onlineAvailable();
  const on = onlineOn();
  // Only name the lookups the server allows; asking for one it has turned
  // off is an error.
  const online = {
    whois: avail.whois ? on : undefined,
    prefixes: avail.prefixes ? on : undefined,
  };
  Object.assign(l, {
    loading: true,
    error: '',
    results: [],
    errors: [],
    ran: text,
    showAll: {},
    asked: { rdns: l.rdns, online: on && (avail.whois || avail.prefixes) },
  });
  update();
  try {
    const data =
      targets.length === 1
        ? await api.lookup(targets[0], { reverseDNS: l.rdns, online, family: prefs.family, signal })
        : await api.bulk(targets, { reverseDNS: l.rdns, online, family: prefs.family, signal });
    l.results = data?.results || [];
    l.errors = data?.errors || [];
  } catch (err) {
    if (err.name === 'AbortError') return;
    l.error = errorText(err);
  }
  l.loading = false;
  update();
}

async function runSearch() {
  const s = state.search;
  if (!s.q.trim()) return;
  searchAbort?.abort();
  searchAbort = new AbortController();
  Object.assign(s, { loading: true, error: '', data: null, ranFuzzy: s.fuzzy, ranScope: s.scope, ranCountry: s.country, copied: '' });
  update();
  try {
    s.data = await api.search(
      { q: s.q.trim(), scope: s.scope, limit: s.limit, family: s.family, fuzzy: s.fuzzy, country: s.country },
      { signal: searchAbort.signal },
    );
  } catch (err) {
    if (err.name === 'AbortError') return;
    s.error = errorText(err);
  }
  s.loading = false;
  update();
}

// refreshStatus polls /v1/status on every tab: the banner and the online
// toggle need it too. Every 2 s while an update runs, else every 15 s.
async function refreshStatus() {
  clearTimeout(pollTimer);
  try {
    state.status = await api.status();
    state.statusError = '';
  } catch (err) {
    state.statusError = errorText(err);
  }
  const running = !!state.status?.update?.running;
  if (wasRunning && !running) {
    const job = state.status.update;
    state.db.notice = job.error
      ? ''
      : `Update finished${job.reloaded ? '; lookups now use the new databases' : ''}.`;
  }
  wasRunning = running;
  update();
  scrollLogToEnd();
  pollTimer = setTimeout(refreshStatus, running ? 2000 : 15000);
}

async function startUpdate(body) {
  const d = state.db;
  Object.assign(d, { busy: true, error: '', notice: '' });
  update();
  try {
    await api.update(body);
  } catch (err) {
    d.error = errorText(err);
  }
  d.busy = false;
  await refreshStatus();
}

async function cancelUpdate() {
  try {
    await api.cancelUpdate();
  } catch (err) {
    state.db.error = errorText(err);
  }
  await refreshStatus();
}

async function saveSetting(name, body) {
  const d = state.db;
  Object.assign(d, { saving: name, settingsError: '' });
  update();
  try {
    state.status = await api.saveSettings(body);
  } catch (err) {
    d.settingsError = errorText(err);
  }
  d.saving = '';
  update();
}

let logPinned = true;
function scrollLogToEnd() {
  const log = document.querySelector('.log');
  if (log && logPinned) log.scrollTop = log.scrollHeight;
}

async function copyJSON(value) {
  try {
    await navigator.clipboard.writeText(JSON.stringify(value, null, 2));
  } catch {
    state.lookup.error = 'The browser refused clipboard access; copy from the developer tools instead.';
    update();
  }
}

// ---------- formatting ----------

function fmtBytes(n) {
  if (!n) return '';
  const units = ['B', 'KB', 'MB', 'GB'];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i++;
  }
  return `${n.toFixed(i ? 1 : 0)} ${units[i]}`;
}

function fmtAge(seconds) {
  if (seconds == null) return '';
  const m = Math.round(seconds / 60);
  if (m < 1) return 'just now';
  if (m < 60) return `${m} min ago`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h} h ago`;
  const d = Math.round(h / 24);
  if (d < 60) return `${d} days ago`;
  if (d < 730) return `${Math.round(d / 30.4)} months ago`;
  return `${Math.round(d / 365.25)} years ago`;
}

function fmtDate(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

function fmtHours(h) {
  if (!h) return 'never';
  if (h % 24 === 0) return h === 24 ? '1 day' : `${h / 24} days`;
  return `${h} hours`;
}

function countryText(c) {
  if (!c) return '';
  return c.name && c.name !== c.code ? `${c.name} (${c.code})` : c.code;
}

// ---------- sorting ----------

function ipv4Number(ip) {
  const p = String(ip).split('.');
  if (p.length !== 4) return null;
  return p.reduce((n, x) => n * 256 + Number(x), 0);
}

const blank = (v) => v === '' || v == null;

function compareValues(a, b) {
  if (typeof a === 'number' && typeof b === 'number') return a - b;
  return String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: 'base' });
}

// sortRows orders rows by one column; blanks stay last whichever way it
// sorts, and equal rows keep the server's order.
function sortRows(rows, sort, getters) {
  if (!sort || sort.dir === 'none' || !getters[sort.key]) return rows;
  const get = getters[sort.key];
  const m = sort.dir === 'descending' ? -1 : 1;
  return rows
    .map((row, i) => ({ row, i, v: get(row) }))
    .sort((x, y) => {
      if (blank(x.v) !== blank(y.v)) return blank(x.v) ? 1 : -1;
      return (blank(x.v) ? 0 : compareValues(x.v, y.v) * m) || x.i - y.i;
    })
    .map((x) => x.row);
}

// sortHeader is a header cell that sorts its table when clicked. Carbon's
// table would reorder the rows itself, behind lit's back, so the event is
// taken here and the rows are rendered in order instead.
function sortHeader(table, key, label, help) {
  const sort = state.search.sort[table];
  const dir = sort?.key === key ? sort.dir : 'none';
  return html`<cds-table-header-cell
    is-sortable
    sort-direction=${dir}
    @cds-table-header-cell-sort=${(e) => {
      e.preventDefault();
      e.stopPropagation();
      state.search.sort[table] = { key, dir: e.detail.sortDirection };
      update();
    }}><span class="th-label">${label}${help ? tip(label, help) : nothing}</span></cds-table-header-cell>`;
}

// ---------- views ----------

const asnLink = (asn, label) =>
  html`<button class="linkish mono" type="button" title="Look up ${asn}" @click=${() => go(`#/lookup?q=${encodeURIComponent(asn)}`)}>${label ?? asn}</button>`;

// field is one labelled value on a result card, with where it came from
// and an (i) explaining it.
const field = (label, body, source, help) =>
  body === nothing || body === '' || body == null
    ? nothing
    : html`<div class="field">
        <dt>
          ${termLink(label)}${source ? html` <span class="source">${source}</span>` : nothing}
          ${help ? tip(label, help) : nothing}
        </dt>
        <dd>${body}</dd>
      </div>`;

const unknown = (text = 'Unknown') => html`<span class="muted">${text}</span>`;

function headerView() {
  const dark = state.theme === 'dark';
  return html`
    <cds-header aria-label="asname">
      <cds-header-name href="#/lookup">asname</cds-header-name>
      <div class="header-global">
        ${state.status?.version ? html`<span class="header-version">${state.status.version}</span>` : nothing}
        <button class="header-api" type="button" title="How to read the results" @click=${openHelp}>Help</button>
        <a class="header-api" href="#/glossary" title="What the terms mean">Glossary</a>
        <button class="header-api" type="button" title="The HTTP API behind this page" @click=${openAPI}>API</button>
        <cds-header-global-action
          aria-label=${dark ? 'Switch to light theme' : 'Switch to dark theme'}
          tooltip-text=${dark ? 'Light theme' : 'Dark theme'}
          tooltip-alignment="right"
          @click=${toggleTheme}>
          ${iconLoader(dark ? Light20 : Asleep20, { slot: 'icon' })}
        </cds-header-global-action>
        <cds-header-global-action
          aria-label="Settings"
          tooltip-text="Settings"
          tooltip-alignment="right"
          @click=${openSettings}>
          ${iconLoader(Settings20, { slot: 'icon' })}
        </cds-header-global-action>
      </div>
    </cds-header>
  `;
}

let tabByPointer = false;

function tabsView() {
  return html`
    <cds-tabs
      class="tabs"
      value=${state.tab}
      @pointerdown=${() => (tabByPointer = true)}
      @keydown=${() => (tabByPointer = false)}
      @cds-tabs-selected=${(e) => {
        go(`#/${e.detail.item.value}`);
        // A click leaves Carbon's focus box on the tab; keyboard users
        // keep it.
        if (tabByPointer) requestAnimationFrame(() => e.detail.item.blur());
      }}>
      <cds-tab value="lookup">Lookup</cds-tab>
      <cds-tab value="search">Search</cds-tab>
      <cds-tab value="explore">Explore</cds-tab>
      <cds-tab value="databases">Databases</cds-tab>
    </cds-tabs>
  `;
}

function errorNote(title, subtitle) {
  return html`<cds-inline-notification kind="error" low-contrast hide-close-button title=${title} subtitle=${subtitle}></cds-inline-notification>`;
}

// databaseIssues sorts what needs attention out of /v1/status.
function databaseIssues(st) {
  const dbs = st?.store?.databases || [];
  return {
    missing: dbs.filter((d) => !d.present && !d.optional),
    stale: dbs.filter((d) => d.present && d.stale),
    incomplete: dbs.filter((d) => d.present && (d.missing?.length || d.last_error)),
  };
}

// bannerView warns on every tab when a database is missing, out of date or
// incomplete, or when an update is running.
function bannerView() {
  const st = state.status;
  if (!st) {
    return state.statusError ? errorNote('Cannot reach asname', state.statusError) : nothing;
  }
  if (st.update?.running) {
    return state.tab === 'databases'
      ? nothing
      : html`<cds-actionable-notification inline kind="info" low-contrast hide-close-button
          title="Updating databases"
          subtitle="Lookups keep answering from the current files until the update finishes.">
          <cds-actionable-notification-button slot="action" @click=${() => go('#/databases')}>Follow it</cds-actionable-notification-button>
        </cds-actionable-notification>`;
  }
  const { missing, stale, incomplete } = databaseIssues(st);
  if (!missing.length && !stale.length && !incomplete.length) return nothing;
  const names = (list) => list.map((d) => d.name).join(', ');
  const parts = [];
  if (missing.length) parts.push(`Missing: ${names(missing)}.`);
  if (stale.length) parts.push(`Older than ${fmtHours(st.store.max_age_hours)}: ${names(stale)}.`);
  if (incomplete.length) parts.push(`The last update left out part of ${names(incomplete)}.`);
  const kind = missing.length ? 'error' : 'warning';
  const title = missing.length ? 'Databases are missing' : stale.length ? 'Databases are out of date' : 'Databases are incomplete';
  return html`<cds-actionable-notification inline kind=${kind} low-contrast hide-close-button title=${title} subtitle=${parts.join(' ')}>
    ${state.tab === 'databases'
      ? nothing
      : html`<cds-actionable-notification-button slot="action" @click=${() => go('#/databases')}>Review databases</cds-actionable-notification-button>`}
  </cds-actionable-notification>`;
}

// tip is an (i) that opens an explanation; body is text or a template.
function tip(label, body, alignment = 'bottom-start') {
  return html`<cds-toggletip class="tip" autoalign alignment=${alignment} button-label="About ${label}">
    <div slot="body-text" class="tip-body">${body}</div>
  </cds-toggletip>`;
}

// tagList explains each tag shown, under the field's own explanation.
function tagList(intro, items) {
  return html`<p>${intro}</p>
    ${items.length ? html`<dl class="tip-tags">${items.map(([k, v]) => html`<dt>${k}</dt><dd>${v}</dd>`)}</dl>` : nothing}`;
}

// switchWithTip is a compact switch with its label beside it and an (i).
function switchWithTip(label, checked, onChange, help, disabled = false) {
  return html`<span class="switch">
    <cds-toggle .hideLabel=${true} label-text=${label} ?checked=${checked} ?disabled=${disabled} @cds-toggle-changed=${onChange}></cds-toggle>
    ${tip(label, help)}
  </span>`;
}

// Lookup

function lookupView() {
  const l = state.lookup;
  const avail = onlineAvailable();
  const submit = () => {
    const text = document.getElementById('lookup-input')?.value ?? l.input;
    const { targets, extracted } = extractTargets(text);
    // Pasted text that was not a plain list is replaced by what was found
    // in it, so the box shows exactly what is looked up.
    l.extracted = extracted ? targets.length || -1 : 0;
    l.input = extracted ? targets.join('\n') : text;
    if (targets.length) go(`#/lookup?q=${encodeURIComponent(targets.join('\n'))}`);
    else update();
  };
  return html`
    <p class="lede">
      Intelligence on ${termLink('IP addresses', 'IP address')} and the networks (${termLink('ASNs', 'ASN')}) that hold them. A hostname or
      URL is resolved to its IP addresses and those are assessed, not the domain or the page itself. Answers come from the local databases.
    </p>
    <div class="form">
      <cds-textarea
        id="lookup-input"
        label="Targets"
        rows="4"
        placeholder="8.8.8.8&#10;dns.google&#10;AS13335"
        helper-text=${l.extracted < 0
          ? 'No IP addresses, URLs, domains or ASNs found in that text.'
          : l.extracted
          ? `Found ${l.extracted} target${l.extracted === 1 ? '' : 's'} in the pasted text. Ctrl+Enter to look up.`
          : 'Paste a list, a log or a page: IPs, URLs, domains and ASNs are picked out. Ctrl+Enter to look up.'}
        .value=${l.input}
        @input=${(e) => {
          l.input = e.target.value;
          l.extracted = 0;
        }}
        @keydown=${(e) => {
          if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
            e.preventDefault();
            submit();
          }
        }}></cds-textarea>
      <div class="form-row controls-row">
        ${switchWithTip('Reverse DNS', l.rdns, (e) => (l.rdns = e.target.checked), CONTROL_HELP.rdns)}
        ${avail.whois || avail.prefixes
          ? switchWithTip('Online lookups', onlineOn(), (e) => {
              l.online = e.target.checked;
              update();
            }, CONTROL_HELP.online)
          : switchWithTip('Online lookups', false, () => {}, CONTROL_HELP.onlineOff, true)}
        <cds-button @click=${submit} ?disabled=${l.loading}>Look up</cds-button>
        ${prefs.family !== 'any'
          ? html`<span class="meta">Hostnames: ${FAMILY_NAMES[prefs.family]} <a href="#" @click=${(e) => (e.preventDefault(), openSettings())}>(Settings)</a></span>`
          : nothing}
        ${l.loading ? html`<cds-inline-loading status="active">Looking up…</cds-inline-loading>` : nothing}
      </div>
    </div>
    <div class="notifications">
      ${l.error ? errorNote('Lookup failed', l.error) : nothing}
      ${l.copied ? html`<cds-inline-notification kind="success" low-contrast hide-close-button title=${l.copied}></cds-inline-notification>` : nothing}
      ${l.errors.map((e) => errorNote(e.target, e.error))}
    </div>
    <div class="results">
      ${l.results.map((r, i) => resultCard(r, i))}
      ${!l.loading && l.ran && !l.error && !l.results.length && !l.errors.length
        ? html`<p class="empty">No results.</p>`
        : nothing}
    </div>
  `;
}

async function copySummary(r) {
  const l = state.lookup;
  try {
    await navigator.clipboard.writeText(summaryText(r, state.status?.loaded || {}));
    l.copied = `Copied the summary of ${r.target || r.ip}.`;
  } catch {
    l.error = 'The browser refused clipboard access.';
  }
  update();
  setTimeout(() => {
    l.copied = '';
    update();
  }, 3000);
}

const LEVEL_LABEL = { high: 'High', medium: 'Warning', info: 'Note', ok: 'OK' };

function findingsView(r, loaded) {
  const who = whoIs(r);
  const where = whereIs(r);
  const points = findings(r, loaded);
  if (!who && !where && !points.length) return nothing;
  const worst = points[0]?.level || 'info';
  return html`<section class="findings findings-${worst}" aria-label="What this means">
    <h4>What this means</h4>
    ${who || where
      ? html`<dl class="answers">
          ${who ? html`<div class="answer"><dt>Who</dt><dd>${linkTerms(who)}</dd></div>` : nothing}
          ${where ? html`<div class="answer"><dt>Where</dt><dd>${linkTerms(where)}</dd></div>` : nothing}
        </dl>`
      : nothing}
    ${points.length
      ? html`<ul>
          ${points.map((f) => html`<li class="finding finding-${f.level}"><span class="level">${LEVEL_LABEL[f.level]}</span><span>${linkTerms(f.text)}</span></li>`)}
        </ul>`
      : nothing}
  </section>`;
}

function resultCard(r, i) {
  const l = state.lookup;
  const loaded = state.status?.loaded || {};
  const rep = r.reputation;
  // Red means the address is listed, or its whole ASN is on Spamhaus
  // ASN-DROP; a few listed addresses in a large ASN are only noted.
  const listed = rep?.listed || rep?.asn?.spamhaus_asn_drop;
  const isASN = !r.ip;
  const title = r.target || r.ip || r.asn?.asn_string || 'result';
  const sub = [r.ip && r.ip !== title ? r.ip : '', r.host ?? '', r.version ? `IPv${r.version}` : '']
    .filter(Boolean)
    .join(' · ');

  if (r.error) {
    return html`<article class="card listed">
      <div class="card-head"><span class="card-title">${title}</span></div>
      ${errorNote('No answer', r.error)}
    </article>`;
  }

  const nb = r.netblock;
  const nbCountry = nb?.country && nb.country.code !== r.country?.code ? nb.country : null;
  const prefixes = r.prefixes?.list || [];
  const shown = l.showAll[i] ? prefixes : prefixes.slice(0, PREFIX_PREVIEW);
  const avail = onlineAvailable();
  const sources = [];

  // ASN and organisation
  const asnBody = r.asn
    ? r.asn.announced === false
      ? unknown(r.asn.no_ipv6_routes ? 'Unknown: no IPv6 routes in this server\'s ASN database' : 'Not announced')
      : html`${asnLink(r.asn.asn_string || `AS${r.asn.number}`)} ${r.asn.name || ''}
        ${r.asn.name_source === 'rdap' ? html`<span class="meta">live RDAP: not in the offline AS names list</span>` : nothing}`
    : nothing;
  const nameSrc = r.asn?.name_source === 'rdap' ? SRC.rdap : SRC.asNames;
  if (r.asn?.announced !== false) {
    if (!isASN) sources.push(['ASN', SRC.rib]);
    sources.push(['Organization', nameSrc]);
  }

  // Country: an address's comes from the RIR delegation, unless its
  // netblock names a different one; an ASN's from its AS name.
  let countryFields;
  if (isASN) {
    countryFields = field('Country', r.country ? countryText(r.country) : unknown(), 'AS registration', FIELD_HELP.countryASN);
    sources.push(['Country', nameSrc]);
  } else if (nbCountry) {
    countryFields = html`${field('Registered in', countryText(nbCountry), 'netblock registration', FIELD_HELP.countryNetblock)}
      ${field('Allocated in', r.country ? countryText(r.country) : unknown(), 'RIR allocation', FIELD_HELP.allocatedIn)}`;
    sources.push(['Registered in', SRC.netblockCountry], ['Allocated in', SRC.rir]);
  } else {
    countryFields = field('Country', r.country ? countryText(r.country) : unknown(), 'RIR registration', FIELD_HELP.countryRIR);
    sources.push(['Country', SRC.rir]);
  }

  // Location: DB-IP's estimate alone, or one row per answer when there is
  // more than one (the network's own geofeed, MaxMind's, DB-IP's).
  let cityBody = nothing;
  let cityLabel = 'City';
  let citySource = '';
  let cityHelp = FIELD_HELP.city;
  if (!isASN) {
    const rows = locationRows(r);
    if (rows.length > 1) {
      cityLabel = 'Location';
      citySource = rows.map((x) => x.label).join(', ');
      cityHelp = FIELD_HELP.location;
      cityBody = html`<div class="rep">
        ${rows.map((x) => html`<div class="rep-row"><span class="rep-label">${termLink(x.label)}</span><span title=${x.title || ''}>${x.name}</span></div>`)}
      </div>`;
    } else if (rows.length === 1 || loaded.city) {
      const only = rows[0];
      cityLabel = only?.label === 'Geofeed' ? 'Location' : 'City';
      citySource = only ? (only.label === 'Geofeed' ? "network's geofeed" : `${only.who} geolocation`) : 'geolocation';
      cityHelp = only?.label === 'Geofeed' ? FIELD_HELP.location : FIELD_HELP.city;
      cityBody = only ? only.name : unknown();
    }
    for (const x of rows) sources.push([`Location (${x.label})`, x.src]);
    if (r.special) sources.push(['Special-purpose', SRC.special]);
  }

  // Netblock: shown when the netblock database is loaded or the registry was asked online.
  const askedWhois = l.asked.online && avail.whois;
  let netblockBody = nothing;
  if (!isASN && nb) {
    const name = nb.organization || nb.raw;
    netblockBody = html`${name}
      <span class="meta">
        ${[nb.handle && nb.handle !== name ? nb.handle : '', nb.created ? `registered ${nb.created}` : '', nb.live_query ? `live ${nb.source === 'rdap' ? 'RDAP' : 'whois'}` : 'offline index']
          .filter(Boolean)
          .join(' · ')}
      </span>`;
    sources.push(['Netblock', nb.live_query ? (nb.source === 'rdap' ? SRC.rdap : SRC.whois) : SRC.netblock]);
  } else if (!isASN && r.special) {
    netblockBody = html`${unknown('No registry record')}<span class="meta">Special-purpose space (${r.special.rfc}): no one holds it</span>`;
  } else if (!isASN && (loaded.netblock || askedWhois)) {
    netblockBody = html`${unknown(askedWhois ? 'None found, offline or online' : 'Not in the offline index')}
      ${!askedWhois && avail.whois
        ? html`<span class="meta">Some registries (ARIN, LACNIC) don't publish this offline; turn on Online lookups to ask the registry.</span>`
        : nothing}`;
    sources.push(['Netblock', askedWhois ? `${SRC.netblock}; ${SRC.online}` : SRC.netblock]);
  }

  // Category
  const catTags = r.category?.tags || [];
  // asname's own tags: [{tag, from}], from "netname", "name" or "list".
  const inferredList = r.category?.inferred || [];
  const inferredTags = inferredList.map((t) => t.tag);
  const fromText = { netname: "the range's netname", netblock: "the block's registered owner", name: 'the AS name', list: "asname's list of known networks" };
  let categoryBody = nothing;
  const inferredView = inferredTags.length
    ? [...new Set(inferredList.map((t) => t.from))].map(
        (from) => html`<div class="tags inferred-tags">
          ${inferredList.filter((t) => t.from === from).map((t) => glossaryTag(html`<cds-tag size="sm" type="outline">${t.tag}</cds-tag>`, t.tag))}
          <span class="meta">inferred from ${fromText[from] || from}</span>
        </div>`,
      )
    : nothing;
  if (catTags.length) {
    categoryBody = html`<div class="tags">${catTags.map((t) => glossaryTag(html`<cds-tag size="sm" type=${isAddrTag(t) ? 'purple' : 'teal'}>${t}</cds-tag>`, t))}</div>${inferredView}`;
    sources.push(['Category', SRC.category]);
  } else if (inferredTags.length) {
    categoryBody = inferredView;
  } else if (loaded.category) {
    categoryBody = unknown();
    sources.push(['Category', SRC.category]);
  }
  for (const from of new Set(inferredList.map((t) => t.from))) {
    sources.push(['Inferred', from === 'list' ? SRC.inferredList : from === 'netname' ? SRC.inferredNetname : SRC.inferredName]);
  }
  const categoryHelp = tagList(
    FIELD_HELP.category,
    [...catTags, ...inferredTags.filter((t) => !catTags.includes(t))].map((t) => [inferredTags.includes(t) && !catTags.includes(t) ? `${t} (inferred)` : t, categoryTagHelp(t)]),
  );

  // Reputation
  const repHelp = rep
    ? tagList(FIELD_HELP.reputation, [
        ...(rep.lists || []).map((e) => [e, reputationTagHelp(e)]),
        ...(rep.asn ? [['ASN', asnReputationHelp(rep.asn)]] : []),
      ])
    : FIELD_HELP.reputation;
  if (rep) sources.push(['Reputation', SRC.rep]);

  // Reverse DNS: only when asked for.
  let rdnsBody = nothing;
  if (!isASN && l.asked.rdns) {
    rdnsBody = r.reverse_dns?.names?.length ? html`<span class="mono">${r.reverse_dns.names.join(', ')}</span>` : unknown('None');
    sources.push(['Reverse DNS', SRC.rdns]);
  }

  if (prefixes.length) sources.push(['Prefixes', r.prefixes.source === 'ripe-stat' ? SRC.ripeStat : SRC.rib]);

  // Who: the organisation the block is registered to, beside the network
  // that carries it, each with the tags that describe it.
  const owner = blockOwner(r);
  const isAddressTag = isAddrTag;
  const tagView = (t) => glossaryTag(html`<cds-tag size="sm" type=${isAddressTag(t) ? 'purple' : 'teal'}>${t}</cds-tag>`, t);
  const inferredGroup = (from) => {
    const list = inferredList.filter((t) => t.from === from);
    return list.length
      ? html`<div class="tags inferred-tags">
          ${list.map((t) => glossaryTag(html`<cds-tag size="sm" type="outline">${t.tag}</cds-tag>`, t.tag))}
          <span class="meta">inferred from ${fromText[from] || from}</span>
        </div>`
      : nothing;
  };
  const addrTags = catTags.filter(isAddressTag);
  const opTags = catTags.filter((t) => !isAddressTag(t));
  const helpFor = (tags, inferred) =>
    tagList(FIELD_HELP.category, [...tags.map((t) => [t, categoryTagHelp(t)]), ...inferred.map((t) => [`${t.tag} (inferred)`, categoryTagHelp(t.tag)])]);
  const ownerInferred = inferredList.filter((t) => t.from === 'netname' || t.from === 'netblock');
  const networkInferred = inferredList.filter((t) => t.from === 'name' || t.from === 'list');
  const asn = r.asn;
  const asnLine = asn && asn.announced !== false
    ? html`${asnLink(asn.asn_string || `AS${asn.number}`)}${asn.handle && asn.handle !== asn.asn_string ? html` · <span class="mono">${asn.handle}</span>` : nothing}${r.country && isASN ? html` · ${countryText(r.country)}` : nothing}`
    : nothing;
  const identity = html`<div class="identity ${isASN ? 'single' : ''}">
    ${isASN
      ? nothing
      : html`<section class="who">
          <div class="who-label">${termLink(owner?.distinct ? 'Registered to' : 'Netblock')} ${tip('Netblock', FIELD_HELP.netblock)}</div>
          ${nb ? html`<div class="who-name">${owner?.name || nb.raw}</div>` : html`<div class="who-name">${netblockBody === nothing ? unknown('No netblock data') : netblockBody}</div>`}
          ${nb
            ? html`<div class="meta">
                ${[owner?.handle, nb.created ? `registered ${nb.created}` : '', nb.live_query ? `live ${nb.source === 'rdap' ? 'RDAP' : 'whois'}` : 'offline index'].filter(Boolean).join(' · ')}
              </div>`
            : nothing}
          ${addrTags.length || ownerInferred.length
            ? html`<div class="who-tags">
                ${addrTags.length ? html`<div class="tags">${addrTags.map(tagView)}</div>` : nothing}
                ${inferredGroup('netblock')} ${inferredGroup('netname')}
                ${tip('These tags', helpFor(addrTags, ownerInferred))}
              </div>`
            : nothing}
        </section>`}
    <section class="who">
      <div class="who-label">${termLink(isASN ? 'Network' : owner?.distinct ? 'Carried by' : 'Network')} ${tip('ASN', FIELD_HELP.asn)}</div>
      <div class="who-name">${asn?.announced === false ? unknown(asn.no_ipv6_routes ? 'Unknown' : 'Not announced') : asn?.organization || asn?.name || unknown()}</div>
      ${asn?.no_ipv6_routes ? html`<div class="meta">This server's ASN database has no IPv6 routes</div>` : nothing}
      ${asnLine !== nothing ? html`<div class="meta">${asnLine}</div>` : nothing}
      ${asn?.name_source === 'rdap' ? html`<div class="meta">name from live RDAP: not in the offline AS names list</div>` : nothing}
      ${opTags.length || networkInferred.length
        ? html`<div class="who-tags">
            ${opTags.length ? html`<div class="tags">${opTags.map(tagView)}</div>` : nothing}
            ${inferredGroup('name')} ${inferredGroup('list')}
            ${tip('These tags', helpFor(opTags, networkInferred))}
          </div>`
        : loaded.category
          ? html`<div class="meta">No category known</div>`
          : nothing}
    </section>
  </div>`;

  return html`
    <article class="card ${listed ? 'listed' : ''}">
      <div class="card-head">
        <div>
          <div class="card-title">${title}</div>
          ${sub ? html`<div class="card-sub">${sub}</div>` : nothing}
          ${r.special
            ? html`<div class="card-cdn">${glossaryTag(html`<cds-tag size="sm" type="warm-gray">${r.special.rfc}</cds-tag>`, 'special-purpose')} ${r.special.name}, ${r.special.prefix}${r.special.globally_reachable === false ? ': not reachable on the internet' : ''}</div>`
            : nothing}
          ${r.nat64
            ? html`<div class="card-cdn">${glossaryTag(html`<cds-tag size="sm" type="warm-gray">NAT64</cds-tag>`, 'NAT64')} ${r.nat64.dns64 ? `the resolver answered ${r.nat64.address}, a made-up DNS64 address that carries this IPv4 address` : `${r.nat64.address} carries this IPv4 address`}</div>`
            : nothing}
          ${r.ipv6_skipped
            ? html`<div class="card-cdn"><cds-tag size="sm" type="warm-gray">IPv6</cds-tag> ${r.host} also has ${r.ipv6_skipped} IPv6 ${r.ipv6_skipped === 1 ? 'address' : 'addresses'}, not looked up: this server's ASN database has no IPv6 routes</div>`
            : nothing}
          ${r.served_by
            ? html`<div class="card-cdn">${glossaryTag(html`<cds-tag size="sm" type="warm-gray">Served by ${r.served_by.cdn}</cds-tag>`, 'CDN')} this is a CDN edge server, not ${r.host}'s own address</div>`
            : nothing}
        </div>
        <div class="card-actions">
          <cds-button kind="ghost" size="sm" @click=${() => copySummary(r)}>Copy summary</cds-button>
          <cds-button kind="ghost" size="sm" @click=${() => copyJSON(r)}>Copy JSON</cds-button>
        </div>
      </div>
      ${identity}
      <dl class="fields">
        ${countryFields}
        ${field(cityLabel, cityBody, citySource, cityHelp)}
        ${field('Reputation', rep ? reputationView(rep, isASN) : nothing, '', repHelp)}
        ${field('Reverse DNS', rdnsBody, '', FIELD_HELP.rdns)}
      </dl>
      ${findingsView(r, loaded)}
      ${r.prefixes
        ? html`<div class="prefixes">
            <h3>${termLink('Announced prefixes')} ${tip('Announced prefixes', FIELD_HELP.prefixes)}</h3>
            <div class="hint">
              ${r.prefixes.total} total · ${r.prefixes.ipv4_count} IPv4 · ${r.prefixes.ipv6_count} IPv6
              · ${r.prefixes.source === 'ripe-stat' ? 'live from RIPEstat' : 'offline index'}
              ${isASN && r.asn?.asn_string
                ? html`· <a href="#/search?q=${encodeURIComponent(r.asn.asn_string)}" title="Every registry netblock inside these prefixes: the AS's own and its customers'">Registry netblocks</a>
                    · <a href="#/explore?asn=${encodeURIComponent(r.asn.asn_string)}" title="These prefixes with their tags and blocklist hits">Explore</a>`
                : nothing}
            </div>
            ${shown.length ? html`<div class="prefix-list">${shown.map((p) => html`<span>${p}</span>`)}</div>` : nothing}
            ${prefixes.length > PREFIX_PREVIEW && !l.showAll[i]
              ? html`<cds-button kind="tertiary" size="sm" @click=${() => {
                  l.showAll[i] = true;
                  update();
                }}>Show all ${prefixes.length}</cds-button>`
              : nothing}
          </div>`
        : isASN
          ? html`<div class="prefixes hint">
              No announced prefixes${l.asked.online && avail.prefixes ? ', offline or from RIPEstat' : ' in the offline index'}${avail.prefixes && !l.asked.online ? '; turn on Online lookups to ask RIPEstat' : ''}.
            </div>`
          : nothing}
      ${sources.length
        ? html`<details class="sources">
            <summary>Data sources</summary>
            <p class="hint">${FIELD_HELP.sources}</p>
            <dl>${sources.map(([k, v]) => html`<div><dt>${k}</dt><dd>${linkTerms(v)}</dd></div>`)}</dl>
          </details>`
        : nothing}
    </article>
  `;
}

// asnSummary drops the ASN-DROP clause the tag beside it already says.
function asnSummary(asn) {
  const s = asn?.summary || '';
  return asn?.spamhaus_asn_drop ? s.replace(/^Spamhaus ASN-DROP(; )?/, '') : s;
}

// isAddrTag says whether a category tag is about the address itself rather
// than the network it is on.
function isAddrTag(t) {
  return t.includes(':') || ['tor-exit', 'anonymised-holder', 'public-dns', 'sinkhole', 'parking', 'bogon'].includes(t);
}

// listLabel names a blocklist entry ("ipsum:3", "spamhaus-drop:SBL123")
// the way the tags show it.
function listLabel(name) {
  const [list, detail] = name.split(':');
  switch (list) {
    case 'firehol-level2':
      return 'FireHOL L2 · 48 h';
    case 'firehol-level3':
      return 'FireHOL L3 · 30 d';
    case 'ipsum':
      return `IPsum · ${detail} lists`;
    case 'feodo':
      return `Feodo C2 · ${detail}`;
    case 'c2intel':
      return `C2 · ${detail}`;
    case 'threatfox':
      return `ThreatFox · ${detail}`;
    case 'spamhaus-drop':
      return detail ? `Spamhaus DROP · ${detail}` : 'Spamhaus DROP';
    default:
      return name;
  }
}

// reputationView shows what the blocklists say in two rows, the address
// and its network, each as tags in one style, with the network's counts.
function reputationView(rep, isASN) {
  const asn = rep.asn;
  const addressRow = isASN
    ? nothing
    : html`<div class="rep-row">
        <span class="rep-label">Address</span>
        ${rep.lists?.length
          ? html`<span class="tags">${rep.lists.map((name) => glossaryTag(html`<cds-tag size="sm" type="red" title=${name}>${listLabel(name)}</cds-tag>`, name))}</span>`
          : html`<span class="rep-none">Not listed</span>`}
      </div>`;
  let networkRow = nothing;
  if (asn) {
    const tags = [];
    if (asn.spamhaus_asn_drop) tags.push('Spamhaus ASN-DROP');
    if (asn.drop_prefixes) tags.push(`Spamhaus DROP · ${asn.drop_prefixes} prefix${asn.drop_prefixes === 1 ? '' : 'es'}`);
    const counts = asn.listed_ips
      ? `${asn.listed_ips.toLocaleString()} listed IP${asn.listed_ips === 1 ? '' : 's'}` +
        (asn.listed_share_pct != null ? ` (${fmtShare(asn.listed_share_pct)} of announced IPv4)` : '') +
        (asn.max_lists ? `, up to ${asn.max_lists} lists` : '')
      : '';
    networkRow = html`<div class="rep-row">
      <span class="rep-label">Network</span>
      ${tags.length || counts
        ? html`<span class="tags">${tags.map((t) => glossaryTag(html`<cds-tag size="sm" type="red">${t}</cds-tag>`, t))}${counts ? html`<span class="rep-counts">${counts}</span>` : nothing}</span>`
        : html`<span class="rep-none">Not listed</span>`}
    </div>`;
  }
  return html`<div class="rep">${addressRow}${networkRow}</div>`;
}

function fmtShare(p) {
  if (p >= 10) return `${Math.round(p)}%`;
  if (p >= 0.1) return `${p.toFixed(1)}%`;
  return p > 0 ? '<0.1%' : '0%';
}

// locationRows lists the answers to where an address is, each with a short
// label: the network's geofeed, MaxMind's estimate and DB-IP's.
function locationRows(r) {
  const rows = [];
  if (r.relay) rows.push({ label: 'Private Relay', who: 'iCloud Private Relay', name: r.relay.name, title: 'Where Apple says this egress range\'s users are', src: SRC.relay });
  if (r.geofeed) rows.push({ label: 'Geofeed', name: r.geofeed.name, title: r.geofeed.feed, src: `${SRC.geofeed}: ${r.geofeed.feed}` });
  if (r.city_maxmind?.present) {
    const who = r.city_maxmind.source || 'MaxMind';
    rows.push({ label: who.replace(/^MaxMind /, ''), who, name: r.city_maxmind.name, src: SRC.cityOf(who) });
  }
  if (r.city?.present) {
    const who = r.city.source || 'DB-IP';
    rows.push({ label: who.replace(/^MaxMind /, ''), who, name: r.city.name, src: SRC.cityOf(who) });
  }
  return rows;
}

// Search

function searchView() {
  const s = state.search;
  const submit = () => {
    s.q = document.getElementById('search-q')?.value ?? s.q;
    const limit = parseInt(document.getElementById('search-limit')?.value, 10);
    s.limit = Number.isFinite(limit) && limit > 0 ? limit : 500;
    if (s.q.trim()) {
      go(`#/search?q=${encodeURIComponent(s.q.trim())}${s.fuzzy ? '&fuzzy=1' : ''}${s.country ? `&country=${s.country}` : ''}`);
    }
  };
  const d = s.data;
  return html`
    <p class="lede">
      Search AS names and, with the netblock database, the organisations and network names registered in whois. Search
      only reads the local databases; it never goes online.
    </p>
    <div class="filter-grid">
      <cds-text-input
        id="search-q"
        class="span-3"
        label="Search for"
        placeholder="A name or handle, e.g. cloudflare; or an AS number"
        .value=${s.q}
        @input=${(e) => (s.q = e.target.value)}
        @keydown=${(e) => e.key === 'Enter' && submit()}></cds-text-input>
      <cds-select label-text="Search in" value=${s.scope} @cds-select-selected=${(e) => (s.scope = e.target.value)}>
        <cds-select-item value="all">Both</cds-select-item>
        <cds-select-item value="asns">AS names</cds-select-item>
        <cds-select-item value="netblocks">Netblocks</cds-select-item>
      </cds-select>
      ${countryCombo('search-country', 'Country', s.country, (v) => (s.country = v))}
      <cds-select label-text="Address family" value=${s.family} @cds-select-selected=${(e) => (s.family = e.target.value)}>
        <cds-select-item value="any">IPv4 and IPv6</cds-select-item>
        <cds-select-item value="v4">IPv4</cds-select-item>
        <cds-select-item value="v6">IPv6</cds-select-item>
      </cds-select>
    </div>
    <div class="filter-actions">
      <cds-button @click=${submit} ?disabled=${s.loading}>Search</cds-button>
      ${switchWithTip('Fuzzy match', s.fuzzy, (e) => (s.fuzzy = e.target.checked), CONTROL_HELP.fuzzy)}
      <cds-number-input id="search-limit" class="inline-limit" label="Limit" hide-label min="1" max="10000" step="10" .value=${String(s.limit)} title="At most this many of each"></cds-number-input>
      <span class="hint">at most, of each</span>
      ${s.loading ? html`<cds-inline-loading status="active">Searching…</cds-inline-loading>` : nothing}
    </div>
    <details class="tips search-tips">
      <summary>Search tips</summary>
      <p>
        A plain search matches any part of a name, ignoring case, but otherwise letter for letter. Fuzzy match also
        ignores spaces and punctuation and matches word by word, which covers most spellings. Beyond that, try:
      </p>
      <ul>
        <li><strong>The acronym or handle:</strong> <code>MSSTATE</code>, <code>UMMC</code>, <code>AWS</code>. AS names start with a short handle.</li>
        <li><strong>One distinctive word</strong> rather than the full legal name: <code>cloudflare</code>, not <code>Cloudflare, Inc.</code></li>
        <li><strong>Part of a word:</strong> <code>missis</code> finds Mississippi and Mississauga.</li>
        <li><strong>Former names, parent companies and brands:</strong> space often stays registered to an old or parent name (<code>Twitter</code>, <code>Facebook</code>, <code>Level 3</code>).</li>
        <li><strong>The name in the local language</strong>, as well as its English form.</li>
      </ul>
      <p>Click a column heading to sort the results, and an ASN to look it up.</p>
    </details>
    <div class="notifications">${s.error ? errorNote('Search failed', s.error) : nothing}</div>
    ${d ? searchResults(d) : nothing}
  `;
}

const asnNumber = (s) => {
  const n = parseInt(String(s ?? '').replace(/^AS/i, ''), 10);
  return Number.isFinite(n) ? n : '';
};
const prefixCount = (a) => (a.ipv4_prefixes?.length || 0) + (a.ipv6_prefixes?.length || 0);
// ASN-DROP first, then by the share of the ASN's space that is listed.
const asnListedShare = (a) => (a.reputation ? (a.reputation.spamhaus_asn_drop ? 1000 : 0) + (a.reputation.listed_share_pct || 0) : '');

const MATCH_ORDER = { exact: 1, compact: 2, words: 3 };
const MATCH_TAG = { exact: ['green', 'exact'], compact: ['cyan', 'compact'], words: ['purple', 'words'] };
const matchCell = (m) => {
  const [type, label] = MATCH_TAG[m] || ['gray', m || ''];
  return html`<cds-table-cell><cds-tag size="sm" type=${type}>${label}</cds-tag></cds-table-cell>`;
};

// countryShort is "Australia" for "AU, Australia".
const countryShort = (c) => (c ? c.split(', ').slice(1).join(', ') || c : '');

// sortedSearch is the search's rows in the order the tables show them.
function sortedSearch(d) {
  const sort = state.search.sort;
  const asns = sortRows(d.asns || [], sort.asns, {
    match: (a) => MATCH_ORDER[a.match] ?? '',
    asn: (a) => asnNumber(a.asn),
    name: (a) => a.name,
    country: (a) => a.country,
    prefixes: prefixCount,
    reputation: asnListedShare,
  });
  const blocks = sortRows(d.results || [], sort.blocks, {
    // IPv4 numerically; IPv6 after it, as text.
    match: (b) => MATCH_ORDER[b.match] ?? '',
    range: (b) => (b.is_v6 ? `~${b.range_start}` : ipv4Number(b.range_start)),
    netname: (b) => b.netname,
    org: (b) => b.org,
    asn: (b) => asnNumber(b.asn),
    country: (b) => b.country,
  });
  return { asns, blocks };
}

// copyKinds are the Search page's copy buttons: what each copies, and how
// many lines when that is worth saying.
function copyKinds(d) {
  const s = state.search;
  const { asns, blocks } = sortedSearch(d);
  const scope = s.ranScope || s.scope;
  const fuzzy = s.ranFuzzy;
  const asnLines = asnList(asns);
  const prefixes = prefixList(asns, blocks);
  const table = () =>
    tableText({
      query: d.query,
      country: s.ranCountry ? `${countryName(s.ranCountry)}` : '',
      asns,
      blocks,
      fuzzy,
      showASNs: scope !== 'netblocks',
      showBlocks: scope !== 'asns' || blocks.length > 0,
      asnCount: d.asn_count,
      blockCount: d.count,
    });
  return [
    { key: 'asns', label: `ASNs (${asnLines.length})`, title: 'The ASNs whose names matched, one per line (not those announcing the netblocks)', text: () => asnLines.join('\n') + '\n', n: asnLines.length },
    { key: 'prefixes', label: `Prefixes (${prefixes.length})`, title: 'The matching ASNs\u2019 announced prefixes and the netblocks\u2019 CIDRs, deduplicated and sorted, one per line', text: () => prefixes.join('\n') + '\n', n: prefixes.length },
    { key: 'table', label: 'Table', title: 'Both tables as shown, as aligned text', text: table, n: asns.length + blocks.length },
    { key: 'csv', label: 'CSV', title: 'One row per ASN and netblock, for a spreadsheet', text: () => csvText({ asns, blocks, fuzzy }), n: asns.length + blocks.length },
    { key: 'json', label: 'JSON', title: 'The API\u2019s answer, as is', text: () => JSON.stringify(d, null, 2) + '\n', n: 1 },
  ];
}

async function copySearch(kind) {
  const s = state.search;
  try {
    await navigator.clipboard.writeText(kind.text());
    s.copied = kind.key;
  } catch {
    s.error = 'The browser refused clipboard access.';
  }
  update();
  setTimeout(() => {
    if (s.copied === kind.key) {
      s.copied = '';
      update();
    }
  }, 2000);
}

function copyBar(d) {
  const s = state.search;
  return html`<div class="copy-bar" role="group" aria-label="Copy the results">
    <span class="copy-label">Copy</span>
    ${copyKinds(d).map(
      (k) => html`<cds-button kind="ghost" size="sm" title=${k.title} ?disabled=${!k.n} @click=${() => copySearch(k)}
        >${s.copied === k.key ? 'Copied' : k.label}</cds-button
      >`,
    )}
  </div>`;
}

function searchResults(d) {
  const fuzzy = state.search.ranFuzzy;
  const scope = state.search.ranScope || state.search.scope;
  const { asns, blocks } = sortedSearch(d);
  const where = state.search.ranCountry ? ` in ${countryName(state.search.ranCountry)}` : '';
  return html`
    <div class="results-head">
      <p class="explore-summary">
        ${scope !== 'netblocks' ? html`<span class="es-big">${(d.asn_count ?? asns.length).toLocaleString()}</span> AS name${(d.asn_count ?? asns.length) === 1 ? '' : 's'}` : nothing}
        ${scope === 'all' ? html`<span class="es-sep">·</span>` : nothing}
        ${scope !== 'asns' || blocks.length ? html`<span class="es-big">${(d.count ?? blocks.length).toLocaleString()}</span> netblock${(d.count ?? blocks.length) === 1 ? '' : 's'}` : nothing}
        ${where ? html`<span class="es-sep">·</span><span>${where.trim()}</span>` : nothing}
      </p>
      ${asns.length || blocks.length ? copyBar(d) : nothing}
    </div>
    ${scope !== 'netblocks'
      ? html`<h2>AS names</h2>
          ${asns.length
            ? html`<div class="table-wrap">
                <cds-table size="sm" use-zebra-styles>
                  <cds-table-head>
                    <cds-table-header-row>
                      ${fuzzy ? sortHeader('asns', 'match', 'Match', COLUMN_HELP.match) : nothing}
                      ${sortHeader('asns', 'asn', 'ASN')}
                      ${sortHeader('asns', 'name', 'Name')}
                      ${sortHeader('asns', 'country', 'Country')}
                      ${sortHeader('asns', 'prefixes', 'Prefixes', COLUMN_HELP.prefixes)}
                      ${sortHeader('asns', 'reputation', 'Reputation', COLUMN_HELP.asnReputation)}
                    </cds-table-header-row>
                  </cds-table-head>
                  <cds-table-body>
                    ${asns.map(
                      (a) => html`<cds-table-row>
                        ${fuzzy ? matchCell(a.match) : nothing}
                        <cds-table-cell class="nowrap">${asnLink(a.asn)}</cds-table-cell>
                        <cds-table-cell class="wrap">${a.name}</cds-table-cell>
                        <cds-table-cell class="nowrap" title=${a.country || ''}>${countryShort(a.country)}</cds-table-cell>
                        <cds-table-cell class="nowrap">${prefixCount(a) || html`<span class="muted">0</span>`}</cds-table-cell>
                        <cds-table-cell class="wrap">
                          ${a.reputation?.listed || a.reputation?.spamhaus_asn_drop
                            ? html`<div class="rep-cell">
                                ${a.reputation.spamhaus_asn_drop
                                  ? html`<div class="rep-flags">${glossaryTag(html`<cds-tag size="sm" type="red">Spamhaus ASN-DROP</cds-tag>`, 'Spamhaus ASN-DROP')}</div>`
                                  : nothing}
                                ${asnSummary(a.reputation) ? html`<div class="rep-facts">${asnSummary(a.reputation)}</div>` : nothing}
                              </div>`
                            : html`<span class="muted">Not listed</span>`}
                        </cds-table-cell>
                      </cds-table-row>`,
                    )}
                  </cds-table-body>
                </cds-table>
              </div>`
            : html`<p class="empty">No AS names match.</p>`}`
      : nothing}
    ${scope !== 'asns' || blocks.length
      ? html`<h2>Netblocks</h2>
          ${blocks.length
            ? html`<div class="table-wrap">
                <cds-table size="sm" use-zebra-styles>
                  <cds-table-head>
                    <cds-table-header-row>
                      ${fuzzy ? sortHeader('blocks', 'match', 'Match', COLUMN_HELP.match) : nothing}
                      ${sortHeader('blocks', 'range', 'Range')}
                      ${sortHeader('blocks', 'netname', 'Network')}
                      ${sortHeader('blocks', 'org', 'Organisation')}
                      ${sortHeader('blocks', 'asn', 'Announced by')}
                      ${sortHeader('blocks', 'country', 'Country')}
                    </cds-table-header-row>
                  </cds-table-head>
                  <cds-table-body>
                    ${blocks.map(
                      (b) => html`<cds-table-row>
                        ${fuzzy ? matchCell(b.match) : nothing}
                        <cds-table-cell class="mono">${(b.cidrs?.length ? b.cidrs : [`${b.range_start} – ${b.range_end}`]).map(
                          (c) => html`<div>${c}</div>`,
                        )}</cds-table-cell>
                        <cds-table-cell class="wrap">${b.netname || ''}</cds-table-cell>
                        <cds-table-cell class="wrap">${b.org || ''}</cds-table-cell>
                        <cds-table-cell class="wrap">
                          ${b.asn && b.asn !== 'N/A' ? html`${asnLink(b.asn)} ${(b.as_name || '').replace(/, [A-Z]{2}$/, '')}` : html`<span class="muted">Not announced</span>`}
                        </cds-table-cell>
                        <cds-table-cell class="nowrap" title=${b.country || ''}>${countryShort(b.country)}</cds-table-cell>
                      </cds-table-row>`,
                    )}
                  </cds-table-body>
                </cds-table>
              </div>`
            : html`<p class="empty">No netblocks match${state.status?.loaded && !state.status.loaded.netblock ? ' (the netblock database is not loaded)' : ''}.</p>`}`
      : nothing}
  `;
}

// Explore

let exploreAbort = null;

async function runExplore() {
  const x = state.explore;
  exploreAbort?.abort();
  exploreAbort = new AbortController();
  const params = toParams(x.f);
  x.ran = params.toString();
  // The page's default family is not the API's: always say which.
  if (!params.has('family')) params.set('family', x.f.family);
  Object.assign(x, { loading: true, error: '', copied: '' });
  update();
  try {
    x.data = await api.explore(params, { signal: exploreAbort.signal });
    if (x.data?.all_tags) x.allTags = x.data.all_tags;
  } catch (err) {
    if (err.name === 'AbortError') return;
    x.error = errorText(err);
    x.data = null;
  }
  x.loading = false;
  update();
}

// exploreGo shows the filters in the URL, which runs them; changed filters
// start again from the first page.
function exploreGo(changes, keepOffset = false) {
  const x = state.explore;
  x.f = { ...x.f, ...changes };
  if (!keepOffset) x.f.offset = 0;
  const p = toParams(x.f).toString();
  go(`#/explore${p ? `?${p}` : ''}`);
}

function exploreSubmit() {
  const x = state.explore;
  const val = (id) => document.getElementById(id)?.value ?? '';
  const limit = parseInt(val('explore-limit'), 10);
  exploreGo({
    len: val('explore-len').trim(),
    asn: val('explore-asn').trim(),
    min_ipsum: val('explore-ipsum').trim(),
    min_listed_pct: val('explore-pct').trim(),
    limit: Number.isFinite(limit) && limit > 0 ? limit : 500,
    tag: x.f.tag,
  });
}

function countryCombo(id, label, value, onChange) {
  return html`<cds-combo-box
    id=${id}
    class="country"
    title-text=${label}
    label="Worldwide"
    should-filter-item
    clear-selection-label="Worldwide"
    value=${value}
    @cds-combo-box-selected=${(e) => {
      const v = String(e.target.value || '').toUpperCase();
      onChange(COUNTRIES.some((c) => c.code === v) ? v : '');
    }}>
    ${COUNTRIES.map((c) => html`<cds-combo-box-item value=${c.code}>${c.name} (${c.code})</cds-combo-box-item>`)}
  </cds-combo-box>`;
}

function exploreView() {
  const x = state.explore;
  const f = x.f;
  const d = x.data;
  const enter = (e) => e.key === 'Enter' && exploreSubmit();
  const filtered = toParams({ ...f, sort: DEFAULT_FILTERS.sort, limit: DEFAULT_FILTERS.limit, offset: 0 }).toString() !== '';
  return html`
    <p class="lede">Every announced prefix with its origin AS, registry country, kind of network and blocklist hits.</p>
    <div class="filter-grid">
      <cds-text-input id="explore-len" label="Prefix length" placeholder="Any, e.g. 16-24" .value=${f.len} @keydown=${enter}></cds-text-input>
      <cds-select label-text="Address family" value=${f.family} @cds-select-selected=${(e) => (f.family = e.target.value)}>
        <cds-select-item value="any">IPv4 and IPv6</cds-select-item>
        <cds-select-item value="v4">IPv4</cds-select-item>
        <cds-select-item value="v6">IPv6</cds-select-item>
      </cds-select>
      ${countryCombo('explore-country', 'Registry country', f.country, (v) => (f.country = v))}
      ${countryCombo('explore-ascountry', 'Origin AS country', f.as_country, (v) => (f.as_country = v))}
      <cds-text-input id="explore-asn" label="Origin AS" placeholder="Any, e.g. AS13335" .value=${f.asn} @keydown=${enter}></cds-text-input>
      <cds-select label-text="Reputation" value=${f.reputation || 'any'} @cds-select-selected=${(e) => (f.reputation = e.target.value === 'any' ? '' : e.target.value)}>
        ${REPUTATIONS.map(([v, l]) => html`<cds-select-item value=${v || 'any'}>${l}</cds-select-item>`)}
      </cds-select>
      <cds-multi-select
        class="span-2"
        title-text="Kind of network"
        label=${f.tag.length ? f.tag.join(', ') : 'Any'}
        value=${f.tag.join(',')}
        @cds-multi-select-selected=${(e) => (f.tag = String(e.target.value || '').split(',').filter(Boolean))}>
        ${(x.allTags.length ? x.allTags : f.tag).map((t) => html`<cds-multi-select-item value=${t} ?selected=${f.tag.includes(t)}>${t}</cds-multi-select-item>`)}
      </cds-multi-select>

      <cds-text-input id="explore-ipsum" label="IPsum feeds, at least" placeholder="Any" .value=${f.min_ipsum} @keydown=${enter}></cds-text-input>
      <cds-text-input id="explore-pct" label="Listed share, at least %" placeholder="Any" .value=${f.min_listed_pct} @keydown=${enter}></cds-text-input>
      <cds-select label-text="Sort" value=${f.sort} @cds-select-selected=${(e) => (f.sort = e.target.value)}>
        ${SORTS.map(([v, l]) => html`<cds-select-item value=${v}>${l}</cds-select-item>`)}
      </cds-select>
      <cds-number-input id="explore-limit" label="Per page" min="1" max="100000" step="100" .value=${String(f.limit)}></cds-number-input>
    </div>
    <div class="filter-actions">
      <cds-button @click=${exploreSubmit} ?disabled=${x.loading}>Explore</cds-button>
      ${filtered ? html`<cds-button kind="ghost" @click=${() => go('#/explore')}>Clear filters</cds-button>` : nothing}
      ${x.loading ? html`<cds-inline-loading status="active">${d ? 'Filtering…' : 'Indexing the routing table…'}</cds-inline-loading>` : nothing}
    </div>
    <div class="notifications">${x.error ? errorNote('Explore failed', x.error) : nothing}</div>
    ${d ? exploreResults(d) : nothing}
  `;
}

const BREAKDOWN_SHOWN = 8;

// breakdownCard ranks what the matches break down into; each row filters.
function breakdownCard(key, title, items, total, pick, active, showCode) {
  const x = state.explore;
  if (!items?.length) return nothing;
  const all = x.more?.[key];
  const shown = all ? items : items.slice(0, BREAKDOWN_SHOWN);
  const top = items[0].count || 1;
  return html`<section class="bd-card">
    <h3>${title}</h3>
    <ol>
      ${shown.map(
        (i) => html`<li>
          <button type="button" class="bd-row ${active(i.value) ? 'bd-on' : ''}" title="Filter on ${i.label || i.value}" @click=${() => pick(i.value)}>
            <span class="bd-bar" style="width:${Math.max(1, (i.count / top) * 100)}%"></span>
            ${showCode ? html`<span class="bd-code">${i.value}</span>` : nothing}
            <span class="bd-label">${showCode ? (i.label !== i.value ? i.label : '') : i.label || i.value}</span>
            <span class="bd-count">${i.count.toLocaleString()}</span>
            <span class="bd-pct">${fmtPct((i.count / total) * 100)}</span>
          </button>
        </li>`,
      )}
    </ol>
    ${items.length > BREAKDOWN_SHOWN
      ? html`<button type="button" class="bd-more" @click=${() => {
          x.more = { ...(x.more || {}), [key]: !all };
          update();
        }}>${all ? 'Show fewer' : `Show ${items.length - BREAKDOWN_SHOWN} more`}</button>`
      : nothing}
  </section>`;
}

function exploreCopyKinds(d) {
  const rows = d.results || [];
  const asns = [...new Set(rows.map((r) => r.asn))];
  const title = `Explore: ${toParams(state.explore.f).toString() || 'everything'} (${rows.length} of ${d.count})`;
  return [
    { key: 'prefixes', label: `Prefixes (${rows.length})`, title: 'This page\u2019s prefixes, one per line', text: () => rows.map((r) => r.prefix).join('\n') + '\n', n: rows.length },
    { key: 'asns', label: `ASNs (${asns.length})`, title: 'This page\u2019s origin ASNs, once each', text: () => asns.join('\n') + '\n', n: asns.length },
    { key: 'table', label: 'Table', title: 'This page as aligned text', text: () => exploreTable(rows, title), n: rows.length },
    { key: 'csv', label: 'CSV', title: 'This page, one row per prefix', text: () => exploreCSV(rows), n: rows.length },
    { key: 'json', label: 'JSON', title: 'The API\u2019s answer, as is', text: () => JSON.stringify(d, null, 2) + '\n', n: 1 },
  ];
}

async function exploreCopy(kind) {
  const x = state.explore;
  try {
    await navigator.clipboard.writeText(kind.text());
    x.copied = kind.key;
  } catch {
    x.error = 'The browser refused clipboard access.';
  }
  update();
  setTimeout(() => {
    if (x.copied === kind.key) {
      x.copied = '';
      update();
    }
  }, 2000);
}

function repCell(r) {
  const rep = r.reputation || {};
  const flags = [];
  if (rep.spamhaus_drop) flags.push(['red', 'Spamhaus DROP']);
  else if (rep.spamhaus_drop_inside) flags.push(['magenta', 'Contains DROP']);
  if (rep.spamhaus_asn_drop) flags.push(['red', 'ASN-DROP']);
  if (rep.firehol_level2) flags.push(['red', 'FireHOL L2']);
  else if (rep.firehol_level3) flags.push(['magenta', 'FireHOL L3']);
  for (const fam of rep.c2 || []) flags.push(['red', `C2 · ${fam}`]);
  const facts = [];
  if (rep.listed_ips) {
    facts.push(`${rep.listed_ips.toLocaleString()} listed`);
    if (r.addresses) facts.push(fmtPct(rep.listed_share_pct));
    if (rep.max_ipsum) facts.push(`IPsum max ${rep.max_ipsum}`);
  }
  if (!flags.length && !facts.length) return html`<span class="muted">Not listed</span>`;
  return html`<div class="rep-cell">
    ${flags.length
      ? html`<div class="rep-flags">${flags.map(([t, l]) => glossaryTag(html`<cds-tag size="sm" type=${t} title=${rep.sbl?.join(' ') || ''}>${l}</cds-tag>`, l))}</div>`
      : nothing}
    ${facts.length ? html`<div class="rep-facts">${facts.join(' · ')}</div>` : nothing}
  </div>`;
}

function exploreResults(d) {
  const x = state.explore;
  const f = x.f;
  const rows = d.results || [];
  const from = d.count ? f.offset + 1 : 0;
  const to = f.offset + rows.length;
  return html`
    <p class="explore-summary">
      <span class="es-big">${d.count.toLocaleString()}</span> prefix${d.count === 1 ? '' : 'es'}
      ${d.ipv4_addresses
        ? html`<span class="es-sep">·</span><span title="Summed over the prefixes, so a prefix inside another is counted twice">${fmtCount(d.ipv4_addresses)} IPv4 addresses</span>`
        : nothing}
      <span class="es-sep">·</span><span class="muted">${d.took_ms} ms</span>
    </p>
    ${d.count
      ? html`<div class="breakdown">
          ${breakdownCard('countries', 'Registry country', d.countries, d.count, (v) => exploreGo({ country: v }), (v) => v === f.country, true)}
          ${breakdownCard('tags', 'Kind of network', d.tags, d.count, (v) => exploreGo({ tag: f.tag.includes(v) ? f.tag.filter((t) => t !== v) : [...f.tag, v] }), (v) => f.tag.includes(v), false)}
          ${breakdownCard('asns', 'Origin AS', d.asns, d.count, (v) => exploreGo({ asn: v }), (v) => v === f.asn.toUpperCase(), true)}
        </div>`
      : nothing}
    ${rows.length
      ? html`<div class="results-head">
            <h2>Prefixes <span class="hint">${from.toLocaleString()}–${to.toLocaleString()} of ${d.count.toLocaleString()}</span></h2>
            <div class="copy-bar" role="group" aria-label="Copy this page">
              <span class="copy-label">Copy</span>
              ${exploreCopyKinds(d).map(
                (k) => html`<cds-button kind="ghost" size="sm" title=${k.title} ?disabled=${!k.n} @click=${() => exploreCopy(k)}
                  >${x.copied === k.key ? 'Copied' : k.label}</cds-button
                >`,
              )}
            </div>
          </div>
          <div class="table-wrap">
            <cds-table size="sm" use-zebra-styles>
              <cds-table-head>
                <cds-table-header-row>
                  <cds-table-header-cell>Prefix</cds-table-header-cell>
                  <cds-table-header-cell>Origin AS</cds-table-header-cell>
                  <cds-table-header-cell>Country</cds-table-header-cell>
                  <cds-table-header-cell>Kind</cds-table-header-cell>
                  <cds-table-header-cell>Reputation</cds-table-header-cell>
                </cds-table-header-row>
              </cds-table-head>
              <cds-table-body>
                ${rows.map(
                  (r) => html`<cds-table-row>
                    <cds-table-cell class="mono nowrap"><a href="#/lookup?q=${encodeURIComponent(r.prefix.split('/')[0])}" title="Look up its first address">${r.prefix}</a></cds-table-cell>
                    <cds-table-cell class="wrap">${asnLink(r.asn)} <span class="as-name">${(r.as_name || '').replace(/, [A-Z]{2}$/, '')}</span></cds-table-cell>
                    <cds-table-cell class="nowrap" title=${r.as_country && r.as_country !== r.country ? `Origin AS registered in ${r.as_country}` : ''}>${r.country ? r.country.split(', ').slice(1).join(', ') || r.country : html`<span class="muted">—</span>`}</cds-table-cell>
                    <cds-table-cell class="wrap kind-cell">${(r.tags || []).length ? r.tags.join(', ') : html`<span class="muted">—</span>`}</cds-table-cell>
                    <cds-table-cell class="wrap">${repCell(r)}</cds-table-cell>
                  </cds-table-row>`,
                )}
              </cds-table-body>
            </cds-table>
          </div>
          ${d.count > rows.length
            ? html`<div class="pager">
                <cds-button kind="ghost" size="sm" ?disabled=${f.offset === 0} @click=${() => exploreGo({ offset: Math.max(0, f.offset - f.limit) }, true)}>Previous</cds-button>
                <span>${from.toLocaleString()}–${to.toLocaleString()} of ${d.count.toLocaleString()}</span>
                <cds-button kind="ghost" size="sm" ?disabled=${to >= d.count} @click=${() => exploreGo({ offset: f.offset + f.limit }, true)}>Next</cds-button>
              </div>`
            : nothing}`
      : html`<p class="empty">No prefixes match.</p>`}
  `;
}

// Databases

function loadedKey(db) {
  return db.name === 'ASN prefixes' ? 'prefixes' : db.key;
}

function dbTags(db, loaded) {
  const tags = [];
  if (!db.present) {
    tags.push(db.optional ? ['gray', 'Not present'] : ['red', 'Missing']);
  } else if (loaded[loadedKey(db)]) {
    tags.push(['green', 'Loaded']);
  } else {
    tags.push(['blue', 'On disk']);
  }
  if (db.stale) tags.push(['warm-gray', 'Stale']);
  if (db.missing?.length) tags.push(['red', 'Incomplete']);
  if (db.last_error) tags.push(['red', 'Last update failed']);
  return tags;
}

const MAX_AGE_SOURCES = {
  default: 'the default',
  saved: 'saved here',
  flag: 'set on the server’s command line (--max-age or ASNAME_MAX_AGE)',
  off: 'off, because the server runs with --no-update',
};

function settingsPanel(st) {
  const d = state.db;
  const store = st.store || {};
  const hours = store.max_age_hours || 0;
  const source = store.max_age_source || 'default';
  const fixed = source === 'flag' || source === 'off';
  const editable = !!st.settings_editable;
  const choices = MAX_AGE_CHOICES.some(([h]) => h === hours) ? MAX_AGE_CHOICES : [...MAX_AGE_CHOICES, [hours, fmtHours(hours)]];
  let ageHelp;
  if (fixed) ageHelp = `Fixed: ${MAX_AGE_SOURCES[source]}.`;
  else if (!editable) ageHelp = 'Start the server with --allow-updates to change this.';
  else ageHelp = `Checked at startup and every 6 hours; currently ${MAX_AGE_SOURCES[source]}.`;
  return html`
    <section class="update-panel">
      <h3>Settings</h3>
      <p class="hint">Kept in the data directory, so the <code>asname</code> command follows them too.</p>
      ${d.settingsError ? errorNote('Setting not saved', d.settingsError) : nothing}
      <div class="settings-grid">
        <div class="setting">
          <div class="setting-label">Refresh databases older than ${tip('Refresh age', CONTROL_HELP.maxAge)}</div>
          <cds-select
            hide-label
            label-text="Refresh databases older than"
            value=${String(hours)}
            ?disabled=${fixed || !editable || d.saving === 'max_age'}
            @cds-select-selected=${(e) => {
              const h = Number(e.target.value);
              if (h !== hours) saveSetting('max_age', { max_age_hours: h });
            }}>
            ${choices.map(([h, label]) => html`<cds-select-item value=${String(h)}>${label}</cds-select-item>`)}
          </cds-select>
          <p class="hint">${ageHelp}</p>
        </div>
        <div class="setting">
          <div class="setting-label">Import IPv6 routes ${tip('IPv6 routes', CONTROL_HELP.ipv6)}</div>
          <cds-toggle
            .hideLabel=${true}
            label-text="Import IPv6 routes"
            ?checked=${!!store.ipv6_routes}
            ?disabled=${!editable || d.saving === 'ipv6'}
            @cds-toggle-changed=${(e) => saveSetting('ipv6', { ipv6_routes: e.target.checked })}></cds-toggle>
          <p class="hint">${store.ipv6_routes ? 'The next ASN update includes IPv6.' : 'IPv4 only; IPv6 lookups find no AS.'}</p>
        </div>
        ${d.saving ? html`<cds-inline-loading status="active">Saving…</cds-inline-loading>` : nothing}
      </div>
    </section>
  `;
}

function databasesView() {
  const st = state.status;
  const d = state.db;
  if (!st) {
    // Without a status the banner says why.
    return state.statusError ? nothing : html`<cds-inline-loading status="active">Reading database status…</cds-inline-loading>`;
  }
  const store = st.store || {};
  const dbs = store.databases || [];
  const job = st.update || {};
  const running = !!job.running;
  const canUpdate = st.updates_enabled && !running && !d.busy;
  const incomplete = dbs.some((db) => db.missing?.length || db.last_error);
  const seenKeys = new Set();

  const toggle = (key, checked) => {
    if (checked) d.selected.add(key);
    else d.selected.delete(key);
    update();
  };

  return html`
    <p class="lede">The databases asname answers from, and updates that rebuild them from their public sources.</p>
    <div class="notifications">
      ${!st.updates_enabled
        ? html`<cds-inline-notification kind="info" low-contrast hide-close-button
            title="Updates are off"
            subtitle="This server was started without --allow-updates, so databases can only be updated with \`asname update\`."></cds-inline-notification>`
        : nothing}
      ${d.error ? errorNote('Update not started', d.error) : nothing}
      ${d.notice && !running ? html`<cds-inline-notification kind="success" low-contrast hide-close-button title=${d.notice}></cds-inline-notification>` : nothing}
    </div>

    <dl class="store-meta">
      <div><dt>Directory</dt><dd class="mono">${store.dir || ''}</dd></div>
      <div>
        <dt>Refreshed when older than</dt>
        <dd>${store.max_age_hours ? fmtHours(store.max_age_hours) : 'never (auto-update off)'}</dd>
      </div>
      <div><dt>IPv6 routes</dt><dd>${store.ipv6_routes ? 'imported' : 'off'}</dd></div>
    </dl>

    <div class="table-wrap">
      <cds-table size="md">
        <cds-table-head>
          <cds-table-header-row>
            ${st.updates_enabled ? html`<cds-table-header-cell class="select-col"><span class="sr-only">Select</span></cds-table-header-cell>` : nothing}
            <cds-table-header-cell>Database</cds-table-header-cell>
            <cds-table-header-cell><span class="th-label">Status${tip('Status', COLUMN_HELP.status)}</span></cds-table-header-cell>
            <cds-table-header-cell>Updated</cds-table-header-cell>
            <cds-table-header-cell>Size</cds-table-header-cell>
            <cds-table-header-cell>Notes</cds-table-header-cell>
          </cds-table-header-row>
        </cds-table-head>
        <cds-table-body>
          ${dbs.map((db) => {
            const first = db.key && !seenKeys.has(db.key);
            if (db.key) seenKeys.add(db.key);
            return html`<cds-table-row>
              ${st.updates_enabled
                ? html`<cds-table-cell class="select-col">
                ${first
                  ? html`<cds-checkbox
                      hide-label
                      label-text="Update ${db.name}"
                      ?checked=${d.selected.has(db.key)}
                      ?disabled=${!st.updates_enabled}
                      @cds-checkbox-changed=${(e) => {
                        // The table row takes any checkbox inside it for its own
                        // selection checkbox; keep this one to ourselves.
                        e.stopPropagation();
                        toggle(db.key, e.target.checked);
                      }}></cds-checkbox>`
                  : nothing}
              </cds-table-cell>`
                : nothing}
              <cds-table-cell>
                ${db.name}
                <div class="hint mono" title=${db.path}>${db.path.split('/').pop()}</div>
              </cds-table-cell>
              <cds-table-cell>
                <div class="tags">${dbTags(db, st.loaded || {}).map(([type, text]) => html`<cds-tag size="sm" type=${type}>${text}</cds-tag>`)}</div>
              </cds-table-cell>
              <cds-table-cell class="nowrap">
                ${db.updated ? html`${fmtAge(db.age_seconds)}<div class="hint">${fmtDate(db.updated)}</div>` : ''}
              </cds-table-cell>
              <cds-table-cell class="nowrap">${db.present ? fmtBytes(db.size) : SIZE_HINTS[db.key] || ''}</cds-table-cell>
              <cds-table-cell class="wrap">
                ${!first && db.key ? html`<div class="hint">Rebuilt with ${db.key.toUpperCase()}</div>` : nothing}
                ${db.built ? html`<div class="hint">Data built ${fmtDate(db.built)}</div>` : nothing}
                ${db.missing?.length ? html`<div>Missing: ${db.missing.join(', ')}</div>` : nothing}
                ${db.last_error ? html`<div>${db.last_error}</div>` : nothing}
                ${first && db.sources?.length
                  ? html`<button class="link-button" @click=${() => showSources(db.key)}>
                      ${db.sources.length} source${db.sources.length === 1 ? '' : 's'}${db.vpn_lists?.length ? `, ${db.vpn_lists.length} VPN lists` : ''}
                    </button>`
                  : nothing}
              </cds-table-cell>
            </cds-table-row>`;
          })}
        </cds-table-body>
      </cds-table>
    </div>

    ${st.updates_enabled || job.started
      ? html`<section class="update-panel">
      <h3>Update</h3>
      ${st.updates_enabled
        ? html`<div class="actions">
        <cds-button
          ?disabled=${!canUpdate || !d.selected.size}
          @click=${() => startUpdate({ databases: [...d.selected] })}>
          Update selected${d.selected.size ? ` (${d.selected.size})` : ''}
        </cds-button>
        <cds-button kind="secondary" ?disabled=${!canUpdate} @click=${() => startUpdate({})}>Refresh all on disk</cds-button>
        <cds-button kind="tertiary" ?disabled=${!canUpdate} @click=${() => startUpdate({ stale_only: true })}>Refresh stale only</cds-button>
        <cds-button kind="tertiary" ?disabled=${!canUpdate || !incomplete} @click=${() => startUpdate({ incremental: true })}>Retry incomplete</cds-button>
        ${running ? html`<cds-button kind="danger-tertiary" @click=${cancelUpdate}>Cancel</cds-button>` : nothing}
      </div>
      <p class="hint" style="margin-top: 0.5rem">
        Updates download from RouteViews or RIPE RIS, the RIRs and the blocklist providers. Lookups keep answering from the
        current files until the new ones are in place.
      </p>`
        : nothing}
      ${job.started ? jobView(job) : nothing}
    </section>`
      : nothing}

    ${st.updates_enabled ? settingsPanel(st) : nothing}

    ${sourcesView(dbs)}
  `;
}

// showSources opens a database's entry under Data sources and scrolls to it.
function showSources(key) {
  state.db.openSources.add(key);
  update();
  requestAnimationFrame(() => document.getElementById(`sources-${key}`)?.scrollIntoView({ behavior: 'smooth', block: 'start' }));
}

// sourcesView lists every public source each database is built from, how
// each fared in the last update, and the VPN server lists in the category
// database.
function sourcesView(dbs) {
  const groups = [];
  for (const db of dbs) {
    if (!db.key) continue;
    let g = groups.find((x) => x.key === db.key);
    if (!g) groups.push((g = { key: db.key, names: [], present: false, sources: [], vpnLists: [] }));
    g.names.push(db.name);
    g.present ||= db.present;
    if (db.sources?.length && !g.sources.length) g.sources = db.sources;
    if (db.vpn_lists?.length) g.vpnLists = db.vpn_lists;
  }
  if (!groups.some((g) => g.sources.length)) return nothing;
  const open = state.db.openSources;
  const toggled = (key) => (e) => {
    if (e.target.open) open.add(key);
    else open.delete(key);
  };
  return html`<section class="sources-panel">
    <h3>Data sources ${tip('Data sources', SOURCES_HELP.section)}</h3>
    <p class="hint">Every public source each database is built from, and how it fared in the last update.</p>
    <cds-accordion>
      ${groups.map((g) => {
        const failed = g.sources.filter((s) => s.failed).length;
        const title = `${g.names.join(' and ')}: ${g.sources.length} source${g.sources.length === 1 ? '' : 's'}${
          g.vpnLists.length ? `, ${g.vpnLists.length} VPN lists` : ''}${failed ? `, ${failed} failed` : ''}`;
        return html`<cds-accordion-item id="sources-${g.key}" title=${title} ?open=${open.has(g.key)}
            @cds-accordion-item-toggled=${toggled(g.key)}>
          ${sourceTable(g)}
          ${g.vpnLists.length ? vpnListTable(g.vpnLists) : nothing}
        </cds-accordion-item>`;
      })}
    </cds-accordion>
  </section>`;
}

function sourceTable(g) {
  // Per-source results are recorded from asname 0.17 on; before that only
  // failures were.
  const recorded = g.sources.some((s) => s.recorded && !s.failed);
  return html`
    ${g.present && !recorded
      ? html`<p class="hint">This database was last updated before asname recorded each source's result; the next update will
          show them. Failures are shown already.</p>`
      : nothing}
    <div class="table-wrap">
      <cds-table size="sm">
        <cds-table-head>
          <cds-table-header-row>
            <cds-table-header-cell>Source</cds-table-header-cell>
            <cds-table-header-cell>What it provides</cds-table-header-cell>
            <cds-table-header-cell>Last update ${tip('Last update', SOURCES_HELP.result)}</cds-table-header-cell>
          </cds-table-header-row>
        </cds-table-head>
        <cds-table-body>
          ${g.sources.map(
            (s) => html`<cds-table-row>
              <cds-table-cell class=${s.group ? 'source-name sub' : 'source-name'}>
                ${s.url ? html`<a href=${s.url} target="_blank" rel="noopener noreferrer">${s.name}</a>` : s.name}
                ${sourceGlossary(s.name)}
              </cds-table-cell>
              <cds-table-cell class="wrap">
                ${s.provides || ''}
                ${s.condition ? html`<div class="hint">Used ${s.condition}.</div>` : nothing}
              </cds-table-cell>
              <cds-table-cell class="wrap">${sourceResult(s, g.present, recorded)}</cds-table-cell>
            </cds-table-row>`,
          )}
        </cds-table-body>
      </cds-table>
    </div>`;
}

function sourceResult(s, present, recorded) {
  if (s.failed) {
    return html`<cds-tag size="sm" type="red">Failed</cds-tag>
      <div class="hint">${s.group === 'VPN providers' ? "Built from gluetun's copy instead." : 'Built without it; Retry incomplete tries again.'}</div>`;
  }
  if (s.recorded) {
    const unused = s.note && /^(not needed|unavailable)/.test(s.note);
    return html`<cds-tag size="sm" type=${unused ? 'gray' : 'green'}>${unused ? 'Not used' : 'Used'}</cds-tag>
      ${s.entries ? html`<span class="hint">${s.entries.toLocaleString()} entries</span>` : nothing}
      ${s.note ? html`<div class="hint">${s.note}</div>` : nothing}`;
  }
  if (!present) return html`<span class="hint">Not built</span>`;
  if (!recorded) return html`<span class="hint">Not recorded</span>`;
  return html`<cds-tag size="sm" type="gray">Not used</cds-tag>`;
}

// A VPN list older than this is flagged: its servers may have moved since.
const VPN_LIST_OLD_DAYS = 180;

function vpnListDate(date) {
  if (!date) return html`<span class="hint">not stated</span>`;
  const age = (Date.now() - Date.parse(date)) / 1000;
  return html`${fmtAge(age)}
    ${age > VPN_LIST_OLD_DAYS * 86400 ? html`<cds-tag size="sm" type="warm-gray">old</cds-tag>` : nothing}
    <div class="hint">${fmtDate(date)}</div>`;
}

function vpnListTable(lists) {
  const own = lists.filter((l) => !l.source.startsWith('gluetun')).length;
  return html`<h4 class="vpn-lists-heading">
      VPN server lists in this database ${tip('VPN server lists', SOURCES_HELP.vpnLists)}
    </h4>
    <p class="hint">
      ${lists.length} providers: ${own} from the provider's own list, ${lists.length - own} from gluetun's copy.
      ${(() => {
        const old = lists.filter((l) => l.date && Date.now() - Date.parse(l.date) > VPN_LIST_OLD_DAYS * 86400000).length;
        return old ? `${old} ${old === 1 ? 'is' : 'are'} more than six months old: treat a match on ${old === 1 ? 'it' : 'them'} as weaker evidence.` : '';
      })()}
    </p>
    <div class="table-wrap">
      <cds-table size="sm">
        <cds-table-head>
          <cds-table-header-row>
            <cds-table-header-cell>Tag</cds-table-header-cell>
            <cds-table-header-cell>List</cds-table-header-cell>
            <cds-table-header-cell>Current as of</cds-table-header-cell>
          </cds-table-header-row>
        </cds-table-head>
        <cds-table-body>
          ${lists.map(
            (l) => html`<cds-table-row>
              <cds-table-cell class="mono">${l.tag}</cds-table-cell>
              <cds-table-cell>${l.source}</cds-table-cell>
              <cds-table-cell class="nowrap">${vpnListDate(l.date)}</cds-table-cell>
            </cds-table-row>`,
          )}
        </cds-table-body>
      </cds-table>
    </div>`;
}

function jobView(job) {
  const what = job.request?.databases?.length
    ? job.request.databases.join(', ')
    : job.request?.stale_only
      ? 'stale databases'
      : job.request?.incremental
        ? 'what the last update left out'
        : 'all databases on disk';
  let status = 'finished';
  let label = `Finished ${fmtDate(job.finished)}`;
  if (job.running) {
    status = 'active';
    label = `Updating ${what}…`;
  } else if (job.error) {
    status = 'error';
    label = `Failed: ${job.error}`;
  }
  return html`
    <div style="margin-top: 1rem">
      <cds-inline-loading status=${status}>${label}</cds-inline-loading>
      <div class="hint">
        ${job.trigger === 'auto' ? 'Automatic refresh' : 'Started from the API'} at ${fmtDate(job.started)} · ${what}
      </div>
      ${job.log?.length
        ? html`<pre
            class="log"
            @scroll=${(e) => {
              const el = e.target;
              logPinned = el.scrollTop + el.clientHeight >= el.scrollHeight - 8;
            }}>${job.log.join('\n')}</pre>`
        : nothing}
    </div>
  `;
}

// Settings

function openSettings() {
  Object.assign(state.settings, { open: true, base: getApiBase(), testing: false, result: null, family: prefs.family, rdns: prefs.rdns });
  update();
}

async function testSettings() {
  const s = state.settings;
  s.base = document.getElementById('api-base')?.value ?? s.base;
  s.testing = true;
  s.result = null;
  update();
  const base = s.base.trim().replace(/\/+$/, '');
  try {
    const h = await api.health(base);
    s.result = { ok: true, text: `Reached asname ${h?.version || ''}`.trim() };
  } catch (err) {
    s.result = { ok: false, text: errorText(err) };
  }
  s.testing = false;
  update();
}

function saveSettings() {
  const s = state.settings;
  s.base = document.getElementById('api-base')?.value ?? s.base;
  setApiBase(s.base);
  // The family is every screen's starting point: apply it now too.
  if (s.family !== prefs.family) {
    prefs.family = s.family;
    DEFAULT_FILTERS.family = s.family;
    state.search.family = s.family;
    state.explore.f.family = s.family;
  }
  if (s.rdns !== prefs.rdns) {
    prefs.rdns = s.rdns;
    state.lookup.rdns = s.rdns;
  }
  savePrefs(prefs);
  s.open = false;
  state.status = null;
  update();
  refreshStatus();
}

// ---------- glossary ----------

const slug = (t) => t.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');

// glossaryTag wraps a tag in a link to its glossary entry, when it has one.
// key is the tag or list name; it defaults to the tag's text.
function glossaryTag(tagHtml, key) {
  const term = glossaryTerm(key);
  return term ? html`<a class="tag-link" href="#/glossary?t=${slug(term)}" title="${term}: what it means">${tagHtml}</a>` : tagHtml;
}

// termLink links a label to its glossary entry (LABEL_TERMS, or term).
function termLink(label, term = LABEL_TERMS[label]) {
  return term ? html`<a class="term-link" href="#/glossary?t=${slug(term)}" title="${term}: what it means">${label}</a>` : label;
}

// linkTerms links every glossary term a data source's description names.
function linkTerms(text) {
  return sourceTerms(text).map((p) => (typeof p === 'string' ? p : termLink(p[0], p[1])));
}

// sourceGlossary is a small glossary link for a data source named name.
function sourceGlossary(name) {
  const term = sourceTerms(name).find((p) => typeof p !== 'string');
  return term ? html`<a class="term-link glossary-mini" href="#/glossary?t=${slug(term[1])}" title="${term[1]}: what it means">glossary</a>` : nothing;
}

// entryBody is a glossary entry's text: the definition, what it means in
// an investigation, how it works, and where to read more. linkify turns
// mentions of other entries into links when given.
function entryBody(t, linkify = (x) => x) {
  return html`<p class="g-body">${linkify(t.body)}</p>
    ${t.practice?.length
      ? html`<div class="g-block g-practice">
          <div class="g-label">In an investigation</div>
          <ul>${t.practice.map((x) => html`<li>${linkify(x)}</li>`)}</ul>
        </div>`
      : nothing}
    ${t.detail?.length
      ? html`<div class="g-block g-detail">
          <div class="g-label">Under the hood</div>
          <ul>${t.detail.map((x) => html`<li>${linkify(x)}</li>`)}</ul>
        </div>`
      : nothing}
    ${t.links?.length
      ? html`<div class="g-links">${t.links.map(([label, url]) => html`<a href=${url} target="_blank" rel="noopener noreferrer">${label}</a>`)}</div>`
      : nothing}`;
}

// glossaryEntries is every glossary entry by its slug.
function glossaryEntries() {
  const out = new Map();
  for (const sec of [...GLOSSARY, tagGlossary()]) for (const t of sec.terms) if (!out.has(slug(t.term))) out.set(slug(t.term), { ...t, section: sec.section });
  return out;
}

// ---------- glossary side panel ----------
// A glossary link opens its entry in a panel beside the page, so the
// result stays where it was. Ctrl-, Cmd-, Shift- or middle-click still
// follow the link to the Glossary page.

function openTerm(id) {
  const p = state.gpanel;
  if (p.stack[p.stack.length - 1] !== id) p.stack.push(id);
  update();
  setTimeout(() => document.querySelector('.gpanel-body')?.scrollTo(0, 0), 0);
}

function closeTerms() {
  state.gpanel.stack = [];
  update();
}

// seeLinks turns "see Tor exit node above" in an entry's text into a link
// that opens that entry in the panel.
// entryLinks links, in one glossary entry's text, the other entries it
// mentions: each once per entry, and never the entry itself.
function entryLinks(entries, self) {
  const see = seeLinks(entries);
  const linked = new Set([self]);
  return (text) =>
    see(text).flatMap((part) =>
      typeof part !== 'string'
        ? [part]
        : glossaryMentions(part).map((p) => {
            if (typeof p === 'string') return p;
            const id = slug(p[1]);
            if (linked.has(id) || !entries.has(id)) return p[0];
            linked.add(id);
            return termLink(p[0], p[1]);
          }),
    );
}

function seeLinks(entries) {
  return (text) => {
    const parts = String(text).split(/(see [^.;:,()]+? (?:above|below))/);
    return parts.map((part) => {
      const m = part.match(/^see (.+) (above|below)$/);
      const id = m && slug(m[1]);
      return id && entries.has(id)
        ? html`see <a class="term-link" href="#/glossary?t=${id}">${m[1]}</a>`
        : part;
    });
  };
}

function gpanelView() {
  const p = state.gpanel;
  if (!p.stack.length) return nothing;
  const entries = glossaryEntries();
  const id = p.stack[p.stack.length - 1];
  const t = entries.get(id);
  const back = () => {
    p.stack.pop();
    update();
  };
  return html`
    <div class="gpanel-scrim" @click=${closeTerms}></div>
    <aside class="gpanel" role="dialog" aria-modal="false" aria-label="Glossary: ${t?.term || id}">
      <div class="gpanel-head">
        ${p.stack.length > 1
          ? html`<button type="button" class="gpanel-btn" title="Back to ${entries.get(p.stack[p.stack.length - 2])?.term || 'the previous entry'}" aria-label="Back" @click=${back}>←</button>`
          : nothing}
        <div class="gpanel-title">
          <div class="gpanel-section">${t?.section || 'Glossary'}</div>
          <h2>${t?.term || id}</h2>
          ${t?.aka ? html`<div class="g-aka">${t.aka}</div>` : nothing}
        </div>
        <button type="button" class="gpanel-btn" title="Close (Esc)" aria-label="Close" @click=${closeTerms}>✕</button>
      </div>
      <div class="gpanel-body glossary-entry">
        ${t ? entryBody(t, entryLinks(entries, id)) : html`<p class="empty">No glossary entry for this.</p>`}
      </div>
      <div class="gpanel-foot">
        <a class="g-open-full" href="#/glossary?t=${id}" @click=${() => (state.gpanel.stack = [])}>Open in Glossary</a>
      </div>
    </aside>
  `;
}

document.addEventListener('click', (e) => {
  if (e.defaultPrevented || e.button !== 0 || e.ctrlKey || e.metaKey || e.shiftKey || e.altKey) return;
  const a = e.composedPath().find((el) => el instanceof HTMLAnchorElement);
  const href = a?.getAttribute('href') || '';
  if (!href.startsWith('#/glossary?t=') || a.classList.contains('g-open-full') || state.tab === 'glossary') return;
  e.preventDefault();
  openTerm(new URLSearchParams(href.split('?')[1]).get('t'));
});

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && state.gpanel.stack.length) closeTerms();
});

// focusGlossary scrolls to a glossary entry and marks it.
function focusGlossary(id) {
  const g = state.glossary;
  g.filter = '';
  g.focus = id;
  update();
  setTimeout(() => document.getElementById(`g-${id}`)?.scrollIntoView({ block: 'start' }), 0);
}

function glossaryView() {
  const g = state.glossary;
  const allEntries = glossaryEntries();
  const q = g.filter.trim().toLowerCase();
  const sections = [...GLOSSARY, tagGlossary()]
    .map((sec) => ({
      ...sec,
      terms: q
        ? sec.terms.filter((t) => [t.term, t.aka, t.body, ...(t.practice || []), ...(t.detail || [])].join(' ').toLowerCase().includes(q))
        : sec.terms,
    }))
    .filter((sec) => sec.terms.length);
  return html`
    <p class="lede">What the terms on these pages mean, and where to read more.</p>
    <div class="glossary-head">
      <cds-text-input
        class="glossary-filter"
        label="Find a term"
        hide-label
        placeholder="Find a term: ASN, DROP, netname, personal…"
        .value=${g.filter}
        @input=${(e) => {
          g.filter = e.target.value;
          update();
        }}></cds-text-input>
      <nav class="glossary-nav" aria-label="Sections">
        ${sections.map(
          (sec) => html`<button type="button" class="link-button" @click=${() => document.getElementById(`g-${slug(sec.section)}`)?.scrollIntoView({ behavior: 'smooth', block: 'start' })}>${sec.section}</button>`,
        )}
      </nav>
    </div>
    ${sections.length
      ? sections.map(
          (sec) => html`<section class="glossary-section" id="g-${slug(sec.section)}">
            <h2>${sec.section}</h2>
            ${sec.intro ? html`<p class="hint">${sec.intro}</p>` : nothing}
            <dl class="glossary-list">
              ${sec.terms.map(
                (t) => html`<div class="glossary-entry ${g.focus === slug(t.term) ? 'g-focus' : ''}" id="g-${slug(t.term)}">
                  <dt>
                    <span class="g-term">${t.term}</span>
                    ${t.aka ? html`<span class="g-aka">${t.aka}</span>` : nothing}
                  </dt>
                  <dd>${entryBody(t, entryLinks(allEntries, slug(t.term)))}</dd>
                </div>`,
              )}
            </dl>
          </section>`,
        )
      : html`<p class="empty">No term matches “${g.filter}”.</p>`}
  `;
}

// ---------- help ----------

function openHelp() {
  state.help.open = true;
  update();
}

// helpView is the guide behind the header's Help button: how to read the
// answers, terse enough for someone who knows the field.
function helpView() {
  const h = state.help;
  if (!h.open) return nothing;
  const level = (l, text) => html`<span class="help-level finding-${l}">${LEVEL_LABEL[l]}</span> ${text}`;
  return html`
    <cds-modal open size="lg" @cds-modal-closed=${() => ((h.open = false), update())}>
      <cds-modal-header>
        <cds-modal-close-button></cds-modal-close-button>
        <cds-modal-heading>Help</cds-modal-heading>
      </cds-modal-header>
      <cds-modal-body class="help-ref">
        <p class="help-glossary">New to the terms? The <a href="#/glossary" @click=${() => ((state.help.open = false), update())}>Glossary</a> explains ASNs, registries, netblocks, blocklists and every tag.</p>
        <p>
          asname tells you who is behind an IP address, hostname, URL or AS number: the network that routes it, who the
          block is registered to, where it most likely is, what kind of network it is and whether public blocklists name
          it. Everything comes from databases on this machine; nothing you look up leaves it unless you turn on Online
          lookups.
        </p>

        <section>
          <h3>Lookup</h3>
          <dl class="help-dl">
            <div><dt>Input</dt><dd>One target per line, or paste anything (a log, an alert, a ticket, a web page) and the IPs, URLs, domains and ASNs are picked out, defanged ones (<code>hxxp</code>, <code>[.]</code>) included. Ctrl+Enter looks up.</dd></div>
            <div><dt>Reverse DNS</dt><dd>Also asks DNS for each address's name. This does go out, to your resolver.</dd></div>
            <div><dt>Online lookups</dt><dd>Asks the registry (RDAP or whois) when the offline netblock data cannot name the block (most ARIN and LACNIC space), and RIPEstat for prefixes missing offline. Off unless the server allows it.</dd></div>
          </dl>
        </section>

        <section>
          <h3>Reading a result</h3>
          <dl class="help-dl">
            <div><dt>Who is it?</dt><dd>The most specific owner known: the netblock's registered organisation, else the AS that announces it. They often differ: a customer's block is routed by its provider, a hosting customer sits inside a cloud's AS.</dd></div>
            <div><dt>Where is it?</dt><dd>The location the sources agree on, grouped by country. Treat a city as a guess; a country is usually right.</dd></div>
            <div><dt>Location</dt><dd>
              Up to three independent answers.
              <strong>Geofeed</strong>: what the network's operator publishes for its own ranges (RFC 8805), used only inside the ranges that name the feed.
              <strong>GeoLite2</strong> (MaxMind) and <strong>DB-IP</strong>: commercial estimates.
              When a geofeed disagrees with both estimates it is flagged: some VPN and proxy providers publish where they want their exits to appear, not where they are.
            </dd></div>
            <div><dt>Country (registry)</dt><dd>Where the block is registered, from the RIR delegation files. That is the holder's country, not necessarily where the address is used.</dd></div>
            <div><dt>Network</dt><dd>The AS announcing the address, its name and its announced prefixes.</dd></div>
            <div><dt>Netblock</dt><dd>The registry record (RIPE, APNIC, AFRINIC, ARIN where available): range, netname, organisation, registration date. Tags such as hosting, broadband, CGNAT or leased are inferred from it and say so.</dd></div>
            <div><dt>Category</dt><dd>Cloud, CDN, hosting, VPN, Tor, ISP, mobile and so on, from public lists of provider ranges.</dd></div>
            <div><dt>Reputation</dt><dd>
              <strong>Address</strong>: lists naming this exact address or its block (Spamhaus DROP, FireHOL level 2 = attacking in the last 48 h, level 3 = 30 days, IPsum = number of feeds naming it, 3+ is the usual blocking threshold).
              <strong>Network</strong>: the whole AS, Spamhaus ASN-DROP, and the share of its space that is listed.
            </dd></div>
          </dl>
        </section>

        <section>
          <h3>Findings</h3>
          <p>The panel at the end of each result says what the data means, worst first.</p>
          <ul class="help-levels">
            <li>${level('high', 'Block or treat as hostile: DROP, ASN-DROP, recent attacks, 3+ threat feeds.')}</li>
            <li>${level('medium', 'Look closer: Tor, VPN, leased or new space, weak list hits, a location the sources dispute.')}</li>
            <li>${level('info', 'Context worth knowing: shared CGNAT addresses, cloud tenancy, missing data.')}</li>
            <li>${level('ok', 'Nothing found against it.')}</li>
          </ul>
          <p><strong>Copy summary</strong> copies the result as text for a ticket; <strong>Copy JSON</strong> copies it as the API returns it.</p>
        </section>

        <section>
          <h3>Search</h3>
          <dl class="help-dl">
            <div><dt>What it searches</dt><dd>AS names, and the organisation names and netnames registered in whois. Use a distinctive word or a handle (<code>roblox</code>, <code>MSSTATE</code>), not the full legal name. Fuzzy match also ignores spaces and punctuation and matches word by word.</dd></div>
            <div><dt>An AS number</dt><dd><code>AS47692</code> lists every registry netblock inside that AS's announced prefixes: its own allocations and its customers' assignments, whatever they are named. A name search cannot find a customer block named something else (Nessus's <code>KNOX</code> block, say); this can.</dd></div>
            <div><dt>Country</dt><dd>Keeps ASNs registered in that country and netblocks registered there. Applied before the limit, so nothing is cut off by it.</dd></div>
            <div><dt>Limit</dt><dd>The most of each table returned.</dd></div>
            <div><dt>Copy</dt><dd>
              <strong>ASNs</strong>: the matching AS names' numbers (not the providers announcing the netblocks).
              <strong>Prefixes</strong>: those ASNs' announced prefixes plus the netblocks' CIDRs, deduplicated, sorted, IPv4 first: ready for a block list or a query.
              <strong>Table</strong>: both tables as shown, aligned. <strong>CSV</strong>: one row per ASN and netblock. <strong>JSON</strong>: the API's answer.
            </dd></div>
            <div><dt>Sorting</dt><dd>Click a column heading. The copies follow the order shown.</dd></div>
          </dl>
        </section>

        <section>
          <h3>Explore</h3>
          <p>
            Every prefix in the routing table, with its origin AS, registry country, kind of network and blocklist hits. Filters
            combine; click a country, kind or AS under the count to filter on it.
          </p>
          <dl class="help-dl">
            <div><dt>Prefix length</dt><dd><code>8</code> for every /8, <code>16-24</code> for a range.</dd></div>
            <div><dt>Countries</dt><dd>Registry country: where the block's holder registered it. Origin AS country: where the announcing AS is registered. Neither is where users are.</dd></div>
            <div><dt>Kind of network</dt><dd>Kept when both ends of the prefix carry the tag, or its AS does, so a tag on a few addresses (a Tor exit, a VPN server) does not label the whole prefix.</dd></div>
            <div><dt>Reputation</dt><dd>
              <strong>Spamhaus DROP (all of it)</strong>: hijacked or criminal space. <strong>(any of it)</strong>: a DROP block inside a larger prefix, common in big carriers.
              <strong>Listed share</strong>: the prefix's addresses on IPsum or FireHOL, as a share of its size (IPv4).
            </dd></div>
            <div><dt>Copy</dt><dd>Prefixes, origin ASNs, table, CSV or JSON, for the page shown. Raise Per page for more.</dd></div>
          </dl>
        </section>

        <section>
          <h3>Databases</h3>
          <p>
            What is on disk, how old it is and where it comes from. Stale databases are refreshed automatically when the server allows updates.
            Geofeeds are opt-in: build them once and they are refreshed with the rest, each feed at most once a day.
          </p>
        </section>

        <section>
          <h3>Command line</h3>
          <pre class="help-cli">asname 8.8.8.8 dns.google AS13335
asname -c -n 185.220.101.1          # with city and netblock
cat alert.txt | asname              # targets picked out of any text
asname search roblox --in US --ips-only
asname search AS47692               # every netblock inside the AS
asname -j 1.1.1.1                   # JSON; -C for CSV</pre>
          <p>The header's API button lists every HTTP endpoint with examples.</p>
        </section>
      </cds-modal-body>
    </cds-modal>
  `;
}

// ---------- HTTP API reference ----------

function openAPI() {
  state.api.open = true;
  state.api.copied = '';
  update();
}

// apiBase is the address the examples use: the configured API, else this
// page's own server.
function apiBase() {
  return (getApiBase() || location.origin).replace(/\/$/, '');
}

const LOOKUP_PARAMS = [
  ['reverse_dns=true', 'Also look up each address\'s reverse DNS name.'],
  ['text=true', 'Add "text": the result as asname -p prints it, for pasting into a ticket.'],
  ['whois=true', "Ask the registry over RDAP (or whois) when the offline netblock database cannot name the block."],
  ['online_prefixes=true', "Ask RIPEstat for an ASN's prefixes when the offline prefix database lacks them."],
  ['online=true', 'Both of the above.'],
];

// apiEndpoints describes the API. curl is the example request; open, for a
// GET, is the URL to try it in the browser.
function apiEndpoints(base) {
  const json = `-H 'Content-Type: application/json'`;
  const groups = [
    {
      title: 'Lookups',
      note: 'An IP address, hostname, URL or ASN. Each answers {"query", "count", "results": [...]}, every result as asname -j prints it: asn, country, city, city_maxmind, geofeed, netblock, category, reputation, prefixes.',
      params: LOOKUP_PARAMS,
      endpoints: [
        { method: 'GET', path: '/v1/lookup?q={target}', what: 'Look up one target.', curl: `curl -s '${base}/v1/lookup?q=8.8.8.8'`, open: `${base}/v1/lookup?q=8.8.8.8` },
        { method: 'GET', path: '/v1/lookup/{target}', what: 'The same, with the target in the path.', curl: `curl -s ${base}/v1/lookup/AS13335`, open: `${base}/v1/lookup/AS13335` },
        { method: 'GET', path: '/v1/lookup/b64/{base64url}', what: 'A target that is awkward in a URL, base64url-encoded.', curl: `curl -s ${base}/v1/lookup/b64/${btoa('https://example.com/a?b=c').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')}` },
        { method: 'POST', path: '/v1/bulk', what: 'Many targets as JSON. The query parameters above go in the body.', curl: `curl -s -X POST ${base}/v1/bulk ${json} \\\n  -d '{"targets": ["8.8.8.8", "AS15169", "dns.google"], "reverse_dns": true}'` },
        { method: 'POST', path: '/v1/bulk', what: 'Any text: a list, a log, an alert. IPs, URLs, domains and ASNs are picked out of it, defanged ones included; one result per target found.', curl: `curl -s -X POST ${base}/v1/bulk --data-binary @alert.txt` },
      ],
    },
    {
      title: 'Search',
      note: 'AS names and registry netblocks by organisation name or netname. AS matches come in "asns", netblocks in "results".',
      params: [
        ['scope=asns|netblocks', 'Search only one (default: both).'],
        ['fuzzy=true', 'Also match misspellings and run-together words.'],
        ['limit=N', 'At most N of each (default 50).'],
        ['country=AU', 'Only ASNs registered in that country and netblocks the country database places there (a code or an English name; default: worldwide).'],
        ['v4_only=true, v6_only=true', 'Only IPv4 or only IPv6 prefixes and ranges.'],
      ],
      endpoints: [
        { method: 'GET', path: '/v1/search?q={name}', what: 'Search by name.', curl: `curl -s '${base}/v1/search?q=cloudflare&limit=10'`, open: `${base}/v1/search?q=cloudflare&limit=10` },
        { method: 'GET', path: '/v1/search?q=AS47692', what: 'Every registry netblock inside an AS\'s announced prefixes.', curl: `curl -s '${base}/v1/search?q=AS47692&scope=netblocks'`, open: `${base}/v1/search?q=AS47692&scope=netblocks` },
      ],
    },
    {
      title: 'Explore',
      note: 'Announced prefixes with origin AS, registry country, tags and blocklist hits. Answers {"count", "ipv4_addresses", "results", "countries", "tags", "asns", "all_tags"}; the last four break the matches down. The first call builds an index (a few seconds).',
      params: [
        ['len=8, len=16-24', 'Prefix length, or a range.'],
        ['family=v4|v6', 'One address family.'],
        ['country=AU, as_country=AU', 'Registry country of the prefix; country of the origin AS.'],
        ['asn=AS13335', 'One origin AS.'],
        ['tag=hosting,vpn', 'Any of these kinds of network (repeatable).'],
        ['reputation=…', 'listed, clean, drop (all of it), drop-inside, asn-drop, firehol2, firehol3.'],
        ['min_ipsum=N, min_listed_pct=P', 'An address on N+ IPsum feeds; P% or more of the prefix listed.'],
        ['sort=address|size|listed|share', 'Order (default address).'],
        ['limit=N, offset=N', 'Page (default 500; limit=0 for the counts alone).'],
      ],
      endpoints: [
        { method: 'GET', path: '/v1/explore', what: 'Filter the routing table.', curl: `curl -s '${base}/v1/explore?country=AU&reputation=drop'`, open: `${base}/v1/explore?country=AU&reputation=drop` },
      ],
    },
    {
      title: 'Server',
      endpoints: [
        { method: 'GET', path: '/v1/status', what: 'The databases on disk and loaded, their age and sources, and the last update.', curl: `curl -s ${base}/v1/status`, open: `${base}/v1/status` },
        { method: 'GET', path: '/health', what: 'Liveness, for monitoring.', curl: `curl -s ${base}/health`, open: `${base}/health` },
      ],
    },
  ];
  if (state.status?.updates_enabled) {
    groups.push({
      title: 'Updates and settings',
      note: 'This server was started with --allow-updates. Only one update runs at a time.',
      endpoints: [
        { method: 'POST', path: '/v1/update', what: 'Rebuild databases by name (asn, names, country, city, netblock, geofeed, category, reputation); {} rebuilds every one on disk; "stale_only" or "incremental" as asname update does.', curl: `curl -s -X POST ${base}/v1/update ${json} -d '{"databases": ["reputation"]}'` },
        { method: 'GET', path: '/v1/update', what: 'The running or last update and its log.', curl: `curl -s ${base}/v1/update`, open: `${base}/v1/update` },
        { method: 'DELETE', path: '/v1/update', what: 'Cancel the running update.', curl: `curl -s -X DELETE ${base}/v1/update ${json}` },
        { method: 'PUT', path: '/v1/settings', what: 'The refresh age in hours (0 is never), and whether ASN updates import IPv6 routes.', curl: `curl -s -X PUT ${base}/v1/settings ${json} -d '{"max_age_hours": 168}'` },
      ],
    });
  }
  return groups;
}

async function copyCurl(text) {
  try {
    await navigator.clipboard.writeText(text);
    state.api.copied = text;
  } catch {
    state.api.copied = '';
  }
  update();
  setTimeout(() => {
    if (state.api.copied === text) {
      state.api.copied = '';
      update();
    }
  }, 2000);
}

function apiView() {
  const a = state.api;
  if (!a.open) return nothing;
  const base = apiBase();
  return html`
    <cds-modal open size="lg" @cds-modal-closed=${() => ((a.open = false), update())}>
      <cds-modal-header>
        <cds-modal-close-button></cds-modal-close-button>
        <cds-modal-heading>HTTP API</cds-modal-heading>
      </cds-modal-header>
      <cds-modal-body class="api-ref">
        <p>Everything this page does goes through this API, at <code>${base}</code>. Answers are JSON.</p>
        ${apiEndpoints(base).map(
          (g) => html`<section>
            <h3>${g.title}</h3>
            ${g.note ? html`<p class="api-note">${g.note}</p>` : nothing}
            ${g.endpoints.map(
              (e) => html`<div class="api-endpoint">
                <div class="api-line">
                  <span class="api-method api-${e.method.toLowerCase()}">${e.method}</span>
                  <code>${e.path}</code>
                  <span class="api-what">${e.what}</span>
                </div>
                <div class="api-example">
                  <pre>${e.curl}</pre>
                  <cds-button kind="ghost" size="sm" @click=${() => copyCurl(e.curl)}>${a.copied === e.curl ? 'Copied' : 'Copy'}</cds-button>
                  ${e.open ? html`<cds-button kind="ghost" size="sm" href=${e.open} target="_blank">Open</cds-button>` : nothing}
                </div>
              </div>`,
            )}
            ${g.params
              ? html`<dl class="api-params">
                  ${g.params.map(([p, d]) => html`<div><dt><code>${p}</code></dt><dd>${d}</dd></div>`)}
                </dl>`
              : nothing}
          </section>`,
        )}
        <p class="api-note">
          Another site's page can call it only if the server runs with --cors; updates are only taken from this server's own page.
          The full guide is in the README under "REST API server".
        </p>
      </cds-modal-body>
    </cds-modal>
  `;
}

function settingsView() {
  const s = state.settings;
  return html`
    <cds-modal ?open=${s.open} size="sm" @cds-modal-closed=${() => ((s.open = false), update())}>
      <cds-modal-header>
        <cds-modal-close-button></cds-modal-close-button>
        <cds-modal-heading>Settings</cds-modal-heading>
      </cds-modal-header>
      <cds-modal-body>
        <cds-text-input
          id="api-base"
          label="asname API"
          placeholder="Same origin as this page"
          helper-text="Leave empty to use the asname that served this page. Another server must run with --cors, and only accepts updates from its own page."
          .value=${s.base}></cds-text-input>
        <div class="actions" style="margin-top: 1rem">
          <cds-button kind="tertiary" size="sm" @click=${testSettings} ?disabled=${s.testing}>Test connection</cds-button>
          ${s.testing ? html`<cds-inline-loading status="active">Testing…</cds-inline-loading>` : nothing}
          ${s.result ? html`<cds-inline-loading status=${s.result.ok ? 'finished' : 'error'}>${s.result.text}</cds-inline-loading>` : nothing}
        </div>
        <div class="settings-prefs">
          <cds-select
            label-text="Address family"
            helper-text="Every screen starts with this. Lookups keep only these addresses of a hostname (an address you paste is always looked up); Search and Explore start on it and can still switch."
            value=${s.family}
            @cds-select-selected=${(e) => (s.family = e.target.value)}>
            ${Object.entries(FAMILY_NAMES).map(([v, label]) => html`<cds-select-item value=${v}>${label}</cds-select-item>`)}
          </cds-select>
          <cds-toggle
            label-text="Reverse DNS by default"
            ?checked=${s.rdns}
            @cds-toggle-changed=${(e) => (s.rdns = e.target.checked)}></cds-toggle>
        </div>
        <p class="hint" style="margin-top: 1rem">
          Saved in this browser, along with the theme. The refresh age and IPv6 routes are server settings, on the Databases tab.
        </p>
      </cds-modal-body>
      <cds-modal-footer>
        <cds-modal-footer-button kind="secondary" data-modal-close>Cancel</cds-modal-footer-button>
        <cds-modal-footer-button kind="primary" @click=${saveSettings}>Save</cds-modal-footer-button>
      </cds-modal-footer>
    </cds-modal>
  `;
}

// ---------- render ----------

function view() {
  let body;
  if (state.tab === 'search') body = searchView();
  else if (state.tab === 'explore') body = exploreView();
  else if (state.tab === 'glossary') body = glossaryView();
  else if (state.tab === 'databases') body = databasesView();
  else body = lookupView();
  return html`
    ${headerView()}
    <main id="main-content">
      <section class="intro">
        <h1>asname Web Interface</h1>
        <div class="subtitle">
          <span>Who is behind an IP address: its network, owner, location and reputation, from databases on this machine.</span>
          <button class="help-trigger" type="button" aria-label="Help" title="Help" @click=${openHelp}>${iconLoader(Help16)}</button>
        </div>
      </section>
      ${tabsView()}
      <div class="notifications">${bannerView()}</div>
      ${body}
    </main>
    ${settingsView()}
    ${apiView()}
    ${helpView()}
    ${gpanelView()}
  `;
}

const root = document.getElementById('app');
function update() {
  render(view(), root);
}

applyTheme();
window.addEventListener('hashchange', route);
// Status first, so the first lookup knows which online lookups exist.
refreshStatus().finally(route);
