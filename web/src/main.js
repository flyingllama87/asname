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
import '@carbon/web-components/es/components/toggle-tip/toggletip.js';

import { iconLoader } from '@carbon/web-components/es/globals/internal/icon-loader.js';
import Asleep20 from '@carbon/icons/es/asleep/20.js';
import Light20 from '@carbon/icons/es/light/20.js';
import Settings20 from '@carbon/icons/es/settings/20.js';

import { html, nothing, render } from 'lit';
import { api, ApiError, getApiBase, setApiBase } from './api.js';
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
} from './help.js';

const THEME_KEY = 'asname.theme';
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
  city: 'DB-IP City Lite geolocation, offline',
  netblock: 'RIR WHOIS dumps, offline',
  netblockCountry: 'Netblock registration in RIR WHOIS dumps (RIPE NCC, APNIC, AFRINIC), offline',
  whois: 'Live WHOIS (IANA referral to the RIR)',
  category: 'Cloud provider ranges, Tor exits, VPN server lists, bgp.tools tags, PeeringDB, offline',
  rdns: 'Live DNS PTR query',
  rep: 'Spamhaus DROP and ASN-DROP, IPsum, FireHOL level 2 and 3, offline',
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
    rdns: false,
    online: null, // null: the server's default
    loading: false,
    error: '',
    results: [],
    errors: [],
    ran: '',
    asked: { rdns: false, online: false },
    showAll: {},
    copied: '',
  },
  search: {
    q: '',
    scope: 'all',
    limit: 50,
    family: 'any',
    loading: false,
    error: '',
    data: null,
    fuzzy: false,
    ranFuzzy: false,
    sort: { asns: null, blocks: null },
  },
  db: { selected: new Set(), busy: false, error: '', notice: '', saving: '', settingsError: '' },
  settings: { open: false, base: getApiBase(), testing: false, result: null },
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
// #/lookup?q=…  #/search?q=…  #/databases

function parseHash() {
  const raw = location.hash.replace(/^#\/?/, '');
  const [path, query = ''] = raw.split('?');
  const tab = ['lookup', 'search', 'databases'].includes(path) ? path : 'lookup';
  const p = new URLSearchParams(query);
  return { tab, q: p.get('q') || '', fuzzy: p.get('fuzzy') === '1' };
}

function go(hash) {
  if (location.hash === hash) route();
  else location.hash = hash;
}

function route() {
  const { tab, q, fuzzy } = parseHash();
  state.tab = tab;
  if (tab === 'lookup' && q) {
    state.lookup.input = q;
    runLookup(q);
  } else if (tab === 'search' && q) {
    state.search.q = q;
    state.search.fuzzy = fuzzy;
    runSearch();
  }
  update();
}

// ---------- API calls ----------

function errorText(err) {
  return err instanceof ApiError ? err.message : String(err?.message || err);
}

function targetsOf(text) {
  return text
    .split(/[\n,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
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
        ? await api.lookup(targets[0], { reverseDNS: l.rdns, online, signal })
        : await api.bulk(targets, { reverseDNS: l.rdns, online, signal });
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
  Object.assign(s, { loading: true, error: '', data: null, ranFuzzy: s.fuzzy });
  update();
  try {
    s.data = await api.search(
      { q: s.q.trim(), scope: s.scope, limit: s.limit, family: s.family, fuzzy: s.fuzzy },
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
  return `${Math.round(h / 24)} days ago`;
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
    }}>${label}${help ? tip(label, help) : nothing}</cds-table-header-cell>`;
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
          ${label}${source ? html` <span class="source">${source}</span>` : nothing}
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

function tabsView() {
  return html`
    <cds-tabs class="tabs" value=${state.tab} @cds-tabs-selected=${(e) => go(`#/${e.detail.item.value}`)}>
      <cds-tab value="lookup">Lookup</cds-tab>
      <cds-tab value="search">Search</cds-tab>
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
    l.input = text;
    const targets = targetsOf(text);
    if (targets.length) go(`#/lookup?q=${encodeURIComponent(targets.join('\n'))}`);
  };
  return html`
    <p class="lede">Look up IP addresses, hostnames, URLs or ASNs, one per line. Answers come from the local databases.</p>
    <div class="form">
      <cds-textarea
        id="lookup-input"
        label="Targets"
        rows="4"
        placeholder="8.8.8.8&#10;dns.google&#10;AS13335"
        helper-text="One per line, or separated by commas. Ctrl+Enter to look up."
        .value=${l.input}
        @input=${(e) => (l.input = e.target.value)}
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
          : nothing}
        <cds-button @click=${submit} ?disabled=${l.loading}>Look up</cds-button>
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

const LEVEL_LABEL = { high: 'High', medium: 'Caution', info: 'Note', ok: 'OK' };

function findingsView(r, loaded) {
  const where = whereIs(r);
  const points = findings(r, loaded);
  if (!where && !points.length) return nothing;
  const worst = points[0]?.level || 'info';
  return html`<section class="findings findings-${worst}" aria-label="What this means">
    <h4>What this means</h4>
    ${where ? html`<p class="where"><strong>Where is it?</strong> ${where}</p>` : nothing}
    ${points.length
      ? html`<ul>
          ${points.map((f) => html`<li class="finding finding-${f.level}"><span class="level">${LEVEL_LABEL[f.level]}</span><span>${f.text}</span></li>`)}
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
      ? unknown('Not announced')
      : html`${asnLink(r.asn.asn_string || `AS${r.asn.number}`)} ${r.asn.name || ''}`
    : nothing;
  if (r.asn?.announced !== false) {
    if (!isASN) sources.push(['ASN', SRC.rib]);
    sources.push(['Organization', SRC.asNames]);
  }

  // Country: an address's comes from the RIR delegation, unless its
  // netblock names a different one; an ASN's from its AS name.
  let countryFields;
  if (isASN) {
    countryFields = field('Country', r.country ? countryText(r.country) : unknown(), 'AS registration', FIELD_HELP.countryASN);
    sources.push(['Country', SRC.asNames]);
  } else if (nbCountry) {
    countryFields = html`${field('Registered in', countryText(nbCountry), 'netblock registration', FIELD_HELP.countryNetblock)}
      ${field('Allocated in', r.country ? countryText(r.country) : unknown(), 'RIR allocation', FIELD_HELP.allocatedIn)}`;
    sources.push(['Registered in', SRC.netblockCountry], ['Allocated in', SRC.rir]);
  } else {
    countryFields = field('Country', r.country ? countryText(r.country) : unknown(), 'RIR registration', FIELD_HELP.countryRIR);
    sources.push(['Country', SRC.rir]);
  }

  // City
  let cityBody = nothing;
  if (!isASN && (r.city?.present || loaded.city)) {
    cityBody = r.city?.present ? r.city.name : unknown();
    sources.push(['City', SRC.city]);
  }

  // Netblock: shown when the netblock database is loaded or whois was asked.
  const askedWhois = l.asked.online && avail.whois;
  let netblockBody = nothing;
  if (!isASN && nb) {
    const name = nb.organization || nb.raw;
    netblockBody = html`${name}
      <span class="meta">
        ${[nb.handle && nb.handle !== name ? nb.handle : '', nb.created ? `registered ${nb.created}` : '', nb.live_query ? 'live whois' : 'offline index']
          .filter(Boolean)
          .join(' · ')}
      </span>`;
    sources.push(['Netblock', nb.live_query ? SRC.whois : SRC.netblock]);
  } else if (!isASN && (loaded.netblock || askedWhois)) {
    netblockBody = html`${unknown(askedWhois ? 'None found, offline or by whois' : 'Not in the offline index')}
      ${!askedWhois && avail.whois
        ? html`<span class="meta">Some registries (ARIN, LACNIC) don't publish this offline; turn on Online lookups to ask whois.</span>`
        : nothing}`;
    sources.push(['Netblock', askedWhois ? `${SRC.netblock}; ${SRC.whois}` : SRC.netblock]);
  }

  // Category
  const catTags = r.category?.tags || [];
  let categoryBody = nothing;
  if (catTags.length) {
    categoryBody = html`<div class="tags">${catTags.map((t) => html`<cds-tag size="sm" type=${t.includes(':') || t === 'tor-exit' || t === 'anonymised-holder' ? 'purple' : 'teal'}>${t}</cds-tag>`)}</div>`;
    sources.push(['Category', SRC.category]);
  } else if (loaded.category) {
    categoryBody = unknown();
    sources.push(['Category', SRC.category]);
  }
  const categoryHelp = tagList(FIELD_HELP.category, catTags.map((t) => [t, categoryTagHelp(t)]));

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

  return html`
    <article class="card ${listed ? 'listed' : ''}">
      <div class="card-head">
        <div>
          <div class="card-title">${title}</div>
          ${sub ? html`<div class="card-sub">${sub}</div>` : nothing}
        </div>
        <div class="card-actions">
          <cds-button kind="ghost" size="sm" @click=${() => copySummary(r)}>Copy summary</cds-button>
          <cds-button kind="ghost" size="sm" @click=${() => copyJSON(r)}>Copy JSON</cds-button>
        </div>
      </div>
      ${findingsView(r, loaded)}
      <dl class="fields">
        ${field('ASN', asnBody, '', FIELD_HELP.asn)}
        ${countryFields}
        ${field('City', cityBody, 'DB-IP geolocation', FIELD_HELP.city)}
        ${field('Netblock', netblockBody, '', FIELD_HELP.netblock)}
        ${field('Category', categoryBody, '', categoryHelp)}
        ${field('Reputation', rep ? reputationView(rep, isASN) : nothing, '', repHelp)}
        ${field('Reverse DNS', rdnsBody, '', FIELD_HELP.rdns)}
      </dl>
      ${r.prefixes
        ? html`<div class="prefixes">
            <h3>Announced prefixes ${tip('Announced prefixes', FIELD_HELP.prefixes)}</h3>
            <div class="hint">
              ${r.prefixes.total} total · ${r.prefixes.ipv4_count} IPv4 · ${r.prefixes.ipv6_count} IPv6
              · ${r.prefixes.source === 'ripe-stat' ? 'live from RIPEstat' : 'offline index'}
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
            <dl>${sources.map(([k, v]) => html`<div><dt>${k}</dt><dd>${v}</dd></div>`)}</dl>
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

function reputationView(rep, isASN) {
  const asn = rep.asn;
  const summary = asnSummary(asn);
  return html`
    ${isASN
      ? nothing
      : rep.lists?.length
        ? html`<div class="tags">${rep.lists.map((name) => html`<cds-tag size="sm" type="red">${name}</cds-tag>`)}</div>`
        : rep.listed
          ? html`<cds-tag size="sm" type="red">Listed</cds-tag>`
          : html`<span>Address not listed</span>`}
    ${asn?.spamhaus_asn_drop ? html`<div class="tags"><cds-tag size="sm" type="red">ASN on Spamhaus ASN-DROP</cds-tag></div>` : nothing}
    ${summary ? html`<span class="meta">ASN: ${summary}</span>` : nothing}
  `;
}

// Search

function searchView() {
  const s = state.search;
  const submit = () => {
    s.q = document.getElementById('search-q')?.value ?? s.q;
    const limit = parseInt(document.getElementById('search-limit')?.value, 10);
    s.limit = Number.isFinite(limit) && limit > 0 ? limit : 50;
    if (s.q.trim()) go(`#/search?q=${encodeURIComponent(s.q.trim())}${s.fuzzy ? '&fuzzy=1' : ''}`);
  };
  const d = s.data;
  return html`
    <p class="lede">
      Search AS names and, with the netblock database, the organisations and network names registered in whois. Search
      only reads the local databases; it never goes online.
    </p>
    <div class="form search-form">
      <div class="form-row">
        <cds-text-input
          id="search-q"
          class="grow"
          label="Search for"
          placeholder="cloudflare"
          .value=${s.q}
          @input=${(e) => (s.q = e.target.value)}
          @keydown=${(e) => e.key === 'Enter' && submit()}></cds-text-input>
        <cds-number-input id="search-limit" class="limit" label="Limit" min="1" max="10000" step="10" .value=${String(s.limit)}></cds-number-input>
      </div>
      <div class="form-row">
        <cds-radio-button-group
          legend-text="Search in"
          name="scope"
          value=${s.scope}
          @cds-radio-button-group-changed=${(e) => (s.scope = e.target.value)}>
          <cds-radio-button label-text="Both" value="all" ?checked=${s.scope === 'all'}></cds-radio-button>
          <cds-radio-button label-text="AS names" value="asns" ?checked=${s.scope === 'asns'}></cds-radio-button>
          <cds-radio-button label-text="Netblocks" value="netblocks" ?checked=${s.scope === 'netblocks'}></cds-radio-button>
        </cds-radio-button-group>
        <cds-select class="family" label-text="Address family" value=${s.family} @cds-select-selected=${(e) => (s.family = e.target.value)}>
          <cds-select-item value="any">IPv4 and IPv6</cds-select-item>
          <cds-select-item value="v4">IPv4 only</cds-select-item>
          <cds-select-item value="v6">IPv6 only</cds-select-item>
        </cds-select>
      </div>
      <div class="form-row controls-row">
        ${switchWithTip('Fuzzy match', s.fuzzy, (e) => (s.fuzzy = e.target.checked), CONTROL_HELP.fuzzy)}
        <cds-button @click=${submit} ?disabled=${s.loading}>Search</cds-button>
        ${s.loading ? html`<cds-inline-loading status="active">Searching…</cds-inline-loading>` : nothing}
      </div>
    </div>
    <details class="tips">
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

function searchResults(d) {
  const sort = state.search.sort;
  const fuzzy = state.search.ranFuzzy;
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
  return html`
    ${state.search.scope !== 'netblocks'
      ? html`<h2>AS names <span class="hint">(${d.asn_count ?? asns.length})</span></h2>
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
                        <cds-table-cell>${a.country || ''}</cds-table-cell>
                        <cds-table-cell class="nowrap">${prefixCount(a) || html`<span class="muted">0</span>`}</cds-table-cell>
                        <cds-table-cell class="wrap">
                          ${a.reputation?.spamhaus_asn_drop
                            ? html`<cds-tag size="sm" type="red">Spamhaus ASN-DROP</cds-tag>`
                            : nothing}
                          <span class=${a.reputation?.listed || a.reputation?.spamhaus_asn_drop ? '' : 'muted'}>${asnSummary(a.reputation)}</span>
                        </cds-table-cell>
                      </cds-table-row>`,
                    )}
                  </cds-table-body>
                </cds-table>
              </div>`
            : html`<p class="empty">No AS names match.</p>`}`
      : nothing}
    ${state.search.scope !== 'asns' || blocks.length
      ? html`<h2>Netblocks <span class="hint">(${d.count ?? blocks.length})</span></h2>
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
                          ${b.asn && b.asn !== 'N/A' ? html`${asnLink(b.asn)} ${b.as_name || ''}` : html`<span class="muted">Not announced</span>`}
                        </cds-table-cell>
                        <cds-table-cell>${b.country || ''}</cds-table-cell>
                      </cds-table-row>`,
                    )}
                  </cds-table-body>
                </cds-table>
              </div>`
            : html`<p class="empty">No netblocks match${state.status?.loaded && !state.status.loaded.netblock ? ' (the netblock database is not loaded)' : ''}.</p>`}`
      : nothing}
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
      <div class="form-row settings-row">
        <cds-select
          class="max-age"
          label-text="Refresh databases older than"
          helper-text=${ageHelp}
          value=${String(hours)}
          ?disabled=${fixed || !editable || d.saving === 'max_age'}
          @cds-select-selected=${(e) => {
            const h = Number(e.target.value);
            if (h !== hours) saveSetting('max_age', { max_age_hours: h });
          }}>
          ${choices.map(([h, label]) => html`<cds-select-item value=${String(h)}>${label}</cds-select-item>`)}
        </cds-select>
        ${tip('Refresh age', CONTROL_HELP.maxAge)}
        ${switchWithTip('Import IPv6 routes', !!store.ipv6_routes, (e) => saveSetting('ipv6', { ipv6_routes: e.target.checked }), CONTROL_HELP.ipv6, !editable || d.saving === 'ipv6')}
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
            <cds-table-header-cell><span class="sr-only">Select</span></cds-table-header-cell>
            <cds-table-header-cell>Database</cds-table-header-cell>
            <cds-table-header-cell>Status ${tip('Status', COLUMN_HELP.status)}</cds-table-header-cell>
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
              <cds-table-cell>
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
              </cds-table-cell>
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
              </cds-table-cell>
            </cds-table-row>`;
          })}
        </cds-table-body>
      </cds-table>
    </div>

    <section class="update-panel">
      <h3>Update</h3>
      <div class="actions">
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
      </p>
      ${job.started ? jobView(job) : nothing}
    </section>

    ${settingsPanel(st)}
  `;
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
  Object.assign(state.settings, { open: true, base: getApiBase(), testing: false, result: null });
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
  s.open = false;
  state.status = null;
  update();
  refreshStatus();
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
  else if (state.tab === 'databases') body = databasesView();
  else body = lookupView();
  return html`
    ${headerView()}
    <main id="main-content">
      <section class="intro">
        <h1>Who is behind an IP address?</h1>
        <p>
          asname takes an IP address, hostname, URL or AS number and tells you the network that routes it, who the
          address block is registered to, where it most likely is, what kind of network it is (cloud, hosting, VPN,
          Tor, home broadband, mobile…) and whether public blocklists name it, with a plain-language summary of what
          that means. Everything comes from databases on this machine, so lookups are instant and nothing you look up
          leaves it, unless you turn on Online lookups.
        </p>
      </section>
      ${tabsView()}
      <div class="notifications">${bannerView()}</div>
      ${body}
    </main>
    ${settingsView()}
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
