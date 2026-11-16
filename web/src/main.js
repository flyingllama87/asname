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

import { iconLoader } from '@carbon/web-components/es/globals/internal/icon-loader.js';
import Asleep20 from '@carbon/icons/es/asleep/20.js';
import Light20 from '@carbon/icons/es/light/20.js';
import Settings20 from '@carbon/icons/es/settings/20.js';

import { html, nothing, render } from 'lit';
import { api, ApiError, getApiBase, setApiBase } from './api.js';

const THEME_KEY = 'asname.theme';
const PREFIX_PREVIEW = 50;

// Rough download sizes, shown for optional databases not yet built.
const SIZE_HINTS = {
  city: '~125 MB download',
  netblock: '~370 MB of RIR whois dumps',
  category: '~3 MB',
  reputation: '~10 MB',
};

const state = {
  tab: 'lookup',
  theme: initialTheme(),
  status: null,
  statusError: '',
  lookup: { input: '', rdns: false, loading: false, error: '', results: [], errors: [], ran: '', showAll: {} },
  search: { q: '', scope: 'all', limit: 50, family: 'any', loading: false, error: '', data: null },
  db: { selected: new Set(), busy: false, error: '', notice: '' },
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
  return { tab, q: new URLSearchParams(query).get('q') || '' };
}

function go(hash) {
  if (location.hash === hash) route();
  else location.hash = hash;
}

function route() {
  const { tab, q } = parseHash();
  state.tab = tab;
  if (tab === 'lookup' && q) {
    state.lookup.input = q;
    runLookup(q);
  } else if (tab === 'search' && q) {
    state.search.q = q;
    runSearch();
  } else if (tab === 'databases') {
    refreshStatus();
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

async function runLookup(text) {
  const targets = targetsOf(text);
  const l = state.lookup;
  if (!targets.length) return;
  lookupAbort?.abort();
  lookupAbort = new AbortController();
  const { signal } = lookupAbort;
  Object.assign(l, { loading: true, error: '', results: [], errors: [], ran: text, showAll: {} });
  update();
  try {
    const data =
      targets.length === 1
        ? await api.lookup(targets[0], { reverseDNS: l.rdns, signal })
        : await api.bulk(targets, { reverseDNS: l.rdns, signal });
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
  Object.assign(s, { loading: true, error: '', data: null });
  update();
  try {
    s.data = await api.search(
      { q: s.q.trim(), scope: s.scope, limit: s.limit, family: s.family },
      { signal: searchAbort.signal },
    );
  } catch (err) {
    if (err.name === 'AbortError') return;
    s.error = errorText(err);
  }
  s.loading = false;
  update();
}

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

function countryText(c) {
  if (!c) return '';
  return c.name && c.name !== c.code ? `${c.name} (${c.code})` : c.code;
}

// ---------- views ----------

const asnLink = (asn, label) =>
  html`<button class="linkish mono" type="button" title="Look up ${asn}" @click=${() => go(`#/lookup?q=${encodeURIComponent(asn)}`)}>${label ?? asn}</button>`;

const field = (label, body) => (body === nothing || body === '' || body == null ? nothing : html`<div class="field"><dt>${label}</dt><dd>${body}</dd></div>`);

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

// Lookup

function lookupView() {
  const l = state.lookup;
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
        helper-text="Ctrl+Enter to look up"
        .value=${l.input}
        @input=${(e) => (l.input = e.target.value)}
        @keydown=${(e) => {
          if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
            e.preventDefault();
            submit();
          }
        }}></cds-textarea>
      <div class="form-row">
        <cds-toggle
          label-text="Reverse DNS"
          label-a="On"
          label-b="Off"
          ?checked=${l.rdns}
          @cds-toggle-changed=${(e) => (l.rdns = e.target.checked)}></cds-toggle>
        <div class="actions">
          <cds-button @click=${submit} ?disabled=${l.loading}>Look up</cds-button>
          ${l.loading ? html`<cds-inline-loading status="active">Looking up…</cds-inline-loading>` : nothing}
        </div>
      </div>
    </div>
    <div class="notifications">
      ${l.error ? errorNote('Lookup failed', l.error) : nothing}
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

function resultCard(r, i) {
  const l = state.lookup;
  const rep = r.reputation;
  // Red means the address is listed, or its whole ASN is on Spamhaus
  // ASN-DROP; a few listed addresses in a large ASN are only noted.
  const listed = rep?.listed || rep?.asn?.spamhaus_asn_drop;
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

  return html`
    <article class="card ${listed ? 'listed' : ''}">
      <div class="card-head">
        <div>
          <div class="card-title">${title}</div>
          ${sub ? html`<div class="card-sub">${sub}</div>` : nothing}
        </div>
        <cds-button kind="ghost" size="sm" @click=${() => copyJSON(r)}>Copy JSON</cds-button>
      </div>
      <dl class="fields">
        ${field(
          'ASN',
          r.asn
            ? html`${asnLink(r.asn.asn_string || `AS${r.asn.number}`)} ${r.asn.name || ''}
                ${r.asn.announced === false ? html`<span class="meta">Not announced</span>` : nothing}`
            : nothing,
        )}
        ${field(
          'Country',
          r.country
            ? html`${countryText(r.country)}
                ${nbCountry ? html`<span class="meta">Netblock registered in ${countryText(nbCountry)}</span>` : nothing}`
            : nothing,
        )}
        ${field('City', r.city?.present ? r.city.name : nothing)}
        ${field(
          'Netblock',
          nb
            ? html`${nb.organization || nb.raw}
                <span class="meta">
                  ${[nb.handle, nb.created ? `registered ${nb.created}` : '', nb.source, nb.live_query ? 'live whois' : '']
                    .filter(Boolean)
                    .join(' · ')}
                </span>`
            : nothing,
        )}
        ${field(
          'Category',
          r.category?.tags?.length
            ? html`<div class="tags">${r.category.tags.map((t) => html`<cds-tag size="sm" type="teal">${t}</cds-tag>`)}</div>`
            : nothing,
        )}
        ${field('Reputation', rep ? reputationView(rep) : nothing)}
        ${field('Reverse DNS', r.reverse_dns?.names?.length ? html`<span class="mono">${r.reverse_dns.names.join(', ')}</span>` : nothing)}
      </dl>
      ${r.prefixes
        ? html`<div class="prefixes">
            <h3>Announced prefixes</h3>
            <div class="hint">
              ${r.prefixes.total} total · ${r.prefixes.ipv4_count} IPv4 · ${r.prefixes.ipv6_count} IPv6
              ${r.prefixes.source ? html` · from ${r.prefixes.source}` : nothing}
            </div>
            ${shown.length ? html`<div class="prefix-list">${shown.map((p) => html`<span>${p}</span>`)}</div>` : nothing}
            ${prefixes.length > PREFIX_PREVIEW && !l.showAll[i]
              ? html`<cds-button kind="tertiary" size="sm" @click=${() => {
                  l.showAll[i] = true;
                  update();
                }}>Show all ${prefixes.length}</cds-button>`
              : nothing}
          </div>`
        : nothing}
    </article>
  `;
}

function reputationView(rep) {
  const asn = rep.asn;
  return html`
    ${rep.lists?.length
      ? html`<div class="tags">${rep.lists.map((name) => html`<cds-tag size="sm" type="red">${name}</cds-tag>`)}</div>`
      : rep.listed
        ? html`<cds-tag size="sm" type="red">Listed</cds-tag>`
        : html`<span>Not listed</span>`}
    ${asn?.spamhaus_asn_drop ? html`<div class="tags"><cds-tag size="sm" type="red">ASN on Spamhaus ASN-DROP</cds-tag></div>` : nothing}
    ${asn?.summary ? html`<span class="meta">ASN: ${asn.summary}</span>` : nothing}
  `;
}

// Search

function searchView() {
  const s = state.search;
  const submit = () => {
    s.q = document.getElementById('search-q')?.value ?? s.q;
    const limit = parseInt(document.getElementById('search-limit')?.value, 10);
    s.limit = Number.isFinite(limit) && limit > 0 ? limit : 50;
    if (s.q.trim()) go(`#/search?q=${encodeURIComponent(s.q.trim())}`);
  };
  const d = s.data;
  return html`
    <p class="lede">Search AS names and, with the netblock database, the organisations and network names registered in whois.</p>
    <div class="form">
      <div class="form-row">
        <cds-text-input
          id="search-q"
          class="grow"
          label="Search for"
          placeholder="cloudflare"
          .value=${s.q}
          @input=${(e) => (s.q = e.target.value)}
          @keydown=${(e) => e.key === 'Enter' && submit()}></cds-text-input>
        <cds-number-input id="search-limit" label="Limit" min="1" max="10000" step="10" .value=${String(s.limit)}></cds-number-input>
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
        <cds-select label-text="Address family" value=${s.family} @cds-select-selected=${(e) => (s.family = e.target.value)}>
          <cds-select-item value="any">IPv4 and IPv6</cds-select-item>
          <cds-select-item value="v4">IPv4 only</cds-select-item>
          <cds-select-item value="v6">IPv6 only</cds-select-item>
        </cds-select>
        <div class="actions">
          <cds-button @click=${submit} ?disabled=${s.loading}>Search</cds-button>
          ${s.loading ? html`<cds-inline-loading status="active">Searching…</cds-inline-loading>` : nothing}
        </div>
      </div>
    </div>
    <div class="notifications">${s.error ? errorNote('Search failed', s.error) : nothing}</div>
    ${d ? searchResults(d) : nothing}
  `;
}

function searchResults(d) {
  const asns = d.asns || [];
  const blocks = d.results || [];
  return html`
    ${state.search.scope !== 'netblocks'
      ? html`<h2>AS names <span class="hint">(${d.asn_count ?? asns.length})</span></h2>
          ${asns.length
            ? html`<div class="table-wrap">
                <cds-table size="sm" use-zebra-styles>
                  <cds-table-head>
                    <cds-table-header-row>
                      <cds-table-header-cell>ASN</cds-table-header-cell>
                      <cds-table-header-cell>Name</cds-table-header-cell>
                      <cds-table-header-cell>Country</cds-table-header-cell>
                      <cds-table-header-cell>Prefixes</cds-table-header-cell>
                      <cds-table-header-cell>Reputation</cds-table-header-cell>
                    </cds-table-header-row>
                  </cds-table-head>
                  <cds-table-body>
                    ${asns.map(
                      (a) => html`<cds-table-row>
                        <cds-table-cell class="nowrap">${asnLink(a.asn)}</cds-table-cell>
                        <cds-table-cell class="wrap">${a.name}</cds-table-cell>
                        <cds-table-cell>${a.country || ''}</cds-table-cell>
                        <cds-table-cell class="nowrap">
                          ${(a.ipv4_prefixes?.length || 0) + (a.ipv6_prefixes?.length || 0) || ''}
                        </cds-table-cell>
                        <cds-table-cell class="wrap">
                          ${a.reputation?.spamhaus_asn_drop
                            ? html`<cds-tag size="sm" type="red">Spamhaus ASN-DROP</cds-tag>`
                            : nothing}
                          ${a.reputation?.summary || ''}
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
                      <cds-table-header-cell>Range</cds-table-header-cell>
                      <cds-table-header-cell>Network</cds-table-header-cell>
                      <cds-table-header-cell>Organisation</cds-table-header-cell>
                      <cds-table-header-cell>Announced by</cds-table-header-cell>
                      <cds-table-header-cell>Country</cds-table-header-cell>
                    </cds-table-header-row>
                  </cds-table-head>
                  <cds-table-body>
                    ${blocks.map(
                      (b) => html`<cds-table-row>
                        <cds-table-cell class="mono">${(b.cidrs?.length ? b.cidrs : [`${b.range_start} – ${b.range_end}`]).map(
                          (c) => html`<div>${c}</div>`,
                        )}</cds-table-cell>
                        <cds-table-cell class="wrap">${b.netname || ''}</cds-table-cell>
                        <cds-table-cell class="wrap">${b.org || ''}</cds-table-cell>
                        <cds-table-cell class="wrap">
                          ${b.asn ? html`${asnLink(b.asn)} ${b.as_name || ''}` : ''}
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

function databasesView() {
  const st = state.status;
  const d = state.db;
  if (!st) {
    return state.statusError
      ? errorNote('Cannot read the database status', state.statusError)
      : html`<cds-inline-loading status="active">Reading database status…</cds-inline-loading>`;
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
      ${state.statusError ? errorNote('Cannot refresh the database status', state.statusError) : nothing}
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
      <div><dt>Refreshed when older than</dt><dd>${store.max_age_hours ? `${Math.round(store.max_age_hours / 24)} days` : 'never (auto-update off)'}</dd></div>
      <div><dt>IPv6 routes</dt><dd>${store.ipv6_routes ? 'imported' : 'off'}</dd></div>
    </dl>

    <div class="table-wrap">
      <cds-table size="md">
        <cds-table-head>
          <cds-table-header-row>
            <cds-table-header-cell><span class="sr-only">Select</span></cds-table-header-cell>
            <cds-table-header-cell>Database</cds-table-header-cell>
            <cds-table-header-cell>Status</cds-table-header-cell>
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
                <div class="hint mono">${db.path}</div>
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
      <h1>asname</h1>
      ${tabsView()}
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
route();
refreshStatus();
