# asname web UI

An optional browser front end for the asname REST API: lookups, searches and
database updates. It is built with IBM's
[Carbon Design System](https://carbondesignsystem.com/) web components
(`@carbon/web-components`) and [lit](https://lit.dev/), and bundled by
[Vite](https://vite.dev/) into static files that asname serves itself.

## Build and run

```bash
make web                                   # npm ci && npm run build, into web/dist
asname --rest --allow-updates --web-dir web/dist
# open http://127.0.0.1:8086/
```

`--allow-updates` is only needed for the Databases tab's update buttons;
without it the tab shows the status alone. To install it as a systemd service,
see "Running as a service" in the [main README](../README.md#running-as-a-service).

## Develop

Run asname, then Vite's dev server, which reloads as you edit and proxies
`/v1` and `/health` to asname, so the page and the API share an origin just as
they do when asname serves the built files:

```bash
asname --rest --allow-updates              # in one terminal
cd web && npm ci && npm run dev            # in another; open the URL it prints
ASNAME_API=http://127.0.0.1:9000 npm run dev   # if asname listens elsewhere
```

Updates are accepted only from the server's own origin, so they work through
the proxy (its `Origin` matches the `Host` it forwards) but not from a page on
another port talking to asname directly.

## Layout

- `index.html` is the page shell.
- `src/main.js` is the whole UI: the header, the Lookup, Search and Databases
  tabs and the Settings modal, rendered with lit's `render()`. Routes live in
  the hash (`#/lookup?q=…`, `#/search?q=…`, `#/databases`), so a lookup can be
  linked to and the back button works.
- `src/help.js` holds every explanation the UI shows, in one place: the (i)
  text for each field, control, column and tag, `findings()` (a result's "What
  this means" points, worst first) and `whereIs()` (which country an address is
  most likely in). It is written for someone new to triage; keep it plain, and
  in line with the README's descriptions of each source.
- `src/api.js` is the REST client. The API base defaults to the page's own
  origin; Settings stores another in `localStorage` (`asname.apiBase`). That,
  and the theme, are per browser; the refresh age and IPv6 routes are server
  settings (`PUT /v1/settings`), on the Databases tab.
- `src/styles.scss` compiles Carbon's reset, theme tokens and type from
  `@carbon/styles`, and the page's own layout. The light (White) and dark
  (Gray 100) themes are Carbon theme zones on `<html>`.

The IBM Plex fonts are bundled, so the UI loads nothing from the internet.

## Rules for changes

- **API data is untrusted.** Organisation, network and AS names come from
  public registries and anyone can register one. Put them in templates as
  `${value}`, which lit escapes; never use `unsafeHTML`, `innerHTML` or a
  data-derived `href`. The server's Content-Security-Policy (`default-src
  'self'`) is a backstop, not a licence.
- **Check Carbon's API in `node_modules`.** Attribute, property and event names
  differ between Carbon's React and web components and between versions; read
  `node_modules/@carbon/web-components/es/components/<name>/*.d.ts` (and the
  `.js` beside it) rather than assuming. Import the element files you use, not a
  component's `index.js`, which pulls in its whole family.
- A `cds-checkbox` inside a `cds-table-row` is taken for the row's selection
  checkbox; stop its `cds-checkbox-changed` event from bubbling, as the
  Databases tab does.
- Carbon's attribute names are not always the dashed form of the property:
  `cds-toggle`'s `hideLabel` has no declared attribute, so lit's default
  `hidelabel` applies and `hide-label` does nothing. Bind the property
  (`.hideLabel=${true}`) when in doubt, and check the decorator in the `.js`.
- Sortable tables sort in the page's state, not in Carbon's table, which would
  reorder the rows behind lit's back: `sortHeader()` cancels the header cell's
  `cds-table-header-cell-sort` event and renders the rows in order.
- `/v1/status` drives more than the Databases tab: the banner, which online
  lookups the Lookup tab offers, and which fields a result card shows as
  "Unknown" (a database that is loaded but had no answer) rather than leaving
  out (a database that is not loaded). It is polled on every tab.
- Dependencies are pinned to exact versions in `package.json`; `make web` uses
  `npm ci`, so builds match `package-lock.json`.
