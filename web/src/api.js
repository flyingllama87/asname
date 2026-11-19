// A small client for the asname REST API. The base URL defaults to the
// page's own origin, which is the local asname that served it (or the Vite
// dev server, which proxies to one). Another server can be set in Settings;
// it must run with --cors, and refuses updates from another origin.

const STORAGE_KEY = 'asname.apiBase';

export function getApiBase() {
  try {
    return localStorage.getItem(STORAGE_KEY) || '';
  } catch {
    return '';
  }
}

export function setApiBase(base) {
  const clean = (base || '').trim().replace(/\/+$/, '');
  try {
    if (clean) localStorage.setItem(STORAGE_KEY, clean);
    else localStorage.removeItem(STORAGE_KEY);
  } catch {
    // Storage blocked: the setting lasts for this page only.
  }
  return clean;
}

export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

async function request(path, { method = 'GET', body, signal, base } = {}) {
  const url = (base ?? getApiBase()) + path;
  const init = { method, signal, headers: { Accept: 'application/json' } };
  if (body !== undefined) {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  let res;
  try {
    res = await fetch(url, init);
  } catch (err) {
    if (err.name === 'AbortError') throw err;
    throw new ApiError(`Cannot reach asname at ${url.replace(path, '') || 'this origin'}. Is \`asname --rest\` running?`, 0);
  }
  let data = null;
  const text = await res.text();
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = { error: text.trim() };
    }
  }
  if (!res.ok) {
    throw new ApiError(data?.error || `${res.status} ${res.statusText}`, res.status);
  }
  return data;
}

export const api = {
  health: (base) => request('/health', { base }),
  status: () => request('/v1/status'),
  // online is {whois, prefixes}; a key left undefined keeps the server's
  // default, as asking for a lookup the server has turned off is an error.
  // family is 'v4' or 'v6' to keep one family of a hostname's addresses.
  // preview is a quick offline lookup for a tooltip, left out of the
  // server's request log.
  preview: (target, { signal } = {}) =>
    request(`/v1/lookup?${new URLSearchParams({ q: target, text: 'false', whois: 'false', online_prefixes: 'false', preview: 'true' })}`, { signal }),
  lookup: (target, { reverseDNS, online = {}, family, signal } = {}) => {
    // text=true: each result also comes as the command line prints it, for
    // Copy summary.
    const p = new URLSearchParams({ q: target, text: 'true' });
    if (reverseDNS) p.set('reverse_dns', 'true');
    if (online.whois !== undefined) p.set('whois', String(online.whois));
    if (online.prefixes !== undefined) p.set('online_prefixes', String(online.prefixes));
    if (family === 'v4') p.set('v4_only', 'true');
    if (family === 'v6') p.set('v6_only', 'true');
    return request(`/v1/lookup?${p}`, { signal });
  },
  bulk: (targets, { reverseDNS, online = {}, family, signal } = {}) =>
    request('/v1/bulk?text=true', {
      method: 'POST',
      body: {
        targets,
        reverse_dns: !!reverseDNS,
        whois: online.whois,
        online_prefixes: online.prefixes,
        v4_only: family === 'v4' || undefined,
        v6_only: family === 'v6' || undefined,
      },
      signal,
    }),
  saveSettings: (body) => request('/v1/settings', { method: 'PUT', body }),
  search: ({ q, scope, limit, family, fuzzy, country }, { signal } = {}) => {
    const p = new URLSearchParams({ q, scope, limit: String(limit) });
    if (fuzzy) p.set('fuzzy', 'true');
    if (country) p.set('country', country);
    if (family === 'v4') p.set('v4_only', 'true');
    if (family === 'v6') p.set('v6_only', 'true');
    return request(`/v1/search?${p}`, { signal });
  },
  explore: (params, { signal } = {}) => request(`/v1/explore?${params}`, { signal }),
  update: (body) => request('/v1/update', { method: 'POST', body }),
  cancelUpdate: () => request('/v1/update', { method: 'DELETE', body: {} }),
};
