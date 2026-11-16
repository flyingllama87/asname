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
  lookup: (target, { reverseDNS, signal } = {}) =>
    request(`/v1/lookup?q=${encodeURIComponent(target)}${reverseDNS ? '&reverse_dns=true' : ''}`, { signal }),
  bulk: (targets, { reverseDNS, signal } = {}) =>
    request('/v1/bulk', { method: 'POST', body: { targets, reverse_dns: !!reverseDNS }, signal }),
  search: ({ q, scope, limit, family }, { signal } = {}) => {
    const p = new URLSearchParams({ q, scope, limit: String(limit) });
    if (family === 'v4') p.set('v4_only', 'true');
    if (family === 'v6') p.set('v6_only', 'true');
    return request(`/v1/search?${p}`, { signal });
  },
  update: (body) => request('/v1/update', { method: 'POST', body }),
  cancelUpdate: () => request('/v1/update', { method: 'DELETE', body: {} }),
};
