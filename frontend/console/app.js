/* VEYRS Console
 * Management UI for the VEYRS API. Zero runtime dependencies by design: a
 * vulnerability-management console should not ship a transitive dependency
 * tree that its own SCA would then have to flag.
 *
 * Every contract used here was read from the live OpenAPI document; nothing
 * is assumed. The API is the authority — the console renders what it returns
 * and degrades visibly when a field is absent.
 */
'use strict';

/* ══ API client ════════════════════════════════════════════════════════ */

const API = '/api/v1';
const store = {
  get at()  { return localStorage.getItem('veyrs.at'); },
  get rt()  { return localStorage.getItem('veyrs.rt'); },
  get org() { return localStorage.getItem('veyrs.org') || ''; },
  get perms() { try { return JSON.parse(localStorage.getItem('veyrs.perms') || '[]'); } catch { return []; } },
  save(tok, orgSlug) {
    if (tok.access_token)  localStorage.setItem('veyrs.at', tok.access_token);
    if (tok.refresh_token) localStorage.setItem('veyrs.rt', tok.refresh_token);
    if (tok.permissions)   localStorage.setItem('veyrs.perms', JSON.stringify(tok.permissions));
    if (orgSlug)           localStorage.setItem('veyrs.org', orgSlug);
  },
  clear() { ['at', 'rt', 'perms', 'enroll'].forEach(k => localStorage.removeItem('veyrs.' + k)); },
};

/* ══ Team ownership ════════════════════════════════════════════════════
 * The team list is small, changes rarely and is needed by three views at once
 * (asset filter, finding filter, every assign dialog), so it is fetched once
 * per session rather than per render. `teamName()` falls back to the id: a
 * team deleted after assignment must degrade to something the operator can
 * still search for, not to a blank cell.
 */
const teamCache = { list: null, byId: new Map() };

async function teams() {
  if (teamCache.list) return teamCache.list;
  try {
    teamCache.list = pageOf(await get('/teams?limit=200')).items || [];
  } catch { teamCache.list = []; }        // team:read is not granted to every role
  teamCache.byId = new Map(teamCache.list.map(t => [t.id, t.name || t.slug]));
  return teamCache.list;
}

function teamName(id) {
  if (!id) return null;
  return teamCache.byId.get(id) || null;
}

async function teamOptions(extra = []) {
  const rows = await teams();
  return extra.concat(rows.map(t => ({ value: t.id, label: t.name || t.slug })));
}

/* What the signed-in identity may see. Set from /auth/me at boot; every view
 * that shows an aggregate reads it so a narrowed number never reads as total. */
const scope = { restricted: false, team_ids: [], include_unowned: false };

/*
 * Console preferences, as `/auth/me` last reported them. Kept in memory rather
 * than in localStorage: the point of moving this to the profile is that the
 * answer follows the person to another browser, and a local copy would be a
 * second source of truth that disagrees on exactly the machine where somebody
 * notices. Written back optimistically on change so the screen never waits on
 * the round trip.
 */
const prefs = { dashboard_team_id: null };

/*
 * Whether this tenant lets VEYRS probe anything at all -- `services/scanning`
 * -- shipped on `/auth/me` for the same reason `preferences` is: the nav is
 * painted once at boot, and a second call would draw the scanner entry and
 * then take it away, which reads as the console losing pages by itself.
 *
 * It could NOT come from `GET /scanning`: that route requires `settings:read`,
 * and of the ten built-in roles only the wildcard `org-admin` carries it. A
 * menu driven from it would be cleaned for exactly the one persona that did
 * not need it cleaned, and 403 for everybody else.
 *
 * Default true, and every failure path leaves it true. An unreadable answer
 * must SHOW the menu: a hidden entry is indistinguishable from a page that was
 * removed, and the operator has nothing to click to find out which it was.
 */
let activeScanning = true;

/*
 * Which system owns remediation work -- `services/ticketing_mode`. Shipped on
 * `/auth/me` for exactly the reason `activeScanning` is, and it could NOT come
 * from `GET /ticketing`: the nav is painted once at boot, and a second call
 * would draw the Tickets section and then take it away, which reads as the
 * console losing pages by itself.
 *
 * Default 'internal', and every failure path leaves it 'internal'. An
 * unreadable answer must show the queue VEYRS actually owns: hiding Tickets on
 * a tenant that has no external connector would leave an operator with no
 * remediation surface at all and nothing to click to find out why.
 */
let ticketingMode = 'internal';
let ticketingUsable = true;
const externalTicketing = () => ticketingMode === 'external';

/*
 * Whether this tenant keeps a risk register -- `services/risk_register_mode`.
 * On `/auth/me` for the reason `activeScanning` and `ticketingMode` are: the
 * nav is painted once at boot, and a section that appears and then vanishes a
 * moment later reads as the console losing pages by itself.
 *
 * Default true, and every failure path leaves it true. An unreadable answer
 * must SHOW the section: a hidden entry is indistinguishable from a page that
 * was removed, and the operator has nothing to click to find out which.
 */
let riskRegisterOn = true;

function scopeBanner() {
  if (!scope.restricted) return '';
  const names = scope.team_ids.map(id => teamName(id) || id.slice(0, 8)).join(', ');
  return `<div class="scope-banner" role="status">
    <strong>Team view</strong>
    <span>You are seeing only ${esc(names || 'your teams')}. Counts, dashboards and
    queues on this screen describe that slice of the estate${scope.include_unowned
      ? ' plus assets with no owning team' : ', and exclude assets with no owning team'}.</span>
  </div>`;
}

function can(perm) {
  const p = store.perms;
  if (!p.length) return true;             // no claim cached → let the API decide
  if (p.includes(perm)) return true;
  const [res] = perm.split(':');
  return p.includes(res + ':admin');
}

class ApiError extends Error {
  constructor(status, detail) { super(detail || ('HTTP ' + status)); this.status = status; this.detail = detail; }
}

async function rawFetch(path, opts = {}, auth = true) {
  const headers = Object.assign({}, opts.headers || {});
  if (auth && store.at) headers['Authorization'] = 'Bearer ' + store.at;
  if (opts.body && !(opts.body instanceof FormData)) headers['Content-Type'] = 'application/json';
  const res = await fetch(API + path, Object.assign({}, opts, { headers }));
  return res;
}

async function refreshToken() {
  if (!store.rt) return false;
  const res = await rawFetch('/auth/refresh', { method: 'POST', body: JSON.stringify({ refresh_token: store.rt }) }, false);
  if (!res.ok) return false;
  store.save(await res.json());
  return true;
}

let refreshing = null;

/* Routes that ESTABLISH a session rather than consume one. A 401 from these
   means the credentials are wrong, not that a session ended -- and that
   difference is the whole diagnosis. Routed through the refresh-then-logout
   path below, a mistyped password was reported as "Session expired", which
   sends the reader to look at the token and away from the field they actually
   got wrong. Their 401 falls through to the generic error path instead, which
   surfaces the API's own detail ("invalid credentials"). */
const AUTH_ENTRY = ['/auth/login', '/auth/refresh', '/auth/sso', '/auth/oidc/exchange'];
const isAuthEntry = p => AUTH_ENTRY.some(a => p === a || p.startsWith(a + '?'));

async function api(path, opts = {}) {
  const entry = isAuthEntry(path);
  let res = await rawFetch(path, opts);
  if (res.status === 401 && store.rt && !entry) {
    // One shared refresh: a dashboard fires several requests at once and we
    // must not rotate the refresh token N times in parallel.
    refreshing = refreshing || refreshToken().finally(() => { refreshing = null; });
    if (await refreshing) res = await rawFetch(path, opts);
  }
  if (res.status === 401 && !entry) {
    // Only a request that CARRIED a session can have lost one. With no token
    // there was never a session to expire, and saying so points at sign-in
    // rather than at an expiry that never happened.
    const had = !!(store.at || store.rt);
    logout();
    throw new ApiError(401, had ? 'Session expired' : 'Sign in to continue.');
  }
  if (res.status === 204) return null;

  const ct = res.headers.get('content-type') || '';
  if (!res.ok) {
    let detail = 'HTTP ' + res.status, data = null;
    if (ct.includes('json')) {
      const body = await res.json().catch(() => ({}));
      /* A structured refusal ({message, ...}) keeps its fields on `data` so a
         page can show them (the web certificate's failed checks); the message
         is still the toast text. */
      if (body.detail && typeof body.detail === 'object' && !Array.isArray(body.detail)) data = body.detail;
      detail = typeof body.detail === 'string' ? body.detail
             : Array.isArray(body.detail) ? body.detail.map(d => (d.loc || []).slice(-1) + ': ' + d.msg).join('; ')
             : (data && typeof data.message === 'string') ? data.message
             : JSON.stringify(body).slice(0, 300);
    }
    const e = new ApiError(res.status, detail);
    e.data = data;
    throw e;
  }
  return ct.includes('json') ? res.json() : res.text();
}

const get  = (p)    => api(p);
const post = (p, b) => api(p, { method: 'POST', body: b instanceof FormData ? b : JSON.stringify(b || {}) });
const patch= (p, b) => api(p, { method: 'PATCH', body: JSON.stringify(b || {}) });
const put  = (p, b) => api(p, { method: 'PUT', body: JSON.stringify(b || {}) });
const del  = (p)    => api(p, { method: 'DELETE' });

/* ══ Utilities ═════════════════════════════════════════════════════════ */

const $  = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

function esc(v) {
  if (v === null || v === undefined) return '';
  return String(v).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function fmtNum(n) { return (n === null || n === undefined) ? '—' : Number(n).toLocaleString(); }
function fmtPct(n, d = 1) { return (n === null || n === undefined) ? '—' : (Number(n) * 100).toFixed(d) + '%'; }
function fmtScore(n) { return (n === null || n === undefined) ? '—' : Number(n).toFixed(1); }
function fmtShortDate(s) {
  const d = new Date(s);
  return isNaN(d) ? esc(s) : d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}
/* Dates never break across lines (0.39.1): a narrow table column used to
   stack "Sep / 07, / 2026, / 02:05 PM" four rows high. No-break spaces
   rather than markup, because these strings also land in attributes and
   in esc()'d text. */
const nbsp = s => s.replace(/ /g, '\u00a0');
function fmtDate(s) {
  if (!s) return '—';
  const d = new Date(s);
  return isNaN(d) ? esc(s) : nbsp(d.toLocaleString(undefined, { year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' }));
}
function fmtDay(s) {
  if (!s) return '—';
  const d = new Date(s);
  return isNaN(d) ? esc(s) : nbsp(d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: '2-digit' }));
}
function titleCase(s) { return String(s || '').replace(/[_-]/g, ' ').replace(/\b\w/g, c => c.toUpperCase()); }

function sevPill(sev) {
  const s = String(sev || '').toLowerCase();
  const known = ['critical', 'high', 'medium', 'low', 'informational'];
  return `<span class="pill ${known.includes(s) ? 'sev-' + s : 'sev-none'}">${esc(sev || 'none')}</span>`;
}
/* Asset criticality is a business rating, not a finding severity: painting
   a "critical" asset in the critical-severity red made every inventory page
   look like an incident (DESIGN_SYSTEM: severity hues are for severities
   only). A neutral pill with a four-step level mark instead. */
function critPill(c) {
  const s = String(c || '').toLowerCase();
  const lv = { low: 1, medium: 2, high: 3, critical: 4 }[s];
  if (!lv) return '<span class="pill st-neutral">—</span>';
  return `<span class="pill crit crit-${s}" title="Asset criticality: ${esc(s)}"><span class="crit-mark" aria-hidden="true">${
    [1, 2, 3, 4].map(i => `<i class="${i <= lv ? 'on' : ''}"></i>`).join('')}</span>${esc(titleCase(s))}</span>`;
}
/* Escalation ladders and assignment conditions are JSON in the API. Shown
   raw, the policy page was one long line of braces that scrolled sideways
   (0.39.1): render them as the sentence they encode, keep the JSON in the
   tooltip for whoever needs the exact value. */
function ladderSteps(steps) {
  const list = Array.isArray(steps) ? steps : [];
  if (!list.length) return '<span class="muted small">No steps</span>';
  const raw = esc(JSON.stringify(list));
  return `<span class="ladder" title="${raw}">${list.map(st => {
    const h = st.after_hours ?? st.hours;
    const who = st.notify || st.target || st.channel || '?';
    const label = /^(ciso|cio|cto|soc|it)$/i.test(String(who)) ? String(who).toUpperCase() : titleCase(String(who));
    return `<span class="ladder-step"><b>L${esc(st.level ?? '?')}</b> ${h != null ? esc(h) + '\u00a0h' : ''} → ${esc(label)}</span>`;
  }).join('<span class="ladder-sep" aria-hidden="true">›</span>')}</span>`;
}
function matchChips(cond) {
  const entries = cond && typeof cond === 'object' ? Object.entries(cond) : [];
  if (!entries.length) return '<span class="muted small">Matches everything</span>';
  return entries.map(([k, v]) => `<span class="cond"><span class="muted">${esc(titleCase(k))}</span> ${
    esc(Array.isArray(v) ? v.join(', ') : (v && typeof v === 'object') ? JSON.stringify(v) : String(v))}</span>`).join(' ');
}
function statePill(state) {
  const s = String(state || '').toLowerCase();
  const good = ['remediated', 'verified', 'closed', 'resolved'];
  const acc  = ['accepted_risk', 'exception'];
  const cls = good.includes(s) ? 'st-' + s : acc.includes(s) ? 'st-' + s : 'st-neutral';
  return `<span class="pill ${cls}">${esc(titleCase(state))}</span>`;
}

function toast(msg, kind = '') {
  const el = document.createElement('div');
  el.className = 'toast ' + kind;
  el.innerHTML = esc(msg);
  $('#toast-stack').appendChild(el);
  setTimeout(() => el.remove(), kind === 'err' ? 7000 : 4000);
}
const ok  = m => toast(m, 'ok');
const err = m => toast(m, 'err');

/* `dismiss` is the label on the button that closes without doing anything.
   It defaults to "Cancel" because most modals here ask for something, but a
   modal that only EXPLAINS has nothing to cancel -- offering "Cancel" as the
   single way out of a reference table reads as "discard", and the reader
   hesitates over a button that cannot lose anything. */
let seqModal = 0;
function modal({ title, body, actions = [], wide = false, dismiss = 'Cancel' }) {
  seqModal += 1;
  return new Promise(resolve => {
    const root = $('#modal-root');
    const back = document.createElement('div');
    back.className = 'modal-backdrop';
    back.innerHTML = `
      <div class="modal${wide ? ' wide' : ''}" role="dialog" aria-modal="true" aria-labelledby="mh-${seqModal}">
        <div class="modal-head"><h2 id="mh-${seqModal}">${esc(title)}</h2><div class="spacer"></div>
          <button class="icon-btn" data-x="cancel" aria-label="Close">✕</button></div>
        <div class="modal-body">${body}</div>
        <div class="modal-foot">
          <button class="btn" data-x="cancel">${esc(dismiss)}</button>
          ${actions.map((a, i) => `<button class="btn ${a.cls || 'btn-primary'}" data-i="${i}">${esc(a.label)}</button>`).join('')}
        </div>
      </div>`;
    /* Escape closes the TOPMOST dialog only (dialogs nest: a picker opens
       over a form), Tab cycles inside it, and focus goes back to whatever
       opened it. Without these a keyboard user could tab out into the page
       behind the backdrop and had no way to dismiss short of the mouse. */
    const opener = document.activeElement;
    const onKey = e => {
      if (root.lastElementChild !== back) return;
      if (e.key === 'Escape') { e.preventDefault(); close(null); return; }
      if (e.key !== 'Tab') return;
      const f = $$('button,[href],input,select,textarea,[tabindex]:not([tabindex="-1"])', back)
        .filter(el => !el.disabled && el.offsetParent !== null);
      if (!f.length) return;
      const [first, last] = [f[0], f[f.length - 1]];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    };
    const close = v => {
      document.removeEventListener('keydown', onKey, true);
      back.remove();
      if (opener && opener.isConnected && typeof opener.focus === 'function') opener.focus();
      resolve(v);
    };
    document.addEventListener('keydown', onKey, true);
    back.addEventListener('click', async e => {
      if (e.target === back || e.target.dataset.x === 'cancel') return close(null);
      const i = e.target.dataset.i;
      if (i === undefined) return;
      const form = {};
      $$('[name]', back).forEach(f => { form[f.name] = f.type === 'checkbox' ? f.checked : f.value; });
      const act = actions[Number(i)];
      if (act.keepOpen) { const r = await act.run?.(form, back); if (r !== false) close(form); }
      else close(form);
    });
    root.appendChild(back);
    const first = $('input,select,textarea', back) || $('.modal-foot .btn', back);
    if (first) first.focus();
  });
}

/* ══ Explainers ════════════════════════════════════════════════════════
   A configuration screen that assumes ITIL vocabulary is a screen only the
   person who built it can use. Every one of them now answers the same three
   questions in the same order, in the page itself rather than in a manual
   nobody opens mid-task:

     what this decides · who normally touches it · what changes if you change it

   The third is the one that was always missing. "Escalation policy" tells a
   reader what the row is called; "raise a level here and the CISO starts
   getting paged at hour 24" tells them whether to touch it.

   It renders COLLAPSED after the first read and remembers per browser: an
   explanation you cannot dismiss becomes furniture, and furniture gets
   scrolled past. The key is versioned (`v1`) so rewriting an explainer
   re-opens it for people who had dismissed the old text -- otherwise the one
   improvement most worth reading is the one nobody sees. */
const EXPLAIN_LS = 'veyrs.explain.dismissed.v1';
const explainDismissed = (() => {
  try { return new Set(JSON.parse(localStorage.getItem(EXPLAIN_LS) || '[]')); }
  catch { return new Set(); }
})();

function explainer(key, { title, what, who, effect, warn = null, links = [] }) {
  const open = !explainDismissed.has(key);
  return `<div class="explainer${open ? '' : ' collapsed'}" data-explain="${esc(key)}">
    <button type="button" class="explainer-head" data-explain-toggle aria-expanded="${open}">
      <span class="explainer-ico" aria-hidden="true">?</span>
      <span class="explainer-title">${esc(title)}</span>
      <span class="explainer-caret">${open ? '▾' : '▸'}</span>
    </button>
    <div class="explainer-body"${open ? '' : ' hidden'}>
      <dl>
        <dt>What this decides</dt><dd>${what}</dd>
        <dt>Who normally touches it</dt><dd>${who}</dd>
        <dt>What changes if you change it</dt><dd>${effect}</dd>
      </dl>
      ${warn ? `<p class="explainer-warn">${warn}</p>` : ''}
      ${links.length ? `<p class="small">${links.map(l =>
        `<a href="${esc(l.href)}">${esc(l.label)}</a>`).join(' · ')}</p>` : ''}
    </div>
  </div>`;
}

/* Delegated once, on the document, rather than wired per render: the router
   replaces `#view` wholesale on every navigation and a per-page listener would
   have to be re-attached by every route that happens to remember. */
document.addEventListener('click', e => {
  const head = e.target.closest?.('[data-explain-toggle]');
  if (!head) return;
  const box = head.closest('.explainer');
  const key = box?.dataset.explain;
  const body = box?.querySelector('.explainer-body');
  if (!box || !body) return;
  const nowOpen = body.hasAttribute('hidden');
  body.toggleAttribute('hidden', !nowOpen);
  box.classList.toggle('collapsed', !nowOpen);
  head.setAttribute('aria-expanded', String(nowOpen));
  box.querySelector('.explainer-caret').textContent = nowOpen ? '▾' : '▸';
  if (nowOpen) explainDismissed.delete(key); else explainDismissed.add(key);
  try { localStorage.setItem(EXPLAIN_LS, JSON.stringify([...explainDismissed])); }
  catch { /* private mode: it still opens and closes, it just forgets */ }
});

/* Reads a paginated envelope: {items,total,limit,offset} */
function pageOf(r) {
  if (Array.isArray(r)) return { items: r, total: r.length, limit: r.length, offset: 0 };
  return { items: r.items || [], total: r.total ?? (r.items || []).length, limit: r.limit ?? 50, offset: r.offset ?? 0 };
}

function qs(obj) {
  const p = new URLSearchParams();
  Object.entries(obj || {}).forEach(([k, v]) => { if (v !== '' && v !== null && v !== undefined) p.set(k, v); });
  const s = p.toString();
  return s ? '?' + s : '';
}

/* ══ Reusable renderers ════════════════════════════════════════════════ */

function table(cols, rows, opts = {}) {
  if (!rows.length) {
    return `<div class="table-wrap"><div class="empty"><strong>${esc(opts.emptyTitle || 'Nothing here yet')}</strong>${esc(opts.emptyHint || '')}</div></div>`;
  }
  // The checkbox column is opt-in. It carries `data-pick` rather than reusing
  // the row's click handler because the row navigates to the detail view --
  // selecting rows to act on them and opening one of them are different
  // intents and must not share a hit area.
  const pick = opts.selectable
    ? `<th class="pick"><input type="checkbox" data-pick-all aria-label="Select all on this page"></th>` : '';
  const pickCell = r => opts.selectable
    ? `<td class="pick"><input type="checkbox" data-pick="${esc(r.id || '')}" aria-label="Select"></td>` : '';
  return `<div class="table-wrap"><table>
    <thead><tr>${pick}${cols.map(c => `<th class="${c.num ? 'num' : ''}">${esc(c.label)}</th>`).join('')}</tr></thead>
    <tbody>${rows.map(r => `<tr class="${opts.onRow ? 'clickable' : ''}"${opts.onRow ? ' tabindex="0"' : ''} data-id="${esc(opts.idOf ? opts.idOf(r) : (r.id || ''))}">
      ${pickCell(r)}${cols.map(c => `<td class="${c.num ? 'num' : ''}">${c.cell(r)}</td>`).join('')}
    </tr>`).join('')}</tbody></table></div>`;
}

/* Wires the checkbox column to a sticky action bar. Returns nothing: the bar
   reads the DOM, so a re-render cannot leave a stale selection behind. */
function wireSelection(view, onAct) {
  const bar = $('#bulk-bar', view);
  if (!bar) return;
  const picked = () => $$('[data-pick]:checked', view).map(i => i.dataset.pick);
  const sync = () => {
    const n = picked().length;
    bar.hidden = n === 0;
    const label = $('#bulk-count', bar);
    if (label) label.textContent = n === 1 ? '1 selected' : n + ' selected';
  };
  const all = $('[data-pick-all]', view);
  if (all) all.onchange = () => { $$('[data-pick]', view).forEach(i => { i.checked = all.checked; }); sync(); };
  $$('[data-pick]', view).forEach(i => {
    i.onchange = sync;
    // A click on the checkbox must not also open the row it sits in.
    i.onclick = e => e.stopPropagation();
  });
  $$('[data-bulk]', bar).forEach(b => {
    b.onclick = () => onAct(b.dataset.bulk, picked());
  });
  sync();
}

function bars(obj, palette) {
  const entries = Object.entries(obj || {});
  const total = entries.reduce((a, [, v]) => a + (Number(v) || 0), 0);
  if (!entries.length || !total) return '<p class="muted small">Every bucket is empty — nothing to plot.</p>';
  const max = Math.max(1, ...entries.map(([, v]) => Number(v) || 0));
  return `<div class="bars">${entries.map(([k, v]) => {
    const n = Number(v) || 0;
    const colour = palette ? palette(k) : 'var(--primary)';
    return `<div class="bar-row" title="${esc(titleCase(k))} — ${fmtNum(n)} of ${fmtNum(total)} (${Math.round(n / total * 100)}%)">
      <span class="bar-label">${esc(titleCase(k))}</span>
      <span class="bar-track"><span class="bar-fill" style="width:${n / max * 100}%;background:${colour}"></span></span>
      <span class="num">${fmtNum(n)}</span></div>`;
  }).join('')}</div>`;
}

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'informational'];
/* Rows keyed by `severity` in scale order. `/dashboard/sla` returns them in
   GROUP BY order, which put Low above Medium in the SLA table. */
const sevSorted = rows => [...(rows || [])].sort((a, b) =>
  (SEV_ORDER.indexOf(String(a.severity).toLowerCase()) + 99) % 99 - (SEV_ORDER.indexOf(String(b.severity).toLowerCase()) + 99) % 99);

/* Composition of ONE total, as a single 100% strip plus a legend that carries
   every number. Answers "what is the open backlog made of" before any of the
   cards below ask the reader to compare two of its parts. Segments under 0.5%
   still get a 3px sliver: a critical finding must never round to invisible. */
function stackBar(obj, order) {
  const keys = (order || SEV_ORDER).filter(k => (obj || {})[k] !== undefined);
  const total = keys.reduce((a, k) => a + (Number(obj[k]) || 0), 0);
  if (!total) return '<p class="muted small">Nothing open — nothing to plot.</p>';
  const seg = keys.filter(k => Number(obj[k]) > 0).map(k => {
    const n = Number(obj[k]), pct = n / total * 100;
    return `<span class="stack-seg" style="flex-grow:${pct};background:${sevColour(k)}" title="${esc(titleCase(k))} — ${fmtNum(n)} (${pct.toFixed(1)}%)"></span>`;
  }).join('');
  const legend = keys.map(k => {
    const n = Number(obj[k]) || 0;
    return `<span class="stack-key"><i style="background:${sevColour(k)}"></i>${esc(titleCase(k))}<b>${fmtNum(n)}</b><span class="muted">${Math.round(n / total * 100)}%</span></span>`;
  }).join('');
  /* `.compo`, not `.stack`: `.stack` is the console's vertical layout class
     (CVSS calculator, automation, forms). 0.36.0 shipped this strip as
     `.stack`, and its 12 px height + overflow:hidden collapsed those six
     layouts to an invisible sliver. */
  return `<div class="compo" role="img" aria-label="${keys.map(k => `${titleCase(k)} ${fmtNum(obj[k])}`).join(', ')}">${seg}</div><div class="stack-legend">${legend}</div>`;
}

/* ── Compact trend marks for KPI tiles (0.37.0) ────────────────────────
   Real series only: the risk trend and the detected/remediated flow the
   dashboard payload already carries. A null bucket is a GAP, never a zero
   and never interpolated -- a line drawn across an empty week claims a
   measurement nobody took. */
function segmentsOf(vals) {
  const segs = []; let cur = [];
  vals.forEach((v, i) => {
    if (v === null || v === undefined || !isFinite(v)) { if (cur.length) segs.push(cur); cur = []; }
    else cur.push([i, Number(v)]);
  });
  if (cur.length) segs.push(cur);
  return segs;
}
function kpiSpark(vals, label) {
  const known = vals.filter(v => v !== null && v !== undefined && isFinite(v));
  if (known.length < 2) return '';
  const W = 120, H = 32, P = 3;
  const lo = Math.min(...known), hi = Math.max(...known), span = (hi - lo) || 1;
  const x = i => P + i / Math.max(1, vals.length - 1) * (W - 2 * P);
  const y = v => H - P - (v - lo) / span * (H - 2 * P);
  const paths = segmentsOf(vals).map(s => {
    if (s.length === 1) return `<circle cx="${x(s[0][0]).toFixed(1)}" cy="${y(s[0][1]).toFixed(1)}" r="1.6" fill="currentColor"/>`;
    const pts = s.map(p => [x(p[0]), y(p[1])]);
    const d = smoothPath(pts);
    return `<path d="${d} L${pts[pts.length - 1][0].toFixed(1)} ${H} L${pts[0][0].toFixed(1)} ${H} Z" fill="currentColor" opacity=".12"/>
      <path d="${d}" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round" stroke-linecap="round"/>`;
  }).join('');
  return `<svg class="kpi-spark" viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(label || 'Trend')}: ${esc(known.map(v => Number.isInteger(v) ? fmtNum(v) : fmtScore(v)).join(', '))}">${paths}</svg>`;
}
/* Change over the window, signed. `goodWhen` says which direction is the
   improvement, so a falling backlog is green and a falling compliance red. */
function delta(n, opts) {
  const o = opts || {};
  if (n === null || n === undefined || !isFinite(n)) return '';
  const v = Number(n);
  const good = v === 0 ? '' : ((v < 0) === (o.goodWhen !== 'up') ? 'good' : 'bad');
  const txt = (v > 0 ? '+' : v < 0 ? '−' : '±') + (o.fmt ? o.fmt(Math.abs(v)) : fmtNum(Math.abs(v)));
  const said = good === 'good' ? ' (improved)' : good === 'bad' ? ' (worse)' : '';
  return `<span class="delta ${good}" title="${esc(o.title || '')}"><span aria-hidden="true">${v > 0 ? '▲' : v < 0 ? '▼' : ''}</span> ${txt}<span class="sr-only">${said}${o.title ? ' — ' + esc(o.title) : ''}</span></span>`;
}
/* One KPI tile. `tone` is the semantic edge (crit/warn/ok) and only applies
   when the value is non-zero -- see tone(). */
function kpi(o) {
  return `<div class="stat kpi ${o.tone || ''}">
    <span class="label">${o.label}</span>
    <span class="value">${o.value}</span>
    ${o.hint ? `<span class="hint">${o.hint}</span>` : ''}
    ${(o.delta || o.spark) ? `<span class="kpi-foot">${o.delta || ''}${o.spark || ''}</span>` : ''}
  </div>`;
}
/* A single ratio against a target, as a ring. Used for SLA compliance only:
   one number, one target, nothing to compare across -- the case a radial
   gauge is actually good at. */
function ring(ratio, target) {
  if (ratio === null || ratio === undefined) return '';
  const pct = Math.max(0, Math.min(1, Number(ratio)));
  const t = target ?? 0.9;
  const R = 34, C = 2 * Math.PI * R;
  const colour = pct >= t ? 'var(--veyrs-remediated)' : pct >= t - 0.2 ? 'var(--veyrs-warning)' : 'var(--veyrs-critical)';
  const tick = (a => [44 + 40 * Math.sin(a), 44 - 40 * Math.cos(a), 44 + 30 * Math.sin(a), 44 - 30 * Math.cos(a)])(t * 2 * Math.PI);
  return `<svg class="ring" viewBox="0 0 88 88" role="img" aria-label="${(pct * 100).toFixed(1)}% against a ${Math.round(t * 100)}% target">
    <circle cx="44" cy="44" r="${R}" fill="none" stroke="var(--surface-2)" stroke-width="9"/>
    <circle cx="44" cy="44" r="${R}" fill="none" stroke="${colour}" stroke-width="9" stroke-linecap="round"
      stroke-dasharray="${(C * pct).toFixed(1)} ${C.toFixed(1)}" transform="rotate(-90 44 44)"/>
    <line x1="${tick[0].toFixed(1)}" y1="${tick[1].toFixed(1)}" x2="${tick[2].toFixed(1)}" y2="${tick[3].toFixed(1)}" stroke="var(--text-secondary)" stroke-width="1.5"/>
  </svg>`;
}

/* Line chart with axes for a 0-100 score over time buckets. Replaces the
   bare sparkline on the executive dashboard: a trend the reader cannot put
   a number or a date on is decoration. The y range is snapped to tens
   around the data (never stretched to fill), gaps stay gaps, and every
   bucket has a hover target that names its date, value and sample size. */
function trendChart(points, opts) {
  const o = opts || {};
  const rows = points || [];
  const vals = rows.map(p => (p.average_risk === null || p.average_risk === undefined) ? null : Number(p.average_risk));
  const known = vals.filter(v => v !== null);
  if (!known.length) return `<p class="muted small">No scored findings in this window — nothing to trend.</p>`;
  if (known.length < 2) return sparkline(points);
  const W = 720, H = 230, L = 34, R = 46, T = 14, B = 28;
  let lo = Math.max(0, Math.floor((Math.min(...known) - 5) / 10) * 10);
  let hi = Math.min(100, Math.ceil((Math.max(...known) + 5) / 10) * 10);
  if (hi - lo < 20) { hi = Math.min(100, lo + 20); lo = Math.max(0, hi - 20); }
  const x = i => L + i / Math.max(1, vals.length - 1) * (W - L - R);
  const y = v => T + (1 - (v - lo) / (hi - lo)) * (H - T - B);
  const ticks = []; for (let v = lo; v <= hi; v += (hi - lo) / 4) ticks.push(v);
  const gid = 'tg' + (++chartSeq);
  const grid = ticks.map(v => `<line x1="${L}" x2="${W - R}" y1="${y(v).toFixed(1)}" y2="${y(v).toFixed(1)}" class="grid-l"/>
    <text x="${L - 8}" y="${(y(v) + 3.5).toFixed(1)}" text-anchor="end" class="axis-t">${Math.round(v)}</text>`).join('');
  const segs = segmentsOf(vals);
  const body = segs.map(sg => {
    const pts = sg.map(p => [x(p[0]), y(p[1])]);
    if (pts.length === 1) return '';
    const d = smoothPath(pts);
    return `<path d="${d} L${pts[pts.length - 1][0].toFixed(1)} ${H - B} L${pts[0][0].toFixed(1)} ${H - B} Z" fill="url(#${gid})"/>
      <path d="${d}" class="trend-line"/>`;
  }).join('');
  const lonely = segs.filter(sg => sg.length === 1).map(sg => `<circle cx="${x(sg[0][0]).toFixed(1)}" cy="${y(sg[0][1]).toFixed(1)}" r="3" class="trend-dot"/>`).join('');
  let li = vals.length - 1; while (li >= 0 && vals[li] === null) li--;
  const lastMark = `<circle cx="${x(li).toFixed(1)}" cy="${y(vals[li]).toFixed(1)}" r="7" class="trend-halo"/>
    <circle cx="${x(li).toFixed(1)}" cy="${y(vals[li]).toFixed(1)}" r="3.5" class="trend-last"/>
    <text x="${(x(li) + 10).toFixed(1)}" y="${(y(vals[li]) + 4).toFixed(1)}" class="trend-val">${fmtScore(vals[li])}</text>`;
  const colW = (W - L - R) / Math.max(1, vals.length - 1);
  const hits = rows.map((p, i) => `<rect x="${(x(i) - colW / 2).toFixed(1)}" y="${T}" width="${colW.toFixed(1)}" height="${H - T - B}" class="hit"
    data-tip="${esc(fmtDay(p.from))} → ${esc(fmtDay(p.to))}&#10;${vals[i] === null ? 'No scored findings' : 'Average risk ' + fmtScore(vals[i]) + ' · n=' + fmtNum(p.sample)}"/>`).join('');
  const lab = i => `<text x="${x(i).toFixed(1)}" y="${H - 8}" text-anchor="${i === 0 ? 'start' : i === rows.length - 1 ? 'end' : 'middle'}" class="axis-t">${esc(fmtShortDate(rows[i].from))}</text>`;
  const xl = [0, Math.floor((rows.length - 1) / 2), rows.length - 1].filter((v, i, a) => a.indexOf(v) === i).map(lab).join('');
  const first = known[0], last = known[known.length - 1];
  return `<svg class="trend" viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(o.label || 'Average VEYRS risk over time')}: from ${fmtScore(first)} to ${fmtScore(last)}">
      <defs><linearGradient id="${gid}" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="var(--chart-risk)" stop-opacity=".32"/>
        <stop offset="100%" stop-color="var(--chart-risk)" stop-opacity="0"/></linearGradient></defs>
      ${grid}<line x1="${L}" x2="${W - R}" y1="${H - B}" y2="${H - B}" class="axis-l"/>${body}${lonely}${lastMark}${xl}${hits}</svg>
    <p class="chart-note">${segs.length > 1 ? 'Gaps are buckets with no scored finding — not zeros. ' : ''}Scale ${lo}–${hi} of 100.</p>
    ${chartData(['From', 'To', 'Average risk', 'Scored findings'], rows.map((p, i) => [fmtDay(p.from), fmtDay(p.to), vals[i] === null ? '—' : fmtScore(vals[i]), fmtNum(p.sample)]))}`;
}

/* Monotone cubic (Fritsch-Carlson) through the given points: smooth, but it
   never overshoots -- a curve that dips below its lowest bucket would draw a
   value nobody measured. */
let chartSeq = 0;
function smoothPath(pts) {
  const n = pts.length;
  const f = v => v.toFixed(1);
  if (n < 3) return pts.map((p, i) => (i ? 'L' : 'M') + f(p[0]) + ' ' + f(p[1])).join(' ');
  const dx = [], m = [], t = [];
  for (let i = 0; i < n - 1; i++) { dx[i] = pts[i + 1][0] - pts[i][0]; m[i] = (pts[i + 1][1] - pts[i][1]) / (dx[i] || 1); }
  t[0] = m[0]; t[n - 1] = m[n - 2];
  for (let i = 1; i < n - 1; i++) t[i] = m[i - 1] * m[i] <= 0 ? 0 : (m[i - 1] + m[i]) / 2;
  for (let i = 0; i < n - 1; i++) {
    if (m[i] === 0) { t[i] = 0; t[i + 1] = 0; continue; }
    const a = t[i] / m[i], b = t[i + 1] / m[i], q = a * a + b * b;
    if (q > 9) { const k = 3 / Math.sqrt(q); t[i] = k * a * m[i]; t[i + 1] = k * b * m[i]; }
  }
  let d = 'M' + f(pts[0][0]) + ' ' + f(pts[0][1]);
  for (let i = 0; i < n - 1; i++) {
    const h = dx[i] / 3;
    d += ` C${f(pts[i][0] + h)} ${f(pts[i][1] + t[i] * h)} ${f(pts[i + 1][0] - h)} ${f(pts[i + 1][1] - t[i + 1] * h)} ${f(pts[i + 1][0])} ${f(pts[i + 1][1])}`;
  }
  return d;
}
const niceMax = v => { if (v <= 0) return 1; const p = Math.pow(10, Math.floor(Math.log10(v))); const r = v / p; return (r <= 1 ? 1 : r <= 2 ? 2 : r <= 5 ? 5 : 10) * p; };

/* Part-to-whole of ONE total with five ordered parts: the case a donut is
   honest for. The ring carries proportion, the legend carries every number --
   nobody has to read an angle. */
function donut(obj, order) {
  const keys = (order || SEV_ORDER).filter(k => (obj || {})[k] !== undefined);
  const total = keys.reduce((a, k) => a + (Number(obj[k]) || 0), 0);
  if (!total) return '<p class="muted small">Nothing open — nothing to break down.</p>';
  const R = 54, C = 2 * Math.PI * R, GAP = 2;
  let acc = 0;
  const arcs = keys.filter(k => Number(obj[k]) > 0).map(k => {
    const n = Number(obj[k]), len = n / total * C;
    const seg = `<circle cx="70" cy="70" r="${R}" fill="none" stroke="${sevColour(k)}" stroke-width="16"
      stroke-dasharray="${Math.max(len - GAP, 1.5).toFixed(2)} ${C.toFixed(2)}" stroke-dashoffset="${(-acc).toFixed(2)}"
      transform="rotate(-90 70 70)" data-tip="${esc(titleCase(k))}: ${fmtNum(n)} (${(n / total * 100).toFixed(1)}%)"/>`;
    acc += len; return seg;
  }).join('');
  const max = Math.max(...keys.map(k => Number(obj[k]) || 0));
  return `<div class="donut-wrap">
    <svg class="donut" viewBox="0 0 140 140" role="img" aria-label="${keys.map(k => `${titleCase(k)} ${fmtNum(obj[k])}`).join(', ')}">
      <circle cx="70" cy="70" r="${R}" fill="none" stroke="var(--surface-2)" stroke-width="16"/>${arcs}
      <text x="70" y="68" text-anchor="middle" class="donut-n">${fmtNum(total)}</text>
      <text x="70" y="86" text-anchor="middle" class="donut-l">open</text></svg>
    <div class="legend-table">${keys.map(k => { const n = Number(obj[k]) || 0; return `
      <div class="lt-row"><i style="background:${sevColour(k)}"></i><span class="lt-k">${esc(titleCase(k))}</span>
        <span class="lt-bar"><span style="width:${(n / max * 100).toFixed(1)}%;background:${sevColour(k)}"></span></span>
        <b>${fmtNum(n)}</b><span class="lt-p">${(n / total * 100).toFixed(0)}%</span></div>`; }).join('')}</div>
  </div>`;
}

/* Compact operational list: label + context on the left, value on the right.
   For figures that matter together but are not worth a tile each. */
function opsList(rows) {
  return `<div class="ops">${rows.map(r => `<div class="ops-row">
    <span class="ops-l">${r.label}${r.hint ? `<small>${r.hint}</small>` : ''}</span>
    <span class="ops-v ${r.tone || ''}">${r.value}</span></div>`).join('')}</div>`;
}

/* Every bucket of a chart as a table, behind a disclosure. The hover
   tooltip is mouse-only; this is the same data for the keyboard, a screen
   reader, and anybody checking a chart against its numbers. */
function chartData(head, rows) {
  if (!rows.length) return '';
  return `<details class="chart-data"><summary>Show data</summary><div class="table-wrap mt-2"><table>
    <thead><tr>${head.map((h, i) => `<th class="${i ? 'num' : ''}">${esc(h)}</th>`).join('')}</tr></thead>
    <tbody>${rows.map(r => `<tr>${r.map((c, i) => `<td class="${i ? 'num' : ''}">${c}</td>`).join('')}</tr>`).join('')}</tbody>
  </table></div></details>`;
}

/* A ratio against its target band. The number stays the headline; the bar
   only says where it sits between 0 and 100 %. */
function meter(ratio) {
  if (ratio === null || ratio === undefined) return '';
  const pct = Math.max(0, Math.min(100, Number(ratio) * 100));
  const c = pct >= 90 ? 'var(--veyrs-remediated)' : pct >= 70 ? 'var(--veyrs-warning)' : 'var(--veyrs-critical)';
  return `<span class="meter" role="img" aria-label="${pct.toFixed(1)}% against a target band of 90% or more" title="${pct.toFixed(1)}% — target band ≥ 90%"><span style="width:${pct}%;background:${c}"></span><i style="left:90%"></i></span>`;
}

/* Two distributions over the SAME ordinal scale are one comparison, not two
   lists. Drawn back-to-back around a shared centre column so the eye reads the
   disagreement — which is the only reason both numbers exist.

   The severity ramp is a *status* palette, and it is measurably weak in the
   middle: high (#EA580C) and medium (#D97706) sit at ΔE 6.7 for normal vision
   and 1.6 under deuteranopia. Every mark here therefore carries its labelled
   pill and its own number; colour is never the only encoding. Do not "clean
   this up" by dropping the labels. */
function splitBars(left, right, opts) {
  const o = opts || {};
  const L = left || {}, R = right || {};
  const palette = o.palette || sevColour;
  const keys = (o.order || SEV_ORDER).filter(k => (k in L) || (k in R));
  const totalL = keys.reduce((a, k) => a + (Number(L[k]) || 0), 0);
  const totalR = keys.reduce((a, k) => a + (Number(R[k]) || 0), 0);
  if (!totalL && !totalR) return '<p class="muted small">No open findings — nothing to compare.</p>';
  const max = Math.max(1, ...keys.map(k => Math.max(Number(L[k]) || 0, Number(R[k]) || 0)));
  const side = (n, k, cls) => `<span class="split-side ${cls}">
      <span class="split-track"><span class="split-fill" style="width:${n / max * 100}%;background:${palette(k)}"></span></span>
      <span class="num">${fmtNum(n)}</span></span>`;
  return `<div class="split">
    <div class="split-head"><span class="l">${esc(o.leftLabel || 'Left')}</span><span class="c">Level</span><span>${esc(o.rightLabel || 'Right')}</span></div>
    ${keys.map(k => {
      const l = Number(L[k]) || 0, r = Number(R[k]) || 0, d = r - l;
      return `<div class="split-row" title="${esc(titleCase(k))} — ${esc(o.leftLabel || 'left')} ${fmtNum(l)} · ${esc(o.rightLabel || 'right')} ${fmtNum(r)}">
        ${side(l, k, 'l')}
        <span class="split-mid">${sevPill(k)}<span class="split-delta ${d > 0 ? 'up' : d < 0 ? 'down' : ''}">${d === 0 ? '±0' : (d > 0 ? '+' : '−') + Math.abs(d)}</span></span>
        ${side(r, k, 'r')}</div>`;
    }).join('')}
    <p class="split-foot small muted">${fmtNum(totalL)} open findings on each side — the same population, scored twice.</p>
  </div>`;
}

/* Ordered numeric bins are a histogram: the x axis carries the scale, height
   carries magnitude, and one hue carries everything else. A per-bin colour
   here would double-encode height and buy nothing. */
function histogram(obj, unit) {
  const entries = Object.entries(obj || {});
  const total = entries.reduce((a, [, v]) => a + (Number(v) || 0), 0);
  if (!entries.length || !total) return `<p class="muted small">No ${esc(unit || 'scored')} data on open findings — nothing to bin.</p>`;
  const max = Math.max(1, ...entries.map(([, v]) => Number(v) || 0));
  return `<div class="hist">${entries.map(([k, v]) => {
    const n = Number(v) || 0;
    return `<span class="hist-col" title="${esc(String(k))} — ${fmtNum(n)} of ${fmtNum(total)} (${Math.round(n / total * 100)}%)">
      ${n ? `<span class="hist-val">${fmtNum(n)}</span>` : ''}
      <span class="hist-bar${n ? '' : ' zero'}" style="height:${n ? Math.max(n / max * 100, 3) : 0}%"></span></span>`;
  }).join('')}</div>
  <div class="hist-axis">${entries.map(([k]) => `<span>${esc(String(k))}</span>`).join('')}</div>`;
}

/* Detected vs remediated is a flow: risk arriving and risk leaving. Drawn
   back-to-back around a zero baseline so *position* carries identity — orange
   and green collide badly under protanopia (ΔE 3.3, measured), so colour here
   is redundant reinforcement, never the encoding. */
function flowColumns(points) {
  const rows = (points || []).filter(Boolean);
  const inflow = rows.map(p => Number(p.detected) || 0);
  const outflow = rows.map(p => Number(p.remediated) || 0);
  const totalIn = inflow.reduce((a, b) => a + b, 0), totalOut = outflow.reduce((a, b) => a + b, 0);
  if (!rows.length || (!totalIn && !totalOut)) return '<p class="muted small">No findings detected or remediated in this window.</p>';
  const net = totalIn - totalOut;
  const W = 720, H = 230, L = 40, R = 14, T = 14, B = 28;
  const top = niceMax(Math.max(1, ...inflow, ...outflow));
  const x = i => L + i / Math.max(1, rows.length - 1) * (W - L - R);
  const y = v => T + (1 - v / top) * (H - T - B);
  const ticks = [0, top / 4, top / 2, top * 3 / 4, top];
  const grid = ticks.map(v => `<line x1="${L}" x2="${W - R}" y1="${y(v).toFixed(1)}" y2="${y(v).toFixed(1)}" class="grid-l"/>
    <text x="${L - 8}" y="${(y(v) + 3.5).toFixed(1)}" text-anchor="end" class="axis-t">${fmtNum(Math.round(v))}</text>`).join('');
  const series = (vals, cls, gid, col) => {
    const pts = vals.map((v, i) => [x(i), y(v)]);
    const d = rows.length > 1 ? smoothPath(pts) : `M${pts[0][0]} ${pts[0][1]}`;
    return `<defs><linearGradient id="${gid}" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="${col}" stop-opacity=".26"/><stop offset="100%" stop-color="${col}" stop-opacity="0"/></linearGradient></defs>
      <path d="${d} L${pts[pts.length - 1][0].toFixed(1)} ${H - B} L${pts[0][0].toFixed(1)} ${H - B} Z" fill="url(#${gid})"/>
      <path d="${d}" class="${cls}"/>
      ${pts.map(p => `<circle cx="${p[0].toFixed(1)}" cy="${p[1].toFixed(1)}" r="2.4" class="${cls}-dot"/>`).join('')}`;
  };
  const colW = (W - L - R) / Math.max(1, rows.length - 1);
  const hits = rows.map((p, i) => `<rect x="${(x(i) - colW / 2).toFixed(1)}" y="${T}" width="${colW.toFixed(1)}" height="${H - T - B}" class="hit"
    data-tip="${esc(fmtDay(p.from))} → ${esc(fmtDay(p.to))}&#10;Detected ${fmtNum(inflow[i])} · Remediated ${fmtNum(outflow[i])} · Net ${inflow[i] - outflow[i] > 0 ? '+' : ''}${fmtNum(inflow[i] - outflow[i])}"/>`).join('');
  const lab = i => `<text x="${x(i).toFixed(1)}" y="${H - 8}" text-anchor="${i === 0 ? 'start' : i === rows.length - 1 ? 'end' : 'middle'}" class="axis-t">${esc(fmtShortDate(rows[i].from))}</text>`;
  const xl = [0, Math.floor((rows.length - 1) / 2), rows.length - 1].filter((v, i, a) => a.indexOf(v) === i).map(lab).join('');
  const a = ++chartSeq;
  return `<div class="legend">
      <span><i class="sw sw-in"></i>Detected <b>${fmtNum(totalIn)}</b></span>
      <span><i class="sw sw-out"></i>Remediated <b>${fmtNum(totalOut)}</b></span>
      <span class="legend-net ${net > 0 ? 'neg' : 'pos'}">Net ${net > 0 ? '+' : ''}${fmtNum(net)}</span>
    </div>
    <svg class="trend flowc" viewBox="0 0 ${W} ${H}" role="img" aria-label="Detected ${fmtNum(totalIn)} and remediated ${fmtNum(totalOut)} findings over the window, net ${net > 0 ? '+' : ''}${fmtNum(net)}">
      ${grid}<line x1="${L}" x2="${W - R}" y1="${H - B}" y2="${H - B}" class="axis-l"/>
      ${series(inflow, 'line-in', 'fi' + a, 'var(--chart-in)')}${series(outflow, 'line-out', 'fo' + a, 'var(--chart-out)')}${xl}${hits}</svg>
    <p class="chart-note">${net > 0 ? 'The backlog grew in this window: more risk arrived than left.' : net < 0 ? 'The backlog shrank in this window.' : 'The backlog held level.'}</p>
    ${chartData(['From', 'To', 'Detected', 'Remediated', 'Net'], rows.map((p, i) => [fmtDay(p.from), fmtDay(p.to), fmtNum(inflow[i]), fmtNum(outflow[i]), (inflow[i] - outflow[i] > 0 ? '+' : '') + fmtNum(inflow[i] - outflow[i])]))}`;
}

/* A ranked list is still a chart: the bar is the comparison, the row is the
   record. Nominal categories get ONE hue — darker-where-bigger would encode
   length twice and say nothing new. */
function rankedBars(rows, opts) {
  const o = opts || {};
  const items = (rows || []).slice(0, o.limit || 8);
  if (!items.length) return `<p class="muted small">${o.empty || 'Nothing to rank yet.'}</p>`;
  const max = Math.max(1, ...items.map(r => Number(o.value(r)) || 0));
  return `<div class="ranked">${items.map(r => {
    const n = Number(o.value(r)) || 0;
    return `<div class="ranked-row">
      <span class="ranked-label">${o.label(r)}</span>
      <span class="bar-track"><span class="bar-fill" style="width:${n / max * 100}%;background:${o.colour ? o.colour(r) : 'var(--primary)'}"></span></span>
      <span class="num">${o.display ? o.display(r) : fmtNum(n)}</span>
    </div>`;
  }).join('')}</div>`;
}
/* Semantic colour is a claim that something is wrong. A zero is not wrong, so
   a count of zero stays neutral no matter which tone the card asks for. */
function tone(cls, value) { return Number(value) > 0 ? cls : ''; }

/* The risk *score* is continuous (0-100, NOT a CVSS 0-10); the ramp is ordinal.
   These cuts mirror LEVEL_BANDS in backend/veyrs/engines/risk.py — if that tuple
   moves, this moves with it, or a bar will be coloured a level the backend does
   not agree with. */
function riskBand(score) {
  const n = Number(score);
  if (!isFinite(n)) return 'informational';
  if (n >= 90) return 'critical';
  if (n >= 70) return 'high';
  if (n >= 40) return 'medium';
  if (n >= 10) return 'low';
  return 'informational';
}

const sevColour = k => ({
  critical: 'var(--veyrs-critical)', high: 'var(--veyrs-high)', medium: 'var(--veyrs-medium)',
  low: 'var(--veyrs-low)', informational: 'var(--veyrs-informational)',
}[String(k).toLowerCase()] || 'var(--veyrs-neutral)');
/* The fallback was `--primary`, so a CVSS score of 0.0 ("None") was painted in
   VEYRS blue -- the identity colour standing in for a severity (DESIGN_SYSTEM
   §12 item 3). Anything outside the five severities is neutral. */

/* Uniform scaling on purpose: preserveAspectRatio="none" stretches the x axis
   and turns every marker into an ellipse. The stroke stays 2px through
   vector-effect, the geometry stays honest. */
function sparkline(points) {
  const rows = points || [];
  const vals = rows.map(p => (p.average_risk === null || p.average_risk === undefined) ? null : Number(p.average_risk));
  const known = vals.filter(v => v !== null);
  if (!known.length) return `<p class="muted small">No scored findings in this window — nothing to trend.</p>`;
  if (known.length < 2) {
    return `<div class="single-point"><span class="value">${fmtScore(known[0])}</span>
      <span class="hint">Average VEYRS risk — one scored bucket in this window.</span></div>
      <p class="small muted">A line through a single point is not a trend. This fills in as risk history accumulates.</p>`;
  }
  const lo = Math.min(...known), hi = Math.max(...known), span = (hi - lo) || 1;
  const W = 720, H = 150, P = 16;
  const px = i => P + (i / Math.max(1, vals.length - 1)) * (W - P * 2);
  const py = v => H - P - ((v - lo) / span) * (H - P * 2.2);
  const pts = vals.map((v, i) => v === null ? null : [px(i), py(v)]).filter(Boolean);
  const line = pts.map((p, i) => (i ? 'L' : 'M') + p[0].toFixed(1) + ' ' + p[1].toFixed(1)).join(' ');
  const area = `${line} L${pts[pts.length - 1][0].toFixed(1)} ${H - P} L${pts[0][0].toFixed(1)} ${H - P} Z`;
  const last = pts[pts.length - 1];
  const hits = vals.map((v, i) => v === null ? '' :
    `<rect x="${(px(i) - 14).toFixed(1)}" y="0" width="28" height="${H}" fill="transparent"><title>${fmtDate(rows[i].from)} — average risk ${fmtScore(v)} (n=${fmtNum(rows[i].sample)})</title></rect>`).join('');
  return `<svg class="spark" viewBox="0 0 ${W} ${H}" role="img" aria-label="Average VEYRS risk over time">
      <defs><linearGradient id="sparkfill" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="var(--primary)" stop-opacity=".24"/>
        <stop offset="100%" stop-color="var(--primary)" stop-opacity="0"/></linearGradient></defs>
      <line x1="${P}" y1="${H - P}" x2="${W - P}" y2="${H - P}" stroke="var(--border)" stroke-width="1" vector-effect="non-scaling-stroke"/>
      <path d="${area}" fill="url(#sparkfill)"/>
      <path d="${line}" fill="none" stroke="var(--primary)" stroke-width="2" stroke-linejoin="round" stroke-linecap="round" vector-effect="non-scaling-stroke"/>
      <circle cx="${last[0].toFixed(1)}" cy="${last[1].toFixed(1)}" r="5" fill="var(--primary)" stroke="var(--surface)" stroke-width="3"/>
      ${hits}
    </svg>
    <p class="small muted">Average VEYRS risk · latest <strong>${fmtScore(known[known.length - 1])}</strong> · min ${fmtScore(lo)} · max ${fmtScore(hi)} — hover a point for its sample size.</p>`;
}

let assistSource = {};   /* see the bulletin assistant, further down */

/* ══ Router ════════════════════════════════════════════════════════════ */

/* The nav is split along ONE axis: what you do every day, and what you set up
   once. That split is the answer to two complaints that sounded like different
   problems -- "Workflows is too complicated" and "Governance is absurdly
   complicated" -- and were the same one. Both screens are platform
   configuration, and both sat next to the queues an analyst lives in, so every
   operator was asked to understand the whole data model before triaging their
   first finding.

   What moved, and why it is worth the disruption:
   * `Governance` is gone as a group. It held four unrelated things: Compliance
     and Reports are OUTPUTS (they belong with reporting), Integrations and
     Administration are SETUP. A group whose members share only "senior people
     care about this" is a group nobody can navigate.
   * `Vulnerability Scanner` moves to Configure. Phase 33 deliberately put it
     FIRST under Risk, reasoning that a reader who cannot find what produced
     the findings assumes nothing did -- a real concern, and the reason the
     Findings page now carries a "Where do these come from?" line pointing at
     it. The page itself is a settings page; keeping it in the daily lane to
     serve as documentation was solving a documentation problem with a menu.
   * `SLA & Policies`, `Workflows` and the two new automation screens are all
     Configure. They are read constantly and written rarely.

   Nothing was renamed for the sake of it. `Documents` became `Documents &
   Advisories` because "Documents" next to "Knowledge Base" reads as "files"
   and gave no clue that this is where a vendor advisory goes. */
const NAV = [
  { group: 'Overview', key: 'overview', ico: 'dashboard', items: [
    /* First, and above Getting Started, on purpose. The console had
       twenty-eight screens and no default one: everybody landed on a
       dashboard, read a number, and had nowhere to act on it. 149 of the
       408 findings in production had never been opened by anybody. */
    { path: 'triage',    label: 'Triage queue', ico: 'triage', perm: 'finding:read' },
    { path: 'guide',     label: 'Getting Started', ico: 'guide' },
    { path: 'dashboard', label: 'Dashboards', ico: 'dashboard', perm: 'report:read', children: [
      { path: 'dashboard', label: 'Executive', q: { tab: 'executive' }, def: true },
      { path: 'dashboard', label: 'Technical', q: { tab: 'technical' } },
      { path: 'dashboard', label: 'SLA',       q: { tab: 'sla' } },
    ] },
    { path: 'search',        label: 'Search',        ico: 'search', hidden: true },
    { path: 'notifications', label: 'Notifications', ico: 'bell', hidden: true },
  ] },

  /* ── Work: the two queues, and the CVE rollup that groups one of them ── */
  { group: 'Work', key: 'work', ico: 'findings', items: [
    { path: 'findings', label: 'Findings', ico: 'findings', perm: 'finding:read', children: [
      { path: 'findings', label: 'All findings' },
      { path: 'findings', label: 'Critical',        q: { severity: 'critical' } },
      { path: 'findings', label: 'New / untriaged', q: { state: 'new' } },
      { path: 'findings', label: "My teams' queue", q: { queue: 'my_teams' } },
      { path: 'findings', label: 'No owner at all', q: { queue: 'unowned' } },
    ] },
    { path: 'changes', label: 'Recent changes', ico: 'changes', perm: 'finding:read' },
    /* Exactly one of these two is ever in the menu. `mode` is matched against
       `ticketingMode` in the nav filter above -- the same mechanism `scan`
       already used, rather than a second one. */
    { path: 'tickets', label: 'Tickets', ico: 'tickets', perm: 'ticket:read', mode: 'internal', children: [
      { path: 'tickets', label: 'All tickets' },
      { path: 'tickets', label: 'Remediation', q: { ticket_type: 'remediation' } },
      { path: 'tickets', label: 'Changes',     q: { ticket_type: 'change' } },
      { path: 'tickets', label: 'Incidents',   q: { ticket_type: 'incident' } },
    ] },
    { path: 'issues', label: 'Issues', ico: 'issues', perm: 'ticket:read', mode: 'external', children: [
      { path: 'issues', label: 'All issues' },
      { path: 'issues', label: 'Critical',  q: { severity: 'critical' } },
      { path: 'issues', label: 'High',      q: { severity: 'high' } },
      { path: 'issues', label: 'Unlinked',  q: { is_active: 'false' } },
    ] },
    { path: 'vulnerabilities', label: 'Vulnerabilities', ico: 'vulns', perm: 'vulnerability:read', children: [
      { path: 'vulnerabilities', label: 'All vulnerabilities' },
      { path: 'vulnerabilities', label: 'Critical', q: { severity: 'critical' } },
      { path: 'vulnerabilities', label: 'High',     q: { severity: 'high' } },
    ] },
    /* `reg: true` -- out of the menu entirely while this tenant does not keep a
       register, through the same filter `scan` and `mode` already use rather
       than a third mechanism. The entries stay readable by URL and by API on
       purpose: they are evidence, and hiding them to tidy a menu would destroy
       the reason somebody wrote them down. */
    { path: 'risks', label: 'Risk Register', ico: 'risks', perm: 'riskregister:read', reg: true, children: [
      { path: 'risks', label: 'All risks' },
      { path: 'risks', label: 'Open only',          q: { open_only: 'true' } },
      { path: 'risks', label: 'Nobody accountable', q: { unassigned: 'true' } },
      { path: 'risks', label: 'Review overdue',     q: { review_overdue: 'true' } },
      { path: 'risks', label: 'Mine',               q: { mine: 'true' } },
    ] },
  ] },

  /* Assets is its own top-level menu, not an entry under Work. The inventory
     is not a sub-topic of the vulnerability list: it is the denominator every
     other number on this console is computed against. */
  { group: 'Estate', key: 'assets', ico: 'assets', items: [
    { path: 'assets', label: 'Inventory', ico: 'assets', perm: 'asset:read', children: [
      { path: 'assets', label: 'All assets' },
      { path: 'assets', label: 'Internet-exposed',  q: { exposure: 'internet' } },
      /* Negation gets its OWN entry rather than four positive ones. Listing
         staging/test/development/dr by hand would stop covering the estate the
         day a sixth environment is added -- and nobody would notice, because
         the list would still return rows. */
      { path: 'assets', label: 'Not internet-facing', q: { exclude_exposure: 'internet' } },
      { path: 'assets', label: 'Business-critical', q: { criticality: 'critical' } },
      { path: 'assets', label: 'Production',        q: { environment: 'production' } },
      { path: 'assets', label: 'Non-production',    q: { exclude_environment: 'production' } },
      { path: 'assets', label: 'No owning team',    q: { unowned: 'true' } },
    ] },
  ] },

  { group: 'Intelligence', key: 'intelligence', ico: 'intel', items: [
    { path: 'intel', label: 'Threat Intel', ico: 'intel', perm: 'cve:read', children: [
      { path: 'intel', label: 'CVE',       q: { tab: 'cve' }, def: true },
      { path: 'intel', label: 'CISA KEV',  q: { tab: 'kev' } },
      { path: 'intel', label: 'News',      q: { tab: 'news' } },
      { path: 'intel', label: 'Sources',   q: { tab: 'sources' }, sec: 'Feeds' },
      { path: 'intel', label: 'Feed runs', q: { tab: 'runs' } },
      { path: 'intel', label: 'Schedule',  q: { tab: 'schedule' } },
    ] },
    { path: 'documents', label: 'Documents & Advisories', ico: 'documents', perm: 'document:read' },
    { path: 'knowledge', label: 'Knowledge Base', ico: 'knowledge', perm: 'knowledge:read' },
    /* The calculator had a group of its own ("Tools"): a heading over a single
       entry is a menu level that carries no information. It scores the CVEs
       listed directly above it, so it lives with them. */
    { path: 'cvss', label: 'CVSS Calculator', ico: 'cvss' },
    { path: 'ai',        label: 'AI Assistant',   ico: 'ai', perm: 'ai:read', children: [
      { path: 'ai', label: 'Ask',                     q: { tab: 'ask' }, def: true },
      { path: 'ai', label: 'Natural-language search', q: { tab: 'search' } },
      { path: 'ai', label: 'Policy',                  q: { tab: 'policy' }, sec: 'Configure' },
      { path: 'ai', label: 'Providers',               q: { tab: 'providers' } },
      { path: 'ai', label: 'AI audit',                q: { tab: 'audit' } },
    ] },
  ] },

  /* Outputs. What you hand to somebody who was not in the room. */
  { group: 'Reporting', key: 'reporting', ico: 'reports', items: [
    { path: 'reports',    label: 'Reports',    ico: 'reports', perm: 'report:read' },
    { path: 'compliance', label: 'Compliance', ico: 'compliance', perm: 'compliance:read' },
    { path: 'audit',      label: 'Audit Log',  ico: 'audit', perm: 'audit:read' },
  ] },

  /* ── Configure: set up once, read often, change rarely ──────────────── */
  /* pin: 'bottom' (0.38.2, owner request): rendered in #nav-pinned, its own
     block at the foot of the sidebar right above the account bar (0.38.3).
     0.39.0 (owner request): the sidebar shows Configure as ONE entry; these
     pages and their sub-views are listed inside the Configure page itself
     (configureFrame), like a settings screen, not as a tree in the menu. */
  { group: 'Configure', key: 'configure', ico: 'admin', pin: 'bottom', items: [
    /* Two related but genuinely different pages, and they cross-link:
       this one is the runner, its queue and its jobs; Administration ->
       Scanning is the single switch that decides whether VEYRS is allowed to
       probe anything at all. Collapsing them would put an estate-wide policy
       toggle in the middle of an operational queue. */
    /* `scan: true` -- out of the menu entirely while this tenant is
       ingest-only. Two neighbours are deliberately NOT flagged, and that
       distinction is the whole design:
         * `Administration -> Scanning` is the SWITCH. Hiding it together with
           what it controls is a one-way door: whoever turned scanning off
           would have no menu path left to turn it back on.
         * `Data sources` is INGESTION, which is what the mode IS. An
           ingest-only deployment without an import screen cannot receive a
           finding at all -- the menu would be consistent and the product dead.
       The ROUTE stays registered either way. A bookmark or a runbook link must
       not land on "No view is registered", and the page already carries the
       banner naming the mode and linking to the switch. */
    { path: 'scanner', label: 'Vulnerability scanner', ico: 'scanner', perm: 'agent:read', scan: true },
    { path: 'integrations', label: 'Data sources', ico: 'integrations', perm: 'importer:read', children: [
      { path: 'integrations', label: 'Scanner import',    q: { tab: 'import' }, def: true },
      { path: 'integrations', label: 'Scanner connectors', q: { tab: 'scanners' } },
      { path: 'integrations', label: 'Import runs',       q: { tab: 'runs' } },
      { path: 'integrations', label: 'ITSM connectors',   q: { tab: 'connectors' } },
      { path: 'integrations', label: 'Documentation',     q: { tab: 'docs' } },
    ] },
    { path: 'policies', label: 'SLA & Policies', ico: 'policies', perm: 'sla:read', children: [
      { path: 'policies', label: 'SLA policies',     q: { tab: 'sla' }, def: true },
      { path: 'policies', label: 'Escalation',       q: { tab: 'escalation' } },
      { path: 'policies', label: 'Assignment rules', q: { tab: 'assignment' } },
      { path: 'policies', label: 'Risk profiles',    q: { tab: 'risk' } },
      { path: 'policies', label: 'SLA events',       q: { tab: 'events' } },
      { path: 'policies', label: 'Upgrade paths',    q: { tab: 'upgrade' } },
    ] },
    { path: 'automation', label: 'Automation', ico: 'automation', perm: 'workflow:read', children: [
      { path: 'automation', label: 'Automatic tickets', q: { tab: 'tickets' }, def: true },
      { path: 'automation', label: 'Workflows',         q: { tab: 'workflows' } },
      { path: 'automation', label: 'Workflow runs',     q: { tab: 'runs' } },
    ] },
    /* `flat: true` (0.42.0, owner request): Administration is not ONE page
       in the Configure menu with twenty sub-items hanging off it -- that read
       as a text tree, unlike every other entry. Its three sections (`sec:`)
       are menu groups of their own and every tab is a first-class row with
       its own icon; the page head names the tab, not "Administration". */
    { path: 'admin', label: 'Administration', ico: 'admin', perm: 'user:read', flat: true, children: [
      { path: 'admin', label: 'Users',        q: { tab: 'users' }, def: true, sec: 'Access', ico: 'users' },
      { path: 'admin', label: 'Teams',        q: { tab: 'teams' }, ico: 'teams' },
      { path: 'admin', label: 'Roles',        q: { tab: 'roles' }, ico: 'roles' },
      { path: 'admin', label: 'Departments',  q: { tab: 'departments' }, ico: 'departments' },
      { path: 'admin', label: 'API keys',     q: { tab: 'apikeys' }, ico: 'apikeys' },
      /* Deliberately NOT flagged `scan: true`. The scanning-mode filter hides
         what the mode switched off; this is how people sign in, and it is on
         in an ingest-only deployment exactly as it is in a scanning one. */
      { path: 'admin', label: 'Directory',    q: { tab: 'directory' }, ico: 'directory' },
      { path: 'admin', label: 'RADIUS',       q: { tab: 'radius' }, ico: 'radius' },
      { path: 'admin', label: 'Single sign-on', q: { tab: 'sso' }, ico: 'sso' },
      { path: 'admin', label: 'Ticketing',    q: { tab: 'ticketing' }, sec: 'Data intake', ico: 'tickets' },
      /* Also NOT flagged `scan: true`. Reading somebody else's inventory is
         what an ingest-only deployment DOES: hiding it alongside the scanner
         would leave that deployment with no way to receive an asset at all. */
      { path: 'admin', label: 'Asset sources', q: { tab: 'sources' }, ico: 'sources' },
      { path: 'admin', label: 'Import teams',  q: { tab: 'teamimport' }, ico: 'teamimport' },
      { path: 'admin', label: 'Scanning',     q: { tab: 'scanning' }, ico: 'toggle' },
      /* The page had this tab and the menu did not: the register switch was
         reachable only by knowing the URL. */
      { path: 'admin', label: 'Risk register', q: { tab: 'riskregister' }, sec: 'Platform', ico: 'risks' },
      { path: 'admin', label: 'Secret storage', q: { tab: 'secrets' }, ico: 'secrets' },
      { path: 'admin', label: 'Organization', q: { tab: 'org' }, ico: 'org' },
      { path: 'admin', label: 'Installed software', q: { tab: 'software' }, ico: 'software' },
      { path: 'admin', label: 'Network access', q: { tab: 'network' }, ico: 'network' },
      { path: 'admin', label: 'Trust store', q: { tab: 'truststore' }, ico: 'truststore' },
      { path: 'admin', label: 'Web certificate', q: { tab: 'webcert' }, ico: 'webcert' },
      { path: 'admin', label: 'Software update', q: { tab: 'updates' }, ico: 'updates' },
    ] },
  ] },
];

/* ── Icons ───────────────────────────────────────────────────────────────
   One drawn set, 24-unit grid, 1.75 stroke, round joins, currentColor. The
   menu used to mix Unicode glyphs from five blocks and an emoji, which render
   at different sizes and weights in every font -- and differently again on
   each operating system. Drawn here, not fetched: the console loads nothing
   from outside its own origin (tests/test_phase53_system_inventory.py). */
const ICONS = {
  triage: '<path d="M3 13h4l2 3h6l2-3h4"/><path d="M5.5 5h13l2.5 8v5a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1v-5z"/>',
  guide: '<circle cx="12" cy="12" r="9"/><path d="m15.5 8.5-2 5-5 2 2-5z"/>',
  dashboard: '<rect x="3" y="3" width="7" height="9" rx="1"/><rect x="14" y="3" width="7" height="5" rx="1"/><rect x="14" y="12" width="7" height="9" rx="1"/><rect x="3" y="16" width="7" height="5" rx="1"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
  bell: '<path d="M6 16v-5a6 6 0 0 1 12 0v5l2 2H4z"/><path d="M10 20.5a2 2 0 0 0 4 0"/>',
  findings: '<path d="M12 3.5 2.5 20h19z"/><path d="M12 10v4.5"/><path d="M12 17.2v.1"/>',
  changes: '<path d="M3.5 12a8.5 8.5 0 1 0 2.6-6.1L3.5 8.5"/><path d="M3.5 3.5v5h5"/><path d="M12 7.5V12l3 2"/>',
  tickets: '<path d="M4 6h16v4a2 2 0 0 0 0 4v4H4v-4a2 2 0 0 0 0-4z"/><path d="M14.5 6v2.5M14.5 11v2M14.5 15.5V18"/>',
  issues: '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/>',
  vulns: '<rect x="7.5" y="7" width="9" height="13" rx="4.5"/><path d="M12 11v9M9.5 4.5 10.5 7M14.5 4.5 13.5 7M3.5 13h4M16.5 13h4M4.5 8.5l3 1.5M19.5 8.5l-3 1.5M4.5 18.5l3-1.5M19.5 18.5l-3-1.5"/>',
  risks: '<path d="M5 21V4"/><path d="M5 4h12l-2.5 4.5L17 13H5"/>',
  assets: '<rect x="3" y="4" width="18" height="7" rx="1"/><rect x="3" y="13" width="18" height="7" rx="1"/><path d="M7 7.5h.01M7 16.5h.01M11 7.5h6M11 16.5h6"/>',
  intel: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4.5"/><path d="M12 12l6.4-6.4"/>',
  documents: '<path d="M14 3H6v18h12V7z"/><path d="M14 3v4h4M9 12h6M9 16h6"/>',
  knowledge: '<path d="M2.5 5H9a3 3 0 0 1 3 3v12a2 2 0 0 0-2-2H2.5z"/><path d="M21.5 5H15a3 3 0 0 0-3 3v12a2 2 0 0 1 2-2h7.5z"/>',
  ai: '<path d="M11 3.5l1.8 5.2 5.2 1.8-5.2 1.8L11 17.5l-1.8-5.2L4 10.5l5.2-1.8z"/><path d="M18.5 15l.7 2 2 .7-2 .7-.7 2-.7-2-2-.7 2-.7z"/>',
  reports: '<rect x="4" y="3" width="16" height="18" rx="1"/><path d="M8 17v-3M12 17V9M16 17v-5"/>',
  compliance: '<path d="M12 3 4.5 6v6c0 4.6 3.2 7.8 7.5 9 4.3-1.2 7.5-4.4 7.5-9V6z"/><path d="m8.8 12 2.3 2.3 4.2-4.6"/>',
  audit: '<rect x="5" y="4" width="14" height="17" rx="1"/><path d="M9 4V2.8h6V4M9 10h6M9 14h6M9 18h3.5"/>',
  cvss: '<rect x="5" y="3" width="14" height="18" rx="1"/><path d="M8.5 7h7M8.5 11.5h.01M12 11.5h.01M15.5 11.5h.01M8.5 15h.01M12 15h.01M15.5 15h.01M8.5 18h.01M12 18h3.5"/>',
  scanner: '<path d="M4 8V5a1 1 0 0 1 1-1h3M16 4h3a1 1 0 0 1 1 1v3M20 16v3a1 1 0 0 1-1 1h-3M8 20H5a1 1 0 0 1-1-1v-3"/><path d="M4 12h16"/>',
  integrations: '<path d="M3 7.5h12.5M12 4l3.5 3.5L12 11"/><path d="M21 16.5H8.5M12 13l-3.5 3.5L12 20"/>',
  policies: '<circle cx="12" cy="13.5" r="7.5"/><path d="M12 9.5v4l2.5 2M9.5 2.5h5"/>',
  automation: '<rect x="3" y="3" width="6.5" height="6.5" rx="1"/><rect x="14.5" y="14.5" width="6.5" height="6.5" rx="1"/><path d="M6.25 9.5v2.5a3 3 0 0 0 3 3h5.25"/>',
  admin: '<path d="M4 6h9M17 6h3M4 12h3M11 12h9M4 18h11M19 18h1"/><circle cx="15" cy="6" r="2"/><circle cx="9" cy="12" r="2"/><circle cx="17" cy="18" r="2"/>',
  /* Configure -> Access / Data intake / Platform (0.42.0). */
  users: '<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20a6.5 6.5 0 0 1 13 0"/><path d="M16 4.6a3.5 3.5 0 0 1 0 6.8M18 14.2a6.5 6.5 0 0 1 3.5 5.8"/>',
  teams: '<circle cx="12" cy="7.5" r="3"/><circle cx="5" cy="10" r="2.2"/><circle cx="19" cy="10" r="2.2"/><path d="M7 20a5 5 0 0 1 10 0M1.5 18.5a3.5 3.5 0 0 1 5-3.2M22.5 18.5a3.5 3.5 0 0 0-5-3.2"/>',
  roles: '<rect x="3" y="5" width="18" height="14" rx="2"/><circle cx="9" cy="11" r="2.2"/><path d="M5.8 16a3.4 3.4 0 0 1 6.4 0M14.5 10h4M14.5 13.5h3"/>',
  departments: '<path d="M4 21V5a1 1 0 0 1 1-1h9a1 1 0 0 1 1 1v16"/><path d="M15 9h4a1 1 0 0 1 1 1v11M2.5 21h19M7.5 8h4M7.5 12h4M7.5 16h4"/>',
  apikeys: '<circle cx="8" cy="15" r="4.5"/><path d="m11.2 11.8 8.8-8.8M16.5 6.5 19 9M14 9l2 2"/>',
  directory: '<rect x="9" y="3" width="6" height="5" rx="1"/><rect x="2.5" y="16" width="6" height="5" rx="1"/><rect x="15.5" y="16" width="6" height="5" rx="1"/><path d="M12 8v4M5.5 16v-2a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v2"/>',
  radius: '<circle cx="12" cy="12" r="1.8"/><path d="M8.2 15.8a5.4 5.4 0 0 1 0-7.6M15.8 8.2a5.4 5.4 0 0 1 0 7.6M5.3 18.7a9.5 9.5 0 0 1 0-13.4M18.7 5.3a9.5 9.5 0 0 1 0 13.4"/>',
  sso: '<path d="M14 4h4a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-4"/><path d="M3 12h11M10 8l4 4-4 4"/>',
  sources: '<ellipse cx="12" cy="5.5" rx="7.5" ry="2.5"/><path d="M4.5 5.5v13c0 1.4 3.4 2.5 7.5 2.5s7.5-1.1 7.5-2.5v-13M4.5 12c0 1.4 3.4 2.5 7.5 2.5s7.5-1.1 7.5-2.5"/>',
  teamimport: '<path d="M12 15V3.5M7.5 8 12 3.5 16.5 8"/><path d="M4 14v5a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-5"/>',
  toggle: '<rect x="2.5" y="7" width="19" height="10" rx="5"/><circle cx="16.5" cy="12" r="2.8"/>',
  secrets: '<rect x="4.5" y="10.5" width="15" height="10" rx="1.5"/><path d="M8 10.5V7a4 4 0 0 1 8 0v3.5M12 14.5V17"/>',
  org: '<path d="M3 21h18M5 21V10l7-5 7 5v11"/><path d="M9.5 21v-5h5v5"/>',
  software: '<path d="M12 2.8 20.5 7.5v9L12 21.2 3.5 16.5v-9z"/><path d="M3.5 7.5 12 12l8.5-4.5M12 12v9.2"/>',
  network: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>',
  truststore: '<rect x="3" y="4" width="18" height="12" rx="1.5"/><path d="M7 8h10M7 11.5h5"/><circle cx="16" cy="15.5" r="2.5"/><path d="m14.6 17.6-.9 3.9 2.3-1.2 2.3 1.2-.9-3.9"/>',
  webcert: '<rect x="2.5" y="4" width="19" height="14" rx="1.5"/><path d="M2.5 8h19"/><rect x="9" y="12" width="6" height="4.5" rx=".8"/><path d="M10.5 12v-1.2a1.5 1.5 0 0 1 3 0V12"/>',
  updates: '<circle cx="12" cy="12" r="9"/><path d="M12 7.5v8M8.5 12.5 12 16l3.5-3.5"/>',
};
const icon = name => `<svg class="i" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[name] || ''}</svg>`;

/* ── Sidebar state ─────────────────────────────────────────────────────
   Two collapsible levels (group, and item-with-children) plus an icon rail.
   All three persist per browser, because a nav that forgets what you closed
   is a nav you close again every morning. The sets below hold what is
   OPEN: the sidebar starts fully COLLAPSED and stays that way until the
   operator opens something, so eight groups do not compete for attention
   before anyone has asked a question. A group added in a later release
   therefore arrives closed like the rest, which is the point -- a new
   release must not silently reflow a nav the operator had arranged.
   The group and item holding the CURRENT route are always rendered open and
   the persisted set is NOT mutated to do it: collapsing is a preference,
   losing your place is a bug, and reopening on navigation would silently
   erase the preference the operator just expressed.
   The storage keys carry `.open` because the SAME key names previously held
   the inverse set; reusing them would read every operator's closed groups as
   the only open ones -- the exact opposite of their preference. */
const NAV_LS = { groups: 'veyrs.nav.open.groups', items: 'veyrs.nav.open.items', rail: 'veyrs.nav.rail' };
const navReadSet = k => {
  try { return new Set(JSON.parse(localStorage.getItem(k) || '[]')); } catch { return new Set(); }
};
const navOpen = { groups: navReadSet(NAV_LS.groups), items: navReadSet(NAV_LS.items) };
function navSave() {
  try {
    localStorage.setItem(NAV_LS.groups, JSON.stringify([...navOpen.groups]));
    localStorage.setItem(NAV_LS.items, JSON.stringify([...navOpen.items]));
  } catch { /* private mode: the nav still works, it just forgets */ }
}
let navCtx = { name: 'dashboard', params: new URLSearchParams() };

/* Expansion is EXCLUSIVE at both levels: opening a section closes whatever the
   operator had open, so the stored set holds at most one key. It previously
   held every section ever expanded, which is why nothing ever appeared to
   close -- the toggle flipped one key and left the rest standing.

   The section holding the current route is deliberately NOT part of this set:
   it is forced open at render time by holdsActive/isActive. That is what keeps
   an accordion from collapsing the page you are standing on, and it is also
   why both handlers below REFUSE the click instead of flipping the key. A
   flip there is invisible on screen -- the render forces it open anyway -- and
   then decides, silently, which branch is open after the next navigation. */
function navSelect(set, key) {
  const wasOpen = set.has(key);
  set.clear();
  if (!wasOpen) set.add(key);
}

/* Mirrors `holdsActive` in renderNav: a group is the active one when it holds
   the item for the current route, not when its own key matches anything. */
const navGroupHoldsActive = key => {
  const g = NAV.find(x => x.key === key);
  return !!g && g.items.some(i => i.path === navCtx.name);
};

const navChildHref = c => '#/' + c.path + (c.q ? '?' + new URLSearchParams(c.q).toString() : '');

/* A `flat` item's children split at every `sec:` label: [{ sec, kids }].
   One reader for the Configure menu, its hub and the breadcrumb. */
function navSections(item) {
  const out = [];
  (item.children || []).filter(navShown).forEach(c => {
    if (c.sec || !out.length) out.push({ sec: c.sec || item.label, kids: [] });
    out[out.length - 1].kids.push(c);
  });
  return out;
}

/* A sub-item without `q` is the "All …" entry. It is active only while none
   of its siblings' filters are applied, so "All assets" and "Internet-exposed"
   are never lit at once -- two highlighted rows would claim the list is both
   filtered and complete. */
function navChildActive(c, name, params, siblingKeys) {
  if (c.path !== name) return false;
  const q = c.q || {};
  const keys = Object.keys(q);
  if (!keys.length) return !siblingKeys.some(k => params.get(k));
  return keys.every(k => {
    const cur = params.get(k);
    return cur === null ? !!c.def : cur === q[k];
  });
}

/* One filter for every list built from NAV (sidebar and Configure frame), so
   a page the tenant switched off never shows up in one and not the other. */
const navShown = i => !i.hidden && !(i.scan && !activeScanning)
  && !(i.reg && !riskRegisterOn)
  && !(i.mode && i.mode !== ticketingMode);

function renderNav(active, params) {
  const p = params || new URLSearchParams();
  /* The pinned group is one link to its own page (0.39.0). Lit on the hub
     and on every page it holds, which is what the gold marker means. */
  const navSolo = g => {
    const on = active === g.key || g.items.some(i => i.path === active);
    return `<div class="nav-sec"><a href="#/${esc(g.key)}" class="nav-solo${on ? ' active' : ''}" title="${esc(g.group)}"${on ? ' aria-current="page"' : ''}>`
      + `<span class="ico">${icon(g.ico)}</span><span class="nav-label">${esc(g.group)}</span></a></div>`;
  };
  const navSec = g => {
    const holdsActive = g.items.some(i => i.path === active);
    const open = holdsActive || navOpen.groups.has(g.key);
    const items = g.items.filter(navShown).map(i => {
      const isActive = active === i.path;
      const kids = i.children || [];
      const siblingKeys = [...new Set(kids.flatMap(c => Object.keys(c.q || {})))];
      const subOpen = kids.length > 0 && (isActive || navOpen.items.has(i.path));
      const caret = kids.length
        ? `<span class="nav-caret nav-toggle" data-item="${esc(i.path)}" data-open="${subOpen}" role="button" tabindex="-1"
             aria-label="Toggle ${esc(i.label)} sub-items">${subOpen ? '▾' : '▸'}</span>`
        : '';
      const sub = kids.length
        ? `<div class="nav-sub"${subOpen ? '' : ' hidden'}>${kids.map(c =>
            (c.sec ? `<span class="nav-subhead">${esc(c.sec)}</span>` : '')
            + `<a href="${navChildHref(c)}" class="nav-subitem${navChildActive(c, active, p, siblingKeys) ? ' active' : ''}">${esc(c.label)}</a>`
          ).join('')}</div>`
        : '';
      return `<div class="nav-item">
        <a href="#/${i.path}" class="${isActive ? 'active' : ''}" title="${esc(i.label)}"><span class="ico">${icon(i.ico)}</span><span class="nav-label">${esc(i.label)}</span>${caret}</a>
        ${sub}</div>`;
    }).join('');
    return `<div class="nav-sec">
      <button type="button" class="nav-group" data-group="${esc(g.key)}" aria-expanded="${open}" title="${esc(g.group)}">
        <span class="ico">${icon(g.ico)}</span><span class="nav-group-label">${esc(g.group)}</span><span class="nav-caret" data-open="${open}">${open ? '▾' : '▸'}</span>
      </button>
      <div class="nav-items"${open ? '' : ' hidden'}>${items}</div>
    </div>`;
  };
  $('#nav').innerHTML = NAV.filter(g => !g.pin).map(navSec).join('');
  const pinned = $('#nav-pinned');
  if (pinned) pinned.innerHTML = NAV.filter(g => g.pin === 'bottom').map(navSolo).join('');
  /* Administration alone has 18 sub-entries: its Platform block opens below
     the fold of a 900 px window, so the highlighted page was off-screen and
     the menu looked as if nothing were selected. Scroll the NAV (never the
     page) just enough to bring it into view. */
  renderCrumbs(active, p);
  for (const nav of [$('#nav'), $('#nav-pinned')]) {
    const cur = nav && (nav.querySelector('a.nav-subitem.active') || nav.querySelector('a.active'));
    if (!cur) continue;
    const r = cur.getBoundingClientRect(), n = nav.getBoundingClientRect();
    if (r.bottom > n.bottom || r.top < n.top) nav.scrollTop += r.top - n.top - n.height / 3;
  }
}

/* ── Breadcrumbs (0.37.0) ──────────────────────────────────────────────
   Group › Page › Sub-view, derived from NAV -- the same source the sidebar
   reads, so the two can never name a page differently. A detail view (a
   path with an id) adds the record's own title as the last crumb once the
   page has rendered it. */
function renderCrumbs(name, params, leaf) {
  const el = $('#crumbs');
  if (!el) return;
  let g = null, it = null;
  for (const grp of NAV) {
    const f = grp.items.find(i => i.path === name);
    if (f) { g = grp; it = f; break; }
  }
  const crumbs = [];
  if (g) crumbs.push({ text: g.group, href: g.pin ? '#/' + g.key : '' });
  const kids = (it && it.children) || [];
  const siblingKeys = [...new Set(kids.flatMap(c => Object.keys(c.q || {})))];
  const kid = kids.find(c => c.q && navChildActive(c, name, params || new URLSearchParams(), siblingKeys));
  // A flat item is not a page of its own in the menu: its section is.
  const sec = it && it.flat && kid ? navSections(it).find(s => s.kids.includes(kid)) : null;
  if (sec) crumbs.push({ text: sec.sec, href: navChildHref(sec.kids[0]) });
  else if (it) crumbs.push({ text: it.label, href: '#/' + it.path });
  if (kid) crumbs.push({ text: kid.label, href: navChildHref(kid) });
  if (leaf) crumbs.push({ text: leaf });
  if (!crumbs.length) crumbs.push({ text: titleCase(name) });
  el.innerHTML = crumbs.map((c, i) => {
    const last = i === crumbs.length - 1;
    return last ? `<span aria-current="page">${esc(c.text)}</span>`
      : c.href ? `<a href="${esc(c.href)}">${esc(c.text)}</a>` : `<span>${esc(c.text)}</span>`;
  }).join('<span class="sep" aria-hidden="true">/</span>');
}

/* Runs after every view has rendered. Three things every page gets without
   any of the ~60 templates having to opt in: the tab title, the detail
   crumb, and a long page description folded to two lines behind "More". */
/* Tabs (the `.tabs` bars of dashboards, policies, admin ...) are buttons that
   change the route. Give them the tab pattern after every render instead of in
   each of the ~12 templates: tablist / tab / aria-selected, and a roving
   tabindex so Tab visits the bar once and the arrow keys move along it (Home
   and End jump). Enter and Space are the buttons' own activation. Link tab
   bars (`.tabs-inline`, Configure) are navigation, not tabs, and are left alone. */
function enhanceTabs(root) {
  $$('.tabs:not(.tabs-inline)', root).forEach(bar => {
    const tabs = [...bar.querySelectorAll(':scope > button')];
    if (!tabs.length || bar.getAttribute('role') === 'tablist') return;
    bar.setAttribute('role', 'tablist');
    const current = tabs.find(b => b.classList.contains('active')) || tabs[0];
    tabs.forEach(b => {
      b.setAttribute('role', 'tab');
      b.setAttribute('aria-selected', String(b === current));
      b.tabIndex = b === current ? 0 : -1;
    });
  });
}
document.addEventListener('keydown', e => {
  const tab = e.target.closest && e.target.closest('.tabs > button[role="tab"]');
  if (!tab || !['ArrowRight', 'ArrowLeft', 'Home', 'End'].includes(e.key)) return;
  const tabs = [...tab.parentElement.querySelectorAll(':scope > button[role="tab"]')];
  let i = tabs.indexOf(tab);
  i = e.key === 'Home' ? 0 : e.key === 'End' ? tabs.length - 1
    : (i + (e.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
  e.preventDefault();
  tabs.forEach(b => { b.tabIndex = b === tabs[i] ? 0 : -1; });
  tabs[i].focus();
});

/* A list row that opens a record is a focusable row: Enter or Space opens it,
   exactly as a click does (TD-13). Only when the row itself has focus, so a
   link, button or checkbox inside the row keeps its own keys. */
document.addEventListener('keydown', e => {
  if ((e.key !== 'Enter' && e.key !== ' ') || !e.target.matches || !e.target.matches('tr.clickable')) return;
  e.preventDefault();
  e.target.click();
});

/* The skip link points at #view, but the address bar IS the router: following
   the fragment would navigate. Move focus instead. */
document.addEventListener('click', e => {
  if (!e.target.closest || !e.target.closest('#skip-link')) return;
  e.preventDefault();
  const v = $('#view');
  if (v) v.focus();
});

function enhancePage(view, name, params, parts) {
  enhanceTabs(view);
  const h1 = view.querySelector('.page-head h1');
  const title = h1 ? h1.textContent.replace(/\s+/g, ' ').trim() : '';
  document.title = (title ? title + ' · ' : '') + 'VEYRS Console';
  if (parts.length && title) renderCrumbs(name, params, title);
  const p = view.querySelector('.page-head > div > p');
  if (p && !p.dataset.fold && p.textContent.trim().length > 180) {
    p.dataset.fold = '1';
    p.id = p.id || 'page-blurb';
    p.classList.add('folded');
    const b = document.createElement('button');
    b.type = 'button'; b.className = 'more-btn'; b.textContent = 'More';
    b.setAttribute('aria-expanded', 'false'); b.setAttribute('aria-controls', p.id);
    b.setAttribute('aria-label', 'Full page description');
    b.onclick = () => {
      const open = !p.classList.toggle('folded');
      b.textContent = open ? 'Less' : 'More';
      b.setAttribute('aria-expanded', String(open));
    };
    /* A link inside the folded text stays in the tab order; landing on it
       unfolds the paragraph, so focus never sits on a clipped line. */
    p.addEventListener('focusin', () => { if (p.classList.contains('folded')) b.click(); });
    p.after(b);
    // Folded by length, but only kept folded if the clamp actually clips.
    requestAnimationFrame(() => { if (p.scrollHeight <= p.clientHeight + 2) { p.classList.remove('folded'); b.remove(); } });
  }
}

/* One tooltip for every chart. Marks keep their `title` until first hover
   (so a mark is never without its text), then it moves to `data-tip` so the
   browser's own slow, unstyled tooltip does not show on top of this one. */
(() => {
  const CHART = '.bars,.compo,.split,.hist,.flow,.ranked,.meter,.trend,.kpi-spark,.ring';
  let tip = null;
  const place = e => {
    const r = tip.getBoundingClientRect();
    let left = e.clientX + 14, top = e.clientY + 16;
    if (left + r.width > innerWidth - 8) left = e.clientX - r.width - 14;
    if (top + r.height > innerHeight - 8) top = e.clientY - r.height - 12;
    tip.style.left = left + 'px'; tip.style.top = top + 'px';
  };
  document.addEventListener('mouseover', e => {
    const t = e.target.closest && e.target.closest('[title],[data-tip]');
    if (!t || !t.closest(CHART)) { if (tip) tip.hidden = true; return; }
    if (!tip) {
      tip = document.createElement('div');
      tip.className = 'tip'; tip.setAttribute('role', 'tooltip');
      document.body.appendChild(tip);
    }
    if (t.hasAttribute('title')) { t.dataset.tip = t.getAttribute('title'); t.removeAttribute('title'); }
    tip.textContent = t.dataset.tip;
    tip.hidden = false;
    place(e);
  });
  document.addEventListener('mousemove', e => { if (tip && !tip.hidden) place(e); });
  document.addEventListener('keydown', e => { if (e.key === 'Escape' && tip) tip.hidden = true; });
  document.documentElement.addEventListener('mouseleave', () => { if (tip) tip.hidden = true; });
  document.addEventListener('scroll', () => { if (tip) tip.hidden = true; }, true);
})();

const routes = {};
function route(name, fn) { routes[name] = fn; }

/* ── Configure frame (0.39.0, owner request) ───────────────────────────
   Everything under Configure lives on its own page: a menu of its own on
   the left (pages, and the current page's sub-views), the page on the
   right. The sidebar carries a single Configure entry. Built from the NAV
   group, so the frame, the breadcrumbs and the routes cannot disagree.
   A page whose sub-views are all in this menu hides its own tab bar (and
   Administration its section switch): two menus for one choice is noise.
   test_console_configure_frame.py pins that every hidden tab is listed. */
const CONFIGURE_BLURB = {
  scanner: 'The scanning runner, its job queue and what it last found.',
  integrations: 'Scanner imports and connectors that bring findings in; ITSM connectors that mirror tickets out.',
  policies: 'Deadlines, escalation ladders, who owns new work and how risk is scored.',
  automation: 'Tickets opened automatically, workflows, and what each run did.',
  admin: 'Who can sign in, where assets come from, and how this installation runs.',
};
/* Administration's sections as the hub shows them: [icon, blurb]. */
const CONFIGURE_SECTION = {
  'Access': ['users', 'Who can sign in and what they may do: accounts, teams, roles, API keys, directory, RADIUS and single sign-on.'],
  'Data intake': ['sources', 'Where tickets and assets come from, the teams imported with them, and whether VEYRS may scan.'],
  'Platform': ['software', 'How this installation runs: secrets, organization, network access, certificates and updates.'],
};
const configureGroup = () => NAV.find(g => g.key === 'configure');
const CFG_RAIL_LS = 'veyrs.cfg.rail';
const CFG_RAIL_SVG = '<svg class="i" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3.5" y="4.5" width="17" height="15" rx="2"/><path d="M9.5 4.5v15"/></svg>';

function configureFrame(view, name, params) {
  const g = configureGroup();
  if (!g || (name !== g.key && !g.items.some(i => i.path === name))) return null;
  const items = g.items.filter(navShown);
  const cur = items.find(i => i.path === name);
  const link = (href, label, cls, on, ico) =>
    `<a href="${esc(href)}" class="${cls}${on ? ' active' : ''}" title="${esc(label)}"${on ? ' aria-current="page"' : ''}>`
    + (ico ? `<span class="ico">${icon(ico)}</span>` : '') + `<span class="cfg-label">${esc(label)}</span></a>`;
  /* One level only (0.42.0): every row is a page with an icon, grouped under
     small headings. Pages with tabs keep their tab bar in the body; a `flat`
     item (Administration) contributes its sections as groups of their own. */
  const head = t => `<span class="cfg-subhead" role="presentation">${esc(t)}</span>`;
  let opsHead = false;
  const pages = items.map(i => {
    if (i.flat) {
      const siblingKeys = [...new Set((i.children || []).flatMap(c => Object.keys(c.q || {})))];
      return navSections(i).map(s => head(s.sec) + s.kids.map(c =>
        link(navChildHref(c), c.label, 'cfg-page', navChildActive(c, name, params, siblingKeys), c.ico || i.ico)).join('')).join('');
    }
    const h = opsHead ? '' : head('Operations');
    opsHead = true;
    return h + link('#/' + i.path, i.label, 'cfg-page', i.path === name, i.ico);
  }).join('');
  const curLabel = !cur ? 'Overview' : (cur.flat && adminTabLabel(params.get('tab'))) || cur.label;
  /* The menu folds to an icon rail (0.39.1), remembered per browser: wide
     tables get the full width back, and the page's own tab bar returns so
     the sub-views stay one click away (see the .cfg.rail rules). */
  let rail = false;
  try { rail = localStorage.getItem(CFG_RAIL_LS) === '1'; } catch { /* private mode */ }
  view.innerHTML = `<div class="cfg${rail ? ' rail' : ''}">
    <aside class="cfg-nav" id="cfg-nav">
      <button type="button" class="cfg-menu-btn" aria-expanded="false" aria-controls="cfg-links">
        <span class="ico">${icon(g.ico)}</span><span class="cfg-label">${esc(curLabel)}</span><span class="nav-caret" data-open="false"></span></button>
      <nav class="cfg-links" id="cfg-links" aria-label="${esc(g.group)} pages">
        <div class="cfg-head"><span class="cfg-title">${esc(g.group)}</span>
          <button type="button" class="cfg-rail-btn" title="${rail ? 'Expand' : 'Collapse'} the Configure menu" aria-label="${rail ? 'Expand' : 'Collapse'} the Configure menu">${CFG_RAIL_SVG}</button></div>
        ${link('#/' + g.key, 'Overview', 'cfg-page', name === g.key, 'dashboard')}
        <div class="cfg-sep" role="presentation"></div>
        ${pages}
      </nav>
    </aside>
    <div class="cfg-body"${cur && cur.flat ? ' data-subnav' : ''}><div class="loading">Loading…</div></div>
  </div>`;
  /* The menu scrolls on its own when it is taller than the window: bring the
     current row into view without scrolling the page (scrollIntoView would). */
  const here = view.querySelector('.cfg-nav a.active');
  const scroller = view.querySelector('.cfg-nav');
  if (here && scroller && scroller.scrollHeight > scroller.clientHeight) {
    const top = here.getBoundingClientRect().top - scroller.getBoundingClientRect().top + scroller.scrollTop;
    if (top + here.offsetHeight > scroller.clientHeight) scroller.scrollTop = top - scroller.clientHeight / 2;
  }
  const btn = view.querySelector('.cfg-menu-btn');
  btn.onclick = () => {
    const open = $('#cfg-nav').classList.toggle('open');
    btn.setAttribute('aria-expanded', String(open));
    btn.querySelector('.nav-caret').dataset.open = String(open);
  };
  const railBtn = view.querySelector('.cfg-rail-btn');
  railBtn.onclick = () => {
    const on = view.querySelector('.cfg').classList.toggle('rail');
    // The accessible name states the action the button will perform NOW. It is
    // not also a toggle (aria-pressed): a changing name plus a pressed state is
    // announced twice and contradicts itself ("Expand ... pressed").
    railBtn.title = (on ? 'Expand' : 'Collapse') + ' the Configure menu';
    railBtn.setAttribute('aria-label', railBtn.title);
    try { localStorage.setItem(CFG_RAIL_LS, on ? '1' : '0'); } catch { /* private mode */ }
  };
  return view.querySelector('.cfg-body');
}

route('configure', async (view) => {
  const items = configureGroup().items.filter(navShown);
  view.innerHTML = `
    <div class="page-head"><div><h1>Configure</h1>
      <p>Set up once, read often, change rarely: where findings come from, the deadlines they are measured against, what happens on its own, and who can sign in.</p></div></div>
    <div class="cfg-cards">${items.map(i => {
      const card = (href, ico, label, blurb, meta) => `<a class="card cfg-card" href="${esc(href)}">
        <span class="cfg-card-ico">${icon(ico)}</span>
        <span class="cfg-card-text"><strong>${esc(label)}</strong>
          <span class="small muted">${esc(blurb)}</span>
          ${meta ? `<span class="cfg-card-meta">${esc(meta)}</span>` : ''}</span></a>`;
      // The hub mirrors the menu: a flat item is one card per section.
      if (i.flat) return navSections(i).map(s => card(navChildHref(s.kids[0]), CONFIGURE_SECTION[s.sec][0], s.sec,
        CONFIGURE_SECTION[s.sec][1], s.kids.map(c => c.label).join(' · '))).join('');
      const kids = i.children || [];
      return card('#/' + i.path, i.ico, i.label, CONFIGURE_BLURB[i.path] || '', kids.length ? `${kids.length} sections` : '');
    }).join('')}</div>`;
});

/* Old hashes that moved in the v0.21.0 reorganisation. A bookmark or a link in
   somebody's runbook must not land on "No view is registered": a 404 for a page
   that still exists under a new name teaches people the console is unreliable.
   `replace` rather than assignment so the dead hash does not sit in the back
   button waiting to bounce them again. */
const MOVED = {
  workflows: '#/automation?tab=workflows',
};
Object.entries(MOVED).forEach(([from, to]) => route(from, async () => {
  location.replace(location.pathname + location.search + to);
}));

async function render() {
  const raw = (location.hash || '#/triage').slice(2);
  const [path, query] = raw.split('?');
  const parts = path.split('/').filter(Boolean);
  const name = parts[0] || 'dashboard';
  const params = new URLSearchParams(query || '');
  // Never paint a view behind the login screen: an unauthenticated hash change
  // would otherwise fire pointless API calls and leave a hidden, stale shell.
  if (!store.at || $('#shell').hidden) return;
  navCtx = { name, params };
  renderNav(name, params);
  $('#sidebar').classList.remove('open');
  const view = $('#view');
  view.innerHTML = '<div class="loading">Loading…</div>';
  const fn = routes[name];
  if (!fn) { view.innerHTML = `<div class="empty"><strong>Not found</strong>No view is registered for “${esc(name)}”.</div>`; return; }
  view.setAttribute('aria-busy', 'true');
  // A Configure page draws into the frame's body; the frame (its own menu)
  // stays on screen even when the page itself fails or is refused.
  const target = configureFrame(view, name, params) || view;
  try {
    await fn(target, parts.slice(1), params);
    enhancePage(view, name, params, parts.slice(1));
  } catch (e) {
    if (e.status === 403) {
      target.innerHTML = `<div class="card"><h2>Access denied</h2><p class="muted">Your role does not carry the permission this view requires. VEYRS enforces authorization server-side; the console only reflects it.</p><p class="small mono">${esc(e.detail || '')}</p></div>`;
    } else {
      target.innerHTML = `<div class="card"><h2>Could not load this view</h2><p class="muted">${esc(e.detail || e.message)}</p>
        <p><button class="btn" data-act="reload">Retry</button></p></div>`;
    }
    document.title = 'VEYRS Console';
  } finally {
    view.removeAttribute('aria-busy');
  }
}

/* ══ Auth flow ═════════════════════════════════════════════════════════ */

function logout() {
  store.clear();
  $('#shell').hidden = true;
  $('#login').hidden = false;
}

async function boot() {
  // 0.38.0: the default is the Midnight (dark) theme; an operator's own
  // choice is kept. The attribute must always be present: both themes are
  // scoped to [data-theme], neither is an unscoped base.
  applyTheme(localStorage.getItem('veyrs.theme') || 'dark');
  // Only the organization this browser last signed in to. A hard-coded slug
  // here pre-filled the author's own tenant on every other installation.
  $('#l-org').value = store.org || '';
  // Back from the identity provider: finish that sign-in before anything else.
  if (location.hash.startsWith('#/sso') && await ssoLanding()) return;
  if (!store.at) { $('#login').hidden = false; ssoButton(); return; }
  if (localStorage.getItem('veyrs.enroll') === '1') { enrolmentScreen(); return; }
  try {
    const me = await get('/auth/me');
    await enterApp(me);
  } catch { logout(); }
}

async function enterApp(me) {
  $('#login').hidden = true;
  $('#shell').hidden = false;
  $('#user-name').textContent = me.full_name || me.email;
  const av = $('#user-avatar');
  if (av) {
    const words = String(me.full_name || me.email || '?').replace(/@.*/, '').split(/[\s._-]+/).filter(Boolean);
    av.textContent = ((words[0] || '?')[0] + (words.length > 1 ? words[words.length - 1][0] : '')).toUpperCase();
  }
  if (me.permissions) localStorage.setItem('veyrs.perms', JSON.stringify(me.permissions));
  Object.assign(scope, me.scope || { restricted: false, team_ids: [] });
  Object.assign(prefs, { dashboard_team_id: null }, me.preferences || {});
  // `!== false`, not a truthiness test: an API that predates the field sends
  // nothing, and nothing must mean "leave the scanner where it is".
  activeScanning = me.active_scanning !== false;
  ticketingMode = me.ticketing_mode === 'external' ? 'external' : 'internal';
  ticketingUsable = me.ticketing_usable !== false;
  riskRegisterOn = me.risk_register_enabled !== false;
  teamCache.list = null;                       // a new identity may read a different set
  if (scope.restricted) await teams();
  try {
    const org = await get('/organization');
    $('#org-name').textContent = org.name || org.slug || '';
  } catch { $('#org-name').textContent = store.org; }
  refreshNotifications();
  setInterval(refreshNotifications, 60000);
  // A dashboard answers "how bad is it"; it is not a place to work. The
  // queue is. Anyone who wants the numbers is one click away in the nav.
  if (!location.hash) location.hash = '#/triage';
  await render();
}

async function refreshNotifications() {
  try {
    const r = await get('/notifications?size=1');
    const n = r.unread ?? 0;
    const b = $('#notif-badge');
    b.hidden = !n; b.textContent = n > 99 ? '99+' : n;
  } catch { /* notifications are not load-bearing */ }
}

function applyTheme(t) {
  const el = document.documentElement;
  if (t) el.setAttribute('data-theme', t); else el.removeAttribute('data-theme');
}

/* ══ Views ═════════════════════════════════════════════════════════════ */

/* ── Dashboards ─────────────────────────────────────────────────────── */
route('dashboard', async (view, _p, params) => {
  const tab = params.get('tab') || 'executive';
  // A team dashboard is the estate dashboard with a smaller set -- same tabs,
  // same cards, one query parameter -- not a screen of its own. Two screens
  // drift, and then the two numbers stop being comparable, which is the whole
  // reason to look at a team in the first place.
  const rows = await teams();
  // Three sources for one answer, in this order:
  //   1. `?team=` in the URL -- a link somebody followed. It wins for this
  //      render and is NOT written back: a colleague's screenshot link must
  //      not silently repoint every dashboard session that follows.
  //   2. the profile preference, for a bare `#/dashboard`.
  //   3. the estate.
  // `team=all` is the explicit estate token rather than an absent parameter.
  // Without it, choosing "Whole estate" would produce a URL with no `team=`,
  // which rule 2 then reads as "use the preference" -- and the picker would
  // spring back to the team the operator just left.
  const asked = params.get('team') || prefs.dashboard_team_id || '';
  const teamId = rows.some(t => t.id === asked) ? asked : '';
  /* Time range (0.37.0): the API has always taken `days` (7-730) on the
     executive and SLA dashboards; the console never offered it, so every
     trend was the same fixed 90 days. Technical has no window: it is a
     snapshot of what is open now, and the control is hidden there rather
     than shown doing nothing. */
  const RANGES = [['30', '30 d'], ['90', '90 d'], ['180', '6 mo'], ['365', '1 yr']];
  const days = RANGES.some(r => r[0] === params.get('days')) ? params.get('days') : '90';
  const href = (t, team, d) => '#/dashboard?tab=' + t + '&team=' + encodeURIComponent(team || 'all') + '&days=' + (d || days);
  const qStr = new URLSearchParams(Object.assign(teamId ? { team_id: teamId } : {}, tab === 'technical' ? {} : { days })).toString();
  const q = qStr ? '?' + qStr : '';
  const rangeCtl = tab === 'technical' ? '' : `<div class="seg seg-sm m-0" role="group" aria-label="Time range">${RANGES.map(([v, l]) =>
    `<button type="button" data-days="${v}" class="${v === days ? 'active' : ''}" aria-pressed="${v === days}">${l}</button>`).join('')}</div>`;
  const picker = rows.length ? `<label class="filter-inline">Scope
      <select id="dash-team" title="Remembered in your profile: this scope comes back the next time you open Dashboards, on any browser.">
        <option value=""${teamId ? '' : ' selected'}>Whole estate</option>
        ${rows.map(t => `<option value="${esc(t.id)}"${t.id === teamId ? ' selected' : ''}>${esc(t.name || t.slug)}</option>`).join('')}
      </select></label>` : '';
  view.innerHTML = `
    <div class="page-head"><div><h1>Dashboards</h1>
      <p>Risk posture across the whole chain: assets, exploitation pressure, SLA health and remediation throughput.</p></div>
      <div class="page-actions">${rangeCtl}${picker}<a class="btn" href="#/reports">Export a report</a></div></div>
    <div class="tabs">
      <button data-t="executive" class="${tab === 'executive' ? 'active' : ''}">Executive</button>
      <button data-t="technical" class="${tab === 'technical' ? 'active' : ''}">Technical</button>
      <button data-t="sla" class="${tab === 'sla' ? 'active' : ''}">SLA</button>
    </div><div id="dash-body"><div class="loading">Loading…</div></div>`;
  view.querySelector('.tabs').onclick = e => {
    if (e.target.dataset.t) location.hash = href(e.target.dataset.t, teamId);
  };
  $$('[data-days]', view).forEach(b => { b.onclick = () => { location.hash = href(tab, teamId, b.dataset.days); }; });
  const sel = $('#dash-team', view);
  if (sel) sel.onchange = async () => {
    const chosen = sel.value || null;
    // Applied first, persisted second. A profile write that fails must not
    // stop the operator from looking at the team they just picked, so the
    // failure is reported as what it is -- the view changed, the memory did
    // not -- rather than as a broken filter.
    prefs.dashboard_team_id = chosen;
    location.hash = href(tab, chosen);
    try { await patch('/auth/me/preferences', { dashboard_team_id: chosen }); }
    catch (e) { err('Scope applied, but not saved to your profile: ' + (e.detail || 'unknown error')); }
  };
  const body = $('#dash-body');
  // The banner is rendered from the payload's own `scope` block, not from the
  // cached token claim: the number and the caveat then come from the same
  // response and cannot disagree after a role change mid-session.
  //
  // Two narrowings, two sentences. "Filtered to a team" is a choice the reader
  // just made and can undo; "restricted" is a limit they cannot. Printing the
  // second over the first would tell an administrator their access is capped.
  const withScope = (payload, html) => {
    const s = (payload && payload.scope) || null;
    if (!s) return html;
    let banner = '';
    if (s.team_filter) {
      banner = `<div class="scope-banner" role="status"><strong>${esc(s.team_filter.team_name || 'Team')}</strong>
        <span>Every figure below counts only what this team owns — a finding's explicit
        assignment first, the owning team of its asset otherwise. Assets with no owning team
        are excluded${s.restricted ? ', and this narrows your own team scope further' : ''}.
        Pick <em>Whole estate</em> to compare against the rest. This choice is remembered
        in your profile, on every browser you sign in from.</span></div>`;
    } else if (s.restricted) {
      banner = `<div class="scope-banner" role="status"><strong>Team view</strong><span>These figures cover
        ${(s.team_ids || []).map(id => esc(teamName(id) || id.slice(0, 8))).join(', ') || 'your teams'}
        only${s.includes_unowned ? ', plus assets with no owning team' : '. Assets with no owning team are excluded'}.
        A zero here means zero <em>in your scope</em>.</span></div>`;
    }
    return banner + html;
  };
  if (tab === 'executive') {
    const d = await get('/dashboard/executive' + q);
    body.innerHTML = withScope(d, execDash(d));
  } else if (tab === 'technical') {
    const d = await get('/dashboard/technical' + q);
    body.innerHTML = withScope(d, techDash(d));
  }
  else {
    // `/policies/sla/summary` takes the same `?team_id=` as the dashboards since
    // v0.17.1, so it is shown under a filter instead of hidden. Dropping it was
    // a workaround for an endpoint that answered with the estate no matter who
    // asked -- an estate total beside filtered counters is the misread this
    // screen exists to avoid, but hiding the widget only hid the symptom.
    const [d, sum] = await Promise.all([
      get('/dashboard/sla' + q),
      get('/policies/sla/summary' + q).catch(() => ({})),
    ]);
    body.innerHTML = withScope(d, slaDash(d, sum));
  }
});

function execDash(d) {
  const t = d.totals || {}, x = d.exploitation || {}, s = d.sla || {}, m = d.mttr || {};
  const sev = d.by_severity || {};
  /* Window deltas come from the flow the payload already carries: arrivals
     minus departures over the selected range. It is a change in the open
     backlog, not a comparison against a second query -- the tile says so. */
  const ft = (d.finding_trend || []).filter(Boolean);
  const netFlow = ft.length ? ft.reduce((a, p) => a + (Number(p.detected) || 0) - (Number(p.remediated) || 0), 0) : null;
  const riskVals = (d.risk_trend || []).map(p => (p.average_risk === null || p.average_risk === undefined) ? null : Number(p.average_risk));
  const riskKnown = riskVals.filter(v => v !== null);
  const riskDelta = riskKnown.length > 1 ? riskKnown[riskKnown.length - 1] - riskKnown[0] : null;
  const flowSeries = ft.map(p => (Number(p.detected) || 0) - (Number(p.remediated) || 0));
  const mttr = m.hours === null || m.hours === undefined ? '—' : Number(m.hours).toFixed(1) + '<small>h</small>';
  return `
  <div class="kpis">
    ${kpi({ label: 'Open findings', value: fmtNum(t.open_findings),
      hint: `${fmtNum(t.assets_with_open_findings)} of ${fmtNum(t.assets)} assets affected`,
      delta: delta(netFlow, { title: `Detected minus remediated over the last ${d.window_days} days` }),
      spark: kpiSpark(flowSeries, 'Net change per bucket') })}
    ${kpi({ label: 'Critical', tone: tone('crit', sev.critical), value: fmtNum(sev.critical),
      hint: `${fmtNum((d.by_risk_level || {}).critical)} at critical VEYRS risk` })}
    ${kpi({ label: 'Known exploited (KEV)', tone: tone('warn', x.kev_open), value: fmtNum(x.kev_open),
      hint: `${fmtNum(x.kev_and_internet_facing)} also internet-facing` })}
    ${kpi({ label: 'Average VEYRS risk', value: fmtScore(d.average_risk_score), hint: 'Composite 0–100, not CVSS',
      delta: delta(riskDelta, { fmt: v => v.toFixed(1), title: `First to last scored bucket in the last ${d.window_days} days` }),
      spark: kpiSpark(riskVals, 'Average risk per bucket') })}
    ${kpi({ label: 'SLA breached (open)', tone: s.breached_open ? 'crit' : 'ok', value: fmtNum(s.breached_open), hint: `${fmtNum(s.escalated_open)} escalated` })}
  </div>
  <div class="dash">
    <section class="card span-8"><div class="row-between"><h2>Risk trend</h2>${delta(riskDelta, { fmt: v => v.toFixed(1) })}</div>${trendChart(d.risk_trend || [])}</section>
    <section class="card span-4"><h2>Backlog composition</h2>${donut(d.by_severity)}</section>
    <section class="card span-6"><h2>Detected vs remediated</h2>${flowColumns(d.finding_trend || [])}</section>
    <section class="card span-6"><h2>Severity vs VEYRS risk</h2>
      ${splitBars(d.by_severity, d.by_risk_level, { leftLabel: 'Scanner severity', rightLabel: 'VEYRS risk level' })}
      <p class="chart-note">Risk level combines CVSS, EPSS, KEV, exposure, asset criticality and business impact. It deliberately disagrees with severity — the signed delta beside each level <em>is</em> that disagreement, and it is the reason this platform exists.</p></section>
    <section class="card span-4"><h2>Exposure and operations</h2>${opsList([
      { label: 'Internet-facing open', value: fmtNum(x.internet_facing_open), tone: tone('warn', x.internet_facing_open) },
      { label: 'High EPSS open', hint: 'Likely exploited within 30 days', value: fmtNum(x.high_epss_open), tone: tone('warn', x.high_epss_open) },
      { label: 'Escalated', value: fmtNum(s.escalated_open), tone: tone('crit', s.escalated_open) },
      { label: 'Asset coverage', hint: 'Assets carrying open findings', value: fmtPct(t.asset_coverage_ratio) },
      { label: 'MTTR', hint: m.hours === null || m.hours === undefined ? 'No remediated findings yet' : (m.reliable ? `n=${fmtNum(m.sample)}` : `n=${fmtNum(m.sample)} — too few to be reliable`), value: mttr },
    ])}</section>
    <section class="card span-4"><h2>Assets carrying the most risk</h2>
      ${rankedBars(d.top_assets, {
        value: r => r.max_risk_score,
        colour: r => sevColour(riskBand(r.max_risk_score)),
        label: r => `<a href="#/assets/${esc(r.asset_id)}">${esc(r.name || 'Unnamed asset')}</a>
          <span class="ranked-sub">${esc(titleCase(r.criticality || '—'))} · ${esc(titleCase(r.exposure || '—'))} · ${fmtNum(r.open_findings)} open${r.kev_findings ? ` · <strong class="kev-note">${fmtNum(r.kev_findings)} KEV</strong>` : ''}</span>`,
        display: r => fmtScore(r.max_risk_score),
        empty: 'No asset carries an open finding yet.',
      })}
      <p class="chart-note">Ranked by <em>peak</em> risk, not by count: forty informational findings on a lab box must not outrank one known-exploited flaw on the payment gateway.</p></section>
    <section class="card span-4"><h2>Open risk by environment</h2>
      ${rankedBars(d.by_environment, {
        value: r => r.open_findings,
        label: r => `${esc(titleCase(r.environment || 'unassigned'))}
          <span class="ranked-sub">avg risk ${fmtScore(r.average_risk_score)}${r.kev_findings ? ` · <strong class="kev-note">${fmtNum(r.kev_findings)} KEV</strong>` : ''}</span>`,
        empty: 'No finding is attached to an asset with an environment.',
      })}
      <h2 class="sub-h">Products carrying the most risk</h2>
      ${rankedBars(d.top_products, {
        limit: 6,
        value: r => r.open_findings,
        label: r => `${esc(r.vendor || '—')} <strong>${esc(r.product || '—')}</strong>
          <span class="ranked-sub">peak risk ${fmtScore(r.max_risk_score)}${r.kev_findings ? ` · <strong class="kev-note">${fmtNum(r.kev_findings)} KEV</strong>` : ''}</span>`,
        empty: 'No finding is linked to a resolved product — load software inventory to populate this.',
      })}</section>
    ${(d.top_teams || []).length ? `<section class="card span-12"><h2>Open risk by team</h2>
      ${rankedBars(d.top_teams, {
        value: r => r.open_findings,
        colour: r => r.breach_ratio > 0 ? 'var(--veyrs-critical)' : 'var(--primary)',
        label: r => `${esc(r.name || '—')}<span class="ranked-sub">avg risk ${fmtScore(r.average_risk_score)} · ${fmtNum(r.sla_breached)} breached (${fmtPct(r.breach_ratio, 0)})</span>`,
      })}</section>` : ''}
  </div>
  <p class="page-foot">Generated ${fmtDate(d.generated_at)} · ${d.window_days}-day window.</p>`;
}

function techDash(d) {
  const e = d.exploitability || {};
  return `
  <div class="kpis">
    ${kpi({ label: 'Scored sample', value: fmtNum(d.sample), hint: 'Open findings with a score' })}
    ${kpi({ label: 'Known exploited', tone: tone('crit', e.known_exploited), value: fmtNum(e.known_exploited), hint: 'On the CISA KEV list' })}
    ${kpi({ label: 'EPSS &gt; 10%', tone: tone('warn', e.epss_over_10_percent), value: fmtNum(e.epss_over_10_percent), hint: 'Likely exploited within 30 days' })}
    ${kpi({ label: 'Theoretical only', value: fmtNum(e.theoretical_only), hint: 'No exploit signal on record' })}
  </div>
  <div class="dash">
    <section class="card span-6"><h2>CVSS distribution</h2>${histogram(d.cvss_distribution, 'CVSS')}
      <p class="chart-note">Base severity as the scanner scored it. Shape, not headline: a wall on the right is a patching backlog, a wall on the left is scanner noise.</p></section>
    <section class="card span-6"><h2>EPSS distribution</h2>${histogram(d.epss_distribution, 'EPSS')}
      <p class="chart-note">Probability of exploitation in the next 30 days. Most real estates are heavily left-skewed — the right-hand bins are the queue that matters.</p></section>
    <section class="card span-7 flush"><h2>Top CWE</h2>${(d.top_cwe || []).length
      ? table([
          { label: 'CWE', cell: r => `<a href="#/intel/cwe/${esc(r.cwe || r.cwe_id || r.id)}" class="mono">${esc(r.cwe || r.cwe_id || r.id)}</a>` },
          { label: 'Name', cell: r => esc(r.name || '—') },
          { label: 'Findings', num: true, cell: r => fmtNum(r.open_findings ?? r.count) },
        ], d.top_cwe)
      : '<p class="muted small">No CWE data — no findings carry a classified weakness yet.</p>'}</section>
    <section class="card span-5"><h2>Lifecycle state</h2>${Object.keys(d.state_breakdown || {}).length
      ? bars(d.state_breakdown) : '<p class="muted small">No findings recorded.</p>'}</section>
    <section class="card span-12 flush"><h2>By scanner</h2>${(d.scanner_breakdown || []).length
      ? table([
          { label: 'Scanner', cell: r => esc(r.scanner || r.source || '—') },
          { label: 'Findings', num: true, cell: r => fmtNum(r.findings ?? r.count) },
          { label: 'Last seen', cell: r => fmtDate(r.last_seen_at) },
        ], d.scanner_breakdown)
      : '<p class="muted small">Nothing imported yet. Load a Nessus, Qualys or Greenbone export from <a href="#/integrations">Integrations</a>.</p>'}</section>
  </div>`;
}

function slaDash(d, sum = {}) {
  const compliance = d.compliance_ratio == null
    ? `<span class="value">—</span><span class="hint">No finding carries an SLA deadline yet</span>`
    : `<span class="value">${fmtPct(d.compliance_ratio)}</span><span class="hint">${d.reliable ? `n=${fmtNum(d.sample)}` : `n=${fmtNum(d.sample)} — too few to be reliable`}</span>`;
  return `
  <div class="kpis">
    ${kpi({ label: 'Under an SLA', value: fmtNum(d.with_sla), hint: `${d.window_days}-day window` })}
    ${kpi({ label: 'Due within 3 days', tone: d.due_within_3_days ? 'warn' : '', value: fmtNum(d.due_within_3_days) })}
    ${kpi({ label: 'Breached &amp; still open', tone: d.open_and_breached ? 'crit' : 'ok', value: fmtNum(d.open_and_breached), hint: `${fmtNum(d.breached)} breached in total` })}
    ${kpi({ label: 'Escalated', tone: sum.escalated ? 'crit' : '', value: fmtNum(sum.escalated), hint: `${fmtNum(sum.due_24h)} due in the next 24 h` })}
  </div>
  <div class="dash">
    <section class="card span-4"><h2>SLA compliance</h2>
      <div class="stat sla-ring">${d.compliance_ratio == null ? '' : ring(d.compliance_ratio, 0.9)}
        <div>${compliance}${meter(d.compliance_ratio)}</div></div>
      <p class="chart-note">Deadlines come from the SLA policies in <a href="#/policies">SLA &amp; Policies</a>. A finding matched by no policy has no clock — and nothing to breach. Target 90 %; amber below it, red below 70 %.</p></section>
    <section class="card span-8 flush"><h2>By severity</h2>
      ${(d.by_severity || []).length
        ? table([
            { label: 'Severity', cell: r => sevPill(r.severity) },
            { label: 'Under SLA', num: true, cell: r => fmtNum(r.with_sla ?? r.total) },
            { label: 'Breached', num: true, cell: r => fmtNum(r.breached) },
            { label: 'Compliance', num: true, cell: r => r.compliance_ratio == null ? '—' : `<span class="cell-bar"><span style="width:${(Number(r.compliance_ratio) * 100).toFixed(1)}%"></span></span>${fmtPct(r.compliance_ratio)}` },
          ], sevSorted(d.by_severity))
        : '<p class="muted small">No findings under an SLA yet — nothing to break down.</p>'}</section>
  </div>
  <p class="page-foot">Generated ${fmtDate(d.generated_at)} · ${d.window_days}-day window.</p>`;
}

/* ── Generic list view factory ──────────────────────────────────────── */
function listView({ title, blurb, endpoint, cols, filters = [], detail, actions = '',
                   emptyHint, bulk = null, onBulk = null, showScope = false, mapQuery = null,
                   /* `savedEntity` opts this list into saved views: the chips row and
                      the Save button. `setup` is what to show when the list is empty
                      AND unfiltered -- see notConfigured(). */
                   savedEntity = null, setup = [] }) {
  /* `blurb` and `setup` accept a function. Both can name the VEYRS scanner,
     and whether that page exists is tenant state read at login -- long after
     this object literal was evaluated at module load. A plain string would be
     frozen with the scanner in it for the life of the tab. */
  const lazy = v => (typeof v === 'function' ? v() : v);
  return async (view, parts, params) => {
    if (parts.length && detail) return detail(view, parts, params);
    const limit = Number(params.get('limit') || 50);
    const offset = Number(params.get('offset') || 0);
    const q = {};
    filters.forEach(f => { const v = params.get(f.name); if (v) q[f.name] = v; });
    const query = mapQuery ? mapQuery(q) : q;
    // The API speaks two pagination dialects: most list routers take page/size,
    // a few (users, audit, agents, teams, imports) take limit/offset. Unknown
    // query params are ignored server-side, so sending BOTH is correct for
    // either dialect — sending only limit/offset silently pinned every
    // page/size list to its first page.
    const data = pageOf(await get(endpoint + qs(Object.assign(
      { limit, offset, page: Math.floor(offset / limit) + 1, size: limit }, query))));
    const base = '#/' + location.hash.slice(2).split('?')[0].split('/')[0];
    const mk = (o) => base + qs(Object.assign({}, Object.fromEntries(params), o));
    // Options may be a function so a filter can be built from live data (the
    // team list). Resolved here, once, rather than baked in at registration.
    const resolved = await Promise.all(filters.map(async f =>
      Object.assign({}, f, { options: typeof f.options === 'function' ? await f.options() : f.options })));
    if (showScope) await teams();      // names for the banner
    if (savedEntity) await loadViews();
    const filtered = Object.keys(q).length > 0;

    view.innerHTML = `
      <div class="page-head"><div><h1>${esc(title)}</h1><p>${lazy(blurb)}</p></div>
        <div class="page-actions">${savedEntity
          ? `<button class="btn btn-sm" data-save-view>Save this view</button>` : ''}${actions}</div></div>
      ${showScope ? scopeBanner() : ''}
      ${resolved.length ? `<form class="filters" id="filters">
        ${resolved.map(f => f.options
          ? `<select name="${f.name}"><option value="">${esc(f.label)}: any</option>
              ${f.options.map(o => `<option value="${esc(o.value ?? o)}" ${params.get(f.name) === String(o.value ?? o) ? 'selected' : ''}>${esc(o.label ?? titleCase(o))}</option>`).join('')}</select>`
          : `<input name="${f.name}" placeholder="${esc(f.label)}" value="${esc(params.get(f.name) || '')}">`).join('')}
        <button class="btn btn-sm" type="submit">Apply</button>
        <a class="btn btn-sm" href="${base}">Clear</a></form>` : ''}
      ${savedEntity ? viewChips(savedEntity, q) : ''}
      ${data.total === 0 && !filtered
        ? notConfigured({ title: `Nothing in ${title.toLowerCase()} yet`, hint: emptyHint || '', steps: lazy(setup) })
        : table(cols, data.items, {
            emptyTitle: filtered ? 'No records match these filters' : 'No records',
            emptyHint: filtered ? 'The list itself is not empty — clear the filters to see it.' : (emptyHint || ''),
            onRow: !!detail, selectable: !!bulk })}
      ${bulk ? `<div class="bulk-bar" id="bulk-bar" hidden>
        <span id="bulk-count" class="mono"></span>
        ${bulk.map(b => `<button class="btn btn-sm ${b.cls || ''}" data-bulk="${esc(b.act)}">${esc(b.label)}</button>`).join('')}
      </div>` : ''}
      <div class="pager">
        <span>${data.total ? `${data.offset + 1}–${Math.min(data.offset + data.limit, data.total)} of ${fmtNum(data.total)}` : '0 records'}</span>
        <a class="btn btn-sm ${offset <= 0 ? 'disabled' : ''}" href="${mk({ offset: Math.max(0, offset - limit) })}">Previous</a>
        <a class="btn btn-sm" href="${mk({ offset: offset + limit })}">Next</a>
      </div>`;

    const f = $('#filters', view);
    if (f) f.onsubmit = e => {
      e.preventDefault();
      const o = {};
      $$('[name]', f).forEach(i => { if (i.value) o[i.name] = i.value; });
      location.hash = base + qs(Object.assign(o, { limit }));
    };
    if (detail) $$('tbody tr.clickable', view).forEach(tr => {
      tr.onclick = () => { if (tr.dataset.id) location.hash = base + '/' + tr.dataset.id; };
    });
    if (bulk && onBulk) wireSelection(view, (act, ids) => onBulk(act, ids, render));
    const saveBtn = $('[data-save-view]', view);
    if (saveBtn) saveBtn.onclick = () => saveViewDialog(savedEntity, q);
    const chipRow = $('.view-chips', view);
    if (chipRow) chipRow.onclick = e => {
      const b = e.target.closest('[data-view]');
      if (!b) return;
      const v = (savedViews.items || []).find(x => x.id === b.dataset.view);
      // Replace the filters wholesale rather than merging: a view is a
      // complete question, and merging it into whatever was already in the
      // address bar produces a query nobody saved and nobody can name.
      if (v) location.hash = base + qs(Object.assign({ limit }, v.filters));
    };
  };
}

/* ── Ownership dialogs ──────────────────────────────────────────────────
 * One dialog shape for both estates. "Leave unchanged" is the default and
 * "Clear the owner" is a separate, explicit choice, mirroring the API: an
 * omitted field and an explicit null are different requests, because a client
 * that forgets a field must never be able to orphan 500 rows silently.
 */
async function assignDialog({ title, note, extraUser = false }) {
  const rows = await teams();
  if (!rows.length) { err('No teams exist yet, or your role cannot read them.'); return null; }
  const r = await modal({
    title,
    body: `<p class="muted small">${esc(note)}</p>
      <div><label>Team</label><select name="team">
        <option value="">Leave unchanged</option>
        <option value="__clear__">— Clear the owner —</option>
        ${rows.map(t => `<option value="${esc(t.id)}">${esc(t.name || t.slug)}</option>`).join('')}
      </select></div>
      ${extraUser ? `<div><label>Reason (recorded on each finding)</label>
        <input name="reason" placeholder="owner confirmed during triage"></div>` : ''}`,
    actions: [{ label: 'Assign' }],
  });
  if (!r) return null;
  if (!r.team) { err('Nothing selected — no change was made.'); return null; }
  return r;
}

/* ── Getting Started — the pipeline, as a place ─────────────────────────
 * VEYRS is a chain: scanners observe, correlation turns observations into
 * findings, risk orders them, tickets carry the fix, verification closes the
 * loop. Every screen in the console is one link of that chain, but nothing
 * used to SHOW the chain — this view does, with live numbers, so a broken
 * link (findings piling up with no tickets) is visible instead of implied. */
route('guide', async (view) => {
  const total = async (path) => { try { return pageOf(await get(path)).total ?? 0; } catch { return null; } };
  const [agents, jobs, nFindings, nCritical, nRem, nTickets] = await Promise.all([
    // Not merely hidden: with scanning off these two are a queue that cannot
    // be fed and a runner that cannot be enrolled. Asking for them anyway puts
    // two requests on every load of the first page a new operator opens.
    activeScanning ? get('/agents?limit=5').then(pageOf).catch(() => null) : null,
    activeScanning ? get('/agents/jobs/summary').catch(() => null) : null,
    // findings and tickets both paginate page/size; `limit` is silently ignored
    total('/findings?size=1'),
    total('/findings?size=1&severity=critical'),
    total('/tickets?size=1&ticket_type=remediation'),
    total('/tickets?size=1'),
  ]);
  const n = (v) => v == null ? '—' : fmtNum(v);
  const chainBroken = (nFindings || 0) > 0 && nRem === 0;
  const agentRows = agents ? agents.items : [];
  const jobBits = jobs && typeof jobs === 'object'
    ? Object.entries(jobs).filter(([, v]) => typeof v === 'number')
        .map(([k, v]) => `<span class="pill st-neutral">${esc(titleCase(k))}: ${fmtNum(v)}</span>`).join(' ')
    : '';

  view.innerHTML = `
    <div class="page-head"><div><h1>Getting started</h1>
      <p>VEYRS is one pipeline: <strong>scan → risk → ticket</strong>. Each step below says where it is
         configured, what it produces, and shows its live numbers — so a gap in the chain is visible here
         before it is a surprise anywhere else.</p></div></div>

    <div class="guide-chain card">
      <div class="chain-node"><span class="chain-step">Step 1</span><b>Scan</b><span class="chain-sub">${activeScanning ? 'agents · imports · intel feeds' : 'imports · connectors · intel feeds'}</span></div>
      <div class="chain-arrow">→</div>
      <div class="chain-node"><span class="chain-step">Step 2</span><b>Risk</b><span class="chain-sub">${n(nFindings)} findings · ${n(nCritical)} critical</span></div>
      <div class="chain-arrow">→</div>
      <div class="chain-node"><span class="chain-step">Step 3</span><b>Ticket</b><span class="chain-sub">${n(nRem)} remediation · ${n(nTickets)} total</span></div>
      <div class="chain-arrow">→</div>
      <div class="chain-node"><span class="chain-step">Close</span><b>Verify</b><span class="chain-sub">resolution advances the finding</span></div>
    </div>

    ${chainBroken ? `<div class="scope-banner" style="border-left-color:var(--veyrs-high);border-color:color-mix(in srgb,var(--veyrs-high) 30%,transparent);background:color-mix(in srgb,var(--veyrs-high) 6%,var(--surface))">
      <strong>The chain is broken at step 3.</strong>
      <span>${n(nFindings)} findings exist and not one remediation ticket tracks a fix. Open
      <a href="#/findings?severity=critical">the critical findings</a>, select them, and use
      <em>Create tickets…</em> — or open one finding and press <em>Create ticket</em>.</span></div>` : ''}

    <div class="grid cols-3 guide-steps">
      <div class="card step-card">
        <div class="step-num">1</div><h2>Scan — where findings come from</h2>
        <p class="small muted">Three inlets, all landing in the same place:</p>
        <ul class="small guide-list">
          ${activeScanning ? `<li><strong>Agents</strong> run authorised scans (nuclei, nmap) as leased jobs — enrolment and
              target allow-lists are operator decisions, an agent never picks its own targets.</li>` : ''}
          ${activeScanning ? '' : `<li><strong>Scanner connectors</strong> pull the export straight from your own
              Nessus or Tenable console — configured under
              <a href="#/integrations?tab=scanners">Integrations → Scanner connectors</a>.</li>`}
          <li><strong>Scanner imports</strong> — upload Nessus, Qualys or Greenbone exports under
              <a href="#/integrations?tab=import">Integrations → Scanner import</a>.</li>
          <li><strong>Intelligence feeds</strong> (NVD, EPSS, KEV, CWE) sync nightly and correlate
              against your <a href="#/assets">asset inventory</a> — no scanner needed for those.</li>
        </ul>
        ${!activeScanning ? `<p class="small muted">This deployment is <strong>ingest-only</strong>: VEYRS
          probes nothing and the scanner screens are out of the menu. An administrator can change that
          under <a href="#/admin?tab=scanning">Administration → Scanning</a>.</p>`
          : (agentRows.length ? table([
          { label: 'Agent', cell: r => esc(r.name || r.hostname || String(r.id).slice(0, 8)) },
          { label: 'Status', cell: r => statePill(r.status) },
          { label: 'Last seen', cell: r => fmtDate(r.last_seen_at || r.last_heartbeat_at) },
        ], agentRows) : '<p class="small muted">No agents enrolled — or your role cannot read them.</p>')}
        ${activeScanning && jobBits ? `<p class="small mt-2">Job queue: ${jobBits}</p>` : ''}
        <div class="row mt-3">
          <a class="btn btn-sm btn-primary" href="#/integrations?tab=import">Import scan results</a>
          <a class="btn btn-sm" href="#/integrations?tab=runs">Import runs</a>
        </div>
      </div>

      <div class="card step-card">
        <div class="step-num">2</div><h2>Risk — what actually matters</h2>
        <p class="small muted">A <strong>finding</strong> is one vulnerability on one asset. Severity is what
          the scanner said; <strong>VEYRS risk</strong> re-orders that by exploitation pressure (EPSS, KEV)
          and business context (asset criticality, exposure). Triage the risk order, not the severity order.</p>
        <div class="grid cols-2" style="margin:10px 0">
          <div class="stat"><span class="label">Findings</span><span class="value">${n(nFindings)}</span></div>
          <div class="stat crit"><span class="label">Critical</span><span class="value">${n(nCritical)}</span></div>
        </div>
        <p class="small muted">Each finding links its asset, its CVE and its history — open one and the
          <em>Why this score</em> table shows the exact factors.</p>
        <div class="row mt-3">
          <a class="btn btn-sm btn-primary" href="#/findings?severity=critical">Review critical findings</a>
          <a class="btn btn-sm" href="#/dashboard">Dashboards</a>
        </div>
      </div>

      <div class="card step-card">
        <div class="step-num">3</div><h2>Ticket — carry the fix, close the loop</h2>
        <p class="small muted">A <strong>remediation ticket</strong> keeps a hard link to its finding:
          one open ticket per finding (duplicates are refused server-side), and resolving the ticket
          advances the finding to <em>remediated</em>. Create them from a finding — detail page or
          bulk-select — so the link is never lost.</p>
        <div class="grid cols-2" style="margin:10px 0">
          <div class="stat"><span class="label">Remediation</span><span class="value">${n(nRem)}</span></div>
          <div class="stat"><span class="label">All tickets</span><span class="value">${n(nTickets)}</span></div>
        </div>
        <p class="small muted">SLA policies put a clock on every ticket; <a href="#/policies">escalation
          ladders</a> fire when the clock runs out. <a href="#/automation?tab=workflows">Workflows</a> can create the
          ticket automatically when a finding crosses a risk threshold.</p>
        <div class="row mt-3">
          <a class="btn btn-sm btn-primary" href="#/tickets?ticket_type=remediation">Open tickets</a>
          <a class="btn btn-sm" href="#/policies">SLA policies</a>
        </div>
      </div>
    </div>

    <div class="card mt-4"><h2>How the records relate</h2>
      <p class="small muted">One <a href="#/intel">CVE</a> → one canonical
      <a href="#/vulnerabilities">vulnerability</a> → many <a href="#/findings">findings</a> (one per affected
      <a href="#/assets">asset</a>) → one open remediation <a href="#/tickets">ticket</a> per finding.
      Ownership flows the other way: an asset's team owns its findings unless a finding is explicitly
      reassigned, and every change is written to the finding's own history for the auditor.</p></div>`;
});

/* ── Vulnerability scanner ────────────────────────────── */

// A tool "version" is whatever the binary printed. nuclei writes its banner
// through a coloured logger, so the declared string arrives carrying ANSI
// escapes that render as `[34mINF[0m]` inside a table cell. The runner and the
// API both strip them now; this keeps rows declared BEFORE that fix readable
// without rewriting stored data.
function toolVersion(raw) {
  if (!raw) return { short: '—', full: '' };
  const flat = String(raw)
    .replace(/\x1B\[[0-9;]*[A-Za-z]/g, '')
    .replace(/[\x00-\x1F\x7F]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  if (!flat) return { short: '—', full: '' };
  const m = flat.match(/v?\d+\.\d+[\w.+-]*/);
  return { short: m ? m[0] : flat.slice(0, 28), full: flat };
}

// Three missed check-ins. Below that a restart looks like an outage; above it,
// a dead runner looks alive - and a queued job that nobody will ever claim is
// the most expensive kind of silence this page exists to break.
const RUNNER_STALE_MS = 15 * 60 * 1000;

function scanDuration(from, to) {
  if (!from || !to) return '—';
  const s = Math.round((Date.parse(to) - Date.parse(from)) / 1000);
  if (!isFinite(s) || s < 0) return '—';
  return s < 60 ? s + 's' : Math.floor(s / 60) + 'm ' + String(s % 60).padStart(2, '0') + 's';
}

function scanBytes(n) {
  if (n === null || n === undefined) return '—';
  if (n < 1024) return fmtNum(n) + ' B';
  if (n < 1048576) return (n / 1024).toFixed(1) + ' kB';
  return (n / 1048576).toFixed(1) + ' MB';
}

// `statePill` maps FINDING states; a job's are a different vocabulary and the
// distinction that matters most (succeeded vs failed) is exactly the one it
// would flatten into the same grey.
const JOB_STATE_CLASSES = ['queued', 'leased', 'running', 'succeeded', 'failed', 'cancelled', 'expired'];
function jobStatePill(state) {
  const s = String(state || '').toLowerCase();
  return `<span class="pill ${JOB_STATE_CLASSES.includes(s) ? 'st-' + s : 'st-neutral'}">${esc(titleCase(state))}</span>`;
}

// Correlation is not a scanner. It reads the inventory against the CVE
// dictionary and never touches the host, so counting it beside nuclei under a
// "scanners" heading overstates how much of the estate has actually been
// looked at.
const CORRELATION_PRODUCER = 'veyrs-correlation';

route('scanner', async (view) => {
  const fail = (e) => ({ error: e });
  const [agents, queue, jobs, tech, importers, runs, mode] = await Promise.all([
    get('/agents?limit=50').then(pageOf).catch(fail),
    get('/agents/jobs/summary').catch(fail),
    get('/agents/jobs?limit=12').then(pageOf).catch(fail),
    get('/dashboard/technical').catch(fail),
    get('/integrations/importers').catch(fail),
    get('/integrations/imports?limit=1').then(pageOf).catch(fail),
    get('/scanning').catch(fail),
  ]);
  const okOf = (r) => (r && !r.error) ? r : null;
  const agentPage = okOf(agents);
  const agentRows = agentPage ? agentPage.items : [];
  const agentsRefused = agents && agents.error && agents.error.status === 403;

  const tools = agentRows.flatMap(a => (a.tools || []).map(t => ({ ...t, agentName: a.name || a.slug })));
  const beats = agentRows.map(a => a.last_heartbeat_at || a.last_seen_at).filter(Boolean).sort();
  const lastBeat = beats.length ? beats[beats.length - 1] : null;
  const stale = agentRows.length > 0 && (!lastBeat || (Date.now() - Date.parse(lastBeat)) > RUNNER_STALE_MS);

  const jobPage = okOf(jobs);
  const jobRows = jobPage ? jobPage.items : [];
  const finished = jobRows.map(j => j.finished_at).filter(Boolean).sort();
  const lastScan = finished.length ? finished[finished.length - 1] : null;
  const q = okOf(queue) || {};
  const queued = (q.queued || 0) + (q.leased || 0);

  const breakdown = (okOf(tech) || {}).scanner_breakdown || [];
  const scanned = breakdown.filter(r => (r.scanner || '') !== CORRELATION_PRODUCER);
  const correlated = breakdown.filter(r => (r.scanner || '') === CORRELATION_PRODUCER);
  const sum = (rows) => rows.reduce((a, r) => a + (r.findings ?? r.count ?? 0), 0);
  const nScanned = sum(scanned);
  const nCorrelated = sum(correlated);

  const formats = (okOf(importers) || {}).formats || [];
  const nRuns = okOf(runs) ? runs.total : null;

  const queueBits = okOf(queue)
    ? Object.entries(q).filter(([k, v]) => typeof v === 'number' && v > 0 && k !== 'active' && k !== 'terminal')
        .map(([k, v]) => `<span class="pill ${JOB_STATE_CLASSES.includes(k) ? 'st-' + k : 'st-neutral'}">${esc(titleCase(k))}: ${fmtNum(v)}</span>`).join(' ')
    : '';

  view.innerHTML = `
    <div class="page-head"><div><h1>Vulnerability scanner</h1>
      <p>VEYRS never scans from the console. An <strong>enrolled agent</strong> pulls authorised jobs,
         runs the scanner on its own host and uploads the raw output for parsing — so the platform holds
         no target credentials and no ability to run a command of its own choosing. This page is the whole
         picture: which engines exist, how a scan is built, when one last ran, and what it produced.</p></div>
      <div class="page-actions">
        <a class="btn" href="#/integrations?tab=import">Import scan results</a>
        <a class="btn" href="#/findings">Findings</a></div></div>

    ${(okOf(mode) && mode.active_scanning_enabled === false) ? `<div class="scope-banner" role="status">
      <strong>Active scanning is off — this deployment is ingest-only</strong>
      <span>VEYRS is not probing anything: jobs cannot be queued and agents cannot claim work.
      Findings still arrive from uploads, scanner connectors and agent results, and everything below
      the scan itself — triage, ownership, SLA, tickets, traceability — is unaffected.
      ${can('settings:admin') ? '<a href="#/admin?tab=scanning">Change it in Administration &rarr; Scanning</a>.' : 'An administrator can change it in Administration &rarr; Scanning.'}</span></div>` : ''}

    ${agentsRefused ? `<div class="scope-banner" role="status"><strong>Estate-wide screen</strong>
      <span>Agents, jobs and scan output are not divided by team, so a team-restricted identity is refused
      rather than served an unfiltered view. Ask an administrator for <em>agent:read</em> without a team
      restriction to see this page.</span></div>` : ''}

    ${stale ? `<div class="scope-banner" role="status" style="border-left-color:var(--veyrs-high);border-color:color-mix(in srgb,var(--veyrs-high) 30%,transparent);background:color-mix(in srgb,var(--veyrs-high) 6%,var(--surface))">
      <strong>No runner has checked in.</strong>
      <span>The last heartbeat was ${esc(fmtDate(lastBeat))}. An agent that is not checking in declares no
      engines and claims no jobs${queued ? `, and ${fmtNum(queued)} job(s) are waiting in the queue for one` : ''}
      — anything scheduled now will sit unclaimed rather than fail. Check
      <code class="mono">veyrs-agent</code> on the runner host and the <code class="mono">VEYRS_URL</code>
      in its environment file.</span></div>` : ''}

    <div class="grid cols-4">
      <div class="card stat"><span class="label">Runner</span>
        <span class="value">${fmtNum(agentRows.length)}</span>
        <span class="hint">${agentRows.length
          ? esc(agentRows.map(a => a.name || a.slug).join(', ')) : 'None enrolled'}</span></div>
      <div class="card stat ${stale ? 'warn' : ''}"><span class="label">Last check-in</span>
        <span class="value t-lg">${esc(fmtDate(lastBeat))}</span>
        <span class="hint">${agentRows.length ? esc(titleCase(agentRows[0].status || 'unknown')) : '—'}</span></div>
      <div class="card stat"><span class="label">Last scan finished</span>
        <span class="value t-lg">${esc(fmtDate(lastScan))}</span>
        <span class="hint">${okOf(queue) ? fmtNum(q.terminal ?? 0) + ' completed · ' + fmtNum(q.active ?? 0) + ' active' : '—'}</span></div>
      <div class="card stat"><span class="label">Findings from a scan</span>
        <span class="value">${fmtNum(nScanned)}</span>
        <span class="hint">${fmtNum(nCorrelated)} more came from correlation, not a scan</span></div>
    </div>

    <div class="grid cols-2 mt-4">
      <div class="card"><h2>Engines on the runner</h2>
        ${tools.length ? table([
          { label: 'Engine', cell: r => `<strong>${esc(r.name)}</strong>` },
          { label: 'Version', cell: r => `<span class="mono" title="${esc(toolVersion(r.tool_version).full)}">${esc(toolVersion(r.tool_version).short)}</span>` },
          { label: 'Parser', cell: r => `<span class="mono small">${esc(r.parser || '—')}</span>` },
          { label: 'Profiles', cell: r => (r.profiles || []).map(p => `<span class="pill st-neutral">${esc(p)}</span>`).join(' ') || '—' },
          { label: 'Authorised', cell: r => r.enabled
              ? '<span class="pill st-verified">Yes</span>'
              : '<span class="pill st-neutral">No — declared only</span>' },
          { label: 'Declared', cell: r => fmtDate(r.declared_at) },
        ], tools) : `<p class="small muted">${agentsRefused
          ? 'Your role cannot read agents.'
          : 'No engine declared. A runner reports only the binaries it can actually find on its PATH, so an engine missing from this table is not installed — queueing a job for it would wait forever.'}</p>`}
        <p class="small muted mt-2">The runner declares only what is on its PATH, and a
          declaration is <strong>not</strong> an authorisation: an operator has to enable an engine before a
          job of that type can be claimed. Installing a binary can never widen what VEYRS may run.</p></div>

      <div class="card"><h2>Scan queue</h2>
        ${queueBits ? `<p class="row gap-2">${queueBits}</p>`
          : '<p class="small muted">The queue is empty — no scan has ever been requested, or your role cannot read it.</p>'}
        <dl class="kv mt-3">
          <dt>Target allow-list</dt><dd>${agentRows.length
            ? agentRows.map(a => (a.allowed_targets || []).map(t => `<span class="pill st-neutral mono">${esc(t)}</span>`).join(' ') || '<em>empty — the agent can run nothing</em>').join(' ')
            : '—'}</dd>
          <dt>Denied</dt><dd>${agentRows.length
            ? (agentRows.flatMap(a => a.denied_targets || []).map(t => `<span class="pill sev-critical mono">${esc(t)}</span>`).join(' ') || 'none')
            : '—'}</dd>
          <dt>Must match an asset</dt><dd>${agentRows.length ? (agentRows[0].require_asset_match ? 'Yes' : 'No') : '—'}</dd>
          <dt>Concurrency · lease</dt><dd>${agentRows.length
            ? `${fmtNum(agentRows[0].max_concurrency)} job(s) · ${fmtNum(agentRows[0].lease_seconds)}s` : '—'}</dd>
          <dt>Runner host</dt><dd>${agentRows.length
            ? `${esc(agentRows[0].hostname || '—')} <span class="small muted">${esc(agentRows[0].platform || '')}</span>` : '—'}</dd>
          <dt>Agent version</dt><dd class="mono">${agentRows.length ? esc(agentRows[0].agent_version || '—') : '—'}</dd>
        </dl></div>
    </div>

    <div class="card mt-4"><h2>How a scan is built and run</h2>
      <div class="guide-chain" style="margin:0 0 14px">
        <div class="chain-node"><span class="chain-step">1</span><b>Claim</b><span class="chain-sub">the agent asks for work</span></div>
        <div class="chain-arrow">→</div>
        <div class="chain-node"><span class="chain-step">2</span><b>Authorise</b><span class="chain-sub">allow-list checked again, locally</span></div>
        <div class="chain-arrow">→</div>
        <div class="chain-node"><span class="chain-step">3</span><b>Probe</b><span class="chain-sub">is the target reachable from here</span></div>
        <div class="chain-arrow">→</div>
        <div class="chain-node"><span class="chain-step">4</span><b>Run</b><span class="chain-sub">argv from a fixed template, no shell</span></div>
        <div class="chain-arrow">→</div>
        <div class="chain-node"><span class="chain-step">5</span><b>Import</b><span class="chain-sub">raw output parsed into findings</span></div>
      </div>
      <ul class="small guide-list">
        <li><strong>The server never sends a command line.</strong> A job is
          <code class="mono">{tool, target, profile, params}</code>. The argument vector is assembled on the
          runner, by the builder registered for that engine, from a fixed template — a key the builder does
          not recognise is dropped, not passed through. A compromised or impersonated VEYRS cannot turn the
          agent into a remote shell.</li>
        <li><strong>No shell, ever.</strong> The process is spawned with an argument list, never a string,
          so there is no interpolation anywhere near execution.</li>
        <li><strong>The allow-list is enforced twice</strong> — once by VEYRS when the job is queued and
          again by the agent against its own local configuration at claim time. A refusal by the local
          operator does <em>not</em> requeue the job: another agent may legitimately be authorised for that
          target, and retrying here would only burn the attempts.</li>
        <li><strong>Reachability is probed before scanning</strong>, over TCP and with the host's own
          resolver. That evidence is deliberately taken outside the scanner: when the probe connects and the
          scan then reports nothing, the disagreement is itself the finding — typically split-horizon DNS.</li>
        <li><strong>Rate limit, timeout and template tags are clamped.</strong> Tags are restricted to a
          fixed set; an arbitrary template directory supplied by the server would be remote code execution
          under another name.</li>
        <li><strong>Output is streamed, then uploaded whole.</strong> Progress lines arrive as job events
          while the scan runs and the lease is extended periodically; at the end the raw report file is
          posted and handed to the same importer used for a manual upload, producing an auditable import
          run.</li>
      </ul></div>

    <div class="grid cols-2 mt-4">
      <div class="card"><h2>What a scan can see</h2>
        <p class="small muted">Remote and unauthenticated. It never logs in, so it sees exactly what the
          host exposes to the network:</p>
        <ul class="small guide-list">
          <li><strong>CVEs</strong> — responses fingerprinting a version with known vulnerabilities.</li>
          <li><strong>Exposures</strong> — <code class="mono">.git</code>, <code class="mono">.env</code>,
            backups, admin panels and config files reachable without authentication.</li>
          <li><strong>Misconfiguration</strong> — headers, TLS, directory listing, unchanged defaults.</li>
          <li>Banners, detected technologies and default endpoints — informational, and usually the bulk
            of the volume.</li>
        </ul></div>
      <div class="card"><h2>What it cannot see</h2>
        <p class="small muted">The gap this page exists to make visible:</p>
        <ul class="small guide-list">
          <li><strong>Installed packages and patch level.</strong> That comes from the agent's inventory
            report, which is a separate function and off unless a target is configured for it.</li>
          <li><strong>Anything behind authentication</strong> — internal configuration, local users,
            file permissions.</li>
          <li><strong>Hosts outside the allow-list</strong>, and hosts nobody has queued a job for. There is
            <strong>no discovery</strong>: one job scans one named target.</li>
          <li><strong>Anything at all on a schedule.</strong> Scans run when a job is requested; the nightly
            timer feeds the CVE, EPSS, KEV and CWE dictionaries, it does not scan.</li>
        </ul></div>
    </div>

    <div class="card mt-4"><h2>Recent scans</h2>
      ${jobRows.length ? table([
        { label: 'Requested', cell: r => fmtDate(r.created_at) },
        { label: 'Engine', cell: r => `<strong>${esc(r.tool)}</strong>` },
        { label: 'Target', cell: r => `<span class="mono small">${esc(r.target)}</span>` },
        { label: 'Profile', cell: r => esc(r.profile || 'default') },
        { label: 'Parameters', cell: r => `<span class="mono small">${esc(Object.entries(r.params || {}).map(([k, v]) => k + '=' + v).join(' ') || '—')}</span>` },
        { label: 'State', cell: r => jobStatePill(r.state) },
        { label: 'Duration', cell: r => esc(scanDuration(r.started_at, r.finished_at)) },
        { label: 'Output', num: true, cell: r => `${esc(scanBytes(r.output_bytes))}${r.output_bytes === 0 ? ' <span class="pill st-neutral">empty</span>' : ''}` },
        { label: 'Findings', cell: r => r.import_run_id
            ? `<a href="#/integrations?tab=runs">imported</a>` : '—' },
      ], jobRows) : `<p class="small muted">${okOf(jobs)
        ? 'No scan has ever been requested on this tenant.'
        : 'Your role cannot read the job history.'}</p>`}
      <p class="small muted mt-2">An empty output on a job that exited cleanly is
        <em>not</em> proof of a clean host: an aborted run and a genuinely clean one produce the same three
        facts. Coverage statistics reported by the engine are what separates them — which is why the runner
        asks for them and why a scan without an internal resolver is worth re-running.</p></div>

    <div class="grid cols-2 mt-4">
      <div class="card"><h2>Who produced the findings</h2>
        ${breakdown.length ? table([
          { label: 'Producer', cell: r => (r.scanner === CORRELATION_PRODUCER
              ? `<strong>${esc(r.scanner)}</strong> <span class="pill st-neutral">not a scan</span>`
              : `<strong>${esc(r.scanner || 'manual')}</strong>`) },
          { label: 'Findings', num: true, cell: r => fmtNum(r.findings ?? r.count) },
          { label: 'Last seen', cell: r => fmtDate(r.last_seen_at) },
        ], breakdown) : `<p class="small muted">${okOf(tech)
          ? 'No findings recorded yet.' : 'Your role cannot read the dashboards.'}</p>`}
        <p class="small muted mt-2">Correlation compares the software recorded against
          each asset with the CVE dictionary. It never touches the host, so its findings say what the
          inventory implies, not what a scan observed — an inventory that is stale or absent produces
          silence, not an error.</p></div>

      <div class="card"><h2>Third-party reports VEYRS can ingest</h2>
        ${formats.length ? `<p class="row" style="gap:5px">${formats.map(f =>
            `<span class="pill st-neutral mono">${esc(f)}</span>`).join('')}</p>
          <p class="small muted mt-2">${fmtNum(formats.length)} parsers. Format is
            auto-detected from the file's own signature, and every upload lands as an auditable import run
            ${nRuns === null ? '' : `— <strong>${fmtNum(nRuns)}</strong> so far`}.</p>`
        : '<p class="small muted">Your role cannot read the importer registry.</p>'}
        <div class="row mt-3">
          <a class="btn btn-sm btn-primary" href="#/integrations?tab=import">Upload a report</a>
          <a class="btn btn-sm" href="#/integrations?tab=runs">Import runs</a></div></div>
    </div>

    <div class="card mt-4"><h2>Where every number on this page comes from</h2>
      <dl class="kv">
        <dt>Runner, status, check-in</dt><dd><code class="mono">GET /agents</code> — written by the
          agent's own heartbeat; nothing else updates it, so a stale timestamp means the agent is not
          talking, not that it is idle.</dd>
        <dt>Engines, versions, profiles</dt><dd><code class="mono">GET /agents</code> — each agent
          declares the binaries it found at check-in. An engine the runner stops declaring is disabled,
          never deleted, so its job history stays readable.</dd>
        <dt>Queue counters</dt><dd><code class="mono">GET /agents/jobs/summary</code> — grouped by job
          state.</dd>
        <dt>Recent scans, parameters, exit codes</dt><dd><code class="mono">GET /agents/jobs</code> — the
          job record itself, including the exact parameters the job was queued with.</dd>
        <dt>Live scan output</dt><dd><code class="mono">GET /agents/jobs/{id}/events</code> — a durable
          log, tailed by polling, so yesterday's scrollback survives a restart of either end.</dd>
        <dt>Who produced the findings</dt><dd><code class="mono">GET /dashboard/technical</code> — grouped
          by the <code class="mono">scanner</code> recorded on each finding when it was created.</dd>
        <dt>Ingestible formats</dt><dd><code class="mono">GET /integrations/importers</code> — the parser
          registry itself, not a hand-kept list, so it cannot drift from what the server accepts.</dd>
        <dt>Import history</dt><dd><code class="mono">GET /integrations/imports</code>.</dd>
      </dl>
      <p class="small muted mt-2">Everything above is read live. The only fixed text on
        this page is the description of the execution model, which is a property of the code rather than of
        the data.</p></div>`;
});

/* ── Findings ───────────────────────────────────────────────────────── */
const FINDING_STATES =['new', 'triaged', 'risk_assessed', 'assigned', 'in_progress', 'mitigation',
  'remediated', 'verification', 'verified', 'closed', 'false_positive', 'duplicate', 'accepted_risk', 'exception', 'deferred'];

route('findings', listView({
  title: 'Findings',
  /* The distinction between a finding and a vulnerability, and the pointer to
     what produced them, live in the blurb rather than in a manual: they are
     the two questions every new operator asks in their first hour, and the
     scanner page moved out of this group in v0.21.0 -- a reader who cannot
     find what produced the findings concludes nothing did. */
  blurb: () => 'A <strong>finding</strong> is one vulnerability on one asset — the unit of work, with a state, an owner, a deadline and a ticket. '
       + 'The same CVE on twelve servers is <a href="#/vulnerabilities">one vulnerability and twelve findings</a>. '
       + 'Severity is what the scanner said; <strong>risk</strong> is what VEYRS computed from exploitation pressure and business context. '
       + 'These come from <a href="#/intel?tab=cve">intelligence feeds correlated against your inventory</a>, from '
       + '<a href="#/integrations?tab=import">imported scanner reports</a>'
       /* Naming a producer this deployment does not have sends the reader to
          look for a page that is not in the menu. When VEYRS does not scan,
          the sentence has to stop being true rather than be hedged. */
       + (activeScanning
           ? ', and from the <a href="#/scanner">VEYRS scanner</a> if it is enabled.'
           : ', and from <a href="#/integrations?tab=scanners">scanner connectors</a>. '
             + 'This deployment does not scan: VEYRS ingests what your own scanner reports.'),
  endpoint: '/findings',
  emptyHint: 'A finding is raised when something VEYRS ingested matches something it knows about your estate. With no findings at all, one of those two halves is missing.',
  savedEntity: 'findings',
  setup: () => [
    { label: 'Load the estate', href: '#/assets', note: 'nothing can be affected until VEYRS knows it exists' },
    { label: 'Import a scanner export', href: '#/integrations?tab=import', note: 'Nessus, nuclei or a connector pull' },
    { label: 'Check the intelligence feeds', href: '#/intel?tab=runs', note: 'NVD, EPSS, KEV and CWE must have run at least once' },
    ...(activeScanning
      ? [{ label: 'Or enable the scanner', href: '#/scanner', note: 'VEYRS probes the estate itself' }]
      : [{ label: 'Or configure a scanner connector', href: '#/integrations?tab=scanners', note: 'VEYRS pulls the export from your scanner on a schedule' }]),
  ],
  showScope: true,
  filters: [
    { name: 'state', label: 'State', options: FINDING_STATES },
    { name: 'severity', label: 'Severity', options: ['critical', 'high', 'medium', 'low', 'informational'] },
    // `owning_team_id`, not `assigned_team_id`: most findings are never
    // explicitly assigned and inherit the team that owns their asset. Filtering
    // on the raw column would answer "this team has no work" for a fully owned
    // estate -- see services/teams.owning_team().
    { name: 'owning_team_id', label: 'Owning team', options: () => teamOptions() },
    { name: 'queue', label: 'Queue', options: [
      { value: 'my_teams', label: "My teams' queue" },
      { value: 'mine', label: 'Assigned to me' },
      { value: 'unowned', label: 'No owner at all' },
    ] },
    { name: 'q', label: 'Search' },
  ],
  // `queue` is a UI convenience over three boolean API flags; translated here
  // so the address bar stays one readable parameter instead of three.
  mapQuery: q => {
    if (q.queue) { q[q.queue] = 'true'; delete q.queue; }
    return q;
  },
  cols: [
    { label: 'Title', cell: r => `<div>${esc(r.title || r.id)}</div><div class="small muted mono">${esc([r.port && ('port ' + r.port), r.protocol, r.path].filter(Boolean).join(' · '))}</div>` },
    { label: 'Severity', cell: r => sevPill(r.severity) },
    { label: 'Risk', num: true, cell: r => `<strong>${fmtScore(r.risk_score)}</strong><div class="small muted">${esc(r.risk_level || '')}</div>` },
    { label: 'CVSS', num: true, cell: r => fmtScore(r.cvss_score) },
    { label: 'EPSS', num: true, cell: r => r.epss_score == null ? '—' : fmtPct(r.epss_score) },
    { label: 'KEV', cell: r => r.kev ? '<span class="pill pill-kev">KEV</span>' : '' },
    { label: 'State', cell: r => statePill(r.state) },
    { label: 'Age', num: true, cell: r => r.age_days == null ? '—' : r.age_days + 'd' },
    { label: 'Owner', cell: r => {
        const team = r.owning_team_name || teamName(r.owning_team_id);
        if (!team) return '<span class="muted small">unowned</span>';
        // An implicit owner is shown as such: it comes from the asset and will
        // move with it, which is a different fact from a deliberate assignment.
        const implicit = !r.assigned_team_id;
        return `<div>${esc(team)}${implicit ? ' <span class="muted small">(via asset)</span>' : ''}</div>`
             + (r.assigned_user_name ? `<div class="small muted">${esc(r.assigned_user_name)}</div>` : '');
      } },
    { label: 'SLA', cell: r => !r.sla_due_at ? '<span class="muted small">no clock</span>'
        : r.sla_breached ? `<span class="pill sev-critical">Breached</span><div class="small muted">${fmtDay(r.sla_due_at)}</div>`
        : `<div class="small">${fmtDay(r.sla_due_at)}</div>${r.escalation_level ? `<span class="pill st-warn">L${esc(r.escalation_level)}</span>` : ''}` },
  ],
  bulk: (can('finding:write') || can('ticket:write')) ? [
    ...(can('finding:write') ? [{ act: 'assign', label: 'Assign to team…', cls: 'btn-primary' }] : []),
    ...(can('ticket:write') ? [{ act: 'ticket', label: externalTicketing() ? 'Raise issues…' : 'Create tickets…' }] : []),
  ] : null,
  onBulk: async (act, ids, reload) => {
    if (!ids.length) return;
    if (act === 'ticket') {
      const ext = externalTicketing();
      const r = await modal({
        title: ext ? 'Raise remediation issues' : 'Create remediation tickets',
        body: ext
          ? `<p class="small muted">One issue per selected finding (${ids.length}), raised in your
             external ITSM. A finding that already has a live issue keeps it — the server returns
             the existing one instead of raising a duplicate in somebody else's queue.</p>
             <p class="small muted">Each issue carries the device, the CVE, the severity, the ports
             and the SLA date, so it can be worked without opening VEYRS. VEYRS keeps the relation
             under <em>Issues</em>.</p>
             <p class="small muted">This talks to a remote system, so ${ids.length} finding(s) means
             ${ids.length} network call(s) — a large selection is not instant.</p>`
          : `<p class="small muted">One remediation ticket per selected finding (${ids.length}).
             A finding that already has an open remediation ticket keeps it — the server
             returns the existing ticket instead of creating a duplicate. Resolving a
             remediation ticket advances its finding to <em>remediated</em>.</p>`,
        actions: [{ label: ext ? 'Raise issues' : 'Create tickets' }],
      });
      if (!r) return;
      let made = 0, failed = 0, lastError = '';
      for (const fid of ids) {
        try { await openRemediationForFinding(await get('/findings/' + fid)); made++; }
        catch (e) { failed++; lastError = e.detail || lastError; }
      }
      const noun = ext ? 'issue' : 'remediation ticket';
      if (made) ok(`${made} ${noun}${made === 1 ? '' : 's'} ready${failed ? `, ${failed} failed` : ''}.`);
      // The remote's own sentence, not a generic failure. "No tickets could be
      // created" sent operators to check permissions when the answer was
      // "project SEC does not exist".
      else err(lastError || `No ${noun}s could be created.`);
      reload();
      return;
    }
    if (act !== 'assign') return;
    const r = await assignDialog({
      title: `Assign ${ids.length} finding${ids.length === 1 ? '' : 's'}`,
      note: 'Each finding records the change in its own history, so a reassignment stays visible to an auditor.',
      extraUser: true,
    });
    if (!r) return;
    const body = { finding_ids: ids, reason: r.reason || null };
    if (r.team === '__clear__') body.clear = ['assigned_team_id'];
    else body.assigned_team_id = r.team;
    try {
      const res = await post('/findings/bulk-assign', body);
      ok(`${res.changed_count} assigned${res.rejected_count ? `, ${res.rejected_count} skipped` : ''}.`);
      reload();
    } catch (e) { err(e.detail); }
  },
  detail: findingDetail,
}));

/* One call closes the scan → risk → work chain for one finding, in WHICHEVER
 * system this tenant put its remediation work in.
 *
 * It used to post to `/tickets` with a finding_id, which hardcoded the internal
 * queue into the front end: the console decided where work went, and any tenant
 * running Jira got a second queue nobody read. `/findings/{id}/remediation`
 * asks the API to arrange the fix and lets `services/ticketing_mode` answer;
 * the response says which system did (`kind`), so nothing here has to guess.
 *
 * The title and description are NOT sent any more. In external mode the server
 * composes them from the finding, the asset, the CVE, the ports and the SLA
 * date — an engineer who opens SEC-4412 and finds a bare CVE id with no host
 * has been handed a riddle. Two composers would be two chances to disagree.
 *
 * Still idempotent, and now in both modes: an open remediation ticket, or a
 * live external issue, is returned rather than doubled.
 */
async function openRemediationForFinding(f) {
  return post(`/findings/${f.id}/remediation`, {});
}

/* Where to send the operator after the work was raised. An external issue lives
 * in somebody else's system, so the useful destination is the relation row --
 * which carries the device, the CVE, the dates and the remote status without a
 * round trip -- and the remote URL is one click from there. Opening Jira in
 * this tab instead would navigate the console away from itself. */
function remediationHref(r) {
  return r.kind === 'external' ? '#/issues?q=' + encodeURIComponent(r.reference || '')
                               : '#/tickets/' + r.id;
}

async function findingDetail(view, parts) {
  const id = parts[0];
  const f = await get('/findings/' + id);
  const asset = f.asset || {};
  const cve = f.cve || {};
  const sla = f.sla || {};
  const explanation = f.risk_explanation || {};
  const factors = explanation.factors || (Array.isArray(explanation) ? explanation : []);
  view.innerHTML = `
    <div class="page-head"><div>
      <h1>${esc(f.title || cve.cve_id || 'Finding')}</h1>
      <p>${sevPill(f.severity)} ${statePill(f.state)} ${f.kev ? '<span class="pill pill-kev">Known exploited</span>' : ''}
         ${f.sla_breached ? '<span class="pill sev-critical">SLA breached</span>' : ''}</p></div>
      <div class="page-actions">
        <button class="btn btn-primary" id="transition">Transition…</button>
        ${can('ticket:write') ? `<button class="btn" id="mk-ticket">${externalTicketing() ? 'Raise issue' : 'Create ticket'}</button>` : ''}
        <button class="btn" id="rescore">Re-score</button>
        <button class="btn" id="accept">Accept risk…</button>
        <button class="btn btn-ai" id="explain">✦ Explain</button>
        <button class="btn btn-ai" id="remediation">✦ Remediation</button>
      </div></div>
    <div class="grid cols-2">
      <div class="card"><h2>Risk</h2>
        <div class="grid cols-3">
          <div class="stat"><span class="label">VEYRS risk</span><span class="value">${fmtScore(f.risk_score)}</span><span class="hint">${esc(f.risk_level || '')}</span></div>
          <div class="stat"><span class="label">CVSS</span><span class="value">${fmtScore(f.cvss_score)}</span><span class="hint mono small">${esc(cve.cvss_vector || '')}</span></div>
          <div class="stat"><span class="label">EPSS</span><span class="value">${f.epss_score == null ? '—' : fmtPct(f.epss_score)}</span><span class="hint">${cve.epss_percentile == null ? '' : 'percentile ' + Math.round(cve.epss_percentile * 100)}</span></div>
        </div>
        <div class="score-sub" style="grid-template-columns:repeat(4,1fr)">
          <div>Technical<b>${fmtScore(f.technical_risk)}</b></div><div>Exploitability<b>${fmtScore(f.exploitability_risk)}</b></div>
          <div>Business<b>${fmtScore(f.business_risk)}</b></div><div>Exposure<b>${fmtScore(f.exposure_risk)}</b></div></div>
        ${factors.length ? `<h3 class="mt-4">Why this score</h3>${table([
          { label: 'Factor', cell: r => esc(r.label || r.name || r.factor) },
          { label: 'Value', cell: r => esc(r.value ?? '—') },
          { label: 'Effect', num: true, cell: r => esc(r.effect ?? r.delta ?? r.contribution ?? '') },
        ], factors)}`
        : explanation && Object.keys(explanation).length
          ? `<h3 class="mt-4">Why this score</h3><pre class="mono small pre-wrap">${esc(JSON.stringify(explanation, null, 2))}</pre>`
          : '<p class="small muted mt-3">No explanation recorded — re-score to generate one.</p>'}
      </div>
      <div class="card"><h2>Context</h2><dl class="kv">
        <dt>Finding ID</dt><dd class="mono">${esc(f.id)}</dd>
        <dt>CVE</dt><dd>${cve.cve_id ? `<a href="#/intel/cve/${esc(cve.cve_id)}" class="mono">${esc(cve.cve_id)}</a>` : '—'}</dd>
        <dt>Vulnerability</dt><dd>${f.vulnerability_id ? `<a href="#/vulnerabilities/${esc(f.vulnerability_id)}" class="mono small">${esc(f.vulnerability_id)}</a>` : '—'}</dd>
        <dt>Asset</dt><dd>${f.asset_id ? `<a href="#/assets/${esc(f.asset_id)}">${esc(asset.name || asset.hostname || f.asset_id)}</a>` : '—'}</dd>
        <dt>Asset criticality</dt><dd>${asset.criticality ? critPill(asset.criticality) : '—'}</dd>
        <dt>Asset exposure</dt><dd>${asset.exposure ? exposurePill(asset.exposure) : '—'}</dd>
        <dt>Service</dt><dd class="mono small">${esc([f.port && ('port ' + f.port), f.protocol, f.path].filter(Boolean).join(' · ') || '—')}</dd>
        <dt>Owner team</dt><dd>${esc(f.owning_team_name || teamName(f.owning_team_id) || '—')}${
          f.owning_team_id && !f.assigned_team_id ? ' <span class="muted small">(via asset)</span>' : ''}</dd>
        <dt>Assignee</dt><dd class="mono small">${esc(f.assigned_user_id || '—')}</dd>
        <dt>Why this owner</dt><dd>${esc(f.assignment_reason || '—')}</dd>
        <dt>Detected</dt><dd>${fmtDate(f.detected_at)}</dd>
        <dt>Remediated</dt><dd>${fmtDate(f.remediated_at)}</dd>
        <dt>SLA due</dt><dd>${fmtDate(f.sla_due_at)} ${f.sla_breached ? '<span class="pill sev-critical">Breached</span>' : ''}</dd>
        <dt>Escalation level</dt><dd>${fmtNum(f.escalation_level ?? 0)}${sla.policy_name ? ` <span class="muted small">(${esc(sla.policy_name)})</span>` : ''}</dd>
      </dl></div>
    </div>
    ${f.detail ? `<div class="card mt-4"><h2>Detail</h2><p>${esc(f.detail)}</p></div>` : ''}
    ${f.recommendation ? `<div class="card mt-4"><h2>Recommendation</h2><p>${esc(f.recommendation)}</p></div>` : ''}
    <div class="card mt-4" id="fix-plan"><h2>Fix plan</h2><div class="loading">Loading…</div></div>
    ${(f.events || []).length ? `<div class="card mt-4"><h2>History</h2>${table([
      { label: 'When', cell: r => fmtDate(r.created_at || r.occurred_at) },
      { label: 'Event', cell: r => statePill(r.event || r.kind || r.type) },
      { label: 'Actor', cell: r => esc(r.actor_label || '—') },
      { label: 'Note', cell: r => esc((r.note || r.message || '').slice(0, 160)) },
    ], f.events)}</div>` : ''}
    <div class="card mt-4" id="why-changed"><h2>Why did this change?</h2><p class="small muted">Loading…</p></div>
    <div class="card mt-4" id="ai-out" hidden><h2>✦ AI analysis</h2><div id="ai-body"></div></div>`;
  loadWhyChanged(id);

  loadFixPlan($('#fix-plan'), `/findings/${id}/fix-plan`);
  $('#transition').onclick = async () => {
    const r = await modal({
      title: 'Transition finding',
      body: `<div><label>Target state</label><select name="state">${FINDING_STATES.map(s => `<option value="${s}">${titleCase(s)}</option>`).join('')}</select></div>
             <div><label>Note (recorded in the audit trail)</label><textarea name="note" placeholder="Why is this moving?"></textarea></div>`,
      actions: [{ label: 'Transition' }],
    });
    if (!r) return;
    try { await post(`/findings/${id}/transition`, { state: r.state, note: r.note || null }); ok('Finding transitioned.'); render(); }
    catch (e) { err(e.detail); }
  };
  $('#rescore').onclick = async () => {
    try { await post(`/findings/${id}/rescore`, {}); ok('Re-scored.'); render(); } catch (e) { err(e.detail); }
  };
  const mkTicket = $('#mk-ticket');
  if (mkTicket) mkTicket.onclick = async () => {
    try {
      const r = await openRemediationForFinding(f);
      ok(r.kind === 'external'
        ? `${r.reference} ${r.created ? 'raised' : 'already open'} in the external system.`
        : `Remediation ticket ${r.reference || ''} ${r.created ? 'ready' : 'already open'}.`);
      location.hash = remediationHref(r);
    } catch (e) { err(e.detail); }
  };
  $('#accept').onclick = async () => {
    const r = await modal({
      title: 'Accept risk',
      body: `<p class="small muted">Accepting risk is a decision, not a fix. It is recorded against your user and surfaces in compliance evidence.</p>
             ${f.state === 'new' ? `<p class="explainer-warn">This finding has never been triaged.
               VEYRS will move it to <strong>triaged</strong> first, because the lifecycle has no
               edge from <code>new</code> straight to <code>accepted_risk</code>.</p>` : ''}
             <div><label>Reason (10 characters minimum)</label><textarea name="reason" required></textarea></div>
             <div><label>Review date</label><input type="date" name="until"></div>`,
      actions: [{ label: 'Accept risk', cls: 'btn-danger' }],
    });
    if (!r) return;
    // The API reads `reason` and `until` from the QUERY STRING (POST
    // /findings/{id}/accept-risk), exactly as the Triage queue sends them. A
    // JSON body here was a 422 on every click until 0.35.3.
    const reason = String(r.reason || '').trim();
    if (reason.length < 10) { err('The reason has to say something — 10 characters minimum.'); return; }
    try {
      if (f.state === 'new') {
        await post(`/findings/${id}/transition`, { state: 'triaged', note: 'Triaged for risk acceptance' });
      }
      await post(`/findings/${id}/accept-risk` + qs({ reason, until: r.until || '' }), {});
      ok('Risk accepted.'); render();
    }
    catch (e) { err(e.detail); }
  };
  const aiCall = async (path, label) => {
    $('#ai-out').hidden = false;
    $('#ai-body').innerHTML = '<div class="loading">Asking the configured provider…</div>';
    try {
      // The AI router is mounted at /ai, not beneath /findings. Posting to
      // `/findings/<id>/explain` was a 404 that aiCall rendered as one muted
      // line, so both ✦ buttons had never once produced an answer.
      const r = await post(`/ai/findings/${id}/${path}`, {});
      $('#ai-body').innerHTML = `<div class="ai-msg veyrs"><strong>${esc(label)}</strong><pre>${esc(r.answer || r.text || r.content || JSON.stringify(r, null, 2))}</pre></div>`;
    } catch (e) { $('#ai-body').innerHTML = `<p class="muted">${esc(e.detail)}</p>`; }
  };
  $('#explain').onclick = () => aiCall('explain', 'Risk explanation');
  $('#remediation').onclick = () => aiCall('remediation', 'Remediation guidance');
}

/* ── Attribution: why did this finding change? ─────────────────────────
   Reads GET /findings/{id}/attribution and GET /findings/changes
   (services/attribution.py). The server reads causes from facts recorded at
   the time of the change and never guesses, so nothing here infers either:
   an `unknown` cause is shown with the sentence naming what was not recorded,
   because an empty cell would read as "no reason" rather than "no record". */
function causePill(t) {
  const cls = t.cause === 'unknown' ? 'st-neutral'
    : t.kind === 'closed' ? 'st-ok' : t.kind === 'reopened' ? 'st-warn' : 'st-neutral';
  return `<span class="pill ${cls}" title="${esc(t.cause)}">${esc(t.cause_label || titleCase(t.cause))}</span>`;
}

function attributionActor(a) {
  if (!a) return '—';
  const where = a.kind === 'external'
    ? [a.system, a.connector && ('connector ' + a.connector)].filter(Boolean).join(', ')
    : a.component || '';
  return esc(a.label || a.kind) + (where ? ` <span class="muted small">(${esc(where)})</span>` : '');
}

function attributionEvidence(t) {
  const sentence = (t.evidence && t.evidence.sentence) || t.evidence || '';
  return `<div>${esc(sentence)}</div>`
    + (t.regression ? `<div class="small"><strong>Regression:</strong> ${esc(t.regression.sentence)}</div>` : '')
    + ((t.missing || []).length ? `<div class="small muted">Not recorded: ${esc(t.missing.join('; '))}</div>` : '');
}

async function loadWhyChanged(id) {
  const box = $('#why-changed');
  if (!box) return;
  let data;
  try { data = await get(`/findings/${encodeURIComponent(id)}/attribution`); }
  catch (e) {
    box.innerHTML = `<h2>Why did this change?</h2><p class="small muted">${esc(e.detail || 'The explanation could not be loaded.')}</p>`;
    return;
  }
  const rows = (data.transitions || []).slice().reverse();
  box.innerHTML = `<h2>Why did this change?</h2>
    <p class="small muted">Every state change of this finding, newest first, with the cause VEYRS
      recorded when it happened. Where a fact was not recorded the entry says which one; causes are
      never guessed. Detailed causes are recorded since ${esc(data.detail_recorded_since)}.</p>
    ${table([
      { label: 'When', cell: t => fmtDate(t.at) },
      { label: 'Change', cell: t => `${statePill(t.from || 'unknown')} → ${statePill(t.to || 'unknown')}` },
      { label: 'Cause', cell: t => causePill(t) },
      { label: 'By', cell: t => attributionActor(t.actor) },
      { label: 'Evidence', cell: t => attributionEvidence(t) },
    ], rows, { emptyTitle: 'No state changes recorded',
               emptyHint: 'This finding has not moved since it was detected.' })}`;
}

route('changes', async (view, _parts, params) => {
  const kind = params.get('kind') || '';
  const cause = params.get('cause') || '';
  const days = ['1', '7', '30', '90'].includes(params.get('days')) ? params.get('days') : '30';
  const page = Math.max(1, Number(params.get('page')) || 1);
  const q = new URLSearchParams({
    since: new Date(Date.now() - Number(days) * 86400000).toISOString(),
    page: String(page), size: '50',
  });
  if (kind) q.set('kind', kind);
  if (cause) q.set('cause', cause);
  const data = await get('/findings/changes?' + q.toString());
  const causes = data.causes || {};
  const href = o => '#/changes?' + new URLSearchParams(
    Object.entries({ kind, cause, days, ...o }).filter(([, v]) => v !== '' && v != null)).toString();
  const opt = (value, label, current) =>
    `<option value="${esc(value)}"${value === current ? ' selected' : ''}>${esc(label)}</option>`;
  view.innerHTML = `
    <div class="page-head"><div><h1>Recent changes</h1>
      <p>Findings that left the queue or came back into it, and the recorded reason: the re-import that
         stopped seeing it, the operator, the ticket closed in Jira, the workflow, the expired risk
         acceptance, the installed version that moved.</p></div>
      <div class="page-actions"><a class="btn btn-sm" href="#/findings">Open the findings list</a></div></div>
    ${scopeBanner()}
    <div class="filters">
      <select id="chg-kind" aria-label="Kind">${opt('', 'Closed and reopened', kind)}${opt('closed', 'Closed', kind)}${opt('reopened', 'Reopened', kind)}</select>
      <select id="chg-cause" aria-label="Cause">${opt('', 'Any cause', cause)}${
        Object.entries(causes).map(([k, label]) => opt(k, label, cause)).join('')}</select>
      <select id="chg-days" aria-label="Window">${opt('1', 'Last 24 hours', days)}${opt('7', 'Last 7 days', days)}${opt('30', 'Last 30 days', days)}${opt('90', 'Last 90 days', days)}</select>
    </div>
    ${data.truncated ? '<p class="small muted">Only the most recent state changes in this window were read; narrow the window to see the rest.</p>' : ''}
    ${table([
      { label: 'When', cell: r => fmtDate(r.at) },
      { label: 'Finding', cell: r => `<a href="#/findings/${esc(r.finding_id)}">${esc(r.finding_title || r.finding_id)}</a><div class="small muted">${esc(r.asset_name || '')}</div>` },
      { label: 'Change', cell: r => `${statePill(r.from || 'unknown')} → ${statePill(r.to || 'unknown')}` },
      { label: 'Cause', cell: r => causePill(r) },
      { label: 'By', cell: r => attributionActor(r.actor) },
      { label: 'Evidence', cell: r => attributionEvidence(r) },
    ], data.items || [], { emptyTitle: 'No closes or reopens in this window',
                           emptyHint: 'Widen the window or clear the cause filter.' })}
    <div class="pager">
      <span>${fmtNum(data.total)} change${data.total === 1 ? '' : 's'} · page ${fmtNum(data.page)} of ${fmtNum(Math.max(1, data.pages || 1))}</span>
      ${page > 1 ? `<a class="btn btn-sm" href="${href({ page: String(page - 1) })}">Previous</a>` : ''}
      ${page < (data.pages || 1) ? `<a class="btn btn-sm" href="${href({ page: String(page + 1) })}">Next</a>` : ''}
    </div>`;
  const go = () => {
    location.hash = href({ kind: $('#chg-kind', view).value, cause: $('#chg-cause', view).value,
                           days: $('#chg-days', view).value, page: '' });
  };
  ['#chg-kind', '#chg-cause', '#chg-days'].forEach(sel => { $(sel, view).onchange = go; });
});

/* ── Vulnerabilities ────────────────────────────────────────────────── */
route('vulnerabilities', listView({
  savedEntity: 'vulnerabilities',
  title: 'Vulnerabilities',
  blurb: 'The canonical vulnerability, independent of where it was found. One vulnerability, many findings.',
  endpoint: '/vulnerabilities',
  emptyHint: 'No CVE data yet. Feeds run on the intelligence schedule (Threat Intel → Schedule), from the host CLI or through POST /intel/feeds/nvd; correlation against the inventory follows.',
  filters: [{ name: 'q', label: 'CVE or title' }, { name: 'severity', label: 'Severity', options: ['critical', 'high', 'medium', 'low'] }],
  cols: [
    { label: 'Identifier', cell: r => `<span class="mono">${esc(r.cve_id || r.internal_ref || r.id)}</span>` },
    { label: 'Title', cell: r => esc((r.title || '').slice(0, 110) || '—') },
    { label: 'Severity', cell: r => sevPill(r.severity) },
    { label: 'CVSS', num: true, cell: r => `${fmtScore(r.cvss_score)}${r.cvss_version ? `<div class="small muted">v${esc(r.cvss_version)}</div>` : ''}` },
    { label: 'EPSS', num: true, cell: r => r.epss_score == null ? '—' : `${fmtPct(r.epss_score)}${r.epss_percentile == null ? '' : `<div class="small muted">p${Math.round(r.epss_percentile * 100)}</div>`}` },
    { label: 'KEV', cell: r => r.kev ? '<span class="pill pill-kev">KEV</span>' : '' },
    { label: 'Risk', num: true, cell: r => `<strong>${fmtScore(r.risk_score)}</strong><div class="small muted">${esc(r.risk_level || '')}</div>` },
    { label: 'State', cell: r => statePill(r.state) },
  ],
  detail: async (view, parts) => {
    const v = await get('/vulnerabilities/' + parts[0]);
    view.innerHTML = `
      <div class="page-head"><div><h1 class="mono">${esc(v.cve_id || v.internal_ref || v.id)}</h1>
        <p>${sevPill(v.severity)} ${statePill(v.state)} ${v.kev ? '<span class="pill pill-kev">KEV</span>' : ''}</p></div>
        <div class="page-actions">${v.cve_id ? `<a class="btn" href="#/intel/cve/${esc(v.cve_id)}">Threat intel</a>` : ''}</div></div>
      <div class="grid cols-4">
        <div class="card stat"><span class="label">VEYRS risk</span><span class="value">${fmtScore(v.risk_score)}</span><span class="hint">${esc(v.risk_level || '')}</span></div>
        <div class="card stat"><span class="label">CVSS</span><span class="value">${fmtScore(v.cvss_score)}</span><span class="hint mono small">${esc(v.cvss_vector || '')}</span></div>
        <div class="card stat"><span class="label">EPSS</span><span class="value">${v.epss_score == null ? '—' : fmtPct(v.epss_score)}</span><span class="hint">${v.epss_percentile == null ? '' : 'percentile ' + Math.round(v.epss_percentile * 100)}</span></div>
        <div class="card stat"><span class="label">Created</span><span class="value t-lg">${fmtDay(v.created_at)}</span></div>
      </div>
      <div class="card mt-4"><h2>${esc(v.title || 'Description')}</h2>
        <p>${esc(v.description || 'No description recorded.')}</p></div>`;
  },
}));

/* ── Assets ─────────────────────────────────────────────────────────── */
/* Mirrors veyrs.models.assets — same order, same values. */
const ASSET_TYPES = ['server', 'vm', 'container', 'kubernetes', 'workstation', 'laptop', 'firewall', 'router',
  'switch', 'network_device', 'application', 'database', 'website', 'api', 'cloud_resource', 'saas', 'iot', 'other'];
const CRITICALITY = ['critical', 'high', 'medium', 'low'];
const CLASSIFICATIONS = ['restricted', 'confidential', 'internal', 'public'];
const ENVIRONMENTS = ['production', 'staging', 'test', 'development', 'dr'];
/* Exposure is a four-level enum, not a boolean — "partner" and "isolated" carry
   their own weight in the risk engine and a checkbox would erase them. */
const EXPOSURES = ['internet', 'partner', 'internal', 'isolated'];
const exposurePill = e => {
  const v = String(e || 'internal');
  // Exposure is a property, not a severity (DESIGN_SYSTEM §12 item 4).
  const cls = v === 'internet' ? 'pill-net' : v === 'partner' ? 'st-warn' : v === 'isolated' ? 'st-ok' : 'st-neutral';
  return `<span class="pill ${cls}">${esc(titleCase(v))}</span>`;
};
const ipList = a => (a.ip_addresses || []).join(', ');

route('assets', listView({
  savedEntity: 'assets',
  setup: () => [
    { label: 'Import an inventory', href: '#/integrations?tab=import', note: 'a scanner export carries the hosts it scanned' },
    ...(activeScanning
      ? [{ label: 'Or enrol an agent', href: '#/scanner', note: 'it reports what is installed on the host it runs on' }]
      : []),
  ],
  title: 'Assets',
  blurb: 'The inventory every other number depends on. Criticality, exposure and data classification are what turn a CVSS score into a business risk.',
  endpoint: '/assets',
  emptyHint: 'Create one manually, or let a scanner import create them.',
  actions: `<button class="btn btn-primary" data-act="newAsset">New asset</button>`,
  showScope: true,
  filters: [
    { name: 'q', label: 'Name, hostname or IP' },
    { name: 'asset_type', label: 'Type', options: ASSET_TYPES },
    { name: 'criticality', label: 'Criticality', options: CRITICALITY },
    { name: 'exposure', label: 'Exposure', options: EXPOSURES },
    { name: 'environment', label: 'Environment', options: ENVIRONMENTS },
    // The two negations. They are separate SELECTs rather than extra options
    // on the ones above because "internal" and "not internet" are different
    // questions: the first names one of four values, the second covers the
    // other three AND whatever fifth value the enum grows later. A dropdown
    // that mixed them would answer the wrong one for anyone who read it as a
    // list of environments.
    { name: 'exclude_environment', label: 'Excluding environment',
      options: [{ value: 'production', label: 'Non-production only' }].concat(
        ENVIRONMENTS.map(e => ({ value: e, label: 'Not ' + e }))) },
    { name: 'exclude_exposure', label: 'Excluding exposure',
      options: [{ value: 'internet', label: 'Not internet-facing' }].concat(
        EXPOSURES.filter(e => e !== 'internet').map(e => ({ value: e, label: 'Not ' + e }))) },
    { name: 'team_id', label: 'Team', options: () => teamOptions() },
    // Unowned assets are invisible to every team-scoped identity at once, so
    // finding them has to be one click and not a saved search nobody runs.
    { name: 'unowned', label: 'Ownership', options: [{ value: 'true', label: 'No owning team' }] },
  ],
  cols: [
    { label: 'Name', cell: r => `<strong>${esc(r.name || r.hostname || r.id)}</strong><div class="small muted mono">${esc(r.hostname && r.hostname !== r.name ? r.hostname : '')} ${esc(ipList(r))}</div>` },
    { label: 'Type', cell: r => esc(titleCase(r.asset_type)) },
    { label: 'Environment', cell: r => esc(titleCase(r.environment || '—')) },
    { label: 'Criticality', cell: r => critPill(r.criticality) },
    { label: 'Exposure', cell: r => exposurePill(r.exposure) },
    { label: 'Classification', cell: r => esc(titleCase(r.data_classification || '—')) },
    { label: 'Team', cell: r => {
        const team = r.team_name || teamName(r.team_id);
        return team
          ? `<div>${esc(team)}</div>${r.owner_name ? `<div class="small muted">${esc(r.owner_name)}</div>` : ''}`
          : '<span class="muted small">unowned</span>';
      } },
    { label: 'Open findings', num: true, cell: r => fmtNum(r.open_findings) },
    { label: 'Max risk', num: true, cell: r => fmtScore(r.max_risk_score) },
  ],
  bulk: can('asset:write') ? [{ act: 'assign', label: 'Assign to team…', cls: 'btn-primary' }] : null,
  onBulk: async (act, ids, reload) => {
    if (act !== 'assign' || !ids.length) return;
    const r = await assignDialog({
      title: `Assign ${ids.length} asset${ids.length === 1 ? '' : 's'}`,
      note: 'Ownership here also decides which findings a team sees: a finding with no explicit assignee inherits the team that owns its asset.',
    });
    if (!r) return;
    const body = { asset_ids: ids };
    if (r.team === '__clear__') body.clear = ['team_id'];
    else body.team_id = r.team;
    try {
      const res = await post('/assets/bulk-assign', body);
      ok(`${res.changed_count} assigned${res.rejected_count ? `, ${res.rejected_count} skipped` : ''}.`);
      reload();
    } catch (e) { err(e.detail); }
  },
  detail: async (view, parts) => {
    const id = parts[0];
    const a = await get('/assets/' + id);
    let findings = { items: [] };
    try { findings = pageOf(await get('/findings' + qs({ asset_id: id, size: 25 }))); } catch { /* optional */ }
    view.innerHTML = `
      <div class="page-head"><div><h1>${esc(a.name || a.hostname)}</h1>
        <p>${critPill(a.criticality)} ${exposurePill(a.exposure)} <span class="muted small">${esc(titleCase(a.asset_type || ''))}${a.is_active === false ? ' · inactive' : ''}</span></p></div>
        <div class="page-actions"><button class="btn" id="rescan">Re-correlate</button><button class="btn btn-danger" id="delete">Delete</button></div></div>
      <div class="grid cols-4 mb-3">
        <div class="card stat ${tone('crit', a.open_findings)}"><span class="label">Open findings</span><span class="value">${fmtNum(a.open_findings)}</span></div>
        <div class="card stat"><span class="label">Max VEYRS risk</span><span class="value">${fmtScore(a.max_risk_score)}</span></div>
        <div class="card stat"><span class="label">First seen</span><span class="value t-lg">${fmtDay(a.first_seen_at || a.created_at)}</span></div>
        <div class="card stat"><span class="label">Last seen</span><span class="value t-lg">${fmtDay(a.last_seen_at)}</span></div>
      </div>
      <div class="grid cols-2">
        <div class="card"><h2>Identity</h2><dl class="kv">
          <dt>Name</dt><dd>${esc(a.name || '—')}</dd>
          <dt>Hostname</dt><dd>${esc(a.hostname || '—')}</dd>
          <dt>FQDN</dt><dd class="mono">${esc(a.fqdn || '—')}</dd>
          <dt>IP addresses</dt><dd class="mono">${esc(ipList(a) || '—')}</dd>
          <dt>Operating system</dt><dd>${esc(a.operating_system || '—')} ${esc(a.os_version || '')}</dd>
          <dt>Location</dt><dd>${esc(a.location || '—')}</dd>
          <dt>Environment</dt><dd>${esc(titleCase(a.environment || '—'))}</dd>
          <dt>Source</dt><dd>${esc(titleCase(a.source || '—'))}</dd>
          <dt>External ID</dt><dd class="mono">${esc(a.external_id || '—')}</dd>
        </dl></div>
        <div class="card"><h2>Business context</h2><dl class="kv">
          <dt>Criticality</dt><dd>${critPill(a.criticality)}</dd>
          <dt>Data classification</dt><dd>${esc(titleCase(a.data_classification || '—'))}</dd>
          <dt>Exposure</dt><dd>${exposurePill(a.exposure)}</dd>
          <dt>Owner</dt><dd class="mono small">${esc(a.owner_id || '—')}</dd>
          <dt>Team</dt><dd>${esc(a.team_name || teamName(a.team_id) || '—')}</dd>
          <dt>Business service</dt><dd class="mono small">${esc(a.business_service_id || '—')}</dd>
          <dt>Compensating controls</dt><dd>${(a.compensating_controls || []).map(t => `<span class="pill st-ok">${esc(t)}</span>`).join(' ') || '—'}</dd>
          <dt>Tags</dt><dd>${(a.tags || []).map(t => `<span class="pill st-neutral">${esc(t)}</span>`).join(' ') || '—'}</dd>
        </dl></div>
      </div>
      <div class="card mt-4"><h2>Installed products</h2>
        ${table([
          { label: 'Vendor', cell: r => esc(r.vendor || r.vendor_name || '—') },
          { label: 'Product', cell: r => esc(r.product || r.product_name || '—') },
          { label: 'Version', cell: r => `<span class="mono">${esc(r.version || '—')}</span>` },
          { label: 'CPE', cell: r => `<span class="mono small">${esc(r.cpe || '—')}</span>` },
        ], a.products || [], { emptyTitle: 'No products recorded', emptyHint: 'Without a product and version, VEYRS cannot correlate CVEs to this asset.' })}</div>
      <div class="card mt-4"><h2>Open findings</h2>
        ${table([
          { label: 'Title', cell: r => `<a href="#/findings/${esc(r.id)}">${esc(r.title || r.cve_id)}</a>` },
          { label: 'Severity', cell: r => sevPill(r.severity) },
          { label: 'Risk', num: true, cell: r => fmtScore(r.risk_score) },
          { label: 'State', cell: r => statePill(r.state) },
        ], findings.items, { emptyTitle: 'No findings on this asset' })}</div>
      <div class="card mt-4" id="fix-plan"><h2>Fix plan</h2><div class="loading">Loading…</div></div>`;
    loadFixPlan($('#fix-plan'), `/assets/${id}/fix-plan`);
    $('#rescan').onclick = async () => {
      try { const r = await post(`/assets/${id}/rescan`, {}); ok('Correlation run complete. ' + (r && r.matched !== undefined ? r.matched + ' matches.' : '')); render(); }
      catch (e) { err(e.detail); }
    };
    $('#delete').onclick = async () => {
      const c = await modal({ title: 'Delete asset', body: `<p>Delete <strong>${esc(a.name || a.hostname)}</strong>? Its findings go with it.</p>`, actions: [{ label: 'Delete', cls: 'btn-danger' }] });
      if (!c) return;
      try { await del('/assets/' + id); ok('Asset deleted.'); location.hash = '#/assets'; } catch (e) { err(e.detail); }
    };
  },
}));

window.newAsset = async function () {
  const sel = (name, values, dflt) =>
    `<select name="${name}">${values.map(t => `<option value="${t}" ${t === dflt ? 'selected' : ''}>${titleCase(t)}</option>`).join('')}</select>`;
  const r = await modal({
    title: 'New asset',
    body: `
      <div><label>Name *</label><input name="name" required placeholder="scanner-01"></div>
      <div><label>Hostname</label><input name="hostname" placeholder="web-01.example.com"></div>
      <div><label>IP addresses (comma separated)</label><input name="ips" placeholder="192.0.2.10"></div>
      <div><label>Type</label>${sel('asset_type', ASSET_TYPES, 'server')}</div>
      <div><label>Environment</label>${sel('environment', ENVIRONMENTS, 'production')}</div>
      <div><label>Criticality</label>${sel('criticality', CRITICALITY, 'medium')}</div>
      <div><label>Data classification</label>${sel('data_classification', CLASSIFICATIONS, 'internal')}</div>
      <div><label>Exposure</label>${sel('exposure', EXPOSURES, 'internal')}</div>
      <div><label>Location</label><input name="location"></div>
      <div><label>Tags (comma separated)</label><input name="tags"></div>
      <p class="small muted">Criticality, classification and exposure are risk inputs, not labels — the engine weights each one.</p>`,
    actions: [{ label: 'Create asset' }],
  });
  if (!r) return;
  const split = s => (s || '').split(',').map(x => x.trim()).filter(Boolean);
  try {
    const a = await post('/assets', {
      name: r.name,
      hostname: r.hostname || null,
      ip_addresses: split(r.ips),
      asset_type: r.asset_type,
      environment: r.environment,
      criticality: r.criticality,
      data_classification: r.data_classification,
      exposure: r.exposure,
      location: r.location || null,
      tags: split(r.tags),
    });
    ok('Asset created.');
    location.hash = '#/assets/' + a.id;
  } catch (e) { err(e.detail); }
};

/* ── Tickets ────────────────────────────────────────────────────────── */
/* ── Issues: the relation, when an external ITSM owns the work ─────────
 * This screen REPLACES Tickets for a tenant in external mode. It is not a
 * queue: VEYRS does not own the work and cannot move it. It is the record of
 * WHICH external issue was raised for WHICH finding on WHICH device and WHEN,
 * which is the thing an auditor asks for and the thing that would otherwise
 * exist only inside somebody else's Jira.
 *
 * Every column is answered from the `external_links` row alone. Fanning out one
 * Jira call per row is how a list view starts timing out at 200 findings and
 * gets blamed on VEYRS; Refresh is per-row and explicit.
 */
route('issues', listView({
  savedEntity: 'issues',
  title: 'Issues',
  blurb: () => `Remediation work for this organization lives in your ITSM. VEYRS keeps the
    relation: which issue covers which finding, on which device, raised when, due when.
    ${ticketingUsable ? '' : '<strong>The configured connector is missing or disabled — no new issue can be raised.</strong>'}`,
  endpoint: '/integrations/links',
  emptyHint: 'No external issue has been raised yet. Open a finding and press Raise issue, or select several in Findings.',
  setup: () => [
    { label: 'Choose who owns ticketing', href: '#/admin?tab=ticketing', note: 'internal queue, or an external ITSM' },
    { label: 'Configure the connector', href: '#/integrations?tab=itsm', note: 'base URL, credentials, project key' },
    { label: 'Raise the first issue', href: '#/findings?severity=critical', note: 'from a finding, or in bulk' },
  ],
  filters: [
    { name: 'q', label: 'Issue key, CVE or summary' },
    { name: 'severity', label: 'Severity', options: ['critical', 'high', 'medium', 'low'] },
    { name: 'remote_status', label: 'Remote status' },
    { name: 'is_active', label: 'Linked', options: [{ value: 'true', label: 'live' }, { value: 'false', label: 'unlinked' }] },
  ],
  cols: [
    { label: 'Issue', cell: r => (r.remote_url
        // rel=noopener: this opens a system whose page we do not control.
        ? `<a class="mono" href="${esc(r.remote_url)}" target="_blank" rel="noopener noreferrer">${esc(r.remote_key || r.remote_id)}</a>`
        : `<span class="mono">${esc(r.remote_key || r.remote_id)}</span>`)
      + `<div class="small muted">${esc(r.connector_name || r.system || '')}</div>`
      + (r.is_active ? '' : '<span class="pill st-neutral">unlinked</span>') },
    { label: 'What', cell: r => `<div>${esc(r.summary || '—')}</div>`
      + `<div class="small muted">${[r.cve_id, r.severity, r.risk_score != null ? 'risk ' + r.risk_score : null]
          .filter(Boolean).map(esc).join(' · ')}</div>` },
    { label: 'Device', cell: r => r.asset_name
        ? `<a href="#/assets/${esc(r.asset_id)}">${esc(r.asset_name)}</a>`
          + (r.asset_environment ? `<div class="small muted">${esc(r.asset_environment)}</div>` : '')
        : '<span class="muted small">—</span>' },
    { label: 'Remote status', cell: r => r.remote_status
        ? `<span class="pill st-neutral">${esc(r.remote_status)}</span>`
        : '<span class="muted small">never read</span>' },
    /* Printed next to the remote status on purpose. A finding VEYRS has since
       verified as fixed while its Jira issue is still open -- or the reverse --
       is the single most useful disagreement this screen can show, and it only
       exists because both sides are on the row. */
    { label: 'VEYRS finding', cell: r => r.finding_id
        ? `<a href="#/findings/${esc(r.finding_id)}">${esc(r.finding_state || 'open')}</a>`
        : '<span class="muted small">detached</span>' },
    { label: 'Dates', cell: r => `<div class="small">raised ${fmtDay(r.created_at)}</div>`
      + (r.due_at ? `<div class="small muted">due ${fmtDay(r.due_at)}</div>` : '')
      + (r.last_pulled_at ? `<div class="small muted">read ${fmtDay(r.last_pulled_at)}</div>` : '') },
    { label: '', cell: r => (can('ticket:write')
        ? `<button class="btn btn-sm" data-refresh="${esc(r.id)}">Refresh</button>`
          + (r.is_active ? ` <button class="btn btn-sm" data-unlink="${esc(r.id)}">Unlink</button>` : '')
        : '') + (r.last_error ? `<div class="small form-error">${esc(r.last_error)}</div>` : '') },
  ],
}));

/* Row actions for the Issues list. Delegated on the view rather than wired per
   row, because `listView` re-renders the table wholesale on every filter. */
document.addEventListener('click', async (e) => {
  const rb = e.target.closest('[data-refresh]');
  if (rb) {
    rb.disabled = true;
    try { const l = await post(`/integrations/links/${rb.dataset.refresh}/refresh`, {});
      // The route never throws for a remote failure -- it records it. So a
      // "success" with last_error set is the case to report honestly.
      if (l.last_error) err(l.last_error); else ok(`Status: ${l.remote_status || 'unchanged'}.`);
      render();
    } catch (ex) { err(ex.detail); rb.disabled = false; }
    return;
  }
  const ub = e.target.closest('[data-unlink]');
  if (!ub) return;
  const r = await modal({
    title: 'Unlink this issue',
    body: `<p class="small">VEYRS forgets the relation. <strong>The issue in the remote system is not
      closed, changed or deleted</strong> — VEYRS is the system of record for the finding, never for
      somebody else's queue.</p>
      <p class="small muted">The finding becomes eligible to have a new issue raised for it.</p>`,
    actions: [{ label: 'Unlink' }],
  });
  if (!r) return;
  try { await post(`/integrations/links/${ub.dataset.unlink}/unlink`, {}); ok('Unlinked.'); render(); }
  catch (ex) { err(ex.detail); }
});

route('tickets', listView({
  savedEntity: 'tickets',
  setup: [
    { label: 'Open the triage queue', href: '#/triage', note: 'one keystroke turns a finding into a ticket' },
    { label: 'Or let VEYRS open them', href: '#/automation?tab=tickets', note: 'automatic tickets above a risk threshold' },
  ],
  title: 'Tickets',
  blurb: 'ITIL-shaped work items. A <em>change</em> cannot close without approval — the graph enforces it, not a convention.',
  endpoint: '/tickets',
  emptyHint: 'Tickets are usually created by a workflow when a finding crosses a risk threshold.',
  actions: `<button class="btn btn-primary" data-act="newTicket">New ticket</button>`,
  filters: [
    { name: 'state', label: 'State' },
    { name: 'ticket_type', label: 'Type', options: ['incident', 'problem', 'change', 'remediation', 'service_request'] },
    { name: 'priority', label: 'Priority', options: ['critical', 'high', 'medium', 'low'] },
  ],
  cols: [
    { label: 'Reference', cell: r => `<span class="mono">${esc(r.reference || String(r.id).slice(0, 8))}</span>` },
    { label: 'Title', cell: r => esc(r.title) },
    { label: 'Type', cell: r => esc(titleCase(r.ticket_type)) },
    { label: 'Priority', cell: r => sevPill(r.priority) },
    { label: 'State', cell: r => statePill(r.state) },
    { label: 'Due', cell: r => r.sla_breached ? `<span class="pill sev-critical">Breached</span><div class="small muted">${fmtDay(r.due_at)}</div>` : fmtDay(r.due_at) },
    { label: 'External', cell: r => r.external_key ? `<span class="mono small">${esc(r.external_system || '')} ${esc(r.external_key)}</span>` : '' },
    { label: 'Created', cell: r => fmtDate(r.created_at) },
  ],
  detail: async (view, parts) => {
    const id = parts[0];
    const t = await get('/tickets/' + id);
    let links = [];
    try { links = (await get(`/integrations/tickets/${id}/links`)) || []; } catch { /* optional */ }
    const allowed = t.allowed_transitions || [];
    view.innerHTML = `
      <div class="page-head"><div><h1>${esc(t.title)}</h1>
        <p><span class="mono">${esc(t.reference || id)}</span> · ${esc(titleCase(t.ticket_type || ''))} ${statePill(t.state)} ${sevPill(t.priority)}
          ${t.sla_breached ? '<span class="pill sev-critical">SLA breached</span>' : ''}</p></div>
        <div class="page-actions"><button class="btn btn-primary" id="tr" ${allowed.length ? '' : 'disabled'}>Transition…</button><button class="btn" id="cm">Comment…</button><button class="btn" id="push">Push to ITSM…</button></div></div>
      <div class="grid cols-2">
        <div class="card"><h2>Detail</h2><dl class="kv">
          <dt>Description</dt><dd>${esc(t.description || '—')}</dd>
          <dt>Resolution</dt><dd>${esc(t.resolution || '—')}</dd>
          <dt>Team</dt><dd>${esc(teamName(t.assigned_team_id) || '—')}</dd>
          <dt>Assignee</dt><dd class="mono small">${esc(t.assigned_user_id || '—')}</dd>
          <dt>Finding</dt><dd>${t.finding_id ? `<a href="#/findings/${esc(t.finding_id)}" class="mono small">${esc(t.finding_id)}</a>` : '—'}</dd>
          <dt>Asset</dt><dd>${t.asset_id ? `<a href="#/assets/${esc(t.asset_id)}" class="mono small">${esc(t.asset_id)}</a>` : '—'}</dd>
          ${t.ticket_type === 'change' ? `<dt>Change type</dt><dd>${esc(titleCase(t.change_type || '—'))}</dd>
          <dt>Approver</dt><dd class="mono small">${esc(t.approver_id || '— not yet approved')}</dd>
          <dt>Approved</dt><dd>${fmtDate(t.approved_at)}</dd>
          <dt>Window</dt><dd>${fmtDate(t.scheduled_start)} → ${fmtDate(t.scheduled_end)}</dd>` : ''}
          <dt>Due</dt><dd>${fmtDate(t.due_at)}</dd>
          <dt>Resolved</dt><dd>${fmtDate(t.resolved_at)}</dd>
          <dt>Closed</dt><dd>${fmtDate(t.closed_at)}</dd>
          <dt>Created</dt><dd>${fmtDate(t.created_at)}</dd>
          <dt>Labels</dt><dd>${(t.labels || []).map(l => `<span class="pill st-neutral">${esc(l)}</span>`).join(' ') || '—'}</dd>
          <dt>Next states</dt><dd>${allowed.map(s => `<span class="pill st-neutral">${esc(titleCase(s))}</span>`).join(' ') || '<span class="muted">terminal state</span>'}</dd>
        </dl></div>
        <div class="card"><h2>External links</h2>
          ${table([
            { label: 'Connector', cell: r => esc(r.connector_name || r.connector || '—') },
            { label: 'Remote key', cell: r => r.url ? `<a href="${esc(r.url)}" target="_blank" rel="noopener" class="mono">${esc(r.remote_key || r.external_id)}</a>` : `<span class="mono">${esc(r.remote_key || r.external_id || '—')}</span>` },
            { label: 'Synced', cell: r => fmtDate(r.last_synced_at) },
          ], links, { emptyTitle: 'Not pushed anywhere', emptyHint: 'Configure a ServiceNow or Jira connector under Integrations.' })}</div>
      </div>
      <div class="grid cols-2 mt-4">
        <div class="card"><h2>Comments</h2>
          ${table([
            { label: 'When', cell: r => fmtDate(r.created_at) },
            { label: 'Who', cell: r => esc(r.author_label || r.actor_label || '—') },
            { label: 'Comment', cell: r => esc(r.body || '') },
          ], t.comments || [], { emptyTitle: 'No comments yet' })}</div>
        <div class="card"><h2>History</h2>
          ${table([
            { label: 'When', cell: r => fmtDate(r.created_at || r.occurred_at) },
            { label: 'Event', cell: r => statePill(r.event || r.kind || r.type) },
            { label: 'Detail', cell: r => esc((r.note || r.message || '').slice(0, 120)) },
          ], t.events || [], { emptyTitle: 'No events yet' })}</div>
      </div>`;
    $('#tr').onclick = async () => {
      // The backend owns the ITIL graph; offer only what it will accept.
      const r = await modal({
        title: 'Transition ticket',
        body: `<div><label>Target state</label><select name="state">${allowed.map(s => `<option value="${esc(s)}">${esc(titleCase(s))}</option>`).join('')}</select></div>
          <div><label>Note</label><textarea name="note"></textarea></div>
          <div><label>Resolution (required by closing states)</label><input name="resolution"></div>`,
        actions: [{ label: 'Transition' }],
      });
      if (!r) return;
      try { await post(`/tickets/${id}/transition`, { state: r.state, note: r.note || null, resolution: r.resolution || null }); ok('Transitioned.'); render(); } catch (e) { err(e.detail); }
    };
    $('#cm').onclick = async () => {
      const r = await modal({ title: 'Add comment', body: `<div><label>Comment</label><textarea name="body" required></textarea></div>`, actions: [{ label: 'Comment' }] });
      if (!r) return;
      try { await post(`/tickets/${id}/comments`, { body: r.body }); ok('Comment added.'); render(); } catch (e) { err(e.detail); }
    };
    $('#push').onclick = async () => {
      const conns = await get('/integrations/connectors').catch(() => []);
      const list = Array.isArray(conns) ? conns : (conns.items || []);
      if (!list.length) return err('No ITSM connector is configured.');
      const r = await modal({ title: 'Push to ITSM', body: `<div><label>Connector</label><select name="cid">${list.map(c => `<option value="${esc(c.id)}">${esc(c.name)} (${esc(c.kind || c.provider)})</option>`).join('')}</select></div>`, actions: [{ label: 'Push' }] });
      if (!r) return;
      try { await post(`/integrations/connectors/${r.cid}/push/${id}`, {}); ok('Pushed.'); render(); } catch (e) { err(e.detail); }
    };
  },
}));

window.newTicket = async function () {
  const r = await modal({
    title: 'New ticket',
    body: `<div><label>Title *</label><input name="title" required></div>
      <div><label>Type</label><select name="ticket_type">${['remediation', 'incident', 'problem', 'change', 'service_request'].map(t => `<option value="${t}">${titleCase(t)}</option>`).join('')}</select></div>
      <div><label>Priority</label><select name="priority">${CRITICALITY.map(t => `<option value="${t}" ${t === 'medium' ? 'selected' : ''}>${titleCase(t)}</option>`).join('')}</select></div>
      <div><label>Description</label><textarea name="description"></textarea></div>`,
    actions: [{ label: 'Create' }],
  });
  if (!r) return;
  try { const t = await post('/tickets', { title: r.title, ticket_type: r.ticket_type, priority: r.priority, description: r.description || null }); ok('Ticket created.'); location.hash = '#/tickets/' + t.id; }
  catch (e) { err(e.detail); }
};

/* ── CVSS calculator (brief §25) ────────────────────────────────────── */
const CVSS_VERSIONS = ['2.0', '3.0', '3.1', '4.0'];

route('cvss', async (view, _p, params) => {
  const version = params.get('v') || '3.1';
  // Provenance is per visit: arriving at the calculator fresh must not show
  // chips left over from a bulletin somebody analysed twenty minutes ago.
  assistSource = {};
  const spec = await get('/cvss/metrics/' + version);
  const selected = {};
  (spec.groups || []).forEach(g => g.metrics.forEach(m => {
    if (m.mandatory) selected[m.abbrev] = m.values[0].value;
  }));

  view.innerHTML = `
    <div class="page-head"><div><h1>CVSS Calculator</h1>
      <p>Scores come from the VEYRS engine, which is validated against FIRST's official reference vectors — 4,382 of them, every release. Nothing here is an approximation.</p></div>
      <div class="page-actions"><button class="btn btn-primary" id="assist-btn">Analyse a bulletin…</button></div></div>
    <div class="tabs">${CVSS_VERSIONS.map(v => `<button data-v="${v}" class="${v === version ? 'active' : ''}">CVSS v${v}</button>`).join('')}</div>
    <div class="cvss-layout">
      <div class="card" id="metrics"></div>
      <div class="stack">
        <div class="card score-panel" id="score"><div class="loading">Select metrics…</div></div>
        <div class="card"><h2>Load a vector</h2>
          <input id="vec-in" class="mono" placeholder="CVSS:3.1/AV:N/AC:L/…">
          <div class="row mt-2"><button class="btn btn-sm" id="vec-load">Parse &amp; load</button>
          <button class="btn btn-sm" id="vec-validate">Validate</button></div></div>
      </div>
    </div>
    <div class="card mt-4" id="explain-card" hidden><h2>Metric breakdown</h2><div id="explain-body"></div></div>`;

  view.querySelector('.tabs').onclick = e => { if (e.target.dataset.v) location.hash = '#/cvss?v=' + e.target.dataset.v; };

  function paint() {
    $('#metrics').innerHTML = (spec.groups || []).map(g => `
      <div class="metric-group"><h3>${esc(g.group)}</h3>
        ${g.metrics.map(m => {
          // Several specifications already expose an explicit "Not Defined"
          // value (X). Adding our own would show the option twice.
          const hasUndefined = m.values.some(v => v.value === 'X' || /not\s*defined/i.test(v.name || ''));
          // A metric the bulletin assistant filled in carries a chip saying
          // which half of the answer it came from. Once the analyst clicks a
          // different value it is theirs, so the chip flips to "you" -- a
          // provenance mark that survives being overruled is a lie.
          const prov = assistSource[m.abbrev];
          return `<div class="metric">
          <div class="metric-name">${esc(m.name)}<span class="abbr">${esc(m.abbrev)}</span>${
            prov ? `<span class="prov prov-${prov === 'bulletin' ? 'bulletin' : 'model'}">${esc(prov)}</span>` : ''}</div>
          <div class="opts">
            ${(m.mandatory || hasUndefined) ? '' : `<button class="opt ${selected[m.abbrev] === undefined ? 'on' : ''}" data-m="${esc(m.abbrev)}" data-v="">Not defined</button>`}
            ${m.values.map(v => {
              const isUndef = v.value === 'X' || /not\s*defined/i.test(v.name || '');
              // With nothing chosen, the spec's own "Not Defined" is the state.
              const on = selected[m.abbrev] === v.value || (selected[m.abbrev] === undefined && isUndef);
              return `<button class="opt ${on ? 'on' : ''}" data-m="${esc(m.abbrev)}" data-v="${esc(v.value)}">${esc(v.name)}</button>`;
            }).join('')}
          </div></div>`;
        }).join('')}
      </div>`).join('');
    $$('#metrics .opt').forEach(b => b.onclick = () => {
      const m = b.dataset.m;
      if (b.dataset.v === '') delete selected[m]; else selected[m] = b.dataset.v;
      delete assistSource[m];      // the analyst just took ownership of this one
      paint(); score();
    });
  }

  function buildVector() {
    const parts = Object.entries(selected).map(([k, v]) => `${k}:${v}`);
    if (!parts.length) return null;
    return version === '2.0' ? parts.join('/') : `CVSS:${version}/${parts.join('/')}`;
  }

  async function score() {
    const vector = buildVector();
    if (!vector) return;
    try {
      const r = await post('/cvss/score', { vector });
      const sev = String(r.severity || '').toLowerCase();
      $('#score').innerHTML = `
        <h2>Score</h2>
        <div class="score-big" style="color:${sevColour(sev)}">${fmtScore(r.score ?? r.base_score)}</div>
        <div>${sevPill(r.severity)} ${r.nomenclature ? `<span class="pill st-neutral">${esc(r.nomenclature)}</span>` : ''}</div>
        <div class="score-vector">${esc(r.vector)}</div>
        <div class="score-sub">
          <div>Base<b>${fmtScore(r.base_score)}</b></div>
          <div>Temporal / Threat<b>${fmtScore(r.temporal_score)}</b></div>
          <div>Environmental<b>${fmtScore(r.environmental_score)}</b></div>
          <div>Version<b>${esc(r.version)}</b></div>
        </div>
        <div class="row mt-3">
          <button class="btn btn-sm" id="copy">Copy vector</button>
          <button class="btn btn-sm" id="explain-btn">Explain</button>
        </div>`;
      $('#copy').onclick = () => { navigator.clipboard.writeText(r.vector); ok('Vector copied.'); };
      $('#explain-btn').onclick = async () => {
        $('#explain-card').hidden = false;
        const x = await post('/cvss/explain', { vector: r.vector }).catch(() => null);
        const metrics = (x && (x.metrics || x.explanation)) || r.metrics || [];
        $('#explain-body').innerHTML = table([
          { label: 'Group', cell: m => esc(m.group) },
          { label: 'Metric', cell: m => `${esc(m.name)} <span class="mono muted">(${esc(m.abbrev)})</span>` },
          { label: 'Value', cell: m => esc(m.value_name || m.value) },
          { label: 'Weight', num: true, cell: m => m.weight === undefined ? '—' : m.weight },
          { label: 'Source', cell: m => m.defaulted ? '<span class="muted small">default</span>' : 'selected' },
        ], metrics);
        if (x && x.narrative) $('#explain-body').insertAdjacentHTML('afterbegin', `<p>${esc(x.narrative)}</p>`);
      };
    } catch (e) {
      $('#score').innerHTML = `<h2>Score</h2><p class="muted">${esc(e.detail)}</p><div class="score-vector">${esc(vector)}</div>`;
    }
  }

  $('#vec-load').onclick = async () => {
    const v = $('#vec-in').value.trim();
    if (!v) return;
    try {
      const r = await post('/cvss/score', { vector: v });
      if (String(r.version) !== String(version)) { location.hash = '#/cvss?v=' + r.version; return; }
      Object.keys(selected).forEach(k => delete selected[k]);
      (r.metrics || []).forEach(m => { if (!m.defaulted) selected[m.abbrev] = m.value; });
      paint(); score();
    } catch (e) { err(e.detail); }
  };
  $('#vec-validate').onclick = async () => {
    const v = $('#vec-in').value.trim();
    try { const r = await post('/cvss/validate', { vector: v }); (r.valid ?? true) ? ok('Vector is valid (v' + (r.version || '?') + ').') : err(r.detail || 'Invalid vector.'); }
    catch (e) { err(e.detail); }
  };

  $('#assist-btn').onclick = () => assistDialog(version, (metrics, source) => {
    Object.keys(selected).forEach(k => delete selected[k]);
    Object.entries(metrics).forEach(([k, v]) => { selected[k] = v; });
    assistSource = source;
    paint(); score();
  });

  paint();
  score();
});

/* ── Bulletin assistant ────────────────────────────────────────────────
   A bulletin answers the calculator's eight questions in prose, in a
   different order, usually without naming a single metric. This reads it and
   fills the form in — and, more usefully, tells you whether the thing it
   describes is on any of your assets.

   Three properties are deliberate and visible in the UI, because they are the
   difference between a helper and something that quietly makes a report
   wrong:

   * A vector the bulletin PRINTS wins outright. The model is never asked to
     second-guess a number the vendor published, and the chip on each metric
     says which of the two it came from.
   * The score is never the model's. Whatever vector comes out is scored by
     the same engine the rest of the page uses.
   * Nothing is applied. It fills the form; the analyst confirms it. */
function assistDialog(version, apply) {
  return modal({
    title: 'Analyse a security bulletin',
    wide: true,
    body: `
      <p class="small muted">Paste the advisory text — a vendor PSIRT page, a CERT
        bulletin, a mailing-list post. VEYRS pulls out the CVE identifiers and any
        CVSS vector it already carries, checks both against <strong>your</strong>
        inventory, and asks the model only about the metrics nothing else could
        settle.</p>
      <div><label>Bulletin text *</label>
        <textarea name="text" rows="12" placeholder="Paste the advisory here…"></textarea></div>
      <label class="inline mt-2"><input type="checkbox" name="use_ai" checked>
        Ask the AI model for the metrics the text does not spell out</label>
      <p class="field-help">Untick to run only the deterministic half — extraction plus
        the inventory cross-check. Nothing leaves your infrastructure either way unless
        your AI policy allows an external provider, and the result says which was used.</p>
      <div id="assist-out"></div>`,
    actions: [{
      label: 'Analyse', keepOpen: true,
      run: async (form, root) => {
        const out = root.querySelector('#assist-out');
        if (!form.text || form.text.trim().length < 20) { err('Paste the bulletin text first.'); return false; }
        out.innerHTML = '<div class="loading">Reading the bulletin…</div>';
        let r;
        try {
          r = await post('/cvss/assist', { text: form.text, version, use_ai: form.use_ai });
        } catch (e) { out.innerHTML = `<p class="muted">${esc(e.detail)}</p>`; return false; }

        const src = k => {
          const s = r.metric_source[k];
          return `<span class="prov prov-${s === 'bulletin' ? 'bulletin' : 'model'}">${s}</span>`;
        };
        const inv = r.inventory || {};
        const affected = (inv.cves || []).reduce((n, c) => n + (c.open_findings || 0), 0);

        out.innerHTML = `
          <div class="card mt-4">
            <h3>Does this affect you?</h3>
            ${(inv.cves || []).length ? `<ul class="small">${(inv.cves || []).map(c => `
              <li><a href="#/intel/cve/${esc(c.cve_id)}" class="mono">${esc(c.cve_id)}</a> —
                ${c.in_catalogue
                  ? `${c.open_findings ? `<strong>${fmtNum(c.open_findings)} open finding(s)</strong> in your estate`
                                        : 'no open findings in your estate'}${
                      c.internet_exposed ? `, ${fmtNum(c.internet_exposed)} on internet-facing assets` : ''}${
                      c.kev ? ' · <span class="pill pill-kev">KEV</span>' : ''}${
                      c.epss_score != null ? ` · EPSS ${fmtPct(c.epss_score)}` : ''}`
                  : '<span class="muted">not in the VEYRS CVE catalogue — either it is very new, or the identifier is wrong</span>'}
              </li>`).join('')}</ul>`
              : '<p class="small muted">The text names no CVE identifier.</p>'}
            ${(inv.products || []).length ? `<p class="small mt-2">Software the bulletin names that you actually run:
              ${(inv.products || []).map(p => `<span class="pill st-neutral">${esc(p.vendor || '?')} ${esc(p.product)} ×${fmtNum(p.installations)}</span>`).join(' ')}</p>`
              : '<p class="small muted mt-2">None of the software it names is in your inventory — which may mean you are not affected, or may mean that product is not mapped to a CPE on your assets.</p>'}
            ${inv.scope_restricted ? '<p class="small muted">These counts cover the assets your role can see, not the whole estate.</p>' : ''}
            ${affected ? '' : '<p class="small muted">Nothing in your estate matches — the vector below is still worth having for the record.</p>'}
          </div>

          <div class="card mt-3">
            <h3>Proposed vector</h3>
            ${r.vector
              ? `<p class="mono">${esc(r.vector)} — <strong>${fmtScore((r.score || {}).score)}</strong> ${sevPill((r.score || {}).severity)}</p>`
              : '<p class="muted small">Not enough to build a complete vector yet.</p>'}
            <p class="small">${Object.keys(r.metrics).map(k => `<span class="mono">${esc(k)}:${esc(r.metrics[k])}</span>${src(k)}`).join(' &nbsp; ')}</p>
            ${(r.needs_decision || []).length ? `<p class="explainer-warn small">Still yours to decide:
              ${esc((r.needs_decision || []).join(', '))}. The bulletin does not say, and a guess here is
              the kind that lands in a report.</p>` : ''}
            ${(r.ai || {}).summary ? `<p class="small mt-2"><strong>Model summary.</strong> ${esc(r.ai.summary)}</p>` : ''}
            ${(r.ai || {}).rationale ? `<details class="mt-2"><summary class="small muted">Why the model chose each metric</summary>
              <dl class="kv mt-2">${Object.entries(r.ai.rationale).map(([k, v]) =>
                `<dt class="mono">${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')}</dl></details>` : ''}
            ${(r.ai || {}).used && !(r.ai || {}).allowed
              ? `<p class="small muted">The model was not consulted: ${esc(r.ai.block_reason || 'blocked by your AI policy')}.
                 Everything above came from the text and your inventory.</p>`
              : ((r.ai || {}).used ? `<p class="small muted">Model: <span class="mono">${esc(r.ai.provider)}/${esc(r.ai.model)}</span>${
                    r.ai.external ? ' — <strong>external provider</strong>' : ' (local)'}.
                 The score itself is computed by VEYRS, never by the model.</p>` : '')}
            ${((r.ai || {}).rejected || []).length ? `<p class="small muted">Discarded as not valid CVSS ${esc(version)}:
              ${esc(r.ai.rejected.join('; '))}.</p>` : ''}
            ${r.truncated ? `<p class="small muted">Only the first ${fmtNum(r.chars_analysed)} characters were analysed.</p>` : ''}
            ${Object.keys(r.metrics).length
              ? '<button type="button" class="btn btn-primary mt-3" id="assist-apply">Fill the calculator with this</button>'
              : ''}
          </div>`;

        const applyBtn = out.querySelector('#assist-apply');
        if (applyBtn) applyBtn.onclick = () => {
          apply(r.metrics, r.metric_source);
          ok('Calculator filled — check the metrics marked “model” before you use the score.');
          root.remove();
        };
        return false;   // keep the dialog open: the result IS the point
      },
    }],
  });
}

/* ── Threat intelligence ────────────────────────────────────────────── */
route('intel', async (view, parts, params) => {
  if (parts[0] === 'cve' && parts[1]) return cveDetail(view, parts[1]);
  if (parts[0] === 'cwe' && parts[1]) return cweDetail(view, parts[1]);
  const tab = params.get('tab') || 'cve';
  // The estate lens. Default ON, and it lives in the URL rather than in a
  // module variable so a bookmarked or pasted link carries the same view the
  // person who sent it was looking at — a screenshot of "17 CVEs" is not the
  // same claim as a screenshot of "17 of 359 353".
  // Three lenses, narrowest first. 'exposed' (default since 0.35.1) = an open
  // finding exists, i.e. a version was actually evaluated; 'estate' = the CVE
  // names a product you run, versions NOT compared (Heartbleed shows up for
  // OpenSSL 3.0); 'all' = the catalogue.
  const scope = ['estate', 'all'].includes(params.get('scope')) ? params.get('scope') : 'exposed';
  const scoped = scope !== 'all';
  const health = await get('/intel/health').catch(() => ({}));
  // /intel/health nests everything: counts.{cve,epss,kev} plus one block per
  // feed with status/age_hours/watermark. The flat cve_count-style fields the
  // first version read here never existed — the cards showed "—" over a loaded
  // dictionary, which is exactly the misread the resolved/placeholder work in
  // phase 25 exists to prevent.
  const counts = health.counts || {};
  const feedPill = (k) => {
    const f = health[k];
    if (!f) return `<span class="pill st-neutral mono">${k}: ?</span>`;
    const okF = f.status === 'ok';
    const age = Number(f.age_hours);
    return `<span class="pill ${okF ? 'st-ok' : 'st-warn'} mono" title="watermark ${esc(f.watermark || '—')}">${k}: ${okF ? (isFinite(age) ? age.toFixed(0) + ' h ago' : 'ok') : esc(f.status || 'unknown')}</span>`;
  };
  const ages = ['nvd', 'epss', 'kev'].map(k => Number((health[k] || {}).age_hours)).filter(isFinite);
  const inv = health.inventory || {};
  // Under the estate lens the inventory IS the boundary of what you can see, so
  // a broken inventory and a clean estate render the same empty table. Say so
  // where the numbers are, not in a document nobody opens during an incident.
  const warnStyle = 'border-left-color:var(--veyrs-high);border-color:color-mix(in srgb,var(--veyrs-high) 30%,transparent);background:color-mix(in srgb,var(--veyrs-high) 6%,var(--surface))';
  let invWarning = '';
  if (!inv.installations) {
    invWarning = `<div class="scope-banner" role="status" style="${warnStyle}">
      <strong>No software inventory.</strong>
      <span>Nothing on this screen can be scoped to your estate, because nothing has been
      inventoried yet. The filtered lists below will look empty — that is a missing inventory,
      not a clean estate. Feed it from ${activeScanning
        ? '<a href="#/scanner">the execution agent</a>, a '
        : ''}<a href="#/integrations?tab=scanners">scanner connector</a>, or a credentialled scan import.</span></div>`;
  } else if (inv.unresolved) {
    invWarning = `<div class="scope-banner" role="status" style="${warnStyle}">
      <strong>${fmtNum(inv.unresolved)} of ${fmtNum(inv.installations)} installations did not resolve to a dictionary entry.</strong>
      <span>Their CVEs cannot appear under the estate filter at all — not as “unmatched”, but as
      nothing. Until they resolve, treat the counters below as a floor.</span></div>`;
  }
  // The hourly tick drives the feeds, the SLA sweep and housekeeping. Shown only
  // when the API reports it (GET /intel/health -> tick.status): never_run, ok,
  // failing (last run failed) or stale (no success within stale_after_minutes).
  const tick = health.tick;
  const tickBad = tick && tick.status && tick.status !== 'ok';
  const tickAge = tick && Number.isFinite(Number(tick.minutes_since_success))
    ? (tick.minutes_since_success >= 120 ? Math.round(tick.minutes_since_success / 60) + ' h' : Math.round(tick.minutes_since_success) + ' min') + ' ago' : 'never';
  const tickPill = tick ? `<span class="pill ${tickBad ? 'st-warn' : 'st-ok'} mono" title="last success ${esc(tick.last_success_at || '—')}">tick: ${tickBad ? esc(String(tick.status).replace('_', ' ')) : tickAge}</span>` : '';
  if (tickBad) {
    invWarning += `<div class="scope-banner" role="status" style="${warnStyle}">
      <strong>The hourly maintenance tick is ${esc(String(tick.status).replace('_', ' '))}.</strong>
      <span>Last success: ${esc(tickAge)} (expected within ${fmtNum(tick.stale_after_minutes || 0)} min).
      Feeds, the SLA sweep, notification dispatch and housekeeping all ride on it${tick.last_detail ? ' — ' + esc(String(tick.last_detail).slice(0, 200)) : ''}.
      Check the timer that runs <span class="mono">scripts/sync-intel.sh</span> on the application node.</span></div>`;
  }
  view.innerHTML = `
    <div class="page-head"><div><h1>Threat Intelligence</h1>
      <p>Authoritative feeds only: MITRE CWE, NVD, FIRST EPSS and the CISA KEV catalog. How often each one
      refreshes is <a href="#/intel?tab=schedule">a setting</a>, not a hard-coded timer — the pills below are
      each feed's freshness, and a red one means the last run needs looking at, not that a button needs
      pressing.</p>
      <p class="small muted">The catalogue is deliberately larger than your estate: correlation is computed
      <em>from</em> it, so a CVE that was never ingested cannot match an asset — it is simply absent, which
      reads as “not affected”. The lists below therefore show <strong>only CVEs with an open finding on
      your assets</strong> by default; “Software you run” widens to every CVE that names one of your products
      (versions not compared), and the whole catalogue is one more click away.</p></div>
      <div class="page-actions">${feedPill('nvd')} ${feedPill('epss')} ${feedPill('kev')} ${tickPill}</div></div>
    ${invWarning}
    <div class="grid cols-4 mb-3">
      <div class="card stat crit"><span class="label">CVEs affecting you</span>
        <span class="value">${fmtNum(counts.cve_exposed)}</span>
        <span class="hint">with an open finding · ${fmtNum(counts.cve_affecting_estate)} name software you run · ${fmtNum(counts.cve)} in the catalogue</span></div>
      <div class="card stat crit"><span class="label">KEV affecting you</span>
        <span class="value">${fmtNum(counts.kev_exposed)}</span>
        <span class="hint">with an open finding · ${fmtNum(counts.kev_affecting_estate)} name software you run · ${fmtNum(counts.kev)} known exploited</span></div>
      <div class="card stat"><span class="label">Products resolved</span>
        <span class="value">${fmtNum(inv.distinct_products)}</span>
        <span class="hint">${fmtNum(inv.installations)} installations${inv.unresolved ? ' · ' + fmtNum(inv.unresolved) + ' unresolved' : ''}</span></div>
      <div class="card stat"><span class="label">Freshest feed</span>
        <span class="value t-lg">${ages.length ? Math.min(...ages).toFixed(1) + ' h ago' : '—'}</span>
        <span class="hint">${fmtNum(counts.epss)} EPSS scores</span></div>
    </div>
    <div class="tabs">
      ${[['cve', 'CVE'], ['kev', 'CISA KEV'], ['news', 'News'], ['sources', 'Sources'], ['runs', 'Feed runs'], ['schedule', 'Schedule']]
        .map(([k, l]) => `<button data-t="${k}" class="${tab === k ? 'active' : ''}">${l}</button>`).join('')}
    </div><div id="intel-body"><div class="loading">Loading…</div></div>`;

  // Carry the lens across tabs: switching CVE → KEV and silently re-widening to
  // the whole catalogue is how somebody ends up reading 1 678 KEV entries as
  // though they were theirs.
  view.querySelector('.tabs').onclick = e => {
    if (e.target.dataset.t) location.hash = '#/intel?tab=' + e.target.dataset.t + (scope === 'exposed' ? '' : '&scope=' + scope);
  };

  /* The switch, and why it is two labelled buttons rather than a checkbox: the
     number of rows behind each option is part of the control. "Estate (2 578)"
     vs "Catalogue (359 353)" answers "what am I not seeing" without a click. */
  const scopeSwitch = (exposedN, estateN, allN, noun) => {
    const btn = (k, label, n) => `<button class="btn btn-sm ${scope === k ? 'btn-primary' : ''}" data-scope="${k}">${label}${n == null ? '' : ' (' + fmtNum(n) + ')'}</button>`;
    const say = {
      exposed: 'Showing only ' + noun + ' with an open finding on at least one of your assets: the installed version was evaluated and is affected.',
      estate: 'Showing ' + noun + ' that name a product you run. Versions are NOT compared: a 0 under “Your assets” means no open finding, usually because your version is outside the affected range.',
      all: 'Showing all ' + noun + ' in the catalogue, including software you do not run.',
    }[scope];
    return `<div class="row mb-2">
      ${btn('exposed', 'Affecting you', exposedN)}
      ${btn('estate', 'Software you run', estateN)}
      ${btn('all', 'Whole catalogue', allN)}
      <span class="small muted">${say}</span>
    </div>`;
  };
  const wireScope = () => {
    (view.querySelectorAll('[data-scope]') || []).forEach(b => {
      b.onclick = () => {
        location.hash = '#/intel?tab=' + tab + (b.dataset.scope === 'exposed' ? '' : '&scope=' + b.dataset.scope);
      };
    });
  };

  const body = $('#intel-body');
  if (tab === 'cve') {
    const d = pageOf(await get('/intel/cve' + qs({
      size: 50, q: params.get('q') || '', affects_estate: scoped, exposed: scope === 'exposed',
    })));
    body.innerHTML = scopeSwitch(counts.cve_exposed, counts.cve_affecting_estate, counts.cve, 'CVEs') + table([
      { label: 'CVE', cell: r => `<a href="#/intel/cve/${esc(r.cve_id)}" class="mono">${esc(r.cve_id)}</a>` },
      { label: 'Published', cell: r => fmtDay(r.published_at) },
      { label: 'CVSS', num: true, cell: r => fmtScore(r.cvss_score ?? r.cvss_base_score) },
      { label: 'Severity', cell: r => sevPill(r.severity) },
      { label: 'EPSS', num: true, cell: r => r.epss_score == null ? '—' : fmtPct(r.epss_score) },
      { label: 'KEV', cell: r => r.kev ? `<span class="pill pill-kev">KEV</span>${r.kev_due_date ? `<div class="small muted">due ${fmtDay(r.kev_due_date)}</div>` : ''}` : '' },
      { label: 'Your assets', num: true, cell: r => r.affected_assets ? `<strong class="sev-critical">${fmtNum(r.affected_assets)}</strong>` : fmtNum(r.affected_assets ?? 0) },
      { label: 'Age', num: true, cell: r => r.age_days == null ? '—' : r.age_days + 'd' },
      { label: 'Title', cell: r => esc((r.title || '').slice(0, 80)) },
    ], d.items, scope === 'exposed'
      ? { emptyTitle: 'No open finding is linked to a CVE',
          emptyHint: 'Either nothing is open, or correlation and scans have not produced findings yet. “Software you run” lists the CVEs that name your products before versions are compared.' }
      : scoped
      ? { emptyTitle: 'Nothing in the catalogue names software you run',
          emptyHint: 'That is either genuinely good news or an inventory that has not resolved. Check the Products resolved counter above, then switch to the whole catalogue to confirm the feeds have data.' }
      : { emptyTitle: 'No CVE records', emptyHint: 'Feeds run on the intelligence schedule (Threat Intel → Schedule), from the host CLI or through POST /intel/feeds/nvd.' });
    wireScope();
  } else if (tab === 'kev') {
    const d = pageOf(await get('/intel/kev' + qs({ size: 50, affects_estate: scoped, exposed: scope === 'exposed' })));
    body.innerHTML = scopeSwitch(counts.kev_exposed, counts.kev_affecting_estate, counts.kev, 'KEV entries') + table([
      { label: 'CVE', cell: r => `<a href="#/intel/cve/${esc(r.cve_id)}" class="mono">${esc(r.cve_id)}</a>` },
      { label: 'Vendor', cell: r => esc(r.vendor || r.vendor_project) },
      { label: 'Product', cell: r => esc(r.product) },
      { label: 'Added', cell: r => fmtDay(r.date_added) },
      { label: 'Due', cell: r => fmtDay(r.due_date) },
      { label: 'Required action', cell: r => esc((r.required_action || '').slice(0, 110)) },
    ], d.items, scope === 'exposed'
      ? { emptyTitle: 'No open finding is a known-exploited vulnerability',
          emptyHint: 'Good news if findings are current. Check “Software you run” for KEV entries that name your products before versions are compared.' }
      : scoped
      ? { emptyTitle: 'No known-exploited vulnerability names software you run',
          emptyHint: 'CISA KEV is the shortest, most urgent list there is — an empty estate view here is worth confirming against the whole catalogue before believing it.' }
      : { emptyTitle: 'KEV catalogue empty', emptyHint: 'Feeds run on the intelligence schedule (Threat Intel → Schedule), from the host CLI or through POST /intel/feeds/kev.' });
    wireScope();
  } else if (tab === 'news') {
    const d = pageOf(await get('/intel/news?limit=40'));
    body.innerHTML = table([
      { label: 'Published', cell: r => fmtDay(r.published_at) },
      { label: 'Source', cell: r => esc(r.source_name || r.source || '—') },
      { label: 'Title', cell: r => r.url ? `<a href="${esc(r.url)}" target="_blank" rel="noopener">${esc(r.title)}</a>` : esc(r.title) },
      { label: 'Relevance', num: true, cell: r => r.relevance == null ? '—' : fmtScore(r.relevance) },
      { label: 'CVEs', cell: r => (r.cve_ids || []).slice(0, 4).map(c => `<a href="#/intel/cve/${esc(c)}" class="mono small">${esc(c)}</a>`).join(' ') },
    ], d.items, { emptyTitle: 'No articles', emptyHint: 'Add an RSS or CERT source under the Sources tab.' });
  } else if (tab === 'sources') {
    const d = pageOf(await get('/intel/sources'));
    body.innerHTML = `<div class="row mb-2"><button class="btn btn-sm btn-primary" id="add-src">Add source</button></div>` + table([
      { label: 'Name', cell: r => esc(r.name) },
      { label: 'Kind', cell: r => esc(titleCase(r.kind || r.type)) },
      { label: 'URL', cell: r => `<span class="mono small">${esc(r.url || '')}</span>` },
      { label: 'Enabled', cell: r => r.enabled === false ? 'No' : 'Yes' },
      { label: 'Last fetched', cell: r => fmtDate(r.last_fetched_at) },
    ], d.items, { emptyTitle: 'No intelligence sources' });
    $('#add-src').onclick = async () => {
      const r = await modal({
        title: 'Add intelligence source',
        body: `<div><label>Name *</label><input name="name" required></div>
               <div><label>Kind</label><select name="kind">${['rss', 'cert', 'vendor_advisory', 'misp', 'opencti'].map(k => `<option value="${k}">${titleCase(k)}</option>`).join('')}</select></div>
               <div><label>URL *</label><input name="url" required placeholder="https://…"></div>`,
        actions: [{ label: 'Add' }],
      });
      if (!r) return;
      try { await post('/intel/sources', { name: r.name, kind: r.kind, url: r.url }); ok('Source added.'); render(); } catch (e) { err(e.detail); }
    };
  } else if (tab === 'schedule') {
    return intelScheduleTab(body);
  } else {
    const d = pageOf(await get('/intel/feeds/runs?size=40'));
    body.innerHTML = table([
      { label: 'Feed', cell: r => esc(r.feed || r.source) },
      { label: 'Started', cell: r => fmtDate(r.started_at || r.created_at) },
      { label: 'Finished', cell: r => fmtDate(r.finished_at) },
      { label: 'Status', cell: r => statePill(r.status) },
      { label: 'Seen', num: true, cell: r => fmtNum(r.records_seen) },
      { label: 'Created', num: true, cell: r => fmtNum(r.records_created) },
      { label: 'Updated', num: true, cell: r => fmtNum(r.records_updated) },
      { label: 'Error', cell: r => esc((r.error || '').slice(0, 120)) },
    ], d.items, { emptyTitle: 'No feed runs yet' });
  }
});

async function cveDetail(view, cveId) {
  const c = await get('/intel/cve/' + encodeURIComponent(cveId));
  let exposure = null, hist = [];
  try { exposure = await get(`/intel/cve/${encodeURIComponent(cveId)}/exposure`); } catch { }
  try { hist = pageOf(await get(`/intel/cve/${encodeURIComponent(cveId)}/epss-history`)).items; } catch { }
  view.innerHTML = `
    <div class="page-head"><div><h1 class="mono">${esc(c.cve_id)}</h1>
      <p>${sevPill(c.severity)} ${c.kev || c.known_exploited ? '<span class="pill pill-kev">CISA KEV</span>' : ''}
      <span class="muted small">Published ${fmtDay(c.published_at)} · modified ${fmtDay(c.modified_at)}</span></p></div>
      <div class="page-actions">${can('ai:read') ? '<button class="btn btn-ai" id="ai-cve">✦ Analyse</button>' : ''}</div></div>
    <div class="grid cols-4">
      <div class="card stat"><span class="label">CVSS</span><span class="value">${fmtScore(c.cvss_score ?? c.cvss_base_score)}</span><span class="hint mono small">${esc(c.cvss_vector || '')}</span></div>
      <div class="card stat"><span class="label">EPSS</span><span class="value">${c.epss_score == null ? '—' : fmtPct(c.epss_score)}</span><span class="hint">${c.epss_percentile == null ? 'no score' : 'percentile ' + Math.round(c.epss_percentile * 100)}</span></div>
      <div class="card stat ${c.kev ? 'crit' : ''}"><span class="label">Known exploited</span><span class="value t-xl">${c.kev || c.known_exploited ? 'Yes' : 'No'}</span><span class="hint">${c.kev_due_date ? 'CISA due ' + fmtDay(c.kev_due_date) : ''}</span></div>
      <div class="card stat ${exposure && exposure.affected_assets ? 'crit' : ''}"><span class="label">Your exposure</span><span class="value">${fmtNum(exposure && (exposure.affected_assets ?? exposure.asset_count))}</span><span class="hint">${fmtNum(exposure && exposure.internet_facing)} internet-facing</span></div>
    </div>
    <div class="grid cols-2 mt-4">
      <div class="card"><h2>Description</h2><p>${esc(c.description || '—')}</p>
        <h3 class="mt-4">Weakness</h3>
        <p>${(c.cwes || c.cwe_ids || []).map(w => { const id = w.cwe_id || w; return `<a href="#/intel/cwe/${esc(id)}" class="mono">${esc(id)}</a>`; }).join(', ') || '—'}</p>
        <h3 class="mt-4">References</h3>
        <ul class="small">${(c.references || []).slice(0, 12).map(r => `<li><a href="${esc(r.url || r)}" target="_blank" rel="noopener">${esc((r.url || r).slice(0, 90))}</a></li>`).join('') || '<li class="muted">None recorded</li>'}</ul></div>
      <div class="card"><h2>Affected products</h2>
        ${table([
          { label: 'Vendor', cell: r => esc(r.vendor || r.vendor_name) },
          { label: 'Product', cell: r => esc(r.product || r.product_name) },
          { label: 'Affected', cell: r => `<span class="mono small">${esc(r.version_range || r.affected_versions || '—')}</span>` },
          { label: 'Fixed in', cell: r => `<span class="mono small">${esc(r.fixed_version || '—')}</span>` },
        ], c.products || c.configurations || [], { emptyTitle: 'No product mapping', emptyHint: 'Without CPE data this CVE cannot be correlated to assets.' })}
        <h3 style="margin-top:16px">EPSS history</h3>
        ${hist.length ? table([
          { label: 'Date', cell: r => fmtDay(r.recorded_at || r.date) },
          { label: 'Probability', num: true, cell: r => fmtPct(r.epss_score ?? r.score, 2) },
          { label: 'Percentile', num: true, cell: r => r.percentile == null ? '—' : Math.round(r.percentile * 100) },
        ], hist) : '<p class="small muted">No history yet — EPSS history accrues from each ingest.</p>'}
      </div>
    </div>
    <div class="card mt-4"><h2>Affected assets</h2>
      ${table([
        { label: 'Asset', cell: r => `<a href="#/assets/${esc(r.asset_id || r.id)}">${esc(r.name || r.hostname || r.asset_hostname)}</a>${r.hostname && r.hostname !== r.name ? ` <span class="mono small muted">${esc(r.hostname)}</span>` : ''}` },
        { label: 'Criticality', cell: r => critPill(r.criticality) },
        { label: 'Exposure', cell: r => exposurePill(r.exposure || (r.internet_exposed ? 'internet' : 'internal')) },
        { label: 'State', cell: r => esc(titleCase(r.state || '')) },
        { label: 'Risk', num: true, cell: r => fmtScore(r.risk_score) },
        { label: 'SLA due', cell: r => fmtDay(r.sla_due_at) },
        { label: 'Finding', cell: r => r.finding_id ? `<a href="#/findings/${esc(r.finding_id)}">open</a>` : '—' },
      ], (exposure && (exposure.assets || exposure.items)) || [], { emptyTitle: 'No open finding on your assets', emptyHint: 'Either your installed versions are outside the affected range, or the products on your assets are not mapped to CPEs. The CVE list’s “Software you run” lens shows CVEs that name your products before versions are compared.' })}</div>
    <div class="card mt-4" id="ai-card" hidden><h2>✦ AI analysis</h2><div id="ai-body"></div></div>`;
  const b = $('#ai-cve');
  if (b) b.onclick = async () => {
    $('#ai-card').hidden = false;
    $('#ai-body').innerHTML = '<div class="loading">Analysing…</div>';
    try { const r = await post(`/ai/cve/${encodeURIComponent(cveId)}/analysis`, {}); $('#ai-body').innerHTML = `<div class="ai-msg veyrs"><pre>${esc(r.answer || r.text || JSON.stringify(r, null, 2))}</pre></div>`; }
    catch (e) { $('#ai-body').innerHTML = `<p class="muted">${esc(e.detail)}</p>`; }
  };
}

async function cweDetail(view, cweId) {
  const c = await get('/intel/cwe/' + encodeURIComponent(cweId));
  view.innerHTML = `
    <div class="page-head"><div><h1 class="mono">${esc(c.id)}</h1>
      <p>${c.name
        ? esc(c.name)
        : '<span class="muted">Not in the loaded dictionary — this row was created from an NVD identifier. Run <code class="mono">veyrs sync-cwe</code>.</span>'}</p></div>
      <div class="page-actions">${c.reference
        ? `<a class="btn" href="${esc(c.reference)}" target="_blank" rel="noopener">MITRE definition ↗</a>` : ''}</div></div>
    <div class="grid cols-4">
      <div class="card stat ${tone('warn', c.open_findings)}"><span class="label">Open findings</span>
        <span class="value">${fmtNum(c.open_findings)}</span><span class="hint">in your estate, this weakness class</span></div>
      <div class="card stat"><span class="label">Abstraction</span>
        <span class="value t-xl">${esc(c.abstraction || '—')}</span>
        <span class="hint">Class → Base → Variant, most general first</span></div>
      <div class="card stat"><span class="label">Catalogue status</span>
        <span class="value t-xl">${esc(c.status || '—')}</span></div>
      <div class="card stat"><span class="label">Dictionary</span>
        <span class="value t-xl">${c.resolved ? 'Loaded' : 'Placeholder'}</span>
        <span class="hint">${c.resolved ? 'MITRE CWE catalogue' : 'identifier only, no definition'}</span></div>
    </div>
    <div class="card mt-4"><h2>Description</h2>
      <p>${esc(c.description || '—')}</p>
      <p class="small muted mt-2">A CWE is the <em>class</em> of flaw, not an instance of it. Counting findings by weakness is how a backlog stops reading as 400 unrelated tickets and starts reading as three engineering problems.</p></div>`;
}

/* ── Intelligence refresh schedule ──────────────────────────────────────
   Until v0.21.0 the cadence lived in a systemd unit on the primary node, so
   "how often does this update?" was a question only somebody with SSH could
   answer, and "make KEV hourly this week" was a deployment change. The timer
   now ticks hourly and asks the database what is due; this screen is the
   database. */
async function intelScheduleTab(body) {
  const st = await get('/intel/schedule');
  const editable = can('intel:write');
  const HUMAN = [
    [60, 'Every hour'], [180, 'Every 3 hours'], [360, 'Every 6 hours'],
    [720, 'Every 12 hours'], [1440, 'Daily'], [2880, 'Every 2 days'],
    [10080, 'Weekly'], [43200, 'Every 30 days'],
  ];
  const humanise = m => (HUMAN.find(([v]) => v === m) || [null, `Every ${fmtNum(m)} min`])[1];

  body.innerHTML = explainer('intel.schedule', {
    title: 'What this schedule does — and the part that surprises people',
    what: 'How often each feed is refreshed. The timer wakes hourly and runs only '
        + 'the feeds whose interval has elapsed since their last <em>successful</em> '
        + 'run — a failed run does not reset the clock, so a broken feed keeps '
        + 'reporting itself as due.',
    who: 'Whoever owns intelligence. It cannot be set from a team-scoped identity.',
    effect: 'From the next hourly tick. Nothing re-downloads immediately; use the '
          + 'feed buttons on the other tabs for that.',
    warn: 'The CVE corpus is <strong>shared by the whole deployment</strong> — '
        + '<span class="mono">cves</span>, <span class="mono">epss_scores</span> and '
        + '<span class="mono">kev_entries</span> have no tenant column, because '
        + 'CVE-2024-3094 is the same row for everybody. So this is your '
        + '<em>demand</em>, and what actually runs is the <strong>tightest</strong> '
        + 'demand across all tenants. If you ask for daily and the column on the '
        + 'right says hourly, another organization asked for hourly — that is not a '
        + 'bug, and it is why both numbers are shown.',
    links: [{ label: 'Feed run history', href: '#/intel?tab=runs' }],
  }) + `<div class="card">
      <h2>Feeds</h2>
      <form id="sched-form">${(st.feeds || []).map(f => `
        <div class="wf-step">
          <div class="wf-step-head">
            <strong>${esc(f.label)}</strong>
            <span class="pill ${f.effective_enabled ? 'st-ok' : 'st-neutral'} mono">${esc(f.feed)}</span>
          </div>
          <div class="grid cols-3">
            <div>
              <label class="inline"><input type="checkbox" data-feed="${esc(f.feed)}" data-k="enabled"${f.enabled ? ' checked' : ''}${editable ? '' : ' disabled'}> Keep this feed refreshed</label>
              <label class="mt-2">You want</label>
              <select data-feed="${esc(f.feed)}" data-k="interval"${editable ? '' : ' disabled'}>
                ${HUMAN.map(([v, l]) => `<option value="${v}"${v === f.interval_minutes ? ' selected' : ''}>${l}</option>`).join('')}
                ${HUMAN.some(([v]) => v === f.interval_minutes) ? '' : `<option value="${f.interval_minutes}" selected>${esc(humanise(f.interval_minutes))}</option>`}
              </select>
              <p class="field-help">${f.explicit ? 'Chosen deliberately.' : 'Never changed — this is the shipped default.'}</p>
            </div>
            <div>
              <label>Actually in force</label>
              <p style="margin:6px 0 0"><strong>${f.effective_enabled ? esc(humanise(f.effective_interval_minutes)) : 'Not refreshed'}</strong></p>
              <p class="field-help">${f.effective_interval_minutes === f.interval_minutes && f.effective_enabled === f.enabled
                  ? 'Same as what you asked for.'
                  : 'Tighter than your setting because another tenant asked for more.'}</p>
            </div>
            <div>
              <label>Last success</label>
              <p style="margin:6px 0 0">${f.last_success_at ? fmtDate(f.last_success_at) : '<span class="muted">never</span>'}</p>
              <p class="field-help">${f.due_now
                  ? '<span class="pill st-warn">Due at the next tick</span>'
                  : (f.next_due_at ? 'Next: ' + fmtDate(f.next_due_at) : '—')}</p>
            </div>
          </div>
        </div>`).join('')}
        ${editable
          ? '<button class="btn btn-primary" type="submit">Save schedule</button>'
          : '<p class="small muted">You can read this schedule but not change it — it needs <span class="mono">intel:write</span> and an estate-wide grant.</p>'}
      </form>
      <p class="small muted mt-3">Intervals are clamped between
        ${fmtNum(st.min_interval_minutes)} minutes and ${fmtNum(st.max_interval_minutes)} minutes.
        The floor is the tick itself: offering “every 15 minutes” on a scheduler that can
        only act hourly would be a control that lies.</p>
    </div>`;

  const form = $('#sched-form');
  if (form && editable) form.onsubmit = async e => {
    e.preventDefault();
    const feeds = {};
    form.querySelectorAll('[data-feed]').forEach(el => {
      const f = (feeds[el.dataset.feed] ||= {});
      if (el.dataset.k === 'enabled') f.enabled = el.checked;
      else f.interval_minutes = Number(el.value);
    });
    try { await put('/intel/schedule', { feeds }); ok('Schedule saved.'); render(); }
    catch (ex) { err(ex.detail); }
  };
}

/* ── Fix plan (finding + asset cards) and Upgrade paths (policies tab) ──
   One block on purpose: the plan card, its loader and the rules tab are the
   whole console surface of the feature, so the three call sites elsewhere are
   one line each. Every interpolated value goes through esc(); a rule's
   source_url is only ever rendered as a link when it is http(s). */
const FIX_STEP_CLASS = { patch: 'st-ok', minor: 'st-neutral', major: 'st-warn', unknown: 'st-neutral' };
function fixStepPill(step) {
  return `<span class="pill ${FIX_STEP_CLASS[step] || 'st-neutral'}">${esc(step || 'unknown')}</span>`;
}
function fixSafeLink(url, label) {
  return url && /^https?:\/\//i.test(String(url))
    ? `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(label || url)}</a>` : esc(label || '');
}
function fixPathHtml(path) {
  if (!path) return '';
  const hops = (path.hops || []).map(h => `<li><span class="mono">${esc(h.from)}</span> → <span class="mono">${esc(h.to)}</span> ${fixStepPill(h.step)}
      ${(h.required_by || []).length ? ' <span class="muted small">required by an upgrade-path rule</span>' : ''}
      ${(h.prerequisites || []).length ? `<ul>${h.prerequisites.map(p => `<li class="small">${esc(p.note)}${p.source_url ? ' — ' + fixSafeLink(p.source_url, 'source') : ''}</li>`).join('')}</ul>` : ''}</li>`).join('');
  const warn = [...(path.warnings || []), ...(path.ignored_rules || []).map(r => r.reason)];
  return `<h3 class="mt-3">Upgrade path ${path.path_required ? '<span class="pill st-warn">intermediate stop required</span>' : '<span class="pill st-neutral">direct</span>'}</h3>
    <ol>${hops}</ol>
    ${warn.length ? `<p class="small muted">${warn.map(w => esc(w)).join('<br>')}</p>` : ''}`;
}
function fixPlanHtml(plan) {
  if (!plan.available) return `<p class="muted">${esc(plan.reason || 'No fix plan available.')}</p>`;
  const byId = {};
  (plan.findings || []).forEach(f => { byId[f.finding_id] = f; });
  const label = id => { const f = byId[id] || {}; return esc(f.cve_id || f.title || String(id).slice(0, 8)); };
  const best = plan.best_single_target;
  const near = plan.nearest_on_branch;
  const cov = plan.coverage || {};
  return `<p class="small muted">${esc(plan.vendor || '')} ${esc(plan.product || '')} · installed <span class="mono">${esc(plan.installed_version || 'unknown')}</span></p>
    ${best ? `<dl class="kv">
        <dt>Best single target</dt><dd><strong class="mono">${esc(best.version)}</strong> ${fixStepPill(best.step)} <span class="muted small">fixes ${fmtNum((best.fixes || []).length)} finding(s)</span></dd>
        ${near && near.version !== best.version ? `<dt>Nearest on your branch</dt><dd><span class="mono">${esc(near.version)}</span> ${fixStepPill(near.step)} <span class="muted small">fixes ${fmtNum((near.fixes || []).length)}${near.fixes_all ? ' (all)' : ' — not all'}</span></dd>` : ''}
      </dl>${fixPathHtml(best.path)}`
      : `<p><strong>No single target.</strong> <span class="muted">${esc(plan.best_single_target_reason || '')}</span></p>
         ${near ? `<p class="small">Nearest on your branch: <span class="mono">${esc(near.version)}</span> ${fixStepPill(near.step)} fixes ${fmtNum((near.fixes || []).length)}</p>` : ''}`}
    ${(plan.candidates || []).length ? `<h3 class="mt-3">Which version fixes what</h3>${table([
      { label: 'Version', cell: c => `<span class="mono">${esc(c.version)}</span>` },
      { label: 'Step', cell: c => fixStepPill(c.step) },
      { label: 'Fixes', cell: c => (c.fixes || []).map(label).join(', ') || '—' },
      { label: 'All?', cell: c => c.fixes_all ? 'Yes' : 'No' },
    ], plan.candidates, { idOf: c => c.version })}` : ''}
    ${(plan.no_fix_known || []).length ? `<h3 class="mt-3">No known fix</h3><ul>${plan.no_fix_known.map(f =>
      `<li><a href="#/findings/${esc(f.finding_id)}">${esc(f.cve_id || f.title)}</a> <span class="muted small">${esc(f.note)}</span></li>`).join('')}</ul>` : ''}
    <p class="small muted mt-2">${esc(cov.statement || '')} · computed ${fmtDate(plan.computed_at)}</p>`;
}
async function loadFixPlan(el, path) {
  if (!el) return;
  try {
    const r = await get(path);
    if (Array.isArray(r.plans)) {
      el.innerHTML = '<h2>Fix plan</h2>' + (r.plans.length
        ? r.plans.map(p => `<div class="mt-2">${fixPlanHtml(p)}</div>`).join('<hr>')
        : '<p class="muted">No installed product on this asset has open findings.</p>')
        + (r.unlinked_open_findings ? `<p class="small muted">${fmtNum(r.unlinked_open_findings)} open finding(s) are not tied to an installed product and are not covered by any plan.</p>` : '');
    } else {
      el.innerHTML = '<h2>Fix plan</h2>' + fixPlanHtml(r);
    }
  } catch (e) { el.innerHTML = `<h2>Fix plan</h2><p class="muted">${esc(e.detail || 'Unavailable')}</p>`; }
}
async function upgradePathsTab(body) {
  const rows = pageOf(await get('/upgrade-path-rules')).items;
  const writable = can('sla:write');
  const range = r => [r.from_start_including && '≥ ' + r.from_start_including, r.from_start_excluding && '> ' + r.from_start_excluding,
    r.from_end_excluding && '< ' + r.from_end_excluding, r.from_end_including && '≤ ' + r.from_end_including].filter(Boolean).join(' and ') || 'any version';
  body.innerHTML = explainer('policies.upgrade', {
    title: 'What an upgrade-path rule is',
    what: 'A vendor requirement the fix plan cannot read from NVD: when the installed version is inside the '
        + '<em>from</em> range, the upgrade must stop at the <em>via</em> version first, and/or do the prerequisite. '
        + 'VEYRS ships no rules — each one is what you read in the vendor\'s upgrade guide, with its URL.',
    who: 'The security manager, from the vendor documentation. Writing one needs an estate-wide grant.',
    effect: 'Every fix plan for that vendor and product is recomputed with the extra stop on the next view. Nothing is stored on findings.',
    warn: 'A rule whose via version is below the version a hop starts from is ignored and reported, never followed, and a path stops after 16 hops.',
  }) + (writable ? `<div class="row mb-2"><button class="btn btn-sm btn-primary" id="upr-add">New upgrade-path rule</button></div>` : '') + table([
    { label: 'Vendor', cell: r => esc(r.vendor) },
    { label: 'Product', cell: r => esc(r.product) },
    { label: 'From', cell: r => `<span class="mono small">${esc(range(r))}</span>` },
    { label: 'Via', cell: r => `<span class="mono">${esc(r.via_version || '—')}</span>` },
    { label: 'Prerequisite', cell: r => esc((r.prerequisite || '—').slice(0, 160)) },
    { label: 'Source', cell: r => r.source_url ? fixSafeLink(r.source_url, 'link') : '—' },
    { label: 'Enabled', cell: r => r.is_enabled === false ? 'No' : 'Yes' },
    { label: '', cell: r => writable ? `<button class="btn btn-sm" data-upr-edit="${esc(r.id)}">Edit</button> <button class="btn btn-sm btn-danger" data-upr-del="${esc(r.id)}">Delete</button>` : '' },
  ], rows, { emptyTitle: 'No upgrade-path rules', emptyHint: 'Fix plans assume a direct upgrade until a rule says otherwise.' });
  const form = (r = {}) => `<div><label>Vendor *</label><input name="vendor" required value="${esc(r.vendor || '')}" placeholder="Acme"></div>
    <div><label>Product *</label><input name="product" required value="${esc(r.product || '')}" placeholder="Widget"></div>
    <div><label>From: start (including)</label><input name="from_start_including" value="${esc(r.from_start_including || '')}"></div>
    <div><label>From: start (excluding)</label><input name="from_start_excluding" value="${esc(r.from_start_excluding || '')}"></div>
    <div><label>From: end (excluding)</label><input name="from_end_excluding" value="${esc(r.from_end_excluding || '')}"></div>
    <div><label>From: end (including)</label><input name="from_end_including" value="${esc(r.from_end_including || '')}"></div>
    <div><label>Via version (mandatory stop)</label><input name="via_version" value="${esc(r.via_version || '')}"></div>
    <div><label>Prerequisite</label><textarea name="prerequisite">${esc(r.prerequisite || '')}</textarea></div>
    <div><label>Source URL</label><input name="source_url" value="${esc(r.source_url || '')}" placeholder="https://example.com/upgrade-guide"></div>
    <div><label><input type="checkbox" name="is_enabled"${r.is_enabled === false ? '' : ' checked'}> Enabled</label></div>`;
  const payload = f => { const out = {}; Object.entries(f).forEach(([k, v]) => { out[k] = typeof v === 'string' ? (v.trim() || null) : v; }); return out; };
  const add = $('#upr-add');
  if (add) add.onclick = async () => {
    const f = await modal({ title: 'New upgrade-path rule', body: form(), actions: [{ label: 'Create' }] });
    if (!f) return;
    try { await post('/upgrade-path-rules', payload(f)); ok('Rule created.'); render(); } catch (e) { err(e.detail); }
  };
  $$('[data-upr-edit]', body).forEach(b => b.onclick = async () => {
    const r = rows.find(x => x.id === b.dataset.uprEdit) || {};
    const f = await modal({ title: 'Edit upgrade-path rule', body: form(r), actions: [{ label: 'Save' }] });
    if (!f) return;
    try { await patch('/upgrade-path-rules/' + r.id, payload(f)); ok('Rule saved.'); render(); } catch (e) { err(e.detail); }
  });
  $$('[data-upr-del]', body).forEach(b => b.onclick = async () => {
    const c = await modal({ title: 'Delete rule', body: '<p>Delete this upgrade-path rule? Fix plans stop applying it immediately.</p>', actions: [{ label: 'Delete', cls: 'btn-danger' }] });
    if (!c) return;
    try { await del('/upgrade-path-rules/' + b.dataset.uprDel); ok('Rule deleted.'); render(); } catch (e) { err(e.detail); }
  });
}

/* ── Policies (SLA / escalation / assignment) ───────────────────────── */
route('policies', async (view, _p, params) => {
  const tab = params.get('tab') || 'sla';
  /* One explainer per tab, not one for the page. The five tabs are five
     unrelated decisions that happen to share a screen -- deadlines, who gets
     woken up, who owns the work, how the number is computed, and what already
     happened. A single paragraph covering all five is the reason this page
     read as "absurdly complicated". */
  const POLICY_HELP = {
    sla: explainer('policies.sla', {
      title: 'What an SLA policy is, in one screen',
      what: 'How long a finding may stay open before it is late. The FIRST policy '
          + 'whose conditions match a finding wins, and lower <em>priority</em> '
          + 'numbers are checked first — so a narrow rule ("critical + KEV + '
          + 'internet-facing: 4 hours") must have a lower number than a broad one.',
      who: 'The security manager. It is a commitment the whole organization is '
         + 'measured against, so it is deliberately not a team-level setting.',
      effect: 'The deadline is recomputed for <strong>every open finding</strong> '
            + 'in the organization, not just new ones. Findings whose new '
            + 'deadline is already in the past become breached immediately.',
      warn: 'A finding that matches no policy has <strong>no deadline at all</strong>. '
          + 'It never turns red, never escalates, and never appears in a breach '
          + 'count — it simply sits there. Keep one broad catch-all policy with a '
          + 'high priority number.',
      links: [{ label: 'SLA events (what actually fired)', href: '#/policies?tab=events' }],
    }),
    escalation: explainer('policies.escalation', {
      title: 'What escalation does when a deadline passes',
      what: 'Who else finds out, and after how long. A ladder is a list of steps: '
          + '<span class="mono small">{"level":2,"after_hours":8,"notify":"team_manager"}</span> '
          + 'means eight hours past the deadline, the manager is notified.',
      who: 'The security manager, usually once, then rarely.',
      effect: 'Nothing retroactive: a finding only ever moves <em>up</em> a level, '
            + 'and only when the sweep runs. Lowering a threshold does not re-notify '
            + 'people about levels already passed.',
      warn: 'A breached SLA with no escalation policy notifies nobody beyond the '
          + 'owning team — and if the finding is unowned, nobody at all.',
    }),
    assignment: explainer('policies.assignment', {
      title: 'How work finds its owner',
      what: 'Which team a finding is routed to. Rules are tried in <em>priority</em> '
          + 'order and the first match wins. If none match, the finding inherits '
          + 'the team that owns its <strong>asset</strong>.',
      who: 'The security manager. A team that could write its own routing rule '
         + 'would be choosing its own queue, so this requires an estate-wide grant.',
      effect: 'New and re-scored findings only. Existing assignments are not '
            + 'rewritten — use <em>Assign to team…</em> on the findings list for those.',
      warn: 'Findings that match no rule and sit on an unowned asset stay unowned, '
          + 'and unowned work is invisible to every team-scoped user at once.',
      links: [{ label: 'Assets with no owning team', href: '#/assets?unowned=true' },
              { label: 'Findings with no owner', href: '#/findings?queue=unowned' }],
    }),
    risk: explainer('policies.risk', {
      title: 'How the 0–100 VEYRS risk score is built',
      what: 'The weighting between the four sub-scores. The shipped default is '
          + '<span class="mono small">0.30 technical + 0.30 exploitability + '
          + '0.25 business + 0.15 exposure</span>, then floors are applied '
          + '(KEV ≥ 75, internet-facing KEV ≥ 90, active exploitation ≥ 80) and '
          + '+3 points per 30 days since detection (6 once the SLA deadline has '
          + 'passed), capped at +15.',
      who: 'Whoever owns prioritisation. Different profiles exist because an '
         + 'executive and a penetration tester are ranking the same estate for '
         + 'different reasons.',
      effect: 'Nothing until you re-score. Existing findings keep the number they '
            + 'were given; <em>Re-score everything</em> rewrites them and writes '
            + 'the change to each finding\'s history.',
      warn: 'Re-scoring moves findings across the priority bands (≥90 critical, '
          + '≥70 high, ≥40 medium), which changes what automatic ticketing and '
          + 'the SLA policies match. Check <a href="#/automation?tab=tickets">'
          + 'Automatic tickets</a> before a large re-weighting.',
    }),
    events: explainer('policies.events', {
      title: 'What this log is for',
      what: 'Every warning, breach and escalation the SLA sweep has produced. It is '
          + 'the evidence trail behind a breach number, not a queue of work.',
      who: 'Anyone auditing why somebody was — or was not — notified.',
      effect: 'Read-only. Nothing on this tab changes anything.',
    }),
  };

  view.innerHTML = `
    <div class="page-head"><div><h1>SLA &amp; Policies</h1>
      <p>Clocks and ownership are configuration, not code. Change a weight or a deadline here and every open finding is re-evaluated on the next pass.</p></div>
      <div class="page-actions"><button class="btn" id="evaluate">Evaluate SLA now</button></div></div>
    <div class="tabs">${[['sla', 'SLA policies'], ['escalation', 'Escalation'], ['assignment', 'Assignment rules'], ['risk', 'Risk profiles'], ['events', 'SLA events'], ['upgrade', 'Upgrade paths']]
      .map(([k, l]) => `<button data-t="${k}" class="${tab === k ? 'active' : ''}">${l}</button>`).join('')}</div>
    ${POLICY_HELP[tab] || ''}
    <div id="pol-body"><div class="loading">Loading…</div></div>`;
  view.querySelector('.tabs').onclick = e => { if (e.target.dataset.t) location.hash = '#/policies?tab=' + e.target.dataset.t; };
  $('#evaluate').onclick = async () => {
    try { const r = await post('/policies/sla/evaluate', {}); ok(`Evaluated. ${fmtNum(r.evaluated ?? r.updated ?? 0)} findings touched.`); render(); } catch (e) { err(e.detail); }
  };
  const body = $('#pol-body');

  if (tab === 'sla') {
    const rows = pageOf(await get('/policies/sla')).items;
    body.innerHTML = `<div class="row mb-2"><button class="btn btn-sm btn-primary" id="add">New SLA policy</button></div>` + table([
      { label: 'Name', cell: r => esc(r.name) },
      { label: 'Applies when', cell: r => matchChips(r.conditions || r.criteria || {}) },
      { label: 'Deadline', num: true, cell: r => fmtNum(r.remediate_within_hours) + ' h' },
      { label: 'Priority', num: true, cell: r => fmtNum(r.priority) },
      { label: 'Enabled', cell: r => r.is_enabled === false ? 'No' : 'Yes' },
    ], rows, { emptyTitle: 'No SLA policies', emptyHint: 'Without a policy, findings have no deadline and nothing escalates.' });
    $('#add').onclick = async () => {
      const r = await modal({
        title: 'New SLA policy',
        body: `<div><label>Name *</label><input name="name" required placeholder="Critical + KEV + internet-facing"></div>
          <div><label>Deadline (hours) *</label><input name="hours" type="number" min="1" value="4" required></div>
          <div><label>Priority (lower wins)</label><input name="priority" type="number" value="10"></div>
          <div><label>Conditions (JSON)</label><textarea name="conditions">{"severity":["critical"],"kev":true,"exposure":["internet"]}</textarea></div>
          <p class="small muted">Keys: severity, kev, exposure, asset_criticality, environment, asset_type, and min_/max_ on cvss, epss, risk.</p>`,
        actions: [{ label: 'Create' }],
      });
      if (!r) return;
      let conditions;
      try { conditions = JSON.parse(r.conditions || '{}'); } catch { return err('Conditions must be valid JSON.'); }
      // SlaPolicyWrite: `slug` and `remediate_within_hours` are required; the
      // old payload (`hours`, no slug) was a 422 on every click until 0.35.3.
      try {
        await post('/policies/sla', {
          slug: slugify(r.name, 'sla-policy'), name: r.name,
          remediate_within_hours: Number(r.hours), priority: Number(r.priority || 10), conditions,
        });
        ok('Policy created.'); render();
      }
      catch (e) { err(e.detail); }
    };
  } else if (tab === 'escalation') {
    const rows = pageOf(await get('/policies/escalation')).items;
    body.innerHTML = table([
      { label: 'Name', cell: r => esc(r.name) },
      { label: 'Ladder', cell: r => ladderSteps(r.steps || r.levels || []) },
      { label: 'Enabled', cell: r => r.enabled === false ? 'No' : 'Yes' },
    ], rows, { emptyTitle: 'No escalation policies', emptyHint: 'A breached SLA with no escalation policy notifies nobody beyond the owning team.' });
  } else if (tab === 'assignment') {
    const rows = pageOf(await get('/policies/assignment')).items;
    body.innerHTML = `<div class="row mb-2"><button class="btn btn-sm" id="test">Test a rule set</button></div>` + table([
      { label: 'Name', cell: r => esc(r.name) },
      { label: 'Match', cell: r => matchChips(r.conditions || r.match || {}) },
      { label: 'Team', cell: r => esc(r.team_name || r.team_id || '—') },
      { label: 'Priority', num: true, cell: r => fmtNum(r.priority) },
    ], rows, { emptyTitle: 'No assignment rules', emptyHint: 'Findings with no rule match stay unowned — and unowned work never gets done.' });
    $('#test').onclick = async () => {
      const r = await modal({ title: 'Test assignment', body: `<div><label>Candidate context (JSON)</label><textarea name="ctx">{"vendor":"Fortinet","product_type":"firewall"}</textarea></div>`, actions: [{ label: 'Test' }] });
      if (!r) return;
      try { const out = await post('/policies/assignment/test', JSON.parse(r.ctx)); await modal({ title: 'Result', body: `<pre class="mono small pre-wrap">${esc(JSON.stringify(out, null, 2))}</pre>`, actions: [] }); }
      catch (e) { err(e.detail); }
    };
  } else if (tab === 'risk') {
    const rows = pageOf(await get('/risk/profiles')).items;
    body.innerHTML = `<div class="row mb-2">
        <button class="btn btn-sm btn-primary" id="add">New risk profile</button>
        <button class="btn btn-sm" id="sim">Simulate</button>
        <button class="btn btn-sm" id="rescore">Re-score everything</button></div>` + table([
      { label: 'Name', cell: r => esc(r.name) },
      { label: 'Slug', cell: r => `<span class="mono small">${esc(r.slug || '')}</span>` },
      { label: 'Weights', cell: r => matchChips(r.weights || {}) },
      { label: 'Default', cell: r => r.is_default ? 'Yes' : '' },
    ], rows, { emptyTitle: 'No custom risk profiles', emptyHint: 'The built-in weighting is in effect. Create a profile to prioritise differently for executives, exposure or compliance.' });
    $('#add').onclick = async () => {
      const r = await modal({
        title: 'New risk profile',
        body: `<div><label>Name *</label><input name="name" required placeholder="Executive Risk Profile"></div>
          <div><label>Weights (JSON)</label><textarea name="weights">{"technical":0.30,"exploitability":0.30,"business":0.25,"exposure":0.15}</textarea></div>
          <p class="small muted">The engine reads four keys: technical, exploitability, business, exposure. Any other key is ignored.</p>`,
        actions: [{ label: 'Create' }],
      });
      if (!r) return;
      let weights;
      try { weights = JSON.parse(r.weights || '{}'); } catch { return err('Weights must be valid JSON.'); }
      // RiskProfileWrite requires `slug`; derived from the name like workflows.
      try { await post('/risk/profiles', { slug: slugify(r.name, 'risk-profile'), name: r.name, weights }); ok('Profile created.'); render(); } catch (e) { err(e.detail); }
    };
    $('#sim').onclick = async () => {
      const r = await modal({ title: 'Simulate risk', body: `<div><label>Inputs (JSON)</label><textarea name="i">{"cvss_score":8.8,"epss_score":0.91,"kev":true,"internet_exposed":true,"asset_criticality":"critical"}</textarea></div>`, actions: [{ label: 'Simulate' }] });
      if (!r) return;
      try { const out = await post('/risk/simulate', JSON.parse(r.i)); await modal({ title: 'Simulated risk', body: `<pre class="mono small pre-wrap">${esc(JSON.stringify(out, null, 2))}</pre>`, actions: [] }); }
      catch (e) { err(e.detail); }
    };
    $('#rescore').onclick = async () => {
      const c = await modal({ title: 'Re-score all findings', body: '<p>Recompute VEYRS risk for every finding using the current profile and the latest EPSS/KEV data. Safe, but it writes history.</p>', actions: [{ label: 'Re-score' }] });
      if (!c) return;
      try { const out = await post('/risk/rescore', {}); ok(`Re-scored ${fmtNum(out.updated ?? out.count ?? 0)} findings.`); } catch (e) { err(e.detail); }
    };
  } else if (tab === 'upgrade') {
    await upgradePathsTab(body);
  } else {
    const rows = pageOf(await get('/policies/sla/events?size=50')).items;
    body.innerHTML = table([
      { label: 'When', cell: r => fmtDate(r.created_at || r.occurred_at) },
      { label: 'Event', cell: r => statePill(r.event || r.kind) },
      { label: 'Finding', cell: r => r.finding_id ? `<a href="#/findings/${esc(r.finding_id)}">${esc(String(r.finding_id).slice(0, 8))}</a>` : '—' },
      { label: 'Level', num: true, cell: r => fmtNum(r.escalation_level) },
      { label: 'Detail', cell: r => esc((r.message || '').slice(0, 120)) },
    ], rows, { emptyTitle: 'No SLA events recorded' });
  }
});

/* ── Automation ─────────────────────────────────────────────────────────
   Two things that were previously in different places and are the same
   question -- "what does VEYRS do without me?" -- now share one screen:
   automatic ticket creation (new) and workflows (moved here from its own
   top-level entry).

   The workflow editor is the reason this section existed in its current form:
   it asked an operator to hand-write a JSON array of steps, from an example
   that put the parameters under the wrong key. It is now a guided builder that
   renders its fields from `/workflows/actions` -- the same file that executes
   them -- so the form and the engine cannot describe a step differently.
   The JSON is still reachable behind an "Advanced" toggle, because somebody
   pasting a step from support should not have to click through a wizard. */

/* `WorkflowWrite.slug` is required by the API and the old editor never sent
   one, so every "New workflow" attempt 422'd. Derived here rather than asked
   for: a slug is an identifier the operator has no reason to choose.
   Same for SLA policies, risk profiles and teams (0.35.3): each requires a
   slug and none of their dialogs asked for one. Team slugs must be 2+
   characters, so a one-character result gets the fallback appended. */
const slugify = (v, fallback = 'workflow') => {
  const s = String(v || '').toLowerCase().replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '').slice(0, 80);
  return !s ? fallback : s.length < 2 ? `${s}-${fallback}` : s;
};

/* Renders one field of an action's config, from the schema the API returned. */
function wfField(step, field, idx) {
  const id = `wf-${idx}-${field.name}`;
  const cur = (step.config || {})[field.name];
  const val = cur === undefined ? field.default : cur;
  const help = field.help ? `<p class="field-help">${field.help}</p>` : '';
  const label = `<label for="${id}">${esc(field.label)}${field.required ? ' *' : ''}</label>`;
  if (field.type === 'select') {
    return `${label}<select id="${id}" data-step="${idx}" data-field="${esc(field.name)}">
      ${!field.required ? '<option value="">—</option>' : ''}
      ${(field.options || []).map(o =>
        `<option value="${esc(o.value)}"${String(val) === String(o.value) ? ' selected' : ''}>${esc(o.label)}</option>`).join('')}
    </select>${help}`;
  }
  if (field.type === 'multiselect') {
    const chosen = Array.isArray(val) ? val.map(String) : [];
    return `${label}<div class="stack" data-step="${idx}" data-field="${esc(field.name)}" data-kind="multi">
      ${(field.options || []).map(o =>
        `<label class="inline"><input type="checkbox" value="${esc(o.value)}"${chosen.includes(String(o.value)) ? ' checked' : ''}> ${esc(o.label)}</label>`).join('')}
    </div>${help}`;
  }
  if (field.type === 'tags') {
    const joined = Array.isArray(val) ? val.join(', ') : (val || '');
    return `${label}<input id="${id}" data-step="${idx}" data-field="${esc(field.name)}" data-kind="tags"
      value="${esc(joined)}" placeholder="comma-separated">${help}`;
  }
  if (field.type === 'textarea') {
    return `${label}<textarea id="${id}" data-step="${idx}" data-field="${esc(field.name)}">${esc(val || '')}</textarea>${help}`;
  }
  return `${label}<input id="${id}" data-step="${idx}" data-field="${esc(field.name)}" value="${esc(val == null ? '' : val)}">${help}`;
}

/* Reads the builder back into the step array the ENGINE expects.

   `config`, never `params`. Spelled out here because the previous example in
   this file used `params` and the engine reads `step.get("config")`, so every
   workflow built from it ran with an empty configuration and reported success
   — a silent misconfiguration, which is the worst kind. */
function wfCollect(root, schema, steps) {
  return steps.map((step, idx) => {
    const spec = schema[step.action];
    const config = {};
    (spec?.fields || []).forEach(field => {
      const el = root.querySelector(`[data-step="${idx}"][data-field="${CSS.escape(field.name)}"]`);
      if (!el) return;
      if (el.dataset.kind === 'multi') {
        const on = [...el.querySelectorAll('input:checked')].map(i => i.value);
        if (on.length) config[field.name] = on;
      } else if (el.dataset.kind === 'tags') {
        const list = el.value.split(',').map(v => v.trim()).filter(Boolean);
        if (list.length) config[field.name] = list;
      } else if (el.value !== '') {
        // "true"/"false" come back as strings from a <select>. Left as strings
        // would make `internal: "false"` truthy in the engine, which is how a
        // comment marked internal ends up visible to the requester.
        config[field.name] = el.value === 'true' ? true
          : el.value === 'false' ? false : el.value;
      }
    });
    return { action: step.action, config };
  });
}

function workflowDialog(cat, existing = null) {
  const schema = cat.action_schema || {};
  const actions = Object.keys(schema).sort();
  let steps = (existing?.steps || []).map(s => ({
    action: s.action,
    // Tolerate a workflow saved by the old editor: read `params` when `config`
    // is absent, so opening one does not silently blank its configuration.
    config: s.config || s.params || {},
  })).filter(s => schema[s.action]);
  if (!steps.length) steps = [{ action: 'create_ticket', config: {} }];

  const stepsHtml = () => steps.map((step, idx) => {
    const spec = schema[step.action] || { label: step.action, fields: [] };
    return `<div class="wf-step">
      <div class="wf-step-head">
        <span class="wf-step-num">${idx + 1}</span>
        <strong>${esc(spec.label || step.action)}</strong>
        <select data-pick="${idx}" aria-label="Change step ${idx + 1}">
          ${actions.map(a => `<option value="${esc(a)}"${a === step.action ? ' selected' : ''}>${esc(schema[a].label)}</option>`).join('')}
        </select>
        <button type="button" class="btn btn-sm" data-del="${idx}"${steps.length === 1 ? ' disabled' : ''}>Remove</button>
      </div>
      <p class="small muted">${esc(spec.summary || '')}${spec.requires ? ` <em>Needs ${esc(spec.requires)}.</em>` : ''}</p>
      ${(spec.fields || []).map(f => wfField(step, f, idx)).join('')}
    </div>`;
  }).join('');

  const body = `
    <div><label>Name *</label><input name="name" required value="${esc(existing?.name || '')}"></div>
    <div><label>Run this when…</label>
      <select name="trigger">${(cat.triggers || []).map(t =>
        `<option value="${esc(t)}"${existing?.trigger === t ? ' selected' : ''}>${esc(t)} — ${esc((cat.trigger_help || {})[t] || '')}</option>`).join('')}</select></div>
    <h3 style="margin:16px 0 8px">Then do this, in order</h3>
    <div id="wf-steps">${stepsHtml()}</div>
    <button type="button" class="btn btn-sm" id="wf-add">Add a step</button>
    <p class="small muted mt-2">Steps share context and run top to
      bottom: a step that acts on a ticket does nothing unless an “Open a ticket”
      step came before it. It reports <span class="mono">skipped</span> rather than
      failing, so the order is worth checking twice.</p>`;

  const promise = modal({
    title: existing ? `Edit ${existing.name}` : 'New workflow',
    wide: true,
    body,
    actions: [{
      label: existing ? 'Save' : 'Create',
      keepOpen: true,
      run: async (form, root) => {
        if (!form.name?.trim()) { err('Name is required.'); return false; }
        const built = wfCollect(root, schema, steps);
        const payload = { name: form.name.trim(), trigger: form.trigger, steps: built };
        try {
          if (existing) await patch('/workflows/' + existing.id, payload);
          else await post('/workflows', Object.assign({ slug: slugify(form.name) }, payload));
          ok(existing ? 'Workflow saved.' : 'Workflow created.');
          render();
          return true;
        } catch (e) { err(e.detail); return false; }
      },
    }],
  });

  // `modal()` appends its node synchronously inside the Promise executor, so
  // the body is already in the document here. Re-painting keeps the mutable
  // `steps` array as the single source of truth: reading the DOM back into it
  // on every keystroke is how a half-typed field disappears on re-render.
  const host = document.querySelector('#modal-root .modal-body');
  if (host) {
    const repaint = () => {
      // Preserve what is typed before the structure changes underneath it.
      wfCollect(host, schema, steps).forEach((s, i) => { steps[i].config = s.config; });
      host.querySelector('#wf-steps').innerHTML = stepsHtml();
    };
    host.addEventListener('click', e => {
      if (e.target.id === 'wf-add') {
        repaint();
        steps.push({ action: actions[0], config: {} });
        host.querySelector('#wf-steps').innerHTML = stepsHtml();
      }
      const del = e.target.dataset?.del;
      if (del !== undefined) {
        repaint();
        steps.splice(Number(del), 1);
        host.querySelector('#wf-steps').innerHTML = stepsHtml();
      }
    });
    host.addEventListener('change', e => {
      const idx = e.target.dataset?.pick;
      if (idx === undefined) return;
      const i = Number(idx);
      const chosen = e.target.value;
      repaint();
      // A changed action gets a FRESH config. Carrying the old one over would
      // leave, say, `state: "closed"` sitting under a "tag the asset" step:
      // invisible in the form, still posted to the API.
      steps[i] = { action: chosen, config: {} };
      host.querySelector('#wf-steps').innerHTML = stepsHtml();
    });
  }
  return promise;
}

route('automation', async (view, _p, params) => {
  const tab = params.get('tab') || 'tickets';
  view.innerHTML = `
    <div class="page-head"><div><h1>Automation</h1>
      <p>What VEYRS does on its own. Everything here is off or conservative by default: a platform that starts opening tickets and sending mail the moment it is upgraded is a platform nobody trusts with the switch.</p></div></div>
    <div class="tabs">${[['tickets', 'Automatic tickets'], ['workflows', 'Workflows'], ['runs', 'Workflow runs']]
      .map(([k, l]) => `<button data-t="${k}" class="${tab === k ? 'active' : ''}">${l}</button>`).join('')}</div>
    <div id="auto-body"><div class="loading">Loading…</div></div>`;
  view.querySelector('.tabs').onclick = e => { if (e.target.dataset.t) location.hash = '#/automation?tab=' + e.target.dataset.t; };
  const body = $('#auto-body');

  if (tab === 'tickets') return autoTicketTab(body);

  const cat = await get('/workflows/actions');
  if (tab === 'workflows') {
    const rows = pageOf(await get('/workflows')).items;
    body.innerHTML = explainer('automation.workflows', {
      title: 'What a workflow is, and what it cannot do',
      what: 'A trigger plus an ordered list of steps. When the trigger fires, the '
          + 'steps run against the finding or ticket that caused it.',
      who: 'Whoever owns the remediation process. Rarely, and usually once.',
      effect: 'From the next matching event onward. Nothing runs retroactively — '
            + 'enabling a workflow does not act on findings that already exist.',
      warn: 'Steps run <strong>in order and share context</strong>. “Set ticket '
          + 'priority” and “Comment on the ticket” do nothing unless an “Open a '
          + 'ticket” step ran before them — they report <em>skipped</em>, not an '
          + 'error, so a workflow with the steps in the wrong order looks '
          + 'perfectly healthy in the run log.',
      links: [{ label: 'Workflow runs', href: '#/automation?tab=runs' }],
    }) + `<div class="row mb-2">
        <button class="btn btn-sm btn-primary" id="add">New workflow</button>
        <button class="btn btn-sm" id="seed">Seed the built-in set</button></div>`
      + table([
        { label: 'Name', cell: r => esc(r.name) },
        { label: 'Runs when', cell: r => `<span class="pill st-neutral mono">${esc(r.trigger)}</span>
            <div class="small muted">${esc((cat.trigger_help || {})[r.trigger] || '')}</div>` },
        { label: 'Steps', cell: r => (r.steps || []).length
            ? (r.steps || []).map((st, i) =>
                `<div class="small">${i + 1}. ${esc((cat.action_schema?.[st.action]?.label) || st.action)}${
                  // A step whose config is empty when the action has required
                  // fields is the fingerprint of the old `params` bug. Named
                  // here rather than left to be discovered at 3am.
                  (cat.action_schema?.[st.action]?.fields || []).some(f => f.required)
                  && !Object.keys(st.config || {}).length
                    ? ' <span class="pill st-warn">unconfigured</span>' : ''
                }</div>`).join('')
            : '<span class="muted small">no steps</span>' },
        { label: 'Enabled', cell: r => r.is_enabled === false || r.enabled === false ? 'No' : 'Yes' },
        { label: '', cell: r => `<button class="btn btn-sm" data-edit="${esc(r.id)}">Edit</button>` },
      ], rows, { emptyTitle: 'No workflows defined',
                 emptyHint: 'Use “Seed the built-in set” for the detect → assess → assign → ticket → SLA chain.' });

    $('#seed').onclick = async () => {
      try { await post('/workflows/seed', {}); ok('Built-in workflows installed.'); render(); }
      catch (e) { err(e.detail); }
    };
    $('#add').onclick = () => workflowDialog(cat);
    body.addEventListener('click', e => {
      const id = e.target.dataset?.edit;
      if (id) workflowDialog(cat, rows.find(r => String(r.id) === id));
    });

  } else {
    const rows = pageOf(await get('/workflows/runs?size=50')).items;
    body.innerHTML = explainer('automation.runs', {
      title: 'Reading a run',
      what: 'One row per time a workflow fired, with how many of its steps executed.',
      who: 'Anyone asking why an email did or did not arrive.',
      effect: 'Read-only.',
      warn: 'A run can be <em>succeeded</em> and still have done nothing: steps that '
          + 'find no ticket or no recipient report <span class="mono">skipped</span> '
          + 'and <span class="mono">warning</span>, which do not fail the run. '
          + 'Compare “Steps run” against the workflow’s step count.',
    }) + table([
      { label: 'When', cell: r => fmtDate(r.started_at || r.created_at) },
      { label: 'Workflow', cell: r => esc(r.workflow_name || r.workflow_id) },
      { label: 'Trigger', cell: r => `<span class="mono small">${esc(r.trigger)}</span>` },
      { label: 'Status', cell: r => statePill(r.status) },
      { label: 'Steps run', num: true, cell: r => fmtNum(r.steps_executed) },
      { label: 'Error', cell: r => esc((r.error || '').slice(0, 100)) },
    ], rows, { emptyTitle: 'No workflow runs' });
  }
});

/* ── Automatic tickets ─────────────────────────────────────────────────
   The screen that answers the question this feature has to answer BEFORE it
   is switched on: how many tickets is this about to create? The preview runs
   the real predicate against the real estate and writes nothing. */
async function autoTicketTab(body) {
  const state = await get('/tickets/automation');
  const editable = can('ticket:admin');

  const preview = async (overrides) => {
    const out = $('#at-preview');
    out.innerHTML = '<div class="loading">Counting…</div>';
    try {
      const r = await post('/tickets/automation/preview', overrides || {});
      out.innerHTML = `<div class="grid cols-3 mt-3">
          <div class="card stat"><span class="label">Would open now</span>
            <span class="value">${fmtNum(r.would_create)}</span>
            <span class="hint">${Object.entries(r.by_severity || {}).map(([k, v]) => `${v} ${k}`).join(' · ') || 'nothing matches'}</span></div>
          <div class="card stat"><span class="label">Already ticketed</span>
            <span class="value">${fmtNum(r.already_ticketed)}</span>
            <span class="hint">these are skipped, never duplicated</span></div>
          <div class="card stat"><span class="label">Findings examined</span>
            <span class="value">${fmtNum(r.scanned)}</span>
            <span class="hint">${r.truncated ? 'capped — the real number is higher' : 'the whole backlog'}</span></div>
        </div>
        ${(r.sample || []).length ? `<div class="card mt-3"><h3>First ${r.sample.length}</h3>` + table([
          { label: 'Finding', cell: f => `<a href="#/findings/${esc(f.finding_id)}">${esc(f.title || f.finding_id)}</a>` },
          { label: 'Severity', cell: f => sevPill(f.severity) },
          { label: 'Risk', num: true, cell: f => fmtScore(f.risk_score) },
          { label: 'KEV', cell: f => f.kev ? '<span class="pill pill-kev">KEV</span>' : '' },
        ], r.sample) + '</div>' : ''}`;
    } catch (e) { out.innerHTML = `<p class="muted">${esc(e.detail)}</p>`; }
  };

  body.innerHTML = explainer('automation.tickets', {
    title: 'When VEYRS opens a ticket without being asked',
    what: 'Every finding that clears <strong>all</strong> the conditions below gets '
        + 'one <span class="mono">remediation</span> ticket, with the priority its '
        + 'risk score implies (≥90 critical, ≥70 high, ≥40 medium) and the SLA '
        + 'deadline it already carries.',
    who: 'The security manager. It governs the whole estate, so a team-scoped '
       + 'identity cannot change it.',
    effect: 'Findings from that moment on — including existing ones whose risk '
          + '<em>rises</em> past the threshold, which is the case worth having: a '
          + 'CVE you have lived with for months joins CISA KEV overnight and the '
          + 'ticket is waiting in the morning. To catch up on the existing '
          + 'backlog you have to ask, below.',
    warn: 'One open remediation ticket per finding, always: creating a second is a '
        + 'no-op that returns the first. And the automation is <strong>capped</strong> '
        + `at ${fmtNum(state.max_per_run)} tickets per ${fmtNum(state.budget_window_minutes)} minutes — `
        + 'when the cap is hit, work is skipped and logged rather than queued.',
  }) + `
    <div class="grid cols-2">
      <div class="card"><h2>Conditions</h2>
        <form id="at-form">
          <label class="inline"><input type="checkbox" name="enabled"${state.enabled ? ' checked' : ''}${editable ? '' : ' disabled'}>
            <strong>Open tickets automatically</strong></label>
          <p class="small muted">${state.explicit
            ? `Set deliberately${state.changed_at ? ' on ' + fmtDate(state.changed_at) : ''}.`
            : 'Never configured — this is the shipped default (off).'}</p>

          <label class="mt-3">Minimum VEYRS risk score</label>
          <input type="number" name="min_risk_score" min="0" max="100" step="1"
            value="${state.min_risk_score == null ? '' : state.min_risk_score}"${editable ? '' : ' disabled'}>
          <p class="field-help">Leave empty for “no risk threshold” — allowed only if
            you also restrict by severity or KEV, otherwise every open finding qualifies.</p>

          <label class="mt-3">Only these severities</label>
          <div class="stack" id="at-sev">
            ${['critical', 'high', 'medium', 'low'].map(sv =>
              `<label class="inline"><input type="checkbox" value="${sv}"${(state.severities || []).includes(sv) ? ' checked' : ''}${editable ? '' : ' disabled'}> ${titleCase(sv)}</label>`).join('')}
          </div>
          <p class="field-help">None ticked means “do not filter by severity”, not “nothing”.</p>

          <div class="stack mt-3">
            <label class="inline"><input type="checkbox" name="require_kev"${state.require_kev ? ' checked' : ''}${editable ? '' : ' disabled'}>
              Only CVEs in the CISA KEV catalogue</label>
            <label class="inline"><input type="checkbox" name="internet_exposed_only"${state.internet_exposed_only ? ' checked' : ''}${editable ? '' : ' disabled'}>
              Only findings on internet-facing assets</label>
            <label class="inline"><input type="checkbox" name="require_owner"${state.require_owner ? ' checked' : ''}${editable ? '' : ' disabled'}>
              Only findings that already have an owner</label>
          </div>
          <p class="field-help">The ownership rule is on by default: a ticket with no
            assignee lands in a queue nobody reads.
            <a href="#/findings?queue=unowned">See what has no owner</a>.</p>

          <label class="mt-3">Cap per hour</label>
          <input type="number" name="max_per_run" min="1" max="500" value="${fmtNum(state.max_per_run)}"${editable ? '' : ' disabled'}>

          <div class="row mt-4">
            <button class="btn" type="button" id="at-preview-btn">Preview these settings</button>
            ${editable ? '<button class="btn btn-primary" type="submit">Save</button>' : ''}
          </div>
          ${editable ? '' : '<p class="small muted">You can read this policy but not change it — it needs an estate-wide <span class="mono">ticket:admin</span> grant.</p>'}
        </form>
      </div>

      <div class="card"><h2>The existing backlog</h2>
        <p class="small">Turning the switch on changes nothing about findings that
          already exist. That is deliberate: an estate with hundreds of open
          findings would produce hundreds of tickets and hundreds of
          notifications on the next correlation pass.</p>
        <p class="small">Catching up is a separate, deliberate action — and it
          always shows you the number first.</p>
        <div class="row mt-3">
          <button class="btn" id="at-dry">Dry run the backfill</button>
          ${editable ? '<button class="btn btn-primary" id="at-run">Open them for real…</button>' : ''}
        </div>
        <div id="at-backfill"></div>
      </div>
    </div>
    <div id="at-preview"></div>`;

  const readForm = () => {
    const f = $('#at-form');
    const severities = [...$('#at-sev').querySelectorAll('input:checked')].map(i => i.value);
    const body = {
      enabled: f.enabled.checked,
      severities,
      require_kev: f.require_kev.checked,
      internet_exposed_only: f.internet_exposed_only.checked,
      require_owner: f.require_owner.checked,
      max_per_run: Number(f.max_per_run.value || 50),
    };
    // An empty box means "no threshold" and must be sent as an explicit null,
    // not omitted: `exclude_unset` on the server would otherwise leave the old
    // number in place and the operator would watch their change do nothing.
    body.min_risk_score = f.min_risk_score.value === '' ? null : Number(f.min_risk_score.value);
    return body;
  };

  $('#at-preview-btn').onclick = () => preview(readForm());
  $('#at-form').onsubmit = async e => {
    e.preventDefault();
    try { await put('/tickets/automation', readForm()); ok('Policy saved.'); render(); }
    catch (ex) { err(ex.detail); }
  };
  $('#at-dry').onclick = async () => {
    const out = $('#at-backfill');
    out.innerHTML = '<div class="loading">Counting…</div>';
    try {
      const r = await post('/tickets/automation/backfill', { dry_run: true, limit: 2000 });
      out.innerHTML = `<p class="mt-3"><strong>${fmtNum(r.eligible)}</strong> finding(s) would
        get a ticket. ${fmtNum(r.skipped_existing)} already have one.
        ${r.capped ? `<span class="pill st-warn">${fmtNum(r.remaining)} beyond the limit</span>` : ''}</p>
        <p class="small muted">Nothing was written.</p>`;
    } catch (e) { out.innerHTML = `<p class="muted">${esc(e.detail)}</p>`; }
  };
  if (editable) $('#at-run').onclick = async () => {
    const dry = await post('/tickets/automation/backfill', { dry_run: true, limit: 2000 });
    const c = await modal({
      title: 'Open tickets for the backlog',
      body: `<p>This will create <strong>${fmtNum(Math.min(dry.eligible, 500))}</strong> remediation
          ticket(s) right now, each with a reference number, an SLA deadline and whatever
          notifications your workflows send.</p>
        <p class="small muted">There is no undo. Tickets are closed individually.</p>
        <div><label>How many at most</label><input name="limit" type="number" min="1" max="2000" value="${Math.min(dry.eligible, 500) || 1}"></div>`,
      actions: [{ label: 'Open them', cls: 'btn-danger' }],
    });
    if (!c) return;
    try {
      const r = await post('/tickets/automation/backfill', { dry_run: false, limit: Number(c.limit) });
      ok(`Opened ${fmtNum(r.created)} ticket(s).${r.capped ? ` ${fmtNum(r.remaining)} left — run it again.` : ''}`);
      render();
    } catch (e) { err(e.detail); }
  };

  preview(null);
}

/* ── Compliance ─────────────────────────────────────────────────────── */
route('compliance', async (view, parts) => {
  if (parts[0]) return frameworkDetail(view, parts[0]);
  const fws = pageOf(await get('/compliance/frameworks')).items;
  view.innerHTML = `
    <div class="page-head"><div><h1>Compliance</h1>
      <p>Controls linked to real evidence: assets, findings, remediation and tickets. VEYRS ships partial catalogues where the source text is copyrighted, and says so on every one.</p></div></div>
    <div class="grid cols-2">${fws.map(f => `
      <a class="card" href="#/compliance/${esc(f.id)}" style="text-decoration:none;color:inherit">
        <h2>${esc(f.name)} <span class="muted small">v${esc(f.version || '')}</span></h2>
        <p class="small muted">${esc(f.description || '')}</p>
        <p class="small"><strong>${esc(f.publisher || '')}</strong>${f.licence_note ? ' · <span class="muted">licence-constrained catalogue</span>' : ''}</p>
      </a>`).join('') || '<div class="card"><div class="empty"><strong>No frameworks</strong>Import a framework to begin.</div></div>'}</div>`;
});

async function frameworkDetail(view, id) {
  // The coverage payload already joins the catalogue with each control's
  // implementation status, evidence count and automation signal — the separate
  // /controls list is the bare catalogue and carries NO state. Rendering the
  // catalogue here painted every control "Not Assessed" forever.
  const cov = await get(`/compliance/frameworks/${id}/coverage`);
  const fw = cov.framework || {};
  const counts = cov.counts || {};
  const rows = cov.controls || [];
  view.innerHTML = `
    <div class="page-head"><div><h1>${esc(fw.name || 'Framework')} <span class="muted small">v${esc(fw.version || '')}</span></h1>
      <p>Implementation state is <strong>derived from evidence</strong>, never self-declared. Automatic signals can reach “partial” — only a human with evidence reaches “implemented”.</p></div>
      <div class="page-actions"><button class="btn" id="refresh">Refresh signals</button><a class="btn" href="#/compliance">All frameworks</a></div></div>
    ${fw.is_partial && fw.disclaimer ? `<div class="scope-banner" role="note"><strong>Partial catalogue</strong><span>${esc(fw.disclaimer)}</span></div>` : ''}
    <div class="grid cols-4">
      <div class="card stat"><span class="label">Applicable controls</span><span class="value">${fmtNum(cov.applicable_controls ?? rows.length)}</span></div>
      <div class="card stat ${tone('ok', cov.implemented)}"><span class="label">Implemented</span><span class="value">${fmtNum(cov.implemented)}</span></div>
      <div class="card stat ${tone('warn', counts.partial)}"><span class="label">Partial</span><span class="value">${fmtNum(counts.partial)}</span></div>
      <div class="card stat"><span class="label">Coverage</span><span class="value">${cov.implemented_ratio == null ? '—' : fmtPct(cov.implemented_ratio)}</span></div>
    </div>
    <div class="card mt-4"><h2>Controls</h2>
      ${table([
        { label: 'Ref', cell: r => `<span class="mono">${esc(r.ref)}</span>` },
        { label: 'Title', cell: r => esc(r.title) },
        { label: 'Theme', cell: r => esc(titleCase(r.theme || '—')) },
        { label: 'State', cell: r => statePill(r.status || 'not_assessed') + (r.is_stale ? ' <span class="pill st-warn">Stale</span>' : '') },
        { label: 'Signal', cell: r => r.automation_signal ? `<span class="mono small" title="${esc(r.automation_signal)}">${esc(String(r.automated_result ?? 'auto'))}</span>` : '<span class="muted small">manual</span>' },
        { label: 'Evidence', num: true, cell: r => fmtNum(r.evidence_count) },
        { label: '', cell: r => `<button class="btn btn-sm" data-chain="${esc(r.control_id)}">Chain</button>` },
      ], rows, { emptyTitle: 'No controls imported', emptyHint: 'Import the catalogue for this framework first.' })}</div>`;
  $('#refresh').onclick = async () => {
    try { const r = await post(`/compliance/frameworks/${id}/refresh-signals`, {}); ok(`Signals refreshed: ${fmtNum(r.updated ?? 0)} controls touched.`); render(); }
    catch (e) { err(e.detail); }
  };
  $$('[data-chain]', view).forEach(b => b.onclick = async () => {
    try {
      const chain = await get(`/compliance/controls/${b.dataset.chain}/chain`);
      await modal({ title: 'Control → evidence chain', wide: true, body: `<pre class="mono small pre-wrap">${esc(JSON.stringify(chain, null, 2))}</pre>`, actions: [] });
    } catch (e) { err(e.detail); }
  });
}

/* ── Reports ────────────────────────────────────────────────────────── */
route('reports', async (view, _p, params) => {
  const tab = params.get('tab') || 'fixed';
  view.innerHTML = `
    <div class="page-head"><div><h1>Reports</h1>
      <p>Every export carries its provenance: which data, which window, generated when and by whom. A report you cannot trace is a report you cannot defend in an audit.</p></div></div>
    <div class="tabs">${[['fixed', 'Fixed reports'], ['builder', 'Builder']]
      .map(([k, l]) => `<button data-t="${k}" class="${tab === k ? 'active' : ''}">${l}</button>`).join('')}</div>
    <div id="reports-body"><div class="loading">Loading…</div></div>`;
  view.querySelector('.tabs').onclick = e => { if (e.target.dataset.t) location.hash = '#/reports?tab=' + e.target.dataset.t; };
  if (tab === 'builder') return reportBuilderTab($('#reports-body'));
  const cat = await get('/reports');
  $('#reports-body').innerHTML = `
    <div class="grid cols-2">${(cat.reports || []).map(r => `
      <div class="card"><h2>${esc(r.title)}</h2>
        <p class="small muted">${esc(r.description || '')}</p>
        <div class="row mt-3">
          ${(r.formats || cat.formats).map(f => `<a class="btn btn-sm" href="${API}/reports/${esc(r.slug)}/export?format=${esc(f)}" data-dl="${esc(r.slug)}|${esc(f)}">${esc(f.toUpperCase())}</a>`).join('')}
          <button class="btn btn-sm" data-preview="${esc(r.slug)}">Preview</button>
        </div>
        ${r.available === false ? '<p class="small muted mt-2">Not available: no data in scope yet.</p>' : ''}</div>`).join('')}</div>`;

  /* The Compliance Coverage report is per framework: the API refuses it without
     `framework_id`, and the buttons used to send none (a 422 on every click
     until 0.35.3). Ask which framework; null = the operator cancelled. */
  const reportParams = async slug => {
    if (slug !== 'compliance') return {};
    const fws = pageOf(await get('/compliance/frameworks')).items;
    if (!fws.length) { err('No compliance framework is loaded yet.'); return null; }
    const form = await modal({
      title: 'Which framework?',
      body: `<div><label>Framework</label><select name="framework_id">${fws.map(f =>
        `<option value="${esc(f.id)}">${esc(f.name)} v${esc(f.version || '')}</option>`).join('')}</select></div>`,
      actions: [{ label: 'Continue' }],
    });
    return form ? { framework_id: form.framework_id } : null;
  };

  /* Preview = the same JSON the export is built from, in a dialog. It used to
     link to #/reports/{slug}, which this route answers with the catalogue. */
  $$('[data-preview]', view).forEach(b => b.onclick = async () => {
    const slug = b.dataset.preview;
    try {
      const extra = await reportParams(slug);
      if (extra === null) return;
      const data = await get(`/reports/${slug}` + qs(extra));
      const text = JSON.stringify(data, null, 2);
      await modal({ title: 'Preview', wide: true, actions: [],
        body: `<pre class="mono small" style="white-space:pre-wrap;max-height:60vh;overflow:auto">${esc(text.length > 20000 ? text.slice(0, 20000) + '\n…' : text)}</pre>` });
    } catch (ex) { err(ex.detail || ex.message); }
  });

  // Exports need the bearer token, so download through fetch rather than a bare link.
  $$('[data-dl]', view).forEach(a => a.onclick = async e => {
    e.preventDefault();
    const [slug, fmt] = a.dataset.dl.split('|');
    const extra = await reportParams(slug).catch(ex => { err(ex.detail || ex.message); return null; });
    if (extra === null) return;
    a.textContent = '…';
    try {
      const res = await rawFetch(`/reports/${slug}/export` + qs({ format: fmt, ...extra }));
      if (!res.ok) throw new ApiError(res.status, await res.text());
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url; link.download = `veyrs-${slug}.${fmt}`;
      link.click(); URL.revokeObjectURL(url);
      ok('Export downloaded.');
    } catch (ex) { err(ex.detail || ex.message); }
    a.textContent = fmt.toUpperCase();
  });
});

/* ── Report builder (Reports → Builder) ─────────────────────────────────
   The client builds a JSON spec from the catalog the server offers and never
   anything else: there is no SQL box, and every field, operator and value
   below is re-validated server-side (`services/report_builder.py`). Results
   are the caller's own slice -- the API applies role and team scope -- and the
   scope line from the provenance is printed above the table so a narrowed
   count is never read as the estate's. Self-contained on purpose: one entry
   point, `reportBuilderTab(body)`, called from the Reports route. */
async function reportBuilderTab(body) {
  const cat = await get('/report-builder/catalog');
  const entities = (cat.entities || []).filter(e => e.available);
  if (!entities.length) {
    body.innerHTML = `<div class="card"><h2>Nothing to report on</h2><p class="muted">Your role can open the builder but cannot read any of the entities it reports on (findings, assets, vulnerabilities, tickets, the risk register).</p></div>`;
    return;
  }
  const rb = { saved: [], current: null, result: null,
               spec: { entity: entities[0].key, columns: [...entities[0].default_columns],
                       filters: [], group_by: [], aggregates: [], sort: [], limit: null } };
  const ent = () => entities.find(e => e.key === rb.spec.entity) || entities[0];
  const fld = k => ent().fields.find(f => f.key === k);
  const opts = (items, sel) => items.map(([v, l]) => `<option value="${esc(v)}" ${v === sel ? 'selected' : ''}>${esc(l)}</option>`).join('');
  const fieldOpts = (sel, pred = () => true) => opts(ent().fields.filter(pred).map(f => [f.key, f.label]), sel);
  const aggKey = a => a.fn === 'count' ? 'count' : `${a.fn}:${a.field}`;

  async function loadSaved() {
    try { rb.saved = (await get('/report-builder/queries')).items || []; } catch (e) { rb.saved = []; }
  }

  function valueInput(f, i) {
    const field = fld(f.field) || { type: 'string' };
    const v = f.value;
    if (['is_null', 'not_null'].includes(f.op)) return '<span class="muted small">no value</span>';
    if (['last_days', 'older_than_days', 'next_days'].includes(f.op))
      return `<input type="number" min="1" max="3650" data-fv="${i}" value="${esc(v ?? 30)}" placeholder="days">`;
    if (field.type === 'bool')
      return `<select data-fv="${i}">${opts([['true', 'true'], ['false', 'false']], String(v ?? true))}</select>`;
    if (field.type === 'enum' && ['eq', 'ne'].includes(f.op))
      return `<select data-fv="${i}">${opts((field.values || []).map(x => [x, x]), v)}</select>`;
    const list = Array.isArray(v) ? v.join(', ') : (v ?? '');
    const hint = ['in', 'not_in'].includes(f.op) ? 'a, b, c' : f.op === 'between' ? 'low, high'
               : field.type === 'date' ? 'YYYY-MM-DD' : 'value';
    return `<input data-fv="${i}" value="${esc(list)}" placeholder="${esc(hint)}">`;
  }

  function coerce(field, raw) {
    if (field.type === 'number') return Number(raw);
    if (field.type === 'bool') return raw === true || raw === 'true';
    return String(raw);
  }

  /* Form → spec. Values are typed here for convenience only; the server
     re-checks every one of them against the field's type. */
  function readForm() {
    const s = rb.spec;
    s.columns = $$('[data-col]', body).filter(c => c.checked).map(c => c.dataset.col);
    s.group_by = $$('[data-gb]', body).map(x => x.value).filter(Boolean);
    s.aggregates = $$('[data-agg]', body).map(row => {
      const fn = $('[data-agg-fn]', row).value;
      if (fn === 'count') return { fn };
      // Switching from `count` there is no field picker yet: start from the
      // first field this function accepts, and let the repaint offer the rest.
      const pick = $('[data-agg-field]', row);
      const types = cat.aggregates[fn] || [];
      const okField = pick && types.includes((fld(pick.value) || {}).type);
      return { fn, field: okField ? pick.value : (ent().fields.find(f => types.includes(f.type)) || {}).key };
    });
    s.filters = $$('[data-filter]', body).map((row, i) => {
      const field = fld($('[data-ff]', row).value) || { type: 'string' };
      const ops = cat.operators[field.type] || [];
      // A field change can leave an operator the new type does not have.
      const op = ops.includes($('[data-fo]', row).value) ? $('[data-fo]', row).value : ops[0];
      const out = { field: field.key, op };
      const input = $(`[data-fv="${i}"]`, row);
      if (['is_null', 'not_null'].includes(op) || !input) return out;
      const raw = input.value;
      if (['last_days', 'older_than_days', 'next_days'].includes(op)) out.value = parseInt(raw, 10);
      else if (['in', 'not_in', 'between'].includes(op))
        out.value = raw.split(',').map(x => x.trim()).filter(x => x !== '').map(x => coerce(field, x));
      else out.value = coerce(field, raw);
      return out;
    });
    const sf = $('#rb-sort', body).value;
    s.sort = sf ? [{ field: sf, dir: $('#rb-dir', body).value }] : [];
    const lim = parseInt($('#rb-limit', body).value, 10);
    s.limit = Number.isFinite(lim) && lim > 0 ? lim : null;
    // Grouped reports send no columns, but the ticks are kept for when the
    // grouping is removed again.
    const grouped = s.group_by.length || s.aggregates.length;
    return { entity: s.entity, columns: grouped ? [] : s.columns, filters: s.filters, group_by: s.group_by,
             aggregates: s.aggregates, sort: s.sort, limit: s.limit };
  }

  function sortChoices() {
    const s = rb.spec;
    if (s.group_by.length || s.aggregates.length) {
      const aggs = s.aggregates.length ? s.aggregates : [{ fn: 'count' }];
      return [...s.group_by.map(k => [k, (fld(k) || {}).label || k]),
              ...aggs.map(a => [aggKey(a), a.fn === 'count' ? 'Count' : `${a.fn} of ${(fld(a.field) || {}).label || a.field}`])];
    }
    return ent().fields.map(f => [f.key, f.label]);
  }

  function resultHtml() {
    const r = rb.result;
    if (!r) return '<p class="muted small">Choose what to see and press Run. Nothing is saved until you press Save.</p>';
    const cols = (r.columns || []).map(c => ({
      label: c.label, num: c.type === 'number',
      cell: row => { const v = row[c.key]; return v === null || v === undefined ? '<span class="muted">—</span>' : esc(v); },
    }));
    return `<p class="small muted">${esc(fmtNum(r.row_count))} row(s)${r.truncated ? ` — <strong>truncated at ${esc(fmtNum(r.limit))}</strong>; narrow the filters or export for more` : ''}.
        Scope: <strong>${esc(r.provenance && r.provenance.scope)}</strong>. Generated ${esc(fmtDate(r.provenance && r.provenance.generated_at))}.</p>
      ${table(cols, r.rows || [], { emptyTitle: 'No rows match', emptyHint: 'Loosen a filter, or check the scope line above.' })}`;
  }

  function paint() {
    const s = rb.spec, e = ent();
    const grouped = s.group_by.length || s.aggregates.length;
    const savedOpts = rb.saved.map(q => [q.id, `${q.name}${q.is_shared ? ' (shared)' : ''}${q.valid ? '' : ' (needs editing)'}`]);
    const mine = rb.current && rb.current.is_mine;
    body.innerHTML = `
      <div class="stack">
      <div class="card">
        <div class="filters">
          <label>Report on <select id="rb-entity">${opts(entities.map(x => [x.key, x.label]), s.entity)}</select></label>
          <label>Saved reports <select id="rb-saved"><option value="">— new report —</option>${opts(savedOpts, rb.current && rb.current.id)}</select></label>
          ${mine ? '<button class="btn btn-sm btn-danger" id="rb-delete">Delete saved</button>' : ''}
        </div>
        ${rb.current && !rb.current.valid ? `<p class="small muted">This saved report no longer matches the catalog: ${esc(rb.current.problem)}</p>` : ''}
        <p class="small muted">${esc(e.description || '')}</p>

        <h3 class="section-h">Columns${grouped ? ' <span class="muted small">(a grouped report shows the group-by fields and the aggregates instead)</span>' : ''}</h3>
        <div class="checkgrid">${e.fields.map(f => `<label title="${esc(f.description || '')}"><input type="checkbox" data-col="${esc(f.key)}" ${s.columns.includes(f.key) ? 'checked' : ''} ${grouped ? 'disabled' : ''}> ${esc(f.label)}</label>`).join('')}</div>

        <h3 class="section-h">Filters</h3>
        ${s.filters.map((f, i) => {
          const field = fld(f.field) || e.fields[0];
          return `<div class="filters" data-filter="${i}">
            <select data-ff="${i}">${fieldOpts(field.key)}</select>
            <select data-fo="${i}">${opts((cat.operators[field.type] || []).map(o => [o, o.replace(/_/g, ' ')]), f.op)}</select>
            ${valueInput(f, i)}
            <button class="btn btn-sm btn-ghost" data-frm="${i}" aria-label="Remove filter">✕</button></div>`;
        }).join('')}
        <button class="btn btn-sm" id="rb-addf">Add filter</button>

        <h3 class="section-h">Group by and aggregate <span class="muted small">(optional, up to ${esc(cat.limits.group_by)} fields)</span></h3>
        <div class="filters">${[0, 1, 2].slice(0, cat.limits.group_by).map(i => `<select data-gb="${i}"><option value="">—</option>${fieldOpts(s.group_by[i], f => f.groupable)}</select>`).join('')}</div>
        ${s.aggregates.map((a, i) => `<div class="filters" data-agg="${i}">
            <select data-agg-fn>${opts(Object.keys(cat.aggregates).map(k => [k, k.replace(/_/g, ' ')]), a.fn)}</select>
            ${a.fn === 'count' ? '' : `<select data-agg-field>${fieldOpts(a.field, f => (cat.aggregates[a.fn] || []).includes(f.type))}</select>`}
            <button class="btn btn-sm btn-ghost" data-arm="${i}" aria-label="Remove aggregate">✕</button></div>`).join('')}
        <button class="btn btn-sm" id="rb-adda">Add aggregate</button>

        <h3 class="section-h">Sort and limit</h3>
        <div class="filters">
          <select id="rb-sort"><option value="">— default —</option>${opts(sortChoices(), s.sort[0] && s.sort[0].field)}</select>
          <select id="rb-dir">${opts([['desc', 'descending'], ['asc', 'ascending']], (s.sort[0] && s.sort[0].dir) || 'desc')}</select>
          <input id="rb-limit" type="number" min="1" max="${esc(cat.limits.export_rows)}" value="${esc(s.limit ?? '')}" placeholder="rows (default ${esc(cat.limits.default_rows)})">
        </div>
        <div class="row mt-4">
          <button class="btn btn-primary" id="rb-run">Run</button>
          ${(cat.formats || []).filter(f => f !== 'json').map(f => `<button class="btn" data-rbx="${esc(f)}">Export ${esc(f.toUpperCase())}</button>`).join('')}
          <button class="btn" id="rb-save">${mine ? 'Save changes' : 'Save'}</button>
        </div>
        <p class="small muted">On screen at most ${esc(fmtNum(cat.limits.run_rows))} rows; exports at most ${esc(fmtNum(cat.limits.export_rows))}. Every export carries provenance, including the scope it was produced under, and is audited.</p>
      </div>
      <div class="card"><h2>Result</h2><div id="rb-result">${resultHtml()}</div></div>
      </div>`;
    wire();
  }

  function wire() {
    const s = rb.spec;
    const repaint = () => { readForm(); paint(); };
    $('#rb-entity', body).onchange = ev => {
      const next = entities.find(x => x.key === ev.target.value);
      rb.spec = { entity: next.key, columns: [...next.default_columns], filters: [], group_by: [],
                  aggregates: [], sort: [], limit: null };
      rb.current = null; rb.result = null; paint();
    };
    $('#rb-saved', body).onchange = ev => {
      const q = rb.saved.find(x => x.id === ev.target.value);
      if (!q) { rb.current = null; paint(); return; }
      if (!entities.some(x => x.key === q.spec.entity)) { err('Your role cannot read the entity this report is about.'); return; }
      rb.current = q; rb.result = null;
      rb.spec = Object.assign({ columns: [], filters: [], group_by: [], aggregates: [], sort: [], limit: null },
                              JSON.parse(JSON.stringify(q.spec)));
      paint();
    };
    $$('[data-ff], [data-fo], [data-gb], [data-agg-fn]', body).forEach(x => x.onchange = repaint);
    $$('[data-col]', body).forEach(x => x.onchange = () => readForm());
    $('#rb-addf', body).onclick = () => {
      readForm();
      const f = ent().fields[0];
      s.filters.push({ field: f.key, op: (cat.operators[f.type] || ['eq'])[0], value: '' });
      paint();
    };
    $('#rb-adda', body).onclick = () => { readForm(); s.aggregates.push({ fn: 'count' }); paint(); };
    $$('[data-frm]', body).forEach(b => b.onclick = () => { readForm(); s.filters.splice(Number(b.dataset.frm), 1); paint(); });
    $$('[data-arm]', body).forEach(b => b.onclick = () => { readForm(); s.aggregates.splice(Number(b.dataset.arm), 1); paint(); });
    $('#rb-run', body).onclick = async () => {
      const spec = readForm();
      try { rb.result = await post('/report-builder/run', spec); paint(); }
      catch (e) { err(e.detail || 'The report could not run.'); }
    };
    $$('[data-rbx]', body).forEach(b => b.onclick = async () => {
      const fmt = b.dataset.rbx, spec = readForm();
      b.textContent = '…';
      try {
        const res = await rawFetch(`/report-builder/export?format=${encodeURIComponent(fmt)}`,
                                   { method: 'POST', body: JSON.stringify(spec) });
        if (!res.ok) {
          const detail = await res.json().then(j => j.detail, () => 'HTTP ' + res.status);
          throw new ApiError(res.status, typeof detail === 'string' ? detail : JSON.stringify(detail));
        }
        const url = URL.createObjectURL(await res.blob());
        const link = document.createElement('a');
        link.href = url; link.download = `veyrs-report-${spec.entity}.${fmt}`;
        link.click(); URL.revokeObjectURL(url);
        ok('Export downloaded.');
      } catch (e) { err(e.detail || e.message); }
      b.textContent = 'Export ' + fmt.toUpperCase();
    });
    $('#rb-save', body).onclick = async () => {
      const spec = readForm();
      const existing = rb.current && rb.current.is_mine ? rb.current : null;
      const form = await modal({
        title: existing ? 'Save changes to this report' : 'Save this report',
        body: `<p class="muted small">A saved report stores the question, not the answer. Whoever runs it
            sees what <em>their own</em> role and team scope allow at that moment.</p>
          <label>Name<input name="name" maxlength="120" value="${esc(existing ? existing.name : '')}" placeholder="Open criticals per team"></label>
          <label>Note (optional)<input name="description" maxlength="400" value="${esc(existing ? (existing.description || '') : '')}"></label>
          <label><input type="checkbox" name="is_shared" ${existing && existing.is_shared ? 'checked' : ''} ${cat.can_share ? '' : 'disabled'}>
            Share with everyone in this organization</label>
          <p class="small muted">${cat.can_share ? 'Shared means <em>visible</em>. Only you can change or delete it.'
            : 'Sharing needs the <span class="mono">report:write</span> permission; you can still save it for yourself.'}</p>`,
        actions: [{ label: existing ? 'Save changes' : 'Save report' }],
      });
      if (!form || !String(form.name || '').trim()) return;
      const payload = { name: form.name.trim(), description: form.description || null, spec,
                        is_shared: !!form.is_shared };
      try {
        rb.current = existing ? await patch('/report-builder/queries/' + existing.id, payload)
                              : await post('/report-builder/queries', payload);
        await loadSaved(); ok('Report saved.'); paint();
      } catch (e) { err(e.detail || 'Could not save the report.'); }
    };
    const delBtn = $('#rb-delete', body);
    if (delBtn) delBtn.onclick = async () => {
      const q = rb.current;
      const yes = await modal({ title: 'Delete this saved report?',
        body: `<p>“${esc(q.name)}” will be removed${q.is_shared ? ' for everyone it was shared with' : ''}. No data is touched.</p>`,
        actions: [{ label: 'Delete', cls: 'btn-danger' }] });
      if (!yes) return;
      try { await del('/report-builder/queries/' + q.id); rb.current = null; await loadSaved(); ok('Saved report deleted.'); paint(); }
      catch (e) { err(e.detail || 'Could not delete the report.'); }
    };
  }

  await loadSaved();
  paint();
}

/* ── Integrations ───────────────────────────────────────────────────── */
route('integrations', async (view, _p, params) => {
  const tab = params.get('tab') || 'import';
  // Optional: only the import tab's format list and the page blurb use it, and
  // the ITSM connectors / Documentation tabs must open without importer:read.
  const meta = await get('/integrations/importers').catch(() => ({}));
  const INT_HELP = {
    import: explainer('integrations.import', {
      title: 'What a scanner import actually does',
      what: 'Parses a report you already have — a Nessus/Qualys/Greenbone export — '
          + 'and turns each row into a finding against the asset it names. '
          + 'Optionally it also records what each host <em>has installed</em>, which '
          + 'is what the correlation engine joins CVEs against.',
      who: 'Whoever runs the scanner. This is ingestion, not scanning: VEYRS '
         + 'touches nothing on your network here.',
      effect: 'Findings appear, are scored, assigned and given a deadline like any '
            + 'other. <strong>Dry run is on by default</strong> — nothing is written '
            + 'until you untick it.',
      warn: 'A record whose asset cannot be identified is <em>rejected with a reason</em>: '
          + 'VEYRS will not invent an asset to make an import look clean. And '
          + 'inventory is only ever added, never pruned — a scan of three hosts is '
          + 'not a statement about the estate.',
    }),
    scanners: explainer('integrations.scanners', {
      title: 'Connectors pull the same file you would have downloaded',
      what: 'A saved connection to a Nessus or Tenable console. On each sync it '
          + 'exports the scans you have allowed, downloads them, and runs them '
          + 'through the <em>same parser</em> a hand upload uses.',
      who: 'Whoever owns the scanner. Needs the same <span class="mono">importer:*</span> '
         + 'permission as an upload — a pulled file is not more privileged than a '
         + 'pushed one.',
      effect: 'One import run per scan. A byte-identical export is skipped, so a '
            + 'connector polling an unchanged scan does nothing rather than '
            + 'duplicating findings.',
      warn: 'Connectors are created <strong>disabled</strong>, and an empty scan '
          + 'allow-list means <strong>inert</strong>, not “everything”. The blast '
          + 'radius of a sync is the set of scans it pulls, so it has to be named.',
    }),
    runs: explainer('integrations.runs', {
      title: 'Reading an import run',
      what: 'One row per import, with what it saw and what it did. Findings and '
          + 'inventory are counted separately on purpose: an import that created '
          + 'no findings and 900 inventory rows did useful work.',
      who: 'Anyone reconciling “the scanner found 40 things and VEYRS shows 31”.',
      effect: 'Read-only.',
      warn: '<span class="mono">Rejected</span> is about records whose <em>asset</em> '
          + 'could not be identified, not about findings VEYRS disagreed with. '
          + 'A non-zero number there means part of the report was not ingested.',
    }),
    connectors: explainer('integrations.connectors', {
      title: 'ITSM connectors push OUT, they do not pull in',
      what: 'Where a VEYRS ticket is mirrored — Jira, ServiceNow, a webhook. The '
          + 'ticket still lives here; this is the copy your organization works from.',
      who: 'Whoever owns the ITSM platform. It needs credentials for that system.',
      effect: 'New tickets from the moment it is enabled. Existing tickets are not '
            + 'back-filled into the external system.',
      warn: 'This is the opposite direction from “Scanner connectors” on the tab '
          + 'before it, despite the similar name. One brings vulnerability data '
          + 'in; this one sends work out.',
    }),
  };

  view.innerHTML = `
    <div class="page-head"><div><h1>Data sources</h1>
      <p>${esc(meta.notes || '')}</p></div></div>
    <div class="tabs">${[['import', 'Scanner import'], ['scanners', 'Scanner connectors'], ['runs', 'Import runs'], ['connectors', 'ITSM connectors'], ['docs', 'Documentation']]
      .map(([k, l]) => `<button data-t="${k}" class="${tab === k ? 'active' : ''}">${l}</button>`).join('')}</div>
    ${INT_HELP[tab] || ''}
    <div id="int-body"><div class="loading">Loading…</div></div>`;
  view.querySelector('.tabs').onclick = e => { if (e.target.dataset.t) location.hash = '#/integrations?tab=' + e.target.dataset.t; };
  const body = $('#int-body');

  /* ── Documentation (Confluence) ──────────────────────────────────────
     Publishing is ONE-WAY. Nothing is ever read back from the wiki, because a
     page anybody can edit is not a source of truth for a security procedure --
     if it were, "who changed the remediation steps for CVE-2023-44487?" would
     have no answer, which is the question a runbook exists to make answerable. */
  if (tab === 'docs') {
    const st = await get('/knowledge-publishing').catch(e => ({ error: e }));
    if (st.error) { body.innerHTML = `<div class="card"><p class="muted">Could not read the documentation connectors.</p></div>`; return; }
    const rows = st.connectors || [];
    body.innerHTML = `
      <div class="card">
        <div class="row row-split">
          <div><h2 class="mt-0">Publish runbooks to Confluence</h2>
            <p class="small muted measure">Articles in the Knowledge Base are published
              into a Confluence space and re-published in place when they change. <strong>VEYRS stays the
              system of record</strong> — nothing is read back, and every published page carries a footer
              saying so, so the first person to edit it there knows they are editing a mirror.</p></div>
          <span class="pill ${st.ready ? 'st-ok' : 'st-neutral'} nowrap">${st.ready ? 'ready' : 'not configured'}</span>
        </div>
        ${can('ticket:admin') ? `<div class="row mt-3"><button class="btn btn-primary" id="doc-new">Add a Confluence space</button></div>`
          : `<p class="small muted mt-3">Adding one needs <em>ticket:admin</em>.</p>`}
      </div>
      <div class="card mt-4">
        ${table([
          { label: 'Name', cell: r => `<div>${esc(r.name)}</div><div class="small muted mono">${esc(r.slug)}</div>` },
          { label: 'Site', cell: r => `<span class="small mono">${esc(r.base_url || '—')}</span>` },
          { label: 'Space', cell: r => r.space_key ? `<span class="mono">${esc(r.space_key)}</span>`
              : '<span class="pill st-warn">none set</span>' },
          /* `usable` and `is_enabled` are printed apart on purpose. A row that
             exists is not a row that can publish -- the phase 42 lesson, where
             a source with no token reported ready and pressing the button
             surfaced the remote's bare 403. */
          { label: 'State', cell: r => (r.is_enabled ? '<span class="pill st-ok">Enabled</span>' : '<span class="pill st-warn">Disabled</span>')
              + (r.credentials_set ? '' : ' <span class="pill st-warn">no credential</span>')
              + (r.usable ? '' : ' <span class="pill st-neutral">cannot publish</span>') },
          { label: '', cell: r => can('ticket:admin')
              ? `<button class="btn btn-sm" data-doctest="${esc(r.id)}">Test</button>`
              : '' },
        ], rows, { emptyTitle: 'No Confluence space is configured',
                   emptyHint: 'Add one to publish runbooks out of the Knowledge Base.' })}
        <div id="doc-test"></div>
      </div>
      <details class="why mt-4"><summary>What Markdown survives the trip</summary>
        <p class="small muted">${esc(st.supported_markdown || '')}. Anything else — tables, blockquotes,
          images, nested lists — arrives as plain paragraphs: the text survives, the formatting does not.
          Said here rather than left to be discovered, because a runbook that arrives subtly reformatted
          is worse than one that arrives plainly.</p>
        <p class="small muted"><strong>Cloud vs Data Center:</strong> Cloud is your
          <span class="mono">https://site.atlassian.net</span> URL (the <span class="mono">/wiki</span>
          segment is added for you) with your account e-mail plus an API token. Data Center is the wiki
          base URL with a personal access token.</p></details>`;

    const add = $('#doc-new', body);
    if (add) add.onclick = async () => {
      const r = await modal({
        title: 'Add a Confluence space',
        body: `<div class="grid2">
            <div class="field"><label>Name *</label><input name="name" required placeholder="Security wiki"></div>
            <div class="field"><label>Slug *</label><input name="slug" required placeholder="confluence-sec"></div>
          </div>
          <div class="field"><label>Base URL *</label><input name="base_url" required placeholder="https://acme.atlassian.net"></div>
          <div class="grid2">
            <div class="field"><label>Space key *</label><input name="space_key" required placeholder="SEC"></div>
            <div class="field"><label>Parent page id</label><input name="parent_page_id" placeholder="optional"></div>
          </div>
          <div class="grid2">
            <div class="field"><label>Account e-mail <span class="small muted">(Cloud)</span></label><input name="email" placeholder="you@acme.com"></div>
            <div class="field"><label>API token / PAT *</label><input name="token" type="password" required></div>
          </div>
          <p class="small muted">Leave the e-mail empty for Data Center: the token is then sent as a Bearer.</p>`,
        actions: [{ label: 'Add' }],
      });
      if (!r) return;
      const credentials = r.email ? { email: r.email, token: r.token } : { token: r.token };
      try {
        await post('/integrations/connectors', {
          slug: r.slug, name: r.name, system: 'confluence', base_url: r.base_url,
          field_mapping: Object.assign({ space_key: r.space_key },
            r.parent_page_id ? { parent_page_id: r.parent_page_id } : {}),
          credentials,
        });
        ok('Confluence space added. Press Test before relying on it.');
        render();
      } catch (e) { err(e.detail); }
    };

    body.onclick = async (e) => {
      const b = e.target.closest('[data-doctest]');
      if (!b) return;
      const out = $('#doc-test', body);
      out.innerHTML = '<p class="small muted mt-3">Testing…</p>';
      try {
        const res = await post(`/integrations/connectors/${b.dataset.doctest}/test`, {});
        out.innerHTML = `<p class="small mt-3">${res.ok ? 'Connection OK.' : 'Not usable yet.'}</p>`
          + table([
            { label: 'Step', cell: s => esc(s.step) },
            { label: '', cell: s => s.status === 'ok' ? '<span class="pill st-succeeded">OK</span>'
                : s.status === 'skipped' ? '<span class="pill st-neutral">Skipped</span>'
                : '<span class="pill st-failed">Failed</span>' },
            { label: 'Detail', cell: s => `<span class="small muted">${esc(s.detail || '')}</span>` },
          ], res.steps || []);
      } catch (ex) { out.innerHTML = `<p class="form-error mt-3">${esc(ex.detail || 'Test failed.')}</p>`; }
    };
    return;
  }

  if (tab === 'import') {
    body.innerHTML = `<div class="card" style="max-width:640px"><h2>Import a scanner export</h2>
      <form id="imp">
        <label>Format</label>
        <select name="source"><option value="">Detect from the file</option>${(meta.formats || []).map(f => `<option value="${f}">${f.toUpperCase()}</option>`).join('')}</select>
        <label class="mt-3">File</label>
        <input type="file" name="file" required>
        <div class="stack mt-4">
          <label class="inline"><input type="checkbox" name="dry_run" checked> Dry run — parse and report without persisting</label>
          <label class="inline"><input type="checkbox" name="create_assets"> Create assets the scanner reports but VEYRS does not know</label>
          <label class="inline"><input type="checkbox" name="close_absent"> Close findings this test previously reported and no longer does</label>
          <label class="inline"><input type="checkbox" name="import_inventory"> Also record what each host has installed (software inventory)</label>
          <label class="inline"><input type="checkbox" name="inventory_from_plugin_output"> &nbsp;&nbsp;…including software read from plugin text output <span class="muted small">(inferred, not a CPE)</span></label>
        </div>
        <label class="mt-3">Minimum severity</label>
        <select name="min_severity"><option value="">All</option>${['informational', 'low', 'medium', 'high', 'critical'].map(s => `<option value="${s}">${titleCase(s)}</option>`).join('')}</select>
        <button class="btn btn-primary btn-block" type="submit">Import</button>
      </form>
      <p class="small muted mt-3">A Nessus report answers two questions and VEYRS reads only the first unless you ask: what is <em>wrong</em> with each host, and what each host <em>has</em>. The second is what the correlation engine joins CVEs against. Inventory is only ever added, never pruned — a scan of three hosts is not a statement about the estate.</p>
      <p class="small muted mt-3">A record whose asset cannot be identified is rejected with a reason — VEYRS will not invent an asset to make an import look clean. Closure is scoped to the test that ran: an import can never close a finding on a host it did not look at.</p>
      <div id="imp-out"></div></div>`;
    $('#imp').onsubmit = async e => {
      e.preventDefault();
      const f = e.target;
      const fd = new FormData();
      fd.append('file', f.file.files[0]);
      // The field is `source`, not `format`. It was posted as `format` for as
      // long as this page existed, so the server never saw it and silently fell
      // back to detection — the selector looked like it worked because
      // detection usually agreed with it.
      if (f.source.value) fd.append('source', f.source.value);
      fd.append('dry_run', f.dry_run.checked);
      fd.append('create_assets', f.create_assets.checked);
      fd.append('close_absent', f.close_absent.checked);
      fd.append('import_inventory', f.import_inventory.checked);
      fd.append('inventory_from_plugin_output', f.inventory_from_plugin_output.checked);
      if (f.min_severity.value) fd.append('min_severity', f.min_severity.value);
      $('#imp-out').innerHTML = '<div class="loading">Parsing…</div>';
      try {
        const r = await post('/integrations/imports', fd);
        $('#imp-out').innerHTML = `<div class="card mt-4"><h3>Result${r.status === 'preview' ? ' (dry run — nothing written)' : ''}</h3>
          <pre class="mono small pre-wrap">${esc(JSON.stringify(r, null, 2))}</pre></div>`;
        ok('Import finished.');
      } catch (ex) { $('#imp-out').innerHTML = `<p class="muted">${esc(ex.detail)}</p>`; }
    };

  } else if (tab === 'runs') {
    const rows = pageOf(await get('/integrations/imports?limit=50')).items;
    // Column keys match ImportRunOut. They did not: `format`, `parsed`,
    // `imported`, `rejected` and `dry_run` are fields the API has never
    // returned, so five of the seven columns rendered blank on every row and
    // the page read as "the import did nothing".
    body.innerHTML = table([
      { label: 'When', cell: r => fmtDate(r.started_at) },
      { label: 'Source', cell: r => esc(r.source || '') },
      { label: 'File', cell: r => `<span class="mono small">${esc(r.filename || '')}</span>` },
      { label: 'Status', cell: r => statePill(r.status) },
      { label: 'Seen', num: true, cell: r => fmtNum(r.records_seen) },
      { label: 'Created', num: true, cell: r => fmtNum(r.findings_created) },
      { label: 'Updated', num: true, cell: r => fmtNum(r.findings_updated) },
      { label: 'Rejected', num: true, cell: r => fmtNum(r.records_rejected) },
      { label: 'Closed absent', num: true, cell: r => fmtNum(r.findings_closed_absent) },
      // Inventory is reported separately from findings on purpose: an import
      // that created no findings and 900 inventory rows did useful work, and
      // one number for both would hide that in either direction.
      { label: 'Inv. hosts', num: true, cell: r => fmtNum(r.inventory_hosts) },
      { label: 'Inv. added', num: true, cell: r => fmtNum(r.inventory_added) },
      { label: 'Inv. unmatched', num: true, cell: r => r.inventory_unmatched
          ? `<span class="pill st-warn">${fmtNum(r.inventory_unmatched)}</span>`
          : fmtNum(0) },
    ], rows, { emptyTitle: 'No imports yet', emptyHint: 'Upload an export, or pull one with a scanner connector.' });

  } else if (tab === 'scanners') {
    await renderScannerConnectors(body);

  } else {
    const rows = pageOf(await get('/integrations/connectors')).items;
    // `kind`/`enabled` were read from fields the API does not return; it
    // serialises `system` and `is_enabled`. Every row therefore claimed to be
    // enabled, whatever it actually was.
    body.innerHTML = `<div class="row mb-2"><button class="btn btn-sm btn-primary" id="add">Add connector</button></div>` + table([
      { label: 'Name', cell: r => esc(r.name) },
      { label: 'Slug', cell: r => `<span class="mono small">${esc(r.slug)}</span>` },
      { label: 'System', cell: r => esc(titleCase(r.system || '')) },
      { label: 'Base URL', cell: r => `<span class="mono small">${esc(r.base_url || '')}</span>` },
      { label: 'Enabled', cell: r => r.is_enabled ? 'Yes' : 'No' },
      { label: 'Inbound', cell: r => r.inbound_enabled ? 'Yes' : 'No' },
      { label: 'Last error', cell: r => r.last_error ? `<span class="pill st-failed">${esc(r.last_error.slice(0, 60))}</span>` : '' },
      { label: 'Credentials', cell: r => r.credentials_set ? '<span class="pill st-ok">Set</span>' : '<span class="pill st-warn">Missing</span>' },
      { label: '', cell: r => `<button class="btn btn-sm" data-test="${esc(r.id)}">Test</button> <button class="btn btn-sm" data-edit="${esc(r.id)}">Edit</button> <button class="btn btn-sm" data-pull="${esc(r.id)}">Refresh status</button> <button class="btn btn-sm btn-danger" data-del="${esc(r.id)}">Delete</button>` },
    ], rows, { emptyTitle: 'No ITSM connectors', emptyHint: 'Add ServiceNow, Jira Service Management, or a generic webhook.' });
    // The credential a connector needs depends on WHICH system it is, and the
    // previous form ignored that: it posted {username, password} for every
    // system, so a Jira connector reached `JiraAdapter._headers` with neither
    // `email` nor `token` and authenticated as `Basic ""`. Every Jira
    // connector ever built from this console returned 401, and the operator
    // had no way to tell that from a wrong password.
    const connectorForm = (r = {}) => {
      const fm = r.field_mapping || {};
      const sys = ['jira', 'servicenow', 'webhook'];
      return `<div class="grid2">
          <div class="field"><span class="lbl">Slug${r.id ? '' : '<span class="req">*</span>'}</span>
            <input name="slug" ${r.id ? `value="${esc(r.slug)}" disabled` : 'required placeholder="jira-sec"'}></div>
          <div class="field"><span class="lbl">Name<span class="req">*</span></span>
            <input name="name" required value="${esc(r.name || '')}" placeholder="Jira — security backlog"></div>
        </div>
        <div class="grid2">
          <div class="field"><span class="lbl">System</span>
            <select name="system" ${r.id ? 'disabled' : ''}>${sys.map(k => `<option value="${k}" ${r.system === k ? 'selected' : ''}>${titleCase(k)}</option>`).join('')}</select>
            ${r.id ? '<span class="hint">Not editable. The stored credential was entered for this system; switching it would send it somewhere else.</span>' : ''}</div>
          <div class="field"><span class="lbl">Jira deployment</span>
            <select name="api_version">
              <option value="3" ${String(fm.api_version) === '2' ? '' : 'selected'}>Cloud — REST v3</option>
              <option value="2" ${String(fm.api_version) === '2' ? 'selected' : ''}>Data Center / Server — REST v2</option>
            </select>
            <span class="hint">Cloud wants Atlassian Document Format; Data Center wants plain text. Ignored for other systems.</span></div>
        </div>
        <div class="field"><span class="lbl">Base URL<span class="req">*</span></span>
          <input name="base_url" required value="${esc(r.base_url || '')}" placeholder="https://yourteam.atlassian.net">
          <span class="hint">The site root, not a REST path. VEYRS appends <code>/rest/api/&lt;version&gt;</code> itself.</span></div>
        <div class="grid2">
          <div class="field"><span class="lbl">Account email <span class="muted">(Jira Cloud)</span></span>
            <input name="email" placeholder="you@example.com"></div>
          <div class="field"><span class="lbl">API token / PAT</span>
            <input name="token" type="password" autocomplete="new-password"></div>
        </div>
        <div class="grid2">
          <div class="field"><span class="lbl">Username <span class="muted">(ServiceNow, Jira DC basic)</span></span>
            <input name="username"></div>
          <div class="field"><span class="lbl">Password</span>
            <input name="password" type="password" autocomplete="new-password"></div>
        </div>
        <div class="grid2">
          <div class="field"><span class="lbl">Project key <span class="muted">(Jira)</span></span>
            <input name="project_key" value="${esc(fm.project_key || '')}" placeholder="SEC"></div>
          <div class="field"><span class="lbl">Issue type <span class="muted">(Jira)</span></span>
            <input name="issue_type" value="${esc(fm.issue_type || '')}" placeholder="Task"></div>
        </div>
        ${r.id ? `<p class="small muted">${r.credentials_set ? 'A credential is stored. Leave every credential field blank to keep it — this form cannot read it back.' : 'No credential is stored yet.'}</p>` : ''}
        <details class="why"><summary>Which credential does my Jira want?</summary>
          <p><strong>Jira Cloud</strong> (<code>*.atlassian.net</code>) takes your <strong>account email</strong> plus an <strong>API token</strong> minted at id.atlassian.com. Atlassian removed password authentication from the Cloud REST API in 2019 — your login password returns 401 no matter how correct it is.</p>
          <p><strong>Jira Data Center / Server</strong> takes a <strong>personal access token</strong> in the token field on its own (sent as <code>Bearer</code>), or a real username and password.</p>
          <p><strong>ServiceNow</strong> takes the integration user's username and password.</p>
          <p>The project key and issue type are checked by <strong>Test</strong>. A valid token pointed at a project that does not exist fails on the first real ticket, not on the button.</p>
        </details>
        <p class="small muted">Credentials are stored with envelope encryption and are never returned by the API.</p>`;
    };

    // Jira reads `email`/`token`; ServiceNow reads `username`/`password`.
    const credsOf = r => {
      const c = {};
      ['email', 'token', 'username', 'password'].forEach(k => { if (r[k]) c[k] = r[k]; });
      return c;
    };
    const mappingOf = r => {
      const fm = {};
      if (r.system === 'jira') {
        if (r.project_key) fm.project_key = r.project_key;
        if (r.issue_type) fm.issue_type = r.issue_type;
        fm.api_version = Number(r.api_version || 3);
      }
      return fm;
    };

    const add = $('#add');
    if (add) add.onclick = async () => {
      const r = await modal({ title: 'Add ITSM connector', wide: true,
                              body: connectorForm(), actions: [{ label: 'Add' }] });
      if (!r) return;
      try {
        await post('/integrations/connectors', {
          slug: r.slug, name: r.name, system: r.system, base_url: r.base_url,
          credentials: credsOf(r), field_mapping: mappingOf(r),
        });
        ok('Connector added. Press Test before enabling it.'); render();
      } catch (e) { err(e.detail); }
    };

    $$('[data-edit]', view).forEach(b => b.onclick = async () => {
      const row = rows.find(x => String(x.id) === b.dataset.edit);
      if (!row) return;
      const r = await modal({ title: `Edit ${row.name}`, wide: true,
                              body: connectorForm(row), actions: [{ label: 'Save' }] });
      if (!r) return;
      const credentials = credsOf(r);
      const body = { name: r.name, base_url: r.base_url,
                     field_mapping: { ...(row.field_mapping || {}), ...mappingOf({ ...r, system: row.system }) } };
      // Omitted, not empty: an empty object would encrypt `{}` over the stored
      // token and the connector would start failing for a reason the operator
      // never chose. `null`/absent means "keep what is there".
      if (Object.keys(credentials).length) body.credentials = credentials;
      try { await patch('/integrations/connectors/' + row.id, body); ok('Saved.'); render(); }
      catch (e) { err(e.detail); }
    });

    $$('[data-test]', view).forEach(b => b.onclick = async () => {
      b.disabled = true;
      try {
        const res = await post('/integrations/connectors/' + b.dataset.test + '/test', {});
        const pill = s => s === 'ok' ? 'st-ok' : s === 'skipped' ? 'st-warn' : 'st-failed';
        await modal({
          title: res.ok ? 'Connection verified' : 'Connection failed',
          body: `<div class="table-wrap"><table><tbody>${(res.steps || []).map(s =>
            `<tr><td><b>${esc(titleCase(s.step))}</b></td><td><span class="pill ${pill(s.status)}">${esc(s.status)}</span></td><td class="small">${esc(s.detail || '')}</td></tr>`).join('')}</tbody></table></div>
            <p class="small muted">Steps run in order and stop at the first failure — the last line is the one to fix.</p>`,
          actions: [],
        });
        render();
      } catch (e) { err(e.detail); } finally { b.disabled = false; }
    });

    $$('[data-pull]', view).forEach(b => b.onclick = async () => {
      b.disabled = true;
      try {
        const res = await post('/integrations/connectors/' + b.dataset.pull + '/pull', {});
        if (!res.links_total) ok('Nothing to refresh: no ticket has been pushed through this connector yet.');
        else if (res.changed.length) ok(`${res.refreshed} refreshed, ${res.changed.length} changed: ` + res.changed.map(c => `${c.remote_key} ${c.from || '—'} → ${c.to || '—'}`).join(', '));
        else ok(`${res.refreshed} refreshed, none changed.${res.failed ? ` ${res.failed} failed.` : ''}${res.not_attempted ? ` ${res.not_attempted} not reached this pass — press again.` : ''}`);
        render();
      } catch (e) { err(e.detail); } finally { b.disabled = false; }
    });

    $$('[data-del]', view).forEach(b => b.onclick = async () => {
      try { await del('/integrations/connectors/' + b.dataset.del); ok('Deleted.'); render(); } catch (e) { err(e.detail); }
    });
  }
});

/* ── Scanner connectors (pull) ──────────────────────────────────────────
   The import tab above receives a file someone downloaded. This one makes
   VEYRS go and fetch it. Both end in the same parser on the server, which is
   why there is no second "format" choice here: the driver declares it. */
async function renderScannerConnectors(body) {
  const [meta, rows] = await Promise.all([
    get('/integrations/scanner-drivers'),
    get('/integrations/scanners'),
  ]);
  const drivers = meta.drivers || [];
  const byDriver = Object.fromEntries(drivers.map(d => [d.driver, d]));

  body.innerHTML = `
    <div class="row mb-2"><button class="btn btn-sm btn-primary" id="sc-add">Add scanner connector</button></div>
    ${table([
      { label: 'Name', cell: r => esc(r.name) },
      { label: 'Driver', cell: r => esc((byDriver[r.driver] || {}).label || r.driver) },
      { label: 'Base URL', cell: r => `<span class="mono small">${esc(r.base_url || (byDriver[r.driver] || {}).default_base_url || '')}</span>` },
      { label: 'State', cell: r => (!r.is_enabled
          ? `<span class="pill st-neutral">Disabled</span>`
          : r.is_inert
            ? `<span class="pill st-running">Inert — no allowed scans</span>`
            : `<span class="pill st-succeeded">Enabled</span>`) },
      { label: 'Allowed scans', num: true, cell: r => fmtNum((r.allowed_scans || []).length) },
      { label: 'Inventory', cell: r => r.import_inventory
          ? `<span class="pill st-succeeded">Harvested</span>${r.inventory_from_plugin_output ? ' <span class="pill st-neutral">+ plugin text</span>' : ''}`
          : '<span class="pill st-neutral">Findings only</span>' },
      { label: 'Last sync', cell: r => r.last_sync_at ? fmtDate(r.last_sync_at) : '—' },
      { label: 'Last error', cell: r => r.last_error ? `<span class="pill st-failed">${esc(r.last_error.slice(0, 60))}</span>` : '' },
      { label: '', cell: r => `
          <button class="btn btn-sm" data-sc-test="${esc(r.id)}">Test</button>
          <button class="btn btn-sm" data-sc-scans="${esc(r.id)}">Scans</button>
          <button class="btn btn-sm btn-primary" data-sc-sync="${esc(r.id)}">Sync</button>
          <button class="btn btn-sm btn-danger" data-sc-del="${esc(r.id)}">Delete</button>` },
    ], rows, {
      emptyTitle: 'No scanner connectors',
      emptyHint: 'Add a Nessus, Tenable Vulnerability Management or Tenable Security Center console and VEYRS will pull its exports instead of waiting for an upload.',
    })}
    <p class="small muted mt-2">${esc(meta.notes || '')}</p>`;

  const addBtn = $('#sc-add', body);
  if (addBtn) addBtn.onclick = async () => {
    const r = await modal({
      title: 'Add scanner connector',
      body: `<div><label>Slug *</label><input name="slug" required placeholder="nessus-lab"></div>
        <div><label>Name *</label><input name="name" required placeholder="Nessus (lab)"></div>
        <div><label>Driver</label><select name="driver">${drivers.map(d => `<option value="${esc(d.driver)}">${esc(d.label)}</option>`).join('')}</select></div>
        <div><label>Base URL</label><input name="base_url" placeholder="https://nessus.example:8834 — leave blank for the cloud default"></div>
        <div><label>Access key <span class="muted small">(Nessus / Tenable VM)</span></label><input name="access_key" autocomplete="off"></div>
        <div><label>Secret key <span class="muted small">(Nessus / Tenable VM)</span></label><input name="secret_key" type="password" autocomplete="new-password"></div>
        <div><label>Username <span class="muted small">(Security Center)</span></label><input name="username" autocomplete="off"></div>
        <div><label>Password <span class="muted small">(Security Center)</span></label><input name="password" type="password" autocomplete="new-password"></div>
        <label class="inline mt-2"><input type="checkbox" name="verify_tls" checked> Verify the TLS certificate</label>
        <label class="inline"><input type="checkbox" name="import_inventory" checked> Harvest the host inventory from every export it pulls</label>
        <label class="inline"><input type="checkbox" name="inventory_from_plugin_output"> &nbsp;&nbsp;…including software read from plugin text output <span class="muted small">(inferred, not a CPE)</span></label>
        <p class="small muted">Inventory defaults <strong>on</strong> here and off for a hand upload: a connector exists to keep VEYRS fed from a scanner you own, and the software list is already sitting in the bytes it downloads. Plugin text output stays off — a CPE is the scanner naming a dictionary entry, a line of output is a guess, and a wrong guess creates a product that matches no CVE.</p>
        <p class="small muted">The connector is created <strong>disabled and inert</strong>: enable it, then choose which scans it may pull. Only the credentials your driver declares are sent — a Security Center password is never stored as an API key.</p>`,
      actions: [{ label: 'Add' }],
    });
    if (!r) return;
    const fields = (byDriver[r.driver] || {}).credential_fields || [];
    const credentials = {};
    fields.forEach(f => { if (r[f]) credentials[f] = r[f]; });
    try {
      await post('/integrations/scanners', {
        slug: r.slug, name: r.name, driver: r.driver,
        base_url: r.base_url || '', verify_tls: r.verify_tls, credentials,
        import_inventory: r.import_inventory !== false,
        inventory_from_plugin_output: r.inventory_from_plugin_output === true,
      });
      ok('Connector added — disabled and inert until you enable it.');
      render();
    } catch (e) { err(e.detail); }
  };

  $$('[data-sc-test]', body).forEach(b => b.onclick = async () => {
    b.disabled = true;
    try {
      const r = await post('/integrations/scanners/' + b.dataset.scTest + '/test', {});
      ok(`Credentials work — ${r.scans_visible} scan(s) visible.${r.inert ? ' Connector is still inert: choose its scans.' : ''}`);
      render();
    } catch (e) { err(e.detail); } finally { b.disabled = false; }
  });

  $$('[data-sc-scans]', body).forEach(b => b.onclick = async () => {
    const id = b.dataset.scScans;
    let remote;
    b.disabled = true;
    try { remote = await get('/integrations/scanners/' + id + '/scans'); }
    catch (e) { b.disabled = false; return err(e.detail); }
    b.disabled = false;
    const scans = remote.scans || [];
    if (!scans.length) return err('The remote console lists no scans for these credentials.');
    const r = await modal({
      title: 'Scans this connector may pull',
      wide: true,
      body: `<p class="small muted">An unchecked scan is not merely hidden — the connector refuses to pull it. A connector with nothing checked is inert.</p>
        <div class="stack">${scans.map(s => `<label class="inline"><input type="checkbox" name="s_${esc(s.id)}"${s.allowed ? ' checked' : ''}> <strong>${esc(s.name)}</strong> <span class="muted small mono">#${esc(s.id)}${s.status ? ' · ' + esc(s.status) : ''}${s.finished_at ? ' · ' + esc(s.finished_at) : ''}</span></label>`).join('')}</div>`,
      actions: [{ label: 'Save' }],
    });
    if (!r) return;
    const allowed = scans.filter(s => r['s_' + s.id]).map(s => s.id);
    try {
      await patch('/integrations/scanners/' + id, { allowed_scans: allowed });
      ok(allowed.length ? `${allowed.length} scan(s) allowed.` : 'Connector is now inert.');
      render();
    } catch (e) { err(e.detail); }
  });

  $$('[data-sc-sync]', body).forEach(b => b.onclick = async () => {
    const id = b.dataset.scSync;
    const r = await modal({
      title: 'Sync now',
      body: `<p class="small muted">Each allowed scan is pulled and ingested as its own import run, through the same parser an uploaded file uses.</p>
        <label class="inline"><input type="checkbox" name="dry_run" checked> Dry run — parse and report without persisting</label>
        <label class="inline"><input type="checkbox" name="force"> Re-import an export identical to the last one</label>`,
      actions: [{ label: 'Sync' }],
    });
    if (!r) return;
    b.disabled = true;
    try {
      const out = await post('/integrations/scanners/' + id + '/sync', { dry_run: r.dry_run, force: r.force });
      const results = out.results || [];
      const done = results.filter(x => x.status === 'imported').length;
      const failed = results.filter(x => x.status === 'failed');
      await modal({
        title: out.dry_run ? 'Sync preview — nothing written' : 'Sync finished',
        wide: true,
        body: `<pre class="mono small pre-wrap m-0">${esc(JSON.stringify(results, null, 2))}</pre>`,
        actions: [{ label: 'Close' }],
      });
      if (failed.length) err(`${failed.length} scan(s) failed.`); else ok(`${done} scan(s) imported.`);
      render();
    } catch (e) { err(e.detail); } finally { b.disabled = false; }
  });

  $$('[data-sc-del]', body).forEach(b => b.onclick = async () => {
    try { await del('/integrations/scanners/' + b.dataset.scDel); ok('Deleted.'); render(); }
    catch (e) { err(e.detail); }
  });
}

/* ── Documents ──────────────────────────────────────────────────────── */
/* ── Documents & Advisories ─────────────────────────────────────────────
   Renamed in the nav from plain "Documents", which sat next to "Knowledge
   Base" and read as "files somebody uploaded". This is where a vendor
   advisory, a pentest report or a customer security questionnaire goes, and
   the name has to say so or nobody puts one here.

   Everything on the form beyond the file is metadata a PERSON owns: the
   extractor fills `cve_ids` from the text, and no amount of parsing tells you
   which team should read this or which vendor published it. */
const DOC_CLASSES = ['advisory', 'pentest_report', 'scan_report', 'policy',
                     'questionnaire', 'contract', 'other'];

route('documents', listView({
  title: 'Documents & Advisories',
  blurb: 'Drop a vendor advisory in and VEYRS extracts CVEs, products, versions and remediation, then correlates them against your inventory. Give it a title, an owning team and a vendor so somebody can find it again. XML parsing is hardened against XXE.',
  endpoint: '/documents',
  actions: `<button class="btn btn-primary" data-act="uploadDoc">Upload document</button>`,
  emptyHint: 'Accepted: PDF, DOCX, TXT, HTML, CSV, JSON, XML.',
  filters: [
    { name: 'q', label: 'Title or filename' },
    { name: 'doc_class', label: 'Kind', options: DOC_CLASSES },
    { name: 'status', label: 'Status', options: ['pending', 'processed', 'failed', 'unsupported_format'] },
    { name: 'team_id', label: 'Team', options: () => teamOptions() },
    { name: 'cve_id', label: 'Mentions CVE' },
  ],
  cols: [
    { label: 'Title', cell: r => `<strong>${esc(r.title || r.filename)}</strong>${
        r.title && r.title !== r.filename ? `<div class="small muted mono">${esc(r.filename)}</div>` : ''}` },
    { label: 'Kind', cell: r => esc(titleCase(r.doc_class || '—')) },
    { label: 'Vendor', cell: r => esc(r.vendor_name || '—') },
    { label: 'Team', cell: r => r.team_name ? esc(r.team_name) : '<span class="muted small">unassigned</span>' },
    { label: 'Status', cell: r => statePill(r.status) },
    // Extracted and hand-attached are counted separately: they answer different
    // questions ("what does this text say" vs "what did somebody decide it
    // relates to") and one merged number hides both.
    { label: 'CVEs', cell: r => {
        const auto = (r.cve_ids || []).length, manual = (r.manual_cve_ids || []).length;
        if (!auto && !manual) return '<span class="muted small">none</span>';
        return `${fmtNum(auto)} found${manual ? ` <span class="pill st-neutral">+${fmtNum(manual)} linked</span>` : ''}`;
      } },
    { label: 'Uploaded', cell: r => fmtDate(r.created_at) },
  ],
  detail: async (view, parts) => {
    const d = await get('/documents/' + parts[0]);
    const editable = can('document:write');
    const cveChips = (ids, cls) => (ids || []).map(c =>
      `<a href="#/intel/cve/${esc(c)}" class="pill ${cls} mono">${esc(c)}</a>`).join(' ');
    view.innerHTML = `<div class="page-head"><div><h1>${esc(d.title || d.filename)}</h1>
      <p>${statePill(d.status)} <span class="muted small mono">${esc(d.filename)} · ${esc(d.content_type || '')}</span></p></div>
      <div class="page-actions">
        ${editable ? '<button class="btn btn-primary" id="edit">Edit details</button>' : ''}
        ${can('document:delete') ? '<button class="btn btn-danger" id="del">Delete</button>' : ''}</div></div>
      <div class="grid cols-2">
        <div class="card"><h2>Filing</h2>
          <dl class="kv">
            <dt>Kind</dt><dd>${esc(titleCase(d.doc_class || '—'))}</dd>
            <dt>Vendor</dt><dd>${esc(d.vendor_name || '—')}</dd>
            <dt>Owning team</dt><dd>${d.team_name ? esc(d.team_name) : '<span class="muted">unassigned</span>'}</dd>
            <dt>Classification</dt><dd>${esc(titleCase(d.data_classification || '—'))}</dd>
            <dt>Uploaded</dt><dd>${fmtDate(d.created_at)}</dd>
          </dl>
          <h3 class="mt-4">Notes</h3>
          <p>${d.notes ? esc(d.notes) : '<span class="muted">None. Why was this uploaded, and what was decided?</span>'}</p>
        </div>
        <div class="card"><h2>Vulnerabilities</h2>
          <h3>Found in the text</h3>
          <p>${cveChips(d.cve_ids, 'st-neutral') || '<span class="muted">The extractor found none.</span>'}</p>
          <h3 class="mt-3">Linked by a person</h3>
          <p>${cveChips(d.manual_cve_ids, 'pill-net') || '<span class="muted">None.</span>'}</p>
          ${(d.unknown_cves || []).length ? `<p class="small muted mt-3">
            Referenced but not in the VEYRS catalogue: <span class="mono">${esc((d.unknown_cves || []).join(', '))}</span>.
            A document may reference a vulnerability; it cannot create one.</p>` : ''}
        </div>
      </div>
      ${d.text_preview ? `<div class="card mt-4"><h2>Extracted text</h2>
        <pre class="mono small" style="white-space:pre-wrap;margin:0;max-height:340px;overflow:auto">${esc(d.text_preview)}</pre></div>` : ''}
      <div class="card mt-4"><h2>Extracted entities</h2>
        <pre class="mono small pre-wrap m-0">${esc(JSON.stringify(d.extracted || {}, null, 2))}</pre></div>`;

    const delBtn = $('#del');
    if (delBtn) delBtn.onclick = async () => {
      const c = await modal({ title: 'Delete document',
        body: `<p>Delete <strong>${esc(d.title || d.filename)}</strong>? Its extracted text and chunks go with it.</p>`,
        actions: [{ label: 'Delete', cls: 'btn-danger' }] });
      if (!c) return;
      try { await del('/documents/' + parts[0]); ok('Deleted.'); location.hash = '#/documents'; }
      catch (e) { err(e.detail); }
    };

    const editBtn = $('#edit');
    if (editBtn) editBtn.onclick = async () => {
      const teams_ = await teamOptions();
      const r = await modal({
        title: 'Edit document details',
        wide: true,
        body: `<div><label>Title</label><input name="title" value="${esc(d.title || '')}" placeholder="${esc(d.filename)}"></div>
          <p class="field-help">The filename is kept as evidence — it is what the content hash was taken over — so a title never overwrites it.</p>
          <div><label>Kind</label><select name="doc_class"><option value="">—</option>
            ${DOC_CLASSES.map(k => `<option value="${k}"${d.doc_class === k ? ' selected' : ''}>${titleCase(k)}</option>`).join('')}</select></div>
          <div><label>Owning team</label><select name="team_id"><option value="">Unassigned</option>
            ${teams_.map(t => `<option value="${esc(t.value)}"${String(d.team_id) === String(t.value) ? ' selected' : ''}>${esc(t.label)}</option>`).join('')}</select></div>
          <div><label>Vendor</label><input name="vendor" value="${esc(d.vendor_name || '')}" placeholder="Type a name, e.g. Fortinet"></div>
          <p class="field-help">Matched against the same vendor dictionary the CPE catalogue uses, so
            “every Fortinet advisory” and “every Fortinet product you run” answer from one identifier.
            Leave empty to clear it.</p>
          <div><label>Linked CVEs</label><input name="manual_cve_ids" class="mono"
            value="${esc((d.manual_cve_ids || []).join(', '))}" placeholder="CVE-2024-21762, CVE-2024-3400"></div>
          <p class="field-help">Comma-separated. These are yours: re-extraction never touches them.
            An identifier that is not in the CVE catalogue is rejected rather than stored.</p>
          <div><label>Notes</label><textarea name="notes" rows="4">${esc(d.notes || '')}</textarea></div>`,
        actions: [{ label: 'Save', keepOpen: true, run: async (form) => {
          const body = { title: form.title.trim() || null, notes: form.notes.trim() || null,
                         doc_class: form.doc_class || null,
                         manual_cve_ids: form.manual_cve_ids.split(',').map(v => v.trim().toUpperCase()).filter(Boolean) };
          const clear = [];
          if (form.team_id) body.team_id = form.team_id; else clear.push('team_id');
          // The vendor is typed by name, so it has to be resolved to an id
          // before it can be stored. An unmatched name is REFUSED here rather
          // than silently dropped: a form that accepts "Fortnet" and saves
          // nothing looks exactly like one that saved it.
          if (form.vendor.trim()) {
            const hit = pageOf(await get('/intel/vendors' + qs({ q: form.vendor.trim(), size: 10 }))).items
              .find(v => (v.name || '').toLowerCase() === form.vendor.trim().toLowerCase());
            if (!hit) { err(`No vendor called “${form.vendor.trim()}” in the dictionary.`); return false; }
            body.vendor_id = hit.id;
          } else clear.push('vendor_id');
          if (clear.length) body.clear = clear;
          try { await patch('/documents/' + parts[0], body); ok('Saved.'); render(); return true; }
          catch (e) { err(e.detail); return false; }
        } }],
      });
      return r;
    };
  },
}));

window.uploadDoc = async function () {
  const teams_ = await teamOptions();
  const r = await modal({
    title: 'Upload document',
    body: `<div><label>File *</label><input type="file" name="__file" id="doc-file" required></div>
           <div><label>Title</label><input name="title" placeholder="Defaults to the filename"></div>
           <div><label>Owning team</label><select name="team_id"><option value="">Unassigned</option>
             ${teams_.map(t => `<option value="${esc(t.value)}">${esc(t.label)}</option>`).join('')}</select></div>
           <div><label>Notes</label><textarea name="notes" rows="3" placeholder="Why this was uploaded, and what was decided."></textarea></div>
           <p class="small muted">The document is parsed server-side. Untrusted content is wrapped before it ever reaches a model, and XML entity declarations are rejected outright.</p>`,
    actions: [{ label: 'Upload' }],
  });
  if (!r) return;
  const input = document.getElementById('doc-file');
  const file = input && input.files[0];
  if (!file) return err('No file selected.');
  const fd = new FormData();
  fd.append('file', file);
  // The metadata rides in the QUERY STRING, not in the multipart body. The
  // route declares these as `Query(...)` parameters, so a `fd.append('title')`
  // is read by nobody and thrown away in silence — which is exactly what the
  // previous version of this function did, and why every document here is
  // called by its filename.
  try {
    await post('/documents' + qs({
      title: r.title || undefined,
      notes: r.notes || undefined,
      team_id: r.team_id || undefined,
    }), fd);
    ok('Uploaded — extraction ran.');
    render();
  } catch (e) { err(e.detail); }
};

/* ── Knowledge base ─────────────────────────────────────────────────── */
route('knowledge', listView({
  title: 'Knowledge Base',
  blurb: 'Versioned runbooks, remediation guides and internal procedures. Every edit keeps the previous revision.',
  endpoint: '/knowledge',
  actions: `<button class="btn btn-primary" data-act="newArticle">New article</button>`,
  filters: [{ name: 'q', label: 'Search' }],
  cols: [
    { label: 'Title', cell: r => esc(r.title) },
    { label: 'Tags', cell: r => (r.tags || []).map(t => `<span class="pill st-neutral">${esc(t)}</span>`).join(' ') },
    { label: 'Version', num: true, cell: r => fmtNum(r.version) },
    { label: 'Updated', cell: r => fmtDate(r.updated_at) },
  ],
  detail: async (view, parts) => {
    const a = await get('/knowledge/' + parts[0]);
    const [pubState, pubs] = await Promise.all([
      get('/knowledge-publishing').catch(() => ({ ready: false, connectors: [] })),
      get(`/knowledge/${parts[0]}/publications`).catch(() => []),
    ]);
    const live = (pubs || []).filter(p => p.is_active);
    view.innerHTML = `<div class="page-head"><div><h1>${esc(a.title)}</h1>
      <p class="muted small">Version ${fmtNum(a.version)} · updated ${fmtDate(a.updated_at)}</p></div>
      <div class="page-actions"><button class="btn" id="edit">Edit</button>
      ${pubState.ready && can('knowledge:write') ? `<button class="btn btn-primary" id="publish">${live.length ? 'Re-publish' : 'Publish to Confluence'}</button>` : ''}</div></div>
      ${live.length ? `<div class="card mb-3">
        <h2 class="mt-0">Published</h2>
        ${table([
          { label: 'Page', cell: p => p.url
              ? `<a href="${esc(p.url)}" target="_blank" rel="noopener noreferrer">${esc(p.title || p.page_id)}</a>`
              : `<span class="mono">${esc(p.page_id)}</span>` },
          { label: 'Space', cell: p => `<span class="mono">${esc(p.space_key || '—')}</span>` },
          /* The wiki's own version, not ours. They diverge the moment somebody
             edits the page in Confluence, and seeing that they have diverged is
             the point of printing it. */
          { label: 'Wiki version', cell: p => `<span class="small muted">${esc(p.remote_version || '—')}</span>` },
          { label: 'Last published', cell: p => `<span class="small">${fmtDate(p.published_at) || '—'}</span>`
              + (p.last_error ? `<div class="small form-error">${esc(p.last_error)}</div>` : '') },
        ], live)}
        <p class="small muted mt-2">One way. VEYRS is the system of record — edits made
          on the wiki page are not read back, and re-publishing overwrites them.</p></div>` : ''}
      <div class="card"><pre style="white-space:pre-wrap;margin:0;font-family:inherit">${esc(a.body || a.content || '')}</pre></div>`;
    const pub = $('#publish');
    if (pub) pub.onclick = async () => {
      pub.disabled = true;
      try {
        const p = await post(`/knowledge/${parts[0]}/publish`, {});
        ok(`Published to ${p.space_key || 'the wiki'} (${p.remote_version || 'page updated'}).`);
        render();
      } catch (e) { err(e.detail); pub.disabled = false; }
    };
    $('#edit').onclick = async () => {
      const r = await modal({ title: 'Edit article', wide: true, body: `<div><label>Title</label><input name="title" value="${esc(a.title)}"></div><div><label>Body</label><textarea name="body" style="min-height:280px">${esc(a.body || a.content || '')}</textarea></div>`, actions: [{ label: 'Save' }] });
      if (!r) return;
      try { await patch('/knowledge/' + parts[0], { title: r.title, body: r.body }); ok('Saved as a new revision.'); render(); } catch (e) { err(e.detail); }
    };
  },
}));

window.newArticle = async function () {
  const r = await modal({ title: 'New article', wide: true, body: `<div><label>Title *</label><input name="title" required></div><div><label>Body</label><textarea name="body" style="min-height:240px"></textarea></div><div><label>Tags (comma separated)</label><input name="tags"></div>`, actions: [{ label: 'Create' }] });
  if (!r) return;
  try { const a = await post('/knowledge', { title: r.title, body: r.body, tags: (r.tags || '').split(',').map(s => s.trim()).filter(Boolean) }); ok('Article created.'); location.hash = '#/knowledge/' + a.id; }
  catch (e) { err(e.detail); }
};

/* ── AI assistant ───────────────────────────────────────────────────── */
route('ai', async (view, _p, params) => {
  const tab = params.get('tab') || 'ask';
  const caps = await get('/ai/capabilities').catch(() => ({}));
  view.innerHTML = `
    <div class="page-head"><div><h1>AI Assistant</h1>
      <p>The model never sees more than your role allows, and it never executes a query it wrote. Natural language is compiled through a closed grammar and validated before it touches the database.</p></div></div>
    <div class="tabs">${[['ask', 'Ask'], ['search', 'Natural-language search'], ['policy', 'Policy'], ['providers', 'Providers'], ['audit', 'AI audit']]
      .map(([k, l]) => `<button data-t="${k}" class="${tab === k ? 'active' : ''}">${l}</button>`).join('')}</div>
    <div id="ai-body"><div class="loading">Loading…</div></div>`;
  view.querySelector('.tabs').onclick = e => { if (e.target.dataset.t) location.hash = '#/ai?tab=' + e.target.dataset.t; };
  const body = $('#ai-body');

  if (tab === 'ask') {
    body.innerHTML = `<div class="card">
      <div class="ai-log" id="log"><p class="muted small">Capabilities: ${(caps.capabilities || []).map(c => `<span class="pill pill-ai">${esc(c)}</span>`).join(' ') || 'none advertised'}</p></div>
      <form id="ask" class="row" style="margin-top:14px;flex-wrap:nowrap">
        <input name="q" placeholder="Which internet-facing assets carry a KEV vulnerability?" class="grow">
        <button class="btn btn-ai" type="submit">Ask</button></form>
      <p class="small muted mt-2">Prompt-injection guards, secret and PII detection, and the data-classification ceiling all apply before anything leaves this host.</p></div>`;
    $('#ask').onsubmit = async e => {
      e.preventDefault();
      const q = e.target.q.value.trim(); if (!q) return;
      e.target.q.value = '';
      const log = $('#log');
      log.insertAdjacentHTML('beforeend', `<div class="ai-msg you">${esc(q)}</div>`);
      const slot = document.createElement('div');
      slot.className = 'ai-msg veyrs'; slot.textContent = 'Thinking…';
      log.appendChild(slot); log.scrollTop = log.scrollHeight;
      try {
        const r = await post('/ai/ask', { question: q });
        slot.innerHTML = `<pre>${esc(r.answer || r.text || JSON.stringify(r, null, 2))}</pre>` +
          (r.provider ? `<p class="small muted" style="margin:8px 0 0">via ${esc(r.provider)}${r.model ? ' · ' + esc(r.model) : ''}</p>` : '');
      } catch (ex) { slot.innerHTML = `<span class="muted">${esc(ex.detail)}</span>`; }
      log.scrollTop = log.scrollHeight;
    };
  } else if (tab === 'search') {
    const g = await get('/ai/search/grammar').catch(() => ({}));
    body.innerHTML = `<div class="card">
      <form id="nls" class="row" style="flex-wrap:nowrap">
        <input name="q" placeholder="critical findings on internet-facing FortiWeb with EPSS above 0.5 and KEV" class="grow">
        <button class="btn btn-ai" type="submit">Search</button></form>
      <div id="nls-out" class="mt-4"></div>
      <details class="mt-4"><summary class="small muted">Closed grammar the model must produce</summary>
        <pre class="mono small pre-wrap">${esc(JSON.stringify(g, null, 2))}</pre></details></div>`;
    $('#nls').onsubmit = async e => {
      e.preventDefault();
      const out = $('#nls-out'); out.innerHTML = '<div class="loading">Compiling query…</div>';
      try {
        const r = await post('/ai/search', { question: e.target.q.value });
        const items = r.results || r.items || [];
        if (r.understood === false) {
          out.innerHTML = `<p class="muted">${esc(r.error || 'Could not interpret the question.')}</p>` +
            (r.hint ? `<p class="small muted">${esc(r.hint)}</p>` : '');
          return;
        }
        out.innerHTML = `<p class="small muted">Compiled query: <span class="mono">${esc(JSON.stringify(r.query || r.structured || {}))}</span></p>` +
          table([
            { label: 'Type', cell: x => esc(x.type || x.entity || '—') },
            { label: 'Label', cell: x => esc(x.label || x.title || x.hostname || x.cve_id || '') },
            { label: 'Severity', cell: x => x.severity ? sevPill(x.severity) : '' },
            { label: 'Risk', num: true, cell: x => fmtScore(x.risk_score) },
          ], items, { emptyTitle: 'No matches', emptyHint: 'The query compiled but nothing in your tenant satisfies it.' });
      } catch (ex) { out.innerHTML = `<p class="muted">${esc(ex.detail)}</p>`; }
    };
  } else if (tab === 'policy') {
    const p = await get('/ai/policy');
    body.innerHTML = `<div class="card" style="max-width:640px"><h2>AI policy</h2>
      <form id="pol">
        <label class="inline"><input type="checkbox" name="allow_external" ${p.allow_external ? 'checked' : ''}> Allow external providers</label>
        <label class="inline mt-2"><input type="checkbox" name="allow_local" ${p.allow_local !== false ? 'checked' : ''}> Allow local providers</label>
        <label class="mt-4">Maximum data classification sent to an <strong>external</strong> provider</label>
        <select name="max_external_classification">${['public', 'internal', 'confidential', 'restricted'].map(c => `<option value="${c}" ${p.max_external_classification === c ? 'selected' : ''}>${titleCase(c)}</option>`).join('')}</select>
        <label class="mt-4">Maximum prompt size (characters)</label>
        <input name="max_prompt_chars" type="number" value="${esc(p.max_prompt_chars ?? 20000)}">
        <button class="btn btn-primary btn-block" type="submit">Save policy</button>
      </form>
      <p class="small muted mt-3">A tenant with no policy row inherits the strictest defaults — the guard fails closed, not open.</p></div>`;
    $('#pol').onsubmit = async e => {
      e.preventDefault();
      const f = e.target;
      try {
        await put('/ai/policy', {
          allow_external: f.allow_external.checked, allow_local: f.allow_local.checked,
          max_external_classification: f.max_external_classification.value,
          max_prompt_chars: Number(f.max_prompt_chars.value),
        });
        ok('Policy saved.');
      } catch (ex) { err(ex.detail); }
    };
  } else if (tab === 'providers') {
    const rows = pageOf(await get('/ai/providers')).items;
    const AUTH_LABEL = { api_key: 'API key', session: 'Sign-in (user)', oauth2: 'OAuth 2.0 client' };
    body.innerHTML = `<div class="row mb-2"><button class="btn btn-sm btn-primary" id="add">Add provider</button></div>` + table([
      { label: 'Name', cell: r => esc(r.name) },
      { label: 'Kind', cell: r => esc(titleCase(r.kind || r.provider)) },
      { label: 'Model', cell: r => `<span class="mono small">${esc(r.model || '')}</span>` },
      { label: 'Placement', cell: r => r.is_external ? '<span class="pill pill-net">External</span>' : '<span class="pill st-ok">Local</span>' },
      { label: 'Authentication', cell: r => esc(AUTH_LABEL[r.auth_mode || 'api_key'] || r.auth_mode) },
      { label: 'Enabled', cell: r => r.is_enabled === false ? 'No' : 'Yes' },
      { label: '', cell: r => (r.auth_mode && r.auth_mode !== 'api_key' ? `<button class="btn btn-sm" data-test="${esc(r.id)}">Test sign-in</button> ` : '') + `<button class="btn btn-sm btn-danger" data-del="${esc(r.id)}">Delete</button>` },
    ], rows, { emptyTitle: 'No AI providers configured', emptyHint: 'VEYRS falls back to a deterministic backend that answers without a model — degraded, but never wrong by hallucination.' });
    const add = $('#add');
    if (add) add.onclick = async () => {
      const pending = modal({
        title: 'Add AI provider',
        wide: true,
        body: `<div><label>Name *</label><input name="name" required placeholder="Local Ollama"></div>
          <div><label>Kind</label><select name="kind" id="aip-kind">${[['ollama', 'Ollama'], ['openai_compatible', 'OpenAI-compatible gateway'], ['openai', 'OpenAI'], ['anthropic', 'Anthropic'], ['gemini', 'Gemini']].map(([k, l]) => `<option value="${k}">${esc(l)}</option>`).join('')}</select></div>
          <div><label>Base URL</label><input name="base_url" placeholder="https://ai-gateway.example.com"></div>
          <div><label>Model *</label><input name="model" required placeholder="llama3.1:8b"></div>
          <div><label class="row"><input type="checkbox" name="is_external"> External endpoint (data leaves your network; the policy's external ceiling applies)</label></div>
          <div><label>Authentication</label><select name="auth_mode" id="aip-auth">
            <option value="api_key">API key</option>
            <option value="session">Sign in with a user (token renewed automatically)</option>
            <option value="oauth2">OAuth 2.0 client credentials (token renewed automatically)</option></select>
            <p class="small muted">Sign-in modes are available for OpenAI and OpenAI-compatible gateways.</p></div>
          <div data-auth="api_key"><label>API key</label><input name="api_key" type="password" autocomplete="off"></div>
          <div data-auth="session oauth2" hidden><label>Token URL *</label><input name="token_url" placeholder="https://ai-gateway.example.com/auth/token"></div>
          <div data-auth="session" hidden><label>User name *</label><input name="username" autocomplete="off"></div>
          <div data-auth="session" hidden><label>Password *</label><input name="auth_secret_session" type="password" autocomplete="new-password"></div>
          <div data-auth="session" hidden class="row">
            <div><label>User field</label><input name="username_field" placeholder="username"></div>
            <div><label>Password field</label><input name="password_field" placeholder="password"></div>
            <div><label>Body</label><select name="body_format"><option value="json">JSON</option><option value="form">Form</option></select></div></div>
          <div data-auth="oauth2" hidden><label>Client ID *</label><input name="client_id" autocomplete="off"></div>
          <div data-auth="oauth2" hidden><label>Client secret *</label><input name="auth_secret_oauth2" type="password" autocomplete="new-password"></div>
          <div data-auth="oauth2" hidden><label>Scope</label><input name="scope"></div>
          <div data-auth="session oauth2" hidden><label>Token field</label><input name="token_field" placeholder="Auto (access_token, token, id_token)"></div>
          <div data-auth="session oauth2" hidden><label>Session lifetime (minutes)</label><input name="lifetime_minutes" type="number" min="1" max="1440" placeholder="Auto">
            <p class="small muted">Leave empty if you do not know it: VEYRS reads it from the sign-in answer (<span class="mono">expires_in</span>, <span class="mono">expires_at</span>) or from the token itself, and renews before it expires. A value you type is a maximum; if the server says less, the server wins.</p></div>`,
        actions: [{ label: 'Add' }],
      });
      const kindSel = $('#aip-kind'), authSel = $('#aip-auth');
      const sync = () => {
        const tokenKinds = ['openai', 'openai_compatible'].includes(kindSel.value);
        [...authSel.options].forEach(o => { o.disabled = o.value !== 'api_key' && !tokenKinds; });
        if (!tokenKinds) authSel.value = 'api_key';
        $$('[data-auth]').forEach(el => { el.hidden = !el.dataset.auth.split(' ').includes(authSel.value); });
      };
      if (kindSel && authSel) { kindSel.onchange = sync; authSel.onchange = sync; sync(); }
      const r = await pending;
      if (!r) return;
      const mode = r.auth_mode || 'api_key';
      const auth_config = {};
      if (mode !== 'api_key') {
        const keys = mode === 'session'
          ? ['token_url', 'username', 'username_field', 'password_field', 'body_format', 'token_field', 'lifetime_minutes']
          : ['token_url', 'client_id', 'scope', 'token_field', 'lifetime_minutes'];
        keys.forEach(k => {
          if (r[k] !== undefined && String(r[k]).trim() !== '') auth_config[k] = k === 'lifetime_minutes' ? Number(r[k]) : String(r[k]).trim();
        });
      }
      const slug = String(r.name || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60) || 'provider';
      try {
        await post('/ai/providers', {
          slug, name: r.name, kind: r.kind, base_url: r.base_url || null, model: r.model,
          is_external: !!r.is_external, auth_mode: mode, auth_config,
          api_key: mode === 'api_key' ? (r.api_key || null) : null,
          auth_secret: mode === 'session' ? (r.auth_secret_session || null) : mode === 'oauth2' ? (r.auth_secret_oauth2 || null) : null,
        });
        ok('Provider added.'); render();
      } catch (e) { err(e.detail); }
    };
    $$('[data-test]', view).forEach(b => b.onclick = async () => {
      b.disabled = true;
      try {
        const t = await post('/ai/providers/' + b.dataset.test + '/test', {});
        if (t.ok) ok(`Signed in. Session lifetime: ${Math.round(t.lifetime_seconds / 6) / 10} min (from ${t.lifetime_source}); renewed after ${t.renews_after_seconds} s.`);
        else err('Sign-in failed: ' + (t.error || 'unknown error'));
      } catch (e) { err(e.detail); } finally { b.disabled = false; }
    });
    $$('[data-del]', view).forEach(b => b.onclick = async () => {
      try { await del('/ai/providers/' + b.dataset.del); ok('Deleted.'); render(); } catch (e) { err(e.detail); }
    });
  } else {
    const rows = pageOf(await get('/ai/audit?limit=50')).items;
    body.innerHTML = table([
      { label: 'When', cell: r => fmtDate(r.created_at) },
      { label: 'Actor', cell: r => esc(r.actor_label || '—') },
      { label: 'Capability', cell: r => `<span class="pill pill-ai">${esc(r.capability || r.action)}</span>` },
      { label: 'Provider', cell: r => esc(r.provider || '—') },
      { label: 'Verdict', cell: r => statePill(r.verdict || r.status) },
      { label: 'Reason', cell: r => esc((r.reason || '').slice(0, 120)) },
    ], rows, { emptyTitle: 'No AI calls recorded' });
  }
});

/* Narrow (or restore) which teams a user's role grants cover.
 *
 * Deliberately blunt: a checkbox list and a warning, no live preview. The
 * decision is "which slice of the estate does this person answer for", and a
 * preview of today's counts would invite tuning the scope to make a number
 * look better. */
async function scopeUser(userId) {
  const [rows, user] = await Promise.all([teams(), get('/users/' + userId).catch(() => ({}))]);
  if (!rows.length) { err('No teams exist yet — create one before scoping a user.'); return; }
  const r = await modal({
    title: `Visibility for ${user.full_name || user.email || 'user'}`,
    body: `<p class="muted small">Selecting nothing leaves this identity <strong>estate-wide</strong>, which is
        the default and what every existing user is. Selecting teams narrows every one of their role grants:
        they stop seeing assets, findings and tickets owned by anyone else, and assets with no owning team
        become invisible to them entirely.</p>
      <div class="pick-list">${rows.map(t => `<label class="inline">
        <input type="checkbox" name="t_${esc(t.id)}"> ${esc(t.name || t.slug)}</label>`).join('')}</div>`,
    actions: [{ label: 'Apply' }],
  });
  if (!r) return;
  const team_ids = rows.map(t => t.id).filter(id => r['t_' + id]);
  try {
    const res = await put('/users/' + userId + '/scope', { team_ids });
    ok(res.restricted ? `Narrowed to ${team_ids.length} team(s).` : 'Restored estate-wide visibility.');
    render();
  } catch (e) { err(e.detail); }
}

/* ── Audit log ──────────────────────────────────────────────────────── */
route('audit', listView({
  title: 'Audit Log',
  blurb: 'Append-only. Entries cannot be edited or deleted through any API surface — that is the point of an audit log.',
  endpoint: '/audit',
  filters: [{ name: 'action', label: 'Action' }, { name: 'object_type', label: 'Object type' }],
  cols: [
    { label: 'When', cell: r => fmtDate(r.created_at) },
    { label: 'Actor', cell: r => esc(r.actor_label || '—') },
    { label: 'Action', cell: r => `<span class="mono small">${esc(r.action)}</span>` },
    { label: 'Object', cell: r => `${esc(r.object_type || '')} ${r.object_label ? '· ' + esc(r.object_label) : ''}` },
    { label: 'Changes', cell: r => `<span class="mono small">${esc(JSON.stringify(r.changes || {}).slice(0, 110))}</span>` },
    { label: 'IP', cell: r => `<span class="mono small">${esc(r.ip_address || '—')}</span>` },
  ],
}));

/* ── Administration ─────────────────────────────────────────────────── */
/* ── Risk Register ──────────────────────────────────────────────────────

   Risks that are not findings. No asset is required and none is implied: the
   supplier with no exit plan and the process nobody documented belong here, and
   neither of them will ever be reported by a scanner.

   The screen is built around the two questions a register is opened for --
   "how bad" and "who answers for it" -- so the band and the Accountable are
   columns in the list, not facts you have to open a row to discover. A register
   whose list view cannot tell you who owns a risk is a list of worries.       */

const RISK_BAND_CLASS = {
  critical: 'sev-critical', high: 'sev-high', medium: 'sev-medium', low: 'sev-low',
};
const RACI_ORDER = ['A', 'R', 'C', 'I'];

function riskBandPill(band) {
  if (!band) return '<span class="pill st-neutral">Unscored</span>';
  return `<span class="pill ${RISK_BAND_CLASS[band] || 'st-neutral'}">${esc(band)}</span>`;
}

function riskSeatLabel(seat) {
  const who = seat.user_name || seat.team_name || '—';
  /* A person seated under a team is rendered as "Ana Ruiz · Platform" rather
     than as two columns: the team is context for the person, not a second
     party, and splitting them invites reading it as both. */
  return seat.user_name && seat.team_name
    ? `${esc(seat.user_name)} <span class="muted small">· ${esc(seat.team_name)}</span>`
    : esc(who);
}

async function riskPeople() {
  /* `user:read` is not granted to every role that may read the register --
     an auditor, for instance. The picker degrades to a message instead of an
     empty select that looks like "this organization has no people". */
  try { return pageOf(await get('/users?limit=200')).items || []; }
  catch { return null; }
}

/* ── The scale, explained where the scale is used ───────────────────────

   A 1-5 picker with no anchors is not a scale, it is five numbers: one
   person's "4" is another's "2" and the register stops being comparable --
   which is the entire reason the score is computed rather than typed.

   Two rules this screen obeys:

   1. NOTHING here restates a threshold. The bands and the whole 5x5 are
      rendered from `meta.band_of` -- the 1..25 -> band map the API publishes
      for exactly this ("two different band boundaries is two different
      registers", `api/v1/risk_register.meta`). It had shipped with no
      consumer. A copy of `>=15 is critical` in JS is a second authority that
      goes wrong silently the day somebody moves the boundary in Python.
   2. The level anchors ARE console copy and say so. VEYRS stores the number,
      not the word; presenting a house convention as if the platform enforced
      it is how a reader stops questioning a 3 that should have been a 5. */
const RISK_LEVEL_ANCHORS = {
  likelihood: [
    [1, 'Rare', 'No known occurrence here or in comparable estates.'],
    [2, 'Unlikely', 'Credible, but it would be a surprise this year.'],
    [3, 'Possible', 'Has happened to organisations like this one.'],
    [4, 'Likely', 'Expected within the year; near misses already seen here.'],
    [5, 'Almost certain', 'Happening now, or will unless something changes.'],
  ],
  impact: [
    [1, 'Negligible', 'Absorbed by the team. No customer, money or regulator.'],
    [2, 'Minor', 'A day of work or a degraded service. Contained internally.'],
    [3, 'Moderate', 'Customers notice. Reportable inside the organisation.'],
    [4, 'Major', 'Customer data or revenue lost; a contract or regulator engaged.'],
    [5, 'Severe', 'The business cannot operate, or the breach is notifiable.'],
  ],
};

/* Contiguous score ranges per band, read OFF the server's map rather than
   assumed to be four. A fifth band, or a moved boundary, reflows this table
   and the heat map together because both read the same source. */
function riskBandRanges(bandOf) {
  const out = [];
  for (let n = 1; n <= 25; n++) {
    const band = bandOf[String(n)] || bandOf[n];
    if (!band) continue;
    const last = out[out.length - 1];
    if (last && last.band === band && last.hi === n - 1) last.hi = n;
    else out.push({ band, lo: n, hi: n });
  }
  return out;
}

async function riskMatrixModal() {
  let meta;
  try { meta = await get('/risks/meta'); }
  catch (e) { return err(e.detail || 'Could not read the scale from the server.'); }

  const bandOf = meta.band_of || {};
  const bandAt = n => bandOf[String(n)] || bandOf[n] || null;
  const ranges = riskBandRanges(bandOf);

  /* Impact descends down the rows so the worst corner is top-right, which is
     where every printed risk matrix a reader has seen before puts it. */
  const head = [`<div class="rm-cell rm-head rm-corner"><span class="rm-axis">×</span></div>`]
    .concat([1, 2, 3, 4, 5].map(l => `<div class="rm-cell rm-head">${l}</div>`)).join('');
  const rows = [5, 4, 3, 2, 1].map(i => {
    const cells = [1, 2, 3, 4, 5].map(l => {
      const n = l * i, band = bandAt(n);
      return `<div class="rm-cell ${band ? RISK_BAND_CLASS[band] || '' : ''}">
        <span class="rm-n">${n}</span><span class="rm-b">${esc(band || '—')}</span></div>`;
    }).join('');
    return `<div class="rm-cell rm-head">${i}</div>${cells}`;
  }).join('');

  const anchorTable = (kind) => `<div class="table-wrap"><table>
    <thead><tr><th>${kind === 'likelihood' ? 'Likelihood' : 'Impact'}</th><th>Read it as</th></tr></thead>
    <tbody>${RISK_LEVEL_ANCHORS[kind].map(([n, name, hint]) => `<tr>
      <td><span class="mono">${n}</span> <strong>${esc(name)}</strong></td>
      <td class="small muted">${esc(hint)}</td></tr>`).join('')}</tbody></table></div>`;

  await modal({
    title: 'How a risk is scored',
    wide: true,
    dismiss: 'Close',
    body: `
      <p class="small muted">The score is <strong>likelihood × impact</strong> on a 5×5, and VEYRS computes
         it — you never type it. Two risks written by two people six months apart have to land in the same
         place, which only holds if both of them read the levels the same way.</p>

      <div>
        <label>The 5×5, and the band each score falls in</label>
        <div class="rm-wrap">
          <div class="rm-side">Impact</div>
          <div>
            <div class="rm-grid">${head}${rows}</div>
            <div class="rm-foot small muted">Likelihood →</div>
          </div>
        </div>
      </div>

      <div>
        <label>Bands</label>
        <p class="rm-bands">${ranges.map(r =>
          `<span class="pill ${RISK_BAND_CLASS[r.band] || 'st-neutral'}">${esc(r.band)}</span>
           <span class="small muted">${r.lo === r.hi ? r.lo : `${r.lo}–${r.hi}`}</span>`).join('')}</p>
        <p class="small muted">Bands are derived from the score, never stored as text, and these boundaries
           come from the server — this table cannot disagree with how a risk was actually filed.</p>
      </div>

      <div>
        <label>What each level means</label>
        <div class="grid cols-2">${anchorTable('likelihood')}${anchorTable('impact')}</div>
        <p class="small muted">These wordings are a reading convention, not a rule the platform enforces:
           VEYRS stores the number. Agree them once, or the register drifts one assessor at a time.</p>
      </div>

      <div>
        <label>Inherent and residual</label>
        <p class="small muted"><strong>Inherent</strong> is the score before the controls you are counting on.
           <strong>Residual</strong> is what is left once the treatment is actually in place — and it stays
           empty until somebody assesses it. It is deliberately not pre-filled with the inherent score:
           <em>“we have not looked yet”</em> and <em>“the controls changed nothing”</em> are different
           answers and must never render identically.</p>
      </div>`,
  });
}

/* Delegated once, so the same button works from the page header and from
   inside the Add/Edit dialog -- where the 1-5 is actually being chosen, and
   where `modal()` gives no handle to bind against before it resolves. The
   nested backdrop is a SIBLING under `#modal-root`, so the click never
   reaches the form's own handler and the half-typed risk survives. */
document.addEventListener('click', e => {
  if (e.target.closest?.('[data-risk-matrix]')) riskMatrixModal();
});

route('risks', async (view, parts, params) => {
  if (parts.length) return riskDetail(view, parts[0]);

  const q = params.get('q') || '';
  const query = new URLSearchParams();
  ['status', 'band', 'category', 'treatment'].forEach(k => {
    if (params.get(k)) query.set(k, params.get(k));
  });
  ['open_only', 'review_overdue', 'unassigned', 'mine'].forEach(k => {
    if (params.get(k) === 'true') query.set(k, 'true');
  });
  if (q) query.set('q', q);
  query.set('size', '200');

  const [page, sum] = await Promise.all([
    get('/risks?' + query.toString()).then(pageOf),
    get('/risks/summary').catch(() => null),
  ]);

  /* `grid` is not decoration here: `.cols-4` only carries the column template,
     and the rule it belongs to is `.grid.cols-4`. Written alone it resolves to
     nothing, so the four stat cards stacked as plain blocks with no gap at all
     -- touching, which is what "the divs are too close together" looked like. */
  const cards = sum ? `<div class="grid cols-4 mb-3">
    <div class="card stat"><div class="label">Open risks</div><div class="value">${fmtNum(sum.open)}</div>
      <div class="small muted">${fmtNum(sum.total)} in the register</div></div>
    <div class="card stat"><div class="label">Critical &amp; high</div>
      <div class="value">${fmtNum((sum.by_band.critical || 0) + (sum.by_band.high || 0))}</div>
      <div class="small muted">by inherent score</div></div>
    <div class="card stat"><div class="label">Nobody accountable</div><div class="value">${fmtNum(sum.unassigned)}</div>
      <div class="small muted">open, with no A named</div></div>
    <div class="card stat"><div class="label">Review overdue</div><div class="value">${fmtNum(sum.review_overdue)}</div>
      <div class="small muted">past their review date</div></div>
  </div>` : '';

  view.innerHTML = `
    <div class="page-head">
      <div><h1>Risk Register</h1>
        <p>Risks that are not tied to an asset — suppliers, processes, people, contracts — with a
           RACI that says who answers for each one. Linking a risk to an asset or a finding is
           optional and never required.</p></div>
      <div class="page-actions">
        <!-- Deliberately NOT gated on the write permission. The people who only
             read this register -- an auditor, a board member, the team named in
             a RACI seat -- are the ones most likely to be looking at a 12 they
             did not assign and have no other way to interpret it. -->
        <button class="btn btn-ghost" data-risk-matrix>How a risk is scored</button>
        ${can('riskregister:write') ? '<button class="btn btn-primary" id="add">Add a risk</button>' : ''}
      </div>
    </div>
    ${cards}
    <div class="filters">
      <input id="q" placeholder="Search code or title" value="${esc(q)}">
      <span class="chip ${params.get('unassigned') === 'true' ? 'chip-on' : ''}" data-f="unassigned">Nobody accountable</span>
      <span class="chip ${params.get('review_overdue') === 'true' ? 'chip-on' : ''}" data-f="review_overdue">Review overdue</span>
      <span class="chip ${params.get('mine') === 'true' ? 'chip-on' : ''}" data-f="mine">Mine</span>
      <span class="chip ${params.get('open_only') === 'true' ? 'chip-on' : ''}" data-f="open_only">Open only</span>
    </div>
    <div id="risk-list"></div>`;

  $('#risk-list', view).innerHTML = table([
    { label: 'Ref', cell: r => `<span class="mono small">${esc(r.code)}</span>` },
    { label: 'Risk', cell: r => `${esc(r.title)}${r.category ? ` <span class="chip-tag">${esc(r.category)}</span>` : ''}` },
    { label: 'Inherent', cell: r => `${riskBandPill(r.band)}${r.score ? ` <span class="small muted">${r.likelihood}×${r.impact} = ${r.score}</span>` : ''}` },
    { label: 'Residual', cell: r => r.residual_score ? `${riskBandPill(r.residual_band)} <span class="small muted">${r.residual_score}</span>` : '<span class="muted small">—</span>' },
    /* The column that makes this a register rather than a list. An open risk
       with nobody accountable is called out here, not buried in a detail page
       nobody opens. */
    { label: 'Accountable', cell: r => r.accountable
        ? esc(r.accountable)
        : (r.is_open ? '<span class="pill st-warn">Nobody</span>' : '<span class="muted small">—</span>') },
    { label: 'Status', cell: r => `<span class="pill st-${r.is_open ? 'neutral' : 'closed'}">${esc(r.status)}</span>` },
    { label: 'Review', cell: r => r.review_due_at
        ? `<span class="${r.review_overdue ? 'err' : ''}">${esc(r.review_due_at)}</span>`
        : '<span class="muted small">—</span>' },
  ], page.items, {
    onRow: true, idOf: r => r.id,
    emptyTitle: 'No risks recorded',
    emptyHint: 'This register is for what a scanner will never find: a single supplier, an undocumented process, a key person, a contract with no exit.',
  });

  $('#risk-list', view).onclick = e => {
    const tr = e.target.closest('tr[data-id]');
    if (tr && tr.dataset.id) location.hash = '#/risks/' + tr.dataset.id;
  };
  $$('.chip[data-f]', view).forEach(chip => chip.onclick = () => {
    const p = new URLSearchParams(location.hash.split('?')[1] || '');
    const key = chip.dataset.f;
    if (p.get(key) === 'true') p.delete(key); else p.set(key, 'true');
    location.hash = '#/risks' + (p.toString() ? '?' + p.toString() : '');
  });
  const search = $('#q', view);
  search.onkeydown = e => {
    if (e.key !== 'Enter') return;
    const p = new URLSearchParams(location.hash.split('?')[1] || '');
    if (search.value.trim()) p.set('q', search.value.trim()); else p.delete('q');
    location.hash = '#/risks' + (p.toString() ? '?' + p.toString() : '');
  };
  const add = $('#add', view);
  if (add) add.onclick = () => riskForm();
});

async function riskForm(existing) {
  const meta = await get('/risks/meta');
  const r = existing || {};
  const opts = (list, sel) => list.map(v =>
    `<option value="${esc(v)}" ${v === sel ? 'selected' : ''}>${esc(v)}</option>`).join('');
  const scale = sel => [1, 2, 3, 4, 5].map(n =>
    `<option value="${n}" ${String(n) === String(sel) ? 'selected' : ''}>${n}</option>`).join('');

  const form = await modal({
    title: existing ? `Edit ${r.code}` : 'Add a risk',
    wide: true,
    body: `
      <div><label>What could go wrong *</label>
        <input name="title" required maxlength="300" value="${esc(r.title || '')}"
               placeholder="Single supplier for the payment gateway"></div>
      <div><label>Description</label>
        <textarea name="description" rows="3" placeholder="What happens, to whom, and why it matters">${esc(r.description || '')}</textarea></div>
      <div class="grid2">
        <div><label>Category</label><select name="category">
          <option value="">—</option>${opts(meta.categories, r.category)}</select></div>
        <div><label>Where it came from</label><select name="source">
          <option value="">—</option>${opts(meta.sources, r.source)}</select></div>
        <div><label>Status</label><select name="status">${opts(meta.statuses, r.status || 'identified')}</select></div>
        <div><label>Treatment</label><select name="treatment">${opts(meta.treatments, r.treatment || 'pending')}</select></div>
      </div>
      <div class="grid2">
        <div><label>Likelihood (1–5)</label><select name="likelihood"><option value="">—</option>${scale(r.likelihood)}</select></div>
        <div><label>Impact (1–5)</label><select name="impact"><option value="">—</option>${scale(r.impact)}</select></div>
      </div>
      <p class="small muted">The score is likelihood × impact and is computed by VEYRS, not typed in —
         two risks written by two people six months apart have to be comparable.
         <button type="button" class="btn btn-ghost btn-sm" data-risk-matrix>What do 1–5 mean?</button></p>
      <div class="grid2">
        <div><label>Review again on</label><input type="date" name="review_due_at" value="${esc(r.review_due_at || '')}"></div>
        <div><label>Reference elsewhere</label><input name="external_ref" maxlength="300" value="${esc(r.external_ref || '')}" placeholder="GRC-1042 / board pack Q3"></div>
      </div>
      <div><label>Treatment plan</label>
        <textarea name="treatment_plan" rows="2" placeholder="What is being done about it">${esc(r.treatment_plan || '')}</textarea></div>
      <div><label>Closure note</label>
        <input name="closure_note" value="${esc(r.closure_note || '')}" placeholder="Required to set the status to closed"></div>
      <p class="small muted">A risk cannot leave the register without a sentence saying why — that is the
         first question asked about a closed risk, and it is unrecoverable a year later.</p>`,
    actions: [{ label: existing ? 'Save' : 'Add to the register' }],
  });
  if (!form) return;

  const body = {
    title: form.title, description: form.description || null,
    category: form.category || null, source: form.source || null,
    status: form.status, treatment: form.treatment,
    treatment_plan: form.treatment_plan || null,
    likelihood: form.likelihood ? Number(form.likelihood) : null,
    impact: form.impact ? Number(form.impact) : null,
    review_due_at: form.review_due_at || null,
    external_ref: form.external_ref || null,
    closure_note: form.closure_note || null,
  };
  try {
    if (existing) { await patch('/risks/' + existing.id, body); ok('Risk updated.'); }
    else {
      const created = await post('/risks', body);
      ok(`${created.code} added. Name who is accountable next — an entry nobody owns is the one that sits untouched for a year.`);
      location.hash = '#/risks/' + created.id;
      return;
    }
    render();
  } catch (e) { err(e.detail); }
}

async function riskDetail(view, id) {
  const [risk, meta, people] = await Promise.all([
    get('/risks/' + id), get('/risks/meta'), riskPeople(),
  ]);
  const teamRows = await teams();
  const writable = can('riskregister:write');

  view.innerHTML = `
    <div class="page-head">
      <div>
        <p class="small muted"><a href="#/risks">← Risk Register</a></p>
        <h1><span class="mono">${esc(risk.code)}</span> ${esc(risk.title)}</h1>
        <p>${riskBandPill(risk.band)} <span class="pill st-neutral">${esc(risk.status)}</span>
           <span class="pill st-neutral">${esc(risk.treatment)}</span>
           ${risk.review_overdue ? '<span class="pill st-warn">Review overdue</span>' : ''}</p>
      </div>
      <div class="page-actions">
        ${writable ? '<button class="btn" id="edit">Edit</button>' : ''}
        ${can('riskregister:delete') ? '<button class="btn btn-danger" id="drop">Remove</button>' : ''}
      </div>
    </div>

    <!-- `.grid2` is the FORM-field primitive (12px gap, 260px columns, and a
         margin reset for `.field`). Two page-level cards are `.grid.cols-2`
         everywhere else in this console: 14px apart, and they break to one
         column at 320px instead of staying squeezed side by side. -->
    <div class="grid cols-2">
      <div class="card">
        <h2>The risk</h2>
        <p class="pre-wrap">${esc(risk.description || 'No description.')}</p>
        <dl class="kv">
          <dt>Category</dt><dd>${esc(risk.category || '—')}</dd>
          <dt>Where it came from</dt><dd>${esc(risk.source || '—')}</dd>
          <dt>Identified</dt><dd>${esc(risk.identified_at || '—')}</dd>
          <dt>Review again on</dt><dd>${esc(risk.review_due_at || '—')}</dd>
          <dt>Reference elsewhere</dt><dd>${esc(risk.external_ref || '—')}</dd>
          <dt>Treatment plan</dt><dd>${esc(risk.treatment_plan || '—')}</dd>
          ${risk.closure_note ? `<dt>Closed because</dt><dd>${esc(risk.closure_note)}</dd>` : ''}
        </dl>
      </div>
      <div class="card">
        <h2>Score</h2>
        <dl class="kv">
          <dt>Inherent</dt><dd>${risk.score ? `${risk.likelihood} × ${risk.impact} = <strong>${risk.score}</strong> ${riskBandPill(risk.band)}` : '<span class="muted">not assessed</span>'}</dd>
          <dt>Residual</dt><dd>${risk.residual_score ? `${risk.residual_likelihood} × ${risk.residual_impact} = <strong>${risk.residual_score}</strong> ${riskBandPill(risk.residual_band)}` : '<span class="muted">not assessed</span>'}</dd>
        </dl>
        <p class="small muted">Residual is deliberately empty until somebody assesses it. “We have not looked
           yet” and “the controls changed nothing” are different answers and must not look the same.</p>
        ${writable ? `<form id="residual" class="form-grid mt-3">
          <div class="field"><span class="lbl">Residual likelihood</span>
            <select name="residual_likelihood"><option value="">—</option>${[1,2,3,4,5].map(n => `<option value="${n}" ${String(n) === String(risk.residual_likelihood) ? 'selected' : ''}>${n}</option>`).join('')}</select></div>
          <div class="field"><span class="lbl">Residual impact</span>
            <select name="residual_impact"><option value="">—</option>${[1,2,3,4,5].map(n => `<option value="${n}" ${String(n) === String(risk.residual_impact) ? 'selected' : ''}>${n}</option>`).join('')}</select></div>
          <div><button class="btn btn-sm" type="submit">Save residual</button></div>
        </form>` : ''}
      </div>
    </div>

    <div class="card mt-4">
      <h2>RACI</h2>
      <p class="small muted">Accountable is <strong>one named person</strong> — a team cannot be called into a
         room, and a seat everybody holds is a seat nobody holds. Responsible, Consulted and Informed
         take teams or people, in any number.</p>
      <div id="raci-table"></div>
      ${writable ? `<form id="raci-add" class="form-grid mt-4">
        <div class="field"><span class="lbl">Seat</span><select name="raci">
          ${meta.raci.map(r => `<option value="${r.key}">${esc(r.key)} — ${esc(r.label)}</option>`).join('')}</select></div>
        <div class="field"><span class="lbl">Who</span><select name="party">
          <optgroup label="Teams">${teamRows.map(t => `<option value="team:${t.id}">${esc(t.name || t.slug)}</option>`).join('')}</optgroup>
          ${people ? `<optgroup label="People">${people.map(u => `<option value="user:${u.id}">${esc(u.full_name || u.email)}</option>`).join('')}</optgroup>` : ''}
        </select></div>
        <div class="field"><span class="lbl">In team (people only)</span><select name="context">
          <option value="">—</option>${teamRows.map(t => `<option value="${t.id}">${esc(t.name || t.slug)}</option>`).join('')}</select></div>
        <div class="field"><span class="lbl">Why this seat</span>
          <input name="note" maxlength="400" placeholder="signs off the exit plan"></div>
        <div class="form-actions"><button class="btn btn-sm btn-primary" type="submit">Add seat</button></div>
      </form>
      ${people ? '' : '<p class="small muted">Your role cannot read the user list, so only teams can be named from this screen.</p>'}
      <p class="small muted">Naming somebody <em>in</em> a team is checked against the membership: a matrix that
         names a person under a team they left is worse than an empty one, because it looks answered.</p>` : ''}
    </div>

    <div class="card mt-4">
      <h2>Linked to the estate <span class="small muted">(optional)</span></h2>
      <div id="risk-links"></div>
      ${writable ? `<form id="link-add" class="form-grid mt-4">
        <div class="field"><span class="lbl">Type</span><select name="object_type">
          ${meta.link_types.map(t => `<option value="${t}">${esc(t)}</option>`).join('')}</select></div>
        <div class="field" style="grid-column:span 2"><span class="lbl">Identifier</span>
          <input name="object_id" placeholder="UUID of the asset, finding, vulnerability or control"></div>
        <div><button class="btn btn-sm" type="submit">Link</button></div>
      </form>
      <p class="small muted">A risk with no link at all is completely ordinary — that is the reason this
         section exists. A link enriches the record; it never owns it.</p>` : ''}
    </div>

    <div class="card mt-4">
      <h2>History</h2>
      ${table([
        { label: 'When', cell: e => fmtDate(e.created_at) },
        { label: 'What', cell: e => esc(e.event) },
        { label: 'Who', cell: e => esc(e.actor_label || 'system') },
        { label: 'Detail', cell: e => `<span class="small mono">${esc(JSON.stringify(e.details || {}).slice(0, 180))}</span>` },
      ], risk.events || [], { emptyTitle: 'No history yet' })}
    </div>`;

  const seats = [...(risk.raci || [])].sort(
    (a, b) => RACI_ORDER.indexOf(a.raci) - RACI_ORDER.indexOf(b.raci));
  $('#raci-table', view).innerHTML = table([
    { label: 'Seat', cell: s => `<span class="pill st-neutral">${esc(s.raci)}</span> <span class="small">${esc(s.raci_label)}</span>` },
    { label: 'Who', cell: s => riskSeatLabel(s) },
    { label: 'Why', cell: s => `<span class="small muted">${esc(s.note || '—')}</span>` },
    ...(writable ? [{ label: '', cell: s => `<button class="btn btn-sm btn-danger" data-seat="${esc(s.id)}">Remove</button>` }] : []),
  ], seats, {
    emptyTitle: 'Nobody is named yet',
    emptyHint: 'An open risk with no Accountable is the one the next incident review will find.',
  });

  $('#risk-links', view).innerHTML = table([
    { label: 'Type', cell: l => esc(l.object_type) },
    { label: 'What it was called', cell: l => esc(l.label || '—') },
    { label: 'Id', cell: l => `<span class="mono small">${esc(l.object_id)}</span>` },
    ...(writable ? [{ label: '', cell: l => `<button class="btn btn-sm btn-danger" data-link="${esc(l.id)}">Unlink</button>` }] : []),
  ], risk.links || [], { emptyTitle: 'Not linked to anything' });

  /* Every seat change PUTs the WHOLE matrix, because that is what the API
     takes and why: swapping the Accountable through two calls would leave a
     window in which the register says nobody is accountable. */
  const putSeats = async list => {
    try {
      await put(`/risks/${risk.id}/raci`, { raci: list });
      ok('RACI updated.');
      render();
    } catch (e) { err(e.detail); }
  };
  const currentSeats = () => (risk.raci || []).map(s => ({
    raci: s.raci, party_type: s.party_type, team_id: s.team_id, user_id: s.user_id, note: s.note,
  }));

  const raciAdd = $('#raci-add', view);
  if (raciAdd) raciAdd.onsubmit = e => {
    e.preventDefault();
    const [kind, partyId] = e.target.party.value.split(':');
    const seat = { raci: e.target.raci.value, party_type: kind, note: e.target.note.value || null };
    if (kind === 'team') seat.team_id = partyId;
    else { seat.user_id = partyId; seat.team_id = e.target.context.value || null; }
    putSeats([...currentSeats(), seat]);
  };
  $('#raci-table', view).onclick = e => {
    const seatId = e.target.dataset.seat;
    if (!seatId) return;
    const keep = (risk.raci || []).filter(s => s.id !== seatId).map(s => ({
      raci: s.raci, party_type: s.party_type, team_id: s.team_id, user_id: s.user_id, note: s.note,
    }));
    putSeats(keep);
  };

  const linkAdd = $('#link-add', view);
  if (linkAdd) linkAdd.onsubmit = async e => {
    e.preventDefault();
    try {
      await post(`/risks/${risk.id}/links`, {
        object_type: e.target.object_type.value, object_id: e.target.object_id.value.trim(),
      });
      ok('Linked.'); render();
    } catch (ex) { err(ex.detail); }
  };
  $('#risk-links', view).onclick = async e => {
    const linkId = e.target.dataset.link;
    if (!linkId) return;
    try { await del(`/risks/${risk.id}/links/${linkId}`); ok('Unlinked.'); render(); }
    catch (ex) { err(ex.detail); }
  };

  const residual = $('#residual', view);
  if (residual) residual.onsubmit = async e => {
    e.preventDefault();
    try {
      await patch('/risks/' + risk.id, {
        residual_likelihood: e.target.residual_likelihood.value ? Number(e.target.residual_likelihood.value) : null,
        residual_impact: e.target.residual_impact.value ? Number(e.target.residual_impact.value) : null,
      });
      ok('Residual score saved.'); render();
    } catch (ex) { err(ex.detail); }
  };

  const edit = $('#edit', view);
  if (edit) edit.onclick = () => riskForm(risk);
  const drop = $('#drop', view);
  if (drop) drop.onclick = async () => {
    const confirmed = await modal({
      title: `Remove ${risk.code}?`,
      body: `<p class="small">This is for the duplicate and the typo. The ordinary way to retire a risk is
               to <strong>close</strong> it with a note — a risk that was on the register and is not any
               more is itself a fact an auditor asks about.</p>
             <p class="small muted">The entry is soft-deleted: it leaves this screen and stays in the database.</p>`,
      actions: [{ label: 'Remove', cls: 'btn-danger' }],
    });
    if (!confirmed) return;
    try { await del('/risks/' + risk.id); ok('Removed from the register.'); location.hash = '#/risks'; }
    catch (e) { err(e.detail); }
  };
}

/* ── Administration → Secret storage ────────────────────────────────────
   Where stored third-party credentials live (VEYRS_SECRET_BACKEND), in plain
   language, with the command that changes it. READ-ONLY ON PURPOSE: moving
   every tenant's credentials needs the host and the vault policy, so it is
   `veyrs secrets migrate` on the host and never a button in this console. */
async function secretStorageTab(body) {
  let st;
  try { st = await get('/secret-storage'); }
  catch (e) {
    body.innerHTML = `<div class="card"><p class="muted">${e.status === 403
      ? 'Secret storage is readable with <em>settings:admin</em> and an estate-wide grant only.'
      : 'Could not read the secret storage status: ' + esc(e.detail || e.message)}</p></div>`;
    return;
  }
  const v = st.vault || {};
  const yn = x => x === true ? 'Yes' : x === false ? 'No' : '—';
  const label = { local: 'Local (database + key on this host)', mirror: 'Mirror (vault + local copy)', vault: 'External vault only' }[st.mode] || st.mode;
  const pill = st.mode === 'vault' ? 'st-ok' : st.mode === 'mirror' ? 'st-warn' : 'st-neutral';
  const healthy = v.reachable && v.auth_ok && !v.sealed;
  const t = st.totals || {};
  body.innerHTML = `
    <div class="card">
      <div class="row row-split">
        <div>
          <h2 class="mt-0">Stored credentials: ${esc(label)}</h2>
          <p class="small muted" style="max-width:70ch">${esc(st.meaning)}</p>
        </div>
        <span class="pill ${pill} nowrap">${esc(st.mode)}</span>
      </div>
      <dl class="kv mt-3">
        <dt>Still on this host</dt><dd>${st.on_host
          ? `<strong>${fmtNum(st.on_host)}</strong> credential(s) of this organization can be read by anyone who can read this server's disk`
          : 'None for this organization'}</dd>
        <dt>Vault address</dt><dd>${v.addr ? `<span class="mono">${esc(v.addr)}</span>` : 'Not configured'}</dd>
        ${v.addr ? `
        <dt>Mount / auth</dt><dd><span class="mono">${esc(v.mount || '—')}</span> · ${esc(v.auth_method || '—')}${v.namespace ? ' · namespace ' + esc(v.namespace) : ''}</dd>
        <dt>Reachable</dt><dd>${yn(v.reachable)}</dd>
        <dt>Sealed</dt><dd>${yn(v.sealed)}</dd>
        <dt>VEYRS can log in</dt><dd>${yn(v.auth_ok)}</dd>
        ${v.error ? `<dt>Problem</dt><dd><span class="pill st-failed">${esc(v.error)}</span></dd>` : ''}
        ${(v.problems || []).length ? `<dt>Missing settings</dt><dd>${(v.problems || []).map(esc).join('<br>')}</dd>` : ''}` : ''}
        <dt>Next step</dt><dd>${esc(st.next_step)}</dd>
      </dl>
      ${st.mode !== 'local' && !healthy ? `<p class="small mt-3"><span class="pill st-failed">Vault not usable</span>
        Features that need a stored credential will fail until it is back${st.mode === 'mirror' ? ' — except mirrored ones, which fall back to their local copy' : ''}.</p>` : ''}
    </div>

    <div class="card mt-4">
      <h2>This organization's credentials, by where they are stored</h2>
      ${table([
        { label: 'Stored in', cell: r => `<span class="mono small">${esc(r.column)}</span>` },
        { label: 'Local', cell: r => fmtNum(r.local) },
        { label: 'Mirror', cell: r => fmtNum(r.mirror) },
        { label: 'Vault', cell: r => fmtNum(r.vault) },
        { label: 'Empty', cell: r => fmtNum(r.empty) },
        { label: 'Unrecognised', cell: r => r.unknown ? `<span class="pill st-failed">${fmtNum(r.unknown)}</span>` : '0' },
      ], st.columns || [])}
      <p class="small muted">Totals: ${fmtNum(t.local)} local · ${fmtNum(t.mirror)} mirror · ${fmtNum(t.vault)} vault · ${fmtNum(t.empty)} empty.</p>
    </div>

    <div class="card mt-4">
      <h2>What each mode means</h2>
      ${table([
        { label: 'Mode', cell: r => `<span class="mono">${esc(r[0])}</span>` },
        { label: 'Where the credential is', cell: r => esc(r[1]) },
        { label: 'Readable from this host’s disk?', cell: r => r[2] ? '<span class="pill st-failed">Yes</span>' : '<span class="pill st-ok">No</span>' },
      ], [
        ['local', 'Database, encrypted with VEYRS_ENCRYPTION_KEY — which is stored on the same host.', true],
        ['mirror', 'External vault, plus the local encrypted copy as a fallback. A migration step.', true],
        ['vault', 'External vault only; the database keeps a reference.', false],
      ])}
    </div>

    <div class="card mt-4">
      <h2>Changing it</h2>
      <p class="small muted measure">There is deliberately no button here. Migrating moves the credentials of
        every organization on this platform and needs the server and the vault policy, so it is done by the platform
        operator on the host. Every command is a dry run until <span class="mono">--apply</span> is added, and a credential
        that cannot be read is reported and left as it was.</p>
      <dl class="kv">
        <dt>See the whole platform</dt><dd><span class="mono">${esc(st.commands.status)}</span></dd>
        <dt>Step 1 · mirror</dt><dd>set <span class="mono">VEYRS_SECRET_BACKEND=mirror</span>, restart, then <span class="mono">${esc(st.commands.to_mirror)}</span></dd>
        <dt>Step 2 · vault only</dt><dd>set <span class="mono">VEYRS_SECRET_BACKEND=vault</span>, restart, then <span class="mono">${esc(st.commands.to_vault)}</span></dd>
        <dt>Roll back</dt><dd>set <span class="mono">VEYRS_SECRET_BACKEND=local</span> (keep the vault settings), restart, then <span class="mono">${esc(st.commands.to_local)}</span></dd>
        <dt>Remove orphans</dt><dd><span class="mono">${esc(st.commands.gc)}</span></dd>
      </dl>
    </div>`;
}

/* ── Administration → Software update ─────────────────────────────────
   What is installed, what the latest release is, whether it is SIGNED, and --
   on a native install only -- a button that QUEUES the update. The API never
   updates itself: it drops a request that the root veyrs-updater.service acts
   on (signature check, backup hook, installer, health check), and the steps of
   each run come back as the history below. Platform administrators only: the
   version belongs to the installation, not to one organization. */
/* Who is a platform administrator (security/platform.py): an Organization
   Administrator or Platform Administrator of the organization VEYRS was
   installed for, or an account granted on the host. Appended to every
   installation-wide page that answers 403, so nobody is left guessing. */
const PLATFORM_HINT = ' Organization Administrators of the organization VEYRS was installed for have it; anyone else needs the <strong>Platform Administrator</strong> role (Configure → Administration → Users).';

async function adminSoftwareUpdate(body, refresh = false) {
  let st;
  try { st = await get('/admin/updates' + (refresh ? '?refresh=true' : '')); }
  catch (e) {
    body.innerHTML = `<div class="card"><h2>Software update</h2><p class="muted">${e.status === 403
      ? 'Only a platform administrator can see or apply software updates: they concern the whole installation, not one organization.' + PLATFORM_HINT
      : 'Could not read the update status: ' + esc(e.detail || e.message)}</p></div>`;
    return;
  }
  const modes = { native: 'Native (install.sh)', docker: 'Docker', git: 'Git checkout (git deploy)', unknown: 'Unknown' };
  const chk = st.check || {};
  const latest = st.latest
    ? `<span class="mono">${esc(st.latest)}</span>${st.published_at ? ` <span class="small muted">published ${fmtDate(st.published_at)}</span>` : ''}`
    : `<span class="muted">${chk.disabled ? 'checks are disabled' : 'unknown'}</span>`;
  const signed = !st.latest ? ''
    : st.signed ? ' <span class="pill st-succeeded" title="The release carries SHA256SUMS.sig">Signed</span>'
    : ' <span class="pill st-failed" title="The release carries no SHA256SUMS.sig">Unsigned</span>';
  const notes = /^https:\/\//.test(st.notes_url || '')
    ? `<a href="${esc(st.notes_url)}" target="_blank" rel="noopener noreferrer">Release notes</a>` : '—';
  const runPill = h => `<span class="pill ${h.ok ? 'st-succeeded' : h.state === 'running' ? 'st-neutral' : 'st-failed'}">${esc(h.state || (h.ok ? 'succeeded' : 'failed'))}</span>`;
  const hist = st.history || [];
  body.innerHTML = `
    <div class="card">
      <div class="row row-split">
        <div><h2 class="mt-0">${st.update_available ? 'An update is available' : 'Software update'}</h2>
          <p class="small muted measure">Releases are verified by signature (<span class="mono">SHA256SUMS.sig</span>)
            against the release key shipped with this installation. Applying one only queues it: a root service on this
            host downloads, verifies, backs up, installs and checks health. The API restarts during the install.</p></div>
        <span class="pill ${st.update_available ? 'st-warn' : 'st-succeeded'} nowrap">${st.update_available ? 'Update available' : 'Up to date'}</span>
      </div>
      <dl class="kv mt-3">
        <dt>Installed</dt><dd class="mono">${esc(st.current)}</dd>
        <dt>Latest release</dt><dd>${latest}${signed}</dd>
        <dt>Release notes</dt><dd>${notes}</dd>
        <dt>Install mode</dt><dd>${esc(modes[st.mode] || st.mode)}</dd>
        <dt>Last checked</dt><dd>${fmtDate(chk.checked_at)}${chk.cached ? ' <span class="small muted">(cached)</span>' : ''}</dd>
        ${chk.error ? `<dt>Check failed</dt><dd class="small">${esc(chk.error)}</dd>` : ''}
        <dt>Can be applied here</dt><dd>${st.can_apply ? 'Yes' : 'No'} — <span class="small">${esc(st.reason)}</span></dd>
      </dl>
      ${st.command ? `<p class="small mt-3">On the Docker host, run:</p><pre class="mono small">${esc(st.command)}</pre>` : ''}
      <div class="row" style="margin-top:14px;gap:8px">
        <button class="btn btn-sm" id="upd-refresh">Check now</button>
        ${st.can_apply ? `<button class="btn btn-sm btn-primary" id="upd-apply">Apply ${esc(st.latest)}…</button>` : ''}
      </div>
    </div>
    <div class="card mt-4">
      <h2>Install from a local copy</h2>
      <p class="small muted measure">For a host that cannot reach GitHub, or one that must not. Copy the files of
        a release — <span class="mono">SHA256SUMS</span>, <span class="mono">SHA256SUMS.sig</span>,
        <span class="mono">veyrs-setup.sh</span>, <span class="mono">veyrs-&lt;version&gt;-src.tar.gz</span> and
        <span class="mono">veyrs-&lt;version&gt;-wheels-x86_64.tar.gz</span> (the Python packages; without it the update
        needs PyPI) — then upload them here, or put them in the local update directory
        (a USB disk or a share mounted there). Nothing is trusted because of where it came from: the signature is checked
        against the release key of this installation, here and again by the root updater before it installs.</p>
      <dl class="kv mt-2">
        <dt>Local update directory</dt><dd>${st.local_dir ? `<span class="mono">${esc(st.local_dir)}</span>` : '<span class="muted">not set — <span class="mono">VEYRS_UPDATE_LOCAL_DIR</span> in .env (not under /home or /root: the API cannot read those)</span>'}</dd>
        <dt>Uploads are kept in</dt><dd class="mono small">${esc(st.upload_dir || '—')}</dd>
      </dl>
      ${table([
        { label: 'Version', cell: i => `<span class="mono">${esc(i.version)}</span>` },
        { label: 'From', cell: i => `${i.origin === 'upload' ? 'Uploaded here' : 'Local directory'}<div class="small muted mono">${esc(i.path)}</div>` },
        { label: 'Files', cell: i => `${fmtNum(i.files.length)} · ${(i.bytes / 1048576).toFixed(1)} MB${i.has_wheels ? '' : ' <span class="pill st-warn" title="Without the wheelhouse the update downloads the Python packages from PyPI">no wheels</span>'}` },
        { label: 'Signature', cell: i => `<span class="pill ${i.verification === 'signed' ? 'st-succeeded' : 'st-failed'}" title="${esc(i.verification_detail || '')}">${esc(i.verification === 'signed' ? 'verified' : i.verification)}</span>` },
        { label: 'Apply', cell: i => i.can_apply
            ? `<button class="btn btn-sm btn-primary" data-apply="${esc(i.version)}" data-src="${esc(i.origin)}">Apply ${esc(i.version)}…</button>`
            : `<span class="small">${esc(i.reason || '')}</span>` },
        { label: '', cell: i => i.origin === 'upload' ? `<button class="btn btn-sm" data-del="${esc(i.version)}">Delete</button>` : '' },
      ], st.local || [], { emptyTitle: 'No local copy found', emptyHint: 'Upload a release below, or fill the local update directory.' })}
      <div class="mt-3">
        <label>Upload the files of ONE release</label>
        <input type="file" id="upd-files" multiple>
        <div class="row" style="gap:8px;margin-top:8px;align-items:center">
          <button class="btn btn-sm" id="upd-upload">Upload</button>
          <span class="small muted" id="upd-progress"></span>
        </div>
      </div>
    </div>
    <div class="card mt-4">
      <h2>Recent updates</h2>
      ${hist.length ? hist.map(h => `
        <details style="margin-bottom:8px">
          <summary>${runPill(h)} ${esc(h.from_version || '?')} → ${esc(h.target_version || '?')}
            <span class="small muted">${fmtDate(h.started_at)}${h.requested_by ? ' · ' + esc(h.requested_by) : ''}</span></summary>
          ${h.error ? `<p class="small">${esc(h.error)}</p>` : ''}
          ${table([
            { label: 'Step', cell: s => esc(s.name) },
            { label: 'Result', cell: s => s.ok ? '<span class="pill st-succeeded">ok</span>' : '<span class="pill st-failed">failed</span>' },
            { label: 'Detail', cell: s => `<span class="small">${esc(s.detail)}</span>` },
            { label: 'At', cell: s => fmtDate(s.at) },
          ], h.steps || [], { emptyTitle: 'No steps recorded' })}
        </details>`).join('') : '<p class="small muted">No update has run on this installation yet.</p>'}
    </div>`;
  $('#upd-refresh', body).onclick = () => adminSoftwareUpdate(body, true);
  $$('[data-apply]', body).forEach(b => { b.onclick = async () => {
    const v = b.dataset.apply, src = b.dataset.src;
    const yes = await modal({
      title: `Update VEYRS to ${v} from the ${src === 'upload' ? 'uploaded' : 'local'} copy?`,
      body: `<p class="small">The root updater copies the files into its own directory, refuses them unless the signature
               verifies, runs the pre-update backup, re-runs the installer${b.closest('tr')?.textContent.includes('no wheels') ? '' : ' with the bundled Python packages (no PyPI)'}
               and checks that <span class="mono">/healthz</span> reports ${esc(v)}.</p>
             <p class="small muted">The API restarts during the install. The outcome appears under Recent updates.</p>`,
      actions: [{ label: 'Queue the update' }],
    });
    if (!yes) return;
    try { await post('/admin/updates/apply', { version: v, source: src }); ok('Update queued.'); adminSoftwareUpdate(body); }
    catch (e) { err(e.detail); }
  }; });
  $$('[data-del]', body).forEach(b => { b.onclick = async () => {
    try { await del('/admin/updates/uploads/' + encodeURIComponent(b.dataset.del)); ok('Uploaded copy deleted.'); adminSoftwareUpdate(body); }
    catch (e) { err(e.detail); }
  }; });
  $('#upd-upload', body).onclick = async () => {
    const files = [...($('#upd-files', body).files || [])];
    const prog = $('#upd-progress', body);
    if (!files.length) { err('Choose the release files first.'); return; }
    const button = $('#upd-upload', body);
    button.disabled = true;
    try {
      const { upload_id, chunk_bytes } = await post('/admin/updates/uploads');
      const total = files.reduce((n, f) => n + f.size, 0);
      let sent = 0;
      for (const f of files) {
        for (let off = 0; off < f.size; off += chunk_bytes) {
          const part = f.slice(off, Math.min(f.size, off + chunk_bytes));
          await api(`/admin/updates/uploads/${upload_id}/${encodeURIComponent(f.name)}?offset=${off}&total=${f.size}`,
                    { method: 'PUT', body: part });
          sent += part.size;
          prog.textContent = `${f.name}: ${Math.round(100 * sent / total)} %`;
        }
      }
      const item = await post(`/admin/updates/uploads/${upload_id}/finish`);
      prog.textContent = '';
      (item.verification === 'signed' ? ok : err)(`Release ${item.version} uploaded: ${item.verification_detail || item.verification}`);
      adminSoftwareUpdate(body);
    } catch (e) { prog.textContent = ''; err(e.detail); }
    finally { button.disabled = false; }
  };
  const apply = $('#upd-apply', body);
  if (apply) apply.onclick = async () => {
    const yes = await modal({
      title: `Update VEYRS to ${st.latest}?`,
      body: `<p class="small">The root updater will download release <span class="mono">${esc(st.latest)}</span>,
               refuse it unless its signature verifies, run the pre-update backup, re-run the installer and
               check that <span class="mono">/healthz</span> reports the new version.</p>
             <p class="small muted">The API restarts during the install: this console will be unavailable
               for a few minutes. The outcome appears under Recent updates.</p>`,
      actions: [{ label: 'Queue the update' }],
    });
    if (!yes) return;
    try {
      await post('/admin/updates/apply', { version: st.latest });
      ok('Update queued. The root updater has taken it over.');
      adminSoftwareUpdate(body);
    } catch (e) { err(e.detail); }
  };
}

/* ── Administration → Installed software ──────────────────────────────
   What this node runs: the platform components (with the version the binary
   reports AND the one the package manager records -- the second is what an
   advisory names) and every Python package in the API's interpreter, checked
   against the lock in requirements.txt. Drift is flagged, because two app
   nodes on different packages is how a failover serves different code.
   Platform administrators only; read-only. */
async function adminInstalledSoftware(body, refresh = false) {
  let inv;
  try { inv = await get('/admin/system/software' + (refresh ? '?refresh=true' : '')); }
  catch (e) {
    body.innerHTML = `<div class="card"><h2>Installed software</h2><p class="muted">${e.status === 403
      ? 'Only a platform administrator can see what this installation runs: versions of every component are reconnaissance data.' + PLATFORM_HINT
      : 'Could not read the inventory: ' + esc(e.detail || e.message)}</p></div>`;
    return;
  }
  const n = inv.node || {}, s = inv.summary || {};
  const modes = { native: 'Native (install.sh)', docker: 'Docker', git: 'Git checkout (git deploy)', unknown: 'Unknown' };
  const compState = { ok: ['st-succeeded', 'found'], no_version: ['st-warn', 'no version'],
    not_found: ['st-neutral', 'not installed'], unreachable: ['st-failed', 'unreachable'] };
  const pkgState = { ok: ['st-succeeded', 'matches lock'], differs: ['st-failed', 'differs from lock'],
    not_in_lock: ['st-warn', 'not in lock'], missing: ['st-failed', 'missing'],
    tooling: ['st-neutral', 'venv tooling'], no_lock: ['st-neutral', 'no lock file'],
    application: ['st-neutral', 'this application'] };
  const pill = (map, k) => { const [c, l] = map[k] || ['st-neutral', k]; return `<span class="pill ${c}">${esc(l)}</span>`; };
  const pkgs = inv.python_packages || [];
  body.innerHTML = `
    <div class="card">
      <div class="row row-split">
        <div><h2 class="mt-0">This node</h2>
          <p class="small muted measure">What the node that answered this page runs. Behind the proxy that is the
            primary node unless it is down; check each node before a failover test. Python packages are compared with the
            lock (<span class="mono">requirements.txt</span>): a difference is drift, not a preference.</p></div>
        <span class="pill ${s.drift ? 'st-failed' : 'st-succeeded'} nowrap">${s.drift ? fmtNum(s.drift) + ' drifted' : 'Matches the lock'}</span>
      </div>
      <dl class="kv mt-3">
        <dt>Node</dt><dd class="mono">${esc(n.hostname || '—')}</dd>
        <dt>VEYRS</dt><dd><span class="mono">${esc(n.veyrs_version || '—')}</span>${n.revision ? ` <span class="small muted">commit ${esc(n.revision)}</span>` : ''}</dd>
        <dt>Install mode</dt><dd>${esc(modes[n.install_mode] || n.install_mode || '—')}</dd>
        <dt>Operating system</dt><dd>${esc(n.os || '—')} <span class="small muted">kernel ${esc(n.kernel || '?')} · ${esc(n.architecture || '?')}</span></dd>
        <dt>Python</dt><dd><span class="mono">${esc(n.python || '—')}</span> <span class="small muted mono">${esc(n.python_executable || '')}</span></dd>
        <dt>Package manager</dt><dd>${esc(n.package_manager || 'none found')}</dd>
        <dt>Generated</dt><dd>${fmtDate(inv.generated_at)}${inv.cached ? ' <span class="small muted">(cached)</span>' : ''}</dd>
      </dl>
      <div class="row mt-4"><button class="btn btn-sm" id="inv-refresh">Re-read now</button></div>
    </div>
    <div class="card mt-4">
      <h2>Platform components</h2>
      <p class="small muted measure">"Running" is what the binary or server reports; "Package" is what the
        package manager has on record — the version a security advisory names. PostgreSQL and Redis may live on another host.</p>
      ${table([
        { label: 'Component', cell: c => `<strong>${esc(c.name)}</strong>${c.host ? `<div class="small muted mono">${esc(c.host)}</div>` : ''}` },
        { label: 'Running', cell: c => c.version ? `<span class="mono">${esc(c.version)}</span>` : '<span class="muted">—</span>' },
        { label: 'Package', cell: c => c.package ? `<span class="mono small">${esc(c.package)} ${esc(c.package_version || '')}</span>` : '<span class="muted small">—</span>' },
        { label: 'State', cell: c => pill(compState, c.state) },
        { label: 'Used by', cell: c => `<span class="small">${esc(c.used_by || '')}</span>` },
      ], inv.components || [], { emptyTitle: 'No components measured' })}
    </div>
    <div class="card mt-4">
      <h2>Scan agents</h2>
      <p class="small muted measure">The scanners run on each agent's own host, so their versions are the ones the
        agent declared when it last registered — not measured from here.</p>
      ${(inv.agents || []).length ? table([
        { label: 'Agent', cell: a => `<strong>${esc(a.name)}</strong>${a.hostname ? `<div class="small muted mono">${esc(a.hostname)}</div>` : ''}` },
        { label: 'Agent version', cell: a => a.agent_version ? `<span class="mono">${esc(a.agent_version)}</span>` : '<span class="muted">—</span>' },
        { label: 'Tools', cell: a => (a.tools || []).map(t => `<span class="mono small">${esc(t.name)} ${esc(t.version || '?')}</span>${t.enabled ? '' : ' <span class="small muted">(off)</span>'}`).join('<br>') || '<span class="muted small">none declared</span>' },
        { label: 'Last heartbeat', cell: a => a.disabled ? '<span class="pill st-neutral">disabled</span>' : fmtDate(a.last_heartbeat_at) },
      ], inv.agents) : '<p class="small muted">No agent is registered in this organization.</p>'}
    </div>
    <div class="card mt-4">
      <h2>Python packages <span class="small muted">${fmtNum(s.python_packages || 0)} installed · ${fmtNum(s.direct || 0)} direct</span></h2>
      <p class="small muted measure">Every distribution in the interpreter that runs the API, not a curated subset.
        <em>Direct</em> = declared in <span class="mono">pyproject.toml</span>; the rest are what those pull in. Packages are
        updated with a VEYRS release, never one by one: the lock is tested as a whole.</p>
      ${table([
        { label: 'Package', cell: p => `<span class="mono">${esc(p.name)}</span>${p.direct ? ' <span class="pill st-neutral">direct</span>' : ''}${p.summary ? `<div class="small muted">${esc(p.summary)}</div>` : ''}` },
        { label: 'Installed', cell: p => p.version ? `<span class="mono">${esc(p.version)}</span>` : '<span class="muted">—</span>' },
        { label: 'Lock', cell: p => p.locked ? `<span class="mono small">${esc(p.locked)}</span>` : '<span class="muted small">—</span>' },
        { label: 'State', cell: p => pill(pkgState, p.state) },
        { label: 'Licence', cell: p => `<span class="small">${esc(p.license || '—')}</span>` },
      ], pkgs, { emptyTitle: 'No packages found' })}
    </div>`;
  $('#inv-refresh', body).onclick = () => adminInstalledSoftware(body, true);
}

/* ── Configure → Platform → Web certificate ─────────────────────────────────
   The certificate VEYRS itself serves. Three steps, in this order on the page:
   request (the key is generated on the server and never leaves it), attach
   what the CA signed (every check shown), install (each app node's root
   veyrs-tls-sync.timer applies it and reports back below). Platform
   administrators only (services/web_tls.py). */
const WEBTLS_NODE = { applied: ['st-succeeded', 'Serving HTTPS'], off: ['st-neutral', 'HTTP only'],
  not_configured: ['st-warn', 'nginx not prepared'], error: ['st-failed', 'Error'],
  not_reporting: ['st-failed', 'Not reporting'] };
const WEBTLS_CHECK = { pass: ['st-succeeded', 'pass'], warn: ['st-warn', 'warning'], fail: ['st-failed', 'fail'] };
let webTlsPoll = null;
const WEBTLS_PATH_LS = 'veyrs.webcert.path';

function webTlsChecks(checks) {
  if (!(checks || []).length) return '';
  return table([
    { label: 'Check', cell: c => `<strong>${esc(c.check)}</strong>` },
    { label: 'Result', cell: c => { const [k, l] = WEBTLS_CHECK[c.result] || ['st-neutral', c.result]; return `<span class="pill ${k}">${esc(l)}</span>`; } },
    { label: 'Detail', cell: c => `<span class="small">${esc(c.detail)}</span>` },
  ], checks);
}
function webTlsExpiry(c) {
  if (!c || !c.not_after) return '—';
  const k = c.expiry === 'expired' ? 'st-failed' : c.expiry === 'expiring' ? 'st-warn' : 'st-succeeded';
  const l = c.expiry === 'expired' ? 'expired' : `${fmtNum(c.days_left)} days left`;
  return `${fmtDay(c.not_after)} <span class="pill ${k}">${esc(l)}</span>`;
}
async function fileAsText(file) {
  const buf = await file.arrayBuffer();
  const text = new TextDecoder('ascii').decode(buf);
  if (text.includes('-----BEGIN')) return text;
  const bytes = new Uint8Array(buf); let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);           // DER / PKCS#12: the API takes base64
}

async function adminWebCertificate(body) {
  if (webTlsPoll) { clearTimeout(webTlsPoll); webTlsPoll = null; }
  let st;
  try { st = await get('/admin/web-certificate'); }
  catch (e) {
    body.innerHTML = `<div class="card"><h2>Web certificate</h2><p class="muted">${e.status === 403
      ? 'Only a platform administrator can manage the certificate VEYRS serves: whoever controls it can impersonate VEYRS to every user.' + PLATFORM_HINT
      : 'Could not read the web certificate state: ' + esc(e.detail || e.message)}</p></div>`;
    return;
  }
  const a = st.active, nodes = st.nodes || [];
  const allSynced = nodes.length > 0 && nodes.every(n => n.in_sync);
  const head = a
    ? (allSynced ? ['st-succeeded', 'Serving HTTPS'] : ['st-warn', 'Installing…'])
    : ['st-neutral', 'No certificate installed'];
  const keyOpts = (st.key_types || []).map(k => `<option value="${esc(k.value)}" ${k.value === st.default_key_type ? 'selected' : ''}>${esc(k.label)}</option>`).join('');
  const pendingOpts = (st.pending || []).map(p => `<option value="${esc(p.id)}">${esc(p.common_name)} (${esc(p.key_label)}, ${fmtDay(p.created_at)})</option>`).join('');
  /* Two ways in (0.42.0, owner request): A = CSR generated here and signed by
     the operator's CA, B = certificate + key brought from elsewhere. The
     choice is remembered per browser; a request waiting for its certificate
     always opens on A, where it is. */
  let path = 'csr';
  try { if (localStorage.getItem(WEBTLS_PATH_LS) === 'import') path = 'import'; } catch { /* private mode */ }
  if ((st.pending || []).length) path = 'csr';
  body.innerHTML = `
    <div class="card">
      <div class="row row-split">
        <div><h2 class="mt-0">Current certificate</h2>
          <p class="small muted measure">The certificate VEYRS presents on HTTPS (port 443 of every app node: console,
            documentation and product site). Get one below in either of two ways. Either way its private key is kept sealed
            like every other credential and is never shown or downloaded again.</p></div>
        <span class="pill ${head[0]} nowrap">${head[1]}</span>
      </div>
      ${a ? `<dl class="kv mt-3">
          <dt>Names</dt><dd class="mono small">${esc((a.names || []).join(', '))}</dd>
          <dt>Subject</dt><dd class="mono small">${esc(a.subject)}</dd>
          <dt>Issued by</dt><dd class="mono small">${esc(a.issuer)}</dd>
          <dt>Valid until</dt><dd>${webTlsExpiry(a)}</dd>
          <dt>Key</dt><dd>${esc(a.key_label)} · ${a.source === 'csr' ? 'generated by VEYRS' : 'imported'}</dd>
          <dt>SHA-256</dt><dd class="mono small">${esc(a.fingerprint)}</dd>
          <dt>Installed</dt><dd>${fmtDate(a.activated_at)}${a.activated_by ? ' by ' + esc(a.activated_by) : ''}</dd>
        </dl>
        <div class="row mt-3"><button class="btn btn-sm btn-danger" id="wt-uninstall">Stop serving HTTPS</button></div>`
      : `<p class="small mt-3">Nothing is installed: every node serves plain HTTP only. Get a certificate below, then install it.</p>`}
    </div>

    <div class="card mt-4">
      <h2 class="mt-0">Get a certificate</h2>
      <p class="small muted measure">Choose how. Whichever way it arrives, VEYRS checks it before it can be installed:
        names, dates, key, signature, usage (server authentication) and the chain of trust. A failing check says why and
        nothing is stored.</p>
      <div class="wt-paths mt-3" role="radiogroup" aria-label="How to get the certificate">
        <button type="button" role="radio" class="wt-path" data-path="csr" aria-checked="${path === 'csr'}">
          <span class="wt-path-title">A · Request it here, sign it with your CA <span class="pill st-ok">Recommended</span></span>
          <span class="small muted">VEYRS generates the private key and a CSR. Your CA (corporate or public) signs the
            CSR and you upload the certificate it returns. The private key never leaves VEYRS.</span>
        </button>
        <button type="button" role="radio" class="wt-path" data-path="import" aria-checked="${path === 'import'}">
          <span class="wt-path-title">B · Upload a certificate and its private key</span>
          <span class="small muted">For a certificate issued elsewhere: a PEM certificate with its private key, or a
            PKCS#12 file (.pfx, .p12). The key is sealed on arrival.</span>
        </button>
      </div>

      <div class="wt-pane" data-pane="csr"${path === 'csr' ? '' : ' hidden'}>
        <h3 class="mt-4">1 · Generate the key and the request</h3>
        <p class="small muted measure">The common name and every extra name must be the names users type to reach VEYRS
          (and the node names, if anything connects to a node directly). Browsers only read the names list (SAN), which
          VEYRS fills with all of them.</p>
        <form id="wt-req" class="mt-3">
          <label>Common name</label><input name="common_name" required maxlength="253" value="${esc(location.hostname)}">
          <label class="mt-3">Extra names (one per line: host names or IP addresses)</label>
          <textarea name="extra_names" rows="3" class="mono small"></textarea>
          <label class="mt-3">Key</label><select name="key_type">${keyOpts}</select>
          <label class="mt-3">Organization (optional)</label><input name="organization" maxlength="64">
          <label class="mt-3">Organizational unit (optional)</label><input name="organizational_unit" maxlength="64">
          <label class="mt-3">City (optional)</label><input name="locality" maxlength="64">
          <label class="mt-3">State or province (optional)</label><input name="state" maxlength="64">
          <label class="mt-3">Country (optional, two letters)</label><input name="country" maxlength="2">
          <button class="btn btn-primary mt-3" type="submit">Generate key and request</button>
        </form>
        <h3 class="mt-4">2 · Have the CSR signed</h3>
        <p class="small muted measure">Download the CSR and submit it to your CA. It is public: names and public key only.</p>
        ${(st.pending || []).length ? table([
          { label: 'Names', cell: p => `<span class="mono small">${esc(p.requested_names.join(', '))}</span>` },
          { label: 'Key', cell: p => esc(p.key_label) },
          { label: 'Created', cell: p => `${fmtDate(p.created_at)}${p.created_by ? `<div class="small muted">${esc(p.created_by)}</div>` : ''}` },
          { label: '', cell: p => `<span class="nowrap"><button class="btn btn-sm btn-primary" data-csr="${esc(p.id)}" data-cn="${esc(p.common_name)}">Download CSR</button>
              <button class="btn btn-sm" data-showcsr="${esc(p.id)}">Show</button>
              <button class="btn btn-sm btn-danger" data-discard="${esc(p.id)}" data-what="request for ${esc(p.common_name)}">Discard</button></span>` },
        ], st.pending) : '<p class="small muted">No request yet: generate one in step 1.</p>'}
        <h3 class="mt-4">3 · Upload the signed certificate</h3>
        <p class="small muted measure">What the CA returned, ideally with its intermediate chain (a "full chain" file is
          fine). VEYRS finds the request it belongs to by its public key. If your CA is private, import its root in
          <a href="#/admin?tab=truststore">Trust store</a> first.</p>
        ${(st.pending || []).length ? `<form id="wt-attach" class="mt-3">
          <label>Request</label><select name="request_id"><option value="">Find it automatically</option>${pendingOpts}</select>
          <label class="mt-3">Certificate file (.crt, .cer, .pem; PEM or DER)</label><input type="file" name="file" accept=".crt,.cer,.pem,.der">
          <label class="mt-3">Or paste the PEM (certificate, then chain)</label><textarea name="certificate" rows="8" class="mono small" placeholder="-----BEGIN CERTIFICATE-----"></textarea>
          <label class="mt-3">Chain file (optional, if the CA sent it separately)</label><input type="file" name="chain" accept=".crt,.cer,.pem,.p7b">
          <button class="btn btn-primary mt-3" type="submit">Check and attach</button>
        </form>` : '<p class="small muted">Nothing is waiting for a certificate: generate a request in step 1 first.</p>'}
        <div id="wt-checks" class="mt-3"></div>
      </div>

      <div class="wt-pane" data-pane="import"${path === 'import' ? '' : ' hidden'}>
        <h3 class="mt-4">Certificate and private key</h3>
        <p class="small muted measure">Either the PKCS#12 file, or the certificate (PEM, with its chain) and its private
          key (PEM). The passphrase is used once to open the key and is not kept.</p>
        <form id="wt-import" class="mt-3">
        <label>PKCS#12 file (.pfx, .p12)</label><input type="file" name="p12" accept=".pfx,.p12">
        <label class="mt-3">Or certificate (PEM, with chain)</label><textarea name="certificate" rows="5" class="mono small"></textarea>
        <label class="mt-3">and private key (PEM)</label><textarea name="private_key" rows="5" class="mono small" autocomplete="off"></textarea>
        <label class="mt-3">Passphrase (if the key or the file has one)</label><input name="passphrase" type="password" autocomplete="off">
        <button class="btn btn-primary mt-3" type="submit">Check and import</button>
        </form>
        <div id="wt-imp-checks" class="mt-3"></div>
      </div>
    </div>

    <div class="card mt-4">
      <h2>Ready to install</h2>
      <p class="small muted measure">Accepted certificates, from either path. Installing makes one THE certificate of the
        installation; the checks run again at that moment. Each app node writes it, tests nginx's configuration before
        reloading (a refused configuration is rolled back and never reloaded), connects to its own port 443 and reports
        under App nodes.</p>
      ${(st.ready || []).length ? table([
        { label: 'Names', cell: c => `<span class="mono small">${esc((c.names || []).join(', '))}</span>` },
        { label: 'Issued by', cell: c => `<span class="mono small">${esc(c.issuer)}</span>` },
        { label: 'Valid until', cell: c => webTlsExpiry(c) },
        { label: 'Checks', cell: c => { const w = (c.checks || []).filter(x => x.result === 'warn').length; return w ? `<span class="pill st-warn">${w} warning${w > 1 ? 's' : ''}</span>` : '<span class="pill st-succeeded">all passed</span>'; } },
        { label: '', cell: c => `<span class="nowrap"><button class="btn btn-sm btn-primary" data-install="${esc(c.id)}">Install</button>
            <button class="btn btn-sm" data-details="${esc(c.id)}">Checks</button>
            <button class="btn btn-sm btn-danger" data-discard="${esc(c.id)}" data-what="certificate ${esc(c.common_name)}">Discard</button></span>` },
      ], st.ready) : '<p class="small muted">No certificate is ready to install.</p>'}
      <div id="wt-inst-checks" class="mt-3"></div>
    </div>

    <div class="card mt-4">
      <div class="row row-split"><h2 class="mt-0">App nodes</h2><button class="btn btn-sm" id="wt-refresh">Refresh</button></div>
      <p class="small muted measure">What each node reports after its last check (every 30 seconds, by the root
        <span class="mono">veyrs-tls-sync.timer</span>). "Serving HTTPS" is measured: the node connected to its own port
        443 and compared the certificate it received with the one installed here.</p>
      ${nodes.length ? table([
        { label: 'Node', cell: n => `<strong class="mono">${esc(n.node)}</strong>${n.nginx_version ? `<div class="small muted">nginx ${esc(n.nginx_version)}</div>` : ''}` },
        { label: 'State', cell: n => { const [k, l] = WEBTLS_NODE[n.state] || ['st-neutral', n.state]; return `<span class="pill ${k}">${esc(l)}</span>${n.redirect_http ? ' <span class="pill st-neutral">HTTP redirects</span>' : ''}`; } },
        { label: 'Detail', cell: n => `<span class="small">${esc(n.state === 'not_reporting' ? `No report for over ${Math.round(st.stale_seconds / 60)} minutes: check systemctl status veyrs-tls-sync.timer on this node. Last report: ${n.detail}` : n.detail)}</span>` },
        { label: 'Last check', cell: n => fmtDate(n.checked_at) },
      ], nodes) : `<p class="small"><span class="pill st-warn">No node has reported</span> Each app node needs the root
        timer <span class="mono">veyrs-tls-sync.timer</span> (installed by <span class="mono">install.sh</span> from 0.41.0).
        Docker deployments do not run it: terminate TLS on the proxy in front of the stack instead.</p>`}
    </div>

    <div class="card mt-4">
      <h2>Redirect HTTP to HTTPS</h2>
      <p class="small muted measure">When on, every node answers plain HTTP with a redirect to HTTPS, except
        <span class="mono">/healthz</span>, <span class="mono">/readyz</span> and <span class="mono">/metrics</span> (load balancers and monitoring reach those on
        HTTP). Turn it on only when every user and every proxy in front of VEYRS reaches it on port 443: a proxy that
        still talks HTTP to the nodes would loop.</p>
      <div class="row mt-3">
        <span class="pill ${st.policy.redirect_http ? 'st-succeeded' : 'st-neutral'}">${st.policy.redirect_http ? 'On' : 'Off'}</span>
        <button class="btn btn-sm" id="wt-redirect" ${a ? '' : 'disabled'}>${st.policy.redirect_http ? 'Turn off' : 'Turn on'}</button>
      </div>
    </div>

    ${(st.retired || []).length ? `<div class="card mt-4"><h2>Previous certificates</h2>
      <p class="small muted measure">Kept so a change can be rolled back: install one again to serve it.</p>` + table([
        { label: 'Names', cell: c => `<span class="mono small">${esc((c.names || []).join(', '))}</span>` },
        { label: 'Issued by', cell: c => `<span class="mono small">${esc(c.issuer)}</span>` },
        { label: 'Valid until', cell: c => webTlsExpiry(c) },
        { label: '', cell: c => `<span class="nowrap"><button class="btn btn-sm" data-install="${esc(c.id)}">Install again</button>
            <button class="btn btn-sm btn-danger" data-discard="${esc(c.id)}" data-what="certificate ${esc(c.common_name)}">Discard</button></span>` },
      ], st.retired) + '</div>' : ''}`;

  const all = [].concat(st.ready || [], st.retired || [], a ? [a] : []);
  $$('.wt-path', body).forEach(b => {
    b.onclick = () => {
      $$('.wt-path', body).forEach(x => x.setAttribute('aria-checked', String(x === b)));
      $$('.wt-pane', body).forEach(x => { x.hidden = x.dataset.pane !== b.dataset.path; });
      try { localStorage.setItem(WEBTLS_PATH_LS, b.dataset.path); } catch { /* private mode */ }
    };
  });
  // Each path reports its refused checks next to its own form.
  const showChecks = (e, where = '#wt-checks') => {
    const out = $(where, body);
    const data = e && e.data;
    out.innerHTML = data && data.checks
      ? `<p class="small"><span class="pill st-failed">Not accepted</span> Nothing was stored. Fix the failing checks and upload again.</p>` + webTlsChecks(data.checks)
      : '';
    err(e.detail || e.message);
  };

  const req = $('#wt-req', body);
  req.onsubmit = async e => {
    e.preventDefault();
    const f = Object.fromEntries(new FormData(req).entries());
    try {
      const r = await post('/admin/web-certificate/requests', f);
      ok(`Key and request created for ${r.common_name}. Download the CSR and send it to your CA.`);
      adminWebCertificate(body);
    } catch (ex) { err(ex.detail || ex.message); }
  };

  const att = $('#wt-attach', body);
  if (att) att.onsubmit = async e => {
    e.preventDefault();
    const file = att.file.files[0], chainFile = att.chain.files[0];
    let cert = att.certificate.value.trim();
    if (file && cert) return err('Choose a file or paste PEM, not both.');
    if (file) cert = await fileAsText(file);
    if (!cert) return err('Upload or paste the signed certificate.');
    const payload = { certificate: cert, request_id: att.request_id.value || null };
    if (chainFile) payload.chain = await fileAsText(chainFile);
    try {
      const r = await post('/admin/web-certificate/certificate', payload);
      ok(`Certificate for ${(r.names || []).join(', ')} accepted. Install it under Ready to install.`);
      await adminWebCertificate(body);
      $('#wt-checks', body).innerHTML = '<p class="small"><span class="pill st-succeeded">Accepted</span> Checks:</p>' + webTlsChecks(r.checks);
    } catch (ex) { showChecks(ex); }
  };

  const imp = $('#wt-import', body);
  imp.onsubmit = async e => {
    e.preventDefault();
    const p12 = imp.p12.files[0];
    const payload = { passphrase: imp.passphrase.value || null };
    if (p12) payload.pkcs12_base64 = await fileAsText(p12);
    else { payload.certificate = imp.certificate.value.trim() || null; payload.private_key = imp.private_key.value.trim() || null; }
    try {
      await post('/admin/web-certificate/import', payload);
      imp.reset();
      ok('Certificate and key imported. Install it under Ready to install.');
      adminWebCertificate(body);
    } catch (ex) { showChecks(ex, '#wt-imp-checks'); }
  };

  $('#wt-refresh', body).onclick = () => adminWebCertificate(body);
  const unin = $('#wt-uninstall', body);
  if (unin) unin.onclick = async () => {
    const r = await modal({ title: 'Stop serving HTTPS?', actions: [{ label: 'Stop HTTPS', cls: 'btn-danger' }],
      body: `<p>Every app node removes its port 443 block within about 30 seconds and serves plain HTTP only. Anyone reaching
        VEYRS directly on HTTPS loses access${st.policy.redirect_http ? ', and the HTTP to HTTPS redirect is switched off with it' : ''}.
        The certificate is kept under Previous certificates.</p>` });
    if (!r) return;
    try { await post('/admin/web-certificate/uninstall'); ok('HTTPS is being removed from the nodes.'); adminWebCertificate(body); }
    catch (ex) { err(ex.detail || ex.message); }
  };
  const redir = $('#wt-redirect', body);
  redir.onclick = async () => {
    const on = !st.policy.redirect_http;
    if (on) {
      const r = await modal({ title: 'Redirect HTTP to HTTPS?', actions: [{ label: 'Turn on' }],
        body: `<p>Plain HTTP requests will be answered with a redirect to HTTPS (except /healthz, /readyz and /metrics). Confirm that
          users and any proxy in front of VEYRS already use port 443; otherwise they will loop or lose access.</p>` });
      if (!r) return;
    }
    try { await put('/admin/web-certificate/policy', { redirect_http: on }); ok(on ? 'HTTP now redirects to HTTPS.' : 'HTTP no longer redirects.'); adminWebCertificate(body); }
    catch (ex) { err(ex.detail || ex.message); }
  };

  body.onclick = async e => {
    const b = e.target.closest('button');
    if (!b) return;
    if (b.dataset.csr) {
      try {
        const pem = await api('/admin/web-certificate/' + encodeURIComponent(b.dataset.csr) + '/csr');
        const link = document.createElement('a');
        link.href = URL.createObjectURL(new Blob([pem], { type: 'application/pkcs10' }));
        link.download = b.dataset.cn.replace('*', 'wildcard').replace(/[^A-Za-z0-9.-]/g, '_') + '.csr';
        document.body.appendChild(link); link.click(); link.remove();
        setTimeout(() => URL.revokeObjectURL(link.href), 1000);
      } catch (ex) { err(ex.detail || ex.message); }
    } else if (b.dataset.showcsr) {
      const p = (st.pending || []).find(x => x.id === b.dataset.showcsr);
      await modal({ title: 'Certificate signing request', wide: true, dismiss: 'Close', actions: [],
        body: `<p class="small muted">Public: it contains the names and the public key, never the private key. Paste it into your CA's request form.</p>
          <pre class="mono small pre-wrap mt-3">${esc(p ? p.csr_pem : '')}</pre>` });
    } else if (b.dataset.details) {
      const c = all.find(x => x.id === b.dataset.details);
      await modal({ title: 'Checks for ' + (c ? c.common_name : ''), wide: true, dismiss: 'Close', actions: [], body: webTlsChecks(c ? c.checks : []) });
    } else if (b.dataset.install) {
      const c = all.find(x => x.id === b.dataset.install) || {};
      const r = await modal({ title: 'Install this certificate?', actions: [{ label: 'Install' }],
        body: `<p>Every app node will serve <span class="mono">${esc((c.names || []).join(', '))}</span> on port 443 within about
          30 seconds${a ? ', replacing the current certificate (kept under Previous certificates)' : ''}. Each node tests nginx's
          configuration first and keeps its current one if the test fails.</p>` });
      if (!r) return;
      try {
        await post('/admin/web-certificate/' + encodeURIComponent(b.dataset.install) + '/install');
        ok('Installing: the nodes apply it within about 30 seconds.');
        adminWebCertificate(body);
      } catch (ex) { showChecks(ex, '#wt-inst-checks'); }
    } else if (b.dataset.discard) {
      const r = await modal({ title: 'Discard the ' + b.dataset.what + '?', actions: [{ label: 'Discard', cls: 'btn-danger' }],
        body: '<p>Its private key is destroyed: a certificate the CA issues later for this request can no longer be attached. Recorded in the audit trail.</p>' });
      if (!r) return;
      try { await del('/admin/web-certificate/' + encodeURIComponent(b.dataset.discard)); ok('Discarded.'); adminWebCertificate(body); }
      catch (ex) { err(ex.detail || ex.message); }
    }
  };

  /* While a change is reaching the nodes, re-read the state every 10 s (at most
     two minutes, and only while this page is open). */
  const converging = a ? !allSynced : nodes.some(n => n.reported_state !== 'off' && n.state !== 'not_reporting');
  if (converging) {
    let left = 12;
    const tick = async () => {
      if (!body.isConnected || !location.hash.includes('tab=webcert') || --left < 0) return;
      await adminWebCertificate(body);
    };
    webTlsPoll = setTimeout(tick, 10000);
  }
}

/* ── Configure → Platform → Trust store ─────────────────────────────────────
   The certificate authorities VEYRS accepts when it connects OUT: asset
   sources, scanner connectors, ITSM, directory, single sign-on, SMTP, AI
   endpoints, the vault and the intelligence feeds. They are ADDED to the
   public roots, never substituted. Installation-wide, so platform
   administrators only (services/trust_store.py). */
const TRUST_STATE = { valid: ['st-succeeded', 'valid'], expiring: ['st-warn', 'expires soon'],
  expired: ['st-failed', 'expired'], not_yet_valid: ['st-warn', 'not yet valid'] };

/* A DER upload becomes PEM here, so the API only ever parses one text format. */
function derToPem(buf) {
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return `-----BEGIN CERTIFICATE-----\n${btoa(bin).replace(/(.{64})/g, '$1\n')}\n-----END CERTIFICATE-----\n`;
}
async function certFileText(file) {
  const buf = await file.arrayBuffer();
  const text = new TextDecoder('ascii').decode(buf);
  return text.includes('-----BEGIN') ? text : derToPem(buf);
}

async function adminTrustStore(body) {
  let st;
  try { st = await get('/admin/trust-store'); }
  catch (e) {
    body.innerHTML = `<div class="card"><h2>Trust store</h2><p class="muted">${e.status === 403
      ? 'Only a platform administrator can change which certificate authorities this installation trusts: the store applies to every organization.' + PLATFORM_HINT
      : 'Could not read the trust store: ' + esc(e.detail || e.message)}</p></div>`;
    return;
  }
  const s = st.summary || {};
  const statePill = c => { const [k, l] = TRUST_STATE[c.state] || ['st-neutral', c.state]; return `<span class="pill ${k}">${esc(l)}</span>`; };
  body.innerHTML = `
    <div class="card">
      <div class="row row-split">
        <div><h2 class="mt-0">Status</h2>
          <p class="small muted measure">The certificate authorities VEYRS accepts when it connects <em>out</em>: asset
            sources, scanner connectors, ITSM and Confluence, directory (LDAPS / StartTLS), single sign-on, SMTP, AI
            endpoints, the secret vault and the intelligence feeds. They are added to the ${fmtNum(st.public_roots)}
            public roots, never substituted for them. A connector with TLS verification switched off stays unverified.
            A change reaches every API node within ${fmtNum(st.refresh_seconds)} seconds.</p></div>
        <span class="pill ${s.enabled ? 'st-succeeded' : 'st-neutral'} nowrap">${s.enabled ? fmtNum(s.enabled) + ' trusted' : 'Public roots only'}</span>
      </div>
      <dl class="kv mt-3">
        <dt>Root CAs</dt><dd>${fmtNum(s.roots || 0)}</dd>
        <dt>Intermediate CAs</dt><dd>${fmtNum(s.intermediates || 0)}</dd>
        <dt>Disabled</dt><dd>${fmtNum((s.total || 0) - (s.enabled || 0))}</dd>
        <dt>Expired / expiring</dt><dd>${fmtNum(s.expired || 0)} / ${fmtNum(s.expiring || 0)}</dd>
      </dl>
      ${(st.gaps || []).length ? `<p class="small mt-3"><span class="pill st-warn">Incomplete chain</span> ${st.gaps.map(g =>
        `<strong>${esc(g.name)}</strong> was issued by <span class="mono">${esc(g.issuer)}</span>, which is neither here nor a public root. Import that CA too, or every server it signs fails with "unable to get issuer certificate".`).join('<br>')}</p>` : ''}
    </div>
    <div class="card mt-4">
      <h2>Certificate authorities</h2>
      ${table([
        { label: 'Name', cell: c => `<strong>${esc(c.name)}</strong>${c.note ? `<div class="small muted">${esc(c.note)}</div>` : ''}` },
        { label: 'Role', cell: c => `<span class="pill st-neutral">${c.role === 'root' ? 'Root' : 'Intermediate'}</span>` },
        { label: 'Subject', cell: c => `<span class="mono small">${esc(c.subject)}</span>` },
        { label: 'Expires', cell: c => `${fmtDay(c.not_after)} ${statePill(c)}` },
        { label: 'In use', cell: c => c.is_enabled ? '<span class="pill st-succeeded">enabled</span>' : '<span class="pill st-neutral">disabled</span>' },
        { label: '', cell: c => `<span class="nowrap"><button class="btn btn-sm" data-view="${esc(c.id)}">View</button>
            <button class="btn btn-sm" data-toggle="${esc(c.id)}" data-on="${c.is_enabled ? 1 : 0}">${c.is_enabled ? 'Disable' : 'Enable'}</button>
            <button class="btn btn-sm btn-danger" data-del="${esc(c.id)}" data-name="${esc(c.name)}">Remove</button></span>` },
      ], st.items || [], { emptyTitle: 'No private certificate authority', emptyHint: ' VEYRS trusts the public roots only. Import your company root below.' })}
    </div>
    <div class="card mt-4">
      <h2>Import a CA</h2>
      <p class="small muted measure">Choose a <span class="mono">.pem</span>, <span class="mono">.crt</span> or
        <span class="mono">.cer</span> file (PEM or DER) or paste one certificate or a whole chain (root + intermediates).
        Only CA certificates are accepted; a server certificate in the paste is skipped with the reason. Importing a CA
        that is already here updates it instead of adding a duplicate.</p>
      <form id="ts-import" class="mt-3">
        <label>Certificate file</label><input type="file" name="file" accept=".pem,.crt,.cer,.der">
        <label class="mt-3">Or paste PEM</label><textarea name="pem" rows="8" class="mono small" placeholder="-----BEGIN CERTIFICATE-----"></textarea>
        <label class="mt-3">Name (optional: defaults to the certificate's common name)</label><input name="name" maxlength="180">
        <label class="mt-3">Note (optional)</label><input name="note" maxlength="500">
        <button class="btn btn-primary mt-3" type="submit">Import</button>
      </form>
    </div>
    <div class="card mt-4">
      <h2>Test a server</h2>
      <p class="small muted measure">Connects from the API node that answers this page and checks the server's
        certificate against the store as it is now. When it fails it names the cause: untrusted issuer, wrong host
        name, expired, or self-signed. Each test is recorded in the audit trail.</p>
      <form id="ts-probe" class="row mt-3">
        <input name="host" placeholder="Host name or IP address" required maxlength="253" aria-label="Host">
        <input name="port" type="number" min="1" max="65535" value="443" required aria-label="Port">
        <button class="btn" type="submit">Test</button>
      </form>
      <div id="ts-probe-out"></div>
    </div>`;

  $('#ts-import', body).onsubmit = async e => {
    e.preventDefault();
    const f = e.target;
    const file = f.file.files[0];
    let pem = f.pem.value.trim();
    if (file && pem) return err('Choose a file or paste PEM, not both.');
    if (file) pem = await certFileText(file);
    if (!pem) return err('Choose a certificate file or paste PEM.');
    try {
      const r = await post('/admin/trust-store', { pem, name: f.name.value.trim() || null, note: f.note.value.trim() || null });
      const parts = [];
      if (r.imported.length) parts.push(`Imported ${r.imported.map(i => i.name).join(', ')}`);
      if (r.updated.length) parts.push(`updated ${r.updated.map(i => i.name).join(', ')}`);
      if (r.rejected.length) parts.push(`skipped ${r.rejected.map(i => i.name).join(', ')} (not a CA)`);
      ok(parts.join('; ') + '.');
      adminTrustStore(body);
    } catch (ex) { err(ex.detail || ex.message); }
  };

  $('#ts-probe', body).onsubmit = async e => {
    e.preventDefault();
    const out = $('#ts-probe-out', body);
    out.innerHTML = '<div class="loading">Testing…</div>';
    try {
      const r = await post('/admin/trust-store/probe', { host: e.target.host.value.trim(), port: Number(e.target.port.value) });
      const l = r.leaf || {};
      out.innerHTML = `<dl class="kv mt-3">
          <dt>Result</dt><dd><span class="pill ${r.verified ? 'st-succeeded' : 'st-failed'}">${r.verified ? 'Verifies' : 'Does not verify'}</span> ${esc(r.reason)}</dd>
          <dt>What to do</dt><dd>${esc(r.advice)}</dd>
          ${r.leaf ? `<dt>Subject</dt><dd class="mono small">${esc(l.subject)}</dd>
          <dt>Issuer</dt><dd class="mono small">${esc(l.issuer)}</dd>
          <dt>Names covered</dt><dd class="mono small">${esc((l.sans || []).join(', ') || l.common_name || '—')}</dd>
          <dt>Valid until</dt><dd>${fmtDate(l.not_after)}</dd>
          <dt>Protocol</dt><dd class="mono small">${esc(l.protocol || '')} ${esc(l.cipher || '')}</dd>` : ''}
        </dl>`;
    } catch (ex) { out.innerHTML = ''; err(ex.detail || ex.message); }
  };

  body.onclick = async e => {
    const b = e.target.closest('button');
    if (!b) return;
    if (b.dataset.view) {
      try {
        const c = await get('/admin/trust-store/' + encodeURIComponent(b.dataset.view));
        const x = c.content || {};
        await modal({ title: c.name, wide: true, dismiss: 'Close', actions: [], body: `
          <dl class="kv">
            <dt>Subject</dt><dd class="mono small">${esc(x.subject)}</dd>
            <dt>Issuer</dt><dd class="mono small">${esc(x.issuer)}</dd>
            <dt>Valid</dt><dd>${fmtDate(x.not_before)} → ${fmtDate(x.not_after)}</dd>
            <dt>Public key</dt><dd>${esc(x.public_key)} · ${esc(x.signature_algorithm)}</dd>
            <dt>Serial</dt><dd class="mono small">${esc(x.serial)}</dd>
            <dt>SHA-256</dt><dd class="mono small">${esc(x.sha256)}</dd>
            ${(x.extensions || []).map(ex => `<dt>${esc(ex.name)}${ex.critical ? ' (critical)' : ''}</dt><dd class="mono small">${esc(ex.value || '—')}</dd>`).join('')}
            <dt>Added</dt><dd>${fmtDate(c.created_at)}${c.added_by ? ' by ' + esc(c.added_by) : ''}</dd>
          </dl>
          <pre class="mono small pre-wrap mt-3">${esc(x.pem)}</pre>` });
      } catch (ex) { err(ex.detail || ex.message); }
    } else if (b.dataset.toggle) {
      try {
        await patch('/admin/trust-store/' + encodeURIComponent(b.dataset.toggle), { is_enabled: b.dataset.on !== '1' });
        ok(b.dataset.on === '1' ? 'Disabled: no client trusts it any more.' : 'Enabled.');
        adminTrustStore(body);
      } catch (ex) { err(ex.detail || ex.message); }
    } else if (b.dataset.del) {
      const r = await modal({ title: 'Remove ' + b.dataset.name + '?', actions: [{ label: 'Remove', cls: 'btn-danger' }],
        body: `<p>Servers signed by this CA stop verifying on every connector. Disable keeps the record; Remove deletes it.
          The removal is recorded in the audit trail.</p>` });
      if (!r) return;
      try { await del('/admin/trust-store/' + encodeURIComponent(b.dataset.del)); ok('Removed.'); adminTrustStore(body); }
      catch (ex) { err(ex.detail || ex.message); }
    }
  };
}

/* ── Administration → Network access ──────────────────────────────────
   Every destination VEYRS contacts, when, why, and what to do on a host that
   cannot reach it -- the page a firewall team asks for before go-live. The
   fixed list comes from services/network_requirements.py (a test keeps it in
   step with the code); below it, what THIS installation's settings and THIS
   organization's connectors add. Platform administrators only; read-only. */
async function adminNetworkAccess(body) {
  let net;
  try { net = await get('/admin/system/network'); }
  catch (e) {
    body.innerHTML = `<div class="card"><h2>Network access</h2><p class="muted">${e.status === 403
      ? 'Only a platform administrator can see the network requirements: they name the internal hosts this installation depends on.' + PLATFORM_HINT
      : 'Could not read the network requirements: ' + esc(e.detail || e.message)}</p></div>`;
    return;
  }
  const need = { required: ['st-failed', 'required'], recommended: ['st-warn', 'recommended'], optional: ['st-neutral', 'optional'] };
  const needPill = k => { const [c, l] = need[k] || ['st-neutral', k]; return `<span class="pill ${c}">${esc(l)}</span>`; };
  const dests = net.destinations || [];
  const hostCell = d => d.hosts.map(h => /\s/.test(h) ? `<em>${esc(h)}</em>` : `<span class="mono">${esc(h)}</span>`).join('<br>')
    + `<div class="small muted">${esc(d.protocol)} ${esc(String(d.port))}</div>`;
  const runtime = dests.filter(d => ['intelligence', 'updates', 'ai'].includes(d.group) && !d.disabled);
  const allow = [...new Set(runtime.flatMap(d => d.hosts.filter(h => !/\s/.test(h)).map(h => `${h}:${d.port}`)))];
  const groupCard = g => {
    const rows = dests.filter(d => d.group === g.key);
    if (!rows.length) return '';
    return `<div class="card mt-4"><h2>${esc(g.label)}</h2>${table([
      { label: 'Destination', cell: hostCell },
      { label: 'What for', cell: d => `<span class="small">${esc(d.purpose)}</span><div class="small muted">${esc(d.used_by)}</div>${d.note ? `<div class="small muted">${esc(d.note)}</div>` : ''}` },
      { label: 'Need', cell: d => needPill(d.need) + (d.disabled ? ' <span class="pill st-neutral" title="Switched off by this installation\'s settings">off here</span>' : '') + (d.moved ? ' <span class="pill st-neutral" title="Pointed at a mirror by a setting">mirror</span>' : '') },
      { label: 'Setting', cell: d => d.setting ? `<span class="mono small">${esc(d.setting)}</span>` : '<span class="muted small">—</span>' },
      { label: 'Without it', cell: d => `<span class="small">${esc(d.offline)}</span>` },
    ], rows)}</div>`;
  };
  body.innerHTML = `
    <div class="card">
      <h2 class="mt-0">Network access</h2>
      <p class="small muted measure">Every destination VEYRS contacts, when, and what to do on a host that cannot
        reach it. All internet destinations are outbound HTTPS. ${esc(net.browser)} ${esc(net.inbound)}</p>
      <p class="small mt-2">Run-time internet allowlist for this installation (feeds, update check, enabled external AI):</p>
      <pre class="mono small">${allow.length ? esc(allow.join('\n')) : '(none: every run-time internet destination is switched off)'}</pre>
      <p class="small muted">Install-time destinations are listed separately below: they are needed while installing or
        updating, not while running, and the offline bundle replaces all of them.</p>
    </div>
    ${(net.groups || []).map(groupCard).join('')}
    <div class="card mt-4">
      <h2>This installation's own services</h2>
      <p class="small muted">From the settings in <span class="mono">.env</span>; usually inside your network.</p>
      ${table([
        { label: 'Service', cell: r => `<strong>${esc(r.name)}</strong>` },
        { label: 'Host', cell: r => `<span class="mono">${esc(r.host)}${r.port ? ':' + esc(String(r.port)) : ''}</span>` },
        { label: 'What for', cell: r => `<span class="small">${esc(r.purpose)}</span>` },
        { label: 'Need', cell: r => needPill(r.need) },
        { label: 'Setting', cell: r => `<span class="mono small">${esc(r.setting)}</span>` },
      ], net.platform || [], { emptyTitle: 'Nothing configured' })}
    </div>
    <div class="card mt-4">
      <h2>Configured in this organization</h2>
      <p class="small muted">Enabled connectors only: a disabled connector contacts nothing.</p>
      ${table([
        { label: 'Kind', cell: r => esc(r.kind) },
        { label: 'Name', cell: r => `${esc(r.name)} <span class="small muted mono">${esc(r.driver)}</span>` },
        { label: 'Host', cell: r => r.host ? `<span class="mono">${esc(r.host)}${r.port ? ':' + esc(String(r.port)) : ''}</span>` : '<span class="pill st-warn">no URL set</span>' },
        { label: 'What for', cell: r => `<span class="small">${esc(r.purpose)}</span>` },
      ], net.configured || [], { emptyTitle: 'No enabled connectors', emptyHint: 'Ticketing, scanners, asset sources, AI providers and the directory appear here once enabled.' })}
    </div>`;
}

/* ── My account: two-factor sign-in and password ───────────────────────
   Three methods: an authenticator app (the code is computed on the phone),
   a code by e-mail, or a code from a Telegram bot. Enrolling never turns the
   second factor on by itself: the person types back a code first, which is
   the only proof that the app works or the message actually arrived. The
   recovery codes are shown once, at activation. */
const MFA_LABEL = { totp: 'Authenticator app', email: 'E-mail code', telegram: 'Telegram code' };

/* Administration → Organization: the organization-wide two-factor policy
   (0.41.0, PUT /mfa-policy). Never a lock-out: an account without a factor
   proves its password and lands on the enrolment screen (enrolmentScreen). */
async function mfaPolicyCard(card) {
  let st;
  try { st = await get('/mfa-policy'); }
  catch (e) { card.innerHTML = `<h2 class="mt-0">Two-factor policy</h2><p class="muted">${esc(e.detail || e.message)}</p>`; return; }
  const n = st.users_without_mfa || 0;
  card.innerHTML = `
    <div class="row row-split">
      <div><h2 class="mt-0">Two-factor policy</h2>
        <p class="small muted measure">Require a second factor for every account of this organization,
          administrators included. Accounts without one are taken to the set-up screen right after their
          password; nobody is locked out.</p></div>
      <span class="pill ${st.require_mfa ? 'st-ok' : 'st-warn'}">${st.require_mfa ? 'Required' : 'Optional'}</span>
    </div>
    <p class="small">${n === 0 ? 'Every active account already has a second factor.'
      : `${n} active account${n === 1 ? '' : 's'} ${n === 1 ? 'has' : 'have'} no second factor yet${st.require_mfa ? ' and will be asked to set one up at the next sign-in' : ''}.`}</p>
    <button class="btn btn-sm ${st.require_mfa ? '' : 'btn-primary'}" id="mfa-policy-toggle">
      ${st.require_mfa ? 'Stop requiring two-factor' : 'Require two-factor sign-in'}</button>`;
  $('#mfa-policy-toggle', card).onclick = async () => {
    try {
      await put('/mfa-policy', { require_mfa: !st.require_mfa });
      ok(st.require_mfa ? 'Two-factor sign-in is optional again.' : 'Two-factor sign-in is now required.');
      mfaPolicyCard(card);
    } catch (e) { err(e.detail); }
  };
}

/* The organization requires a second factor and this account has none: the
   sign-in returned an enrolment-only token (no refresh token, every other
   route answers 403 mfa_enrollment_required). Show only the set-up card; the
   activation answer carries the full token pair. Survives a reload through
   `veyrs.enroll`. */
function enrolmentScreen() {
  localStorage.setItem('veyrs.enroll', '1');
  $('#shell').hidden = true;
  $('#login').hidden = false;
  const panel = $('.login-panel');
  $('#login-form').hidden = true;
  let card = $('#enrol-card');
  if (!card) {
    card = document.createElement('div');
    card.id = 'enrol-card';
    card.className = 'card enrol-card';
    panel.insertBefore(card, panel.firstChild);
  }
  card.hidden = false;
  const intro = document.createElement('p');
  intro.className = 'small';
  intro.textContent = 'Your organization requires two-factor sign-in. Set it up now to continue.';
  renderMfaCard(card).then(() => card.insertBefore(intro, card.firstChild));
}

async function finishEnrolment(tokens) {
  store.save(tokens);
  localStorage.removeItem('veyrs.enroll');
  const card = $('#enrol-card');
  if (card) card.hidden = true;
  $('#login-form').hidden = false;
  await enterApp(await get('/auth/me'));
}

function showRecoveryCodes(card, codes, onDone) {
  const text = '# VEYRS recovery codes -- each works once. Keep them offline.\n' + codes.join('\n') + '\n';
  card.innerHTML = `
    <h2 class="mt-0">Save your recovery codes</h2>
    <p class="small measure">If you lose your phone, your mailbox or your Telegram account, each of these
      codes signs you in <strong>once</strong>, typed where the six-digit code goes. They are shown only now.</p>
    <pre class="mono" style="columns:2;max-width:420px">${codes.map(esc).join('\n')}</pre>
    <div class="row gap-2 mt-2">
      <button class="btn btn-sm" id="rc-dl">Download as .txt</button>
      <button class="btn btn-sm btn-primary" id="rc-done">I have saved them</button>
    </div>`;
  $('#rc-dl', card).onclick = () => {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
    a.download = 'veyrs-recovery-codes.txt';
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  };
  $('#rc-done', card).onclick = () => (onDone ? onDone() : renderMfaCard(card));
}

async function renderMfaCard(card) {
  let st;
  try { st = await get('/auth/mfa'); }
  catch (e) { card.innerHTML = `<h2>Two-factor sign-in</h2><p class="muted">${esc(e.detail || e.message)}</p>`; return; }
  const av = st.available || {};
  if (st.enabled) {
    const delivered = st.method === 'email' || st.method === 'telegram';
    card.innerHTML = `
      <div class="row row-split">
        <div><h2 class="mt-0">Two-factor sign-in</h2>
          <p class="small muted measure">After your password, VEYRS asks for a second code.</p></div>
        <span class="pill st-succeeded">On</span>
      </div>
      <dl class="kv mt-2">
        <dt>Method</dt><dd>${esc(MFA_LABEL[st.method] || st.method)}</dd>
        ${st.destination ? `<dt>Codes go to</dt><dd class="mono">${esc(st.destination)}</dd>` : ''}
        <dt>Recovery codes left</dt><dd>${fmtNum(st.recovery_codes_left)}${st.recovery_codes_left < 3 ? ' <span class="pill st-warn">replace them soon</span>' : ''}</dd>
      </dl>
      <div class="row gap-2 mt-3">
        ${delivered ? '<button class="btn btn-sm" id="mfa-send">Send me a code</button>' : ''}
        <button class="btn btn-sm" id="mfa-rc">New recovery codes…</button>
        <button class="btn btn-sm btn-danger" id="mfa-off">Turn off…</button>
      </div>`;
    const ask = (title, label) => modal({
      title,
      body: `<div><label>Password *</label><input name="password" type="password" autocomplete="current-password" required></div>
             <div><label>${esc(delivered ? 'Code we sent you, or a recovery code' : 'Code from your app, or a recovery code')} *</label>
               <input name="code" autocomplete="one-time-code" spellcheck="false" required></div>`,
      actions: [{ label, cls: label.startsWith('Turn') ? 'btn-danger' : 'btn-primary' }],
    });
    const send = $('#mfa-send', card);
    if (send) send.onclick = async () => {
      try { const r = await post('/auth/mfa/send-code');
        ok(r.throttled ? `A code was sent moments ago to ${r.sent_to}; it is still valid.` : `Code sent to ${r.sent_to}.`);
      } catch (e) { err(e.detail); }
    };
    $('#mfa-rc', card).onclick = async () => {
      const f = await ask('Replace recovery codes', 'Replace');
      if (!f) return;
      try { const r = await post('/auth/mfa/recovery-codes', f); showRecoveryCodes(card, r.recovery_codes); }
      catch (e) { err(e.detail); }
    };
    $('#mfa-off', card).onclick = async () => {
      const f = await ask('Turn off two-factor sign-in', 'Turn off');
      if (!f) return;
      try { await post('/auth/mfa/disable', f); ok('Two-factor sign-in is off.'); renderMfaCard(card); }
      catch (e) { err(e.detail); }
    };
    return;
  }

  const opt = (m, hint) => `<label class="row" style="gap:8px;align-items:flex-start;margin:6px 0;${av[m] ? '' : 'opacity:.55'}">
      <input type="radio" name="mfa-m" value="${m}" ${av[m] ? '' : 'disabled'} style="margin-top:4px">
      <span><strong>${MFA_LABEL[m]}</strong><br><span class="small muted">${hint}</span></span></label>`;
  card.innerHTML = `
    <div class="row row-split">
      <div><h2 class="mt-0">Two-factor sign-in</h2>
        <p class="small muted measure">A second code after your password. Choose how you receive it;
          nothing changes until you type back a code, so a wrong choice cannot lock you out.</p></div>
      <span class="pill st-warn">Off</span>
    </div>
    ${st.local_password ? '' : '<p class="small">Your account signs in through the directory; two-factor here protects the VEYRS session only.</p>'}
    <div class="mt-2">
      ${opt('totp', 'Google Authenticator, Microsoft Authenticator, 1Password, Aegis… Works offline.')}
      ${opt('email', av.email ? 'A code to your account e-mail address.' : 'Not available: this installation has no mail relay (VEYRS_SMTP_HOST).')}
      ${opt('telegram', av.telegram ? `A code from the Telegram bot${st.telegram_bot ? ' <span class="mono">@' + esc(st.telegram_bot) + '</span>' : ''}.` : 'Not available: no Telegram bot is configured (VEYRS_TELEGRAM_BOT_TOKEN).')}
    </div>
    <div id="mfa-tg" hidden style="margin-top:8px;max-width:520px">
      <label>Your Telegram chat id *</label><input id="mfa-chat" inputmode="numeric" placeholder="123456789">
      <p class="small muted">First open ${st.telegram_bot ? '<span class="mono">@' + esc(st.telegram_bot) + '</span>' : 'the VEYRS bot'} in Telegram and press
        <strong>Start</strong> (a bot cannot write to you before that). Your chat id is the number
        <span class="mono">@userinfobot</span> replies with.</p>
    </div>
    <div class="row mt-3"><button class="btn btn-sm btn-primary" id="mfa-start" disabled>Continue</button></div>
    <div id="mfa-step"></div>`;
  let method = null;
  $$('input[name="mfa-m"]', card).forEach(r => { r.onchange = () => {
    method = r.value; $('#mfa-start', card).disabled = false; $('#mfa-tg', card).hidden = method !== 'telegram';
  }; });
  $('#mfa-start', card).onclick = async () => {
    const body = { method };
    if (method === 'telegram') body.telegram_chat_id = $('#mfa-chat', card).value.trim();
    let r;
    try { r = await post('/auth/mfa/enroll', body); } catch (e) { err(e.detail); return; }
    const step = $('#mfa-step', card);
    step.innerHTML = `<div style="margin-top:14px;max-width:560px">
        ${method === 'totp' ? `
          <p class="small">Scan this with your authenticator app, or type the key by hand.</p>
          ${r.qr_svg ? `<div style="background:#fff;display:inline-block;padding:6px;border-radius:8px">${r.qr_svg}</div>` : ''}
          <p class="small">Key: <span class="mono">${esc((r.secret || '').replace(/(.{4})/g, '$1 ').trim())}</span></p>`
        : `<p class="small">${r.throttled ? 'A code was sent moments ago to' : 'We sent a code to'} <span class="mono">${esc(r.sent_to || '')}</span>.
             It expires in ${Math.round((r.expires_in || 300) / 60)} minutes.</p>`}
        <label>Code *</label><input id="mfa-code" autocomplete="one-time-code" inputmode="numeric" maxlength="6">
        <div class="row gap-2 mt-2">
          <button class="btn btn-sm btn-primary" id="mfa-act">Turn on</button>
          ${method === 'totp' ? '' : '<button class="btn btn-sm" id="mfa-resend">Send another code</button>'}
        </div></div>`;
    const resend = $('#mfa-resend', step);
    if (resend) resend.onclick = async () => {
      try { const x = await post('/auth/mfa/send-code'); ok(x.throttled ? 'The last code is still valid; wait a few seconds for a new one.' : `Code sent to ${x.sent_to}.`); }
      catch (e) { err(e.detail); }
    };
    $('#mfa-act', step).onclick = async () => {
      try {
        const a = await post('/auth/mfa/activate', { code: $('#mfa-code', step).value.trim() });
        ok('Two-factor sign-in is on.');
        // After a policy-forced enrolment the answer carries the full token
        // pair (0.41.0): the enrolment-only token cannot open anything else.
        showRecoveryCodes(card, a.recovery_codes, a.tokens ? () => finishEnrolment(a.tokens) : null);
      } catch (e) { err(e.status === 422 ? 'That code is not right, or it expired.' : e.detail); }
    };
  };
}

route('account', async view => {
  view.innerHTML = `
    <div class="page-head"><div><h1>My account</h1>
      <p>How you sign in. Changes here apply to your account only.</p></div></div>
    <div class="card" id="mfa-card"><div class="loading">Loading…</div></div>
    <div class="card mt-4" id="pw-card">
      <h2 class="mt-0">Password</h2>
      <p class="small muted">At least 12 characters. Changing it signs you out everywhere, here included.</p>
      <form id="pw-form" style="max-width:420px">
        <label>Current password *</label><input name="current_password" type="password" autocomplete="current-password" required>
        <label>New password *</label><input name="new_password" type="password" autocomplete="new-password" minlength="12" required>
        <label>Repeat the new password *</label><input name="again" type="password" autocomplete="new-password" minlength="12" required>
        <button class="btn btn-sm btn-primary mt-2">Change password</button>
      </form>
    </div>`;
  renderMfaCard($('#mfa-card'));
  $('#pw-form').onsubmit = async e => {
    e.preventDefault();
    const f = Object.fromEntries(new FormData(e.target));
    if (f.new_password !== f.again) { err('The two new passwords differ.'); return; }
    try {
      await post('/auth/password', { current_password: f.current_password, new_password: f.new_password });
      ok('Password changed. Sign in again with the new one.');
      setTimeout(logout, 1200);
    } catch (ex) { err(ex.status === 401 ? 'The current password is not right.' : ex.detail); }
  };
});

/* ── Administration → RADIUS ───────────────────────────────────────────
   Sign-in through the organization's RADIUS server (FortiAuthenticator, NPS,
   Duo proxy, FreeRADIUS...) with ITS second factor: when the server answers
   Access-Challenge, the console shows the server's own message and sends the
   code back. Message-Authenticator is required on every answer and cannot be
   switched off (Blast-RADIUS). The shared secret is write-only. */
async function adminRadius(body) {
  let st;
  try { st = await get('/radius'); }
  catch (e) { body.innerHTML = `<div class="card"><h2>RADIUS</h2><p class="muted">${esc(e.detail || e.message)}</p></div>`; return; }
  const map = Object.entries(st.value_role_map || {}).map(([k, v]) => `${k}=${v}`).join('\n');
  body.innerHTML = `
    <div class="card">
      <div class="row row-split">
        <div><h2 class="mt-0">RADIUS sign-in</h2>
          <p class="small muted measure">People sign in with the password and the second factor of your
            RADIUS server — the same ones as the VPN. When the server asks for a code (Access-Challenge), VEYRS shows its
            message and sends the code back; that is the second factor, so VEYRS does not ask for its own. Accounts must
            exist here first (their username or e-mail is the RADIUS User-Name). Platform administrators always use their
            local password. Register VEYRS on the server as a RADIUS client with the address of every app node.</p></div>
        <span class="pill ${st.enabled ? 'st-succeeded' : 'st-neutral'}">${st.enabled ? 'On' : 'Off'}</span>
      </div>
      <form id="rad-form" style="max-width:640px;margin-top:10px">
        <label>Servers (host or host:port, one per line, tried in order on timeout) *</label>
        <textarea name="servers" rows="3" spellcheck="false">${esc((st.servers || []).join('\n'))}</textarea>
        <label>Shared secret ${st.secret_set ? '<span class="small muted">(stored — leave empty to keep it)</span>' : '*'}</label>
        <input name="secret" type="password" autocomplete="new-password" placeholder="${st.secret_set ? '••••••••' : 'at least 16 characters'}">
        <div class="row gap-3">
          <div><label>Timeout (s)</label><input name="timeout_seconds" type="number" min="1" max="120" value="${esc(String(st.timeout_seconds))}"></div>
          <div><label>Retries</label><input name="retries" type="number" min="0" max="3" value="${esc(String(st.retries))}"></div>
          <div><label>NAS-Identifier</label><input name="nas_identifier" value="${esc(st.nas_identifier || 'veyrs')}"></div>
        </div>
        <p class="small muted">Push approval (FortiToken Mobile, Duo push) holds the answer until the person approves: use 60 s.</p>
        <label>Role from the reply attribute</label>
        <select name="role_attribute">${['', 'Class', 'Filter-Id'].map(a => `<option value="${a}" ${st.role_attribute === a ? 'selected' : ''}>${a || '— roles are managed in VEYRS —'}</option>`).join('')}</select>
        <label>Value → role slug (one per line, e.g. <span class="mono">veyrs-admins=org-admin</span>)</label>
        <textarea name="value_role_map" rows="3" spellcheck="false">${esc(map)}</textarea>
        <dl class="kv mt-2"><dt>Message-Authenticator</dt><dd>${esc(st.message_authenticator)} — answers without it are discarded (CVE-2024-3596)</dd></dl>
        <div class="row gap-2 mt-2">
          <button class="btn btn-sm btn-primary" data-save="1">Save</button>
          <button class="btn btn-sm" data-save="toggle">${st.enabled ? 'Turn off' : 'Save and turn on'}</button>
        </div>
      </form>
    </div>
    <div class="card mt-4">
      <h2>Test with a test account</h2>
      <p class="small muted measure">A real exchange with the SAVED settings. RADIUS has no lookup, so the test
        needs a password: use a dedicated test account, never a colleague's. Nothing is stored or logged but the user name.</p>
      <form id="rad-test" style="max-width:420px">
        <label>User name</label><input name="user_name" autocomplete="off" spellcheck="false" required>
        <label>Password</label><input name="password" type="password" autocomplete="off" required>
        <label>Code <span class="small muted">(only after the server asked for one)</span></label><input name="code" autocomplete="off">
        <button class="btn btn-sm mt-2">Run the test</button>
      </form>
      <div id="rad-result" class="mt-2"></div>
    </div>`;
  const form = $('#rad-form', body);
  const read = () => {
    const f = Object.fromEntries(new FormData(form));
    const out = {
      servers: f.servers.split('\n').map(s => s.trim()).filter(Boolean),
      timeout_seconds: Number(f.timeout_seconds), retries: Number(f.retries),
      nas_identifier: f.nas_identifier.trim(), role_attribute: f.role_attribute,
      value_role_map: Object.fromEntries(f.value_role_map.split('\n').map(l => l.split('=').map(x => x.trim())).filter(p => p.length === 2 && p[0] && p[1])),
    };
    if (f.secret) out.secret = f.secret;
    return out;
  };
  form.onclick = async e => {
    const which = e.target.dataset.save;
    if (!which) return;
    e.preventDefault();
    const payload = read();
    if (which === 'toggle') payload.enabled = !st.enabled;
    try { await put('/radius', payload); ok('RADIUS settings saved.'); adminRadius(body); }
    catch (ex) { err(ex.detail); }
  };
  $('#rad-test', body).onsubmit = async e => {
    e.preventDefault();
    const f = Object.fromEntries(new FormData(e.target));
    const out = $('#rad-result', body);
    out.innerHTML = '<p class="small muted">Asking the server…</p>';
    try {
      const r = await post('/radius/test', { user_name: f.user_name, password: f.password, code: f.code || null });
      out.innerHTML = (r.challenge ? `<p class="small"><strong>The server asks:</strong> ${esc(r.message || 'a code')}. Type it in Code and run the test again.</p>` : '')
        + table([
          { label: 'Step', cell: s => esc(s.step) },
          { label: 'Result', cell: s => s.ok ? '<span class="pill st-succeeded">ok</span>' : '<span class="pill st-failed">failed</span>' },
          { label: 'Detail', cell: s => `<span class="small">${esc(s.detail)}</span>` },
        ], r.steps || []);
    } catch (ex) { out.innerHTML = ''; err(ex.detail); }
  };
}

/* ── Administration → Single sign-on (OIDC) ────────────────────────────
   Any OpenID Connect provider (Authentik, Entra ID, Okta, Keycloak...). Off
   until configured here; the client secret is write-only. The redirect URI to
   register at the provider is this console's own address. */
async function adminSso(body) {
  let st;
  try { st = await get('/oidc'); }
  catch (e) { body.innerHTML = `<div class="card"><h2>Single sign-on</h2><p class="muted">${esc(e.detail || e.message)}</p></div>`; return; }
  const suggested = location.origin + '/api/v1/auth/oidc/callback';
  const map = Object.entries(st.group_role_map || {}).map(([k, v]) => `${k}=${v}`).join('\n');
  body.innerHTML = `
    <div class="card">
      <div class="row row-split">
        <div><h2 class="mt-0">Single sign-on (OpenID Connect)</h2>
          <p class="small muted measure">People sign in at your identity provider — Authentik, Entra ID,
            Okta, Keycloak — with its password, second factor and policies, and come back signed in. Create a confidential
            OIDC client there with the redirect URI below. Accounts are matched by e-mail; platform administrators always
            use their local password. Nothing changes until you turn it on.</p></div>
        <span class="pill ${st.enabled ? 'st-succeeded' : 'st-neutral'}">${st.enabled ? 'On' : 'Off'}</span>
      </div>
      <form id="sso-form" style="max-width:680px;margin-top:10px">
        <label>Issuer URL *</label>
        <input name="issuer" spellcheck="false" placeholder="https://auth.example.com/application/o/veyrs/" value="${esc(st.issuer || '')}">
        <label>Client ID *</label><input name="client_id" spellcheck="false" value="${esc(st.client_id || '')}">
        <label>Client secret ${st.client_secret_set ? '<span class="small muted">(stored — leave empty to keep it)</span>' : '*'}</label>
        <input name="client_secret" type="password" autocomplete="new-password">
        <label>Redirect URI (register exactly this at the provider) *</label>
        <input name="redirect_uri" spellcheck="false" value="${esc(st.redirect_uri || suggested)}">
        <label>Scopes</label><input name="scopes" value="${esc(st.scopes || 'openid email profile')}">
        <div class="row gap-3">
          <div><label>E-mail claim</label><input name="email_claim" value="${esc(st.email_claim || 'email')}"></div>
          <div><label>Groups claim</label><input name="groups_claim" value="${esc(st.groups_claim || 'groups')}"></div>
          <div><label>Button label</label><input name="button_label" value="${esc(st.button_label || 'Sign in with SSO')}"></div>
        </div>
        <label>Group → role slug (one per line, e.g. <span class="mono">veyrs-admins=org-admin</span>; empty = roles are managed in VEYRS)</label>
        <textarea name="group_role_map" rows="3" spellcheck="false">${esc(map)}</textarea>
        <label class="row" style="gap:8px;margin-top:8px"><input type="checkbox" name="jit_provisioning" ${st.jit_provisioning ? 'checked' : ''}>
          Create the account on first sign-in (off: the account must exist here)</label>
        <label class="row" style="gap:8px"><input type="checkbox" name="require_mfa_amr" ${st.require_mfa_amr ? 'checked' : ''}>
          Refuse a sign-in the provider does not report as multi-factor (<span class="mono">amr</span> claim)</label>
        <div class="row gap-2 mt-3">
          <button class="btn btn-sm btn-primary" data-save="1">Save</button>
          <button class="btn btn-sm" data-save="toggle">${st.enabled ? 'Turn off' : 'Save and turn on'}</button>
          <button class="btn btn-sm" data-save="test">Check the provider</button>
        </div>
      </form>
      <div id="sso-result" class="mt-2"></div>
    </div>`;
  const form = $('#sso-form', body);
  const read = () => {
    const f = Object.fromEntries(new FormData(form));
    const out = {
      issuer: f.issuer.trim(), client_id: f.client_id.trim(), redirect_uri: f.redirect_uri.trim(),
      scopes: f.scopes.trim(), email_claim: f.email_claim.trim(), groups_claim: f.groups_claim.trim(),
      button_label: f.button_label.trim(), jit_provisioning: !!f.jit_provisioning, require_mfa_amr: !!f.require_mfa_amr,
      group_role_map: Object.fromEntries(f.group_role_map.split('\n').map(l => l.split('=').map(x => x.trim())).filter(p => p.length === 2 && p[0] && p[1])),
    };
    if (f.client_secret) out.client_secret = f.client_secret;
    return out;
  };
  form.onclick = async e => {
    const which = e.target.dataset.save;
    if (!which) return;
    e.preventDefault();
    if (which === 'test') {
      const out = $('#sso-result', body);
      out.innerHTML = '<p class="small muted">Asking the provider…</p>';
      try {
        const r = await post('/oidc/test');
        out.innerHTML = table([
          { label: 'Step', cell: s => esc(s.step) },
          { label: 'Result', cell: s => s.ok ? '<span class="pill st-succeeded">ok</span>' : '<span class="pill st-failed">failed</span>' },
          { label: 'Detail', cell: s => `<span class="small">${esc(s.detail)}</span>` },
        ], r.steps || []);
      } catch (ex) { out.innerHTML = ''; err(ex.detail); }
      return;
    }
    const payload = read();
    if (which === 'toggle') payload.enabled = !st.enabled;
    try { await put('/oidc', payload); ok('Single sign-on settings saved.'); adminSso(body); }
    catch (ex) { err(ex.detail); }
  };
}

/* Back from the identity provider: #/sso?h=<one-time handoff> or ?error=... */
async function ssoLanding() {
  const params = new URLSearchParams(location.hash.split('?')[1] || '');
  history.replaceState(null, '', location.pathname);            // the handoff never stays in the address bar
  if (params.get('error')) {
    $('#login').hidden = false;
    const box = $('#login-error'); box.textContent = 'Single sign-on: ' + params.get('error'); box.hidden = false;
    return true;
  }
  if (!params.get('h')) return false;
  try {
    const tok = await api('/auth/oidc/exchange', { method: 'POST', body: JSON.stringify({ handoff: params.get('h') }) });
    store.save(tok, $('#l-org').value.trim() || store.org);
    await enterApp(await get('/auth/me'));
  } catch (ex) {
    $('#login').hidden = false;
    const box = $('#login-error'); box.textContent = 'Single sign-on failed: ' + (ex.detail || 'try again'); box.hidden = false;
  }
  return true;
}

async function ssoButton() {
  try {
    const r = await api('/auth/sso');
    if (!r || !r.available) return;
    $('#sso-btn').hidden = false;
    $('#sso-btn').onclick = async () => {
      const org = $('#l-org').value.trim();
      const box = $('#login-error');
      if (!org) { box.textContent = 'Type your organization first.'; box.hidden = false; return; }
      try {
        const s = await api('/auth/oidc/' + encodeURIComponent(org) + '/start');
        localStorage.setItem('veyrs.org', org);
        location.href = s.authorization_url;
      } catch (ex) { box.textContent = ex.detail || 'Single sign-on is not available for this organization.'; box.hidden = false; }
    };
  } catch { /* SSO is optional: no button */ }
}

/* Eighteen tabs in one row wrapped onto three lines and read as one list.
   They are three questions: who gets in, what flows in, how it runs. The
   sidebar uses the same three labels (`sec:` in NAV). */
const ADMIN_SECTIONS = [
  ['Access',      ['users', 'teams', 'roles', 'departments', 'apikeys', 'directory', 'radius', 'sso']],
  ['Data intake', ['ticketing', 'sources', 'teamimport', 'scanning']],
  ['Platform',    ['riskregister', 'secrets', 'org', 'software', 'network', 'truststore', 'webcert', 'updates']],
];
const adminSection = tab => (ADMIN_SECTIONS.find(([, keys]) => keys.includes(tab)) || ADMIN_SECTIONS[0])[1];

/* Each Administration tab is a page of its own in the Configure menu
   (0.42.0), so the head names it and says what it is for. */
const ADMIN_BLURB = {
  users: 'Accounts that can sign in, how each one is authenticated, and what it can see.',
  teams: 'Groups that own assets and receive the findings and tickets assigned to them.',
  roles: 'Named sets of permissions. Every endpoint checks them on the server; the console only reflects them.',
  departments: 'The departments of this organization.',
  apikeys: 'Credentials for scripts and integrations, each with its own scopes and expiry.',
  directory: 'LDAP / Active Directory sign-in and group mapping.',
  radius: 'Sign-in through your RADIUS server, with its password and second factor (FortiToken, Duo and the like).',
  sso: 'OpenID Connect providers users can sign in with.',
  ticketing: 'Whether tickets live in VEYRS or in your ITSM, and how the two stay in step.',
  sources: 'Other inventories (CMDB, NetBox, virtualisation) VEYRS reads assets from on a schedule.',
  teamimport: 'Create teams from another system of record, such as NetBox.',
  scanning: 'The switch that decides whether VEYRS may probe anything itself, or only ingest results.',
  riskregister: 'Turn the risk register on or off for this organization.',
  secrets: 'Where the credentials VEYRS uses are stored: sealed in its database or in an external vault.',
  org: 'Name and default language of this organization, and its sign-in policy.',
  software: 'What the node that answered runs: component versions, and Python packages compared with the lock.',
  network: 'The hosts this installation must reach, and what each one is for.',
  truststore: 'Private certificate authorities VEYRS trusts when it connects out to your systems.',
  webcert: 'The certificate VEYRS presents to browsers on HTTPS: request one here and have it signed, or upload one with its key.',
  updates: 'The installed version, signed releases, and applying one through the root updater.',
};
function adminTabLabel(tab) {
  const it = (configureGroup() || { items: [] }).items.find(i => i.path === 'admin');
  const kids = (it && it.children) || [];
  const c = kids.find(k => k.q && k.q.tab === tab) || (!tab && kids.find(k => k.def));
  return c ? c.label : '';
}

route('admin', async (view, _p, params) => {
  const tab = params.get('tab') || 'users';
  view.innerHTML = `
    <div class="page-head"><div><h1>${esc(adminTabLabel(tab) || 'Administration')}</h1>
      <p>${esc(ADMIN_BLURB[tab] || 'Who can sign in, where data comes from, and how this installation runs.')}</p></div></div>
    <nav class="seg" aria-label="Administration sections">${ADMIN_SECTIONS.map(([label, keys]) =>
      `<button type="button" data-t="${keys[0]}" class="${keys.includes(tab) ? 'active' : ''}">${label}</button>`).join('')}</nav>
    <div class="tabs">${[['users', 'Users'], ['teams', 'Teams'], ['roles', 'Roles'], ['departments', 'Departments'], ['apikeys', 'API keys'], ['directory', 'Directory'], ['radius', 'RADIUS'], ['sso', 'Single sign-on'], ['ticketing', 'Ticketing'], ['sources', 'Asset sources'], ['teamimport', 'Import teams'], ['scanning', 'Scanning'], ['riskregister', 'Risk register'], ['secrets', 'Secret storage'], ['org', 'Organization'], ['software', 'Installed software'], ['network', 'Network access'], ['truststore', 'Trust store'], ['webcert', 'Web certificate'], ['updates', 'Software update']]
      .filter(([k]) => adminSection(tab).includes(k))
      .map(([k, l]) => `<button data-t="${k}" class="${tab === k ? 'active' : ''}">${l}</button>`).join('')}</div>
    <div id="adm-body"><div class="loading">Loading…</div></div>`;
  view.querySelectorAll('.tabs, .seg').forEach(el => { el.onclick = e => { if (e.target.dataset.t) location.hash = '#/admin?tab=' + e.target.dataset.t; }; });
  const body = $('#adm-body');

  if (tab === 'users') {
    const rows = pageOf(await get('/users?limit=100')).items;
    body.innerHTML = `<div class="row mb-2"><button class="btn btn-sm btn-primary" id="add">Add user</button></div>` + table([
      { label: 'Name', cell: r => esc(r.full_name || '—') },
      { label: 'Username', cell: r => r.username ? `<span class="mono small">${esc(r.username)}</span>` : '<span class="muted small">—</span>' },
      { label: 'Email', cell: r => esc(r.email) },
      /* Where this account's password is checked. It is the first question
         asked when somebody reports "my password stopped working", and
         answering it otherwise means opening the database. */
      { label: 'Source', cell: r => r.ldap_dn
          ? `<span class="pill st-neutral" title="${esc(r.ldap_dn)}">Directory</span>`
          : '<span class="pill st-neutral">Local</span>' },
      { label: 'Roles', cell: r => (r.roles || []).map(x => `<span class="pill st-neutral">${esc(x)}</span>`).join(' ') },
      { label: 'MFA', cell: r => r.mfa_enabled ? '<span class="pill st-remediated">On</span>' : '<span class="pill st-warn">Off</span>' },
      { label: 'Active', cell: r => r.is_active === false ? 'No' : 'Yes' },
      { label: 'Last login', cell: r => fmtDate(r.last_login_at) },
      { label: 'Visibility', cell: r => can('role:admin')
          ? `<button class="btn btn-sm" data-scope="${esc(r.id)}">Scope…</button>` : '' },
    ], rows);
    $$('[data-scope]', body).forEach(b => { b.onclick = () => scopeUser(b.dataset.scope); });
    $('#add').onclick = async () => {
      const roles = pageOf(await get('/roles')).items;
      const r = await modal({
        title: 'Add user',
        body: `<p class="small muted">The account is active as soon as you create it: nothing is e-mailed.
            Give the person the password yourself; they can change it under My account.</p>
          <div><label>Email *</label><input name="email" type="email" required></div>
          <div><label>Username</label><input name="username" spellcheck="false" autocapitalize="none" placeholder="jsmith">
            <p class="small muted">Optional. A second way to sign in, alongside the email address.
               Letters, digits, dot, underscore and hyphen — no "@", which would be
               ambiguous with an address. For a directory account, use the same
               name it has upstream (<span class="mono">sAMAccountName</span>).</p></div>
          <div><label>Full name *</label><input name="full_name" required></div>
          <div><label>Password *</label><input name="password" type="password" required></div>
          <div><label>Role</label><select name="role">${roles.map(x => `<option value="${esc(x.slug || x.id)}">${esc(x.name)}</option>`).join('')}</select></div>`,
        actions: [{ label: 'Create user' }],
      });
      if (!r) return;
      // UserCreate.full_name is required (2+ characters). The dialog used to
      // mark it optional and send null, which the API refused with a 422.
      const fullName = String(r.full_name || '').trim();
      if (fullName.length < 2) { err('Full name is required (2 characters minimum).'); return; }
      try {
        await post('/users', {
          email: r.email, full_name: fullName, password: r.password,
          // Omitted rather than sent as "" -- the field is optional and an
          // empty string is not a username, it is a validation error.
          ...(r.username ? { username: r.username } : {}),
          role_slugs: [r.role],
        });
        ok('User created.'); render();
      } catch (e) { err(e.detail); }
    };
  } else if (tab === 'teams') {
    const rows = pageOf(await get('/teams?limit=100')).items;
    body.innerHTML = `<div class="row mb-2"><button class="btn btn-sm btn-primary" id="add">New team</button></div>` + table([
      { label: 'Name', cell: r => esc(r.name) },
      { label: 'Slug', cell: r => `<span class="mono small">${esc(r.slug || '')}</span>` },
      { label: 'Members', num: true, cell: r => fmtNum(r.member_count ?? (r.members || []).length) },
      { label: 'Email', cell: r => esc(r.email || '—') },
    ], rows, { emptyTitle: 'No teams', emptyHint: 'Assignment rules route findings to teams — without teams, nothing gets an owner.' });
    $('#add').onclick = async () => {
      const r = await modal({ title: 'New team', body: `<div><label>Name *</label><input name="name" required placeholder="Network Security"></div><div><label>Contact email</label><input name="email" type="email"></div>`, actions: [{ label: 'Create' }] });
      if (!r) return;
      // TeamCreate requires `slug` (^[a-z0-9][a-z0-9-]*$, 2+ chars); the
      // dialog never sent one, so every New team was a 422 until 0.35.3.
      try { await post('/teams', { name: r.name, slug: slugify(r.name, 'team'), email: r.email || null }); ok('Team created.'); render(); } catch (e) { err(e.detail); }
    };
  } else if (tab === 'roles') {
    const [roles, perms] = await Promise.all([get('/roles').then(pageOf), get('/permissions').catch(() => [])]);
    const plist = Array.isArray(perms) ? perms : (perms.items || perms.permissions || []);
    body.innerHTML = table([
      { label: 'Role', cell: r => esc(r.name) },
      { label: 'Slug', cell: r => `<span class="mono small">${esc(r.slug || '')}</span>` },
      { label: 'Built-in', cell: r => r.is_builtin || r.organization_id == null ? 'Yes' : '' },
      { label: 'Permissions', num: true, cell: r => fmtNum((r.permissions || []).length) },
    ], roles.items) + `<div class="card mt-4"><h2>Permission catalogue</h2>
      <p class="small muted">${fmtNum(plist.length)} permissions across ${new Set(plist.map(p => String(p.code || p).split(':')[0])).size} resources.</p>
      <p class="small mono">${plist.slice(0, 200).map(p => esc(p.code || p)).join(' · ')}</p></div>`;
  } else if (tab === 'departments') {
    const rows = pageOf(await get('/departments')).items;
    body.innerHTML = `<div class="row mb-2"><button class="btn btn-sm btn-primary" id="add">New department</button></div>` +
      table([{ label: 'Name', cell: r => esc(r.name) }, { label: 'Slug', cell: r => `<span class="mono small">${esc(r.slug || '')}</span>` }], rows, { emptyTitle: 'No departments' });
    $('#add').onclick = async () => {
      const r = await modal({ title: 'New department', body: `<div><label>Name *</label><input name="name" required></div>`, actions: [{ label: 'Create' }] });
      if (!r) return;
      try { await post('/departments', { name: r.name }); ok('Created.'); render(); } catch (e) { err(e.detail); }
    };
  } else if (tab === 'apikeys') {
    const rows = pageOf(await get('/api-keys')).items;
    body.innerHTML = `<div class="row mb-2"><button class="btn btn-sm btn-primary" id="add">Create API key</button></div>` + table([
      { label: 'Name', cell: r => esc(r.name) },
      { label: 'Prefix', cell: r => `<span class="mono">${esc(r.prefix || '')}</span>` },
      { label: 'Created', cell: r => fmtDate(r.created_at) },
      { label: 'Last used', cell: r => fmtDate(r.last_used_at) },
      { label: 'Expires', cell: r => fmtDay(r.expires_at) },
      { label: '', cell: r => `<button class="btn btn-sm btn-danger" data-del="${esc(r.id)}">Revoke</button>` },
    ], rows, { emptyTitle: 'No API keys' });
    $('#add').onclick = async () => {
      const r = await modal({ title: 'Create API key', body: `<div><label>Name *</label><input name="name" required></div><p class="small muted">The secret is shown once and never again — VEYRS stores only a hash.</p>`, actions: [{ label: 'Create' }] });
      if (!r) return;
      try {
        const k = await post('/api-keys', { name: r.name });
        await modal({ title: 'Copy this key now', body: `<p class="small muted">This is the only time it will be shown.</p><div class="score-vector">${esc(k.api_key || '')}</div>`, actions: [] });
        render();
      } catch (e) { err(e.detail); }
    };
    $$('[data-del]', view).forEach(b => b.onclick = async () => {
      try { await del('/api-keys/' + b.dataset.del); ok('Revoked.'); render(); } catch (e) { err(e.detail); }
    });
  } else if (tab === 'sources') {
    /* ── Asset sources ───────────────────────────────────────────────────
       Somebody else's inventory, read on a schedule. Lives under
       Administration because connecting a CMDB is a configuration act done
       once, not a work queue — the queue it produces is the record list
       below it.

       The form deliberately shows the field mapping for EVERY driver, not
       only the ones that require it. NetBox's published schema is known and
       mapped for you; `custom_fields.*` is installation-specific by
       definition and is the half no driver can know. Hiding the mapping
       whenever it is optional is exactly how this estate's `pve_node`,
       `pve_tags` and `vmid` stayed unreachable. */
    /* `importer:*`, NOT `settings:admin`. Gating the screen on the wrong
       permission family hides it from exactly the role built to use it, and
       the person affected sees a missing page rather than a refusal. */
    if (!can('importer:read')) {
      body.innerHTML = `<div class="card"><p class="muted">Asset sources need <em>importer:read</em>.</p></div>`;
      return;
    }
    const mayAdmin = can('importer:admin');
    const [drivers, sources] = await Promise.all([
      get('/asset-sources/drivers').catch(() => []),
      get('/asset-sources').catch(() => []),
    ]);
    const byDriver = Object.fromEntries((drivers.drivers || drivers || []).map(d => [d.driver, d]));
    const KNOWN = drivers.fields || (byDriver.netbox || byDriver.file || {}).fields || [];

    const kvRows = (obj, aName, bName, aList) => Object.entries(obj || {}).map(([k, v]) => `
      <div class="kv-row">
        <input name="${aName}" value="${esc(k)}" placeholder="hostname" list="${aList}">
        <input name="${bName}" value="${esc(v)}" placeholder="custom_fields.pve_node">
        <button type="button" class="btn btn-sm kv-del" title="Remove this row">✕</button>
      </div>`).join('');

    /* The fields are grouped for reading, not for the wire: the form still
       submits the flat `include_fields` list. Anything the API adds later and
       this map has not heard of lands in "Other", so a new field can never
       disappear from the picker by omission. */
    const FIELD_GROUPS = [
      ['Identity', ['external_id', 'name', 'hostname', 'fqdn', 'serial', 'ip_addresses', 'mac_addresses']],
      ['Classification', ['asset_type', 'environment', 'criticality', 'exposure', 'data_classification']],
      ['Platform', ['operating_system', 'os_version']],
      ['Ownership and context', ['location', 'owner_label', 'team_label', 'status_label', 'tags']],
    ];
    const groupedFields = (known) => {
      const seen = new Set();
      const out = FIELD_GROUPS
        .map(([title, fs]) => [title, fs.filter(f => known.includes(f) && seen.add(f))])
        .filter(([, fs]) => fs.length);
      const rest = known.filter(f => !seen.has(f));
      return rest.length ? [...out, ['Other', rest]] : out;
    };

    /* The match ladder names `ip`; the field that satisfies it is
       `ip_addresses`. Comparing the two literally is how the picker would warn
       about a selection the server accepts. */
    const LADDER_FIELD = f => (f === 'ip' ? 'ip_addresses' : f);
    const blindPick = (on, ladder) => {
      const keys = new Set(ladder.map(LADDER_FIELD));
      return on.length > 0 && !on.some(f => keys.has(f));
    };
    const incText = (on, total, ladder) => !on.length
      ? `Nothing ticked — every field (${total}) is collected`
      : blindPick(on, ladder)
        ? `${on.length} of ${total} — no match field ticked, the server will refuse this`
        : `${on.length} of ${total} fields`;

    const editor = (s) => {
      const d = byDriver[s.driver] || {};
      const isNetbox = s.driver === 'netbox';
      const inc = s.include_fields || [];
      const ladder = s.match_order || ['external_id', 'serial', 'fqdn', 'hostname', 'ip', 'name'];
      return `
      <datalist id="veyrs-fields">${KNOWN.map(f => `<option value="${esc(f)}">`).join('')}</datalist>

      <div class="formsec">
        <h3>Identification</h3>
        <div class="grid2">
          <label class="field"><span class="lbl">Name</span><input name="name" value="${esc(s.name || '')}"></label>
          <label class="field"><span class="lbl">Slug</span><input name="slug" value="${esc(s.slug || '')}" ${s.id ? 'disabled' : ''}></label>
          <label class="field"><span class="lbl">Base URL</span><input name="base_url" value="${esc(s.base_url || '')}" placeholder="https://netbox.example.internal"></label>
          <label class="field"><span class="lbl">Priority</span><input name="priority" type="number" value="${s.priority ?? 100}"></label>
        </div>
        <label class="field mt-3"><span class="lbl">Description</span>
          <input name="description" value="${esc(s.description || '')}"></label>
      </div>

      <div class="formsec">
        <h3>Collections</h3>
        <p class="lede">What this source is asked to read. Empty means it is inert: it will run and read nothing.</p>
        ${(d.collections || []).length
          ? `<div class="checkgrid">${(d.collections).map(c => `<label><input type="checkbox" name="col:${esc(c)}"
               ${(s.collections || []).includes(c) ? 'checked' : ''}><span class="mono">${esc(c)}</span></label>`).join('')}</div>`
          : `<label class="field"><span class="lbl">Paths, one per line</span>
               <textarea name="collections_text" rows="3">${esc((s.collections || []).join('\n'))}</textarea></label>`}
      </div>

      <div class="formsec">
        <h3>${isNetbox ? 'Field overrides (optional)' : 'Field mapping (required)'}</h3>
        <p class="lede">${isNetbox
          ? `NetBox's own schema is already mapped. Add a row only to override a field, or to reach a
             <strong>custom field</strong> such as <span class="mono">custom_fields.pve_node</span>.`
          : `Which path in the source holds each VEYRS field.`}</p>
        <details class="why"><summary>${isNetbox ? 'What a row can reach' : 'Why this is required'}</summary>
          <div>
            ${isNetbox
              ? `<p>This NetBox carries <span class="mono">custom_fields.pve_node</span>,
                 <span class="mono">custom_fields.pve_tags</span> and <span class="mono">custom_fields.vmid</span>,
                 and none of them are in anybody's published schema. A row whose path resolves to nothing
                 leaves the default alone.</p>`
              : `<p>Guessing which column is the hostname is how an import files 900 hosts under a
                 serial number.</p>`}
            <p>To keep a value VEYRS has no column for, name the target
               <span class="mono">extra.something</span> — the prefix is required so a typo like
               <span class="mono">hostnmae</span> is refused instead of quietly disappearing.</p>
          </div>
        </details>
        <div class="kv-head two mt-2"><span>VEYRS field</span><span>Path in the source</span><span></span></div>
        <div id="fm-rows">${kvRows(s.field_map, 'fm_k', 'fm_v', 'veyrs-fields')
          || '<p class="kv-empty">No overrides — every field takes the driver\'s default.</p>'}</div>
        <button type="button" class="btn btn-sm mt-2" id="fm-add">Add a mapping</button>
      </div>

      <div class="formsec">
        <h3>Value translation</h3>
        <p class="lede">For the fields VEYRS holds as a fixed vocabulary — say what your own role
          and status names mean.</p>
        <details class="why"><summary>Why a translation and not a default</summary>
          <div><p>A role slug this driver does not recognise collapses to
            <span class="mono">server</span>, which is indistinguishable from a deliberate answer.
            Read on the <em>raw</em> NetBox token (<span class="mono">role.slug</span>), not on the
            value we already derived from it.</p></div>
        </details>
        <div class="kv-head three mt-2"><span>VEYRS field</span><span>Their value</span><span>VEYRS value</span><span></span></div>
        <div id="vm-rows">${Object.entries(s.value_maps || {}).flatMap(([field, m]) =>
          Object.entries(m || {}).map(([from, to]) => `
          <div class="vm-row">
            <input name="vm_f" value="${esc(field)}" placeholder="asset_type" list="veyrs-fields">
            <input name="vm_from" value="${esc(from)}" placeholder="hypervisor">
            <input name="vm_to" value="${esc(to)}" placeholder="server">
            <button type="button" class="btn btn-sm vm-del" title="Remove this row">✕</button>
          </div>`)).join('')
          || '<p class="kv-empty">No translations — the driver\'s own vocabulary is used.</p>'}</div>
        <button type="button" class="btn btn-sm mt-2" id="vm-add">Add a translation</button>
      </div>

      <div class="formsec">
        <h3>Which data to collect</h3>
        <p class="lede">Nothing ticked means <strong>every field</strong>. Tick a subset and this source
          may only report those.</p>
        <details class="why"><summary>Keep at least one field the match ladder reads</summary>
          <div><p>The ladder is
            <span class="mono">${esc(ladder.join(' → '))}</span>. Narrow past all of it and every record
            stages as unmatched — which reads as "the CMDB disagrees with the estate" rather than as a
            filter set too tight. The server refuses that combination.</p></div>
        </details>
        <div class="pickbar mt-3">
          <button type="button" class="btn btn-sm" data-incpick="all">Everything</button>
          <button type="button" class="btn btn-sm" data-incpick="none">Nothing</button>
          <button type="button" class="btn btn-sm" data-incpick="identity">Identity only</button>
          <span class="count ${blindPick(inc, ladder) ? 'warn' : ''}" id="inc-count">${esc(incText(inc, KNOWN.length, ladder))}</span>
        </div>
        ${groupedFields(KNOWN).map(([title, fs]) => `
          <div class="checkgroup">
            <div class="gh">${esc(title)}</div>
            <div class="checkgrid">${fs.map(f => `<label><input type="checkbox" name="inc:${esc(f)}"
              ${inc.includes(f) ? 'checked' : ''}><span class="mono">${esc(f)}</span></label>`).join('')}</div>
          </div>`).join('')}
      </div>

      <div class="formsec">
        <h3>Credentials</h3>
        <p class="lede">Encrypted at rest and never returned by any response.
          ${s.credentials_set ? 'A credential is stored; leave blank to keep it.' : 'None stored yet.'}</p>
        <div class="grid2">
          ${(d.credential_fields || ['token']).map(f => `<label class="field"><span class="lbl">${esc(f)}</span>
            <input name="cred:${esc(f)}" type="${/pass|token|secret/.test(f) ? 'password' : 'text'}"
            autocomplete="new-password"></label>`).join('')}
        </div>
      </div>

      <div class="formsec">
        <h3>Behaviour</h3>
        <div class="switches">
          <label><input type="checkbox" name="is_enabled" ${s.is_enabled ? 'checked' : ''}>
            <span class="t">Enabled<span class="d">A disabled source is kept and configured, but never run.</span></span></label>
          <label><input type="checkbox" name="verify_tls" ${s.verify_tls !== false ? 'checked' : ''}>
            <span class="t">Verify TLS<span class="d">Off accepts any certificate the host presents.</span></span></label>
          <label><input type="checkbox" name="auto_promote" ${s.auto_promote ? 'checked' : ''}>
            <span class="t">Write straight into the asset register<span class="d">Skips the staging queue. With this on and
              two sources enabled, the last sync of the day decides what the estate looks like.</span></span></label>
          <label><input type="checkbox" name="promote_creates_assets" ${s.promote_creates_assets ? 'checked' : ''}>
            <span class="t">Promotion may create assets<span class="d">Off, a record that matches nothing stays staged
              instead of adding a host.</span></span></label>
        </div>
      </div>`;
    };

    const readEditor = (root, s) => {
      const val = n => root.querySelector(`[name="${n}"]`)?.value?.trim() || '';
      const chk = n => !!root.querySelector(`[name="${n}"]`)?.checked;
      const d = byDriver[s.driver] || {};
      const collections = (d.collections || []).length
        ? (d.collections).filter(c => chk('col:' + c))
        : val('collections_text').split('\n').map(x => x.trim()).filter(Boolean);
      const field_map = {};
      root.querySelectorAll('.kv-row').forEach(r => {
        const k = r.querySelector('[name="fm_k"]').value.trim();
        const v = r.querySelector('[name="fm_v"]').value.trim();
        if (k && v) field_map[k] = v;
      });
      const value_maps = {};
      root.querySelectorAll('.vm-row').forEach(r => {
        const f = r.querySelector('[name="vm_f"]').value.trim();
        const from = r.querySelector('[name="vm_from"]').value.trim();
        const to = r.querySelector('[name="vm_to"]').value.trim();
        if (f && from && to) (value_maps[f] = value_maps[f] || {})[from] = to;
      });
      const include_fields = KNOWN.filter(f => chk('inc:' + f));
      const credentials = {};
      (d.credential_fields || []).forEach(f => {
        const v = val('cred:' + f);
        if (v) credentials[f] = v;
      });
      const out = {
        name: val('name'), description: val('description') || null,
        base_url: val('base_url'), priority: Number(val('priority') || 100),
        collections, field_map, value_maps, include_fields,
        is_enabled: chk('is_enabled'), verify_tls: chk('verify_tls'),
        auto_promote: chk('auto_promote'),
        promote_creates_assets: chk('promote_creates_assets'),
      };
      /* Only sent when something was typed. An empty object would be
         indistinguishable from "clear the token", and clearing it silently
         is how a working source starts failing to authenticate overnight. */
      if (Object.keys(credentials).length) out.credentials = credentials;
      if (!s.id) { out.slug = val('slug'); out.driver = s.driver; }
      return out;
    };

    const openEditor = async (s) => {
      const form = await modal({
        title: s.id ? `Edit ${s.name}` : `New ${(byDriver[s.driver] || {}).label || s.driver} source`,
        wide: true,
        body: `<div id="src-ed" data-ladder="${esc((s.match_order || ['external_id', 'serial', 'fqdn', 'hostname', 'ip', 'name']).join(','))}">${editor(s)}</div>`,
        actions: [{ label: s.id ? 'Save' : 'Create', keepOpen: true, run: async (_f, back) => {
          const root = back.querySelector('#src-ed');
          try {
            const payload = readEditor(root, s);
            if (s.id) await patch('/asset-sources/' + s.id, payload);
            else await post('/asset-sources', payload);
            ok(s.id ? 'Source saved.' : 'Source created.');
            return true;
          } catch (e) { err(e.detail || e.message || 'Could not save the source.'); return false; }
        } }],
      });
      if (form) render();
    };

    /* Live count for the field picker. Nothing ticked is not "0 of 19" -- it
       is the default, and saying so is the whole point of the line. */
    const incCount = (root) => {
      const out = root.querySelector('#inc-count');
      if (!out) return;
      const boxes = [...root.querySelectorAll('[name^="inc:"]')];
      const on = boxes.filter(b => b.checked).map(b => b.name.slice(4));
      const ladder = (root.dataset.ladder || '').split(',');
      out.classList.toggle('warn', blindPick(on, ladder));
      out.textContent = incText(on, boxes.length, ladder);
    };

    /* Delegated once, on the modal root, so rows added after render work. */
    document.getElementById('modal-root').onclick = e => {
      const root = e.target.closest('#src-ed');
      if (!root) return;
      if (e.target.id === 'fm-add') {
        root.querySelector('#fm-rows').querySelector('.kv-empty')?.remove();
        root.querySelector('#fm-rows').insertAdjacentHTML('beforeend',
          `<div class="kv-row">
            <input name="fm_k" placeholder="hostname" list="veyrs-fields">
            <input name="fm_v" placeholder="custom_fields.pve_node">
            <button type="button" class="btn btn-sm kv-del" title="Remove this row">✕</button></div>`);
      } else if (e.target.id === 'vm-add') {
        root.querySelector('#vm-rows').querySelector('.kv-empty')?.remove();
        root.querySelector('#vm-rows').insertAdjacentHTML('beforeend',
          `<div class="vm-row">
            <input name="vm_f" placeholder="asset_type" list="veyrs-fields">
            <input name="vm_from" placeholder="hypervisor">
            <input name="vm_to" placeholder="server">
            <button type="button" class="btn btn-sm vm-del" title="Remove this row">✕</button></div>`);
      } else if (e.target.classList.contains('kv-del') || e.target.classList.contains('vm-del')) {
        /* `.row` was the old hook. It is a generic class, so the nearest one
           was not necessarily this row. */
        e.target.closest('.kv-row, .vm-row')?.remove();
      } else if (e.target.dataset && e.target.dataset.incpick) {
        const pick = e.target.dataset.incpick;
        const identity = new Set((FIELD_GROUPS.find(g => g[0] === 'Identity') || [, []])[1]);
        root.querySelectorAll('[name^="inc:"]').forEach(b => {
          const f = b.name.slice(4);
          b.checked = pick === 'all' ? true : pick === 'none' ? false : identity.has(f);
        });
        incCount(root);
      }
    };

    /* A tick is a `change`, not a `click` on the label -- and the count must
       follow the boxes however they were reached, keyboard included. */
    document.getElementById('modal-root').onchange = e => {
      const root = e.target.closest('#src-ed');
      if (root && e.target.name && e.target.name.startsWith('inc:')) incCount(root);
    };

    body.innerHTML = explainer('assetsources', {
      title: 'Asset sources (CMDB, NetBox, uploads)',
      what: 'Where VEYRS reads somebody else\'s inventory from, and which of its fields it is allowed to keep.',
      who: 'A platform administrator, once per source — and again when a token rotates.',
      effect: 'A sync writes STAGING rows and links them to assets it recognises. It does not change the asset ' +
              'register until you promote, which is the only reason two sources can be compared instead of ' +
              'overwriting each other.',
      warn: 'A source narrowed past its own match keys stages every host as unmatched, which looks like the CMDB ' +
            'disagreeing with the estate rather than a filter set too tight. The server refuses that combination.',
    }) + `
      <div class="row" style="gap:8px;margin-bottom:12px;flex-wrap:wrap">
        ${mayAdmin ? (drivers.drivers || drivers || []).map(d => `<button class="btn btn-sm btn-primary" data-new="${esc(d.driver)}">New ${esc(d.label)}</button>`).join('')
          : '<p class="small muted">Adding or editing a source needs <em>importer:admin</em>.</p>'}
      </div>
      <div id="src-list"></div>`;

    $('#src-list').innerHTML = (sources.length ? table([
      { label: 'Source', cell: r => `<strong>${esc(r.name)}</strong><br><span class="mono small muted">${esc(r.slug)}</span>` },
      { label: 'Driver', cell: r => esc((byDriver[r.driver] || {}).label || r.driver) },
      { label: 'State', cell: r => (r.is_enabled ? '<span class="pill st-ok">Enabled</span>' : '<span class="pill st-neutral">Disabled</span>')
          + (r.is_inert ? ' <span class="pill st-warn" title="It will run and read nothing">Inert</span>' : '') },
      { label: 'Collects', cell: r => (r.include_fields || []).length
          ? `<span class="small">${esc(r.include_fields.join(', '))}</span>`
          : '<span class="small muted">every field</span>' },
      { label: 'Overrides', cell: r => Object.keys(r.field_map || {}).length
          ? `<span class="small mono">${esc(Object.keys(r.field_map).join(', '))}</span>`
          : '<span class="small muted">—</span>' },
      { label: 'Last sync', cell: r => r.last_sync_at ? esc(String(r.last_sync_at).slice(0, 16).replace('T', ' ')) : '<span class="muted">never</span>' },
      { label: '', cell: r => `<div class="row gap-2">
          ${can('importer:write') ? `<button class="btn btn-sm" data-test="${r.id}">Test</button>
          <button class="btn btn-sm" data-sync="${r.id}">Sync</button>` : ''}
          ${mayAdmin ? `<button class="btn btn-sm" data-edit="${r.id}">Edit</button>
          <button class="btn btn-sm btn-danger" data-del="${r.id}">Delete</button>` : ''}</div>` },
    ], sources) : `<div class="card"><p class="muted">No asset source yet. Add your NetBox URL;
        you will need an API token from it.</p></div>`)
      + `<div id="src-out"></div>`;

    body.onclick = async e => {
      const t = e.target;
      if (t.dataset.new) return openEditor({ driver: t.dataset.new, is_enabled: false, verify_tls: true });
      const id = t.dataset.test || t.dataset.sync || t.dataset.edit || t.dataset.del;
      if (!id) return;
      const s = sources.find(x => x.id === id);
      const out = $('#src-out');
      if (t.dataset.edit) return openEditor(s);
      if (t.dataset.del) {
        const go = await modal({ title: `Delete ${s.name}?`, body: `<p>Its staged records go with it. The assets
          it matched are NOT touched — a source is a description of the estate, not the estate.</p>`,
          actions: [{ label: 'Delete', cls: 'btn-danger' }] });
        if (!go) return;
        try { await del('/asset-sources/' + id); ok('Source deleted.'); render(); }
        catch (e2) { err(e2.detail || 'Could not delete it.'); }
        return;
      }
      t.disabled = true;
      out.innerHTML = `<div class="card"><p class="muted">${t.dataset.test ? 'Reaching the source…' : 'Syncing…'}</p></div>`;
      try {
        if (t.dataset.test) {
          const res = await post(`/asset-sources/${id}/test`, {});
          out.innerHTML = `<div class="card"><h2 class="mt-0">Reachable</h2>
            <p>${res.records} record${res.records === 1 ? '' : 's'} readable.
            ${(s.include_fields || []).length ? 'Shown as this source is configured to collect them:' : ''}</p>
            <pre class="small" style="overflow:auto;max-height:320px">${esc(JSON.stringify(res.sample, null, 2))}</pre></div>`;
        } else {
          const run = await post(`/asset-sources/${id}/sync`, {});
          out.innerHTML = `<div class="card"><h2 class="mt-0">Sync ${esc(run.status)}</h2>
            <p>${run.records_seen} seen · ${run.records_created} new · ${run.records_updated} changed ·
               ${run.assets_matched} matched an asset · ${run.assets_unmatched} did not ·
               ${run.records_rejected} rejected.</p>
            <p class="small muted">Nothing was written to the asset register. Promote from the records view
               when you have read what changed.</p></div>`;
        }
      } catch (e2) {
        out.innerHTML = `<div class="card"><h2 class="mt-0">Failed</h2>
          <p class="small">${esc(e2.detail || e2.message || 'unknown error')}</p></div>`;
      } finally { t.disabled = false; }
    };

  } else if (tab === 'teamimport') {
    /* ── Import teams ────────────────────────────────────────────────────
       Teams that already exist somewhere else. Two providers because the
       answer to "who owns this host" lives in two places and neither is
       wrong: NetBox knows which tenant a device belongs to, the directory
       knows where the humans are.

       Preview is a separate call and the same function backs both, so the
       screen the operator approved and the summary shown afterwards cannot
       describe two different things. */
    if (!can('team:write')) {
      body.innerHTML = `<div class="card"><p class="muted">Importing teams needs <em>team:write</em>.</p></div>`;
      return;
    }
    const providers = await get('/teams/import/providers').catch(() => []);
    const nb = providers.find(p => p.provider === 'netbox') || {};
    const ld = providers.find(p => p.provider === 'ldap') || {};

    body.innerHTML = explainer('teamimport', {
      title: 'Import teams from NetBox or the directory',
      what: 'Creates VEYRS teams from NetBox tenants, sites or roles, or from LDAP / Active Directory groups.',
      who: 'A platform administrator, when the estate is first laid out and after a reorganisation.',
      effect: 'Ownership flows from the asset: a finding with no explicit owner belongs to its asset\'s team. ' +
              'Importing the teams is what turns the label NetBox already gives every device into something ' +
              'SLAs and escalation chains can hang off.',
      warn: 'This never deletes. A team absent from the source is reported and left alone — reconciling ' +
            'ownership by deletion means one expired bind password detaches every ticket that pointed at it. ' +
            'It never creates a user account either; membership only seats people who already exist here.',
    }) + `
      <div class="grid2" style="gap:14px;align-items:start">
        <div class="card">
          <h2 class="mt-0">NetBox <span class="pill ${nb.ready ? 'st-ok' : 'st-neutral'}">${nb.ready ? 'ready' : 'not ready'}</span></h2>
          ${nb.ready ? `
            <label>Source<select id="nb-src">${(nb.sources || []).map(s =>
              `<option value="${s.id}">${esc(s.name)}${s.is_enabled ? '' : ' (disabled)'}</option>`).join('')}</select></label>
            <label style="margin-top:8px;display:block">What stands for a team
              <select id="nb-col">${(nb.collections || []).map(c =>
                `<option value="${esc(c.key)}">${esc(c.label)}</option>`).join('')}</select></label>
            <p class="small muted"><strong>Tenants</strong> is the one the asset driver already reads into every
              device's team label, so importing it makes those labels resolve to a real team.</p>
            <label class="row gap-2"><input type="checkbox" id="nb-upd"> Also update teams that already exist</label>
            <div class="row gap-2 mt-2">
              <button class="btn btn-sm" id="nb-prev">Preview</button>
              <button class="btn btn-sm btn-primary" id="nb-run">Import</button>
            </div>
            <hr class="rule">
            <h3 style="margin:0 0 4px">Assign assets to the teams</h3>
            <p class="small muted mt-0">Reads the label captured by the last sync, not NetBox —
              so it agrees with what you reviewed and works while NetBox is down. An asset somebody assigned
              by hand keeps that assignment unless you tick overwrite.</p>
            <label class="row gap-2"><input type="checkbox" id="nb-over"> Overwrite existing assignments</label>
            <div class="row gap-2 mt-2">
              <button class="btn btn-sm" id="nb-adry">Dry run</button>
              <button class="btn btn-sm btn-primary" id="nb-assign">Assign</button>
            </div>`
            : `<p class="muted">${esc(nb.detail || 'Not available.')}</p>
               <p class="small">Add one under <a href="#/admin?tab=sources">Asset sources</a>.</p>`}
        </div>
        <div class="card">
          <h2 class="mt-0">LDAP / Active Directory <span class="pill ${ld.ready ? 'st-ok' : 'st-neutral'}">${ld.ready ? 'ready' : 'not ready'}</span></h2>
          ${ld.detail ? `<p class="small muted">${esc(ld.detail)}</p>` : ''}
          ${ld.ready ? `
            <p class="small muted">Every group under the configured group base becomes a candidate team.
              Not filtered by the group-to-role map: that map says which groups grant a ROLE, and a team is
              not a role — an estate routinely has teams nobody signs in as.</p>
            <label class="row gap-2"><input type="checkbox" id="ld-mem"> Also seat members</label>
            <p class="small muted">${esc(ld.member_detail || '')}. Matched on username first and email second —
              the two identifiers the sign-in page already accepts.</p>
            <label class="row gap-2"><input type="checkbox" id="ld-upd"> Also update teams that already exist</label>
            <div class="row gap-2 mt-2">
              <button class="btn btn-sm" id="ld-prev">Preview</button>
              <button class="btn btn-sm btn-primary" id="ld-run">Import</button>
            </div>`
            : `<p class="small">Configure it under <a href="#/admin?tab=directory">Directory</a>.
               Importing teams reads the directory even when sign-in against it is off.</p>`}
        </div>
      </div>
      <div id="ti-out" class="mt-4"></div>`;

    const ACTION_PILL = { create: 'st-ok', update: 'st-warn', unchanged: 'st-neutral',
                          orphan: 'st-neutral', conflict: 'st-crit' };
    const showPlan = (res, title) => {
      const counts = Object.entries(res.counts || {}).map(([k, v]) => `${v} ${k}`).join(' · ');
      $('#ti-out').innerHTML = `<div class="card"><h2 class="mt-0">${esc(title)}</h2>
        <p>${esc(counts || 'nothing to do')}${res.members ? ` · ${res.members.added} member${res.members.added === 1 ? '' : 's'} seated` : ''}</p>
        ${res.members && res.members.unmatched_total
          ? `<p class="small muted">${res.members.unmatched_total} directory account${res.members.unmatched_total === 1 ? '' : 's'}
             matched nobody in VEYRS and ${res.members.unmatched_total === 1 ? 'was' : 'were'} skipped:
             <span class="mono">${esc((res.members.unmatched || []).join(', '))}</span>.
             Nothing here creates an account.</p>` : ''}
        </div>` + table([
        { label: 'Team', cell: r => `<strong>${esc(r.name)}</strong><br><span class="mono small muted">${esc(r.slug)}</span>` },
        { label: 'Action', cell: r => `<span class="pill ${ACTION_PILL[r.action] || 'st-neutral'}">${esc(r.action)}</span>` },
        { label: 'Detail', cell: r => r.detail ? `<span class="small">${esc(r.detail)}</span>` : '<span class="muted">—</span>' },
      ], res.rows || []);
    };

    const call = async (path, payload, title, btn) => {
      btn.disabled = true;
      $('#ti-out').innerHTML = `<div class="card"><p class="muted">Reading…</p></div>`;
      try { showPlan(await post(path, payload), title); }
      catch (e) { $('#ti-out').innerHTML = `<div class="card"><h2 class="mt-0">Failed</h2>
        <p class="small">${esc(e.detail || e.message || 'unknown error')}</p></div>`; }
      finally { btn.disabled = false; }
    };

    body.onclick = async e => {
      const t = e.target, id = t.id;
      if (!id) return;
      const nbPayload = () => ({ provider: 'netbox', source_id: $('#nb-src').value,
                                 collection: $('#nb-col').value, update_existing: $('#nb-upd').checked });
      const ldPayload = () => ({ provider: 'ldap', import_members: $('#ld-mem').checked,
                                 update_existing: $('#ld-upd').checked });
      if (id === 'nb-prev') return call('/teams/import/preview', nbPayload(), 'Preview — nothing written', t);
      if (id === 'nb-run')  return call('/teams/import', nbPayload(), 'Imported from NetBox', t);
      if (id === 'ld-prev') return call('/teams/import/preview', ldPayload(), 'Preview — nothing written', t);
      if (id === 'ld-run')  return call('/teams/import', ldPayload(), 'Imported from the directory', t);
      if (id === 'nb-adry' || id === 'nb-assign') {
        t.disabled = true;
        try {
          const r = await post('/teams/import/assign-assets', {
            source_id: $('#nb-src').value, dry_run: id === 'nb-adry',
            overwrite: $('#nb-over').checked });
          $('#ti-out').innerHTML = `<div class="card">
            <h2 class="mt-0">${r.dry_run ? 'Dry run — nothing written' : 'Assets assigned'}</h2>
            <p>${r.assigned} asset${r.assigned === 1 ? '' : 's'} ${r.dry_run ? 'would be' : ''} pointed at a team,
               out of ${r.records} staged record${r.records === 1 ? '' : 's'} carrying a team label.</p>
            ${r.already_assigned_elsewhere
              ? `<p class="small muted">${r.already_assigned_elsewhere} already belong to a different team and
                 ${r.dry_run ? 'would be' : 'were'} left alone.</p>` : ''}
            ${r.unknown_labels_total
              ? `<p class="small muted">${r.unknown_labels_total} label${r.unknown_labels_total === 1 ? '' : 's'}
                 match no team here — import them first:
                 <span class="mono">${esc((r.unknown_labels || []).join(', '))}</span></p>` : ''}
            </div>`;
        } catch (e2) { err(e2.detail || 'Could not assign.'); }
        finally { t.disabled = false; }
      }
    };
  } else if (tab === 'directory') {
    /* LDAP / Active Directory. Configuration, not a work queue -- which is why
       it lives under Configure and carries an explainer rather than a table.

       `settings:admin` on the READ too, unlike Scanning. This payload names the
       directory host, the service-account DN, the search base and the exact
       group-to-role mapping: a map of how to become an administrator here. */
    if (!can('settings:admin')) {
      body.innerHTML = `<div class="card"><p class="muted">Directory settings need <em>settings:admin</em>.
        They decide how everybody in this organization signs in, so they are not readable
        with a narrower grant.</p></div>`;
      return;
    }
    const st = await get('/ldap').catch(e => ({ error: e }));
    if (st.error) { body.innerHTML = `<div class="card"><p class="muted">Could not read the directory settings.</p></div>`; return; }
    const on = st.enabled === true;
    const b = v => v === true;
    body.innerHTML = explainer('directory', {
      title: 'Directory authentication (LDAP / Active Directory)',
      what: 'Whether passwords are checked by VEYRS or by your LDAP / Active Directory server.',
      who: 'An identity or platform administrator, once — and again when the service account rotates.',
      effect: 'With it on, people sign in with their domain password and VEYRS stores none of it. ' +
              'Roles can follow directory groups. Local passwords already set keep working, and the ' +
              'platform superuser is never delegated, so a bad configuration here cannot lock you out of fixing it.',
      warn: 'Creating accounts on first sign-in is a separate switch, and it is off. Turning it on lets ' +
            'everyone your directory will bind sign in to the platform holding this estate\'s unpatched vulnerabilities.',
    }) + `
      <div class="card">
        <div class="row row-split">
          <div>
            <h2 class="mt-0">${on ? 'Directory authentication is ON' : 'Directory authentication is OFF'}</h2>
            <p class="small muted measure">
              ${on
                ? `Sign-in checks the local password first, then binds against
                   <span class="mono">${esc(st.host || '')}</span>. VEYRS never stores a domain password.`
                : `Every account signs in against a password stored here. Turn this on to delegate the
                   credential check to your directory and keep offboarding in one place.`}
            </p>
          </div>
          <span class="pill ${on ? 'st-succeeded' : 'st-neutral'} nowrap">${on ? 'Delegated' : 'Local only'}</span>
        </div>
        ${st.library_available === false ? `<div class="scope-banner mt-3" role="status">
          <strong>The <span class="mono">ldap3</span> package is not installed on this node.</strong>
          <span>Settings can be saved, but no login will reach the directory until it is installed and the API restarted.</span></div>` : ''}
      </div>

      <form id="ldap-form" class="card mt-4">
        <div class="formsec">
          <h3>Connection</h3>
          <p class="lede">Where the directory is and how the channel is protected.</p>
          <div class="grid2">
            <label class="field"><span class="lbl">Host <span class="req">*</span></span>
              <input name="host" value="${esc(st.host || '')}" placeholder="dc01.corp.local"></label>
            <label class="field"><span class="lbl">Port</span>
              <input name="port" type="number" min="1" max="65535" value="${esc(String(st.port ?? 636))}"></label>
            <label class="field"><span class="lbl">Timeout (seconds)</span>
              <input name="timeout_seconds" type="number" min="1" max="60" value="${esc(String(st.timeout_seconds ?? 8))}"></label>
          </div>
          <div class="switches mt-2">
            <label><input type="checkbox" name="use_ssl" ${b(st.use_ssl) ? 'checked' : ''}>
              <span class="t">LDAPS<span class="d">Encrypted from the first byte. Port 636.</span></span></label>
            <label><input type="checkbox" name="start_tls" ${b(st.start_tls) ? 'checked' : ''}>
              <span class="t">StartTLS<span class="d">Upgrades a plaintext connection. Port 389.</span></span></label>
            <label><input type="checkbox" name="verify_certificate" ${st.verify_certificate !== false ? 'checked' : ''}>
              <span class="t">Verify certificate<span class="d">Off accepts any certificate the host presents.</span></span></label>
          </div>
          <details class="why"><summary>One or the other, never both</summary>
            <div><p>StartTLS upgrades a plaintext connection and there is nothing to upgrade inside an
              SSL one. An unencrypted bind sends the password in cleartext, so VEYRS refuses to enable
              one.</p></div>
          </details>
        </div>

        <div class="formsec">
          <h3>Service account</h3>
          <p class="lede">A read-only account that may search the directory. VEYRS finds the person
            first, then binds as the entry it found.</p>
          <label class="field"><span class="lbl">Bind DN <span class="req">*</span></span>
            <input name="bind_dn" value="${esc(st.bind_dn || '')}" placeholder="CN=veyrs,OU=Service Accounts,DC=corp,DC=local"></label>
          <!-- A div, not a label: the "erase it" control is itself a label and
               nesting two is invalid HTML with no defined click behaviour. -->
          <div class="field"><span class="lbl">Bind password</span>
            <input name="bind_password" type="password" autocomplete="new-password"
              placeholder="${st.bind_password_set ? 'stored — leave blank to keep it' : 'not set'}">
            <p class="hint">Fernet-encrypted and never returned by the API.${st.bind_password_set
              ? ' <label style="display:inline-flex;gap:5px;align-items:center;margin-left:6px"><input type="checkbox" name="clear_bind_password" style="width:14px"> erase it</label>'
              : ''}</p></div>
          <details class="why"><summary>Why an account is needed at all</summary>
            <div><p>Without one, group membership and email cannot be read — so nothing can be
              provisioned, and no group can be mapped to a role. Direct bind would authenticate people
              into an estate it can tell you nothing about.</p></div>
          </details>
        </div>

        <div class="formsec">
          <h3>Search</h3>
          <p class="lede">Where to look, and which attributes carry the account name, address and groups.</p>
          <label class="field"><span class="lbl">Base DN <span class="req">*</span></span>
            <input name="base_dn" value="${esc(st.base_dn || '')}" placeholder="DC=corp,DC=local"></label>
          <label class="field"><span class="lbl">User filter</span>
            <input name="user_filter" class="mono" value="${esc(st.user_filter || '')}">
            <span class="hint">Must contain <span class="mono">{username}</span>;
              <span class="mono">{attr}</span> is replaced by the account attribute below.</span></label>
          <details class="why"><summary>Why the shipped filter excludes computer accounts</summary>
            <div><p><span class="mono">objectClass=user</span> on its own matches every workstation in
              the domain.</p></div>
          </details>
          <div class="grid2 mt-3">
            <label class="field"><span class="lbl">Account attribute</span>
              <input name="attr_username" value="${esc(st.attr_username || '')}" placeholder="sAMAccountName"></label>
            <label class="field"><span class="lbl">Email attribute</span>
              <input name="attr_email" value="${esc(st.attr_email || '')}" placeholder="mail"></label>
            <label class="field"><span class="lbl">Display-name attribute</span>
              <input name="attr_full_name" value="${esc(st.attr_full_name || '')}" placeholder="displayName"></label>
            <label class="field"><span class="lbl">Group attribute</span>
              <input name="attr_member_of" value="${esc(st.attr_member_of || '')}" placeholder="memberOf"></label>
          </div>
        </div>

        <div class="formsec">
          <h3>Groups and roles</h3>
          <p class="lede">One per line, <span class="mono">group = role-slug</span>. The group may be a
            full DN or the bare CN.</p>
          <label class="field"><span class="lbl">Group → role mapping</span>
            <textarea name="group_role_map" rows="5" class="mono" placeholder="SOC Analysts = security-analyst
CN=Vuln Managers,OU=Groups,DC=corp,DC=local = security-manager">${esc(Object.entries(st.group_role_map || {}).map(([g, r]) => `${g} = ${r}`).join('\n'))}</textarea></label>
          <details class="why"><summary>What this never does</summary>
            <div><p>Nothing is granted by name resemblance — an unmapped group grants nothing. Roles you
              assign by hand are never removed by this.</p></div>
          </details>
          <div class="switches mt-2">
            <label><input type="checkbox" name="sync_roles_on_login" ${st.sync_roles_on_login !== false ? 'checked' : ''}>
              <span class="t">Re-apply group roles on every sign-in<span class="d">Off, the mapping is applied once and
                a group removed in the directory keeps its role here.</span></span></label>
          </div>
        </div>

        <div class="formsec">
          <h3>Account provisioning</h3>
          <p class="lede">Whether a person your directory accepts, but VEYRS has never seen, gets an
            account on the spot.</p>
          <div class="switches">
            <label><input type="checkbox" name="jit_provisioning" ${b(st.jit_provisioning) ? 'checked' : ''}>
              <span class="t">Create accounts on first sign-in<span class="d">Off by default, and it should usually
                stay off.</span></span></label>
          </div>
          <div class="scope-banner mt-2" role="status">
            <strong>With this on, everyone your directory will bind can sign in.</strong>
            <span>Contractors, the service desk, the intern — into the platform holding this estate's
              unpatched vulnerabilities. What they then see is the default role below; empty means an
              account that signs in and reads nothing.</span>
          </div>
          <label class="field mt-3"><span class="lbl">Default roles for new accounts</span>
            <input name="default_role_slugs" class="mono" value="${esc((st.default_role_slugs || []).join(', '))}" placeholder="viewer"></label>
        </div>

        <div class="row" style="gap:10px;margin-top:20px;padding-top:14px;border-top:1px solid var(--border)">
          <button class="btn btn-primary" type="submit">Save</button>
          <button class="btn" type="button" id="ldap-test">Test connection</button>
          <button class="btn ${on ? 'btn-danger' : ''}" type="button" id="ldap-flip">${on ? 'Turn directory authentication off' : 'Turn it on and save'}</button>
        </div>
        <div id="ldap-result"></div>
      </form>`;

    /* The form is read once and turned into the PUT body. `enabled` is NOT in
       here: it is flipped by its own button, so that saving a half-finished
       form can never switch authentication on by accident. */
    const readForm = () => {
      const f = $('#ldap-form', body);
      const map = {};
      (f.group_role_map.value || '').split('\n').forEach(line => {
        const i = line.indexOf('=');
        if (i < 0) return;
        const g = line.slice(0, i).trim(), r = line.slice(i + 1).trim();
        if (g && r) map[g] = r;
      });
      const payload = {
        host: f.host.value.trim(), port: Number(f.port.value) || 636,
        use_ssl: f.use_ssl.checked, start_tls: f.start_tls.checked,
        verify_certificate: f.verify_certificate.checked,
        timeout_seconds: Number(f.timeout_seconds.value) || 8,
        bind_dn: f.bind_dn.value.trim(), base_dn: f.base_dn.value.trim(),
        user_filter: f.user_filter.value.trim(),
        attr_username: f.attr_username.value.trim(), attr_email: f.attr_email.value.trim(),
        attr_full_name: f.attr_full_name.value.trim(), attr_member_of: f.attr_member_of.value.trim(),
        group_role_map: map,
        jit_provisioning: f.jit_provisioning.checked,
        sync_roles_on_login: f.sync_roles_on_login.checked,
        default_role_slugs: f.default_role_slugs.value.split(',').map(s => s.trim()).filter(Boolean),
      };
      // Only sent when actually typed. An empty box means "keep the stored
      // one", never "set the password to the empty string".
      if (f.bind_password.value) payload.bind_password = f.bind_password.value;
      if (f.clear_bind_password && f.clear_bind_password.checked) payload.clear_bind_password = true;
      return payload;
    };

    $('#ldap-form', body).onsubmit = async e => {
      e.preventDefault();
      try { await put('/ldap', { ...readForm(), enabled: on }); ok('Directory settings saved.'); render(); }
      catch (ex) { err(ex.detail); }
    };
    $('#ldap-flip', body).onclick = async () => {
      const r = await modal({
        title: on ? 'Turn directory authentication off' : 'Turn directory authentication on',
        body: on
          ? `<p class="small">Sign-in goes back to local passwords only. Accounts that were created from the
               directory and have no local password <strong>will not be able to sign in</strong> until somebody
               sets one for them.</p>`
          : `<p class="small">The settings on screen are saved and applied. VEYRS will check the local password
               first and fall back to the directory.</p>
             <p class="small muted">If the settings are wrong, sign-in for local accounts is unaffected and the
               platform superuser is never delegated — so this is reversible from the same screen.</p>`,
        actions: [{ label: on ? 'Turn off' : 'Turn on' }],
      });
      if (!r) return;
      try { await put('/ldap', { ...readForm(), enabled: !on }); ok(on ? 'Directory authentication is off.' : 'Directory authentication is on.'); render(); }
      catch (ex) { err(ex.detail); }
    };
    $('#ldap-test', body).onclick = async () => {
      const box = $('#ldap-result', body);
      box.innerHTML = `<p class="small muted mt-3">Testing the <strong>saved</strong> settings…</p>`;
      const r = await modal({
        title: 'Test the saved configuration',
        body: `<p class="small">This tests what is stored, not what is on screen — that is the configuration
                 sign-in will actually use. Save first if you have changed anything.</p>
               <div><label>Look somebody up (optional)</label><input name="sample" placeholder="jsmith">
                 <p class="small muted">Proves the filter finds the right entry. No password needed.</p></div>`,
        actions: [{ label: 'Run test' }],
      });
      if (!r) { box.innerHTML = ''; return; }
      try {
        const res = await post('/ldap/test', { sample_identifier: r.sample || null });
        box.innerHTML = `<div class="card mt-4"><h2>${res.ok ? 'Directory reachable' : 'Test failed'}</h2>` +
          table([
            { label: 'Step', cell: s => esc(s.step) },
            { label: '', cell: s => s.ok ? '<span class="pill st-succeeded">OK</span>' : '<span class="pill st-failed">Failed</span>' },
            { label: 'Detail', cell: s => `<span class="small muted">${esc(s.detail || '')}</span>` },
          ], res.steps || []) + '</div>';
      } catch (ex) { box.innerHTML = `<p class="form-error mt-3">${esc(ex.detail || 'Test failed.')}</p>`; }
    };
  } else if (tab === 'ticketing') {
    /* Which system owns remediation work. A page rather than a toggle in a
       corner, for the same reason Scanning is one: the answer changes what the
       platform IS for everyone who logs in, and an operator who cannot find
       Tickets has to be able to read WHY here instead of filing a bug. */
    const st = await get('/ticketing').catch(e => ({ error: e }));
    if (st.error) { body.innerHTML = `<div class="card"><p class="muted">Could not read the ticketing mode.</p></div>`; return; }
    const ext = st.mode === 'external';
    const conns = can('ticket:read')
      ? await get('/integrations/connectors').catch(() => []) : [];
    body.innerHTML = `
      <div class="card">
        <div class="row row-split">
          <div>
            <h2 class="mt-0">${ext ? 'Remediation work lives in your ITSM' : "Remediation work lives in VEYRS' own queue"}</h2>
            <p class="small muted" style="max-width:66ch">
              ${ext
                ? `The <strong>Tickets</strong> section is gone from this console and
                   <code>POST /tickets</code> is refused. Raising remediation for a finding creates
                   the issue in <strong>${esc(st.connector_name || 'the configured system')}</strong>
                   and VEYRS records the relation — which issue, which finding, which device, raised
                   when, due when — under <a href="#/issues">Issues</a>.`
                : `VEYRS owns the ticket: reference, state machine, comments, approvals, the SLA
                   mirror and the escalation chain. An ITSM connector can still mirror those tickets
                   outward; that is a copy, and VEYRS stays the authority.`}
            </p>
          </div>
          <span class="pill ${ext ? (st.usable ? 'st-ok' : 'st-failed') : 'st-neutral'} nowrap">${
            ext ? (st.usable ? esc(st.connector_system || 'external') : 'broken') : 'internal'}</span>
        </div>
        ${ext && !st.usable ? `<p class="form-error mt-3">External ticketing is selected
          but its connector is missing or disabled. <strong>No new remediation work can be raised in
          either system.</strong> Fix the connector under
          <a href="#/integrations?tab=itsm">Integrations → ITSM</a>, or switch back to the internal queue.</p>` : ''}
        <dl class="kv mt-3">
          <dt>Set explicitly</dt><dd>${st.explicit ? 'Yes' : 'No — this is the shipped default'}</dd>
          <dt>Connector</dt><dd>${ext ? `${esc(st.connector_name || '—')} <span class="small muted">${esc(st.connector_system || '')}${st.connector_enabled === false ? ' · disabled' : ''}</span>` : '—'}</dd>
          <dt>Last changed</dt><dd>${fmtDate(st.changed_at) || '—'}</dd>
          <dt>Reason</dt><dd>${esc(st.reason || '—')}</dd>
          <dt>Open internal tickets</dt><dd>${fmtNum(st.open_internal_tickets ?? 0)}${
            ext && st.open_internal_tickets ? ' <span class="small muted">— still open, still closable at <a href="#/tickets">/tickets</a></span>' : ''}</dd>
        </dl>
        ${can('settings:admin') ? `<div class="row mt-4">
          <button class="btn ${ext ? '' : 'btn-primary'}" id="tk-flip">${ext ? 'Move back to the VEYRS queue' : 'Hand ticketing to an external ITSM'}</button>
        </div>` : `<p class="small muted mt-4">Changing this needs <em>settings:admin</em>.</p>`}
      </div>

      <div class="card mt-4">
        <h2>What handing ticketing over does, exactly</h2>
        <p class="small muted">A mode that only hides a menu is not a mode — the API, the automation and
           the workflow engine would carry on filling a queue you believe is closed. This one is enforced
           where work is <strong>created</strong>, and deliberately not where work is
           <strong>finished</strong> or <strong>read</strong>.</p>
        ${table([
          { label: 'Capability', cell: r => esc(r[0]) },
          { label: 'In external mode', cell: r => r[1]
              ? '<span class="pill st-failed">Refused</span>'
              : '<span class="pill st-succeeded">Still works</span>' },
          { label: 'Why', cell: r => `<span class="small muted">${esc(r[2])}</span>` },
        ], [
          ['Create a VEYRS ticket (API or console)', true, 'The internal queue is no longer the authority; creating there would split remediation in two.'],
          ['Raise remediation for a finding', false, 'Redirected: the issue is created in your ITSM and the relation is recorded here.'],
          ['Automatic tickets, workflow actions', false, 'Redirected through the same dispatcher, so automation cannot route around the switch.'],
          ['Transition an existing internal ticket', false, 'The one that matters: flipping the switch must not strand tickets already open and unclosable.'],
          ['Read the Tickets list and its history', false, 'History from before the flip is evidence. Hiding it would destroy an audit trail to tidy a menu.'],
          ['The inbound webhook from your ITSM', false, 'It updates the relation, which is the record external mode keeps.'],
        ])}
        <p class="small muted mt-2">Nothing is migrated, closed or deleted when you flip
           this. Tickets that exist keep existing.</p>
      </div>

      <details class="why mt-4"><summary>Why the setting is not called "Jira"</summary>
        <p class="small muted">The connector layer speaks Jira Cloud, Jira Data Center, ServiceNow and a
          generic webhook. Naming the tenant policy after one vendor is how <code>/rest/api/3</code> got
          hardcoded and Data Center stopped working. The mode names the shape of the decision; the
          connector names who holds the authority — so "where did this ticket go?" is answered by a row
          and not by a guess.</p></details>`;

    const flip = $('#tk-flip', body);
    if (flip) flip.onclick = async () => {
      if (!ext && !conns.length) {
        err('Create an ITSM connector first, under Integrations → ITSM.');
        return;
      }
      const r = await modal({
        title: ext ? 'Move ticketing back to VEYRS' : 'Hand ticketing to an external ITSM',
        body: ext
          ? `<p class="small">New remediation work will open VEYRS tickets again. Issues already raised
               in ${esc(st.connector_name || 'the external system')} are <strong>not</strong> closed or
               deleted — their relations stay readable under Issues.</p>
             <div class="field"><label>Reason</label><input name="reason" placeholder="Bringing remediation back in house"></div>`
          : `<p class="small">The <strong>Tickets</strong> section will disappear from this console for
               everyone in this organization, and <code>POST /tickets</code> will be refused. Remediation
               for a finding will be raised in the system you pick here.</p>
             <div class="field"><label>Which system owns the work *</label>
               <select name="connector_id" required>
                 <option value="">Choose an ITSM connector…</option>
                 ${conns.map(c => `<option value="${esc(c.id)}">${esc(c.name)} — ${esc(c.system)}${c.is_enabled === false ? ' (disabled)' : ''}</option>`).join('')}
               </select></div>
             <div class="field"><label>Reason</label><input name="reason" placeholder="Engineering works out of Jira"></div>
             ${st.open_internal_tickets ? `<p class="small muted"><strong>${fmtNum(st.open_internal_tickets)}
               internal ticket(s) are open.</strong> They are not closed or migrated: they stay reachable at
               <code>/tickets</code> and can still be transitioned, so nothing in flight is stranded. New work
               goes to the external system.</p>` : ''}
             <p class="small muted">VEYRS still owns the finding, the risk score, the SLA clock and
               verification. A remote closure is evidence that the work was done, never proof the
               finding is fixed.</p>`,
        actions: [{ label: ext ? 'Use the VEYRS queue' : 'Hand it over' }],
      });
      if (!r) return;
      try {
        await put('/ticketing', {
          mode: ext ? 'internal' : 'external',
          connector_id: ext ? null : (r.connector_id || null),
          reason: r.reason || null,
        });
        // Move the in-memory flag before re-rendering, exactly as the scanning
        // switch does: waiting for the next `/auth/me` would leave the operator
        // looking at a menu that still offers the section they just switched
        // off, and the obvious next move -- a reload -- hides the confirmation.
        ticketingMode = ext ? 'internal' : 'external';
        ok(ext ? 'Remediation work is back in the VEYRS queue.' : 'Remediation work now goes to your ITSM.');
        render();
      } catch (e) { err(e.detail); }
    };
  } else if (tab === 'riskregister') {
    /* The switch that decides whether this tenant keeps a risk register at all.
       Rendered as a page rather than a toggle in a corner for the same reason
       the scanning one is: an operator who turns it off is entitled to see, on
       the same screen and before they press the button, exactly what stops
       working and exactly how much is in there. */
    const st = await get('/risk-register').catch(e => ({ error: e }));
    if (st.error) { body.innerHTML = `<div class="card"><p class="muted">Could not read the risk register setting.</p></div>`; return; }
    const on = st.enabled !== false;
    body.innerHTML = `
      <div class="card">
        <div class="row row-split">
          <div>
            <h2 class="mt-0">${on ? 'The risk register is ON' : 'The risk register is OFF'}</h2>
            <p class="small muted measure">
              ${on
                ? `VEYRS keeps a register of risks that are <strong>not tied to an asset</strong> —
                   suppliers, processes, contracts, people — each with a RACI naming who answers for it.
                   It sits beside the CVE-derived risk on your estate; it is not computed from it.`
                : `This organization keeps its enterprise risk somewhere else. The section is out of the
                   menu and every write is refused — <strong>nothing has been deleted</strong>, and the
                   ${fmtNum(st.entries)} entr${st.entries === 1 ? 'y' : 'ies'} already recorded stay
                   readable and exportable.`}
            </p>
          </div>
          <span class="pill ${on ? 'st-succeeded' : 'st-neutral'} nowrap">${on ? 'Register kept' : 'Not kept here'}</span>
        </div>
        <dl class="kv mt-3">
          <dt>Set explicitly</dt><dd>${st.explicit ? 'Yes' : 'No — this is the shipped default'}</dd>
          <dt>Last changed</dt><dd>${fmtDate(st.changed_at) || '—'}</dd>
          <dt>Reason</dt><dd>${esc(st.reason || '—')}</dd>
          <dt>Entries recorded</dt><dd>${fmtNum(st.entries)} (${fmtNum(st.open_entries)} open)</dd>
        </dl>
        ${can('settings:admin') ? `<div class="row mt-4">
          <button class="btn ${on ? '' : 'btn-primary'}" id="flip-reg">${on ? 'Turn the risk register off' : 'Turn the risk register back on'}</button>
        </div>` : `<p class="small muted mt-4">Changing this needs <em>settings:admin</em>.</p>`}
      </div>

      <div class="card mt-4">
        <h2>What turning it off does, exactly</h2>
        <p class="small muted">Hiding a menu entry is not a switch. This one is enforced where entries are
           <strong>created and changed</strong>, and deliberately not where they are <strong>read</strong>.</p>
        ${table([
          { label: 'Capability', cell: r => esc(r[0]) },
          { label: 'With the register off', cell: r => r[1]
              ? '<span class="pill st-failed">Refused</span>'
              : '<span class="pill st-succeeded">Still works</span>' },
          { label: 'Why', cell: r => `<span class="small muted">${esc(r[2])}</span>` },
        ], [
          ['Add a risk', true, 'No new entries in a register this organization does not keep.'],
          ['Change a risk', true, 'Including its status, its score and its treatment.'],
          ['Change a RACI', true, 'Assignment is the work this module does.'],
          ['Link a risk to an asset', true, 'Same reason.'],
          ['Remove a risk', true, 'Deliberate: turning the module off must not become a quiet way to erase risk records. Turn it back on and delete them on the record.'],
          ['Read the register', false, 'Entries written before the flip are evidence. Hiding them to tidy a menu destroys the reason somebody wrote them down.'],
          ['Read the summary counts', false, 'So this screen can tell you how much you are about to hide, instead of letting you decide blind.'],
        ])}
      </div>`;
    const flipReg = $('#flip-reg', body);
    if (flipReg) flipReg.onclick = async () => {
      const r = await modal({
        title: on ? 'Turn the risk register off' : 'Turn the risk register back on',
        body: on
          ? `<p class="small">The Risk Register section leaves the menu and every write is refused.
               The ${fmtNum(st.entries)} entr${st.entries === 1 ? 'y' : 'ies'} already recorded are
               <strong>not deleted</strong> and stay readable.</p>
             <div><label>Reason *</label><input name="reason" required placeholder="Our enterprise risk lives in the GRC tool"></div>`
          : `<p class="small">The section comes back, with everything that was already in it.</p>
             <div><label>Reason</label><input name="reason" placeholder="Bringing enterprise risk into VEYRS"></div>`,
        actions: [{ label: on ? 'Turn off' : 'Turn on' }],
      });
      if (!r) return;
      try {
        await put('/risk-register', { risk_register_enabled: !on, reason: r.reason || null });
        // Move the in-memory flag before re-rendering, exactly as the scanning
        // switch does: waiting for the next `/auth/me` leaves the operator
        // looking at a menu that still offers the section they just removed.
        riskRegisterOn = !on;
        ok(on ? 'The risk register is off and has left the menu. Nothing was deleted.'
              : 'The risk register is back in the menu.');
        render();
      } catch (e) { err(e.detail); }
    };
  } else if (tab === 'sso') {
    await adminSso(body);
  } else if (tab === 'radius') {
    await adminRadius(body);
  } else if (tab === 'software') {
    await adminInstalledSoftware(body);
  } else if (tab === 'network') {
    await adminNetworkAccess(body);
  } else if (tab === 'truststore') {
    await adminTrustStore(body);
  } else if (tab === 'webcert') {
    await adminWebCertificate(body);
  } else if (tab === 'updates') {
    await adminSoftwareUpdate(body);
  } else if (tab === 'scanning') {
    /* The switch that decides whether VEYRS probes anything at all.
       Rendered as a page rather than a toggle in a corner because the answer
       changes what the whole platform IS, and an operator arriving at an empty
       scan queue has to be able to tell "nothing is scheduled" from "this
       deployment does not scan". */
    const st = await get('/scanning').catch(e => ({ error: e }));
    if (st.error) { body.innerHTML = `<div class="card"><p class="muted">Could not read the scanning mode.</p></div>`; return; }
    const on = st.active_scanning_enabled !== false;
    body.innerHTML = `
      <div class="card">
        <div class="row row-split">
          <div>
            <h2 class="mt-0">${on ? 'Active scanning is ON' : 'Active scanning is OFF'}</h2>
            <p class="small muted measure">
              ${on
                ? `VEYRS may run scans itself: an enrolled agent claims authorised jobs and runs the
                   scanner on its own host. It also ingests everything you send it.`
                : `VEYRS runs as an <strong>ingest-only vulnerability management platform</strong>.
                   It probes nothing. Findings arrive from your own scanner — uploads, scanner
                   connectors, agent results — and VEYRS does the triage, ownership, SLA, ticketing
                   and traceability on top of them.`}
            </p>
          </div>
          <span class="pill ${on ? 'st-succeeded' : 'st-neutral'} nowrap">${on ? 'Scanning' : 'Ingest only'}</span>
        </div>
        <dl class="kv mt-3">
          <dt>Set explicitly</dt><dd>${st.explicit ? 'Yes' : 'No — this is the shipped default'}</dd>
          <dt>Last changed</dt><dd>${fmtDate(st.changed_at) || '—'}</dd>
          <dt>Reason</dt><dd>${esc(st.reason || '—')}</dd>
          <dt>Jobs queued</dt><dd>${fmtNum(st.queued_jobs ?? 0)}</dd>
        </dl>
        ${can('settings:admin') ? `<div class="row mt-4">
          <button class="btn ${on ? '' : 'btn-primary'}" id="flip">${on ? 'Turn active scanning off' : 'Turn active scanning back on'}</button>
        </div>` : `<p class="small muted mt-4">Changing this needs <em>settings:admin</em>.</p>`}
      </div>

      <div class="card mt-4">
        <h2>What turning it off does, exactly</h2>
        <p class="small muted">A control that only hides a button is not a control. This one is enforced
           where work is <strong>created</strong> and where it is <strong>handed out</strong> — and
           deliberately not where work is <strong>finished</strong>.</p>
        ${table([
          { label: 'Capability', cell: r => esc(r[0]) },
          { label: 'With scanning off', cell: r => r[1]
              ? '<span class="pill st-failed">Refused</span>'
              : '<span class="pill st-succeeded">Still works</span>' },
          { label: 'Why', cell: r => `<span class="small muted">${esc(r[2])}</span>` },
        ], [
          ['Queue a scan job', true, 'No new scan is scheduled.'],
          ['An agent claims a job', true, 'The one that matters: work queued before the switch was thrown must not drain into the estate afterwards.'],
          ['Enrol a new agent', true, 'A runner cannot be added to a platform that does not run scans.'],
          ['Agent heartbeat', false, 'A live agent is told to stand down instead of polling a door that now refuses it.'],
          ['Submit a scan result', false, 'A scan already in flight has already touched the estate; refusing its output would discard it and wedge the job in "running" forever.'],
          ['Report host inventory', false, 'Reporting what is installed is not scanning, and it is what the correlation engine reads.'],
          ['Import a file or pull a connector', false, 'Ingestion is the entire point of this mode.'],
        ])}
      </div>`;
    const flip = $('#flip', body);
    if (flip) flip.onclick = async () => {
      const r = await modal({
        title: on ? 'Turn active scanning off' : 'Turn active scanning back on',
        body: on
          ? `<p class="small">VEYRS will stop running scans of its own. It keeps ingesting, triaging and
               tracking everything your scanners report.</p>
             <div><label>Reason *</label><input name="reason" required placeholder="We run Nessus; VEYRS manages the findings"></div>
             <div><label><input type="checkbox" name="cancel" checked> Cancel the ${fmtNum(st.queued_jobs ?? 0)} job(s) already queued</label></div>
             <p class="small muted">A job that can never be claimed is not queued, it is stuck — and a queue
               depth counting work nobody will run is a number this console would report wrongly.
               Jobs already <em>running</em> are left alone so they can deliver their output.</p>`
          : `<p class="small">VEYRS will be able to queue and run scans again through its enrolled agents.</p>
             <div><label>Reason</label><input name="reason" placeholder="Bringing the internal runner back"></div>`,
        actions: [{ label: on ? 'Turn off' : 'Turn on' }],
      });
      if (!r) return;
      try {
        await put('/scanning', {
          active_scanning_enabled: !on,
          reason: r.reason || null,
          cancel_queued_jobs: on ? r.cancel !== false : false,
        });
        // Move the in-memory flag before re-rendering. Waiting for the next
        // `/auth/me` would leave the operator looking at a menu that still
        // offers the page they just switched off -- and the obvious next move,
        // a reload, is the one thing that hides the confirmation too.
        activeScanning = !on;
        ok(on
          ? 'Active scanning is off. VEYRS is now ingest-only, and the scanner screens have left the menu.'
          : 'Active scanning is back on, and the scanner is back in the menu.');
        render();
      } catch (e) { err(e.detail); }
    };
  } else if (tab === 'secrets') {
    await secretStorageTab(body);
  } else {
    const o = await get('/organization');
    body.innerHTML = `<div class="card" style="max-width:600px"><h2>Details</h2>
      <form id="org"><label>Name</label><input name="name" value="${esc(o.name || '')}">
      <label class="mt-3">Slug</label><input value="${esc(o.slug || '')}" disabled>
      <label class="mt-3">Default locale</label>
      <select name="default_locale">${['en', 'es', 'de', 'fr', 'it'].map(l => `<option value="${l}" ${o.default_locale === l ? 'selected' : ''}>${l.toUpperCase()}</option>`).join('')}</select>
      <button class="btn btn-primary btn-block" type="submit">Save</button></form>
      <dl class="kv mt-5"><dt>Organization ID</dt><dd class="mono">${esc(o.id)}</dd>
      <dt>Created</dt><dd>${fmtDate(o.created_at)}</dd></dl></div>
      <div class="card mt-4" style="max-width:600px" id="mfa-policy-card"><div class="loading">Loading…</div></div>`;
    $('#org').onsubmit = async e => {
      e.preventDefault();
      try { await patch('/organization', { name: e.target.name.value, default_locale: e.target.default_locale.value }); ok('Saved.'); } catch (ex) { err(ex.detail); }
    };
    await mfaPolicyCard($('#mfa-policy-card'));
  }
});

/* ── Global search ──────────────────────────────────────────────────── */


/* ══ Wiring ════════════════════════════════════════════════════════════ */

/* Top-level element wiring goes through on(): a single missing element would
   otherwise throw here, abort the module BEFORE boot() runs, and leave both
   #login and #shell hidden -- a blank white page with nothing on screen to
   say why. tests/test_phase31_console_wiring.py keeps the ids honest. */
const on = (sel, ev, fn) => { const el = $(sel); if (el) el.addEventListener(ev, fn); };

on('#login-form', 'submit', async e => {
  e.preventDefault();
  const errBox = $('#login-error');
  errBox.hidden = true;
  const org = $('#l-org').value.trim();
  /* `identifier` accepts a username OR an email address. `organization` is the
     field the API has always declared -- the console sent `organization_slug`,
     pydantic dropped the extra key, and the Organization box on this form had
     never done anything. The backend now accepts both spellings so older
     clients keep working; this one sends the declared name. */
  const payload = { identifier: $('#l-email').value.trim(), password: $('#l-pass').value, organization: org };
  const mfa = $('#l-mfa').value.trim();
  if (mfa) payload.mfa_code = mfa;
  // The answer to a RADIUS Access-Challenge carries the id VEYRS handed out.
  if (mfa && window.__radiusChallenge) payload.radius_challenge = window.__radiusChallenge;
  try {
    const tok = await api('/auth/login', { method: 'POST', body: JSON.stringify(payload) });
    store.save(tok, org);
    if (tok.mfa_enrollment_required) { enrolmentScreen(); return; }
    const me = await get('/auth/me');
    await enterApp(me);
  } catch (ex) {
    /* The API answers a password that needs a second factor with
       {error: 'mfa_required', method, sent_to}; api() hands that over as JSON
       text. For e-mail and Telegram the code has ALREADY been sent. */
    let info = null;
    try { info = JSON.parse(ex.detail).detail; } catch { /* a plain message */ }
    let msg = ex.detail || 'Sign-in failed.';
    window.__radiusChallenge = null;   // single use: a new round needs a new challenge
    if (info && info.error === 'mfa_required') {
      $('#l-mfa-wrap').hidden = false; $('#l-mfa').focus();
      const to = info.sent_to ? ` to ${info.sent_to}` : '';
      if (info.method === 'radius') window.__radiusChallenge = info.radius_challenge;
      $('#l-mfa-label').textContent = info.method === 'radius' ? (info.message || 'Code')
        : info.method === 'totp' ? 'Code from your authenticator app'
        : info.method === 'telegram' ? 'Code from Telegram' : 'Code from your e-mail';
      $('#l-mfa').value = '';
      msg = info.method === 'radius' ? (info.message || 'Your authentication server asks for a code.')
        : info.method === 'totp' ? 'Enter the 6-digit code from your authenticator app.'
        : info.throttled ? `A code was sent moments ago${to}: use it, or try again in ${info.retry_after || 30} s for a new one.`
        : `We sent a code${to}. It expires in a few minutes.`;
    } else if (info && info.error === 'mfa_delivery_failed') {
      msg = 'Your sign-in code could not be sent: ' + (info.message || 'delivery failed') + '. Use a recovery code, or ask an administrator.';
      $('#l-mfa-wrap').hidden = false;
    }
    errBox.textContent = msg;
    errBox.hidden = false;
  }
});

on('#logout-btn', 'click', async () => {
  try { await post('/auth/logout', { refresh_token: store.rt }); } catch { /* local logout regardless */ }
  logout();
});

on('#search-form', 'submit', e => {
  e.preventDefault();
  const q = $('#q').value.trim();
  if (q) location.hash = '#/search?q=' + encodeURIComponent(q);
});

on('#notif-btn', 'click', () => { location.hash = '#/notifications'; });
on('#menu-btn', 'click', () => $('#sidebar').classList.toggle('open'));

/* The icon rail is a layout state on the shell, not on the sidebar, because
   the grid column it collapses is defined there. Disabled below 900px: the
   sidebar is already an off-canvas drawer at that width and a 68px rail
   permanently covering the content would be strictly worse than the drawer. */
function applyRail(on) {
  $('#shell').classList.toggle('rail', !!on);
  const b = $('#rail-btn');
  if (b) {
    // The button carries a drawn panel icon (0.38.0); its state is the title.
    b.title = on ? 'Expand sidebar' : 'Collapse sidebar';
    b.setAttribute('aria-label', b.title);
  }
}
applyRail(localStorage.getItem(NAV_LS.rail) === '1');
on('#rail-btn', 'click', () => {
  const rail = !$('#shell').classList.contains('rail');
  try { localStorage.setItem(NAV_LS.rail, rail ? '1' : '0'); } catch { /* private mode */ }
  applyRail(rail);
});

/* One delegated listener for both collapse levels. The item caret lives
   INSIDE its anchor so the row keeps a single hit target for navigation;
   that makes preventDefault mandatory here, or every collapse would also
   navigate. */
const navClick = e => {
  const toggle = e.target.closest('.nav-toggle[data-item]');
  if (toggle) {
    e.preventDefault();
    e.stopPropagation();
    const k = toggle.dataset.item;
    if (k === navCtx.name) return;
    navSelect(navOpen.items, k);
    navSave();
    renderNav(navCtx.name, navCtx.params);
    return;
  }
  const group = e.target.closest('.nav-group[data-group]');
  if (group) {
    const k = group.dataset.group;
    if (navGroupHoldsActive(k)) return;
    navSelect(navOpen.groups, k);
    navSave();
    renderNav(navCtx.name, navCtx.params);
  }
};
on('#nav', 'click', navClick);
on('#nav-pinned', 'click', navClick);
on('#theme-toggle', 'click', () => {
  const cur = document.documentElement.getAttribute('data-theme');
  const next = cur === 'dark' ? 'light' : 'dark';
  applyTheme(next);
  try { localStorage.setItem('veyrs.theme', next); } catch { /* private mode: applied, not remembered */ }
});

document.addEventListener('click', async e => {
  const b = e.target.closest('[data-read]');
  if (!b) return;
  try { await post(`/notifications/${b.dataset.read}/read`, {}); refreshNotifications(); render(); } catch { /* ignore */ }
});

/* Delegated actions. Inline on* attributes are deliberately absent so the
   console runs under a Content-Security-Policy without 'unsafe-inline'. */
const ACTIONS = {
  reload: () => location.reload(),
  newAsset: () => window.newAsset(),
  newTicket: () => window.newTicket(),
  uploadDoc: () => window.uploadDoc(),
  newArticle: () => window.newArticle(),
};
document.addEventListener('click', e => {
  const b = e.target.closest('[data-act]');
  if (b && ACTIONS[b.dataset.act]) { e.preventDefault(); ACTIONS[b.dataset.act](); }
});

window.addEventListener('hashchange', render);

/* ══════════════════════════════════════════════════════════════════════
   v0.22.0 — the disposition half of the product
   ──────────────────────────────────────────────────────────────────────
   Measured in production before any of this was written: 408 findings, of
   which 149 had never been touched and exactly ONE had reached `remediated`;
   5 tickets; 0 risk acceptances; 74 notifications generated and nothing that
   ever left the console; one of two users had not signed in for thirteen days.

   The ingestion half of VEYRS works. What did not exist was anywhere to make
   a decision, any way to keep the query you make it from, and any reason to
   come back tomorrow. Three additions, in that order:

     · #/triage      one finding, four decisions, no mouse required
     · saved views   the filter set survives the session
     · ⌘K + digest   reach the operator instead of waiting for them

   ══════════════════════════════════════════════════════════════════════ */

/* ══ "Not configured" vs "no results" ══════════════════════════════════
   Every list in this console rendered the same "Nothing here yet" whether the
   module had never been set up or the operator's filter simply matched
   nothing. Those are opposite situations: one needs a setup step, the other
   needs the Clear button. Conflating them is why a fresh deployment reads as a
   working one with an empty estate — and why an over-filtered list reads as a
   broken integration. `listView` now picks between them on whether any filter
   is applied, which is the only signal that distinguishes them. */
function notConfigured({ title, hint = '', steps = [] }) {
  return `<div class="not-configured">
    <strong>${esc(title)}</strong>
    ${hint ? `<p>${hint}</p>` : ''}
    ${steps.length ? `<ol class="nc-steps">${steps.map(s =>
      `<li>${s.href ? `<a href="${esc(s.href)}">${esc(s.label)}</a>` : `<strong>${esc(s.label)}</strong>`}
        ${s.note ? `<span class="muted"> — ${esc(s.note)}</span>` : ''}</li>`).join('')}</ol>` : ''}
  </div>`;
}

/* ══ Saved views ═══════════════════════════════════════════════════════
   A view names a query. It never answers one -- applying it goes back through
   `/findings`, which is permission- and team-scope aware -- so a shared,
   estate-wide view opened by a restricted operator shows their slice rather
   than 403ing or leaking somebody else's estate. */

const savedViews = { items: null, seeded: false };

async function loadViews({ force = false, seed = false } = {}) {
  if (savedViews.items && !force) return savedViews.items;
  try {
    const r = await get('/saved-views' + qs({ seed: seed ? 'true' : '' }));
    savedViews.items = r.items || [];
    if (seed) savedViews.seeded = true;
  } catch { savedViews.items = []; }     // never let a bookmark break a queue
  return savedViews.items;
}

/* Two filter sets are the same view when they ask the same question, so the
   comparison is over sorted key/value pairs and not over the URL text: the
   same query with its parameters in a different order must light the same
   chip, or the operator is told they left a view they are still inside. */
function sameFilters(a, b) {
  const norm = o => Object.entries(o || {})
    .filter(([, v]) => v !== '' && v !== null && v !== undefined)
    .map(([k, v]) => k + '=' + v).sort().join('&');
  return norm(a) === norm(b);
}

function viewChips(entity, active) {
  const rows = (savedViews.items || []).filter(v => v.entity === entity && v.is_pinned);
  if (!rows.length) return '';
  return `<div class="view-chips" role="group" aria-label="Saved views">
    ${rows.map(v => `<button type="button" class="chip${sameFilters(v.filters, active) ? ' chip-on' : ''}"
        data-view="${esc(v.id)}" title="${esc(v.description || Object.entries(v.filters).map(([k, x]) => k + '=' + x).join(' · '))}">
      ${esc(v.name)}${v.is_shared ? '<span class="chip-tag" title="Shared with the organization">shared</span>' : ''}
    </button>`).join('')}
  </div>`;
}

async function saveViewDialog(entity, filters, { existing = null } = {}) {
  if (!Object.keys(filters || {}).length && !existing) {
    err('Pick some filters first — an empty view is the unfiltered list.');
    return null;
  }
  const summary = Object.entries(filters || {}).map(([k, v]) =>
    `<code>${esc(k)}=${esc(v)}</code>`).join(' ') || '<em>no filters</em>';
  const form = await modal({
    title: existing ? 'Rename this view' : 'Save this view',
    body: `
      <p class="muted small">This view will re-run <strong>${esc(entity)}</strong> with ${summary}.
      It stores the question, not the answer: what you see when you open it is
      whatever your permissions and team scope allow at that moment.</p>
      <label>Name<input name="name" maxlength="120" value="${esc(existing ? existing.name : '')}" placeholder="Critical, internet-facing"></label>
      <label>Note (optional)<input name="description" maxlength="400" value="${esc(existing ? (existing.description || '') : '')}"></label>
      <label class="check"><input type="checkbox" name="is_shared" ${existing && existing.is_shared ? 'checked' : ''}>
        Share with everyone in this organization</label>
      <p class="small muted">Shared means <em>visible</em>. Only you can rename or delete it.</p>`,
    actions: [{ label: existing ? 'Rename' : 'Save view' }],
  });
  if (!form || !String(form.name || '').trim()) return null;
  try {
    const body = { name: form.name.trim(), description: form.description || null,
                   is_shared: !!form.is_shared };
    const row = existing
      ? await patch('/saved-views/' + existing.id, body)
      : await post('/saved-views', Object.assign({ entity, filters }, body));
    savedViews.items = null;
    await loadViews({ force: true });
    ok(existing ? 'View renamed.' : 'View saved.');
    return row;
  } catch (e) { err(e.detail || 'Could not save the view.'); return null; }
}

async function deleteViewDialog(view) {
  const confirmed = await modal({
    title: 'Delete this view?',
    body: `<p>“${esc(view.name)}” will be removed${view.is_shared
      ? ' for everyone it was shared with' : ''}. The findings it selects are untouched.</p>`,
    actions: [{ label: 'Delete', cls: 'btn-danger' }],
  });
  if (!confirmed) return false;
  try {
    await del('/saved-views/' + view.id);
    savedViews.items = null;
    await loadViews({ force: true });
    ok('View deleted.');
    return true;
  } catch (e) { err(e.detail || 'Could not delete the view.'); return false; }
}

/* ══ Triage queue ══════════════════════════════════════════════════════
   The console had every screen a vulnerability programme needs and no screen
   where a decision gets made. A list answers "how bad is it"; triage answers
   "what do I do with this one", and those want opposite layouts -- the first
   wants forty rows, the second wants one finding with enough context to judge
   it and the four verbs that dispose of it.

   Keyboard first, deliberately. 149 untriaged findings at four clicks each is
   an afternoon; the same queue at one keystroke each is twenty minutes, and
   the difference decides whether the backlog is ever cleared at all. */

const TRIAGE_QUEUES = [
  { key: 'new', label: 'Never triaged', q: { state: 'new', order: 'risk' },
    hint: 'Nobody has looked at these. This is the number that grows while you are away.' },
  { key: 'critical', label: 'Critical', q: { severity: 'critical', open_only: 'true', order: 'risk' },
    hint: 'Highest severity, still open, whatever their state.' },
  { key: 'kev', label: 'Known exploited', q: { kev: 'true', open_only: 'true', order: 'risk' },
    hint: 'CISA has observed these exploited in the wild. Severity is not the point; exploitation is.' },
  { key: 'sla', label: 'Past its deadline', q: { sla_breached: 'true', order: 'sla' },
    hint: 'Already late, oldest deadline first.' },
  { key: 'mine', label: "My teams' queue", q: { my_teams: 'true', open_only: 'true', order: 'risk' },
    hint: 'Owned by a team you belong to — explicit assignment first, the asset’s team otherwise.' },
];

const triage = { items: [], idx: 0, total: 0, page: 1, size: 50, filters: {}, done: 0, busy: false };

function triageFilters(params) {
  const viewId = params.get('view');
  if (viewId) {
    const v = (savedViews.items || []).find(x => x.id === viewId && x.entity === 'findings');
    if (v) return { filters: Object.assign({}, v.filters), label: v.name, view: v };
  }
  const key = params.get('queue') || 'new';
  const preset = TRIAGE_QUEUES.find(x => x.key === key) || TRIAGE_QUEUES[0];
  return { filters: Object.assign({}, preset.q), label: preset.label, preset };
}

async function triageFetch({ append = false } = {}) {
  const data = pageOf(await get('/findings' + qs(Object.assign(
    {}, triage.filters, { page: triage.page, size: triage.size }))));
  triage.total = data.total;
  triage.items = append ? triage.items.concat(data.items) : data.items;
}

function triageCard(f, detail) {
  const d = detail || {};
  const asset = d.asset || {};
  const cve = d.cve || {};
  const sla = d.sla || {};
  const factors = (d.risk_explanation && d.risk_explanation.factors) || [];
  const due = f.sla_due_at || d.sla_due_at;
  return `
    <article class="triage-card" aria-live="polite">
      <header class="triage-head">
        <div>
          <p class="triage-pills">${sevPill(f.severity)} ${statePill(f.state)}
            ${f.kev ? '<span class="pill pill-kev">Known exploited</span>' : ''}
            ${f.sla_breached ? '<span class="pill sev-critical">SLA breached</span>' : ''}</p>
          <h2>${esc(f.title || cve.cve_id || 'Finding')}</h2>
          <p class="muted small">
            ${asset.name ? `Asset <a href="#/assets/${esc(f.asset_id)}">${esc(asset.name)}</a>` : 'No asset'}
            ${asset.exposure ? ` · ${esc(titleCase(asset.exposure))}` : ''}
            ${asset.criticality ? ` · ${esc(titleCase(asset.criticality))} criticality` : ''}
            ${asset.environment ? ` · ${esc(titleCase(asset.environment))}` : ''}
          </p>
        </div>
        <div class="triage-score">
          <span class="triage-score-n">${fmtScore(f.risk_score)}</span>
          <span class="small muted">VEYRS risk${f.risk_level ? ' · ' + esc(titleCase(f.risk_level)) : ''}</span>
        </div>
      </header>

      <dl class="triage-facts">
        ${cve.cve_id ? `<div><dt>CVE</dt><dd><a href="#/intel/cve/${esc(cve.cve_id)}">${esc(cve.cve_id)}</a>
          ${cve.best_cvss_score != null ? ` · CVSS ${fmtScore(cve.best_cvss_score)}` : ''}</dd></div>` : ''}
        ${f.epss_score != null ? `<div><dt>EPSS</dt><dd>${fmtPct(f.epss_score, 2)} chance of exploitation in 30 days</dd></div>` : ''}
        <div><dt>Detected</dt><dd>${fmtDate(f.detected_at) || '—'}</dd></div>
        <div><dt>Deadline</dt><dd>${due ? fmtDate(due) : 'No SLA policy matched'}
          ${sla.percent_used != null ? ` · ${Math.round(sla.percent_used)}% used` : ''}</dd></div>
        <div><dt>Owner</dt><dd>${esc(f.owning_team_name || f.assigned_team_name || 'Nobody')}</dd></div>
      </dl>

      ${factors.length ? `<details class="triage-why"><summary>Why this score</summary>
        <ul>${factors.slice(0, 8).map(x => `<li>${esc(x.label || x.name || '')}: <strong>${esc(x.value ?? '')}</strong>
          ${x.detail ? `<span class="muted">— ${esc(x.detail)}</span>` : ''}</li>`).join('')}</ul></details>` : ''}

      ${d.recommendation ? `<div class="triage-fix"><h3>Recommended fix</h3><p>${esc(d.recommendation)}</p></div>` : ''}
      ${!d.recommendation && d.detail ? `<div class="triage-fix"><p class="muted">${esc(String(d.detail).slice(0, 600))}</p></div>` : ''}

      <footer class="triage-actions">
        <button class="btn btn-primary" data-tri="ticket"><kbd>T</kbd> ${externalTicketing() ? 'Raise issue' : 'Create ticket'}</button>
        <button class="btn" data-tri="assign"><kbd>A</kbd> Assign to team</button>
        <button class="btn" data-tri="false"><kbd>F</kbd> False positive</button>
        <button class="btn" data-tri="accept"><kbd>R</kbd> Accept risk</button>
        <button class="btn" data-tri="skip"><kbd>S</kbd> Skip</button>
        <a class="btn" href="#/findings/${esc(f.id)}"><kbd>↵</kbd> Full detail</a>
      </footer>
    </article>`;
}

async function triageRender(view) {
  const body = $('#triage-body', view);
  if (!body) return;
  if (triage.busy) return;
  if (triage.idx >= triage.items.length) {
    // The buffer is a page, not the queue. Fetch the next one before declaring
    // the queue clear, or an operator who worked fifty findings is told they
    // finished four hundred.
    if (triage.items.length < triage.total) {
      triage.page += 1;
      body.innerHTML = '<div class="loading">Loading more…</div>';
      await triageFetch({ append: true });
    }
  }
  const f = triage.items[triage.idx];
  if (!f) {
    body.innerHTML = `<div class="empty triage-empty"><strong>This queue is clear</strong>
      ${triage.done ? `You disposed of ${triage.done} finding${triage.done === 1 ? '' : 's'} in this sitting.` : 'Nothing is waiting here.'}
      <p class="small"><a href="#/triage?queue=critical">Critical</a> ·
      <a href="#/triage?queue=kev">Known exploited</a> ·
      <a href="#/triage?queue=sla">Past deadline</a> ·
      <a href="#/dashboard">Dashboards</a></p></div>`;
    return;
  }
  body.innerHTML = '<div class="loading">Loading…</div>';
  // Detail per card rather than per page: the list row carries no asset
  // context, no CVE and no recommendation, and triaging without them is
  // guessing. One request per decision is the cheapest honest option.
  let detail = null;
  try { detail = await get('/findings/' + f.id); } catch { detail = null; }
  body.innerHTML = triageCard(f, detail);
  const counter = $('#triage-count', view);
  if (counter) {
    counter.textContent = `${Math.min(triage.idx + 1, triage.total)} of ${fmtNum(triage.total)}`
      + (triage.done ? ` · ${triage.done} disposed this sitting` : '');
  }
}

async function triageAct(view, act) {
  const f = triage.items[triage.idx];
  if (!f || triage.busy) return;
  const drop = () => {
    // Remove rather than advance: the row no longer belongs to this queue, and
    // leaving it in the buffer means "12 of 149" counts work already done.
    triage.items.splice(triage.idx, 1);
    triage.total = Math.max(0, triage.total - 1);
    triage.done += 1;
  };
  try {
    triage.busy = true;
    if (act === 'skip') { triage.idx += 1; return; }

    if (act === 'ticket') {
      if (!can('ticket:write')) { err('Your role cannot create tickets.'); return; }
      const r = await openRemediationForFinding(f);
      ok(r.kind === 'external'
        ? `${r.reference} ${r.created ? 'raised' : 'already open'} in the external system.`
        : `Ticket ${r.reference || ''} ${r.created ? 'created' : 'already open'}.`);
      drop();
      return;
    }

    if (act === 'assign') {
      const choice = await assignDialog({
        title: 'Assign this finding',
        note: 'Routing it to a team does not change its state. It changes whose queue it is in.',
        extraUser: true,
      });
      if (!choice) return;
      // `assignDialog` speaks the dialog's language (`team`, `user`, `reason`),
      // not the API's. Passing it through unmapped sends `team=` — which the
      // route ignores, so it would answer 200 having assigned nothing.
      const payload = { finding_ids: [f.id], reason: choice.reason || null };
      if (choice.team === '__clear__') payload.clear = ['assigned_team_id'];
      else if (choice.team) payload.assigned_team_id = choice.team;
      if (choice.user) payload.assigned_user_id = choice.user;
      const res = await post('/findings/bulk-assign', payload);
      if (!res.changed_count) { err('Nothing changed — pick a team or a person.'); return; }
      ok('Assigned.');
      drop();
      return;
    }

    if (act === 'false') {
      const form = await modal({
        title: 'Mark as a false positive',
        body: `<p class="muted small">This closes the finding. If the same scan reports it again it
          comes back as new — VEYRS does not remember a verdict across detections, so write down
          <em>why</em> or the next person repeats your work.</p>
          <label>Reason<textarea name="note" rows="3" placeholder="Not exploitable: the vulnerable module is not loaded."></textarea></label>`,
        actions: [{ label: 'Mark false positive' }],
      });
      if (!form) return;
      await post(`/findings/${f.id}/transition`, { state: 'false_positive', note: form.note || null });
      ok('Closed as a false positive.');
      drop();
      return;
    }

    if (act === 'accept') {
      if (!can('risk:admin')) {
        err('Accepting a risk needs risk:admin — that is deliberate, it is a business decision.');
        return;
      }
      const form = await modal({
        title: 'Formally accept this risk',
        body: `<p class="muted small">The finding stays visible and stays counted; it stops being
          work. Give it an expiry unless the risk really is permanent — an acceptance with no end
          date is how a decision made under one set of facts outlives them.</p>
          ${f.state === 'new' ? `<p class="explainer-warn">This finding has never been triaged.
            VEYRS will move it to <strong>triaged</strong> first, because the lifecycle has no
            edge from <code>new</code> straight to <code>accepted_risk</code>.</p>` : ''}
          <label>Reason (10 characters minimum)<textarea name="reason" rows="3"
            placeholder="Compensating control: the host is not reachable from outside the management VLAN."></textarea></label>
          <label>Expires<input type="date" name="until"></label>`,
        actions: [{ label: 'Accept the risk' }],
      });
      if (!form) return;
      const reason = String(form.reason || '').trim();
      if (reason.length < 10) { err('The reason has to say something — 10 characters minimum.'); return; }
      if (f.state === 'new') {
        await post(`/findings/${f.id}/transition`, { state: 'triaged', note: 'Triaged for risk acceptance' });
      }
      await post(`/findings/${f.id}/accept-risk` + qs({ reason, until: form.until || '' }), {});
      ok('Risk accepted and recorded.');
      drop();
      return;
    }
  } catch (e) {
    err(e.detail || 'That action failed.');
  } finally {
    triage.busy = false;
    await triageRender(view);
  }
}

route('triage', async (view, _parts, params) => {
  await loadViews({ seed: true });
  const { filters, label, view: savedView, preset } = triageFilters(params);
  triage.filters = filters;
  triage.idx = 0; triage.page = 1; triage.done = 0; triage.items = []; triage.busy = false;

  const tab = q => '#/triage?queue=' + q;
  view.innerHTML = `
    <div class="page-head"><div><h1>Triage queue</h1>
      <p>One finding, four decisions. ${esc(preset ? preset.hint : (savedView && savedView.description) || 'A saved view of the finding queue.')}</p></div>
      <div class="page-actions">
        <button class="btn btn-sm" id="tri-save">Save this view</button>
        ${savedView ? `<button class="btn btn-sm" id="tri-del">Delete view</button>` : ''}
        <a class="btn btn-sm" href="#/findings">Open as a list</a>
      </div></div>
    ${explainer('triage', {
      title: 'What this screen is for',
      what: 'It hands you the open findings of one queue, one at a time, with the context needed to judge them: the asset and how exposed it is, the CVE, the exploitation signals, the deadline and the recommended fix.',
      who: 'Whoever owns the daily backlog — a security analyst or the owning team’s engineer.',
      effect: 'Every button here is a real state change: a ticket opens remediation work with an SLA, “false positive” closes the finding, “accept risk” records a formal, audited decision. Nothing is a draft.',
      warn: 'Keyboard: <kbd>T</kbd> ticket · <kbd>A</kbd> assign · <kbd>F</kbd> false positive · <kbd>R</kbd> accept risk · <kbd>S</kbd> skip · <kbd>J</kbd>/<kbd>K</kbd> move · <kbd>↵</kbd> full detail.',
      links: [{ href: '#/guide', label: 'How scanning, risk and tickets connect' }],
    })}
    ${scopeBanner()}
    <div class="triage-bar">
      <div class="tabs tabs-inline">
        ${TRIAGE_QUEUES.map(qq => `<a class="${!savedView && qq.key === (params.get('queue') || 'new') ? 'active' : ''}" href="${tab(qq.key)}">${esc(qq.label)}</a>`).join('')}
      </div>
      <span class="mono small" id="triage-count">—</span>
    </div>
    ${viewChips('findings', filters)}
    <div id="triage-body"><div class="loading">Loading…</div></div>`;

  const chips = $('.view-chips', view);
  if (chips) chips.onclick = e => {
    const b = e.target.closest('[data-view]');
    if (b) location.hash = '#/triage?view=' + encodeURIComponent(b.dataset.view);
  };
  const saveBtn = $('#tri-save', view);
  if (saveBtn) saveBtn.onclick = () => saveViewDialog('findings', triage.filters).then(v => {
    if (v) location.hash = '#/triage?view=' + encodeURIComponent(v.id);
  });
  const delBtn = $('#tri-del', view);
  if (delBtn) delBtn.onclick = () => deleteViewDialog(savedView).then(done => {
    if (done) location.hash = '#/triage';
  });

  await triageFetch();
  await triageRender(view);

  const bodyEl = $('#triage-body', view);
  bodyEl.addEventListener('click', e => {
    const b = e.target.closest('[data-tri]');
    if (b) triageAct(view, b.dataset.tri);
  });
});

/* Keyboard is bound once on the document and gated on the route, not attached
   per render: `render()` replaces #view wholesale, and a listener re-attached
   by each navigation is a listener that fires twice after two navigations. */
document.addEventListener('keydown', e => {
  if (navCtx.name !== 'triage') return;
  if (e.metaKey || e.ctrlKey || e.altKey) return;
  const t = e.target;
  if (t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT'
            || t.isContentEditable)) return;
  if ($('.modal-backdrop')) return;         // a dialog owns the keyboard
  const view = $('#view');
  const f = triage.items[triage.idx];
  const map = { t: 'ticket', a: 'assign', f: 'false', r: 'accept', s: 'skip' };
  const key = e.key.toLowerCase();
  if (map[key]) { e.preventDefault(); triageAct(view, map[key]); return; }
  if (key === 'j' || e.key === 'ArrowDown') { e.preventDefault(); triage.idx += 1; triageRender(view); return; }
  if (key === 'k' || e.key === 'ArrowUp') { e.preventDefault(); triage.idx = Math.max(0, triage.idx - 1); triageRender(view); return; }
  if (e.key === 'Enter' && f) { e.preventDefault(); location.hash = '#/findings/' + f.id; }
});

/* ══ Command palette (⌘K / Ctrl-K) ═════════════════════════════════════
   Twenty-eight screens behind seven collapsed nav groups is a product you have
   to learn before you can use it. The palette is the second answer to that,
   after the nav split in v0.21.0: type what you want, not where it lives.

   It searches the same permission-aware endpoint the Search page uses, so it
   cannot surface a row the caller may not read. */

const palette = { el: null, items: [], sel: 0, seq: 0 };

function paletteCommands() {
  const out = [];
  NAV.forEach(group => (group.items || []).forEach(item => {
    if (item.perm && !can(item.perm)) return;
    // The palette is the second door into every screen. Filtering the nav and
    // not this would leave a hidden page one Ctrl-K away, which is worse than
    // not hiding it: the menu would be lying rather than merely tidy.
    if (item.scan && !activeScanning) return;
    if (item.reg && !riskRegisterOn) return;
    if (item.hidden !== true) {
      out.push({ kind: group.group, label: item.label, href: '#/' + item.path });
    }
    (item.children || []).forEach(child => out.push({
      kind: group.group, label: item.label + ' › ' + child.label, href: navChildHref(child),
    }));
  }));
  TRIAGE_QUEUES.forEach(q => out.push({
    kind: 'Triage', label: 'Triage: ' + q.label, href: '#/triage?queue=' + q.key,
  }));
  (savedViews.items || []).filter(v => v.entity === 'findings').forEach(v => out.push({
    kind: 'Saved view', label: v.name, href: '#/triage?view=' + encodeURIComponent(v.id),
  }));
  out.push({ kind: 'Action', label: 'Toggle light / dark theme', run: () => {
    const next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    applyTheme(next);
    try { localStorage.setItem('veyrs.theme', next); } catch { /* private mode */ }
  } });
  out.push({ kind: 'Action', label: 'Sign out', run: () => logout() });
  return out;
}

/* Search hits come back grouped by entity type, not as a flat page:
   `{query, results: {cve: [...], asset: [...]}, total}`. Flattening is what
   turns them into rows -- reading `.items` off that envelope yields an empty
   list for a search that matched, which is what the Search page did until now. */
function flattenSearch(payload) {
  const results = (payload && payload.results) || {};
  const href = {
    cve: r => '#/intel/cve/' + encodeURIComponent(r.id),
    vulnerability: r => '#/vulnerabilities/' + r.id,
    finding: r => '#/findings/' + r.id,
    asset: r => '#/assets/' + r.id,
    ticket: r => '#/tickets/' + r.id,
    document: r => '#/documents/' + r.id,
    knowledge: r => '#/knowledge/' + r.id,
    product: () => null,
    news: () => null,
  };
  const label = {
    cve: r => r.id, vulnerability: r => r.cve_id || r.title, finding: r => r.title,
    asset: r => r.name, ticket: r => (r.reference ? r.reference + ' — ' : '') + (r.title || ''),
    document: r => r.filename, knowledge: r => r.title || r.slug, product: r => r.name,
    news: r => r.title,
  };
  const sub = {
    cve: r => [r.kev ? 'KEV' : '', r.score != null ? 'CVSS ' + r.score : '',
               (r.title || '').slice(0, 80)].filter(Boolean).join(' · '),
    vulnerability: r => [r.risk_level, r.risk_score != null ? 'risk ' + fmtScore(r.risk_score) : ''].filter(Boolean).join(' · '),
    finding: r => [titleCase(r.state), r.risk_score != null ? 'risk ' + fmtScore(r.risk_score) : '',
                   r.sla_breached ? 'SLA breached' : ''].filter(Boolean).join(' · '),
    asset: r => [r.type, r.criticality, r.exposure].filter(Boolean).map(titleCase).join(' · '),
    ticket: r => titleCase(r.state || ''),
    document: r => [r.class, (r.snippet || '').slice(0, 80)].filter(Boolean).join(' · '),
    knowledge: r => (r.summary || '').slice(0, 80),
    product: r => r.type || '',
    news: r => r.source || '',
  };
  const out = [];
  Object.entries(results).forEach(([type, rows]) => (rows || []).forEach(r => {
    const to = (href[type] || (() => null))(r);
    out.push({
      kind: titleCase(type), label: String((label[type] || (x => x.id))(r) || '').slice(0, 120),
      sub: (sub[type] || (() => ''))(r), href: to,
      // A product or a news item has no console page of its own. Sending it to
      // the Search results page is honest; a dead `#` teaches people the
      // palette is decorative.
      fallback: '#/search?q=' + encodeURIComponent(payload.query || ''),
    });
  }));
  return out;
}

function paletteClose() {
  if (palette.el) { palette.el.remove(); palette.el = null; }
}

function paletteRender() {
  const list = $('#pal-list', palette.el);
  if (!list) return;
  if (!palette.items.length) {
    list.innerHTML = '<li class="pal-none">Nothing matched. Try a CVE id, a hostname or a ticket reference.</li>';
    return;
  }
  list.innerHTML = palette.items.map((it, i) => `
    <li class="pal-row${i === palette.sel ? ' on' : ''}" data-i="${i}" role="option" aria-selected="${i === palette.sel}">
      <span class="pal-kind">${esc(it.kind)}</span>
      <span class="pal-label">${esc(it.label)}</span>
      ${it.sub ? `<span class="pal-sub">${esc(it.sub)}</span>` : ''}
    </li>`).join('');
  const on = list.querySelector('.on');
  if (on) on.scrollIntoView({ block: 'nearest' });
}

function paletteRun(i) {
  const it = palette.items[i];
  if (!it) return;
  paletteClose();
  if (it.run) return it.run();
  const to = it.href || it.fallback;
  if (!to) return;
  // Navigating to the hash you are already on fires no `hashchange`, so the
  // palette would close over an unchanged screen and look broken.
  if (location.hash === to) render(); else location.hash = to;
}

async function paletteSearch(term) {
  const commands = paletteCommands().filter(c =>
    c.label.toLowerCase().includes(term.toLowerCase()) ||
    c.kind.toLowerCase().includes(term.toLowerCase()));
  if (!term) { palette.items = commands.slice(0, 12); palette.sel = 0; paletteRender(); return; }
  palette.items = commands.slice(0, 6);
  palette.sel = 0;
  paletteRender();
  const seq = ++palette.seq;
  let hits = [];
  try { hits = flattenSearch(await get('/search' + qs({ q: term, limit_per_type: 5 }))); }
  catch { hits = []; }
  // A slower earlier keystroke must not overwrite a faster later one.
  if (seq !== palette.seq || !palette.el) return;
  palette.items = commands.slice(0, 6).concat(hits.slice(0, 24));
  palette.sel = 0;
  paletteRender();
}

function paletteOpen() {
  if (palette.el) { $('#pal-input', palette.el).focus(); return; }
  const el = document.createElement('div');
  el.className = 'pal-backdrop';
  el.innerHTML = `
    <div class="pal" role="dialog" aria-modal="true" aria-label="Command palette">
      <input id="pal-input" placeholder="Jump to a screen, or search a CVE, asset, finding or ticket…"
             autocomplete="off" spellcheck="false" role="combobox" aria-expanded="true" aria-controls="pal-list">
      <ul id="pal-list" class="pal-list" role="listbox"></ul>
      <footer class="pal-foot"><kbd>↑</kbd><kbd>↓</kbd> move · <kbd>↵</kbd> open · <kbd>esc</kbd> close</footer>
    </div>`;
  document.body.appendChild(el);
  palette.el = el;
  const input = $('#pal-input', el);
  let timer = null;
  input.addEventListener('input', () => {
    clearTimeout(timer);
    timer = setTimeout(() => paletteSearch(input.value.trim()), 160);
  });
  el.addEventListener('click', e => {
    if (e.target === el) return paletteClose();
    const row = e.target.closest('[data-i]');
    if (row) paletteRun(Number(row.dataset.i));
  });
  input.addEventListener('keydown', e => {
    if (e.key === 'Escape') { e.preventDefault(); return paletteClose(); }
    if (e.key === 'ArrowDown') { e.preventDefault(); palette.sel = Math.min(palette.items.length - 1, palette.sel + 1); return paletteRender(); }
    if (e.key === 'ArrowUp') { e.preventDefault(); palette.sel = Math.max(0, palette.sel - 1); return paletteRender(); }
    if (e.key === 'Enter') { e.preventDefault(); return paletteRun(palette.sel); }
  });
  paletteSearch('');
  input.focus();
}

document.addEventListener('keydown', e => {
  if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
    // Only inside the app: on the login screen there is nothing to jump to and
    // no token to search with.
    if ($('#shell') && $('#shell').hidden) return;
    e.preventDefault();
    paletteOpen();
  }
});

/* ══ Search page ═══════════════════════════════════════════════════════
   Re-registered over the v0.21.0 version, which read `.items` off an envelope
   that has never carried one. Every search rendered "No matches", including
   the ones that matched. */
route('search', async (view, _p, params) => {
  const q = params.get('q') || '';
  view.innerHTML = `<div class="page-head"><div><h1>Search</h1>
    <p>Permission-aware across CVEs, vulnerabilities, findings, assets, products, tickets,
    documents and articles. A result you are not entitled to is never returned — not hidden,
    not returned.</p></div>
    <div class="page-actions"><button class="btn btn-sm" id="open-pal">Open the palette (⌘K)</button></div></div>
    <div id="s-body"><div class="loading">Searching…</div></div>`;
  const palBtn = $('#open-pal', view);
  if (palBtn) palBtn.onclick = () => paletteOpen();
  if (!q) {
    $('#s-body').innerHTML = `<div class="empty"><strong>Type a query in the bar above</strong>
      A CVE id, a hostname, a ticket reference or any word in a finding title.</div>`;
    return;
  }
  const [lex, sem] = await Promise.all([
    get('/search' + qs({ q, limit_per_type: 10 })).catch(e => ({ results: {}, error: e.detail })),
    get('/search/semantic' + qs({ q, limit: 10 })).catch(() => ({ results: {} })),
  ]);
  const rows = flattenSearch(lex);
  const semRows = flattenSearch(sem).filter(r => !rows.some(x => x.href && x.href === r.href));
  const cols = [
    { label: 'Type', cell: r => `<span class="pill st-neutral">${esc(r.kind)}</span>` },
    { label: 'Match', cell: r => r.href ? `<a href="${esc(r.href)}">${esc(r.label)}</a>` : esc(r.label) },
    { label: 'Context', cell: r => esc(r.sub || '') },
  ];
  const denied = (lex.denied_types || []);
  $('#s-body').innerHTML = `
    <div class="card"><h2>Results for “${esc(q)}”</h2>
      ${lex.error ? `<p class="form-error">${esc(lex.error)}</p>` : ''}
      ${table(cols, rows, { emptyTitle: 'No matches',
                            emptyHint: 'Lexical search is exact-ish on purpose: a CVE id has to find that CVE.' })}
      ${denied.length ? `<p class="small muted">Not searched, because your role cannot read them:
        ${denied.map(d => esc(titleCase(d))).join(', ')}.</p>` : ''}</div>
    ${semRows.length ? `<div class="card mt-4">
      <h2>Semantically related${sem.mode === 'lexical' ? ' <span class="pill st-neutral">lexical fallback</span>' : ''}</h2>
      ${sem.note ? `<p class="small muted">${esc(sem.note)}</p>` : ''}
      ${table(cols, semRows)}</div>` : ''}`;
});

/* ══ Notifications, preferences and the daily digest ═══════════════════
   The list this replaces read `created_at`, `kind`, `message` and `title`.
   `GET /notifications` returns `at`, `event`, `subject` and `body`, and has
   since it was written — so every row rendered with three blank columns, and
   its "Mark read" button was never wired to anything. Same defect family as
   the Integrations page in v0.19.0: a surface that renders perfectly, is
   wrong, and never changes a status code. */

const NOTIF_TABS = ['inbox', 'preferences', 'digest'];

route('notifications', async (view, _p, params) => {
  const tab = NOTIF_TABS.includes(params.get('tab')) ? params.get('tab') : 'inbox';
  view.innerHTML = `
    <div class="page-head"><div><h1>Notifications</h1>
      <p>What VEYRS told you, what it is allowed to tell you, and what it sends without being asked.</p></div></div>
    <div class="tabs">
      ${NOTIF_TABS.map(t => `<button data-t="${t}" class="${t === tab ? 'active' : ''}">${esc(titleCase(t))}</button>`).join('')}
    </div><div id="n-body"><div class="loading">Loading…</div></div>`;
  view.querySelector('.tabs').onclick = e => {
    if (e.target.dataset.t) location.hash = '#/notifications?tab=' + e.target.dataset.t;
  };
  const body = $('#n-body', view);
  if (tab === 'inbox') return notifInbox(body);
  if (tab === 'preferences') return notifPreferences(body);
  return notifDigest(body);
});

async function notifInbox(body) {
  const data = await get('/notifications' + qs({ page: 1, size: 50 }));
  const rows = data.items || [];
  body.innerHTML = `
    <div class="card">
      <div class="row-between"><h2>Inbox</h2>
        <span class="mono small">${fmtNum(data.unread || 0)} unread of ${fmtNum(data.total || 0)}</span></div>
      ${table([
        { label: 'When', cell: r => fmtDate(r.at) },
        { label: 'Event', cell: r => `<span class="pill st-neutral mono">${esc(r.event)}</span>` },
        { label: 'Message', cell: r => `<strong>${esc(r.subject)}</strong>${r.body
            ? `<div class="small muted pre-wrap">${esc(String(r.body).slice(0, 400))}</div>` : ''}` },
        { label: 'Links', cell: r => [
            r.finding_id ? `<a href="#/findings/${esc(r.finding_id)}">Finding</a>` : '',
            r.ticket_id ? `<a href="#/tickets/${esc(r.ticket_id)}">Ticket</a>` : '',
          ].filter(Boolean).join(' · ') || '—' },
        { label: '', cell: r => r.read_at
            ? `<span class="small muted">read ${fmtShortDate(r.read_at)}</span>`
            : `<button class="btn btn-sm" data-read="${esc(r.id)}">Mark read</button>` },
      ], rows, { emptyTitle: 'Nothing yet',
                 emptyHint: 'In-app messages appear here when a finding is raised, an SLA is at risk, or a ticket moves.' })}
    </div>`;
  body.onclick = async e => {
    const b = e.target.closest('[data-read]');
    if (!b) return;
    try { await post(`/notifications/${b.dataset.read}/read`, {}); b.replaceWith(document.createTextNode('read')); refreshNotifications(); }
    catch (ex) { err(ex.detail || 'Could not mark it read.'); }
  };
}

async function notifPreferences(body) {
  const data = await get('/notifications/preferences');
  body.innerHTML = `
    ${explainer('notif-prefs', {
      title: 'What you can and cannot switch off',
      what: 'Per-event delivery, per channel, for you alone. Nobody else’s inbox is affected.',
      who: 'Every user, for themselves.',
      effect: 'Turning a channel off stops that message reaching you from the moment you save it. Messages already queued are still delivered — the queue is a record of what VEYRS decided to tell you, not a draft folder.',
      warn: 'SLA breaches and escalations ignore this screen entirely. A product whose alerts can be silently switched off is worse than one with no alerts.',
    })}
    <div class="card"><h2>My delivery preferences</h2>
      ${table([
        { label: 'Event', cell: r => `<span class="mono">${esc(r.event)}</span>` },
        { label: 'In-app', cell: r => `<label class="check"><input type="checkbox" data-pref="${esc(r.event)}"
            data-ch="in_app" ${r.in_app ? 'checked' : ''}></label>` },
        { label: 'Email', cell: r => `<label class="check"><input type="checkbox" data-pref="${esc(r.event)}"
            data-ch="email" ${r.email ? 'checked' : ''}></label>` },
        { label: '', cell: r => r.explicit ? '<span class="small muted">changed</span>' : '<span class="small muted">default</span>' },
      ], data.events || [], { emptyTitle: 'No events' })}
    </div>
    <div class="card mt-4"><h2>Always delivered</h2>
      <p class="muted small">These ignore preferences by design.</p>
      <p>${(data.unmutable || []).map(e2 => `<span class="pill st-neutral mono">${esc(e2)}</span>`).join(' ')}</p>
    </div>`;
  body.onchange = async e => {
    const box = e.target.closest('[data-pref]');
    if (!box) return;
    const event = box.dataset.pref;
    const row = box.closest('tr');
    const wanted = {
      event,
      in_app: $(`[data-pref="${event}"][data-ch="in_app"]`, row).checked,
      email: $(`[data-pref="${event}"][data-ch="email"]`, row).checked,
    };
    try { await put('/notifications/preferences', wanted); ok('Saved.'); }
    catch (ex) { err(ex.detail || 'Could not save.'); box.checked = !box.checked; }
  };
}

async function notifDigest(body) {
  const admin = can('notification:admin');
  const [policy, preview] = await Promise.all([
    get('/notifications/digest').catch(() => null),
    post('/notifications/digest/preview', {}).catch(() => null),
  ]);
  const c = (preview && preview.counts) || {};
  body.innerHTML = `
    ${explainer('digest', {
      title: 'The daily digest',
      what: 'One message a day per person: what arrived, what is late, what is being exploited, and what nobody has looked at — each recipient’s own slice of it.',
      who: 'An administrator turns it on for the organization; each user can mute it for themselves under Preferences.',
      effect: 'From the next scheduled hour, every user whose role can read findings starts receiving it on the channels you pick. Somebody with nothing to report is skipped rather than sent an empty message — that is what keeps the one that matters from being deleted unread.',
      warn: 'Email needs SMTP configured on the API host. With no transport the messages queue, stay visible in-app, and retry — they are not lost, but they do not arrive either.',
    })}
    ${preview ? `<h2 class="section-h">What yours would say right now</h2>
      <div class="grid cols-4">
        <div class="card stat"><span class="label">New (${esc(preview.min_severity)}+)</span><span class="value">${fmtNum(c.new_findings)}</span><span class="hint">in the last ${preview.window_hours} h</span></div>
        <div class="card stat ${tone('crit', c.sla_breached)}"><span class="label">Past deadline</span><span class="value">${fmtNum(c.sla_breached)}</span></div>
        <div class="card stat ${tone('warn', c.kev_open)}"><span class="label">Known exploited, open</span><span class="value">${fmtNum(c.kev_open)}</span></div>
        <div class="card stat"><span class="label">Never triaged</span><span class="value">${fmtNum(c.untriaged)}</span><span class="hint">${fmtNum(c.open_tickets)} open tickets</span></div>
      </div>
      <div class="card mt-4">
      ${preview.scope && preview.scope.restricted ? `<p class="small muted">These are your teams only — the digest is built under each recipient’s own scope, never once for the estate and fanned out.</p>` : ''}
      <details><summary>The message itself</summary><pre class="pre-wrap">${esc(preview.body || '')}</pre></details>
      ${preview.empty ? `<p class="small muted">Nothing to report: a digest in this state is <strong>not sent</strong>.</p>` : ''}
    </div>` : ''}
    ${policy ? `<div class="card mt-4">
      <div class="row-between"><h2>Organization policy</h2>
        <span class="pill ${policy.enabled ? 'st-succeeded' : 'st-neutral'}">${policy.enabled ? 'Enabled' : 'Disabled'}</span></div>
      <form id="dig-form" class="form-grid" ${admin ? '' : 'inert'}>
        <label class="check"><input type="checkbox" name="enabled" ${policy.enabled ? 'checked' : ''}> Send the daily digest</label>
        <label>Hour (UTC)<input type="number" name="hour" min="0" max="23" value="${esc(policy.hour)}"></label>
        <label>Look back (hours)<input type="number" name="window_hours" min="1" max="168" value="${esc(policy.window_hours)}"></label>
        <label>Minimum severity<select name="min_severity">
          ${['critical', 'high', 'medium', 'low'].map(s => `<option value="${s}" ${policy.min_severity === s ? 'selected' : ''}>${titleCase(s)}</option>`).join('')}
        </select></label>
        <label class="check"><input type="checkbox" name="ch_in_app" ${(policy.channels || []).includes('in_app') ? 'checked' : ''}> In-app</label>
        <label class="check"><input type="checkbox" name="ch_email" ${(policy.channels || []).includes('email') ? 'checked' : ''}> Email</label>
        ${admin ? `<div class="form-actions">
          <button class="btn btn-primary" type="submit">Save policy</button>
          <button class="btn" type="button" id="dig-dry">Preview the send</button>
          <button class="btn" type="button" id="dig-now">Send it now</button>
        </div>` : '<p class="small muted">Read-only: changing this needs notification:admin.</p>'}
      </form>
      <p class="small muted">Recipients: <strong>${fmtNum(policy.recipients)}</strong> — every active user whose role
      grants <code>finding:read</code>. Membership of a team does not add anybody: membership says whose queue
      something is, grants say what may be read.</p>
      ${policy.last_run_at ? `<p class="small muted">Last run ${fmtDate(policy.last_run_at)} · ${fmtNum(policy.last_recipients)} recipient(s).</p>` : ''}
    </div>` : '<div class="card"><p class="muted">Your role cannot read the digest policy.</p></div>'}`;

  const form = $('#dig-form', body);
  if (form && admin) {
    const read = () => {
      const o = {};
      $$('[name]', form).forEach(i => { o[i.name] = i.type === 'checkbox' ? i.checked : i.value; });
      const channels = [];
      if (o.ch_in_app) channels.push('in_app');
      if (o.ch_email) channels.push('email');
      return { enabled: o.enabled, hour: Number(o.hour), window_hours: Number(o.window_hours),
               min_severity: o.min_severity, channels };
    };
    form.onsubmit = async e => {
      e.preventDefault();
      try { await put('/notifications/digest', read()); ok('Digest policy saved.'); render(); }
      catch (ex) { err(ex.detail || 'Could not save the policy.'); }
    };
    const dry = $('#dig-dry', body);
    if (dry) dry.onclick = async () => {
      try {
        const r = await post('/notifications/digest/send' + qs({ dry_run: 'true' }), {});
        await modal({
          title: 'Nobody was sent anything',
          body: `<p>${fmtNum(r.recipients)} eligible recipient(s); ${fmtNum(r.skipped_empty)} had nothing to report and would be skipped.</p>
            ${table([{ label: 'Recipient', cell: x => esc(x.user) },
                     { label: 'Would send', cell: x => x.empty ? '<span class="muted">skipped — nothing to say</span>' : 'yes' },
                     { label: 'New', num: true, cell: x => fmtNum((x.counts || {}).new_findings) },
                     { label: 'Late', num: true, cell: x => fmtNum((x.counts || {}).sla_breached) }],
                    r.detail || [])}`,
          wide: true, actions: [],
        });
      } catch (ex) { err(ex.detail || 'Preview failed.'); }
    };
    const now = $('#dig-now', body);
    if (now) now.onclick = async () => {
      const go = await modal({
        title: 'Send the digest now?',
        body: `<p>This queues and delivers a message to every eligible recipient immediately,
          <strong>including the ones with nothing to report</strong> — an operator asking for it now
          is asking to see it. Per-user mutes are still honoured.</p>`,
        actions: [{ label: 'Send now', cls: 'btn-danger' }],
      });
      if (!go) return;
      try {
        const r = await post('/notifications/digest/send' + qs({ dry_run: 'false' }), {});
        ok(`Queued ${r.queued} message(s); dispatch ${JSON.stringify(r.dispatch || {})}`);
        refreshNotifications();
      } catch (ex) { err(ex.detail || 'Send failed.'); }
    };
  }
}

/* Last statement in the file, and the test that pins it is not pedantry:
   every route above must be registered before render() can be asked for one,
   and anything that throws after boot() leaves a half-initialised console
   rather than none at all. */
boot();
