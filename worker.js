// FixiT Dashboard - Cloudflare Worker

const ALLOWED_ORIGINS = [
  'https://fixit-dashboard.cuparius.workers.dev',
  'https://fixit-dashboard.cupra-s2027.workers.dev',
  'http://localhost:3000',
  'http://localhost:3002'
];

const BASE_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Cache-Control': 'no-store'
};

const HTML_SECURITY_HEADERS = {
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
};

const GITHUB_HTML = 'https://raw.githubusercontent.com/Cupra-S2027/fixit-dashboard/main/index.html';

function getCorsHeaders(request) {
  var origin = request.headers.get('Origin') || '';
  var headers = {
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Vary': 'Origin'
  };
  if (origin && ALLOWED_ORIGINS.indexOf(origin) !== -1) {
    headers['Access-Control-Allow-Origin'] = origin;
  }
  return headers;
}

function json(request, data, status) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: Object.assign({}, BASE_HEADERS, getCorsHeaders(request), { 'Content-Type': 'application/json; charset=utf-8' }),
  });
}

function b64(input) {
  return btoa(String.fromCharCode.apply(null, input))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function makeToken() {
  var bytes = crypto.getRandomValues(new Uint8Array(32));
  return b64(bytes);
}

async function sha256(input) {
  var encoded = new TextEncoder().encode(input);
  var digest = await crypto.subtle.digest('SHA-256', encoded);
  return b64(new Uint8Array(digest));
}

function sanitizeString(value, maxLen) {
  return String(value == null ? '' : value).trim().slice(0, maxLen || 500);
}

function sanitizeStatus(value) {
  var s = sanitizeString(value || 'pending', 24).toLowerCase();
  if (s === 'live' || s === 'onboarding' || s === 'pending' || s === 'offline') return s;
  return 'pending';
}

function sanitizeDate(value) {
  var v = sanitizeString(value, 32);
  return /^\d{4}-\d{2}-\d{2}$/.test(v) ? v : '';
}

function sanitizeNumber(value, min, max) {
  var n = Number(value);
  if (!isFinite(n)) return 0;
  if (typeof min === 'number' && n < min) n = min;
  if (typeof max === 'number' && n > max) n = max;
  return n;
}

function normalizeUserRole(role) {
  var raw = sanitizeString(role || '', 24).toLowerCase();
  return raw === 'admin' ? 'admin' : 'user';
}

function sanitizeCustomerInput(input, existing) {
  var base = existing ? Object.assign({}, existing) : {};
  var deckIn = input && input.deck ? input.deck : {};
  var out = Object.assign(base, {
    tenantKey: sanitizeString(input.tenantKey || input.erpId || base.tenantKey || '', 80),
    erpId: sanitizeString(input.erpId || input.tenantKey || base.erpId || '', 80),
    partnerKey: sanitizeString(input.partnerKey || base.partnerKey || '', 80),
    ownerUsername: sanitizeString(input.ownerUsername || base.ownerUsername || '', 64),
    name: sanitizeString(input.name || base.name || '', 140),
    status: sanitizeStatus(input.status || base.status || 'pending'),
    email: sanitizeString(input.email || base.email || '', 160),
    phone: sanitizeString(input.phone || base.phone || '', 60),
    goLive: sanitizeDate(input.goLive || base.goLive || ''),
    contact: sanitizeString(input.contact || base.contact || '', 120),
    plz: sanitizeString(input.plz || base.plz || '', 20),
    ort: sanitizeString(input.ort || base.ort || '', 120),
    category: sanitizeString(input.category || base.category || '', 120),
    notes: sanitizeString(input.notes || base.notes || '', 2000),
    portalLink: sanitizeString(input.portalLink || base.portalLink || '', 260),
    onboardingProgress: sanitizeNumber(input.onboardingProgress == null ? base.onboardingProgress : input.onboardingProgress, 0, 100),
    onboardingCompleted: !!(input.onboardingCompleted == null ? base.onboardingCompleted : input.onboardingCompleted),
    mrr: sanitizeNumber(input.mrr == null ? base.mrr : input.mrr, 0, 1000000000),
    activeContracts: sanitizeNumber(input.activeContracts == null ? base.activeContracts : input.activeContracts, 0, 1000000),
    fixitTenantId: input.fixitTenantId == null ? base.fixitTenantId : sanitizeNumber(input.fixitTenantId, 0, 1000000000),
    fixitLeadStatus: sanitizeString(input.fixitLeadStatus || base.fixitLeadStatus || '', 64),
    fixitOnboardingStatus: sanitizeString(input.fixitOnboardingStatus || base.fixitOnboardingStatus || '', 64),
    syncedAt: sanitizeString(input.syncedAt || new Date().toISOString(), 40),
    changeVersion: sanitizeString(input.changeVersion || base.changeVersion || '', 64),
    lastChangeSource: sanitizeString(input.lastChangeSource || base.lastChangeSource || '', 40),
    lastChangedAt: sanitizeString(input.lastChangedAt || base.lastChangedAt || '', 40),
    lastChangedBy: sanitizeString(input.lastChangedBy || base.lastChangedBy || '', 120),
    deck: {
      verwaltungsart: sanitizeString(deckIn.verwaltungsart || (base.deck || {}).verwaltungsart || '', 400),
      hinweise: sanitizeString(deckIn.hinweise || (base.deck || {}).hinweise || '', 2000),
      notfall: sanitizeString(deckIn.notfall || (base.deck || {}).notfall || '', 300),
      wording: sanitizeString(deckIn.wording || (base.deck || {}).wording || '', 1000),
      updated: sanitizeString(deckIn.updated || (base.deck || {}).updated || '', 40)
    }
  });
  if (!out.tenantKey && out.erpId) out.tenantKey = out.erpId;
  if (!out.erpId && out.tenantKey) out.erpId = out.tenantKey;
  return out;
}

async function parseJson(request) {
  try {
    return await request.json();
  } catch (_) {
    return null;
  }
}

async function hashPassword(password, salt) {
  return sha256(salt + ':' + password);
}

async function createPasswordRecord(password) {
  var salt = b64(crypto.getRandomValues(new Uint8Array(16)));
  var hash = await hashPassword(password, salt);
  return { passwordSalt: salt, passwordHash: hash };
}

async function verifyPassword(user, inputPassword) {
  if (!user || !inputPassword) return { ok: false, upgraded: false };
  if (user.passwordHash && user.passwordSalt) {
    var calc = await hashPassword(inputPassword, user.passwordSalt);
    return { ok: calc === user.passwordHash, upgraded: false };
  }
  if (user.password && user.password === inputPassword) {
    var rec = await createPasswordRecord(inputPassword);
    user.passwordHash = rec.passwordHash;
    user.passwordSalt = rec.passwordSalt;
    delete user.password;
    return { ok: true, upgraded: true };
  }
  return { ok: false, upgraded: false };
}

async function migrateLegacyPasswords(users) {
  var changed = false;
  var keys = Object.keys(users || {});
  for (var i = 0; i < keys.length; i++) {
    var key = keys[i];
    var u = users[key];
    if (!u) continue;
    if (u.password && (!u.passwordHash || !u.passwordSalt)) {
      var rec = await createPasswordRecord(String(u.password));
      u.passwordHash = rec.passwordHash;
      u.passwordSalt = rec.passwordSalt;
      delete u.password;
      if (!u.passwordChangedAt) u.passwordChangedAt = new Date().toISOString();
      changed = true;
    }
  }
  return changed;
}

async function getUsers(KV) {
  var data = await KV.get('users');
  if (!data) {
    var adminRec = await createPasswordRecord('fixit2026');
    var def = {
      admin: {
        passwordHash: adminRec.passwordHash,
        passwordSalt: adminRec.passwordSalt,
        role: 'admin',
        name: 'Admin',
        forcePasswordChange: false
      }
    };
    await KV.put('users', JSON.stringify(def));
    return def;
  }
  return JSON.parse(data);
}

async function getCustomers(KV) {
  var data = await KV.get('customers');
  return data ? JSON.parse(data) : [];
}

async function appendAuditLog(KV, actor, action, target, details) {
  var raw = await KV.get('audit_logs');
  var logs = raw ? JSON.parse(raw) : [];
  logs.unshift({
    at: new Date().toISOString(),
    actor: sanitizeString(actor || 'system', 64),
    action: sanitizeString(action || 'unknown', 80),
    target: sanitizeString(target || '', 140),
    details: details || {}
  });
  if (logs.length > 250) logs = logs.slice(0, 250);
  await KV.put('audit_logs', JSON.stringify(logs));
}

async function getAuditLogs(KV, limit) {
  var raw = await KV.get('audit_logs');
  var logs = raw ? JSON.parse(raw) : [];
  var max = sanitizeNumber(limit, 1, 100) || 30;
  return logs.slice(0, max);
}

async function getCustomerReads(KV) {
  var raw = await KV.get('customer_reads');
  if (!raw) return {};
  try {
    var parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch (_) {
    return {};
  }
}

async function markCustomerRead(KV, username, customerId, changeVersion) {
  if (!username || !customerId || !changeVersion) return;
  var reads = await getCustomerReads(KV);
  if (!reads[username] || typeof reads[username] !== 'object') {
    reads[username] = {};
  }
  reads[username][String(customerId)] = String(changeVersion);
  await KV.put('customer_reads', JSON.stringify(reads));
}

function annotateCustomerReadState(customer, username, reads) {
  var out = Object.assign({}, customer || {});
  var version = sanitizeString(out.changeVersion || '', 64);
  var seen = reads && reads[username] ? sanitizeString(reads[username][String(out.id)] || '', 64) : '';
  out.hasUnreadUpdate = !!version && seen !== version;
  return out;
}

function normalizeDashboardStatus(raw) {
  var s = (raw || '').toString().toLowerCase().trim();
  if (s === 'coming_soon' || s === 'pending') return 'pending';
  if (s === 'onboarding') return 'onboarding';
  if (s === 'live' || s === 'active') return 'live';
  if (s === 'offline') return 'offline';
  return 'onboarding';
}

function formatDateYYYYMMDD(isoDate) {
  if (!isoDate) return '';
  var d = new Date(isoDate);
  if (isNaN(d.getTime())) return '';
  var y = d.getUTCFullYear();
  var m = String(d.getUTCMonth() + 1).padStart(2, '0');
  var day = String(d.getUTCDate()).padStart(2, '0');
  return y + '-' + m + '-' + day;
}

function sanitizeCustomerForRead(customer, role) {
  var c = Object.assign({}, customer || {});
  var privileged = normalizeUserRole(role) === 'admin' || normalizeUserRole(role) === 'user';
  if (privileged) return c;

  // DSGVO-Minimierung für nicht-privilegierte Rollen
  return {
    id: c.id,
    tenantKey: c.tenantKey || '',
    erpId: c.erpId || '',
    name: c.name || '',
    status: c.status || 'pending',
    goLive: c.goLive || '',
    category: c.category || '',
    onboardingProgress: c.onboardingProgress || 0,
    onboardingCompleted: !!c.onboardingCompleted,
    mrr: c.mrr || 0,
    activeContracts: c.activeContracts || 0
  };
}

function normalizeScopeType(value, role) {
  var raw = sanitizeString(value || '', 24).toLowerCase();
  role = normalizeUserRole(role);
  if (role === 'admin') {
    return raw === 'all' ? 'all' : 'all';
  }
  if (raw === 'tenant') return raw;
  return 'all';
}

function getUserScope(username, user) {
  var role = normalizeUserRole(user && user.role ? user.role : 'user');
  var scopeType = normalizeScopeType(user && user.scopeType, role);
  return {
    role: role,
    scopeType: scopeType,
    partnerKey: sanitizeString(user && user.scopePartnerKey, 80),
    tenantKey: sanitizeString(user && user.scopeTenantKey, 80),
    username: sanitizeString(username || '', 64)
  };
}

function canReadCustomer(scope, customer) {
  if (!scope || !customer) return false;
  if (scope.scopeType === 'all') return true;
  if (scope.scopeType === 'partner') return !!scope.partnerKey && customer.partnerKey === scope.partnerKey;
  if (scope.scopeType === 'tenant') return !!scope.tenantKey && (customer.tenantKey === scope.tenantKey || customer.erpId === scope.tenantKey);
  return customer.ownerUsername === scope.username;
}

function restrictCustomerWrite(scope, customer) {
  var out = Object.assign({}, customer || {});
  if (scope.scopeType === 'all') return out;
  if (scope.scopeType === 'partner') {
    out.partnerKey = scope.partnerKey;
    return out;
  }
  if (scope.scopeType === 'tenant') {
    out.tenantKey = scope.tenantKey;
    out.erpId = scope.tenantKey;
    return out;
  }
  out.ownerUsername = scope.username;
  return out;
}

function integrationAuthorized(request, env) {
  var expected = (env.FIXIT_SYNC_TOKEN || '').trim();
  if (!expected) return false;
  var auth = request.headers.get('Authorization') || '';
  if (!auth.startsWith('Bearer ')) return false;
  var provided = auth.slice(7).trim();
  return provided === expected;
}

async function pushCustomerUpdateToFixit(env, customer) {
  var endpointBase = sanitizeString((env && (env.FIXIT_APPS_API_URL || env.FIXIT_APPS_SYNC_URL)) || '', 260).replace(/\/+$/, '');
  var token = sanitizeString((env && (env.FIXIT_APPS_SYNC_TOKEN || env.FIXIT_SYNC_TOKEN)) || '', 260);
  if (!endpointBase || !token || !customer || !customer.fixitTenantId) return;

  var payload = {
    company_name: customer.name || '',
    email: customer.email || '',
    phone: customer.phone || '',
    industry: customer.category || '',
    status: customer.status || '',
    dashboard_meta: {
      contact: customer.contact || '',
      go_live: customer.goLive || '',
      plz: customer.plz || '',
      ort: customer.ort || '',
      notes: customer.notes || '',
      verwaltungsart: customer.deck && customer.deck.verwaltungsart ? customer.deck.verwaltungsart : '',
      hinweise: customer.deck && customer.deck.hinweise ? customer.deck.hinweise : '',
      notfall: customer.deck && customer.deck.notfall ? customer.deck.notfall : '',
      wording: customer.deck && customer.deck.wording ? customer.deck.wording : ''
    }
  };

  try {
    await fetch(endpointBase + '/api/v1/integrations/dashboard/customers/' + encodeURIComponent(String(customer.fixitTenantId)), {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token
      },
      body: JSON.stringify(payload)
    });
  } catch (_) {}
}

export default {
  async fetch(request, env) {
    try {
      var url = new URL(request.url);
      var path = url.pathname;
      var parts = (path.startsWith('/') ? path.slice(1) : path).split('/');

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: Object.assign({}, BASE_HEADERS, getCorsHeaders(request)) });
    }

    if (path === '/' || path === '') {
      var resp = await fetch(GITHUB_HTML);
      var html = await resp.text();
      return new Response(html, {
        headers: Object.assign({}, BASE_HEADERS, HTML_SECURITY_HEADERS, { 'Content-Type': 'text/html; charset=utf-8' })
      });
    }

    if (path === '/api/login' && request.method === 'POST') {
      var b = await parseJson(request);
      if (!b || !b.username || !b.password) {
        return json(request, { success: false, error: 'Ungültige Anfrage' }, 400);
      }
      var users = await getUsers(env.KV);
      if (await migrateLegacyPasswords(users)) {
        await env.KV.put('users', JSON.stringify(users));
      }
      var cleanUsername = sanitizeString(b.username, 64);
      var user = users[cleanUsername];
      var verify = await verifyPassword(user, String(b.password));
      if (user && verify.ok) {
        var tk = makeToken();
        var sessions = JSON.parse(await env.KV.get('sessions') || '{}');
        sessions[tk] = { username: cleanUsername, expires: Date.now() + 86400000 };
        await env.KV.put('sessions', JSON.stringify(sessions));
        if (verify.upgraded) {
          users[cleanUsername] = user;
          await env.KV.put('users', JSON.stringify(users));
        }
        return json(request, { success: true, token: tk, user: { username: cleanUsername, name: user.name, role: normalizeUserRole(user.role), forcePasswordChange: user.forcePasswordChange || false } });
      }
      return json(request, { success: false, error: 'Ungültige Anmeldedaten' }, 401);
    }

    // Integration Endpoint for FixiT backend lifecycle sync
    if (path === '/api/integrations/fixit/sync' && request.method === 'POST') {
      if (!integrationAuthorized(request, env)) {
        return json(request, { error: 'Nicht autorisiert' }, 401);
      }

      var payload = await parseJson(request);
      if (!payload || typeof payload !== 'object') {
        return json(request, { error: 'Ungültige Sync-Daten' }, 400);
      }
      var tenant = payload.tenant || {};
      var onboarding = payload.onboarding || {};
      var commercial = payload.commercial || {};
      var dashboardFields = payload.dashboard_fields || {};
      var stage = normalizeDashboardStatus(dashboardFields.status || payload.stage || tenant.status || '');
      var tenantKey = sanitizeString(dashboardFields.erp_id || tenant.tenant_key || ('TENANT-' + (tenant.id || Date.now())), 80);

      var customers = await getCustomers(env.KV);
      var idx = customers.findIndex(function(c) {
        return c.tenantKey === tenantKey || c.erpId === tenantKey;
      });
      var existingCustomer = idx >= 0 ? (customers[idx] || null) : null;

      var syncFields = sanitizeCustomerInput({
        tenantKey: tenantKey,
        erpId: tenantKey,
        partnerKey: dashboardFields.partner_key || tenant.partner_key || '',
        name: dashboardFields.name || tenant.company_name || tenantKey,
        status: stage,
        email: dashboardFields.email || tenant.email || '',
        phone: dashboardFields.phone || tenant.phone || '',
        goLive: dashboardFields.go_live || formatDateYYYYMMDD(tenant.go_live_date),
        contact: dashboardFields.contact || '',
        plz: dashboardFields.plz || '',
        ort: dashboardFields.ort || '',
        category: dashboardFields.verwaltungsart || 'FixiT Sync',
        notes: dashboardFields.notes || '',
        portalLink: '',
        note1: '',
        note2: '',
        note3: '',
        note4: '',
        note5: '',
        note6: '',
        note7: '',
        note8: '',
        note9: '',
        note10: '',
        note11: '',
        note12: '',
        note13: '',
        note14: '',
        note15: '',
        deck: {
          verwaltungsart: dashboardFields.verwaltungsart || '',
          hinweise: dashboardFields.hinweise || '',
          notfall: dashboardFields.notfall || '',
          wording: '',
          updated: new Date().toLocaleDateString('de-DE')
        },
        onboardingProgress: onboarding.progress_percent || 0,
        onboardingCompleted: onboarding.is_completed || false,
        mrr: commercial.monthly_recurring_revenue || 0,
        activeContracts: commercial.active_contract_count || 0,
        fixitTenantId: tenant.id || null,
        fixitLeadStatus: tenant.lead_status || '',
        fixitOnboardingStatus: tenant.onboarding_status || '',
        syncedAt: new Date().toISOString(),
        changeVersion: new Date().toISOString(),
        lastChangeSource: 'fixit-apps',
        lastChangedAt: new Date().toISOString(),
        lastChangedBy: 'FixiT Apps'
      }, existingCustomer);

      var out;
      if (idx === -1) {
        syncFields.id = customers.length > 0 ? Math.max.apply(null, customers.map(function(c) { return c.id; })) + 1 : 1;
        out = syncFields;
        customers.push(out);
      } else {
        var prev = customers[idx] || {};
        var nextStatus = syncFields.status;

        // Anti-regression:
        // - "live" should not be downgraded by any later non-live sync event.
        // - "onboarding" should only be downgraded to "pending" via explicit manual_sync.
        if (prev.status === 'live' && nextStatus !== 'live') {
          nextStatus = 'live';
        }
        if (prev.status === 'onboarding' && nextStatus === 'pending' && payload.event !== 'manual_sync') {
          nextStatus = 'onboarding';
        }
        syncFields.status = nextStatus;

        out = Object.assign({}, prev, syncFields, { id: prev.id });
        customers[idx] = out;
      }

      await env.KV.put('customers', JSON.stringify(customers));
      return json(request, { success: true, customer: out, mode: idx === -1 ? 'created' : 'updated' });
    }

    var auth = request.headers.get('Authorization');
    var tk = auth ? auth.replace('Bearer ', '') : null;
    if (!tk) return json(request, { error: 'Nicht autorisiert' }, 401);

    var sessions = JSON.parse(await env.KV.get('sessions') || '{}');
    var session = sessions[tk];
    if (!session || session.expires < Date.now()) return json(request, { error: 'Session abgelaufen' }, 401);

    var username = session.username;
    var users = await getUsers(env.KV);
    if (await migrateLegacyPasswords(users)) {
      await env.KV.put('users', JSON.stringify(users));
    }
    var me = users[username];
    if (!me) return json(request, { error: 'Ungültige Session' }, 401);
    var scope = getUserScope(username, me);
    var role = normalizeUserRole(me && me.role);
    var isAdmin = role === 'admin';
    var isUser = role === 'user';
    var canCreateCustomers = !!isAdmin;
    var canUpdateCustomers = !!(isAdmin || isUser);

    if (path === '/api/users/me' && request.method === 'GET') {
      var force = me.forcePasswordChange || false;
      var expired = false;
      if (!me.passwordChangedAt) {
        force = true;
      } else {
        var daysSince = (Date.now() - new Date(me.passwordChangedAt).getTime()) / 86400000;
        if (daysSince > 14) expired = true;
      }
      return json(request, {
        username: username,
        name: me.name,
        role: role,
        scopeType: scope.scopeType,
        scopePartnerKey: scope.partnerKey,
        scopeTenantKey: scope.tenantKey,
        passwordChangedAt: me.passwordChangedAt || null,
        forcePasswordChange: force,
        passwordExpired: expired
      });
    }

    if (path === '/api/audit' && request.method === 'GET') {
      if (!isAdmin) return json(request, { error: 'Keine Berechtigung' }, 403);
      var lim = new URL(request.url).searchParams.get('limit');
      return json(request, await getAuditLogs(env.KV, lim));
    }

    if (path === '/api/customers' && request.method === 'GET') {
      var customersRead = await getCustomers(env.KV);
      var scopedRead = customersRead.filter(function(c) { return canReadCustomer(scope, c); });
      var reads = await getCustomerReads(env.KV);
      return json(request, scopedRead.map(function(c) {
        return sanitizeCustomerForRead(annotateCustomerReadState(c, username, reads), role);
      }));
    }

    if (path === '/api/customers' && request.method === 'POST') {
      if (!canCreateCustomers) return json(request, { error: 'Keine Berechtigung' }, 403);
      var customers = await getCustomers(env.KV);
      var ncIn = await parseJson(request);
      if (!ncIn || !ncIn.name) return json(request, { error: 'Mandantenname fehlt' }, 400);
      var createdAt = new Date().toISOString();
      var nc = restrictCustomerWrite(scope, sanitizeCustomerInput(Object.assign({}, ncIn, {
        changeVersion: createdAt,
        lastChangeSource: 'dashboard',
        lastChangedAt: createdAt,
        lastChangedBy: me && me.name ? me.name : username
      }), null));
      nc.id = customers.length > 0 ? Math.max.apply(null, customers.map(function(c) { return c.id; })) + 1 : 1;
      customers.push(nc);
      await env.KV.put('customers', JSON.stringify(customers));
      await appendAuditLog(env.KV, username, 'customer.create', String(nc.id), { name: nc.name, scopeType: scope.scopeType });
      return json(request, sanitizeCustomerForRead(nc, role));
    }

    if (parts[1] === 'customers' && parts[2] && !parts[3] && request.method === 'PUT') {
      if (!canUpdateCustomers) return json(request, { error: 'Keine Berechtigung' }, 403);
      var id = parseInt(parts[2]);
      var customers = await getCustomers(env.KV);
      var idx = customers.findIndex(function(c) { return c.id === id; });
      if (idx === -1) return json(request, { error: 'Nicht gefunden' }, 404);
      if (!canReadCustomer(scope, customers[idx])) return json(request, { error: 'Keine Berechtigung' }, 403);
      var upd = await parseJson(request);
      if (!upd) return json(request, { error: 'Ungültige Daten' }, 400);
      var changeAt = new Date().toISOString();
      customers[idx] = Object.assign({}, restrictCustomerWrite(scope, sanitizeCustomerInput(Object.assign({}, upd, {
        changeVersion: changeAt,
        lastChangeSource: 'dashboard',
        lastChangedAt: changeAt,
        lastChangedBy: me && me.name ? me.name : username
      }), customers[idx])), { id: id });
      await env.KV.put('customers', JSON.stringify(customers));
      await appendAuditLog(env.KV, username, 'customer.update', String(id), { name: customers[idx].name, scopeType: scope.scopeType });
      await pushCustomerUpdateToFixit(env, customers[idx]);
      return json(request, sanitizeCustomerForRead(customers[idx], role));
    }

    if (parts[1] === 'customers' && parts[2] && parts[3] === 'ack' && request.method === 'POST') {
      var ackId = parseInt(parts[2], 10);
      if (!ackId) return json(request, { error: 'Ungültige Mandanten-ID' }, 400);
      var ackCustomers = await getCustomers(env.KV);
      var ackCustomer = ackCustomers.find(function(c) { return c.id === ackId; });
      if (!ackCustomer) return json(request, { error: 'Nicht gefunden' }, 404);
      if (!canReadCustomer(scope, ackCustomer)) return json(request, { error: 'Keine Berechtigung' }, 403);
      await markCustomerRead(env.KV, username, ackId, ackCustomer.changeVersion || '');
      return json(request, { success: true, customerId: ackId, changeVersion: ackCustomer.changeVersion || '' });
    }

    if (parts[1] === 'customers' && parts[2] && !parts[3] && request.method === 'DELETE') {
      if (!isAdmin) return json(request, { error: 'Keine Berechtigung' }, 403);
      var id = parseInt(parts[2]);
      var customers = await getCustomers(env.KV);
      customers = customers.filter(function(c) { return c.id !== id; });
      await env.KV.put('customers', JSON.stringify(customers));
      await appendAuditLog(env.KV, username, 'customer.delete', String(id), {});
      return json(request, { success: true });
    }

    if (path === '/api/users' && request.method === 'GET') {
      if (!isAdmin) return json(request, { error: 'Keine Berechtigung' }, 403);
      var safe = {};
      Object.keys(users).forEach(function(k) {
        safe[k] = {
          name: users[k].name,
          role: normalizeUserRole(users[k].role),
          scopeType: normalizeScopeType(users[k].scopeType, normalizeUserRole(users[k].role)),
          scopePartnerKey: users[k].scopePartnerKey || '',
          scopeTenantKey: users[k].scopeTenantKey || ''
        };
      });
      return json(request, safe);
    }

    if (path === '/api/users' && request.method === 'POST') {
      if (!isAdmin) return json(request, { error: 'Keine Berechtigung' }, 403);
      var nb = await parseJson(request);
      if (!nb || !nb.username || !nb.password || !nb.name) return json(request, { error: 'Ungültige Benutzerdaten' }, 400);
      var un = sanitizeString(nb.username, 64);
      var rn = normalizeUserRole(nb.role);
      if (users[un]) return json(request, { error: 'Benutzername existiert bereits' }, 400);
      var scopeType = normalizeScopeType(nb.scopeType, rn);
      if (String(nb.password).length < 8) return json(request, { error: 'Passwort zu kurz' }, 400);
      var pRec = await createPasswordRecord(String(nb.password));
      users[un] = {
        passwordHash: pRec.passwordHash,
        passwordSalt: pRec.passwordSalt,
        name: sanitizeString(nb.name, 120),
        role: rn,
        scopeType: scopeType,
        scopePartnerKey: sanitizeString(nb.scopePartnerKey, 80),
        scopeTenantKey: sanitizeString(nb.scopeTenantKey, 80),
        forcePasswordChange: true
      };
      await env.KV.put('users', JSON.stringify(users));
      await appendAuditLog(env.KV, username, 'user.create', un, { role: rn, scopeType: scopeType });
      return json(request, { success: true });
    }

    if (parts[1] === 'users' && parts[2] && !parts[3] && request.method === 'DELETE') {
      if (!isAdmin) return json(request, { error: 'Keine Berechtigung' }, 403);
      var target = decodeURIComponent(parts[2]);
      if (target === 'admin') return json(request, { error: 'Admin kann nicht gelöscht werden' }, 400);
      delete users[target];
      await env.KV.put('users', JSON.stringify(users));
      await appendAuditLog(env.KV, username, 'user.delete', target, {});
      return json(request, { success: true });
    }

    if (parts[1] === 'users' && parts[2] && !parts[3] && request.method === 'PUT') {
      if (!isAdmin) return json(request, { error: 'Keine Berechtigung' }, 403);
      var targetUpdate = decodeURIComponent(parts[2]);
      if (!users[targetUpdate]) return json(request, { error: 'User nicht gefunden' }, 404);
      var ub = await parseJson(request);
      if (!ub) return json(request, { error: 'Ungültige Daten' }, 400);

      var nextRole = normalizeUserRole(ub.role || users[targetUpdate].role);
      if (targetUpdate === 'admin') nextRole = 'admin';
      var nextScopeType = normalizeScopeType(ub.scopeType || users[targetUpdate].scopeType, nextRole);
      var nextName = sanitizeString(ub.name || users[targetUpdate].name || targetUpdate, 120);
      var nextPartnerKey = sanitizeString(ub.scopePartnerKey || '', 80);
      var nextTenantKey = sanitizeString(ub.scopeTenantKey || '', 80);

      if (nextScopeType === 'partner' && !nextPartnerKey) {
        return json(request, { error: 'Partner-Key erforderlich' }, 400);
      }
      if (nextScopeType === 'tenant' && !nextTenantKey) {
        return json(request, { error: 'Tenant-Key erforderlich' }, 400);
      }

      users[targetUpdate].name = nextName;
      users[targetUpdate].role = nextRole;
      users[targetUpdate].scopeType = nextScopeType;
      users[targetUpdate].scopePartnerKey = nextScopeType === 'partner' ? nextPartnerKey : '';
      users[targetUpdate].scopeTenantKey = nextScopeType === 'tenant' ? nextTenantKey : '';

      await env.KV.put('users', JSON.stringify(users));
      await appendAuditLog(env.KV, username, 'user.update', targetUpdate, {
        role: nextRole,
        scopeType: nextScopeType,
        scopePartnerKey: users[targetUpdate].scopePartnerKey || '',
        scopeTenantKey: users[targetUpdate].scopeTenantKey || ''
      });
      return json(request, { success: true });
    }

    if (parts[1] === 'users' && parts[2] && parts[3] === 'password' && request.method === 'PUT') {
      var target = decodeURIComponent(parts[2]);
      if (!isAdmin && username !== target) return json(request, { error: 'Keine Berechtigung' }, 403);
      var pb = await parseJson(request);
      if (!users[target]) return json(request, { error: 'User nicht gefunden' }, 404);
      if (!pb || !pb.password || String(pb.password).length < 8) return json(request, { error: 'Passwort zu kurz' }, 400);
      var updRec = await createPasswordRecord(String(pb.password));
      users[target].passwordHash = updRec.passwordHash;
      users[target].passwordSalt = updRec.passwordSalt;
      delete users[target].password;
      users[target].passwordChangedAt = new Date().toISOString();
      users[target].forcePasswordChange = (isAdmin && username !== target) ? true : false;
      await env.KV.put('users', JSON.stringify(users));
      await appendAuditLog(env.KV, username, 'user.password.reset', target, { adminReset: !!(isAdmin && username !== target) });
      return json(request, { success: true });
    }

      return json(request, { error: 'Route nicht gefunden' }, 404);
    } catch (err) {
      return json(request, { error: 'Interner Serverfehler' }, 500);
    }
  }
};
