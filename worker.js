// FixiT Dashboard - Cloudflare Worker

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

const GITHUB_HTML = 'https://raw.githubusercontent.com/Cupra-S2027/fixit-dashboard/main/index.html';

function json(data, status) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: Object.assign({}, CORS, { 'Content-Type': 'application/json' }),
  });
}

function makeToken(username) {
  return btoa(username + ':' + Date.now());
}

async function getUsers(KV) {
  var data = await KV.get('users');
  if (!data) {
    var def = { admin: { password: 'fixit2026', role: 'admin', name: 'Admin', forcePasswordChange: false } };
    await KV.put('users', JSON.stringify(def));
    return def;
  }
  return JSON.parse(data);
}

async function getCustomers(KV) {
  var data = await KV.get('customers');
  return data ? JSON.parse(data) : [];
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

function integrationAuthorized(request, env) {
  var expected = (env.FIXIT_SYNC_TOKEN || '').trim();
  if (!expected) return false;
  var auth = request.headers.get('Authorization') || '';
  if (!auth.startsWith('Bearer ')) return false;
  var provided = auth.slice(7).trim();
  return provided === expected;
}

export default {
  async fetch(request, env) {
    var url = new URL(request.url);
    var path = url.pathname;
    var parts = (path.startsWith('/') ? path.slice(1) : path).split('/');

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS });
    }

    if (path === '/' || path === '') {
      var resp = await fetch(GITHUB_HTML);
      var html = await resp.text();
      return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }

    if (path === '/api/login' && request.method === 'POST') {
      var b = await request.json();
      var users = await getUsers(env.KV);
      var user = users[b.username];
      if (user && user.password === b.password) {
        var tk = makeToken(b.username);
        var sessions = JSON.parse(await env.KV.get('sessions') || '{}');
        sessions[tk] = { username: b.username, expires: Date.now() + 86400000 };
        await env.KV.put('sessions', JSON.stringify(sessions));
        return json({ success: true, token: tk, user: { username: b.username, name: user.name, role: user.role, forcePasswordChange: user.forcePasswordChange || false } });
      }
      return json({ success: false, error: 'Ungültige Anmeldedaten' }, 401);
    }

    // Integration Endpoint for FixiT backend lifecycle sync
    if (path === '/api/integrations/fixit/sync' && request.method === 'POST') {
      if (!integrationAuthorized(request, env)) {
        return json({ error: 'Nicht autorisiert' }, 401);
      }

      var payload = await request.json();
      var tenant = payload.tenant || {};
      var onboarding = payload.onboarding || {};
      var commercial = payload.commercial || {};
      var stage = normalizeDashboardStatus(payload.stage || tenant.status || '');
      var tenantKey = tenant.tenant_key || ('TENANT-' + (tenant.id || Date.now()));

      var customers = await getCustomers(env.KV);
      var idx = customers.findIndex(function(c) {
        return c.tenantKey === tenantKey || c.erpId === tenantKey;
      });

      var syncFields = {
        tenantKey: tenantKey,
        erpId: tenantKey,
        name: tenant.company_name || tenantKey,
        status: stage,
        email: tenant.email || '',
        phone: tenant.phone || '',
        goLive: formatDateYYYYMMDD(tenant.go_live_date),
        contact: '',
        category: 'FixiT Sync',
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
        onboardingProgress: onboarding.progress_percent || 0,
        onboardingCompleted: onboarding.is_completed || false,
        mrr: commercial.monthly_recurring_revenue || 0,
        activeContracts: commercial.active_contract_count || 0,
        fixitTenantId: tenant.id || null,
        fixitLeadStatus: tenant.lead_status || '',
        fixitOnboardingStatus: tenant.onboarding_status || '',
        syncedAt: new Date().toISOString()
      };

      var out;
      if (idx === -1) {
        syncFields.id = customers.length > 0 ? Math.max.apply(null, customers.map(function(c) { return c.id; })) + 1 : 1;
        out = syncFields;
        customers.push(out);
      } else {
        out = Object.assign({}, customers[idx], syncFields, { id: customers[idx].id });
        customers[idx] = out;
      }

      await env.KV.put('customers', JSON.stringify(customers));
      return json({ success: true, customer: out, mode: idx === -1 ? 'created' : 'updated' });
    }

    var auth = request.headers.get('Authorization');
    var tk = auth ? auth.replace('Bearer ', '') : null;
    if (!tk) return json({ error: 'Nicht autorisiert' }, 401);

    var sessions = JSON.parse(await env.KV.get('sessions') || '{}');
    var session = sessions[tk];
    if (!session || session.expires < Date.now()) return json({ error: 'Session abgelaufen' }, 401);

    var username = session.username;
    var users = await getUsers(env.KV);
    var me = users[username];
    var isAdmin = me && me.role === 'admin';

    if (path === '/api/users/me' && request.method === 'GET') {
      var force = me.forcePasswordChange || false;
      var expired = false;
      if (!me.passwordChangedAt) {
        force = true;
      } else {
        var daysSince = (Date.now() - new Date(me.passwordChangedAt).getTime()) / 86400000;
        if (daysSince > 14) expired = true;
      }
      return json({ username: username, name: me.name, role: me.role, passwordChangedAt: me.passwordChangedAt || null, forcePasswordChange: force, passwordExpired: expired });
    }

    if (path === '/api/customers' && request.method === 'GET') {
      return json(await getCustomers(env.KV));
    }

    if (path === '/api/customers' && request.method === 'POST') {
      var customers = await getCustomers(env.KV);
      var nc = await request.json();
      nc.id = customers.length > 0 ? Math.max.apply(null, customers.map(function(c) { return c.id; })) + 1 : 1;
      customers.push(nc);
      await env.KV.put('customers', JSON.stringify(customers));
      return json(nc);
    }

    if (parts[1] === 'customers' && parts[2] && !parts[3] && request.method === 'PUT') {
      var id = parseInt(parts[2]);
      var customers = await getCustomers(env.KV);
      var idx = customers.findIndex(function(c) { return c.id === id; });
      if (idx === -1) return json({ error: 'Nicht gefunden' }, 404);
      var upd = await request.json();
      customers[idx] = Object.assign({}, customers[idx], upd, { id: id });
      await env.KV.put('customers', JSON.stringify(customers));
      return json(customers[idx]);
    }

    if (parts[1] === 'customers' && parts[2] && !parts[3] && request.method === 'DELETE') {
      var id = parseInt(parts[2]);
      var customers = await getCustomers(env.KV);
      customers = customers.filter(function(c) { return c.id !== id; });
      await env.KV.put('customers', JSON.stringify(customers));
      return json({ success: true });
    }

    if (path === '/api/users' && request.method === 'GET') {
      if (!isAdmin) return json({ error: 'Keine Berechtigung' }, 403);
      var safe = {};
      Object.keys(users).forEach(function(k) { safe[k] = { name: users[k].name, role: users[k].role }; });
      return json(safe);
    }

    if (path === '/api/users' && request.method === 'POST') {
      if (!isAdmin) return json({ error: 'Keine Berechtigung' }, 403);
      var nb = await request.json();
      if (users[nb.username]) return json({ error: 'Benutzername existiert bereits' }, 400);
      users[nb.username] = { password: nb.password, name: nb.name, role: nb.role, forcePasswordChange: true };
      await env.KV.put('users', JSON.stringify(users));
      return json({ success: true });
    }

    if (parts[1] === 'users' && parts[2] && !parts[3] && request.method === 'DELETE') {
      if (!isAdmin) return json({ error: 'Keine Berechtigung' }, 403);
      var target = decodeURIComponent(parts[2]);
      if (target === 'admin') return json({ error: 'Admin kann nicht gelöscht werden' }, 400);
      delete users[target];
      await env.KV.put('users', JSON.stringify(users));
      return json({ success: true });
    }

    if (parts[1] === 'users' && parts[2] && parts[3] === 'password' && request.method === 'PUT') {
      var target = decodeURIComponent(parts[2]);
      if (!isAdmin && username !== target) return json({ error: 'Keine Berechtigung' }, 403);
      var pb = await request.json();
      if (!users[target]) return json({ error: 'User nicht gefunden' }, 404);
      users[target].password = pb.password;
      users[target].passwordChangedAt = new Date().toISOString();
      users[target].forcePasswordChange = (isAdmin && username !== target) ? true : false;
      await env.KV.put('users', JSON.stringify(users));
      return json({ success: true });
    }

    return json({ error: 'Route nicht gefunden' }, 404);
  }
};
