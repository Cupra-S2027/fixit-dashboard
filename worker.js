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
      return json({ username: username, name: me.name, role: me.role, passwordChangedAt: me.passwordChangedAt || null, forcePasswordChange: me.forcePasswordChange || false });
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
