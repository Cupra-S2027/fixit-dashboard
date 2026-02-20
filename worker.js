// FixiT Dashboard - Cloudflare Worker
// HTML wird direkt aus GitHub geladen - kein Embedding nötig

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

const GITHUB_HTML_URL = 'https://raw.githubusercontent.com/Cupra-S2027/fixit-dashboard/main/index.html';

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
  });
}

async function getUsers(KV) {
  const data = await KV.get('users');
  if (!data) {
    const def = { admin: { password: 'fixit2026', role: 'admin', name: 'Admin' } };
    await KV.put('users', JSON.stringify(def));
    return def;
  }
  return JSON.parse(data);
}

async function getCustomers(KV) {
  const data = await KV.get('customers');
  return data ? JSON.parse(data) : [];
}

function generateToken(username) {
  return btoa(username + ':' + Date.now());
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS_HEADERS });
    }

    // Serve HTML from GitHub
    if (path === '/' || path === '') {
      const resp = await fetch(GITHUB_HTML_URL);
      const html = await resp.text();
      return new Response(html, {
        headers: { 'Content-Type': 'text/html; charset=utf-8' },
      });
    }

    // LOGIN
    if (path === '/api/login' && request.method === 'POST') {
      const { username, password } = await request.json();
      const users = await getUsers(env.KV);
      const user = users[username];
      if (user && user.password === password) {
        const token = generateToken(username);
        const sessions = JSON.parse(await env.KV.get('sessions') || '{}');
        sessions[token] = { username, expires: Date.now() + 86400000 };
        await env.KV.put('sessions', JSON.stringify(sessions));
        return json({ success: true, token, user: { username, name: user.name, role: user.role } });
      }
      return json({ success: false, error: 'Ungültige Anmeldedaten' }, 401);
    }

    // AUTH CHECK
    const authHeader = request.headers.get('Authorization');
    const token = authHeader ? authHeader.replace('Bearer ', '') : null;
    if (!token) return json({ error: 'Nicht autorisiert' }, 401);

    const sessions = JSON.parse(await env.KV.get('sessions') || '{}');
    const session = sessions[token];
    if (!session || session.expires < Date.now()) return json({ error: 'Session abgelaufen' }, 401);

    const username = session.username;
    const users = await getUsers(env.KV);
    const currentUser = { username, ...users[username] };

    // CUSTOMERS
    if (path === '/api/customers' && request.method === 'GET') {
      return json(await getCustomers(env.KV));
    }

    if (path === '/api/customers' && request.method === 'POST') {
      const customers = await getCustomers(env.KV);
      const nc = await request.json();
      nc.id = customers.length > 0 ? Math.max(...customers.map(c => c.id)) + 1 : 1;
      customers.push(nc);
      await env.KV.put('customers', JSON.stringify(customers));
      return json(nc);
    }

    const cm = path.match(/^\/api\/customers\/(\d+)$/);
    if (cm && request.method === 'PUT') {
      const id = parseInt(cm[1]);
      const customers = await getCustomers(env.KV);
      const idx = customers.findIndex(c => c.id === id);
      if (idx === -1) return json({ error: 'Nicht gefunden' }, 404);
      customers[idx] = { ...customers[idx], ...await request.json(), id };
      await env.KV.put('customers', JSON.stringify(customers));
      return json(customers[idx]);
    }

    if (cm && request.method === 'DELETE') {
      let customers = await getCustomers(env.KV);
      customers = customers.filter(c => c.id !== parseInt(cm[1]));
      await env.KV.put('customers', JSON.stringify(customers));
      return json({ success: true });
    }

    // USERS
    if (path === '/api/users' && request.method === 'GET') {
      if (currentUser.role !== 'admin') return json({ error: 'Keine Berechtigung' }, 403);
      const users = await getUsers(env.KV);
      const safe = Object.fromEntries(Object.entries(users).map(([k, v]) => [k, { name: v.name, role: v.role }]));
      return json(safe);
    }

    if (path === '/api/users' && request.method === 'POST') {
      if (currentUser.role !== 'admin') return json({ error: 'Keine Berechtigung' }, 403);
      const { username: nu, password, name, role } = await request.json();
      const users = await getUsers(env.KV);
      if (users[nu]) return json({ error: 'Benutzername existiert bereits' }, 400);
      users[nu] = { password, name, role };
      await env.KV.put('users', JSON.stringify(users));
      return json({ success: true });
    }

    const um = path.match(/^\/api\/users\/([^/]+)$/);
    if (um && request.method === 'DELETE') {
      if (currentUser.role !== 'admin') return json({ error: 'Keine Berechtigung' }, 403);
      const target = decodeURIComponent(um[1]);
      if (target === 'admin') return json({ error: 'Admin kann nicht gelöscht werden' }, 400);
      const users = await getUsers(env.KV);
      delete users[target];
      await env.KV.put('users', JSON.stringify(users));
      return json({ success: true });
    }

    const pm = path.match(/^\/api\/users\/([^/]+)\/password$/);
    if (pm && request.method === 'PUT') {
      const target = decodeURIComponent(pm[1]);
      if (currentUser.role !== 'admin' && currentUser.username !== target) return json({ error: 'Keine Berechtigung' }, 403);
      const { password } = await request.json();
      const users = await getUsers(env.KV);
      if (!users[target]) return json({ error: 'User nicht gefunden' }, 404);
      users[target].password = password;
      await env.KV.put('users', JSON.stringify(users));
      return json({ success: true });
    }

    return json({ error: 'Route nicht gefunden' }, 404);
  }
};
