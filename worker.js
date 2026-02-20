// FixiT Dashboard - Cloudflare Worker Backend
// Speichert alle Daten in Cloudflare KV (nicht mehr im Browser localStorage!)

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
  });
}

function html(content) {
  return new Response(content, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
}

// Einfache Token-basierte Auth (Base64 encoded username:timestamp)
function generateToken(username) {
  return btoa(`${username}:${Date.now()}`);
}

function getUsernameFromToken(token) {
  try {
    const decoded = atob(token);
    return decoded.split(':')[0];
  } catch {
    return null;
  }
}

async function getUsers(KV) {
  const data = await KV.get('users');
  if (!data) {
    // Default admin user
    const defaultUsers = {
      admin: { password: 'fixit2026', role: 'admin', name: 'Admin' }
    };
    await KV.put('users', JSON.stringify(defaultUsers));
    return defaultUsers;
  }
  return JSON.parse(data);
}

async function getCustomers(KV) {
  const data = await KV.get('customers');
  return data ? JSON.parse(data) : [];
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS_HEADERS });
    }

    // Serve the main HTML page
    if (path === '/' || path === '') {
      // Read the HTML from KV (you'll upload it there)
      const htmlContent = await env.KV.get('index_html');
      if (htmlContent) {
        return html(htmlContent);
      }
      return html('<h1>Bitte index.html hochladen</h1>');
    }

    // === API ROUTES ===

    // POST /api/login
    if (path === '/api/login' && request.method === 'POST') {
      const { username, password } = await request.json();
      const users = await getUsers(env.KV);
      const user = users[username];
      
      if (user && user.password === password) {
        const token = generateToken(username);
        // Speichere aktive Sessions
        const sessions = JSON.parse(await env.KV.get('sessions') || '{}');
        sessions[token] = { username, expires: Date.now() + 86400000 }; // 24h
        await env.KV.put('sessions', JSON.stringify(sessions));
        
        return json({ 
          success: true, 
          token,
          user: { username, name: user.name, role: user.role }
        });
      }
      return json({ success: false, error: 'Ungültige Anmeldedaten' }, 401);
    }

    // Auth-Middleware für alle weiteren API-Routen
    const authHeader = request.headers.get('Authorization');
    const token = authHeader?.replace('Bearer ', '');
    
    if (!token) {
      return json({ error: 'Nicht autorisiert' }, 401);
    }

    const sessions = JSON.parse(await env.KV.get('sessions') || '{}');
    const session = sessions[token];
    
    if (!session || session.expires < Date.now()) {
      return json({ error: 'Session abgelaufen' }, 401);
    }

    const username = session.username;
    const users = await getUsers(env.KV);
    const currentUser = { username, ...users[username] };

    // GET /api/customers
    if (path === '/api/customers' && request.method === 'GET') {
      const customers = await getCustomers(env.KV);
      return json(customers);
    }

    // POST /api/customers (neuer Kunde)
    if (path === '/api/customers' && request.method === 'POST') {
      const customers = await getCustomers(env.KV);
      const newCustomer = await request.json();
      const maxId = customers.length > 0 ? Math.max(...customers.map(c => c.id)) : 0;
      newCustomer.id = maxId + 1;
      customers.push(newCustomer);
      await env.KV.put('customers', JSON.stringify(customers));
      return json(newCustomer);
    }

    // PUT /api/customers/:id (Kunde bearbeiten)
    const customerEditMatch = path.match(/^\/api\/customers\/(\d+)$/);
    if (customerEditMatch && request.method === 'PUT') {
      const id = parseInt(customerEditMatch[1]);
      const customers = await getCustomers(env.KV);
      const idx = customers.findIndex(c => c.id === id);
      if (idx === -1) return json({ error: 'Kunde nicht gefunden' }, 404);
      
      const updatedCustomer = await request.json();
      customers[idx] = { ...customers[idx], ...updatedCustomer, id };
      await env.KV.put('customers', JSON.stringify(customers));
      return json(customers[idx]);
    }

    // DELETE /api/customers/:id
    if (customerEditMatch && request.method === 'DELETE') {
      const id = parseInt(customerEditMatch[1]);
      let customers = await getCustomers(env.KV);
      customers = customers.filter(c => c.id !== id);
      await env.KV.put('customers', JSON.stringify(customers));
      return json({ success: true });
    }

    // GET /api/users (nur Admin)
    if (path === '/api/users' && request.method === 'GET') {
      if (currentUser.role !== 'admin') return json({ error: 'Keine Berechtigung' }, 403);
      const users = await getUsers(env.KV);
      // Passwörter nicht zurückgeben
      const safeUsers = Object.fromEntries(
        Object.entries(users).map(([k, v]) => [k, { name: v.name, role: v.role }])
      );
      return json(safeUsers);
    }

    // POST /api/users (User hinzufügen, nur Admin)
    if (path === '/api/users' && request.method === 'POST') {
      if (currentUser.role !== 'admin') return json({ error: 'Keine Berechtigung' }, 403);
      const { username: newUsername, password, name, role } = await request.json();
      const users = await getUsers(env.KV);
      
      if (users[newUsername]) return json({ error: 'Benutzername existiert bereits' }, 400);
      
      users[newUsername] = { password, name, role };
      await env.KV.put('users', JSON.stringify(users));
      return json({ success: true });
    }

    // DELETE /api/users/:username (nur Admin)
    const userDeleteMatch = path.match(/^\/api\/users\/([^/]+)$/);
    if (userDeleteMatch && request.method === 'DELETE') {
      if (currentUser.role !== 'admin') return json({ error: 'Keine Berechtigung' }, 403);
      const targetUser = decodeURIComponent(userDeleteMatch[1]);
      if (targetUser === 'admin') return json({ error: 'Admin kann nicht gelöscht werden' }, 400);
      
      const users = await getUsers(env.KV);
      delete users[targetUser];
      await env.KV.put('users', JSON.stringify(users));
      return json({ success: true });
    }

    // PUT /api/users/:username/password (Passwort ändern)
    const pwMatch = path.match(/^\/api\/users\/([^/]+)\/password$/);
    if (pwMatch && request.method === 'PUT') {
      const targetUser = decodeURIComponent(pwMatch[1]);
      // Nur Admin oder der User selbst kann Passwort ändern
      if (currentUser.role !== 'admin' && currentUser.username !== targetUser) {
        return json({ error: 'Keine Berechtigung' }, 403);
      }
      const { password } = await request.json();
      const users = await getUsers(env.KV);
      if (!users[targetUser]) return json({ error: 'User nicht gefunden' }, 404);
      users[targetUser].password = password;
      await env.KV.put('users', JSON.stringify(users));
      return json({ success: true });
    }

    // POST /api/upload-html (HTML-Datei in KV speichern, nur Admin)
    if (path === '/api/upload-html' && request.method === 'POST') {
      if (currentUser.role !== 'admin') return json({ error: 'Keine Berechtigung' }, 403);
      const htmlContent = await request.text();
      await env.KV.put('index_html', htmlContent);
      return json({ success: true });
    }

    return json({ error: 'Route nicht gefunden' }, 404);
  }
};
