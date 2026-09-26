const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const {Pool} = require('pg');

const port = Number(process.env.PORT || 3000);
const password = process.env.EDIT_PASSWORD;
const secret = process.env.SESSION_SECRET;
if (!process.env.DATABASE_URL || !password || !secret) {
  console.error('DATABASE_URL, EDIT_PASSWORD and SESSION_SECRET are required');
  process.exit(1);
}
const db = new Pool({connectionString: process.env.DATABASE_URL, max: 5});
const emptyState = {nextCount: 3, cycles: []};
const loginAttempts = new Map();
const maxBody = 25 * 1024 * 1024;
const publicFiles = {'/': 'index.html', '/index.html': 'index.html', '/style.css': 'style.css', '/app.js': 'app.js', '/Truck.jpg': 'Truck.jpg'};
const types = {'.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'application/javascript; charset=utf-8', '.jpg': 'image/jpeg'};

function json(res, status, body, headers = {}) {
  res.writeHead(status, {'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers});
  res.end(JSON.stringify(body));
}
function token(payload) {
  const data = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto.createHmac('sha256', secret).update(data).digest('base64url');
  return `${data}.${signature}`;
}
function authenticated(req) {
  const value = (req.headers.cookie || '').split(';').map(x => x.trim()).find(x => x.startsWith('falcon_editor='))?.slice(14);
  if (!value) return false;
  const [data, signature] = value.split('.');
  if (!data || !signature) return false;
  const expected = crypto.createHmac('sha256', secret).update(data).digest();
  let actual;
  try { actual = Buffer.from(signature, 'base64url'); } catch { return false; }
  if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) return false;
  try { return JSON.parse(Buffer.from(data, 'base64url').toString()).exp > Date.now(); } catch { return false; }
}
function cookie(value, age) {
  return `falcon_editor=${value}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${age}${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`;
}
function sameOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return false;
  try { return new URL(origin).host === req.headers.host; } catch { return false; }
}
async function body(req) {
  return new Promise((resolve, reject) => {
    let size = 0, chunks = [];
    req.on('data', chunk => {
      size += chunk.length;
      if (size > maxBody) { reject(Object.assign(new Error('Request too large'), {status: 413})); req.destroy(); return; }
      chunks.push(chunk);
    });
    req.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch { reject(Object.assign(new Error('Invalid JSON'), {status: 400})); } });
    req.on('error', reject);
  });
}
async function handler(req, res) {
  const pathname = new URL(req.url, 'http://localhost').pathname;
  if (pathname === '/health') return json(res, 200, {ok: true});
  if (pathname === '/api/session' && req.method === 'GET') return json(res, 200, {editor: authenticated(req)});
  if (pathname === '/api/state' && req.method === 'GET') {
    const {rows} = await db.query('SELECT version, data FROM app_state WHERE id = 1');
    return json(res, 200, {version: rows[0].version, state: rows[0].data});
  }
  if (pathname === '/api/login' && req.method === 'POST') {
    if (!sameOrigin(req)) return json(res, 403, {error: 'Invalid origin'});
    const ip = req.socket.remoteAddress || 'unknown', now = Date.now();
    const attempt = loginAttempts.get(ip) || {count: 0, until: now + 15 * 60_000};
    if (attempt.until < now) { attempt.count = 0; attempt.until = now + 15 * 60_000; }
    if (attempt.count >= 10) return json(res, 429, {error: 'Too many attempts. Try again later.'});
    const input = await body(req);
    const candidate = String(input.password || '');
    const a = crypto.createHash('sha256').update(candidate).digest();
    const b = crypto.createHash('sha256').update(password).digest();
    if (!crypto.timingSafeEqual(a, b)) {
      attempt.count++; loginAttempts.set(ip, attempt);
      return json(res, 401, {error: 'Incorrect password'});
    }
    loginAttempts.delete(ip);
    const maxAge = 30 * 24 * 60 * 60;
    return json(res, 200, {editor: true}, {'Set-Cookie': cookie(token({exp: now + maxAge * 1000}), maxAge)});
  }
  if (pathname === '/api/logout' && req.method === 'POST') {
    if (!sameOrigin(req)) return json(res, 403, {error: 'Invalid origin'});
    return json(res, 200, {editor: false}, {'Set-Cookie': cookie('', 0)});
  }
  if (pathname === '/api/state' && req.method === 'PUT') {
    if (!sameOrigin(req) || !authenticated(req)) return json(res, 403, {error: 'Editor login required'});
    const input = await body(req);
    if (!Number.isSafeInteger(input.version) || input.version < 0 || !input.state || !Array.isArray(input.state.cycles) || !Number.isInteger(input.state.nextCount)) return json(res, 400, {error: 'Invalid state'});
    const {rows} = await db.query('UPDATE app_state SET data = $1::jsonb, version = version + 1 WHERE id = 1 AND version = $2 RETURNING version', [JSON.stringify(input.state), input.version]);
    if (!rows.length) return json(res, 409, {error: 'Records changed on another device. Reload to see the latest version.'});
    return json(res, 200, {version: rows[0].version});
  }
  if (pathname.startsWith('/api/')) return json(res, 404, {error: 'Not found'});
  if (req.method !== 'GET' && req.method !== 'HEAD') return json(res, 405, {error: 'Method not allowed'});
  const filename = publicFiles[pathname];
  if (!filename) return json(res, 404, {error: 'Not found'});
  fs.readFile(path.join(__dirname, filename), (err, data) => {
    if (err) return json(res, 404, {error: 'Not found'});
    res.writeHead(200, {'Content-Type': types[path.extname(filename)], 'Cache-Control': filename === 'index.html' ? 'no-cache' : 'public, max-age=3600'});
    res.end(req.method === 'HEAD' ? undefined : data);
  });
}
(async () => {
  await db.query('CREATE TABLE IF NOT EXISTS app_state (id integer PRIMARY KEY CHECK (id = 1), version integer NOT NULL, data jsonb NOT NULL)');
  await db.query('INSERT INTO app_state (id, version, data) VALUES (1, 0, $1::jsonb) ON CONFLICT (id) DO NOTHING', [JSON.stringify(emptyState)]);
  http.createServer((req, res) => handler(req, res).catch(err => {
    console.error('Request failed:', err);
    if (!res.headersSent) json(res, err.status || 500, {error: err.status ? err.message : 'Server error'});
  })).listen(port, '0.0.0.0', () => console.log('Falcon Traders running on ' + port));
})().catch(err => { console.error('Database initialization failed:', err); process.exit(1); });
