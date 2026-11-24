const http = require('node:http');
const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} = require('@simplewebauthn/server');

const root = __dirname;
const port = Number(process.env.PORT || 3000);
const contentPath = path.join(root, 'content.json');
const authPath = path.join(root, '.admin-auth.json');
const browserBundlePath = path.join(root, 'node_modules/@simplewebauthn/browser/dist/bundle/index.umd.min.js');
const fields = ['heroIntro', 'featuredTitle', 'featuredSummary', 'featuredDescription', 'competition', 'team', 'competitionDescription', 'email', 'github', 'linkedin'];
const types = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.json': 'application/json; charset=utf-8' };
const maxAge = 8 * 60 * 60 * 1000;
const ceremonyMaxAge = 5 * 60 * 1000;
const maxCeremonies = 128;
const sessionCookie = 'admin_session';
const ceremonies = new Map();
const sessions = new Map();
const rateLimits = new Map();

const originUrl = new URL(process.env.ADMIN_ORIGIN || `http://localhost:${port}`);
if (originUrl.pathname !== '/' || originUrl.search || originUrl.hash || originUrl.username || originUrl.password) {
  throw new Error('ADMIN_ORIGIN must be an origin without a path, query, or fragment.');
}
const expectedOrigin = originUrl.origin;
const rpID = originUrl.hostname;
const setupToken = process.env.ADMIN_SETUP_TOKEN || '';
const localOrigin = rpID === 'localhost' || rpID === '127.0.0.1';

if (!localOrigin && originUrl.protocol !== 'https:') {
  throw new Error('ADMIN_ORIGIN must use HTTPS outside localhost.');
}
if (setupToken && setupToken.length < 32) {
  throw new Error('ADMIN_SETUP_TOKEN must contain at least 32 characters.');
}

let authStore;
let setupCeremonyId = null;
let setupPending = false;

function send(res, status, body, contentType = types['.json'], headers = {}) {
  res.writeHead(status, { 'Content-Type': contentType, ...headers });
  res.end(typeof body === 'string' ? body : JSON.stringify(body));
}

function setSecurityHeaders(res, pathname) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  if (['/admin', '/admin/', '/admin.html', '/admin.js', '/admin-login.js'].includes(pathname)) {
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'");
  }
  if (originUrl.protocol === 'https:') res.setHeader('Strict-Transport-Security', 'max-age=31536000');
}

function getCookie(req, name) {
  const cookie = req.headers.cookie || '';
  for (const part of cookie.split(';')) {
    const [key, ...value] = part.trim().split('=');
    if (key === name) return value.join('=');
  }
  return '';
}

function getSession(req) {
  const token = getCookie(req, sessionCookie);
  const session = sessions.get(token);
  if (!session) return null;
  if (session.expiresAt <= Date.now()) {
    sessions.delete(token);
    return null;
  }
  return { token, ...session };
}

function sessionCookieHeader(token) {
  const secure = originUrl.protocol === 'https:' ? '; Secure' : '';
  return `${sessionCookie}=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge / 1000}${secure}`;
}

function clearSessionCookie() {
  const secure = originUrl.protocol === 'https:' ? '; Secure' : '';
  return `${sessionCookie}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${secure}`;
}

function createSession(res) {
  const now = Date.now();
  for (const [token, session] of sessions) {
    if (session.expiresAt <= now) sessions.delete(token);
  }
  const token = crypto.randomBytes(32).toString('base64url');
  sessions.set(token, { expiresAt: now + maxAge });
  res.setHeader('Set-Cookie', sessionCookieHeader(token));
}

function enforceOrigin(req) {
  if (req.headers.origin !== expectedOrigin) {
    const error = new Error('Request origin was not allowed.');
    error.statusCode = 403;
    throw error;
  }
  if (!String(req.headers['content-type'] || '').toLowerCase().startsWith('application/json')) {
    const error = new Error('Expected a JSON request.');
    error.statusCode = 415;
    throw error;
  }
}

async function readJson(req, maxBytes = 100_000) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maxBytes) {
      const error = new Error('Request is too large.');
      error.statusCode = 413;
      throw error;
    }
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    const error = new Error('Request body must be valid JSON.');
    error.statusCode = 400;
    throw error;
  }
}

function isSetupAllowed() {
  return authStore.credentials.length === 0 && (Boolean(setupToken) || localOrigin);
}

function checkSetupToken(value) {
  if (!setupToken) return localOrigin;
  const supplied = Buffer.from(String(value || ''));
  const expected = Buffer.from(setupToken);
  return supplied.length === expected.length && crypto.timingSafeEqual(supplied, expected);
}

function allowAttempt(req, kind) {
  const key = `${kind}:${req.socket.remoteAddress || 'unknown'}`;
  const now = Date.now();
  const windowMs = 10 * 60 * 1000;
  const current = rateLimits.get(key);
  if (!current || now - current.startedAt >= windowMs) {
    rateLimits.set(key, { startedAt: now, count: 1 });
    return true;
  }
  if (current.count >= 8) return false;
  current.count += 1;
  return true;
}

function rememberCeremony(type, challenge, sessionToken = '') {
  const now = Date.now();
  for (const [id, ceremony] of ceremonies) {
    if (ceremony.expiresAt <= now) {
      ceremonies.delete(id);
      if (setupCeremonyId === id) setupCeremonyId = null;
    }
  }
  if (ceremonies.size >= maxCeremonies) {
    const error = new Error('Too many active passkey requests. Try again in a few minutes.');
    error.statusCode = 429;
    throw error;
  }
  const id = crypto.randomBytes(24).toString('base64url');
  ceremonies.set(id, { type, challenge, sessionToken, expiresAt: now + ceremonyMaxAge });
  return id;
}

async function readAuthStore() {
  try {
    const stored = JSON.parse(await fs.readFile(authPath, 'utf8'));
    if (typeof stored.userID !== 'string' || !Array.isArray(stored.credentials)) throw new Error('Invalid admin credential file.');
    return stored;
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    const fresh = { userID: crypto.randomBytes(32).toString('base64url'), credentials: [] };
    await writeAuthStore(fresh);
    return fresh;
  }
}

async function writeAuthStore(nextStore) {
  const temporaryPath = `${authPath}.tmp`;
  await fs.writeFile(temporaryPath, `${JSON.stringify(nextStore, null, 2)}\n`, { mode: 0o600 });
  await fs.chmod(temporaryPath, 0o600);
  await fs.rename(temporaryPath, authPath);
  authStore = nextStore;
}

function requireSession(req) {
  const session = getSession(req);
  if (!session) {
    const error = new Error('Sign in with your passkey to continue.');
    error.statusCode = 401;
    throw error;
  }
  return session;
}

function registrationOptions() {
  return generateRegistrationOptions({
    rpName: 'Mohamad Moukayed Portfolio',
    rpID,
    userID: Buffer.from(authStore.userID, 'base64url'),
    userName: 'portfolio-admin',
    userDisplayName: 'Portfolio Admin',
    attestationType: 'none',
    authenticatorSelection: {
      residentKey: 'required',
      userVerification: 'required',
    },
    excludeCredentials: authStore.credentials.map(({ id, transports }) => ({ id, transports })),
  });
}

function credentialToJSON(credential) {
  return {
    id: credential.id,
    publicKey: Buffer.from(credential.publicKey).toString('base64url'),
    counter: credential.counter,
    transports: credential.transports || [],
  };
}

async function verifyAndSaveRegistration(credential, ceremony) {
  const verification = await verifyRegistrationResponse({
    response: credential,
    expectedChallenge: ceremony.challenge,
    expectedOrigin,
    expectedRPID: rpID,
    requireUserVerification: true,
  });
  if (!verification.verified || !verification.registrationInfo) throw new Error('Passkey registration could not be verified.');
  const newCredential = credentialToJSON(verification.registrationInfo.credential);
  if (authStore.credentials.some((entry) => entry.id === newCredential.id)) throw new Error('That passkey is already registered.');
  await writeAuthStore({ ...authStore, credentials: [...authStore.credentials, newCredential] });
}

function jsonError(res, error) {
  const status = Number(error.statusCode) || 400;
  send(res, status, { error: status >= 500 ? 'The request could not be completed.' : error.message });
}

async function readStatic(res, file, cacheControl = 'no-cache') {
  try {
    const data = await fs.readFile(path.join(root, file));
    res.writeHead(200, { 'Content-Type': types[path.extname(file)] || 'application/octet-stream', 'Cache-Control': cacheControl });
    res.end(data);
  } catch {
    send(res, 404, { error: 'Not found.' });
  }
}

async function handleAdminApi(req, res, pathname) {
  try {
    if (req.method === 'GET' && pathname === '/api/admin/status') {
      const session = getSession(req);
      return send(res, 200, {
        authenticated: Boolean(session),
        setupRequired: authStore.credentials.length === 0,
        setupAllowed: isSetupAllowed(),
        setupTokenRequired: Boolean(setupToken),
        credentialsCount: authStore.credentials.length,
      }, types['.json'], { 'Cache-Control': 'no-store' });
    }

    if (req.method !== 'POST') {
      const error = new Error('Method not allowed.');
      error.statusCode = 405;
      throw error;
    }
    enforceOrigin(req);
    const body = await readJson(req);

    if (pathname === '/api/admin/setup/options') {
      if (!allowAttempt(req, 'setup')) {
        const error = new Error('Too many setup attempts. Wait ten minutes and try again.');
        error.statusCode = 429;
        throw error;
      }
      if (!isSetupAllowed()) {
        const error = new Error('Passkey setup is unavailable. Configure ADMIN_SETUP_TOKEN for this origin.');
        error.statusCode = 403;
        throw error;
      }
      if (!checkSetupToken(body.setupToken)) {
        const error = new Error('The setup token is incorrect.');
        error.statusCode = 403;
        throw error;
      }
      if (setupPending) {
        const error = new Error('Passkey setup is already starting. Try again in a moment.');
        error.statusCode = 409;
        throw error;
      }
      if (setupCeremonyId) ceremonies.delete(setupCeremonyId);
      setupCeremonyId = null;
      setupPending = true;
      let options;
      try {
        options = await registrationOptions();
        setupCeremonyId = rememberCeremony('setup', options.challenge);
      } finally {
        setupPending = false;
      }
      return send(res, 200, { options, ceremonyId: setupCeremonyId }, types['.json'], { 'Cache-Control': 'no-store' });
    }

    if (pathname === '/api/admin/setup/verify') {
      if (!isSetupAllowed() || !checkSetupToken(body.setupToken)) {
        const error = new Error('Passkey setup is unavailable.');
        error.statusCode = 403;
        throw error;
      }
      if (authStore.credentials.length !== 0) {
        const error = new Error('A passkey has already been set up.');
        error.statusCode = 409;
        throw error;
      }
      const ceremony = ceremonies.get(body.ceremonyId);
      if (setupCeremonyId !== body.ceremonyId) {
        const error = new Error('Passkey setup expired. Start again.');
        error.statusCode = 400;
        throw error;
      }
      ceremonies.delete(body.ceremonyId);
      if (setupCeremonyId === body.ceremonyId) setupCeremonyId = null;
      if (!ceremony || ceremony.type !== 'setup' || ceremony.expiresAt <= Date.now()) {
        const error = new Error('Passkey setup expired. Start again.');
        error.statusCode = 400;
        throw error;
      }
      await verifyAndSaveRegistration(body.credential, ceremony);
      createSession(res);
      return send(res, 200, { authenticated: true });
    }

    if (pathname === '/api/admin/login/options') {
      if (authStore.credentials.length === 0) {
        const error = new Error('Create the first passkey before signing in.');
        error.statusCode = 409;
        throw error;
      }
      const options = await generateAuthenticationOptions({
        rpID,
        allowCredentials: authStore.credentials.map(({ id, transports }) => ({ id, transports })),
        userVerification: 'required',
      });
      const ceremonyId = rememberCeremony('login', options.challenge);
      return send(res, 200, { options, ceremonyId }, types['.json'], { 'Cache-Control': 'no-store' });
    }

    if (pathname === '/api/admin/login/verify') {
      if (!allowAttempt(req, 'login')) {
        const error = new Error('Too many sign-in attempts. Wait ten minutes and try again.');
        error.statusCode = 429;
        throw error;
      }
      const ceremony = ceremonies.get(body.ceremonyId);
      ceremonies.delete(body.ceremonyId);
      if (!ceremony || ceremony.type !== 'login' || ceremony.expiresAt <= Date.now()) {
        const error = new Error('Passkey request expired. Try again.');
        error.statusCode = 400;
        throw error;
      }
      const credential = authStore.credentials.find((entry) => entry.id === body.credential?.id);
      if (!credential) {
        const error = new Error('This passkey is not registered for the admin page.');
        error.statusCode = 401;
        throw error;
      }
      const verification = await verifyAuthenticationResponse({
        response: body.credential,
        expectedChallenge: ceremony.challenge,
        expectedOrigin,
        expectedRPID: rpID,
        requireUserVerification: true,
        credential: {
          id: credential.id,
          publicKey: Buffer.from(credential.publicKey, 'base64url'),
          counter: credential.counter,
          transports: credential.transports,
        },
      });
      if (!verification.verified) {
        const error = new Error('Passkey sign-in failed.');
        error.statusCode = 401;
        throw error;
      }
      const updated = authStore.credentials.map((entry) => entry.id === credential.id
        ? { ...entry, counter: verification.authenticationInfo.newCounter }
        : entry);
      await writeAuthStore({ ...authStore, credentials: updated });
      createSession(res);
      return send(res, 200, { authenticated: true });
    }

    if (pathname === '/api/admin/credentials/options') {
      const session = requireSession(req);
      const options = await registrationOptions();
      const ceremonyId = rememberCeremony('add-credential', options.challenge, session.token);
      return send(res, 200, { options, ceremonyId }, types['.json'], { 'Cache-Control': 'no-store' });
    }

    if (pathname === '/api/admin/credentials/verify') {
      const session = requireSession(req);
      const ceremony = ceremonies.get(body.ceremonyId);
      ceremonies.delete(body.ceremonyId);
      if (!ceremony || ceremony.type !== 'add-credential' || ceremony.sessionToken !== session.token || ceremony.expiresAt <= Date.now()) {
        const error = new Error('Passkey request expired. Start again.');
        error.statusCode = 400;
        throw error;
      }
      await verifyAndSaveRegistration(body.credential, ceremony);
      return send(res, 200, { credentialsCount: authStore.credentials.length });
    }

    if (pathname === '/api/admin/logout') {
      const session = requireSession(req);
      sessions.delete(session.token);
      res.setHeader('Set-Cookie', clearSessionCookie());
      return send(res, 200, { authenticated: false });
    }

    const error = new Error('Not found.');
    error.statusCode = 404;
    throw error;
  } catch (error) {
    return jsonError(res, error);
  }
}

async function handle(req, res) {
  const pathname = new URL(req.url, expectedOrigin).pathname;
  setSecurityHeaders(res, pathname);

  if (req.method === 'GET' && pathname === '/api/content') {
    try {
      const content = await fs.readFile(contentPath);
      res.writeHead(200, { 'Content-Type': types['.json'], 'Cache-Control': 'no-store' });
      return res.end(content);
    } catch {
      return send(res, 500, { error: 'Content could not be loaded.' });
    }
  }

  if (pathname === '/api/content' && req.method === 'PUT') {
    try {
      enforceOrigin(req);
      requireSession(req);
      const incoming = await readJson(req);
      const next = Object.fromEntries(fields.map((field) => [field, String(incoming[field] ?? '').slice(0, 5000)]));
      await fs.writeFile(contentPath, `${JSON.stringify(next, null, 2)}\n`);
      return send(res, 200, next, types['.json'], { 'Cache-Control': 'no-store' });
    } catch (error) {
      return jsonError(res, error);
    }
  }

  if (pathname.startsWith('/api/admin/')) return handleAdminApi(req, res, pathname);

  if (req.method === 'GET' && ['/admin', '/admin/', '/admin.html'].includes(pathname)) {
    const authenticated = Boolean(getSession(req));
    return readStatic(res, authenticated ? 'admin.html' : 'admin-login.html', 'no-store');
  }

  if (req.method === 'GET' && pathname === '/admin.js') {
    if (!getSession(req)) return send(res, 404, { error: 'Not found.' });
    return readStatic(res, 'admin.js', 'no-store');
  }

  if (req.method === 'GET' && pathname === '/admin-login.js') return readStatic(res, 'admin-login.js', 'no-store');

  if (req.method === 'GET' && pathname === '/assets/webauthn-browser.js') {
    try {
      const bundle = await fs.readFile(browserBundlePath);
      res.writeHead(200, { 'Content-Type': types['.js'], 'Cache-Control': 'public, max-age=31536000, immutable' });
      return res.end(bundle);
    } catch {
      return send(res, 500, { error: 'Passkey support could not be loaded. Run npm install.' });
    }
  }

  const publicFiles = new Map([
    ['/', 'index.html'],
    ['/index.html', 'index.html'],
    ['/styles.css', 'styles.css'],
    ['/app.js', 'app.js'],
    ['/content.json', 'content.json'],
  ]);
  if (req.method === 'GET' && publicFiles.has(pathname)) return readStatic(res, publicFiles.get(pathname));
  return send(res, 404, { error: 'Not found.' });
}

async function start() {
  authStore = await readAuthStore();
  const server = http.createServer((req, res) => {
    handle(req, res).catch(() => {
      if (!res.headersSent) send(res, 500, { error: 'The request could not be completed.' });
      else res.destroy();
    });
  });
  server.listen(port, '127.0.0.1', () => {
    console.log(`Portfolio running at http://localhost:${port} (admin: http://localhost:${port}/admin)`);
    if (authStore.credentials.length === 0 && !isSetupAllowed()) {
      console.log('Set ADMIN_SETUP_TOKEN to a random value of at least 32 characters to enable first passkey setup.');
    }
  });
}

start().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
