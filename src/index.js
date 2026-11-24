import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';

const contentFields = [
  'heroIntro',
  'featuredTitle',
  'featuredSummary',
  'featuredDescription',
  'competition',
  'team',
  'competitionDescription',
  'email',
  'github',
  'linkedin',
];
const encoder = new TextEncoder();
const sessionDuration = 8 * 60 * 60 * 1000;
const challengeDuration = 5 * 60 * 1000;
const maxRequestBytes = 100_000;
const sessionCookie = 'admin_session';

function jsonResponse(status, value, headers = {}) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...headers },
  });
}

function httpError(message, statusCode = 400) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}

function bytesToBase64Url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64UrlToBytes(value) {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(base64 + '='.repeat((4 - (base64.length % 4)) % 4));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function randomBase64Url(size = 32) {
  return bytesToBase64Url(crypto.getRandomValues(new Uint8Array(size)));
}

async function hash(value) {
  return bytesToBase64Url(new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(value))));
}

async function constantTimeEqual(left, right) {
  const [leftDigest, rightDigest] = await Promise.all([hash(left), hash(right)]);
  let difference = 0;
  for (let index = 0; index < leftDigest.length; index += 1) {
    difference |= leftDigest.charCodeAt(index) ^ rightDigest.charCodeAt(index);
  }
  return difference === 0;
}

function getAdminOrigin(env) {
  if (!env.ADMIN_ORIGIN) throw httpError('ADMIN_ORIGIN is not configured.', 500);
  let parsed;
  try {
    parsed = new URL(env.ADMIN_ORIGIN);
  } catch {
    throw httpError('ADMIN_ORIGIN must be a valid origin.', 500);
  }
  if (parsed.origin !== env.ADMIN_ORIGIN.replace(/\/$/, '') || parsed.pathname !== '/' || parsed.search || parsed.hash) {
    throw httpError('ADMIN_ORIGIN must contain only the site origin.', 500);
  }
  if (parsed.protocol !== 'https:' && parsed.hostname !== 'localhost' && parsed.hostname !== '127.0.0.1') {
    throw httpError('ADMIN_ORIGIN must use HTTPS outside localhost.', 500);
  }
  return parsed;
}

function setupSecretIsConfigured(env) {
  return typeof env.ADMIN_SETUP_TOKEN === 'string' && env.ADMIN_SETUP_TOKEN.length >= 32;
}

async function checkSetupToken(env, supplied) {
  if (!setupSecretIsConfigured(env) || typeof supplied !== 'string') return false;
  return constantTimeEqual(supplied, env.ADMIN_SETUP_TOKEN);
}

function cookieValue(request, name) {
  const header = request.headers.get('Cookie') || '';
  for (const part of header.split(';')) {
    const [key, ...value] = part.trim().split('=');
    if (key === name) return value.join('=');
  }
  return '';
}

function cookieHeader(token, secure) {
  return `${sessionCookie}=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${sessionDuration / 1000}${secure ? '; Secure' : ''}`;
}

function expiredCookie(secure) {
  return `${sessionCookie}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${secure ? '; Secure' : ''}`;
}

async function readJson(request) {
  if (!String(request.headers.get('Content-Type') || '').toLowerCase().startsWith('application/json')) {
    throw httpError('Expected a JSON request.', 415);
  }
  const reader = request.body?.getReader();
  if (!reader) throw httpError('Request body is required.', 400);
  const chunks = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maxRequestBytes) {
      await reader.cancel();
      throw httpError('Request is too large.', 413);
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw httpError('Request body must be valid JSON.', 400);
  }
}

function enforceSameOrigin(request, expectedOrigin) {
  const requestOrigin = new URL(request.url).origin;
  if (request.headers.get('Origin') !== expectedOrigin || requestOrigin !== expectedOrigin) {
    throw httpError('Request origin was not allowed.', 403);
  }
}

async function getPasskeys(db) {
  const result = await db.prepare(
    'SELECT credential_id AS id, public_key AS publicKey, counter, transports FROM admin_passkeys ORDER BY created_at, credential_id',
  ).all();
  return (result.results || []).map((row) => ({
    id: row.id,
    publicKey: row.publicKey,
    counter: row.counter,
    transports: JSON.parse(row.transports || '[]'),
  }));
}

async function getUserId(db) {
  let row = await db.prepare("SELECT value FROM app_meta WHERE key = 'user_id'").first();
  if (!row) {
    await db.prepare("INSERT OR IGNORE INTO app_meta (key, value) VALUES ('user_id', ?)")
      .bind(randomBase64Url(32)).run();
    row = await db.prepare("SELECT value FROM app_meta WHERE key = 'user_id'").first();
  }
  return row.value;
}

async function passkeyCount(db) {
  const result = await db.prepare('SELECT COUNT(*) AS count FROM admin_passkeys').first();
  return Number(result?.count || 0);
}

async function getSession(request, db) {
  const token = cookieValue(request, sessionCookie);
  if (!token) return null;
  const tokenHash = await hash(token);
  const now = Date.now();
  const session = await db.prepare(
    'SELECT token_hash FROM admin_sessions WHERE token_hash = ? AND expires_at > ?',
  ).bind(tokenHash, now).first();
  if (session) return { tokenHash };
  await db.prepare('DELETE FROM admin_sessions WHERE token_hash = ? OR expires_at <= ?')
    .bind(tokenHash, now).run();
  return null;
}

async function requireSession(request, db) {
  const session = await getSession(request, db);
  if (!session) throw httpError('Sign in with your passkey to continue.', 401);
  return session;
}

async function createSession(db) {
  const token = randomBase64Url(32);
  const tokenHash = await hash(token);
  const now = Date.now();
  await db.batch([
    db.prepare('DELETE FROM admin_sessions WHERE expires_at <= ?').bind(now),
    db.prepare('INSERT INTO admin_sessions (token_hash, expires_at) VALUES (?, ?)')
      .bind(tokenHash, now + sessionDuration),
  ]);
  return token;
}

async function allowAttempt(db, request, kind) {
  const address = request.headers.get('CF-Connecting-IP') || 'unknown';
  const now = Date.now();
  const row = await db.prepare(
    'SELECT started_at AS startedAt, count FROM admin_attempts WHERE kind = ? AND client_ip = ?',
  ).bind(kind, address).first();
  if (!row || now - row.startedAt >= 10 * 60 * 1000) {
    await db.prepare(
      'INSERT INTO admin_attempts (kind, client_ip, started_at, count) VALUES (?, ?, ?, 1) ON CONFLICT(kind, client_ip) DO UPDATE SET started_at = excluded.started_at, count = 1',
    ).bind(kind, address, now).run();
    return true;
  }
  if (Number(row.count) >= 8) return false;
  await db.prepare('UPDATE admin_attempts SET count = count + 1 WHERE kind = ? AND client_ip = ?')
    .bind(kind, address).run();
  return true;
}

async function storeCeremony(db, ceremonyId, type, challenge, sessionHash = '') {
  const now = Date.now();
  await db.prepare('DELETE FROM webauthn_challenges WHERE expires_at <= ?').bind(now).run();
  const count = await db.prepare('SELECT COUNT(*) AS count FROM webauthn_challenges').first();
  if (Number(count?.count || 0) >= 128) {
    throw httpError('Too many active passkey requests. Try again in a few minutes.', 429);
  }
  await db.prepare(
    'INSERT INTO webauthn_challenges (ceremony_id, ceremony_type, challenge, session_hash, expires_at) VALUES (?, ?, ?, ?, ?)',
  ).bind(ceremonyId, type, challenge, sessionHash, now + challengeDuration).run();
}

async function consumeCeremony(db, ceremonyId, type, sessionHash = '') {
  if (typeof ceremonyId !== 'string' || !ceremonyId) return null;
  return db.prepare(
    'DELETE FROM webauthn_challenges WHERE ceremony_id = ? AND ceremony_type = ? AND session_hash = ? AND expires_at > ? RETURNING challenge, session_hash AS sessionHash',
  ).bind(ceremonyId, type, sessionHash, Date.now()).first();
}

async function registrationOptions(db, rpID) {
  const passkeys = await getPasskeys(db);
  return generateRegistrationOptions({
    rpName: 'Mohamad Moukayed Portfolio',
    rpID,
    userID: base64UrlToBytes(await getUserId(db)),
    userName: 'portfolio-admin',
    userDisplayName: 'Portfolio Admin',
    attestationType: 'none',
    authenticatorSelection: {
      residentKey: 'required',
      userVerification: 'required',
    },
    excludeCredentials: passkeys.map(({ id, transports }) => ({ id, transports })),
  });
}

function credentialRow(credential) {
  return {
    id: credential.id,
    publicKey: bytesToBase64Url(credential.publicKey),
    counter: credential.counter,
    transports: credential.transports || [],
  };
}

async function verifyRegistration(credential, challenge, origin) {
  const verification = await verifyRegistrationResponse({
    response: credential,
    expectedChallenge: challenge,
    expectedOrigin: origin.origin,
    expectedRPID: origin.hostname,
    requireUserVerification: true,
  });
  if (!verification.verified || !verification.registrationInfo) {
    throw httpError('Passkey registration could not be verified.', 401);
  }
  return credentialRow(verification.registrationInfo.credential);
}

async function savePasskey(db, credential, { firstOnly = false } = {}) {
  const base = [credential.id, credential.publicKey, credential.counter, JSON.stringify(credential.transports)];
  const result = firstOnly
    ? await db.prepare(
      'INSERT INTO admin_passkeys (credential_id, public_key, counter, transports) SELECT ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM admin_passkeys)',
    ).bind(...base).run()
    : await db.prepare(
      'INSERT OR IGNORE INTO admin_passkeys (credential_id, public_key, counter, transports) VALUES (?, ?, ?, ?)',
    ).bind(...base).run();
  if (Number(result.meta?.changes || 0) !== 1) {
    throw httpError(firstOnly ? 'A passkey has already been set up.' : 'That passkey is already registered.', 409);
  }
}

async function issueRegistrationCeremony(db, type, rpID, sessionHash = '') {
  const options = await registrationOptions(db, rpID);
  const ceremonyId = randomBase64Url(24);
  await storeCeremony(db, ceremonyId, type, options.challenge, sessionHash);
  return { options, ceremonyId };
}

async function handleAdminApi(request, env, url, origin) {
  const db = env.portfolio_admin;
  if (request.method === 'GET' && url.pathname === '/api/admin/status') {
    const count = await passkeyCount(db);
    const session = await getSession(request, db);
    return jsonResponse(200, {
      authenticated: Boolean(session),
      setupRequired: count === 0,
      setupAllowed: count === 0 && setupSecretIsConfigured(env),
      setupTokenRequired: count === 0 && setupSecretIsConfigured(env),
      credentialsCount: count,
    }, { 'Cache-Control': 'no-store' });
  }
  if (request.method !== 'POST') throw httpError('Method not allowed.', 405);
  enforceSameOrigin(request, origin.origin);
  const body = await readJson(request);

  if (url.pathname === '/api/admin/setup/options') {
    if (!await allowAttempt(db, request, 'setup')) {
      throw httpError('Too many setup attempts. Wait ten minutes and try again.', 429);
    }
    if (await passkeyCount(db) !== 0 || !setupSecretIsConfigured(env)) {
      throw httpError('Passkey setup is unavailable. Configure ADMIN_SETUP_TOKEN for this origin.', 403);
    }
    if (!await checkSetupToken(env, body.setupToken)) throw httpError('The setup token is incorrect.', 403);
    const options = await registrationOptions(db, origin.hostname);
    const ceremonyId = randomBase64Url(24);
    const now = Date.now();
    await db.batch([
      db.prepare("DELETE FROM webauthn_challenges WHERE ceremony_type = 'setup'"),
      db.prepare(
        'INSERT INTO webauthn_challenges (ceremony_id, ceremony_type, challenge, session_hash, expires_at) VALUES (?, ?, ?, ?, ?)',
      ).bind(ceremonyId, 'setup', options.challenge, '', now + challengeDuration),
      db.prepare("INSERT INTO app_meta (key, value) VALUES ('setup_ceremony_id', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
        .bind(ceremonyId),
    ]);
    return jsonResponse(200, { options, ceremonyId }, { 'Cache-Control': 'no-store' });
  }

  if (url.pathname === '/api/admin/setup/verify') {
    if (await passkeyCount(db) !== 0 || !await checkSetupToken(env, body.setupToken)) {
      throw httpError('Passkey setup is unavailable.', 403);
    }
    const current = await db.prepare("SELECT value FROM app_meta WHERE key = 'setup_ceremony_id'").first();
    if (!current || current.value !== body.ceremonyId) throw httpError('Passkey setup expired. Start again.', 400);
    const ceremony = await consumeCeremony(db, body.ceremonyId, 'setup');
    await db.prepare("DELETE FROM app_meta WHERE key = 'setup_ceremony_id'").run();
    if (!ceremony) throw httpError('Passkey setup expired. Start again.', 400);
    const credential = await verifyRegistration(body.credential, ceremony.challenge, origin);
    await savePasskey(db, credential, { firstOnly: true });
    const token = await createSession(db);
    return jsonResponse(200, { authenticated: true }, {
      'Cache-Control': 'no-store',
      'Set-Cookie': cookieHeader(token, origin.protocol === 'https:'),
    });
  }

  if (url.pathname === '/api/admin/login/options') {
    if (await passkeyCount(db) === 0) throw httpError('Create the first passkey before signing in.', 409);
    const passkeys = await getPasskeys(db);
    const options = await generateAuthenticationOptions({
      rpID: origin.hostname,
      allowCredentials: passkeys.map(({ id, transports }) => ({ id, transports })),
      userVerification: 'required',
    });
    const ceremonyId = randomBase64Url(24);
    await storeCeremony(db, ceremonyId, 'login', options.challenge);
    return jsonResponse(200, { options, ceremonyId }, { 'Cache-Control': 'no-store' });
  }

  if (url.pathname === '/api/admin/login/verify') {
    if (!await allowAttempt(db, request, 'login')) {
      throw httpError('Too many sign-in attempts. Wait ten minutes and try again.', 429);
    }
    const ceremony = await consumeCeremony(db, body.ceremonyId, 'login');
    if (!ceremony) throw httpError('Passkey request expired. Try again.', 400);
    const passkeys = await getPasskeys(db);
    const credential = passkeys.find((entry) => entry.id === body.credential?.id);
    if (!credential) throw httpError('This passkey is not registered for the admin page.', 401);
    const verification = await verifyAuthenticationResponse({
      response: body.credential,
      expectedChallenge: ceremony.challenge,
      expectedOrigin: origin.origin,
      expectedRPID: origin.hostname,
      requireUserVerification: true,
      credential: {
        id: credential.id,
        publicKey: base64UrlToBytes(credential.publicKey),
        counter: credential.counter,
        transports: credential.transports,
      },
    });
    if (!verification.verified) throw httpError('Passkey sign-in failed.', 401);
    await db.prepare('UPDATE admin_passkeys SET counter = ? WHERE credential_id = ?')
      .bind(verification.authenticationInfo.newCounter, credential.id).run();
    const token = await createSession(db);
    return jsonResponse(200, { authenticated: true }, {
      'Cache-Control': 'no-store',
      'Set-Cookie': cookieHeader(token, origin.protocol === 'https:'),
    });
  }

  if (url.pathname === '/api/admin/credentials/options') {
    const session = await requireSession(request, db);
    return jsonResponse(200, await issueRegistrationCeremony(db, 'add-credential', origin.hostname, session.tokenHash), {
      'Cache-Control': 'no-store',
    });
  }

  if (url.pathname === '/api/admin/credentials/verify') {
    const session = await requireSession(request, db);
    const ceremony = await consumeCeremony(db, body.ceremonyId, 'add-credential', session.tokenHash);
    if (!ceremony) throw httpError('Passkey request expired. Start again.', 400);
    const credential = await verifyRegistration(body.credential, ceremony.challenge, origin);
    await savePasskey(db, credential);
    return jsonResponse(200, { credentialsCount: await passkeyCount(db) }, { 'Cache-Control': 'no-store' });
  }

  if (url.pathname === '/api/admin/logout') {
    const session = await requireSession(request, db);
    await db.prepare('DELETE FROM admin_sessions WHERE token_hash = ?').bind(session.tokenHash).run();
    return jsonResponse(200, { authenticated: false }, {
      'Cache-Control': 'no-store',
      'Set-Cookie': expiredCookie(origin.protocol === 'https:'),
    });
  }

  throw httpError('Not found.', 404);
}

async function handleContentApi(request, env) {
  const db = env.portfolio_admin;
  if (request.method === 'GET') {
    const row = await db.prepare('SELECT content_json FROM portfolio_content WHERE id = 1').first();
    if (!row) throw httpError('Portfolio content has not been initialized.', 500);
    return new Response(row.content_json, {
      status: 200,
      headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
    });
  }
  if (request.method !== 'PUT') throw httpError('Method not allowed.', 405);
  await requireSession(request, db);
  const body = await readJson(request);
  const content = Object.fromEntries(contentFields.map((field) => [field, String(body?.[field] ?? '').slice(0, 5000)]));
  const serialized = JSON.stringify(content);
  await db.prepare(
    'INSERT INTO portfolio_content (id, content_json, updated_at) VALUES (1, ?, ?) ON CONFLICT(id) DO UPDATE SET content_json = excluded.content_json, updated_at = excluded.updated_at',
  ).bind(serialized, Date.now()).run();
  return jsonResponse(200, content, { 'Cache-Control': 'no-store' });
}

async function fetchAsset(env, request, pathname) {
  const assetUrl = new URL(request.url);
  assetUrl.pathname = pathname;
  assetUrl.search = '';
  return env.ASSETS.fetch(new Request(assetUrl, { method: 'GET', headers: request.headers }));
}

function addSecurityHeaders(response, pathname, origin) {
  const headers = new Headers(response.headers);
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('Referrer-Policy', 'no-referrer');
  headers.set('X-Frame-Options', 'DENY');
  headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  if (origin.protocol === 'https:') headers.set('Strict-Transport-Security', 'max-age=31536000');
  if (['/admin', '/admin/', '/admin.html', '/admin.js', '/admin-login.html', '/admin-login.js'].includes(pathname)) {
    headers.set('Cache-Control', 'no-store');
    headers.set('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'");
  }
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

export default {
  async fetch(request, env) {
    let origin;
    const url = new URL(request.url);
    try {
      origin = getAdminOrigin(env);
      let response;

      if (url.pathname === '/api/content') {
        if (request.method !== 'GET') enforceSameOrigin(request, origin.origin);
        response = await handleContentApi(request, env);
      } else if (url.pathname.startsWith('/api/admin/')) {
        response = await handleAdminApi(request, env, url, origin);
      } else if (request.method === 'GET' && ['/admin', '/admin/', '/admin.html', '/admin-login.html'].includes(url.pathname)) {
        const session = await getSession(request, env.portfolio_admin);
        const assetName = session ? '/admin.html' : '/admin-login.html';
        response = await fetchAsset(env, request, assetName);
      } else if (request.method === 'GET' && url.pathname === '/admin.js') {
        const session = await getSession(request, env.portfolio_admin);
        response = session ? await fetchAsset(env, request, '/admin.js') : jsonResponse(404, { error: 'Not found.' });
      } else if (request.method === 'GET' && url.pathname === '/admin-login.js') {
        response = await fetchAsset(env, request, url.pathname);
      } else {
        response = await env.ASSETS.fetch(request);
      }

      return addSecurityHeaders(response, url.pathname, origin);
    } catch (error) {
      const response = jsonResponse(Number(error.statusCode) || 400, {
        error: Number(error.statusCode) >= 500 ? 'The request could not be completed.' : error.message,
      }, { 'Cache-Control': 'no-store' });
      if (!origin) {
        const fallback = new URL(request.url);
        return addSecurityHeaders(response, url.pathname, fallback);
      }
      return addSecurityHeaders(response, url.pathname, origin);
    }
  },
};
