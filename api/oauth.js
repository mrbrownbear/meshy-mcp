import {
  createHash, createHmac, createCipheriv, createDecipheriv,
  randomBytes, timingSafeEqual
} from 'node:crypto';

const b64 = value => Buffer.from(value).toString('base64url');
const unb64 = value => Buffer.from(value, 'base64url');

export function config() {
  const issuer = process.env.OAUTH_ISSUER?.replace(/\/$/, '');
  const secret = process.env.OAUTH_SECRET;
  if (!issuer || !/^https:\/\/[a-z0-9.-]+(?::\d+)?$/i.test(issuer)) {
    throw new Error('OAUTH_ISSUER must be a stable HTTPS origin');
  }
  if (!secret || Buffer.byteLength(secret, 'utf8') < 32) {
    throw new Error('OAUTH_SECRET requires at least 32 bytes of random entropy');
  }
  return {
    issuer,
    resource: `${issuer}/mcp`,
    encKey: createHash('sha256').update(`meshy:enc:v1:${secret}`).digest(),
    macKey: createHash('sha256').update(`meshy:mac:v1:${secret}`).digest(),
    allowedHosts: (process.env.OAUTH_ALLOWED_REDIRECT_HOSTS || 'chatgpt.com')
      .split(',').map(x => x.trim().toLowerCase()).filter(Boolean)
  };
}

export function seal(data, secretKey, ttlSeconds) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', secretKey, iv);
  const plain = Buffer.from(JSON.stringify({ ...data, exp: Math.floor(Date.now()/1000) + ttlSeconds }));
  const result = Buffer.concat([cipher.update(plain), cipher.final()]);
  return `msh1.${b64(Buffer.concat([iv, cipher.getAuthTag(), result]))}`;
}

export function unseal(value, key, expectedType) {
  if (typeof value !== 'string' || !value.startsWith('msh1.') || value.length > 12000) {
    throw new Error('Invalid OAuth token');
  }
  const bytes = unb64(value.slice(5));
  if (bytes.length < 29) throw new Error('Invalid OAuth token');
  const decipher = createDecipheriv('aes-256-gcm', key, bytes.subarray(0, 12));
  decipher.setAuthTag(bytes.subarray(12, 28));
  const data = JSON.parse(Buffer.concat([decipher.update(bytes.subarray(28)), decipher.final()]).toString());
  if (data.type !== expectedType || !Number.isSafeInteger(data.exp) || Date.now()/1000 >= data.exp) {
    throw new Error('OAuth token expired or invalid');
  }
  return data;
}

export function makeClientId(redirectUris, cfg) {
  const payload = b64(JSON.stringify({ r: redirectUris }));
  const signature = b64(createHmac('sha256', cfg.macKey).update(payload).digest());
  return `mshc1.${payload}.${signature}`;
}

export function getClient(clientId, cfg) {
  const staticId = process.env.OAUTH_CLIENT_ID;
  if (staticId && clientId === staticId) {
    const uris = (process.env.OAUTH_REDIRECT_URIS || '').split(',').map(x => x.trim()).filter(Boolean);
    if (!uris.length) throw new Error('OAUTH_REDIRECT_URIS not configured');
    return uris;
  }
  if (typeof clientId !== 'string' || clientId.length > 10000) throw new Error('Unknown OAuth client');
  const parts = clientId.split('.');
  if (parts.length !== 3 || parts[0] !== 'mshc1') throw new Error('Unknown OAuth client');
  const expected = createHmac('sha256', cfg.macKey).update(parts[1]).digest();
  const given = unb64(parts[2]);
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) throw new Error('Unknown OAuth client');
  const decoded = JSON.parse(unb64(parts[1]).toString());
  return decoded.r;
}

export function validateRedirect(uri, cfg) {
  if (typeof uri !== 'string' || uri.length > 2048) throw new Error('Invalid redirect_uri');
  let url;
  try { url = new URL(uri); } catch { throw new Error('Invalid redirect_uri'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash || !cfg.allowedHosts.includes(url.hostname.toLowerCase())) {
    throw new Error('Redirect URI host is not allowlisted');
  }
  return url.toString();
}

export function sha256pkce(value) {
  return b64(createHash('sha256').update(value).digest());
}
export function isValidVerifier(value) {
  return typeof value === 'string' && /^[A-Za-z0-9._~-]{43,128}$/.test(value);
}
export function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const aa = Buffer.from(a), bb = Buffer.from(b);
  return aa.length === bb.length && timingSafeEqual(aa, bb);
}
/**
 * Browser form-action also applies to redirect targets after an HTML form POST.
 * Authorizing with ChatGPT redirects cross-origin to its allowlisted callback.
 * Keep the relaxation confined to the authorization form response.
 */
export function contentSecurityPolicy(allowedHosts = []) {
  const hosts = [...new Set(allowedHosts
    .filter(host => typeof host === 'string' &&
      /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/i.test(host) &&
      !host.includes('..'))
    .map(host => 'https://' + host.toLowerCase()))];
  const actions = ["'self'", ...hosts].join(' ');
  return "default-src 'none'; form-action " + actions +
    "; base-uri 'none'; frame-ancestors 'none'; style-src 'unsafe-inline'";
}

export function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
}
export function parseParams(req) {
  if (req.body && typeof req.body === 'object' && !Buffer.isBuffer(req.body)) return req.body;
  const str = typeof req.body === 'string' ? req.body : Buffer.isBuffer(req.body) ? req.body.toString() : '';
  if ((req.headers['content-type'] || '').includes('application/json')) {
    try { return JSON.parse(str); } catch { return {}; }
  }
  return Object.fromEntries(new URLSearchParams(str));
}
