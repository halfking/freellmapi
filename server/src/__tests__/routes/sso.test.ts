import crypto from 'crypto';
import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import express, { type Express } from 'express';
import { createApp } from '../../app.js';
import { initDb, getDb } from '../../db/index.js';
import { DEFAULT_SSO_AUDIENCE } from '../../lib/identity.js';

/**
 * End-to-end shape of the single sign-on landing:
 *
 *   gateway ticket → GET /sso?token=… → flm_session cookie → dashboard open
 *
 * The tests assert the properties that make the flow usable in a browser
 * (the cookie is set, the redirect drops the credential, the cookie alone
 * opens the admin surface) and the ones that keep it safe (a bad ticket
 * never sets a cookie).
 */

const SECRET = 'sso-route-test-shared-secret-32-bytes!!';

function b64url(input: string): string {
  return Buffer.from(input).toString('base64url');
}

function mintTicket(claims: Record<string, unknown> = {}, secret = SECRET): string {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: 'llm-gateway',
    sub: '7',
    aud: DEFAULT_SSO_AUDIENCE,
    user_id: '7',
    tenant_id: 'default',
    roles: ['super_admin'],
    username: 'halfking',
    email: 'halfking@itestu.cn',
    iat: now,
    exp: now + 300,
    ...claims,
  };
  const header = { alg: 'HS256', typ: 'JWT' };
  const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  const signature = crypto.createHmac('sha256', secret).update(signingInput).digest();
  return `${signingInput}.${b64url(signature)}`;
}

async function call(app: Express, path: string, init: RequestInit = {}) {
  const server = app.listen(0, '127.0.0.1');
  if (!server.listening) await new Promise<void>((resolve) => server.once('listening', () => resolve()));
  const addr = server.address() as { port: number };
  const res = await fetch(`http://127.0.0.1:${addr.port}${path}`, { redirect: 'manual', ...init });
  const text = await res.text();
  server.close();
  return {
    status: res.status,
    location: res.headers.get('location'),
    setCookie: res.headers.getSetCookie?.() ?? [],
    body: text,
  };
}

describe('single sign-on landing', () => {
  let app: Express;

  beforeAll(() => {
    process.env.ENCRYPTION_KEY = '0'.repeat(64);
    initDb(':memory:');
    app = createApp();
  });

  beforeEach(() => {
    process.env.IDENTITY_SHARED_SECRET = SECRET;
  });

  afterEach(() => {
    delete process.env.IDENTITY_SHARED_SECRET;
  });

  it('exchanges a valid ticket for a session cookie and redirects home', async () => {
    const res = await call(app, `/sso?token=${encodeURIComponent(mintTicket())}`);

    expect(res.status).toBe(302);
    expect(res.location).toBe('/');
    expect(res.setCookie.length).toBeGreaterThan(0);
    expect(res.setCookie[0]).toContain('flm_session=');
    expect(res.setCookie[0]).toContain('HttpOnly');
    expect(res.setCookie[0]).toContain('SameSite=Lax');
  });

  it('does not leak the ticket into the redirect target', async () => {
    const res = await call(app, `/sso?token=${encodeURIComponent(mintTicket())}`);
    expect(res.location).not.toContain('token=');
  });

  it('refuses to redirect off-site (open redirect guard)', async () => {
    const res = await call(app, `/sso?token=${encodeURIComponent(mintTicket())}&next=${encodeURIComponent('//evil.example.com')}`);
    expect(res.location).toBe('/');
  });

  it('keeps a same-site redirect target', async () => {
    const res = await call(app, `/sso?token=${encodeURIComponent(mintTicket())}&next=${encodeURIComponent('/models')}`);
    expect(res.location).toBe('/models');
  });

  it('rejects a bad ticket without setting a cookie', async () => {
    const res = await call(app, `/sso?token=${encodeURIComponent(mintTicket({}, 'a-different-secret-of-32-bytes!!'))}`);
    expect(res.status).toBe(401);
    expect(res.setCookie.length).toBe(0);
  });

  it('rejects a ticket minted for another audience', async () => {
    const res = await call(app, `/sso?token=${encodeURIComponent(mintTicket({ aud: 'memora-api' }))}`);
    expect(res.status).toBe(401);
    expect(res.body).toContain('audience_mismatch');
  });

  it('answers 503 when single sign-on is not configured', async () => {
    delete process.env.IDENTITY_SHARED_SECRET;
    const res = await call(app, `/sso?token=${encodeURIComponent(mintTicket())}`);
    expect(res.status).toBe(503);
  });

  it('requires a token', async () => {
    const res = await call(app, '/sso');
    expect(res.status).toBe(400);
  });

  it('opens the admin surface with nothing but the cookie', async () => {
    const landing = await call(app, `/sso?token=${encodeURIComponent(mintTicket())}`);
    const cookie = landing.setCookie[0]!.split(';')[0]!;

    // No Authorization header — only the cookie the landing set.
    const status = await call(app, '/api/auth/status', { headers: { cookie } });
    expect(status.status).toBe(200);
    const body = JSON.parse(status.body) as { authenticated: boolean; email: string };
    expect(body.authenticated).toBe(true);
    expect(body.email).toBe('halfking@itestu.cn');

    const me = await call(app, '/api/auth/me', { headers: { cookie } });
    expect(me.status).toBe(200);
  });

  it('still refuses the admin surface without a session', async () => {
    const status = await call(app, '/api/auth/status');
    expect(status.status).toBe(200);
    const body = JSON.parse(status.body) as { authenticated: boolean };
    expect(body.authenticated).toBe(false);
  });

  it('auto-provisions the local account on first sign-in', async () => {
    await call(app, `/sso?token=${encodeURIComponent(mintTicket())}`);
    const row = getDb().prepare('SELECT email FROM users WHERE email = ?').get('halfking@itestu.cn');
    expect(row).toBeTruthy();
  });

  it('reuses the same local account on the next sign-in', async () => {
    await call(app, `/sso?token=${encodeURIComponent(mintTicket())}`);
    await call(app, `/sso?token=${encodeURIComponent(mintTicket())}`);
    const rows = getDb().prepare('SELECT COUNT(*) AS c FROM users').get() as { c: number };
    expect(rows.c).toBe(1);
  });

  it('exchanges a ticket for a session token over the JSON endpoint', async () => {
    const res = await call(app, '/api/auth/sso/exchange', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: mintTicket() }),
    });
    expect(res.status).toBe(200);
    const body = JSON.parse(res.body) as { token: string; email: string };
    expect(body.token).toBeTruthy();
    expect(body.email).toBe('halfking@itestu.cn');
  });
});
