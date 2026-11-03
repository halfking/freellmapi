import crypto from 'crypto';
import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from 'vitest';
import express, { type Express } from 'express';
import { createApp } from '../../app.js';
import { initDb } from '../../db/index.js';
import { DEFAULT_SSO_AUDIENCE } from '../../lib/identity.js';

/**
 * The full browser path:
 *
 *   open the dashboard → no local session, but a gateway session
 *     → redirected to /sso
 *     → /sso asks the gateway for a ticket (forwarding ONLY the gateway cookie)
 *     → ticket verified → local session + cookie → dashboard
 *
 * The gateway is stubbed here, so the test is about the wiring: what is
 * forwarded, what is not, and what the visitor ends up with.
 */

const SECRET = 'sso-gateway-test-shared-secret-32-bytes!!';
const GATEWAY_COOKIE = 'llmgw_session';

function b64url(input: string): string {
  return Buffer.from(input).toString('base64url');
}

function mintTicket(secret = SECRET): string {
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

describe('single sign-on through the gateway', () => {
  let app: Express;
  let fetchMock: ReturnType<typeof vi.fn>;
  let seenCookieHeader: string | undefined;
  /** The response the gateway stub hands back; tests can swap it. */
  let gatewayResponse: () => Response;

  beforeAll(() => {
    process.env.ENCRYPTION_KEY = '0'.repeat(64);
    initDb(':memory:');
    app = createApp();
  });

  beforeEach(() => {
    process.env.IDENTITY_SHARED_SECRET = SECRET;
    process.env.FREELLMAPI_GATEWAY_URL = 'https://gateway.example.com';
    seenCookieHeader = undefined;
    // The response the gateway stub hands back; a test can swap it (e.g. to
    // hand back a ticket with the wrong signature).
    gatewayResponse = () => new Response(JSON.stringify({ token: mintTicket() }), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'X-LLMGW-App-Token': mintTicket() },
    });
    // The stub must only answer the GATEWAY. Everything else (the test's own
    // HTTP calls) has to reach the real network stack, or the test would be
    // talking to itself.
    const realFetch = globalThis.fetch;
    fetchMock = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      if (!url.includes('gateway.example.com')) {
        return realFetch(input as RequestInfo, init);
      }
      const headers = new Headers((init?.headers ?? {}) as HeadersInit);
      seenCookieHeader = headers.get('cookie') ?? undefined;
      return gatewayResponse();
    });
    vi.stubGlobal('fetch', fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    delete process.env.IDENTITY_SHARED_SECRET;
    delete process.env.FREELLMAPI_GATEWAY_URL;
  });

  it('redirects a browser with a gateway session to /sso', async () => {
    const res = await call(app, '/', {
      headers: { accept: 'text/html', cookie: `${GATEWAY_COOKIE}=gw-session-value` },
    });
    expect(res.status).toBe(302);
    expect(res.location).toContain('/sso');
  });

  it('does not redirect when the visitor already has a dashboard session', async () => {
    const res = await call(app, '/', {
      headers: {
        accept: 'text/html',
        cookie: `${GATEWAY_COOKIE}=gw-session-value; flm_session=local-session`,
      },
    });
    // Not a redirect to /sso — the dashboard is served as usual.
    expect(res.location ?? '').not.toContain('/sso');
  });

  it('does not redirect a visitor without a gateway session', async () => {
    const res = await call(app, '/', { headers: { accept: 'text/html' } });
    expect(res.location ?? '').not.toContain('/sso');
  });

  it('does not redirect a non-navigation request (XHR)', async () => {
    const res = await call(app, '/', {
      headers: { accept: 'application/json', cookie: `${GATEWAY_COOKIE}=gw-session-value` },
    });
    expect(res.location ?? '').not.toContain('/sso');
  });

  it('exchanges a gateway ticket for a dashboard session', async () => {
    const res = await call(app, '/sso', {
      headers: { accept: 'text/html', cookie: `${GATEWAY_COOKIE}=gw-session-value` },
    });
    expect(res.status).toBe(302);
    expect(res.location).toBe('/');
    expect(res.setCookie[0]).toContain('flm_session=');
  });

  it('forwards ONLY the gateway cookie to the gateway', async () => {
    await call(app, '/sso', {
      headers: {
        accept: 'text/html',
        cookie: `${GATEWAY_COOKIE}=gw-session-value; flm_session=local-secret-value; other=thing`,
      },
    });
    expect(fetchMock).toHaveBeenCalled();
    expect(seenCookieHeader).toContain(`${GATEWAY_COOKIE}=gw-session-value`);
    expect(seenCookieHeader).not.toContain('flm_session');
    expect(seenCookieHeader).not.toContain('other=thing');
  });

  it('asks the gateway for the right app', async () => {
    await call(app, '/sso', {
      headers: { accept: 'text/html', cookie: `${GATEWAY_COOKIE}=gw-session-value` },
    });
    const gatewayCall = fetchMock.mock.calls
      .map((call) => String(call[0]))
      .find((url) => url.includes('gateway.example.com'));
    expect(gatewayCall).toBeTruthy();
    expect(gatewayCall).toContain('/api/auth/app-token?app=freellmapi');
  });

  it('answers 401 when the visitor has no gateway session at all', async () => {
    const res = await call(app, '/sso', { headers: { accept: 'text/html' } });
    expect(res.status).toBe(401);
    expect(res.body).toContain('no_gateway_session');
  });

  it('answers 503 when this service is not enrolled in the mesh', async () => {
    delete process.env.FREELLMAPI_GATEWAY_URL;
    const res = await call(app, '/sso', {
      headers: { accept: 'text/html', cookie: `${GATEWAY_COOKIE}=gw-session-value` },
    });
    expect(res.status).toBe(503);
  });

  it('refuses a ticket the gateway hands back with the wrong signature', async () => {
    gatewayResponse = () => new Response(
      JSON.stringify({ token: mintTicket('a-completely-different-secret-32b!') }),
      { status: 200, headers: { 'Content-Type': 'application/json' } },
    );
    const res = await call(app, '/sso', {
      headers: { accept: 'text/html', cookie: `${GATEWAY_COOKIE}=gw-session-value` },
    });
    expect(res.status).toBe(401);
    expect(res.setCookie.length).toBe(0);
  });
});
