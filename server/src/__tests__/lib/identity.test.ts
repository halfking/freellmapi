import crypto from 'crypto';
import { describe, expect, it, beforeEach, afterEach } from 'vitest';
import {
  DEFAULT_ISSUER_ALLOWLIST,
  DEFAULT_SSO_AUDIENCE,
  expectedAudience,
  issuerAllowlist,
  sharedSecret,
  verifyIdentityToken,
} from '../../lib/identity.js';

/**
 * The verifier is the trust boundary between llm-gateway-go and this
 * dashboard: a token that verifies here is a session here. These tests pin the
 * four checks the identity-go contract requires (alg / iss / aud / exp) and
 * the fail-closed behaviour when the mesh is not configured.
 */

const SECRET = 'test-shared-secret-value-of-32-bytes!!';
const OTHER_SECRET = 'a-different-secret-of-32-bytes-!!';

interface ClaimsInput {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  user_id?: string;
  tenant_id?: string;
  roles?: string[];
  scope?: string;
  email?: string;
  username?: string;
  exp?: number;
  nbf?: number;
  iat?: number;
}

function b64url(input: string | Buffer): string {
  return Buffer.from(input).toString('base64url');
}

function sign(claims: ClaimsInput, secret = SECRET, alg = 'HS256'): string {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: claims.iss ?? 'llm-gateway',
    sub: claims.sub ?? 'u-1',
    aud: claims.aud ?? DEFAULT_SSO_AUDIENCE,
    user_id: claims.user_id ?? '42',
    tenant_id: claims.tenant_id ?? 'default',
    roles: claims.roles ?? ['admin'],
    scope: claims.scope ?? '',
    iat: claims.iat ?? now,
    exp: claims.exp ?? now + 300,
    ...(claims.email ? { email: claims.email } : {}),
    ...(claims.username ? { username: claims.username } : {}),
    ...(claims.nbf !== undefined ? { nbf: claims.nbf } : {}),
  };
  const header = { alg, typ: 'JWT' };
  const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  if (alg === 'none') return `${signingInput}.`;
  const signature = crypto.createHmac('sha256', secret).update(signingInput).digest();
  return `${signingInput}.${b64url(signature)}`;
}

describe('cross-project identity verification', () => {
  const original = {
    secret: process.env.IDENTITY_SHARED_SECRET,
    allowlist: process.env.IDENTITY_ISSUER_ALLOWLIST,
    audience: process.env.FREELLMAPI_SSO_AUDIENCE,
  };

  beforeEach(() => {
    process.env.IDENTITY_SHARED_SECRET = SECRET;
    delete process.env.IDENTITY_ISSUER_ALLOWLIST;
    delete process.env.FREELLMAPI_SSO_AUDIENCE;
  });

  afterEach(() => {
    if (original.secret === undefined) delete process.env.IDENTITY_SHARED_SECRET;
    else process.env.IDENTITY_SHARED_SECRET = original.secret;
    if (original.allowlist === undefined) delete process.env.IDENTITY_ISSUER_ALLOWLIST;
    else process.env.IDENTITY_ISSUER_ALLOWLIST = original.allowlist;
    if (original.audience === undefined) delete process.env.FREELLMAPI_SSO_AUDIENCE;
    else process.env.FREELLMAPI_SSO_AUDIENCE = original.audience;
  });

  it('accepts a gateway token minted for this audience', () => {
    const result = verifyIdentityToken(sign({ email: 'admin@itestu.cn', username: 'admin' }));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.claims.issuer).toBe('llm-gateway');
    expect(result.claims.subject).toBe('u-1');
    expect(result.claims.userId).toBe('42');
    expect(result.claims.tenantId).toBe('default');
    expect(result.claims.roles).toEqual(['admin']);
    expect(result.claims.email).toBe('admin@itestu.cn');
    expect(result.claims.username).toBe('admin');
  });

  it('refuses a token signed with another secret', () => {
    const result = verifyIdentityToken(sign({}, OTHER_SECRET));
    expect(result).toMatchObject({ ok: false, code: 'bad_signature' });
  });

  it('refuses a token whose payload was tampered with', () => {
    const token = sign({ sub: 'u-1' });
    const [header, , signature] = token.split('.');
    const forged = b64url(JSON.stringify({ iss: 'llm-gateway', sub: 'u-999', aud: DEFAULT_SSO_AUDIENCE, exp: Math.floor(Date.now() / 1000) + 300 }));
    const result = verifyIdentityToken(`${header}.${forged}.${signature}`);
    expect(result).toMatchObject({ ok: false, code: 'bad_signature' });
  });

  it('refuses alg=none', () => {
    const result = verifyIdentityToken(sign({}, SECRET, 'none'));
    expect(result).toMatchObject({ ok: false, code: 'bad_algorithm' });
  });

  it('refuses an asymmetric algorithm even with a valid-looking signature', () => {
    const now = Math.floor(Date.now() / 1000);
    const header = b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
    const payload = b64url(JSON.stringify({ iss: 'llm-gateway', sub: 'u-1', aud: DEFAULT_SSO_AUDIENCE, exp: now + 300 }));
    const result = verifyIdentityToken(`${header}.${payload}.${b64url('x')}`);
    expect(result).toMatchObject({ ok: false, code: 'bad_algorithm' });
  });

  it('refuses a token minted for another audience', () => {
    const result = verifyIdentityToken(sign({ aud: 'memora-api' }));
    expect(result).toMatchObject({ ok: false, code: 'audience_mismatch' });
  });

  it('accepts an audience array that contains this service', () => {
    const result = verifyIdentityToken(sign({ aud: ['memora-api', DEFAULT_SSO_AUDIENCE] }));
    expect(result.ok).toBe(true);
  });

  it('refuses an issuer outside the allowlist', () => {
    const result = verifyIdentityToken(sign({ iss: 'asm' }));
    expect(result).toMatchObject({ ok: false, code: 'issuer_not_allowed' });
  });

  it('honours a configured issuer allowlist', () => {
    process.env.IDENTITY_ISSUER_ALLOWLIST = 'memora';
    expect(issuerAllowlist()).toEqual(['memora']);
    expect(verifyIdentityToken(sign({ iss: 'llm-gateway' }))).toMatchObject({ ok: false, code: 'issuer_not_allowed' });
    expect(verifyIdentityToken(sign({ iss: 'memora' })).ok).toBe(true);
  });

  it('defaults to the canonical six-project issuer set', () => {
    expect(issuerAllowlist()).toEqual(DEFAULT_ISSUER_ALLOWLIST);
  });

  it('refuses an expired token', () => {
    const now = Math.floor(Date.now() / 1000);
    const result = verifyIdentityToken(sign({ exp: now - 1 }));
    expect(result).toMatchObject({ ok: false, code: 'token_expired' });
  });

  it('refuses a token without an expiry', () => {
    const now = Math.floor(Date.now() / 1000);
    const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
    const payload = b64url(JSON.stringify({ iss: 'llm-gateway', sub: 'u-1', aud: DEFAULT_SSO_AUDIENCE, iat: now }));
    const signingInput = `${header}.${payload}`;
    const signature = crypto.createHmac('sha256', SECRET).update(signingInput).digest();
    const result = verifyIdentityToken(`${signingInput}.${b64url(signature)}`);
    expect(result).toMatchObject({ ok: false, code: 'missing_expiry' });
  });

  it('refuses a token that is not yet valid', () => {
    const now = Math.floor(Date.now() / 1000);
    const result = verifyIdentityToken(sign({ nbf: now + 600, exp: now + 1200 }));
    expect(result).toMatchObject({ ok: false, code: 'token_not_yet_valid' });
  });

  it('fails closed when the shared secret is not configured', () => {
    delete process.env.IDENTITY_SHARED_SECRET;
    expect(sharedSecret()).toBeNull();
    const result = verifyIdentityToken(sign({}));
    expect(result).toMatchObject({ ok: false, code: 'sso_not_configured' });
  });

  it('fails closed when the shared secret is too short', () => {
    process.env.IDENTITY_SHARED_SECRET = 'too-short';
    expect(sharedSecret()).toBeNull();
    expect(verifyIdentityToken(sign({}))).toMatchObject({ ok: false, code: 'sso_not_configured' });
  });

  it('refuses a malformed token', () => {
    expect(verifyIdentityToken('not-a-jwt')).toMatchObject({ ok: false, code: 'malformed_token' });
    expect(verifyIdentityToken(undefined)).toMatchObject({ ok: false, code: 'missing_token' });
  });

  it('keeps unknown claims available as pass-through extras', () => {
    const now = Math.floor(Date.now() / 1000);
    const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
    const payload = b64url(JSON.stringify({
      iss: 'llm-gateway', sub: 'u-1', aud: DEFAULT_SSO_AUDIENCE, exp: now + 300,
      workspace_id: 'ws-7', isAdmin: true,
    }));
    const signingInput = `${header}.${payload}`;
    const signature = crypto.createHmac('sha256', SECRET).update(signingInput).digest();
    const result = verifyIdentityToken(`${signingInput}.${b64url(signature)}`);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.claims.extra).toMatchObject({ workspace_id: 'ws-7', isAdmin: true });
  });

  it('uses this service as the default audience', () => {
    expect(expectedAudience()).toBe(DEFAULT_SSO_AUDIENCE);
    process.env.FREELLMAPI_SSO_AUDIENCE = 'freellmapi-api-v2';
    expect(expectedAudience()).toBe('freellmapi-api-v2');
  });
});
