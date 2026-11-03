import { createSession, createSsoUser, findUserByEmail, SESSION_TTL_MS } from './auth.js';
import { verifyIdentityToken, type IdentityClaims } from '../lib/identity.js';

/**
 * Single sign-on exchange: turn a gateway-minted identity token into a
 * FreeLLMAPI dashboard session.
 *
 * The chain of custody:
 *
 *   llm-gateway-go  ──mints──▶  JWT (iss=llm-gateway, aud=freellmapi-api)
 *        │                          signed with IDENTITY_SHARED_SECRET
 *        ▼
 *   FreeLLMAPI      ──verifies──▶  local user row (auto-provisioned)
 *                                   └──▶  dashboard session (opaque token)
 *
 * The gateway stays the single source of user identity: this service never
 * asks the user for a second password, and it never invents a tenant. What it
 * does own is the mapping from a gateway identity to a local dashboard
 * account, so an audit of "who touched this dashboard" can still be answered
 * from the local session table.
 */

export type SsoExchangeResult =
  | { ok: true; token: string; email: string; userId: number; expiresAtMs: number }
  | { ok: false; status: number; code: string; message: string };

/** Domain used when the gateway did not put an email on the token. */
const SYNTHETIC_EMAIL_DOMAIN = 'gateway.local';

function sanitizeLocalPart(value: string): string {
  // The email column is the local account key, so a synthetic address has to
  // survive the same normalization a real address would. Everything that is
  // not a letter/digit/dot/dash/underscore collapses to a dash.
  return value.trim().toLowerCase().replace(/[^a-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '');
}

/**
 * The local account an identity maps to.
 *
 * Preference order:
 *   1. the email the gateway put on the token — same human, same account;
 *   2. `<username>@gateway.local`;
 *   3. `<subject>@gateway.local`.
 *
 * A synthetic address is used rather than reusing the subject alone so the
 * mapping stays stable and readable in the dashboard's account list.
 */
export function localEmailFor(claims: IdentityClaims): string {
  const email = claims.email.trim();
  if (email && /^[^@\s]+@[^@\s.]+\.[^@\s]+$/.test(email)) {
    return email.toLowerCase();
  }
  const basis = sanitizeLocalPart(claims.username || claims.subject || 'unknown');
  return `${basis || 'unknown'}@${SYNTHETIC_EMAIL_DOMAIN}`;
}

/**
 * Exchange a gateway identity token for a dashboard session.
 *
 * Failure modes are explicit HTTP statuses because both callers are HTTP
 * surfaces: 503 when this service is not enrolled in the identity mesh, 401
 * when the token is not acceptable, 502 when the token is fine but the local
 * account could not be established.
 */
export function exchangeSsoToken(rawToken: string | undefined | null): SsoExchangeResult {
  const verified = verifyIdentityToken(rawToken);
  if (!verified.ok) {
    const status = verified.code === 'sso_not_configured' ? 503 : 401;
    return { ok: false, status, code: verified.code, message: verified.message };
  }

  const claims = verified.claims;
  const email = localEmailFor(claims);

  let userId: number;
  try {
    const existing = findUserByEmail(email);
    if (existing) {
      userId = existing.userId;
    } else {
      userId = createSsoUser(email).userId;
    }
  } catch (error) {
    return {
      ok: false,
      status: 502,
      code: 'sso_account_failed',
      message: `Could not establish a local account for the gateway identity: ${(error as Error).message}`,
    };
  }

  const token = createSession(userId);
  return {
    ok: true,
    token,
    email,
    userId,
    expiresAtMs: Date.now() + SESSION_TTL_MS,
  };
}
