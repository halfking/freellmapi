import type { Request, Response, NextFunction } from 'express';
import { readCookie, SESSION_COOKIE_NAME } from '../lib/session-cookie.js';
import { gatewayCookieName } from '../services/sso-gateway.js';
import { ssoConfigured } from '../lib/identity.js';

/**
 * Auto sign-in for browser navigations.
 *
 * The visitor arrives at a page of this dashboard. If they already carry a
 * dashboard session, nothing happens. If they do NOT — but they DO carry a
 * gateway session — they are sent to /sso, which asks the gateway for a
 * ticket and turns it into a dashboard session. The net effect is the
 * promise of the whole integration: **signed in to the gateway means signed
 * in here**, with no second form and no second password.
 *
 * Scoped narrowly on purpose:
 *   - only HTML navigations (an XHR asking for JSON must never be
 *     redirected);
 *   - only when this service is actually enrolled in the identity mesh
 *     (no shared secret ⇒ the redirect would be a dead end);
 *   - only for page paths — the API and inference surfaces are mounted
 *     earlier and never reach this middleware.
 */
export function ssoAutoLogin() {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!ssoConfigured()) {
      next();
      return;
    }

    const accept = String(req.headers.accept ?? '');
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      next();
      return;
    }
    if (!accept.includes('text/html')) {
      next();
      return;
    }

    const path = req.originalUrl ?? req.url ?? '';
    if (path.startsWith('/api') || path.startsWith('/v1') || path.startsWith('/v1beta')
      || path.startsWith('/mcp') || path.startsWith('/sso')) {
      next();
      return;
    }

    // Already signed in here — nothing to do.
    if (readCookie(req, SESSION_COOKIE_NAME)) {
      next();
      return;
    }

    // No gateway session either: the visitor has to sign in to the gateway
    // first, and the edge proxy's own gate handles that.
    if (!readCookie(req, gatewayCookieName())) {
      next();
      return;
    }

    const target = path.startsWith('/') ? path : '/';
    res.redirect(302, `/sso?next=${encodeURIComponent(target)}`);
  };
}
