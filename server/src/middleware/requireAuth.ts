import type { Request, Response, NextFunction } from 'express';
import { validateSession } from '../services/auth.js';
import { resolveSessionToken } from '../lib/session-cookie.js';

// Gate the /api/* admin surface behind a dashboard session (#35, item #2).
// The token is the opaque session token issued by /api/auth/login|setup, sent
// as `Authorization: Bearer <token>`. The /v1 proxy is NOT gated by this — it
// keeps its own unified-API-key auth for app clients.
//
// Two transports are accepted for the same session: the `Authorization`
// header the SPA keeps in localStorage, and the `flm_session` cookie that
// single sign-on sets. The cookie is what lets a user who signed in to
// llm-gateway-go use this dashboard without ever seeing a login form.
export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  const session = validateSession(resolveSessionToken(req));
  if (!session) {
    res.status(401).json({ error: { message: 'Authentication required', type: 'authentication_error' } });
    return;
  }
  (req as Request & { user?: typeof session }).user = session;
  next();
}
