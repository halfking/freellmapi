import { Router } from 'express';
import type { Request, Response } from 'express';
import { exchangeSsoToken } from '../services/sso.js';
import { fetchGatewayTicket } from '../services/sso-gateway.js';
import { SESSION_TTL_MS } from '../services/auth.js';
import { isSecureRequest, setSessionCookie } from '../lib/session-cookie.js';

/**
 * Single sign-on landing routes.
 *
 * Two shapes, one verification path:
 *
 *   GET  /sso?token=…      browser landing — the gateway redirects here after
 *                          it has confirmed the visitor's gateway session.
 *                          Sets the dashboard cookie and bounces to the app.
 *   POST /api/auth/sso/exchange
 *                          programmatic exchange — returns the session token
 *                          for a client that wants to drive the dashboard
 *                          itself.
 *
 * Both are mounted OUTSIDE the dashboard session gate on purpose: the token
 * in the URL IS the credential, and requiring a session to obtain a session
 * would be circular.
 */
export const ssoRouter = Router();

/** Only same-site, path-only targets are accepted as a redirect target. */
function safeNext(raw: unknown): string {
  if (typeof raw !== 'string') return '/';
  if (!raw.startsWith('/')) return '/';
  // "//host" and "/\host" are protocol-relative URLs — following them would
  // turn the landing route into an open redirect.
  if (raw.startsWith('//') || raw.startsWith('/\\')) return '/';
  return raw;
}

function readTokenFromQuery(req: Request): string | undefined {
  const token = req.query.token ?? req.query.jwt;
  if (typeof token === 'string') return token;
  if (Array.isArray(token) && typeof token[0] === 'string') return token[0];
  return undefined;
}

function readTokenFromBody(req: Request): string | undefined {
  const body = (req.body ?? {}) as { token?: unknown; jwt?: unknown };
  const token = body.token ?? body.jwt;
  if (typeof token === 'string') return token;
  return undefined;
}

function errorBody(code: string, message: string): { error: { message: string; type: string; code: string } } {
  return { error: { message, type: 'authentication_error', code } };
}

ssoRouter.get('/', async (req: Request, res: Response) => {
  const token = readTokenFromQuery(req);

  if (!token) {
    // No ticket in the URL: ask the gateway for one on the visitor's behalf.
    // The gateway is the identity source, so it is the only party that can
    // say "this browser is signed in as X".
    const ticket = await fetchGatewayTicket(req);
    if (!ticket.ok) {
      res.status(ticket.status).json(errorBody(ticket.code, ticket.message));
      return;
    }
    completeSsoLogin(req, res, ticket.token);
    return;
  }

  completeSsoLogin(req, res, token);
});

/**
 * Verify a ticket and finish the landing: a dashboard session, the cookie
 * that carries it, and a redirect that drops the credential from the URL.
 */
function completeSsoLogin(req: Request, res: Response, token: string): void {
  const result = exchangeSsoToken(token);
  if (!result.ok) {
    res.status(result.status).json(errorBody(result.code, result.message));
    return;
  }

  // The cookie is what makes the dashboard usable afterwards: the browser
  // sends it on every same-origin request, so the SPA lands on the dashboard
  // instead of the login form.
  setSessionCookie(res, result.token, SESSION_TTL_MS / 1000, isSecureRequest(req));

  // The token is a credential, so it must not survive in the address bar (it
  // would end up in history, in the Referer of the next navigation, and in
  // any proxy log between here and the app).
  res.redirect(302, safeNext(req.query.next));
}

ssoRouter.post('/exchange', (req: Request, res: Response) => {
  const token = readTokenFromBody(req);
  if (!token) {
    res.status(400).json(errorBody('missing_token', 'No identity token supplied'));
    return;
  }

  const result = exchangeSsoToken(token);
  if (!result.ok) {
    res.status(result.status).json(errorBody(result.code, result.message));
    return;
  }

  setSessionCookie(res, result.token, SESSION_TTL_MS / 1000, isSecureRequest(req));
  res.json({
    token: result.token,
    email: result.email,
    user_id: result.userId,
    expires_at: new Date(result.expiresAtMs).toISOString(),
  });
});
