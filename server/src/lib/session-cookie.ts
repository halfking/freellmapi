import type { Request, Response } from 'express';

/**
 * The dashboard session cookie.
 *
 * Why a cookie at all: the session token that the dashboard uses is normally
 * held in the browser's localStorage and replayed as `Authorization: Bearer`.
 * That model cannot express "you are already signed in to the gateway" — the
 * browser has to hold a token for THIS service before it will render the
 * dashboard. A cookie is set by the server (the SSO landing route) and sent
 * back automatically on every same-origin request, so a user who arrived
 * through the gateway never sees a login form and never has to paste
 * anything.
 *
 * It is HttpOnly on purpose: the cookie is a bearer credential for the
 * dashboard, and the client-side code has no business reading it. The SPA
 * keeps using its own localStorage token for the rest of its life; the cookie
 * is the *additional* path that single sign-on uses.
 *
 * SameSite=Lax (not Strict) because the landing route is a top-level
 * navigation from another origin (the gateway) — a Strict cookie would not
 * be sent on that first request, and the session would appear to be lost
 * exactly when it was just created.
 */
export const SESSION_COOKIE_NAME = 'flm_session';

/**
 * Read one cookie from the request.
 *
 * Parsed by hand instead of pulling in cookie-parser: the header is a flat
 * `name=value; name=value` list, and the only cookie this service cares
 * about is one it set itself. A value is percent-decoded because a token
 * could legitimately contain characters that are not cookie-safe.
 */
export function readCookie(req: Request, name: string): string | undefined {
  const header = req.headers.cookie;
  if (!header) return undefined;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    const key = part.slice(0, eq).trim();
    if (key !== name) continue;
    const value = part.slice(eq + 1).trim();
    if (!value) return undefined;
    try {
      return decodeURIComponent(value);
    } catch {
      // A malformed percent-escape means the cookie was not written by us.
      // Hand back the raw value; the session lookup will simply not match.
      return value;
    }
  }
  return undefined;
}

/**
 * The session token carried by this request, from either transport.
 *
 * Order matters: an explicit `Authorization` header (the SPA's localStorage
 * token) wins over the cookie, so a browser that holds both uses the token
 * it can revoke on its own.
 */
export function resolveSessionToken(req: Request): string | undefined {
  const header = req.headers.authorization?.replace(/^Bearer\s+/i, '')
    ?? (req.headers['x-dashboard-token'] as string | undefined);
  if (header) return header;
  return readCookie(req, SESSION_COOKIE_NAME);
}

/** Whether the request reached us over TLS (directly or via a proxy). */
export function isSecureRequest(req: Request): boolean {
  if (req.secure) return true;
  const forwarded = req.headers['x-forwarded-proto'];
  const first = (Array.isArray(forwarded) ? forwarded[0] : forwarded)?.split(',')[0]?.trim().toLowerCase();
  return first === 'https';
}

/** Set the dashboard session cookie. */
export function setSessionCookie(res: Response, token: string, maxAgeSeconds: number, secure: boolean): void {
  const attributes = [
    `${SESSION_COOKIE_NAME}=${encodeURIComponent(token)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${Math.max(0, Math.floor(maxAgeSeconds))}`,
  ];
  // `Secure` is only added on an HTTPS origin: a browser refuses to store a
  // Secure cookie sent over plain HTTP, and a LAN install (http://box:3001)
  // would silently lose every session.
  if (secure) attributes.push('Secure');
  res.append('Set-Cookie', attributes.join('; '));
}

/** Remove the dashboard session cookie. */
export function clearSessionCookie(res: Response, secure: boolean): void {
  const attributes = [
    `${SESSION_COOKIE_NAME}=`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    'Max-Age=0',
  ];
  if (secure) attributes.push('Secure');
  res.append('Set-Cookie', attributes.join('; '));
}
