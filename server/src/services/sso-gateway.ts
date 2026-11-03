import type { Request } from 'express';

/**
 * The gateway side of the single sign-on handshake.
 *
 * The gateway owns the user identity, so it is also the only place that can
 * issue a ticket for a browser session. This module asks it for one, on
 * behalf of the visitor whose gateway cookie arrived with the request.
 *
 * Two rules make this safe to do from a request handler:
 *
 *   1. Only the gateway's OWN cookie is forwarded. The visitor's dashboard
 *      cookie (and anything else in the jar) stays here — forwarding the
 *      whole jar would hand this service's session token to another service
 *      for no reason.
 *   2. The ticket is audience-scoped and short-lived on the gateway side;
 *      this side verifies it before it becomes a session. A forged or
 *      replayed ticket is rejected by the shared secret.
 */

export const ENV_GATEWAY_URL = 'FREELLMAPI_GATEWAY_URL';
export const ENV_GATEWAY_COOKIE = 'FREELLMAPI_GATEWAY_COOKIE';
export const ENV_GATEWAY_APP = 'FREELLMAPI_GATEWAY_APP';

const DEFAULT_GATEWAY_COOKIE = 'llmgw_session';
const DEFAULT_GATEWAY_APP = 'freellmapi';
const REQUEST_TIMEOUT_MS = 8000;

export type GatewayTicketResult =
  | { ok: true; token: string }
  | { ok: false; status: number; code: string; message: string };

/** The gateway's base URL, or null when this service is not enrolled. */
export function gatewayUrl(): string | null {
  const raw = (process.env[ENV_GATEWAY_URL] ?? '').trim();
  if (!raw) return null;
  return raw.replace(/\/+$/, '');
}

/** The cookie name that carries the gateway's session. */
export function gatewayCookieName(): string {
  const raw = (process.env[ENV_GATEWAY_COOKIE] ?? '').trim();
  return raw || DEFAULT_GATEWAY_COOKIE;
}

/** The app code the gateway knows this service by. */
export function gatewayAppCode(): string {
  const raw = (process.env[ENV_GATEWAY_APP] ?? '').trim();
  return raw || DEFAULT_GATEWAY_APP;
}

/**
 * Extract one cookie value from a raw `Cookie` header.
 *
 * Only the gateway's cookie is ever forwarded (see the module comment), so
 * this deliberately takes a name rather than returning the whole jar.
 */
export function readCookieValue(cookieHeader: string | undefined, name: string): string | undefined {
  if (!cookieHeader) return undefined;
  for (const part of cookieHeader.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() !== name) continue;
    const value = part.slice(eq + 1).trim();
    if (!value) return undefined;
    try {
      return decodeURIComponent(value);
    } catch {
      return value;
    }
  }
  return undefined;
}

/**
 * Ask the gateway for a ticket for the visitor's session.
 *
 * Returns the ticket in the JSON body; the `X-LLMGW-App-Token` header is
 * accepted as a fallback (the gateway sets both, and a proxy in between may
 * drop one of them).
 */
export async function fetchGatewayTicket(req: Request): Promise<GatewayTicketResult> {
  const base = gatewayUrl();
  if (!base) {
    return {
      ok: false,
      status: 503,
      code: 'gateway_not_configured',
      message: `Single sign-on is not configured: ${ENV_GATEWAY_URL} is unset`,
    };
  }

  const cookieName = gatewayCookieName();
  const gatewayCookie = readCookieValue(req.headers.cookie, cookieName);
  if (!gatewayCookie) {
    // No gateway session in this request — the visitor has to sign in to the
    // gateway first. Nothing to ask for.
    return {
      ok: false,
      status: 401,
      code: 'no_gateway_session',
      message: 'This request carries no gateway session',
    };
  }

  const url = `${base}/api/auth/app-token?app=${encodeURIComponent(gatewayAppCode())}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        // Only the gateway's cookie travels; nothing else from the jar.
        Cookie: `${cookieName}=${gatewayCookie}`,
        Accept: 'application/json',
      },
      signal: controller.signal,
    });

    if (!response.ok) {
      return {
        ok: false,
        status: response.status === 401 || response.status === 403 ? 401 : 502,
        code: response.status === 401 || response.status === 403
          ? 'gateway_session_rejected'
          : 'gateway_ticket_failed',
        message: `The gateway refused to issue a ticket (HTTP ${response.status})`,
      };
    }

    const headerToken = response.headers.get('x-llmgw-app-token');
    let bodyToken = '';
    try {
      const body = await response.json() as { token?: unknown };
      if (typeof body?.token === 'string') bodyToken = body.token;
    } catch {
      // A body we cannot parse is not fatal if the header carried the ticket.
    }

    const token = bodyToken || headerToken || '';
    if (!token) {
      return {
        ok: false,
        status: 502,
        code: 'gateway_ticket_empty',
        message: 'The gateway returned no ticket',
      };
    }
    return { ok: true, token };
  } catch (error) {
    const aborted = (error as Error).name === 'AbortError';
    return {
      ok: false,
      status: aborted ? 504 : 502,
      code: aborted ? 'gateway_timeout' : 'gateway_unreachable',
      message: aborted
        ? `The gateway did not answer within ${REQUEST_TIMEOUT_MS}ms`
        : `Could not reach the gateway: ${(error as Error).message}`,
    };
  }
}

/**
 * Whether this request looks like a browser navigating to a page.
 *
 * The auto sign-in redirect must not fire for XHRs, asset requests or API
 * calls: they are not navigations, and redirecting them would break the
 * dashboard's own calls.
 */
export function isHtmlNavigation(req: Request): boolean {
  if (req.method !== 'GET' && req.method !== 'HEAD') return false;
  const accept = String(req.headers.accept ?? '');
  return accept.includes('text/html');
}
