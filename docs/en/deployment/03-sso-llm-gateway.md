**English** · [简体中文](../../zh-cn/deployment/03-sso-llm-gateway.md)

# Single sign-on with llm-gateway-go

FreeLLMAPI can run behind llm-gateway-go in the request chain:

```
client agent → llm-gateway-go → FreeLLMAPI → upstream providers
```

In that shape the gateway owns the user identity: somebody who signed in to
the gateway opens this dashboard directly, with no second login and no second
password to remember.

## How it works

The two services share the **cross-project identity contract** that
llm-gateway-go already uses with RedClaw, openpocket, memora and acc (the
contract is specified in `llm-gateway-go/pkg/identity/README.md`):

1. The browser arrives at the dashboard. It carries a gateway session cookie
   (the gateway sets it on `Domain=.itestu.cn`, so it reaches this host) but
   no dashboard session yet.
2. This service notices the situation and redirects the navigation to
   `GET /sso` (the redirect only fires for HTML navigations — an XHR asking
   for JSON is never redirected).
3. `/sso` asks the gateway for a ticket: it calls the gateway's
   `GET /api/auth/app-token?app=freellmapi`, **forwarding only the gateway's
   own cookie** — this service's session token never leaves.
4. The gateway mints a **short-lived JWT** for the signed-in user:
   `iss=llm-gateway`, `aud=freellmapi-api`, signed with the shared secret
   (`IDENTITY_SHARED_SECRET`), valid for five minutes.
5. FreeLLMAPI verifies the ticket (signature, issuer allowlist, audience,
   expiry), maps the identity onto a local account, mints a dashboard session
   and sets the `flm_session` cookie.
6. The dashboard renders. Every later request carries the cookie, so the
   login form never appears.

A ticket can also be supplied directly (`GET /sso?token=…`) — that is the
shape a reverse proxy or a hand-written link uses.

The ticket is scoped three ways, on purpose:

| Property | Why it matters |
| --- | --- |
| Audience (`aud=freellmapi-api`) | A token minted for another service is refused here, even with a valid signature. |
| Issuer allowlist | Only the mesh's issuers are trusted. |
| 5-minute lifetime | A URL that leaks into history or a proxy log is worthless almost immediately. |

This service never learns the gateway's session-signing secret — only the
shared mesh secret — so a compromise here cannot be replayed as a gateway
session.

## Configuration

```bash
# .env on the FreeLLMAPI host
IDENTITY_SHARED_SECRET=<the same 32+ byte value the gateway uses>
IDENTITY_ISSUER_ALLOWLIST=redclaw,memora,llm-gateway,pocket,acc   # optional
FREELLMAPI_SSO_AUDIENCE=freellmapi-api                            # optional
FREELLMAPI_GATEWAY_URL=https://llm.example.com                    # optional
FREELLMAPI_GATEWAY_COOKIE=llmgw_session                           # optional
FREELLMAPI_GATEWAY_APP=freellmapi                                 # optional
```

`FREELLMAPI_GATEWAY_URL` is where the ticket is requested from — point it at
the gateway's reachable base URL (the mesh entry, or the container address
inside the same Docker network). Without it the landing route cannot ask for
a ticket, and only the explicit `?token=` shape works.

All of them are opt-in. **With `IDENTITY_SHARED_SECRET` unset (or shorter
than 32 bytes) single sign-on is off** and every token is refused — there is
no fallback secret.

On the gateway side:

```bash
IDENTITY_SHARED_SECRET=<same value>
FREELLMAPI_PUBLIC_URL=https://freellm.example.com   # optional, adds a ready URL
```

## The endpoints

| Endpoint | Where | Purpose |
| --- | --- | --- |
| `GET /sso` | here | Browser landing. Asks the gateway for a ticket (or takes `?token=…`), verifies it, sets the `flm_session` cookie, redirects to `/`. |
| `POST /api/auth/sso/exchange` | here | Programmatic exchange. Body `{"token":"…"}`, returns the dashboard session token. |
| `GET /api/auth/app-token?app=freellmapi` | **on the gateway** | Mints the ticket for the signed-in user. |

The gateway endpoint also returns the ticket in an `X-LLMGW-App-Token`
response header, so a reverse proxy can capture it in an `auth_request`
without parsing a JSON body. That is what makes a fully automatic
"open the app, land inside it" flow possible with no front-end round trip.

## Reverse proxy

The dashboard is served behind the edge proxy, which gates it on the
gateway's own session and forwards the landing hop:

```nginx
location = /sso {
    proxy_pass http://freellmapi_upstream;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $http_x_forwarded_proto;
}

location / {
    auth_request /_llmgw_auth;      # → the gateway's /api/auth/me
    proxy_pass http://freellmapi_upstream;
    proxy_set_header Cookie $http_cookie;
}
```

`/api/ping`, `/v1/*` and `/v1beta/*` stay outside the session gate: the
inference surface authenticates with the unified API key, and a health probe
must not need a browser session.

## What single sign-on does *not* change

- The **local password login keeps working**. It is the fallback for running
  the app standalone, and it is how the first account is claimed.
- **Any user the gateway authenticates becomes a dashboard operator here.**
  This app has a single-operator model (no per-user roles), so the gateway
  decides *who gets in*, not *what they may do*. Per-role gating inside the
  dashboard would need its own authorization model.
- The **unified API key** still authenticates the `/v1` inference surface and
  is unaffected by any of this.

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| `503 single sign-on is not configured` | `IDENTITY_SHARED_SECRET` is unset or under 32 bytes on this service. |
| `401 audience mismatch` | The gateway minted for another audience, or `FREELLMAPI_SSO_AUDIENCE` differs between the two sides. |
| `401 issuer … not in the allowlist` | The minting issuer is not in `IDENTITY_ISSUER_ALLOWLIST`. |
| `401 token expired` | The ticket is older than five minutes — request a fresh one. |
| Landing page still shows the login form | The `flm_session` cookie was not stored (browser refused it) or the redirect landed on a path that bypasses the cookie. Check that the proxy forwards `Set-Cookie` unchanged. |
