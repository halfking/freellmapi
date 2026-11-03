import crypto from 'crypto';

/**
 * Cross-project identity verification — the FreeLLMAPI side of the shared
 * identity contract used by llm-gateway-go, RedClaw, openpocket, memora and
 * acc-go (the contract is documented in llm-gateway-go/pkg/identity/README.md
 * and implemented there in pkg/identity/token).
 *
 * Why this exists: FreeLLMAPI runs behind llm-gateway-go in the request chain
 * (agent → gateway → FreeLLMAPI). The gateway owns the user/tenant/role
 * identity for that whole product line, so a user who signed in to the
 * gateway must be able to open this dashboard without a second login. The
 * contract is deliberately a SHARED SYMMETRIC SECRET + ISSUER ALLOWLIST, not
 * a shared user database: the gateway mints a short-lived, audience-scoped
 * token for this service, and this module verifies it.
 *
 * The verification rules below are a deliberate, line-by-line port of
 * identity-go's `token.VerifyMultiIssuer` — the same four checks, in the same
 * order, with the same failure semantics:
 *
 *   1. alg must be exactly HS256 (rejects `alg: none` and every asymmetric
 *      algorithm, so a token can never be verified with a public key as the
 *      HMAC secret).
 *   2. iss must be in the allowlist.
 *   3. aud must contain the expected audience — the audience is the
 *      resource-server boundary, so a token minted for another service
 *      (aud=redclaw-api) is refused here even though it carries a valid
 *      signature.
 *   4. exp must exist and be in the future (nbf is honoured when present).
 *
 * Fail-closed by construction: with no shared secret configured, verification
 * always fails — there is no fallback secret and no "trust anyone" mode.
 */

// The canonical env var names. These are the SAME names the other six
// projects use, so one value can be copied into each deployment without
// renaming anything.
export const ENV_SHARED_SECRET = 'IDENTITY_SHARED_SECRET';
export const ENV_ISSUER_ALLOWLIST = 'IDENTITY_ISSUER_ALLOWLIST';
export const ENV_SSO_AUDIENCE = 'FREELLMAPI_SSO_AUDIENCE';

// The audience of THIS service. A token minted for another audience is not
// accepted here: the audience is what keeps a gateway-issued token for
// `memora-api` from being replayed against the dashboard.
export const DEFAULT_SSO_AUDIENCE = 'freellmapi-api';

// The shared issuers of the identity mesh. FreeLLMAPI is a pure VERIFIER: it
// never mints a user token of its own, so it does not need to be listed here
// (the same posture ai-session-manager takes in the gateway).
export const DEFAULT_ISSUER_ALLOWLIST = ['redclaw', 'memora', 'llm-gateway', 'pocket', 'acc'];

// identity-go's LoadSharedSecret refuses anything shorter than 32 bytes. The
// same floor applies here: a short secret is a weak HMAC key, and silently
// accepting one would make the trust boundary depend on an operator typo.
const MIN_SECRET_BYTES = 32;

export interface IdentityClaims {
  /** iss — the project that minted the token. */
  issuer: string;
  /** sub — the subject inside that project. */
  subject: string;
  /** aud — the audience(s) the token was minted for. */
  audience: string[];
  /** user_id — the minting project's own user id, as a string. */
  userId: string;
  /** tenant_id — the minting project's tenant. */
  tenantId: string;
  /** roles — the minting project's roles for this user. */
  roles: string[];
  /** scope — the service scope the token grants. */
  scope: string;
  /** iat / exp — seconds since the epoch. */
  issuedAt: number;
  expiresAt: number;
  /** email — pass-through claim, when the minter included one. */
  email: string;
  /** username — pass-through claim, when the minter included one. */
  username: string;
  /** everything else the minter put in the token. */
  extra: Record<string, unknown>;
}

export type IdentityVerifyResult =
  | { ok: true; claims: IdentityClaims }
  | { ok: false; code: string; message: string };

/** The configured shared secret, or null when it is absent/too weak. */
export function sharedSecret(): string | null {
  const raw = (process.env[ENV_SHARED_SECRET] ?? '').trim();
  if (raw.length < MIN_SECRET_BYTES) return null;
  return raw;
}

/** The issuers whose tokens are accepted. */
export function issuerAllowlist(): string[] {
  const raw = (process.env[ENV_ISSUER_ALLOWLIST] ?? '').trim();
  if (!raw) return [...DEFAULT_ISSUER_ALLOWLIST];
  const parsed = raw
    .split(',')
    .map((entry) => entry.trim().toLowerCase())
    .filter(Boolean);
  return parsed.length > 0 ? parsed : [...DEFAULT_ISSUER_ALLOWLIST];
}

/** The audience this service accepts. */
export function expectedAudience(): string {
  const raw = (process.env[ENV_SSO_AUDIENCE] ?? '').trim();
  return raw || DEFAULT_SSO_AUDIENCE;
}

/** True when SSO is configured at all — used to answer "is this feature on?". */
export function ssoConfigured(): boolean {
  return sharedSecret() !== null;
}

function base64UrlDecode(segment: string): Buffer {
  // Node's base64url decoder tolerates missing padding, which is what every
  // JWT producer emits.
  return Buffer.from(segment, 'base64url');
}

function parseJsonSegment(segment: string): Record<string, unknown> {
  const decoded = base64UrlDecode(segment).toString('utf8');
  const parsed = JSON.parse(decoded) as unknown;
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('segment is not a JSON object');
  }
  return parsed as Record<string, unknown>;
}

/**
 * Constant-time signature comparison.
 *
 * crypto.timingSafeEqual throws when the two buffers have different lengths,
 * and "different length" is itself a signal — so both sides are hashed to a
 * fixed size first and the digests are compared. The digest comparison is
 * still constant time, and the length of the signature itself leaks nothing
 * useful (it is fixed at 32 bytes for HS256).
 */
function signatureMatches(signingInput: string, signature: Buffer, secret: string): boolean {
  const expected = crypto.createHmac('sha256', secret).update(signingInput).digest();
  const a = crypto.createHash('sha256').update(expected).digest();
  const b = crypto.createHash('sha256').update(signature).digest();
  return crypto.timingSafeEqual(a, b);
}

/** identity-go's AudienceStrings: a single audience may be comma-separated. */
function audienceList(value: unknown): string[] {
  if (typeof value === 'string') {
    return value
      .split(',')
      .map((entry) => entry.trim())
      .filter(Boolean);
  }
  if (Array.isArray(value)) {
    return value
      .filter((entry): entry is string => typeof entry === 'string')
      .map((entry) => entry.trim())
      .filter(Boolean);
  }
  return [];
}

function stringClaim(payload: Record<string, unknown>, key: string): string {
  const value = payload[key];
  return typeof value === 'string' ? value : '';
}

function numberClaim(payload: Record<string, unknown>, key: string): number {
  const value = payload[key];
  return typeof value === 'number' && Number.isFinite(value) ? value : 0;
}

/**
 * Verify a cross-project identity token.
 *
 * Returns a discriminated result instead of throwing: every caller in this
 * codebase answers HTTP, so a rejection reason (and not a stack trace) is
 * what the caller actually needs.
 */
export function verifyIdentityToken(raw: string | undefined | null): IdentityVerifyResult {
  const token = (raw ?? '').trim();
  if (!token) {
    return { ok: false, code: 'missing_token', message: 'No identity token supplied' };
  }

  const secret = sharedSecret();
  if (!secret) {
    // Fail closed. An install without IDENTITY_SHARED_SECRET has no identity
    // mesh membership, so it must not accept a token signed with anything.
    return {
      ok: false,
      code: 'sso_not_configured',
      message: `Single sign-on is not configured: ${ENV_SHARED_SECRET} is unset or shorter than ${MIN_SECRET_BYTES} bytes`,
    };
  }

  const parts = token.split('.');
  if (parts.length !== 3) {
    return { ok: false, code: 'malformed_token', message: 'Identity token is not a compact JWT' };
  }
  const [headerSegment, payloadSegment, signatureSegment] = parts as [string, string, string];

  let header: Record<string, unknown>;
  let payload: Record<string, unknown>;
  try {
    header = parseJsonSegment(headerSegment);
    payload = parseJsonSegment(payloadSegment);
  } catch {
    return { ok: false, code: 'malformed_token', message: 'Identity token header/payload is not valid JSON' };
  }

  // 1. Algorithm — HS256 only. `alg: none` and RS256 are both refused here,
  // so an attacker cannot downgrade the verification or smuggle a public key
  // in as the shared secret.
  if (header.alg !== 'HS256') {
    return {
      ok: false,
      code: 'bad_algorithm',
      message: `Unsupported token algorithm ${String(header.alg)} (expected HS256)`,
    };
  }

  // 2. Signature.
  let signature: Buffer;
  try {
    signature = base64UrlDecode(signatureSegment);
  } catch {
    return { ok: false, code: 'malformed_token', message: 'Identity token signature is not base64url' };
  }
  if (!signatureMatches(`${headerSegment}.${payloadSegment}`, signature, secret)) {
    return { ok: false, code: 'bad_signature', message: 'Identity token signature does not verify' };
  }

  // 3. Issuer allowlist.
  const issuer = stringClaim(payload, 'iss').toLowerCase();
  if (!issuer) {
    return { ok: false, code: 'missing_issuer', message: 'Identity token has no iss claim' };
  }
  if (!issuerAllowlist().includes(issuer)) {
    return { ok: false, code: 'issuer_not_allowed', message: `Issuer ${issuer} is not in the allowlist` };
  }

  // 4. Audience — the resource-server boundary.
  const audiences = audienceList(payload.aud);
  if (audiences.length === 0) {
    return { ok: false, code: 'missing_audience', message: 'Identity token has no aud claim' };
  }
  const wanted = expectedAudience();
  if (!audiences.includes(wanted)) {
    return {
      ok: false,
      code: 'audience_mismatch',
      message: `Identity token audience ${audiences.join(',')} does not include ${wanted}`,
    };
  }

  // 5. Time bounds. exp is mandatory — a token without it would be valid
  // forever, which is exactly what a leaked browser URL would want.
  const expiresAt = numberClaim(payload, 'exp');
  if (expiresAt === 0) {
    return { ok: false, code: 'missing_expiry', message: 'Identity token has no exp claim' };
  }
  const nowSec = Math.floor(Date.now() / 1000);
  if (nowSec >= expiresAt) {
    return { ok: false, code: 'token_expired', message: 'Identity token has expired' };
  }
  const notBefore = numberClaim(payload, 'nbf');
  if (notBefore !== 0 && nowSec < notBefore) {
    return { ok: false, code: 'token_not_yet_valid', message: 'Identity token is not valid yet' };
  }

  // 6. Subject — identity-go requires it, so the same token is not usable as
  // an anonymous "system" grant here.
  const subject = stringClaim(payload, 'sub');
  if (!subject) {
    return { ok: false, code: 'missing_subject', message: 'Identity token has no sub claim' };
  }

  const known = new Set([
    'iss', 'sub', 'aud', 'user_id', 'tenant_id', 'roles', 'scope',
    'iat', 'exp', 'nbf',
  ]);
  const extra: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(payload)) {
    if (!known.has(key)) extra[key] = value;
  }

  const roles = Array.isArray(payload.roles)
    ? payload.roles.filter((role): role is string => typeof role === 'string')
    : [];

  return {
    ok: true,
    claims: {
      issuer,
      subject,
      audience: audiences,
      userId: stringClaim(payload, 'user_id'),
      tenantId: stringClaim(payload, 'tenant_id'),
      roles,
      scope: stringClaim(payload, 'scope'),
      issuedAt: numberClaim(payload, 'iat'),
      expiresAt,
      email: stringClaim(payload, 'email'),
      username: stringClaim(payload, 'username'),
      extra,
    },
  };
}
