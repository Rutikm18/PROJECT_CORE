/**
 * apiFetch — one place that makes every dashboard API call carry its credential.
 *
 * WHY THIS EXISTS
 * The operator session is delivered two ways at login (auth_ui.py): an httpOnly
 * `al_session` cookie (SameSite=Strict) AND the same JWT in localStorage. The
 * backend accepts either — `authz.py` reads the cookie first, then an
 * `Authorization: Bearer` header.
 *
 * Most `fetch()` call sites send neither explicitly and lean on the browser's
 * default cookie behaviour. On localhost that is fine. Behind the AWS Caddy
 * proxy / a real domain it is not: the SameSite=Strict cookie is not reliably
 * attached, the call returns 401, and AuthContext treats any 401 as "session
 * gone" and logs the operator out. Patching call sites one page at a time (the
 * `credentials: "include"` additions already scattered across the code) can
 * never be complete — the next un-patched page 401s again.
 *
 * WHAT THIS DOES
 * A single install-once wrapper around window.fetch. For SAME-ORIGIN requests
 * to `/api/...` it:
 *   1. forces `credentials: "include"` so the cookie flows in every transport, and
 *   2. for operator routes attaches `Authorization: Bearer <al_token>` from
 *      localStorage when the caller has not set it — a header credential that
 *      no cookie/SameSite/Secure/proxy quirk can strip.
 *
 * WHAT IT DELIBERATELY LEAVES ALONE
 *   • Cross-origin requests — never touched (no token leaks off-origin, no CORS).
 *   • `/api/v1/portal/*` — the customer portal owns a *different* session
 *     (`al_portal_session`); injecting the operator token there would make the
 *     backend reject it (wrong audience → 403). Portal calls still get
 *     `credentials: "include"`, which is a harmless no-op for its own client.
 *   • An Authorization header the caller already set (e.g. AuthContext logout).
 */

// Must match TOKEN_KEY in AuthContext.tsx — the operator JWT mirror.
const TOKEN_KEY = "al_token";

// Portal routes carry their own session; never attach the operator token here.
const PORTAL_PREFIX = "/api/v1/portal";

let installed = false;

/** Resolve the request path for same-origin `/api` detection. Returns "" when
 *  the request is cross-origin or the URL cannot be understood. */
function sameOriginApiPath(input: RequestInfo | URL): string {
  let raw: string;
  if (typeof input === "string") raw = input;
  else if (input instanceof URL) raw = input.href;
  else if (input instanceof Request) raw = input.url;
  else return "";

  try {
    // Relative URLs resolve against the current origin; absolute ones keep theirs.
    const u = new URL(raw, window.location.origin);
    if (u.origin !== window.location.origin) return "";   // cross-origin: hands off
    return u.pathname;
  } catch {
    return "";
  }
}

function readToken(): string | null {
  try {
    return localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;   // storage disabled/blocked — fall back to cookie-only auth
  }
}

/**
 * Install the wrapper. Idempotent — safe to call more than once. Call before the
 * app makes its first request (see main.tsx).
 */
export function installApiFetch(): void {
  if (installed || typeof window === "undefined" || typeof window.fetch !== "function") {
    return;
  }
  installed = true;

  const originalFetch = window.fetch.bind(window);

  window.fetch = function patchedFetch(
    input: RequestInfo | URL,
    init?: RequestInit,
  ): Promise<Response> {
    const path = sameOriginApiPath(input);
    if (!path.startsWith("/api/")) {
      return originalFetch(input, init);   // not our API — untouched
    }

    const next: RequestInit = { ...init };

    // 1) Always let the cookie ride. Same-origin, so this triggers no CORS.
    next.credentials = next.credentials ?? "include";

    // 2) Operator routes get the bearer fallback when the caller didn't set one.
    if (!path.startsWith(PORTAL_PREFIX)) {
      const headers = new Headers(init?.headers ?? {});
      if (!headers.has("Authorization")) {
        const token = readToken();
        if (token) headers.set("Authorization", `Bearer ${token}`);
      }
      next.headers = headers;
    }

    return originalFetch(input, next);
  };
}
