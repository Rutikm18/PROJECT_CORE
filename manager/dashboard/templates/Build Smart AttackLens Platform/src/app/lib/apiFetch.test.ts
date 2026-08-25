import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { installApiFetch } from "./apiFetch";

/**
 * These tests run in the default node environment (no jsdom), so we stand up the
 * few browser globals the wrapper touches: window.location, window.fetch and a
 * localStorage stub. installApiFetch() is idempotent, so installing once in
 * beforeAll and mutating the token store per test is enough.
 */
const ORIGIN = "https://app.example.com";
const originalSpy = vi.fn(async () => new Response("{}", { status: 200 }));
let tokenStore: Record<string, string> = {};

beforeAll(() => {
  (globalThis as unknown as { localStorage: Storage }).localStorage = {
    getItem: (k: string) => (k in tokenStore ? tokenStore[k] : null),
  } as Storage;
  (globalThis as unknown as { window: Window }).window = {
    location: { origin: ORIGIN },
    fetch: originalSpy,
  } as unknown as Window;
  installApiFetch();
});

afterEach(() => {
  originalSpy.mockClear();
  tokenStore = {};
});

/** The (input, init) the wrapper actually forwarded to the real fetch. */
function forwarded(): [RequestInfo | URL, RequestInit | undefined] {
  return originalSpy.mock.calls[0] as [RequestInfo | URL, RequestInit | undefined];
}

const call = (input: RequestInfo | URL, init?: RequestInit) =>
  (window.fetch as typeof fetch)(input, init);

describe("installApiFetch", () => {
  it("attaches the bearer token and credentials to operator API calls", async () => {
    tokenStore["al_token"] = "JWT123";
    await call("/api/v1/agents");

    const [input, init] = forwarded();
    expect(input).toBe("/api/v1/agents");
    expect(init?.credentials).toBe("include");
    expect(new Headers(init?.headers).get("Authorization")).toBe("Bearer JWT123");
  });

  it("still sends the cookie when no token is stored (cookie-only fallback)", async () => {
    await call("/api/v1/agents");

    const [, init] = forwarded();
    expect(init?.credentials).toBe("include");
    expect(new Headers(init?.headers).has("Authorization")).toBe(false);
  });

  it("never attaches the operator token to portal routes", async () => {
    tokenStore["al_token"] = "JWT123";
    await call("/api/v1/portal/findings");

    const [, init] = forwarded();
    expect(init?.credentials).toBe("include");           // cookie still allowed
    expect(new Headers(init?.headers).has("Authorization")).toBe(false);
  });

  it("does not override an Authorization header the caller already set", async () => {
    tokenStore["al_token"] = "JWT123";
    await call("/api/v1/agents", { headers: { Authorization: "Bearer CUSTOM" } });

    const [, init] = forwarded();
    expect(new Headers(init?.headers).get("Authorization")).toBe("Bearer CUSTOM");
  });

  it("leaves cross-origin requests completely untouched", async () => {
    tokenStore["al_token"] = "JWT123";
    await call("https://evil.example.com/api/v1/steal");

    const [input, init] = forwarded();
    expect(input).toBe("https://evil.example.com/api/v1/steal");
    expect(init).toBeUndefined();   // forwarded verbatim: no credentials, no token
  });

  it("leaves same-origin non-API paths untouched", async () => {
    tokenStore["al_token"] = "JWT123";
    await call("/static/logo.png");

    const [, init] = forwarded();
    expect(init).toBeUndefined();
  });
});
