/**
 * portalClient — transport for the customer portal.
 *
 * A separate client from the operator dashboard's fetches, for the same reason
 * the cookie and the router are separate: a customer session is a different
 * principal, and mixing the two transports is how one quietly ends up
 * satisfying the other.
 *
 * Every call goes to /api/v1/portal/*, which is the only surface an
 * `aud=portal` token can reach. On 401 the portal sends the user to its own
 * login, never the operator one.
 */

export const PORTAL_API = "/api/v1/portal";
export const PORTAL_LOGIN_PATH = "/portal/login";

export class PortalApiError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
    this.name = "PortalApiError";
  }
}

/** Where a failed portal request should send the user, or null to stay put. */
export function redirectForStatus(status: number): string | null {
  // 401 = no session. 403 = a session that is not valid here — a suspended org,
  // or an operator token. Both mean "sign in as a customer", and neither should
  // land on the operator login.
  return status === 401 || status === 403 ? PORTAL_LOGIN_PATH : null;
}

async function readError(response: Response): Promise<string> {
  try {
    const body = await response.json();
    const detail = body?.detail ?? body?.error;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) {
      return detail.map((d: { msg?: string }) => d.msg ?? JSON.stringify(d)).join("; ");
    }
  } catch { /* fall through to the status text */ }
  return response.statusText || `Request failed (${response.status})`;
}

export async function portalApi<T>(
  path: string,
  init: RequestInit & { redirectOnAuthFailure?: boolean } = {},
): Promise<T> {
  const { redirectOnAuthFailure = true, ...rest } = init;
  const response = await fetch(`${PORTAL_API}${path}`, {
    credentials: "include",
    ...rest,
    headers: { "Content-Type": "application/json", ...(rest.headers ?? {}) },
  });

  if (!response.ok) {
    const target = redirectForStatus(response.status);
    if (target && redirectOnAuthFailure && typeof window !== "undefined") {
      if (window.location.pathname !== target) window.location.assign(target);
    }
    throw new PortalApiError(response.status, await readError(response));
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

// ── Shapes the portal renders ───────────────────────────────────────────────

export interface PortalMe {
  email: string;
  role: string;
  org: {
    org_id: string; slug: string; name: string; tier: string;
    license_expires_at: number | null;
    license_days_remaining: number | null;
  };
  agent_count: number;
  capabilities: Record<string, boolean>;
}

export interface PortalSummary {
  total: number;
  by_severity: Record<string, number>;
  critical: number;
  high: number;
  validated: number;
  by_terrain: Record<string, number>;
  agent_count: number;
}

export interface PortalFinding {
  id: number;
  external_id?: string;
  agent_id: string;
  category: string;
  terrain_id?: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  score: number;
  composite_score?: number;
  confidence_pct?: number;
  title: string;
  description: string;
  cve_ids: string[];
  cvss_score?: number | null;
  epss_score?: number | null;
  kev: boolean;
  exploit_available: boolean;
  mitre_technique?: string;
  status: string;
  first_detected_at: number;
  last_detected_at: number;
  validation_state?: string;
  evidence: Record<string, unknown>;
}

export interface PortalAgent {
  agent_id: string; hostname: string; os: string;
  os_version: string; finding_count: number;
}
