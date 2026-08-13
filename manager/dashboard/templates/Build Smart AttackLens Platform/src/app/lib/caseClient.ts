export type CaseStatus = "open" | "in_progress" | "resolved" | "closed";
export type CasePriority = "critical" | "high" | "medium" | "low";

export interface CaseRecord {
  id: number;
  external_id: string;
  title: string;
  description: string;
  status: CaseStatus;
  priority: CasePriority;
  owner_user_id: string;
  due_at: number;
  findings: number[];
  tags: string[];
  version: number;
  created_at: number;
  updated_at: number;
}

export interface CaseEvent {
  id: number;
  actor: string;
  action: string;
  created_at: number;
  elapsed: string;
  old_value: Record<string, unknown>;
  new_value: Record<string, unknown>;
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" ? value as Record<string, unknown> : {};
}

function jsonObject(value: unknown): Record<string, unknown> {
  if (value && typeof value === "object") return value as Record<string, unknown>;
  if (typeof value !== "string") return {};
  try { return asRecord(JSON.parse(value)); } catch { return {}; }
}

function elapsed(epochSeconds: number): string {
  const seconds = Math.max(0, Math.floor(Date.now() / 1000 - epochSeconds));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

export function parseCase(value: unknown): CaseRecord | null {
  const row = asRecord(value);
  if (typeof row.id !== "number") return null;
  return {
    id: row.id,
    external_id: String(row.external_id ?? ""),
    title: String(row.title ?? "Untitled case"),
    description: String(row.description ?? ""),
    status: (["open", "in_progress", "resolved", "closed"].includes(String(row.status))
      ? row.status : "open") as CaseStatus,
    priority: (["critical", "high", "medium", "low"].includes(String(row.priority))
      ? row.priority : "medium") as CasePriority,
    owner_user_id: String(row.owner_user_id ?? ""),
    due_at: Number(row.due_at ?? 0),
    findings: Array.isArray(row.findings)
      ? row.findings.filter((id): id is number => typeof id === "number") : [],
    tags: Array.isArray(row.tags)
      ? row.tags.filter((tag): tag is string => typeof tag === "string") : [],
    version: Number(row.version ?? 1),
    created_at: Number(row.created_at ?? 0),
    updated_at: Number(row.updated_at ?? 0),
  };
}

async function api<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, { credentials: "same-origin", ...init });
  if (!response.ok) throw new Error(`Case request failed (${response.status})`);
  return response.json() as Promise<T>;
}

export async function listCases(query: {
  status?: CaseStatus; priority?: CasePriority; owner_user_id?: string;
  finding_id?: number; cursor?: number; limit?: number;
} = {}): Promise<CaseRecord[]> {
  const params = new URLSearchParams();
  Object.entries(query).forEach(([key, value]) => {
    if (value !== undefined && value !== "" && value !== 0) params.set(key, String(value));
  });
  const data = await api<{ cases?: unknown[] }>(
    `/api/v1/cases${params.size ? `?${params}` : ""}`,
  );
  return (data.cases ?? []).map(parseCase).filter((row): row is CaseRecord => row !== null);
}

export async function getCaseForFinding(findingId: number): Promise<CaseRecord | null> {
  return (await listCases({ finding_id: findingId, limit: 1 }))[0] ?? null;
}

export async function createCase(input: {
  title: string; description?: string; status?: CaseStatus; priority?: CasePriority;
  owner_user_id?: string; due_at?: number; finding_ids?: number[]; tags?: string[];
}): Promise<CaseRecord> {
  const value = await api<unknown>("/api/v1/cases", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Idempotency-Key": globalThis.crypto?.randomUUID?.() ?? `case-${Date.now()}`,
    },
    body: JSON.stringify(input),
  });
  const parsed = parseCase(value);
  if (!parsed) throw new Error("Case response was malformed");
  return parsed;
}

export async function updateCase(
  caseId: number,
  version: number,
  changes: Partial<Pick<CaseRecord,
    "title" | "description" | "status" | "priority" | "owner_user_id" | "due_at" | "tags"
  >>,
): Promise<CaseRecord> {
  const value = await api<unknown>(`/api/v1/cases/records/${caseId}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ version, ...changes }),
  });
  const parsed = parseCase(value);
  if (!parsed) throw new Error("Case response was malformed");
  return parsed;
}

export async function addCaseNote(caseId: number, body: string): Promise<void> {
  await api(`/api/v1/cases/records/${caseId}/notes`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ body }),
  });
}

export async function getCaseTimeline(caseId: number): Promise<CaseEvent[]> {
  const data = await api<{ events?: unknown[] }>(
    `/api/v1/cases/records/${caseId}/timeline?limit=500`,
  );
  return (data.events ?? []).map((value) => {
    const row = asRecord(value);
    const createdAt = Number(row.created_at ?? 0);
    return {
      id: Number(row.id ?? 0),
      actor: String(row.actor_user_id ?? "system"),
      action: String(row.event_type ?? "activity").replaceAll(".", " "),
      created_at: createdAt,
      elapsed: elapsed(createdAt),
      old_value: jsonObject(row.old_value_json),
      new_value: jsonObject(row.new_value_json),
    };
  });
}

export async function importLegacyCases(cases: unknown[]): Promise<{ count: number }> {
  return api<{ count: number }>("/api/v1/cases/import", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ cases }),
  });
}
