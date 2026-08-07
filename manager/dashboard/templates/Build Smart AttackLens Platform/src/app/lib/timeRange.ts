export type WindowKey =
  | "30s" | "1m" | "5m" | "15m" | "1h" | "6h" | "1d" | "7d" | "15d" | "30d";

export const WINDOW_SECONDS: Record<WindowKey, number> = {
  "30s": 30, "1m": 60, "5m": 300, "15m": 900, "1h": 3600,
  "6h": 21600, "1d": 86400, "7d": 604800, "15d": 1296000, "30d": 2592000,
};
export const WINDOW_KEYS = Object.keys(WINDOW_SECONDS) as WindowKey[];
export const DEFAULT_WINDOW: WindowKey = "1h";

export type TimeRange =
  | { kind: "relative"; key: WindowKey }
  | { kind: "absolute"; start: number; end: number };

export function parseRangeFromParams(sp: URLSearchParams): TimeRange | null {
  const start = sp.get("start"), end = sp.get("end");
  if (start !== null && end !== null) {
    const s = Number(start), e = Number(end);
    if (Number.isFinite(s) && Number.isFinite(e) && s < e) return { kind: "absolute", start: s, end: e };
    return null;
  }
  const w = sp.get("window");
  if (w && (w in WINDOW_SECONDS)) return { kind: "relative", key: w as WindowKey };
  return null;
}

export function rangeToParams(r: TimeRange): URLSearchParams {
  return r.kind === "relative"
    ? new URLSearchParams({ window: r.key })
    : new URLSearchParams({ start: String(r.start), end: String(r.end) });
}

export const DEFAULT_RANGE: TimeRange = { kind: "relative", key: DEFAULT_WINDOW };

/** True when two ranges are semantically identical (used to avoid redundant state churn / render loops). */
export function rangesEqual(a: TimeRange, b: TimeRange): boolean {
  if (a.kind !== b.kind) return false;
  if (a.kind === "relative" && b.kind === "relative") return a.key === b.key;
  if (a.kind === "absolute" && b.kind === "absolute") return a.start === b.start && a.end === b.end;
  return false;
}

/** True when the range is the app default (relative 1h) — i.e. no active filter. */
export function isDefaultRange(r: TimeRange): boolean {
  return rangesEqual(r, DEFAULT_RANGE);
}

export function pollIntervalMs(r: TimeRange): number | null {
  if (r.kind === "absolute") return null;      // frozen historical view — never poll
  const secs = WINDOW_SECONDS[r.key];
  if (secs <= 60) return 5000;
  if (secs <= 3600) return 30000;
  if (secs <= 86400) return 60000;
  return 300000;
}

export function validateCustom(startSec: number, endSec: number, nowSec: number): string | null {
  if (!Number.isFinite(startSec) || !Number.isFinite(endSec)) return "Pick a valid start and end.";
  if (startSec >= endSec) return "Start must be before end.";
  if (endSec > nowSec) return "End can't be in the future.";
  return null;
}
