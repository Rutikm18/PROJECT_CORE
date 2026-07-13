/**
 * timezoneStore — module-level timezone preference store.
 *
 * Persistence: localStorage (key "al_timezone"), default Asia/Kolkata (IST).
 * Live propagation: CustomEvent "al:timezone" so any component using
 * useTimezone() updates instantly when the setting changes — no Context
 * provider needed.
 *
 * Edge cases handled:
 *   • localStorage unavailable (private mode, Safari ITP, quota) → silent fallback
 *   • Corrupted/invalid stored value → stripped, default applied
 *   • Invalid IANA string from API → rejected, default applied
 *   • Network offline for initTimezone() → localStorage/default value kept
 *   • Server returns unknown timezone → validated, rejected gracefully
 */
import { useState, useEffect } from "react";

export const TZ_DEFAULT = "Asia/Kolkata";
const LS_KEY = "al_timezone";

// ── localStorage helpers (never throw) ───────────────────────────────────────

function lsRead(): string | null {
  try {
    return localStorage.getItem(LS_KEY);
  } catch {
    return null; // private mode, SecurityError, etc.
  }
}

function lsWrite(tz: string): void {
  try {
    localStorage.setItem(LS_KEY, tz);
  } catch {
    // QuotaExceededError, SecurityError — not fatal, in-memory event still fires
  }
}

function lsRemove(): void {
  try {
    localStorage.removeItem(LS_KEY);
  } catch { /* ignore */ }
}

// ── Validation ────────────────────────────────────────────────────────────────

/**
 * Returns true if `tz` is a valid IANA timezone the current browser understands.
 * Uses the Intl API — no external lookup table needed.
 */
export function isValidTimezone(tz: unknown): tz is string {
  if (!tz || typeof tz !== "string" || tz.trim() === "") return false;
  try {
    // Intl.DateTimeFormat throws RangeError for unknown timezones
    Intl.DateTimeFormat(undefined, { timeZone: tz });
    return true;
  } catch {
    return false;
  }
}

// ── Core store ────────────────────────────────────────────────────────────────

/**
 * Read the active timezone — always returns a valid IANA string.
 * Validates what's in localStorage; falls back to TZ_DEFAULT on any issue.
 */
export function getTimezone(): string {
  const stored = lsRead();
  if (isValidTimezone(stored)) return stored as string;
  // Stored value is invalid or absent — clear it so the next write starts clean
  if (stored !== null) lsRemove();
  return TZ_DEFAULT;
}

/**
 * Persist a new timezone and notify all useTimezone() subscribers immediately.
 * Invalid values are silently replaced with TZ_DEFAULT.
 */
export function setTimezone(tz: unknown): void {
  const safe = isValidTimezone(tz) ? (tz as string) : TZ_DEFAULT;
  lsWrite(safe);
  try {
    window.dispatchEvent(new CustomEvent("al:timezone", { detail: safe }));
  } catch { /* rare — environment without CustomEvent */ }
}

/**
 * Fetch the authoritative timezone from the backend and apply it.
 * Called once on app startup (non-blocking — never delays first render).
 *
 * Only overwrites localStorage if the server value is a valid IANA timezone
 * that differs from the current stored value, so repeat visits are no-ops.
 */
export async function initTimezone(): Promise<void> {
  try {
    // Timeout: avoid hanging forever if the server is slow/offline.
    // AbortSignal.timeout is ES2022 — use manual timeout for broader support.
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 6_000);
    let r: Response;
    try {
      r = await fetch("/api/v1/settings", { signal: controller.signal });
    } finally {
      clearTimeout(timer);
    }
    if (!r.ok) return;
    const d = await r.json();
    const serverTz: unknown = d?.settings?.platform_timezone;
    if (isValidTimezone(serverTz) && serverTz !== getTimezone()) {
      setTimezone(serverTz);
    }
  } catch {
    // Network offline, timeout, parse error — keep localStorage / TZ_DEFAULT
  }
}

// ── React hook ────────────────────────────────────────────────────────────────

/** Subscribe to timezone changes. Always returns a valid IANA timezone. */
export function useTimezone(): string {
  const [tz, setTz] = useState<string>(getTimezone);

  useEffect(() => {
    const h = (e: Event) => {
      const next = (e as CustomEvent<unknown>).detail;
      if (isValidTimezone(next)) setTz(next as string);
    };
    window.addEventListener("al:timezone", h);
    return () => window.removeEventListener("al:timezone", h);
  }, []);

  return tz;
}

// ── Formatting helpers ────────────────────────────────────────────────────────

/** Short abbreviation — "IST", "EST", "GMT". Never throws. */
export function tzAbbr(tz: string): string {
  const safeZone = isValidTimezone(tz) ? tz : TZ_DEFAULT;
  try {
    return (
      new Intl.DateTimeFormat("en-US", { timeZone: safeZone, timeZoneName: "short" })
        .formatToParts(new Date())
        .find(p => p.type === "timeZoneName")?.value ?? safeZone.split("/").pop() ?? safeZone
    );
  } catch {
    return safeZone.split("/").pop() ?? safeZone;
  }
}

/** UTC offset string — "+05:30", "-05:00". Never throws. */
export function tzOffsetStr(tz: string): string {
  const safeZone = isValidTimezone(tz) ? tz : TZ_DEFAULT;
  try {
    const raw =
      new Intl.DateTimeFormat("en-US", { timeZone: safeZone, timeZoneName: "longOffset" })
        .formatToParts(new Date())
        .find(p => p.type === "timeZoneName")?.value ?? "GMT+0:00";
    const m = raw.match(/GMT([+-])(\d{1,2}):(\d{2})/);
    if (!m) return "+00:00";
    return `${m[1]}${m[2].padStart(2, "0")}:${m[3]}`;
  } catch {
    return "+00:00";
  }
}

/**
 * Format a Date as HH:MM:SS in the given timezone.
 * Falls back through TZ_DEFAULT, then returns "--:--:--" if all else fails.
 */
export function fmtTime(tz: string, date = new Date()): string {
  for (const zone of [tz, TZ_DEFAULT]) {
    if (!isValidTimezone(zone)) continue;
    try {
      return date.toLocaleTimeString("en-GB", {
        hour: "2-digit", minute: "2-digit", second: "2-digit", timeZone: zone,
      });
    } catch { /* try next */ }
  }
  return "--:--:--";
}

/**
 * Format a Date as "DD Mon" in the given timezone.
 * Falls back through TZ_DEFAULT, then returns "-- ---" if all else fails.
 */
export function fmtDate(tz: string, date = new Date()): string {
  for (const zone of [tz, TZ_DEFAULT]) {
    if (!isValidTimezone(zone)) continue;
    try {
      return date.toLocaleDateString("en-GB", { day: "2-digit", month: "short", timeZone: zone });
    } catch { /* try next */ }
  }
  return "-- ---";
}

/** Ordered timezone list with display metadata. */
export const TIMEZONE_LIST: { tz: string; label: string; group: string }[] = [
  { tz: "UTC",                 label: "UTC — Coordinated Universal Time",  group: "UTC"      },
  { tz: "Asia/Kolkata",        label: "IST — Asia/Kolkata ★ Default",      group: "Asia"     },
  { tz: "Asia/Dubai",          label: "GST — Asia/Dubai",                  group: "Asia"     },
  { tz: "Asia/Karachi",        label: "PKT — Asia/Karachi",                group: "Asia"     },
  { tz: "Asia/Dhaka",          label: "BST — Asia/Dhaka",                  group: "Asia"     },
  { tz: "Asia/Bangkok",        label: "ICT — Asia/Bangkok",                group: "Asia"     },
  { tz: "Asia/Singapore",      label: "SGT — Asia/Singapore",              group: "Asia"     },
  { tz: "Asia/Shanghai",       label: "CST — Asia/Shanghai",               group: "Asia"     },
  { tz: "Asia/Tokyo",          label: "JST — Asia/Tokyo",                  group: "Asia"     },
  { tz: "Asia/Colombo",        label: "SLST — Asia/Colombo",               group: "Asia"     },
  { tz: "Asia/Riyadh",         label: "AST — Asia/Riyadh",                 group: "Asia"     },
  { tz: "Asia/Kabul",          label: "AFT — Asia/Kabul",                  group: "Asia"     },
  { tz: "Europe/London",       label: "GMT/BST — Europe/London",           group: "Europe"   },
  { tz: "Europe/Paris",        label: "CET/CEST — Europe/Paris",           group: "Europe"   },
  { tz: "Europe/Berlin",       label: "CET/CEST — Europe/Berlin",          group: "Europe"   },
  { tz: "Europe/Moscow",       label: "MSK — Europe/Moscow",               group: "Europe"   },
  { tz: "Europe/Istanbul",     label: "TRT — Europe/Istanbul",             group: "Europe"   },
  { tz: "Europe/Amsterdam",    label: "CET/CEST — Europe/Amsterdam",       group: "Europe"   },
  { tz: "America/New_York",    label: "EST/EDT — America/New_York",        group: "Americas" },
  { tz: "America/Chicago",     label: "CST/CDT — America/Chicago",         group: "Americas" },
  { tz: "America/Denver",      label: "MST/MDT — America/Denver",          group: "Americas" },
  { tz: "America/Los_Angeles", label: "PST/PDT — America/Los_Angeles",     group: "Americas" },
  { tz: "America/Toronto",     label: "EST/EDT — America/Toronto",         group: "Americas" },
  { tz: "America/Sao_Paulo",   label: "BRT — America/Sao_Paulo",           group: "Americas" },
  { tz: "America/Mexico_City", label: "CST/CDT — America/Mexico_City",     group: "Americas" },
  { tz: "Australia/Sydney",    label: "AEST/AEDT — Australia/Sydney",      group: "Pacific"  },
  { tz: "Australia/Perth",     label: "AWST — Australia/Perth",            group: "Pacific"  },
  { tz: "Pacific/Auckland",    label: "NZST/NZDT — Pacific/Auckland",      group: "Pacific"  },
  { tz: "Pacific/Honolulu",    label: "HST — Pacific/Honolulu",            group: "Pacific"  },
  { tz: "Africa/Cairo",        label: "EET — Africa/Cairo",                group: "Africa"   },
  { tz: "Africa/Nairobi",      label: "EAT — Africa/Nairobi",              group: "Africa"   },
  { tz: "Africa/Lagos",        label: "WAT — Africa/Lagos",                group: "Africa"   },
];
