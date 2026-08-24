/**
 * Data Retention panel logic.
 *
 * Kept out of the component so it can be tested without a DOM: the panel's
 * bugs were state-transition bugs, not rendering bugs.
 *
 * `period_months` is a legacy field name — 0/7/15 are day presets and 1+ are
 * month presets. See RETENTION_PERIODS_MONTHS in manager/manager/api/settings.py;
 * the order here mirrors it so the dropdown reads shortest-to-longest.
 */

export const RETENTION_PERIOD_CODES = [0, 7, 15, 1, 3, 6, 12, 24] as const;

/** Windows the backend marks as slow to query (RETENTION_SLOW_FETCH_MONTHS). */
const SLOW_FETCH_CODES: ReadonlySet<number> = new Set([12, 24]);

export interface RetentionConfigShape {
  period_months:           number;
  period_days:             number;
  action:                  "delete" | "archive";
  slow_fetch_warning:      boolean;
  auto_resolve_stale_days: number;
  available_periods:       number[];
  available_actions:       string[];
}

export interface RetentionChange {
  periodMonths:     number;
  action:           "delete" | "archive";
  autoResolveDays?: number;
}

export function isSlowFetchPeriod(code: number): boolean {
  return SLOW_FETCH_CODES.has(code);
}

/**
 * The config the panel should show the instant the user picks a value, before
 * the write round-trips. Returns a new object — the caller keeps the previous
 * one to roll back to if the PUT fails.
 *
 * `period_days` is deliberately left alone: it is not rendered, and deriving it
 * here would duplicate the backend's day/month conversion and let the two drift.
 * The next successful fetch supplies the authoritative value.
 */
export function optimisticRetentionConfig<T extends RetentionConfigShape>(
  config: T | null,
  change: RetentionChange,
): T | null {
  if (!config) return null;
  return {
    ...config,
    period_months:      change.periodMonths,
    action:             change.action,
    slow_fetch_warning: isSlowFetchPeriod(change.periodMonths),
    auto_resolve_stale_days:
      change.autoResolveDays ?? config.auto_resolve_stale_days,
  };
}

/**
 * True when a response belongs to a request that a newer one has superseded.
 *
 * The panel polls storage stats every 60s while also writing config on every
 * dropdown change. Both used to call setConfig unconditionally, so a poll
 * issued just before a save could resolve just after it and put the old period
 * back on screen — the "I changed it and it jumped back" symptom.
 */
export function isStaleResponse(requestSeq: number, latestSeq: number): boolean {
  return requestSeq !== latestSeq;
}
