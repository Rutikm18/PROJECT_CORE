import { createContext, useContext, useCallback, useEffect, useMemo, useState, ReactNode } from "react";
import { useSearchParams } from "react-router";
import { TimeRange, parseRangeFromParams, rangeToParams, rangesEqual, DEFAULT_RANGE } from "../lib/timeRange";

const LS_KEY = "attacklens.timeRange";
const DEFAULT: TimeRange = DEFAULT_RANGE;

function initialRange(sp: URLSearchParams): TimeRange {
  return parseRangeFromParams(sp) ?? (() => {
    try {
      const v = localStorage.getItem(LS_KEY);
      return v ? (JSON.parse(v) as TimeRange) : DEFAULT;
    } catch {
      return DEFAULT;
    }
  })();
}

const Ctx = createContext<{ range: TimeRange; setRange(r: TimeRange): void }>({
  range: DEFAULT,
  setRange() {},
});

export function TimeRangeProvider({ children }: { children: ReactNode }) {
  const [sp, setSp] = useSearchParams();
  const [range, setRangeState] = useState<TimeRange>(() => initialRange(sp));

  const setRange = useCallback(
    (r: TimeRange) => {
      setRangeState(r);
      try { localStorage.setItem(LS_KEY, JSON.stringify(r)); } catch {}
      const next = new URLSearchParams(sp);
      next.delete("window");
      next.delete("start");
      next.delete("end");
      for (const [k, v] of rangeToParams(r)) next.set(k, v);
      setSp(next, { replace: true });
    },
    [sp, setSp],
  );

  // Keep in-memory state in sync when the URL's range params change from
  // outside setRange — browser back/forward, or landing on a shared deep link.
  // Only reacts to explicit range params (a plain sidebar navigation drops the
  // query string, and we intentionally keep the current range in that case).
  useEffect(() => {
    const parsed = parseRangeFromParams(sp);
    if (parsed && !rangesEqual(parsed, range)) {
      setRangeState(parsed);
      try { localStorage.setItem(LS_KEY, JSON.stringify(parsed)); } catch {}
    }
  }, [sp]); // eslint-disable-line react-hooks/exhaustive-deps

  const value = useMemo(() => ({ range, setRange }), [range, setRange]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export const useTimeRange = () => useContext(Ctx);
