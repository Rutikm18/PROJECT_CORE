import { createContext, useContext, useCallback, useMemo, useState, ReactNode } from "react";
import { useSearchParams } from "react-router";
import { TimeRange, parseRangeFromParams, rangeToParams, DEFAULT_WINDOW } from "../lib/timeRange";

const LS_KEY = "attacklens.timeRange";
const DEFAULT: TimeRange = { kind: "relative", key: DEFAULT_WINDOW };

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

  const value = useMemo(() => ({ range, setRange }), [range, setRange]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export const useTimeRange = () => useContext(Ctx);
