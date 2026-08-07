import { useCallback, useEffect, useRef, useState } from "react";
import { useTimeRange } from "../context/TimeRangeContext";
import { rangeToParams, pollIntervalMs } from "../lib/timeRange";

export function useWindowedData<T>(
  fetcher: (a: { qs: string; signal: AbortSignal }) => Promise<T>,
) {
  const { range } = useTimeRange();
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);
  const [lastUpdated, setLastUpdated] = useState<number | null>(null);
  const acRef = useRef<AbortController | null>(null);
  const qs = rangeToParams(range).toString();

  const run = useCallback(() => {
    acRef.current?.abort();
    const ac = new AbortController();
    acRef.current = ac;
    setLoading(true);
    fetcher({ qs, signal: ac.signal })
      .then((d) => {
        if (!ac.signal.aborted) {
          setData(d);
          setError(null);
          setLastUpdated(Date.now());
        }
      })
      .catch((e) => {
        if (!ac.signal.aborted) setError(e);
      })
      .finally(() => {
        if (!ac.signal.aborted) setLoading(false);
      });
  }, [qs, fetcher]);

  useEffect(() => {
    run();
    const ms = pollIntervalMs(range);
    if (ms == null) return () => acRef.current?.abort();
    const id = setInterval(run, ms);
    return () => {
      clearInterval(id);
      acRef.current?.abort();
    };
  }, [run, range]);

  return { data, loading, error, lastUpdated, refresh: run };
}
