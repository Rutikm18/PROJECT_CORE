import { useState } from "react";
import { Clock, Calendar, RefreshCw, ChevronDown, RotateCcw } from "lucide-react";
import { useTimeRange } from "../context/TimeRangeContext";
import {
  WINDOW_KEYS, validateCustom, DEFAULT_RANGE, isDefaultRange,
  type TimeRange, type WindowKey,
} from "../lib/timeRange";
import { cn } from "../../lib/utils";

const LABELS: Record<WindowKey, string> = {
  "30s": "30s", "1m": "1m", "5m": "5m", "15m": "15m",
  "1h": "1h", "6h": "6h", "1d": "1d", "7d": "7d", "15d": "15d", "30d": "30d",
};

function fmtEpoch(ts: number) {
  return new Date(ts * 1000).toLocaleString();
}

export function TimeRangePicker({ lastUpdated }: { lastUpdated?: number | null }) {
  const { range, setRange } = useTimeRange();
  const [open, setOpen] = useState(false);
  const [customOpen, setCustomOpen] = useState(false);
  const [startDt, setStartDt] = useState("");
  const [endDt, setEndDt] = useState("");
  const [validErr, setValidErr] = useState<string | null>(null);

  const activeLabel =
    range.kind === "relative"
      ? LABELS[range.key]
      : `${fmtEpoch(range.start)} → ${fmtEpoch(range.end)}`;

  const isAbsolute = range.kind === "absolute";
  const isDefault = isDefaultRange(range);

  function applyCustom() {
    const s = Math.floor(new Date(startDt).getTime() / 1000);
    const e = Math.floor(new Date(endDt).getTime() / 1000);
    const now = Math.floor(Date.now() / 1000);
    const err = validateCustom(s, e, now);
    if (err) { setValidErr(err); return; }
    setValidErr(null);
    setRange({ kind: "absolute", start: s, end: e });
    setCustomOpen(false);
    setOpen(false);
  }

  function reset() {
    setRange(DEFAULT_RANGE);
    setStartDt("");
    setEndDt("");
    setValidErr(null);
    setCustomOpen(false);
    setOpen(false);
  }

  return (
    <div className="relative">
      {/* Trigger */}
      <button
        onClick={() => { setOpen(o => !o); setCustomOpen(false); }}
        className={cn(
          "flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border text-[10px] font-semibold transition-all",
          isAbsolute
            ? "bg-violet-50 border-violet-200 text-violet-700"
            : "bg-blue-50 border-blue-200 text-blue-700 hover:bg-blue-100",
        )}
        title={isAbsolute ? "Custom absolute range" : "Time window preset"}
      >
        {isAbsolute ? <Calendar className="w-3 h-3" /> : <Clock className="w-3 h-3" />}
        <span className="max-w-[120px] truncate">{activeLabel}</span>
        {!isDefault && <span className="w-1.5 h-1.5 rounded-full bg-amber-500" title="Custom filter active" />}
        {!isAbsolute && lastUpdated && (
          <span className="text-[9px] opacity-60 ml-0.5">
            {Math.round((Date.now() - lastUpdated) / 1000)}s ago
          </span>
        )}
        <ChevronDown className={cn("w-3 h-3 opacity-60 transition-transform", open && "rotate-180")} />
      </button>

      {/* Dropdown */}
      {open && (
        <>
          <div className="fixed inset-0 z-40" onClick={() => setOpen(false)} />
          <div
            className="absolute right-0 top-9 z-50 w-52 bg-white rounded-xl border border-gray-200 shadow-xl overflow-hidden"
            style={{ boxShadow: "0 8px 32px rgba(0,0,0,0.12)" }}
          >
            {/* Preset buttons */}
            <div className="px-2 pt-2 pb-1">
              <div className="flex items-center justify-between px-1 mb-1">
                <span className="text-[9px] font-bold text-gray-400 uppercase tracking-wider">Relative presets</span>
                <button
                  onClick={reset}
                  disabled={isDefault}
                  title="Reset to default (1h)"
                  className={cn(
                    "flex items-center gap-1 text-[9px] font-bold uppercase tracking-wider transition-colors",
                    isDefault ? "text-gray-300 cursor-default" : "text-blue-600 hover:text-blue-700",
                  )}
                >
                  <RotateCcw className="w-2.5 h-2.5" />
                  Reset
                </button>
              </div>
              <div className="grid grid-cols-5 gap-1">
                {WINDOW_KEYS.map(key => (
                  <button
                    key={key}
                    onClick={() => { setRange({ kind: "relative", key }); setOpen(false); }}
                    className={cn(
                      "px-1 py-1.5 rounded-lg text-[10px] font-bold transition-all",
                      range.kind === "relative" && range.key === key
                        ? "bg-blue-500 text-white"
                        : "bg-gray-50 text-gray-600 hover:bg-blue-50 hover:text-blue-600",
                    )}
                  >
                    {LABELS[key]}
                  </button>
                ))}
              </div>
            </div>

            {/* Custom absolute */}
            <div className="border-t border-gray-100 px-2 pb-2 pt-1">
              <button
                onClick={() => setCustomOpen(o => !o)}
                className={cn(
                  "w-full flex items-center gap-2 px-2 py-1.5 rounded-lg text-[10px] font-semibold transition-all",
                  customOpen || isAbsolute
                    ? "bg-violet-50 text-violet-700"
                    : "hover:bg-gray-50 text-gray-600",
                )}
              >
                <Calendar className="w-3 h-3" />
                Custom range
              </button>

              {customOpen && (
                <div className="mt-1.5 space-y-1.5">
                  <div>
                    <label className="text-[9px] font-bold text-gray-500 block mb-0.5">Start</label>
                    <input
                      type="datetime-local"
                      value={startDt}
                      onChange={e => { setStartDt(e.target.value); setValidErr(null); }}
                      className="w-full text-[10px] border border-gray-200 rounded-lg px-2 py-1 focus:outline-none focus:border-violet-400"
                    />
                  </div>
                  <div>
                    <label className="text-[9px] font-bold text-gray-500 block mb-0.5">End</label>
                    <input
                      type="datetime-local"
                      value={endDt}
                      onChange={e => { setEndDt(e.target.value); setValidErr(null); }}
                      className="w-full text-[10px] border border-gray-200 rounded-lg px-2 py-1 focus:outline-none focus:border-violet-400"
                    />
                  </div>
                  {validErr && (
                    <p className="text-[9px] text-red-600 px-1">{validErr}</p>
                  )}
                  {/* Large range warning */}
                  {startDt && endDt && !validErr && (() => {
                    const spanDays = (new Date(endDt).getTime() - new Date(startDt).getTime()) / 86400000;
                    return spanDays > 30 ? (
                      <p className="text-[9px] text-amber-600 px-1">Large range ({Math.round(spanDays)}d) — charts will use hourly buckets.</p>
                    ) : null;
                  })()}
                  <button
                    onClick={applyCustom}
                    disabled={!startDt || !endDt}
                    className="w-full py-1.5 rounded-lg text-[10px] font-bold bg-violet-500 text-white hover:bg-violet-600 disabled:opacity-40 transition-all"
                  >
                    Apply range
                  </button>
                </div>
              )}
            </div>

            {/* Manual refresh for absolute */}
            {isAbsolute && (
              <div className="border-t border-gray-100 px-2 py-1.5">
                <button
                  onClick={() => { setRange({ ...range } as TimeRange); setOpen(false); }}
                  className="w-full flex items-center gap-2 px-2 py-1.5 rounded-lg text-[10px] font-semibold text-gray-600 hover:bg-gray-50 transition-all"
                >
                  <RefreshCw className="w-3 h-3" />
                  Refresh
                </button>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}

/** Returns true for routes that show time-series data and should display the picker. */
export function isTimeAwareRoute(pathname: string): boolean {
  const nonTimeAware = [
    /^\/login/,
    /^\/settings/,
    /^\/analysis\/custom-rules/,
  ];
  return !nonTimeAware.some(r => r.test(pathname));
}
