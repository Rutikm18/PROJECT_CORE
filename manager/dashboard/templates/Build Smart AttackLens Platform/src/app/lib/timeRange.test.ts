import { describe, it, expect } from "vitest";
import {
  parseRangeFromParams, rangeToParams, pollIntervalMs, validateCustom,
  rangesEqual, isDefaultRange, DEFAULT_RANGE, DEFAULT_WINDOW,
} from "./timeRange";

describe("timeRange", () => {
  it("parses relative window param", () => {
    expect(parseRangeFromParams(new URLSearchParams("window=6h")))
      .toEqual({ kind: "relative", key: "6h" });
  });
  it("parses absolute start/end", () => {
    expect(parseRangeFromParams(new URLSearchParams("start=100&end=200")))
      .toEqual({ kind: "absolute", start: 100, end: 200 });
  });
  it("returns null for absent/invalid params", () => {
    expect(parseRangeFromParams(new URLSearchParams("window=13h"))).toBeNull();
    expect(parseRangeFromParams(new URLSearchParams(""))).toBeNull();
  });
  it("round-trips relative and absolute to params", () => {
    expect(rangeToParams({ kind: "relative", key: "1d" }).toString()).toBe("window=1d");
    expect(rangeToParams({ kind: "absolute", start: 5, end: 9 }).toString()).toBe("start=5&end=9");
  });
  it("polls for relative (scaled), never for absolute", () => {
    expect(pollIntervalMs({ kind: "relative", key: "30s" })).toBe(5000);
    expect(pollIntervalMs({ kind: "relative", key: "1h" })).toBe(30000);
    expect(pollIntervalMs({ kind: "relative", key: "1d" })).toBe(60000);
    expect(pollIntervalMs({ kind: "relative", key: "7d" })).toBe(300000);
    expect(pollIntervalMs({ kind: "absolute", start: 1, end: 2 })).toBeNull();
  });
  it("validates custom range", () => {
    expect(validateCustom(100, 200, 1000)).toBeNull();
    expect(validateCustom(200, 100, 1000)).toMatch(/start/i);      // start>=end
    expect(validateCustom(100, 5000, 1000)).toMatch(/future/i);    // end in future
  });
  it("default window is 1h", () => { expect(DEFAULT_WINDOW).toBe("1h"); });

  it("rangesEqual compares by kind and value", () => {
    expect(rangesEqual({ kind: "relative", key: "1h" }, { kind: "relative", key: "1h" })).toBe(true);
    expect(rangesEqual({ kind: "relative", key: "1h" }, { kind: "relative", key: "6h" })).toBe(false);
    expect(rangesEqual({ kind: "absolute", start: 1, end: 2 }, { kind: "absolute", start: 1, end: 2 })).toBe(true);
    expect(rangesEqual({ kind: "absolute", start: 1, end: 2 }, { kind: "absolute", start: 1, end: 3 })).toBe(false);
    expect(rangesEqual({ kind: "relative", key: "1h" }, { kind: "absolute", start: 1, end: 2 })).toBe(false);
  });
  it("isDefaultRange is true only for relative 1h", () => {
    expect(isDefaultRange(DEFAULT_RANGE)).toBe(true);
    expect(isDefaultRange({ kind: "relative", key: "1h" })).toBe(true);
    expect(isDefaultRange({ kind: "relative", key: "6h" })).toBe(false);
    expect(isDefaultRange({ kind: "absolute", start: 1, end: 2 })).toBe(false);
  });
});
