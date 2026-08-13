import { describe, expect, it } from "vitest";

import {
  DEFAULT_BRIGHTNESS,
  brightnessOverlay,
  normalizeBrightness,
} from "./brightness";

describe("application brightness", () => {
  it("defaults invalid values and clamps saved preferences", () => {
    expect(normalizeBrightness(null)).toBe(DEFAULT_BRIGHTNESS);
    expect(normalizeBrightness("not-a-number")).toBe(DEFAULT_BRIGHTNESS);
    expect(normalizeBrightness("20")).toBe(60);
    expect(normalizeBrightness(150)).toBe(120);
    expect(normalizeBrightness(87.6)).toBe(88);
  });

  it("uses a neutral overlay at the default brightness", () => {
    expect(brightnessOverlay(100)).toEqual({ background: "white", opacity: 0 });
  });

  it("dims with black and brightens with white", () => {
    expect(brightnessOverlay(70)).toEqual({ background: "black", opacity: 0.3 });
    expect(brightnessOverlay(115)).toEqual({ background: "white", opacity: 0.15 });
  });
});
