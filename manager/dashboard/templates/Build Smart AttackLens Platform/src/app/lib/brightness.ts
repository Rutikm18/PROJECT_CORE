export const BRIGHTNESS_STORAGE_KEY = "attacklens.brightness";
export const DEFAULT_BRIGHTNESS = 100;
export const MIN_BRIGHTNESS = 60;
export const MAX_BRIGHTNESS = 120;

export function normalizeBrightness(value: unknown): number {
  if (value === null || value === undefined || value === "") return DEFAULT_BRIGHTNESS;
  const numeric = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(numeric)) return DEFAULT_BRIGHTNESS;
  return Math.min(MAX_BRIGHTNESS, Math.max(MIN_BRIGHTNESS, Math.round(numeric)));
}

export function brightnessOverlay(value: number): {
  background: "black" | "white";
  opacity: number;
} {
  const brightness = normalizeBrightness(value);
  return brightness < DEFAULT_BRIGHTNESS
    ? { background: "black", opacity: (DEFAULT_BRIGHTNESS - brightness) / 100 }
    : { background: "white", opacity: (brightness - DEFAULT_BRIGHTNESS) / 100 };
}
