import { describe, expect, it } from "vitest";

import { navigationModeForWidth } from "./AppShell";


describe("responsive navigation modes", () => {
  it("uses off-canvas navigation on phones", () => {
    expect(navigationModeForWidth(390)).toBe("mobile");
    expect(navigationModeForWidth(767)).toBe("mobile");
  });

  it("uses the icon rail on tablets and compact desktop windows", () => {
    expect(navigationModeForWidth(768)).toBe("rail");
    expect(navigationModeForWidth(1024)).toBe("rail");
    expect(navigationModeForWidth(1199)).toBe("rail");
  });

  it("honors the user's compact preference on large screens", () => {
    expect(navigationModeForWidth(1440, false)).toBe("expanded");
    expect(navigationModeForWidth(1440, true)).toBe("rail");
  });
});
