import { describe, it, expect } from "vitest";
import { licenseState, seatState, statusTone } from "./CustomersPanel";

/**
 * These drive what an operator sees at a glance in the customer table. Seats
 * and licence state are the two that carry consequence: at the cap, agent
 * assignment starts failing; past expiry, the customer's entitlement is gone.
 */

describe("seat usage", () => {
  it("shows used against the licensed cap", () => {
    expect(seatState({ agent_count: 3, max_agents: 10 }).label).toBe("3 / 10");
  });

  it("flags the cap so a failed assignment is predictable", () => {
    expect(seatState({ agent_count: 10, max_agents: 10 }).atCap).toBe(true);
    expect(seatState({ agent_count: 9, max_agents: 10 }).atCap).toBe(false);
  });

  it("warns before the cap rather than only at it", () => {
    expect(seatState({ agent_count: 8, max_agents: 10 }).tone).toBe("amber");
    expect(seatState({ agent_count: 5, max_agents: 10 }).tone).toBe("gray");
    expect(seatState({ agent_count: 10, max_agents: 10 }).tone).toBe("red");
  });

  it("treats a zero cap as unlimited, not as a cap of zero", () => {
    const state = seatState({ agent_count: 4, max_agents: 0 });
    expect(state.label).toBe("4");
    expect(state.atCap).toBe(false);
  });
});

describe("licence state", () => {
  it("reports expiry ahead of the countdown", () => {
    expect(licenseState({ license_expired: true, license_days_remaining: 0 }))
      .toEqual({ label: "Expired", tone: "red" });
  });

  it("warns inside 30 days", () => {
    expect(licenseState({ license_expired: false, license_days_remaining: 30 }).tone).toBe("amber");
    expect(licenseState({ license_expired: false, license_days_remaining: 31 }).tone).toBe("gray");
  });

  it("shows a perpetual licence as perpetual, not as zero days", () => {
    expect(licenseState({ license_expired: false, license_days_remaining: null }))
      .toEqual({ label: "Perpetual", tone: "gray" });
  });
});

describe("status tone", () => {
  it("distinguishes suspended from not-yet-activated", () => {
    expect(statusTone("active")).toBe("emerald");
    expect(statusTone("suspended")).toBe("red");
    expect(statusTone("pending")).toBe("amber");
  });
});
