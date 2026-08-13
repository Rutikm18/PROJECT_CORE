import { describe, expect, it } from "vitest";

import { initialRefreshState, refreshReducer } from "./RefreshContext";


describe("central refresh coordinator", () => {
  it("stays active until registered requests settle", () => {
    let state = refreshReducer(initialRefreshState, { type: "trigger" });
    const revision = state.refreshRevision;
    state = refreshReducer(state, { type: "request_started", revision });
    state = refreshReducer(state, { type: "registration_closed", revision, at: 100 });

    expect(state.isRefreshing).toBe(true);
    expect(state.pendingRequests).toBe(1);

    state = refreshReducer(state, { type: "request_settled", revision, at: 120 });

    expect(state.isRefreshing).toBe(false);
    expect(state.lastSuccessfulAt).toBe(120);
  });

  it("reports a real partial failure", () => {
    let state = refreshReducer(initialRefreshState, { type: "trigger" });
    const revision = state.refreshRevision;
    state = refreshReducer(state, { type: "request_started", revision });
    state = refreshReducer(state, { type: "registration_closed", revision, at: 100 });
    state = refreshReducer(state, {
      type: "request_settled", revision, at: 130, error: "header stats failed",
    });

    expect(state.isRefreshing).toBe(false);
    expect(state.lastError).toBe("header stats failed");
    expect(state.lastSuccessfulAt).toBeNull();
  });

  it("ignores stale completions from a superseded refresh", () => {
    let state = refreshReducer(initialRefreshState, { type: "trigger" });
    const stale = state.refreshRevision;
    state = refreshReducer(state, { type: "request_started", revision: stale });
    state = refreshReducer(state, { type: "trigger" });

    expect(refreshReducer(state, {
      type: "request_settled", revision: stale, at: 200,
    })).toEqual(state);
  });
});
