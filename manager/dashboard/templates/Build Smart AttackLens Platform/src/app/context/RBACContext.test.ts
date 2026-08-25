import { describe, it, expect } from "vitest";
import {
  ROLES, isRole, permitted, userFromAuthMe, isAdminRole, type Role,
} from "./RBACContext";

/**
 * The role used to come from localStorage and was settable from a "Switch Role"
 * menu, so any viewer could grant themselves admin in devtools. It now comes
 * from /api/v1/auth/me. These cover the mapping and the fail-closed rules; the
 * server remains the actual authority.
 */

describe("role recognition", () => {
  it("accepts exactly the three known roles", () => {
    expect(ROLES).toEqual(["admin", "analyst", "viewer"]);
    for (const r of ROLES) expect(isRole(r)).toBe(true);
  });

  it("rejects anything else, including near-misses", () => {
    for (const v of ["owner", "superuser", "Admin", "", null, undefined, 1, {}]) {
      expect(isRole(v), String(v)).toBe(false);
    }
  });
});

describe("mapping /auth/me onto a display user", () => {
  it("uses the role, name and initials the server supplied", () => {
    expect(userFromAuthMe({
      email: "jane.doe@corp.io", role: "analyst", name: "Jane Doe", initials: "JD",
    })).toEqual({
      name: "Jane Doe", initials: "JD", role: "analyst", email: "jane.doe@corp.io",
    });
  });

  it("falls back to viewer when the server sends an unknown role", () => {
    // A signed token could still carry a role this build does not know about.
    expect(userFromAuthMe({ email: "x@y.z", role: "superuser" }).role).toBe("viewer");
    expect(userFromAuthMe({ email: "x@y.z" }).role).toBe("viewer");
  });

  it("never returns admin for a malformed payload", () => {
    for (const payload of [null, undefined, "admin", 42, [], {}]) {
      expect(userFromAuthMe(payload).role, JSON.stringify(payload)).toBe("viewer");
    }
  });

  it("derives a name from the email when the server omits one", () => {
    const u = userFromAuthMe({ email: "ops.lead@corp.io", role: "admin" });
    expect(u.name).toBe("ops.lead");
    expect(u.initials).toBe("O");
  });

  it("caps initials at two characters", () => {
    expect(userFromAuthMe({
      email: "a@b.c", role: "admin", name: "A", initials: "toolong",
    }).initials).toBe("TO");
  });
});

describe("permission checks", () => {
  const cases: [Role, string, boolean][] = [
    ["admin",   "manage_keys",    true],
    ["analyst", "manage_keys",    false],
    ["viewer",  "manage_keys",    false],
    ["admin",   "update_finding", true],
    ["analyst", "update_finding", true],
    ["viewer",  "update_finding", false],
    ["viewer",  "view_findings",  true],
    ["admin",   "export_data",    true],
    ["analyst", "export_data",    false],
  ];

  it.each(cases)("%s / %s -> %s", (role, action, expected) => {
    expect(permitted(role, action)).toBe(expected);
  });

  it("offers nothing while the session is still resolving", () => {
    // null role = /auth/me has not answered. Least privilege, not most.
    for (const action of ["view_findings", "update_finding", "manage_keys"]) {
      expect(permitted(null, action), action).toBe(false);
    }
  });

  it("restricts an unknown action to admin rather than allowing it", () => {
    expect(permitted("admin", "some_future_action")).toBe(true);
    expect(permitted("analyst", "some_future_action")).toBe(false);
    expect(permitted("viewer", "some_future_action")).toBe(false);
    expect(permitted(null, "some_future_action")).toBe(false);
  });
});

describe("administrator-only gate", () => {
  it("treats only the admin role as privileged", () => {
    expect(isAdminRole("admin")).toBe(true);
  });

  it("denies every non-admin role and the unresolved session", () => {
    for (const role of ["analyst", "viewer", null] as (Role | null)[]) {
      expect(isAdminRole(role), String(role)).toBe(false);
    }
  });
});
