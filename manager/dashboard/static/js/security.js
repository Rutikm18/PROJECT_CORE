/** security.js — Security status panel */

const CHECKS = {
  "sec-sip":    { key: "sip",         ok: /enabled/i,      label: "SIP"           },
  "sec-gk":     { key: "gatekeeper",  ok: /enabled|on/i,   label: "Gatekeeper"    },
  "sec-fv":     { key: "filevault",   ok: /on|enabled/i,   label: "FileVault"     },
  "sec-fw":     { key: "firewall",    ok: /enabled|on/i,   label: "Firewall"      },
  "sec-ssh":    { key: "sip",         ok: null,            label: "SSH Server"    },
  "sec-screen": { key: "sip",         ok: null,            label: "Screen Share"  },
};

export function updateSecurity(data) {
  for (const [id, check] of Object.entries(CHECKS)) {
    const el = document.getElementById(id);
    if (!el) continue;
    const val = String(data[check.key] || "");
    let state = "warn";
    let icon  = "?";
    if (check.ok) {
      if (check.ok.test(val))         { state = "ok";   icon = "✓"; }
      else if (/disabled|off/i.test(val)) { state = "fail"; icon = "✗"; }
    }
    el.className = `sec-item ${state}`;
    el.querySelector(".sec-icon").textContent = icon;
  }
}
