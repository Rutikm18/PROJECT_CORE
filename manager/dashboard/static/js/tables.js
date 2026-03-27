/** tables.js — Render + filter + sort tables */

function esc(s) {
  return String(s ?? "")
    .replace(/&/g,"&amp;").replace(/</g,"&lt;")
    .replace(/>/g,"&gt;");
}

function fillTable(tbodyId, rows, cols) {
  const tbody = document.querySelector(`#${tbodyId} tbody`);
  if (!tbody) return;
  tbody.innerHTML = rows.map(row =>
    `<tr>${cols.map(c =>
      `<td class="${c.mono ? "mono" : ""}">${esc(row[c.key] ?? "")}</td>`
    ).join("")}</tr>`
  ).join("");
}

export function renderProcesses(data) {
  fillTable("tbl-procs", data.slice(0, 80), [
    { key: "pid"  },
    { key: "user" },
    { key: "cpu", mono: true },
    { key: "mem", mono: true },
    { key: "cmd"  },
  ]);
}

export function renderPorts(data) {
  fillTable("tbl-ports", data.slice(0, 100), [
    { key: "proc" },
    { key: "pid",   mono: true },
    { key: "proto", mono: true },
    { key: "addr",  mono: true },
  ]);
}

export function renderConnections(data) {
  fillTable("tbl-conns", data.slice(0, 100), [
    { key: "proc" },
    { key: "pid",  mono: true },
    { key: "addr", mono: true },
  ]);
}

export function renderSbom(items) {
  const el = document.getElementById("sbom-count");
  if (el) el.textContent = items.length + " components";
  fillTable("tbl-sbom", items.slice(0, 200), [
    { key: "name" },
    { key: "version", mono: true },
    { key: "type"    },
    { key: "source"  },
  ]);
}

/** Live filter: hides rows not matching input */
export function wireFilter(inputId, tableId) {
  const input = document.getElementById(inputId);
  if (!input) return;
  input.addEventListener("input", () => {
    const q = input.value.toLowerCase();
    document.querySelectorAll(`#${tableId} tbody tr`).forEach(tr => {
      tr.style.display = tr.textContent.toLowerCase().includes(q) ? "" : "none";
    });
  });
}
