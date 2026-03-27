/**
 * app.js — mac_intel Dashboard
 * ES module, no framework, no build step.
 * Manages: agent list, WebSocket lifecycle, section dispatch.
 */

import { initCpuChart, initMemChart, initBatteryChart,
         pushCpu, pushMem, pushBattery } from "./charts.js";
import { renderProcesses, renderPorts, renderConnections,
         renderSbom, wireFilter } from "./tables.js";
import { updateSecurity } from "./security.js";
import { WsClient } from "./ws_client.js";

// ── State ─────────────────────────────────────────────────────────────────────
let activeAgentId = null;
let wsClient      = null;

// ── Boot ──────────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  initCpuChart("chart-cpu");
  initMemChart("chart-mem");
  initBatteryChart("chart-battery");
  wireFilter("filter-procs",  "tbl-procs");
  wireFilter("filter-ports",  "tbl-ports");
  wireFilter("filter-conns",  "tbl-conns");
  loadAgentList();
  setInterval(loadAgentList, 10_000);
  setInterval(tickServerTime, 1_000);
});

// ── Agent list ────────────────────────────────────────────────────────────────
async function loadAgentList() {
  try {
    const agents = await apiFetch("/api/v1/agents");
    renderAgentList(agents);
  } catch (e) { console.warn("loadAgentList:", e); }
}

function renderAgentList(agents) {
  const ul = document.getElementById("agent-list");
  ul.innerHTML = "";
  for (const a of agents) {
    const li = document.createElement("li");
    li.dataset.id = a.agent_id;
    if (a.agent_id === activeAgentId) li.classList.add("active");
    li.innerHTML = `
      <span class="agent-dot ${a.online ? "online" : "offline"}"></span>
      <div class="agent-info">
        <div class="name">${esc(a.name || a.agent_id)}</div>
        <div class="lastseen">${relTime(a.last_seen)}</div>
      </div>`;
    li.addEventListener("click", () => selectAgent(a));
    ul.appendChild(li);
  }
}

// ── Select agent ──────────────────────────────────────────────────────────────
async function selectAgent(agent) {
  if (activeAgentId === agent.agent_id) return;
  activeAgentId = agent.agent_id;

  document.querySelectorAll("#agent-list li").forEach(li => {
    li.classList.toggle("active", li.dataset.id === agent.agent_id);
  });

  document.getElementById("welcome").classList.add("hidden");
  document.getElementById("dashboard").classList.remove("hidden");

  document.getElementById("agent-name").textContent = agent.name || agent.agent_id;
  document.getElementById("agent-id").textContent   = agent.agent_id;
  setStatus(agent.online);

  // Load initial data for all sections from REST
  const sections = ["metrics", "processes", "ports", "connections",
                    "battery", "security", "sbom"];
  await Promise.allSettled(sections.map(s => loadSection(agent.agent_id, s)));

  // Open WebSocket for live updates
  if (wsClient) wsClient.disconnect();
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const token = window.__API_KEY__ || prompt("Enter API key for live updates:");
  wsClient = new WsClient(
    `${proto}://${location.host}/ws/${agent.agent_id}?token=${encodeURIComponent(token)}`,
    onWsMessage
  );
  wsClient.connect();
}

// ── Load initial section data (REST) ─────────────────────────────────────────
async function loadSection(agentId, section) {
  try {
    const rows = await apiFetch(
      `/api/v1/agents/${agentId}/${section}?limit=60`
    );
    if (!rows || !rows.length) return;
    // Feed historical data into charts / tables (latest first → reverse)
    for (const row of [...rows].reverse()) {
      dispatchSection(section, row.data, row.collected_at);
    }
  } catch (e) { console.warn("loadSection", section, e); }
}

// ── WebSocket message handler ─────────────────────────────────────────────────
function onWsMessage(msg) {
  if (msg.type !== "payload") return;
  if (msg.agent_id !== activeAgentId) return;
  dispatchSection(msg.section, msg.data, msg.collected_at);
  document.getElementById("last-seen").textContent =
    "Live · " + new Date().toLocaleTimeString();
}

// ── Section dispatch → render ─────────────────────────────────────────────────
function dispatchSection(section, data, ts) {
  switch (section) {
    case "metrics":     handleMetrics(data, ts);     break;
    case "processes":   handleProcesses(data);        break;
    case "ports":       handlePorts(data);            break;
    case "connections": handleConnections(data);      break;
    case "battery":     handleBattery(data, ts);      break;
    case "security":    updateSecurity(data);         break;
    case "sbom":        renderSbom(data.items || []); break;
  }
}

// ── Section handlers ──────────────────────────────────────────────────────────
function handleMetrics(data, ts) {
  // Parse CPU % from top output line: "CPU usage: X% user, Y% sys, Z% idle"
  const cpu_match = (data.cpu || "").match(/(\d+\.?\d*)%\s+idle/);
  const idle = cpu_match ? parseFloat(cpu_match[1]) : null;
  const cpu  = idle !== null ? Math.round(100 - idle) : null;

  if (cpu !== null) {
    pushCpu(cpu, ts);
    document.getElementById("val-cpu").textContent = cpu + "%";
  }

  // Parse memory from vm_stat
  const vm = data.vmstat || "";
  const freeM  = parseVmStat(vm, "Pages free");
  const activeM = parseVmStat(vm, "Pages active");
  const wiredM  = parseVmStat(vm, "Pages wired down");
  const pg = 16384; // 16KB pages on Apple Silicon
  const used = ((activeM + wiredM) * pg / 1e9).toFixed(1);
  if (used > 0) {
    pushMem(parseFloat(used), ts);
    document.getElementById("val-mem").textContent = used + " GB";
  }

  // Load average
  const load = (data.load || "").match(/\{([^}]+)\}/);
  if (load) {
    const parts = load[1].trim().split(/\s+/);
    if (parts[0])
      document.getElementById("val-cpu").title = `Load: ${parts.join(" ")}`;
  }
}

function parseVmStat(text, key) {
  const m = text.match(new RegExp(key + "\\s*:\\s*(\\d+)"));
  return m ? parseInt(m[1]) : 0;
}

function handleProcesses(data) {
  if (!Array.isArray(data)) return;
  document.getElementById("val-procs").textContent = data.length;
  renderProcesses(data);
}

function handlePorts(data) {
  if (!Array.isArray(data)) return;
  document.getElementById("val-ports").textContent = data.length;
  renderPorts(data);
}

function handleConnections(data) {
  if (!Array.isArray(data)) return;
  document.getElementById("val-conns").textContent = data.length;
  renderConnections(data);
}

function handleBattery(data, ts) {
  const line = data.pmset || "";
  const m    = line.match(/(\d+)%/);
  if (m) {
    const pct = parseInt(m[1]);
    pushBattery(pct, ts);
    const charging = /charging/i.test(line) ? " ⚡" : "";
    document.getElementById("val-battery").textContent = pct + "%" + charging;
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function setStatus(online) {
  const el = document.getElementById("agent-status");
  el.textContent  = online ? "Online" : "Offline";
  el.className    = "badge " + (online ? "online" : "offline");
}

function tickServerTime() {
  document.getElementById("server-time").textContent =
    new Date().toLocaleTimeString();
}

function relTime(ts) {
  if (!ts) return "never";
  const s = Math.round(Date.now() / 1000 - ts);
  if (s < 5)   return "just now";
  if (s < 60)  return s + "s ago";
  if (s < 3600) return Math.floor(s / 60) + "m ago";
  return Math.floor(s / 3600) + "h ago";
}

function esc(str) {
  return String(str)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

async function apiFetch(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}
