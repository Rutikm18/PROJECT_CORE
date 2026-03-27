/** charts.js — Chart.js wrappers for CPU, Memory, Battery */

const MAX_POINTS = 60;
const charts = {};

const CHART_DEFAULTS = {
  responsive: true, maintainAspectRatio: true,
  animation: { duration: 200 },
  plugins: { legend: { display: false } },
  scales: {
    x: { display: false },
    y: { grid: { color: "#21262d" }, ticks: { color: "#8b949e", font: { size: 10 } } },
  },
};

function makeLabels() { return Array(MAX_POINTS).fill(""); }

export function initCpuChart(id) {
  charts[id] = new Chart(document.getElementById(id), {
    type: "line",
    data: {
      labels: makeLabels(),
      datasets: [{
        data: Array(MAX_POINTS).fill(null),
        borderColor: "#58a6ff", backgroundColor: "rgba(88,166,255,.12)",
        fill: true, tension: 0.3, pointRadius: 0, borderWidth: 1.5,
      }],
    },
    options: { ...CHART_DEFAULTS, scales: { ...CHART_DEFAULTS.scales,
      y: { ...CHART_DEFAULTS.scales.y, min: 0, max: 100 } } },
  });
}

export function initMemChart(id) {
  charts[id] = new Chart(document.getElementById(id), {
    type: "line",
    data: {
      labels: makeLabels(),
      datasets: [{
        data: Array(MAX_POINTS).fill(null),
        borderColor: "#3fb950", backgroundColor: "rgba(63,185,80,.12)",
        fill: true, tension: 0.3, pointRadius: 0, borderWidth: 1.5,
      }],
    },
    options: { ...CHART_DEFAULTS },
  });
}

export function initBatteryChart(id) {
  charts[id] = new Chart(document.getElementById(id), {
    type: "line",
    data: {
      labels: makeLabels(),
      datasets: [{
        data: Array(MAX_POINTS).fill(null),
        borderColor: "#d29922", backgroundColor: "rgba(210,153,34,.12)",
        fill: true, tension: 0.3, pointRadius: 0, borderWidth: 1.5,
      }],
    },
    options: { ...CHART_DEFAULTS, scales: { ...CHART_DEFAULTS.scales,
      y: { ...CHART_DEFAULTS.scales.y, min: 0, max: 100 } } },
  });
}

function push(chartId, value, ts) {
  const c = charts[chartId];
  if (!c) return;
  const label = ts ? new Date(ts * 1000).toLocaleTimeString() : "";
  c.data.labels.push(label);
  c.data.datasets[0].data.push(value);
  if (c.data.labels.length > MAX_POINTS) {
    c.data.labels.shift();
    c.data.datasets[0].data.shift();
  }
  c.update("none");
}

export const pushCpu     = (v, ts) => push("chart-cpu",     v, ts);
export const pushMem     = (v, ts) => push("chart-mem",     v, ts);
export const pushBattery = (v, ts) => push("chart-battery", v, ts);
