/**
 * static/dashboard.js
 * =====================
 * Chart.js chart initialisation and live-update logic.
 *
 * Charts:
 *   1. timelineChart  – area chart: packets & alerts per minute
 *   2. protocolChart  – doughnut: protocol distribution
 */

"use strict";

// ── Shared Chart.js defaults ──────────────────────────────────

Chart.defaults.color         = "#4a6070";
Chart.defaults.font.family   = "'Share Tech Mono', monospace";
Chart.defaults.font.size     = 11;
Chart.defaults.borderColor   = "rgba(0,229,255,.08)";

// ── Color palette ─────────────────────────────────────────────

const PROTOCOL_PALETTE = [
  "#00e5ff", "#ffd60a", "#ff6b35", "#30d158",
  "#bf5af2", "#ff2d55", "#ff9f0a", "#64d2ff",
];

// ── Timeline Chart ────────────────────────────────────────────

let timelineChart = null;

function initTimelineChart() {
  const ctx = document.getElementById("timelineChart").getContext("2d");

  // Gradient fill for packet area
  const pktGrad = ctx.createLinearGradient(0, 0, 0, 200);
  pktGrad.addColorStop(0, "rgba(0,229,255,.35)");
  pktGrad.addColorStop(1, "rgba(0,229,255,.00)");

  const altGrad = ctx.createLinearGradient(0, 0, 0, 200);
  altGrad.addColorStop(0, "rgba(255,45,85,.35)");
  altGrad.addColorStop(1, "rgba(255,45,85,.00)");

  timelineChart = new Chart(ctx, {
    type: "line",
    data: {
      labels:   [],
      datasets: [
        {
          label:           "Packets / min",
          data:            [],
          borderColor:     "#00e5ff",
          backgroundColor: pktGrad,
          borderWidth:     2,
          pointRadius:     2,
          tension:         0.4,
          fill:            true,
          yAxisID:         "yPkts",
        },
        {
          label:           "Alerts / min",
          data:            [],
          borderColor:     "#ff2d55",
          backgroundColor: altGrad,
          borderWidth:     2,
          pointRadius:     2,
          tension:         0.4,
          fill:            true,
          yAxisID:         "yAlerts",
        },
      ],
    },
    options: {
      responsive:          true,
      maintainAspectRatio: false,
      animation:           { duration: 400 },
      interaction:         { mode: "index", intersect: false },
      plugins: {
        legend: {
          position: "top",
          align:    "end",
          labels:   { boxWidth: 10, padding: 14 },
        },
        tooltip: {
          backgroundColor: "rgba(7,13,26,.95)",
          borderColor:     "rgba(0,229,255,.3)",
          borderWidth:     1,
          padding:         10,
        },
      },
      scales: {
        x: {
          grid:  { color: "rgba(255,255,255,.04)" },
          ticks: { maxTicksLimit: 10 },
        },
        yPkts: {
          type:     "linear",
          position: "left",
          grid:     { color: "rgba(255,255,255,.04)" },
          ticks:    { color: "#00e5ff" },
        },
        yAlerts: {
          type:     "linear",
          position: "right",
          grid:     { drawOnChartArea: false },
          ticks:    { color: "#ff2d55" },
        },
      },
    },
  });
}

async function updateTimelineChart() {
  const data = await fetchJSON("/api/timeline");
  if (!data || !timelineChart) return;

  timelineChart.data.labels                 = data.map(d => d.time);
  timelineChart.data.datasets[0].data       = data.map(d => d.packets);
  timelineChart.data.datasets[1].data       = data.map(d => d.alerts);
  timelineChart.update("none");
}

// ── Protocol Doughnut Chart ───────────────────────────────────

let protocolChart = null;

function initProtocolChart() {
  const ctx = document.getElementById("protocolChart").getContext("2d");

  protocolChart = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels:   [],
      datasets: [{
        data:            [],
        backgroundColor: PROTOCOL_PALETTE,
        borderColor:     "rgba(7,13,26,.8)",
        borderWidth:     2,
        hoverBorderColor:"rgba(0,229,255,.5)",
        hoverOffset:     6,
      }],
    },
    options: {
      responsive:          true,
      maintainAspectRatio: false,
      cutout:              "72%",
      animation:           { duration: 600 },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: "rgba(7,13,26,.95)",
          borderColor:     "rgba(0,229,255,.3)",
          borderWidth:     1,
          callbacks: {
            label: (ctx) =>
              ` ${ctx.label}: ${ctx.parsed} pkts (${
                ((ctx.parsed / ctx.dataset.data.reduce((a,b)=>a+b,0))*100).toFixed(1)
              }%)`,
          },
        },
      },
    },
  });
}

async function updateProtocolChart() {
  const data = await fetchJSON("/api/protocol-stats");
  if (!data || !protocolChart) return;

  protocolChart.data.labels                = data.map(d => d.protocol);
  protocolChart.data.datasets[0].data      = data.map(d => d.count);
  protocolChart.update("none");

  // Rebuild legend chips
  const legendEl = document.getElementById("protocolLegend");
  legendEl.innerHTML = data.slice(0, 6).map((d, i) => `
    <div class="proto-chip">
      <div class="proto-dot" style="background:${PROTOCOL_PALETTE[i % PROTOCOL_PALETTE.length]}"></div>
      ${d.protocol} <span class="text-dim">${d.pct}%</span>
    </div>`).join("");
}

// ── Bandwidth counter ─────────────────────────────────────────

async function updateBandwidth() {
  const data = await fetchJSON("/api/analytics");
  if (!data) return;
  const bytes = data.total_bytes || 0;
  document.getElementById("totalBandwidth").textContent = fmtBytes(bytes);
}

function fmtBytes(b) {
  if (b < 1024)           return `${b} B`;
  if (b < 1048576)        return `${(b/1024).toFixed(1)} KB`;
  if (b < 1073741824)     return `${(b/1048576).toFixed(1)} MB`;
  return `${(b/1073741824).toFixed(2)} GB`;
}

// ── Full chart refresh ────────────────────────────────────────

async function refreshCharts() {
  await Promise.all([
    updateTimelineChart(),
    updateProtocolChart(),
    updateBandwidth(),
  ]);
}

// ── Init on DOMContentLoaded ──────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {
  initTimelineChart();
  initProtocolChart();
  refreshCharts();
  setInterval(refreshCharts, 2000);
});
