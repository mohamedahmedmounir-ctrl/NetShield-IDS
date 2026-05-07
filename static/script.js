/**
 * static/script.js
 * ==================
 * Core dashboard controller.
 * Handles: IDS control (start/stop), polling, alert table,
 * packet stream, top-IP list, threat score ring, modal,
 * toast notifications, status bar.
 */

"use strict";

// ── Polling interval (ms) ─────────────────────────────────────
const POLL_MS = 2000;
let   pollTimer = null;

// ── Protocol color map ────────────────────────────────────────
const PROTO_COLORS = {
  TCP:   "#00e5ff",
  UDP:   "#ffd60a",
  ICMP:  "#ff6b35",
  HTTP:  "#30d158",
  HTTPS: "#bf5af2",
  DNS:   "#ff2d55",
  FTP:   "#ff9f0a",
  SSH:   "#64d2ff",
};

const SEV_COLORS = {
  CRITICAL: "#ff2d55",
  HIGH:     "#ff6b35",
  MEDIUM:   "#ffd60a",
  LOW:      "#30d158",
};

// ── IDS Control ───────────────────────────────────────────────

async function startIDS() {
  try {
    const res  = await fetch("/api/start", { method: "POST" });
    const data = await res.json();
    showToast("▶ " + data.message);
    document.getElementById("btnStart").disabled = true;
    document.getElementById("btnStop").disabled  = false;
    setStatusActive(true);
    startPolling();
  } catch (e) {
    showToast("⚠ Could not start IDS — is Flask running?");
  }
}

async function stopIDS() {
  try {
    const res  = await fetch("/api/stop", { method: "POST" });
    const data = await res.json();
    showToast("■ " + data.message);
    document.getElementById("btnStart").disabled = false;
    document.getElementById("btnStop").disabled  = true;
    setStatusActive(false);
  } catch (e) {
    showToast("⚠ Could not stop IDS.");
  }
}

async function exportLogs() {
  showToast("⬇ Downloading logs…");
  window.location.href = "/api/logs/export";
}

async function clearLogs() {
  if (!confirm("Clear all logs and counters?")) return;
  await fetch("/api/logs/clear", { method: "POST" });
  document.getElementById("alertsBody").innerHTML =
    '<tr><td colspan="9" class="no-data-row">Logs cleared</td></tr>';
  document.getElementById("packetsBody").innerHTML =
    '<tr><td colspan="10" class="no-data-row">Logs cleared</td></tr>';
  document.getElementById("topIPList").innerHTML =
    '<div class="no-data">Waiting for data…</div>';
  showToast("⌫ Logs cleared");
}

// ── Status helpers ────────────────────────────────────────────

function setStatusActive(active) {
  const pill  = document.getElementById("statusPill");
  const label = document.getElementById("statusLabel");
  pill.classList.toggle("active", active);
  label.textContent = active ? "MONITORING" : "OFFLINE";
}

// ── Polling Loop ──────────────────────────────────────────────

function startPolling() {
  if (pollTimer) return;
  pollAll();
  pollTimer = setInterval(pollAll, POLL_MS);
}

async function pollAll() {
  try {
    await Promise.all([
      pollStatus(),
      pollAlerts(),
      pollPackets(),
      pollTopIPs(),
      pollThreatScore(),
    ]);
  } catch (_) { /* silently ignore network glitches */ }
}

// ── Status / Counters ─────────────────────────────────────────

async function pollStatus() {
  const data = await fetchJSON("/api/status");
  if (!data) return;

  setStatusActive(data.monitoring);
  document.getElementById("uptimeDisplay").textContent  = data.uptime || "00:00:00";
  document.getElementById("totalPackets").textContent   = fmtNum(data.packets_captured);
  document.getElementById("totalAlerts").textContent    = fmtNum(data.threats_detected);
  document.getElementById("monitoringInterface").textContent = data.interface || "N/A";

  if (data.monitoring) {
    document.getElementById("btnStart").disabled = true;
    document.getElementById("btnStop").disabled  = false;
  }
}

// ── Threat Score Ring ─────────────────────────────────────────

async function pollThreatScore() {
  const data = await fetchJSON("/api/threat-score");
  if (!data) return;

  const score     = data.score;
  const level     = data.level;
  const scoreEl   = document.getElementById("scoreNum");
  const ringEl    = document.getElementById("scoreRing");
  const levelEl   = document.getElementById("threatLevelLabel");
  const actionEl  = document.getElementById("threatAction");
  const bannerEl  = document.getElementById("threatBanner");

  // Update ring
  const circumference = 326.73;
  const offset = circumference - (score / 100) * circumference;
  ringEl.style.strokeDashoffset = offset;

  // Color based on level
  const color = SEV_COLORS[level] || "#30d158";
  ringEl.style.stroke     = color;
  scoreEl.style.color     = color;
  levelEl.style.color     = color;
  scoreEl.textContent     = score;
  levelEl.textContent     = level;

  const actions = {
    CRITICAL: "Immediate response required — isolate affected systems.",
    HIGH:     "Elevated threat — review active alerts.",
    MEDIUM:   "Suspicious activity detected — monitor closely.",
    LOW:      "All systems nominal.",
  };
  actionEl.textContent = actions[level] || "Monitoring…";

  // Banner border tint
  bannerEl.style.borderBottomColor = color + "40";
}

// ── Alerts Table ──────────────────────────────────────────────

let _alertCache = [];

async function pollAlerts() {
  const severity = document.getElementById("severityFilter").value;
  const search   = document.getElementById("alertSearch").value;
  const url      = `/api/alerts?limit=100&severity=${encodeURIComponent(severity)}&search=${encodeURIComponent(search)}`;
  const data     = await fetchJSON(url);
  if (!data) return;

  _alertCache = data.alerts;
  renderAlerts(_alertCache);

  const totalEl = document.getElementById("totalAlerts");
  totalEl.textContent = fmtNum(data.total);
}

function filterAlerts() {
  pollAlerts();
}

function renderAlerts(alerts) {
  const tbody = document.getElementById("alertsBody");
  if (!alerts.length) {
    tbody.innerHTML = '<tr><td colspan="9" class="no-data-row">No alerts matching filter</td></tr>';
    return;
  }

  tbody.innerHTML = alerts.map((a, i) => {
    const sev   = a.severity || "LOW";
    const score = a.score   || 0;
    const color = SEV_COLORS[sev] || "#30d158";
    const src   = a.source === "AI Anomaly Detector" ?
                  '<span class="src-ai">🤖 AI</span>' :
                  '<span class="src-rule">⚡ Rule</span>';
    return `
      <tr class="${i === 0 ? 'row-new' : ''}" onclick="showAlertDetail(${i})">
        <td class="text-dim">${fmtTime(a.timestamp)}</td>
        <td><span class="badge badge-${sev}">${sev}</span></td>
        <td class="text-bright">${escHtml(a.attack_type)}</td>
        <td class="text-cyan font-mono">${a.src_ip}</td>
        <td class="text-dim font-mono">${a.dst_ip}</td>
        <td class="text-yellow">${a.protocol}</td>
        <td>
          <div class="score-bar-wrap">
            <div class="score-bar">
              <div class="score-fill" style="width:${score}%;background:${color}"></div>
            </div>
            <span class="score-num-sm" style="color:${color}">${score}</span>
          </div>
        </td>
        <td>${src}</td>
        <td class="text-dim" style="max-width:200px;overflow:hidden;text-overflow:ellipsis"
            title="${escHtml(a.action)}">${escHtml(a.action)}</td>
      </tr>`;
  }).join("");
}

function showAlertDetail(idx) {
  const a = _alertCache[idx];
  if (!a) return;
  const sev   = a.severity || "LOW";
  const color = SEV_COLORS[sev] || "#30d158";

  document.getElementById("modalTitle").textContent = a.attack_type;
  document.getElementById("modalTitle").style.color = color;

  document.getElementById("modalBody").innerHTML = `
    <div class="detail-grid">
      <span class="detail-label">Timestamp</span>
      <span class="detail-value">${a.timestamp}</span>

      <span class="detail-label">Severity</span>
      <span class="detail-value"><span class="badge badge-${sev}">${sev}</span></span>

      <span class="detail-label">Risk Score</span>
      <span class="detail-value" style="color:${color}; font-family:'Orbitron',sans-serif">
        ${a.score} / 100
      </span>

      <div class="detail-divider"></div>

      <span class="detail-label">Source IP</span>
      <span class="detail-value text-cyan">${a.src_ip}:${a.src_port}</span>

      <span class="detail-label">Dest IP</span>
      <span class="detail-value">${a.dst_ip}:${a.dst_port}</span>

      <span class="detail-label">Protocol</span>
      <span class="detail-value">${a.protocol}</span>

      <div class="detail-divider"></div>

      <span class="detail-label">Description</span>
      <span class="detail-value">${escHtml(a.description)}</span>

      <span class="detail-label">Detected by</span>
      <span class="detail-value">${a.source}</span>

      <div class="action-box">${escHtml(a.action)}</div>
    </div>`;

  document.getElementById("modalOverlay").classList.add("open");
}

function closeModal() {
  document.getElementById("modalOverlay").classList.remove("open");
}

// ── Packet Stream ──────────────────────────────────────────────

async function pollPackets() {
  const data = await fetchJSON("/api/packets?limit=50");
  if (!data) return;
  renderPackets(data.packets);
  document.getElementById("totalPackets").textContent = fmtNum(data.total);
}

function renderPackets(packets) {
  const tbody = document.getElementById("packetsBody");
  if (!packets.length) {
    tbody.innerHTML = '<tr><td colspan="10" class="no-data-row">No packets yet</td></tr>';
    return;
  }

  tbody.innerHTML = packets.map((p, i) => {
    const dirClass = p.direction === "inbound" ? "dir-in" : "dir-out";
    const dirSym   = p.direction === "inbound" ? "↓ IN" : "↑ OUT";
    const protoColor = PROTO_COLORS[p.protocol] || "#a8c0cc";
    return `
      <tr class="${i === 0 ? 'row-new' : ''}">
        <td class="text-dim">${fmtTime(p.timestamp)}</td>
        <td class="text-cyan">${p.src_ip}</td>
        <td class="text-dim">${p.dst_ip}</td>
        <td class="text-dim">${p.src_port}</td>
        <td class="text-yellow">${p.dst_port}</td>
        <td style="color:${protoColor}">${p.protocol}</td>
        <td class="text-dim">${p.size} B</td>
        <td class="text-dim">${p.flags || '—'}</td>
        <td class="text-dim">${p.service || '—'}</td>
        <td class="${dirClass}">${dirSym}</td>
      </tr>`;
  }).join("");
}

// ── Top Suspicious IPs ────────────────────────────────────────

async function pollTopIPs() {
  const data = await fetchJSON("/api/top-ips");
  if (!data) return;
  renderTopIPs(data.top_ips);
}

function renderTopIPs(ips) {
  const container = document.getElementById("topIPList");
  if (!ips.length) {
    container.innerHTML = '<div class="no-data">No suspicious IPs yet</div>';
    return;
  }

  const maxScore = Math.max(...ips.map(i => i.risk_score), 1);
  container.innerHTML = ips.map((ip, idx) => {
    const color = SEV_COLORS[ip.severity] || "#30d158";
    const pct   = (ip.risk_score / maxScore) * 100;
    return `
      <div class="ip-row">
        <span class="ip-rank">#${idx + 1}</span>
        <span class="ip-addr">${ip.ip}</span>
        <span class="ip-count">${ip.alert_count} alerts</span>
        <div class="ip-bar-wrap">
          <div class="ip-bar" style="width:${pct}%;background:${color}"></div>
        </div>
        <span class="ip-score" style="color:${color}">${ip.risk_score}</span>
      </div>`;
  }).join("");
}

// ── Toast ─────────────────────────────────────────────────────

function showToast(msg) {
  const el = document.getElementById("toast");
  el.textContent = msg;
  el.classList.add("show");
  setTimeout(() => el.classList.remove("show"), 3000);
}

// ── Status Bar Clock ──────────────────────────────────────────

function updateClock() {
  document.getElementById("sbTime").textContent =
    new Date().toLocaleString("en-GB", { hour12: false });
}
updateClock();
setInterval(updateClock, 1000);

// ── Utilities ─────────────────────────────────────────────────

async function fetchJSON(url) {
  try {
    const res = await fetch(url);
    if (!res.ok) throw new Error(res.statusText);
    return await res.json();
  } catch (_) {
    return null;
  }
}

function fmtNum(n) {
  return (n || 0).toLocaleString();
}

function fmtTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleTimeString("en-GB", { hour12: false });
}

function escHtml(str) {
  return String(str || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ── On page load: poll once immediately, then start full loop ──

window.addEventListener("DOMContentLoaded", () => {
  pollAll();          // immediate first paint from warm-up data
  startPolling();     // continuous refresh
});
