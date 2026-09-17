const API = "/api/v1";
const REFRESH_MS = 10000;

const state = { hosts: [], alerts: [], stats: null, selectedHost: null, timer: null };

const el = (id) => document.getElementById(id);

async function api(path, options) {
  const response = await fetch(API + path, options);
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
  return response.json();
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[c]);
}

function severityColour(severity) {
  return {
    NORMAL: "var(--normal)", LOW: "var(--low)", MEDIUM: "var(--medium)",
    HIGH: "var(--high)", CRITICAL: "var(--critical)",
  }[severity] || "var(--muted)";
}

function pill(severity) {
  return `<span class="pill sev-${escapeHtml(severity)}">${escapeHtml(severity)}</span>`;
}

function score(value, severity) {
  return `<span class="score score-${escapeHtml(severity)}">${value}</span>`;
}

function relativeTime(iso) {
  if (!iso) return "never";
  const seconds = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (seconds < 60) return `${Math.round(seconds)}s ago`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)}h ago`;
  return `${Math.round(seconds / 86400)}d ago`;
}

function minutes(seconds) {
  if (!seconds) return "–";
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${(seconds / 60).toFixed(0)}m`;
  return `${(seconds / 3600).toFixed(1)}h`;
}

function renderStats(stats) {
  const counts = stats.severity_counts || {};
  const cards = [
    { label: "Hosts monitored", value: stats.hosts_monitored },
    { label: "Hosts online", value: stats.hosts_online },
    { label: "Active alerts", value: stats.active_alerts, colour: stats.active_alerts ? "var(--high)" : null },
    { label: "Critical", value: counts.CRITICAL || 0, colour: "var(--critical)" },
    { label: "High", value: counts.HIGH || 0, colour: "var(--high)" },
    { label: "Medium", value: counts.MEDIUM || 0, colour: "var(--medium)" },
    { label: "Detections 24h", value: stats.detections_24h },
  ];
  el("stats").innerHTML = cards.map((card) => `
    <div class="stat">
      <div class="label">${escapeHtml(card.label)}</div>
      <div class="value" ${card.colour && card.value ? `style="color:${card.colour}"` : ""}>${card.value}</div>
    </div>`).join("");
}

function renderHosts(hosts) {
  const body = el("hosts-table").querySelector("tbody");
  el("hosts-empty").hidden = hosts.length > 0;
  el("host-count").textContent = hosts.length ? `${hosts.length} reporting` : "";

  body.innerHTML = hosts.map((host) => `
    <tr data-host="${host.id}">
      <td>
        <span class="dot ${host.online ? "online" : "offline"}"></span>
        <strong>${escapeHtml(host.hostname)}</strong>
        ${host.top_process ? `<div class="muted mono">${escapeHtml(host.top_process)}</div>` : ""}
      </td>
      <td class="muted">${escapeHtml(host.os || "unknown")}</td>
      <td class="mono muted">${escapeHtml(host.ip_address || "–")}</td>
      <td class="num">${score(host.risk_score, host.severity)}
        <div class="bar"><span style="width:${host.risk_score}%;background:${severityColour(host.severity)}"></span></div>
      </td>
      <td>${pill(host.severity)}</td>
      <td class="num">${host.open_alerts || 0}<div class="muted">${relativeTime(host.last_seen)}</div></td>
    </tr>`).join("");

  body.querySelectorAll("tr").forEach((row) => {
    row.addEventListener("click", () => showHost(Number(row.dataset.host)));
  });
}

function renderAlerts(alerts) {
  el("alerts-empty").hidden = alerts.length > 0;
  el("alert-count").textContent = alerts.length ? `${alerts.length} open` : "";

  el("alerts-list").innerHTML = alerts.map((alert) => `
    <div class="alert sevbar-${escapeHtml(alert.severity)}">
      <div class="alert-head">
        ${pill(alert.severity)}
        <span class="host">${escapeHtml(alert.hostname)}</span>
        <span class="mono muted">${escapeHtml(alert.process_name || alert.detection_type)}</span>
        <span class="tag">${alert.risk_score}</span>
        <span class="tag">${escapeHtml(alert.status)}</span>
      </div>
      <div class="alert-reason">${escapeHtml(alert.reason)}</div>
      <div class="alert-actions">
        <button class="btn btn-sm" data-alert="${alert.id}" data-status="acknowledged">Acknowledge</button>
        <button class="btn btn-sm" data-alert="${alert.id}" data-status="investigating">Investigate</button>
        <button class="btn btn-sm" data-alert="${alert.id}" data-status="closed">Close</button>
        <button class="btn btn-sm" data-alert="${alert.id}" data-status="false_positive">False positive</button>
      </div>
    </div>`).join("");

  el("alerts-list").querySelectorAll("button[data-alert]").forEach((button) => {
    button.addEventListener("click", async () => {
      button.disabled = true;
      const status = button.dataset.status;
      const body = { status };
      if (status === "false_positive") body.resolution = "Marked as a false positive from the dashboard.";
      if (status === "closed") body.resolution = "Closed from the dashboard.";
      try {
        await api(`/alerts/${button.dataset.alert}`, {
          method: "PATCH",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(body),
        });
        await refresh();
      } finally {
        button.disabled = false;
      }
    });
  });
}

function renderSignals(signals) {
  if (!signals || !signals.length) return "";
  return `<div class="signals">${signals.map((signal) => `
    <div class="signal">
      <span class="pts ${signal.points >= 0 ? "pos" : "neg"}">${signal.points >= 0 ? "+" : ""}${signal.points}</span>
      <span>${escapeHtml(signal.title)}</span>
      <span class="detail">${escapeHtml(signal.detail)}</span>
    </div>`).join("")}</div>`;
}

function renderFindings(detections) {
  if (!detections.length) return `<p class="empty">No detections recorded for this host.</p>`;
  return detections.map((detection) => `
    <div class="finding">
      <div class="finding-head">
        ${pill(detection.severity)}
        <span class="name">${escapeHtml(detection.process_name || detection.detection_type)}</span>
        <span class="tag">score ${detection.risk_score}</span>
        <span class="tag">${escapeHtml(detection.detection_type)}</span>
        <span class="tag">${escapeHtml(detection.status)}</span>
        <span class="tag">seen ${detection.observation_count}x</span>
      </div>
      <div class="finding-reason">${escapeHtml(detection.reason)}</div>
      ${renderSignals(detection.signals)}
    </div>`).join("");
}

function renderProcesses(processes) {
  if (!processes.length) return `<p class="empty">No process telemetry.</p>`;
  return `<div class="scroll"><table class="grid">
    <thead><tr>
      <th>Process</th><th class="num">CPU</th><th class="num">Machine</th>
      <th class="num">GPU</th><th class="num">Sustained</th><th class="num">Age</th><th>Path</th>
    </tr></thead>
    <tbody>${processes.map((proc) => `
      <tr>
        <td class="mono">${escapeHtml(proc.name)}<div class="muted">pid ${proc.pid}</div></td>
        <td class="num mono">${proc.cpu_usage.toFixed(0)}%</td>
        <td class="num mono muted">${proc.cpu_share.toFixed(0)}%</td>
        <td class="num mono">${proc.gpu_usage ? `${proc.gpu_usage.toFixed(0)}%` : "–"}</td>
        <td class="num mono">${minutes(proc.cpu_sustained_seconds)}</td>
        <td class="num mono muted">${minutes(proc.lifetime_seconds)}</td>
        <td class="mono muted">${escapeHtml(proc.path || "unavailable")}</td>
      </tr>`).join("")}</tbody></table></div>`;
}

function renderNetwork(events) {
  if (!events.length) return `<p class="empty">No outbound connections recorded.</p>`;
  return `<div class="scroll"><table class="grid">
    <thead><tr>
      <th>Destination</th><th class="num">Port</th><th>Process</th>
      <th class="num">Age</th><th class="num">Seen</th><th>State</th>
    </tr></thead>
    <tbody>${events.map((event) => `
      <tr>
        <td class="mono">${escapeHtml(event.destination_domain || event.destination_ip)}
          ${event.destination_domain ? `<div class="muted">${escapeHtml(event.destination_ip)}</div>` : ""}</td>
        <td class="num mono">${event.destination_port}</td>
        <td class="mono muted">${escapeHtml(event.process_name || `pid ${event.pid}`)}</td>
        <td class="num mono">${minutes(event.duration_seconds)}</td>
        <td class="num mono">${event.connection_count}x</td>
        <td class="muted">${escapeHtml(event.status || event.protocol)}</td>
      </tr>`).join("")}</tbody></table></div>`;
}

function renderPersistence(items) {
  if (!items.length) return `<p class="empty">No autostart entries collected.</p>`;
  return `<div class="scroll"><table class="grid">
    <thead><tr><th>Mechanism</th><th>Name</th><th>Command</th><th>Source</th></tr></thead>
    <tbody>${items.map((item) => `
      <tr>
        <td class="mono">${escapeHtml(item.mechanism)}</td>
        <td>${escapeHtml(item.name)}</td>
        <td class="mono muted">${escapeHtml(item.command || item.target_path)}</td>
        <td class="mono muted">${escapeHtml(item.source)}</td>
      </tr>`).join("")}</tbody></table></div>`;
}

async function showHost(hostId) {
  state.selectedHost = hostId;
  const data = await api(`/hosts/${hostId}`);
  const host = data.host;

  el("detail-panel").hidden = false;
  el("detail-title").textContent = host.hostname;
  el("detail-body").innerHTML = `
    <div class="detail-grid">
      <div class="stat"><div class="label">Risk score</div>
        <div class="value" style="color:${severityColour(host.severity)}">${host.risk_score}</div></div>
      <div class="stat"><div class="label">Severity</div><div class="value">${pill(host.severity)}</div></div>
      <div class="stat"><div class="label">Open alerts</div><div class="value">${host.open_alerts}</div></div>
      <div class="stat"><div class="label">Operating system</div>
        <div class="value" style="font-size:14px">${escapeHtml(host.os_version || host.os || "unknown")}</div></div>
      <div class="stat"><div class="label">Address</div>
        <div class="value" style="font-size:14px">${escapeHtml(host.ip_address || "–")}</div></div>
      <div class="stat"><div class="label">Last report</div>
        <div class="value" style="font-size:14px">${relativeTime(host.last_seen)}</div></div>
    </div>

    <div class="subsection"><h3>Detections</h3>${renderFindings(data.detections)}</div>
    <div class="subsection"><h3>Processes (latest sample)</h3>${renderProcesses(data.processes)}</div>
    <div class="subsection"><h3>Outbound network</h3>${renderNetwork(data.network_events)}</div>
    <div class="subsection"><h3>Persistence</h3>${renderPersistence(data.persistence)}</div>`;

  el("detail-panel").scrollIntoView({ behavior: "smooth", block: "start" });
}

async function refresh() {
  try {
    const [stats, hosts, alerts] = await Promise.all([
      api("/stats"), api("/hosts"), api("/alerts"),
    ]);
    state.stats = stats;
    state.hosts = hosts;
    state.alerts = alerts;
    renderStats(stats);
    renderHosts(hosts);
    renderAlerts(alerts);
    el("last-updated").textContent = `updated ${new Date().toLocaleTimeString()}`;
    if (state.selectedHost && hosts.some((h) => h.id === state.selectedHost)) {
      await showHost(state.selectedHost);
    }
  } catch (error) {
    el("last-updated").textContent = `error: ${error.message}`;
  }
}

function setAutoRefresh(enabled) {
  if (state.timer) clearInterval(state.timer);
  state.timer = enabled ? setInterval(refresh, REFRESH_MS) : null;
}

el("refresh").addEventListener("click", refresh);
el("detail-close").addEventListener("click", () => {
  el("detail-panel").hidden = true;
  state.selectedHost = null;
});
el("auto-refresh").addEventListener("change", (event) => setAutoRefresh(event.target.checked));

refresh();
setAutoRefresh(true);


