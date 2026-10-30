/* Omarchy Pulse Frontend Controller */

let currentReport = null;
let lastThemeMtime = null;
let activeTab = "overview";
let liveTimer = null;
let livePaused = false;
let liveSortBy = "cpu";

function showToast(msg) {
  const container = document.getElementById("toast-container");
  const el = document.createElement("div");
  el.className = "toast";
  el.textContent = msg;
  container.appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

function applyTheme(themeObj) {
  if (!themeObj || !themeObj.colors) return;
  if (themeObj.theme_mtime) lastThemeMtime = themeObj.theme_mtime;
  const c = themeObj.colors;
  const root = document.documentElement;
  if (c.background) root.style.setProperty("--bg", c.background);
  if (c.dark_background) root.style.setProperty("--bg-dark", c.dark_background);
  if (c.darker_background) root.style.setProperty("--bg-darker", c.darker_background);
  if (c.lighter_background) root.style.setProperty("--surface", c.lighter_background);
  if (c.foreground) root.style.setProperty("--fg", c.foreground);
  if (c.dark_foreground) root.style.setProperty("--fg-muted", c.dark_foreground);
  if (c.bright_foreground) root.style.setProperty("--fg-bright", c.bright_foreground);
  if (c.accent) root.style.setProperty("--accent", c.accent);
  if (c.selection) root.style.setProperty("--selection", c.selection);
  if (c.red) root.style.setProperty("--red", c.red);
  if (c.yellow) root.style.setProperty("--yellow", c.yellow);
  if (c.green) root.style.setProperty("--green", c.green);
  if (c.cyan) root.style.setProperty("--cyan", c.cyan);
  if (c.blue) root.style.setProperty("--blue", c.blue);
  if (themeObj.font_family) {
    root.style.setProperty("--font-main", `"${themeObj.font_family}", monospace`);
  }
  const themeLbl = document.getElementById("sidebar-theme-label");
  if (themeLbl && themeObj.theme_name) {
    themeLbl.textContent = `Theme: ${themeObj.theme_name}`;
  }
}

function switchTab(tabId) {
  activeTab = tabId;
  document.querySelectorAll(".nav-item").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.tab === tabId);
  });
  document.querySelectorAll(".tab-panel").forEach((panel) => {
    panel.classList.toggle("active", panel.id === `tab-${tabId}`);
  });
  syncLivePolling();
}

function syncLivePolling() {
  if (liveTimer) {
    clearInterval(liveTimer);
    liveTimer = null;
  }
  if (activeTab === "live" && !livePaused) {
    fetchLiveMetrics();
    liveTimer = setInterval(fetchLiveMetrics, 1500);
  }
}

async function fetchLiveMetrics() {
  if (activeTab !== "live" || livePaused) return;
  try {
    const res = await fetch(`/api/live?sort=${encodeURIComponent(liveSortBy)}`);
    const data = await res.json();
    renderLiveMetrics(data);
  } catch (_) {}
}

function barColorForPct(pct) {
  if (pct >= 85) return "var(--red)";
  if (pct >= 65) return "var(--yellow)";
  return "var(--green)";
}

function renderFastfetch(ff, r) {
  if (!ff) return;
  const uh = document.getElementById("ff-user-host");
  if (uh) uh.textContent = ff.user_host || "";

  const rows = [
    ["󰌢 Host", `${ff.host_model}${ff.bios ? ` (BIOS ${ff.bios})` : ""}`],
    ["󰣇 OS", ff.os],
    ["󰒋 Kernel", ff.kernel],
    ["󰅐 Uptime", r?.overview?.uptime_human || "--"],
    ["󰏖 Packages", ff.packages],
    [" WM", ff.wm],
    ["󰍹 Display", ff.display],
    ["󰸌 Theme", `${ff.theme} (${ff.font})`],
    [" Shell / Term", `${ff.shell} / ${ff.terminal}`],
    ["󰻠 CPU", ff.cpu],
    ["󰢮 GPU", ff.gpu],
    ["󰋊 Root FS", r ? `${r.storage.disk.used_human} / ${r.storage.disk.total_human} (${r.storage.disk.percent}%) Btrfs` : "--"],
  ];

  const grid = document.getElementById("fastfetch-grid");
  if (grid) {
    grid.innerHTML = rows
      .map(
        ([k, v]) => `
        <div class="ff-key">${esc(k)}</div>
        <div class="ff-val" title="${esc(v)}">${esc(v)}</div>`
      )
      .join("");
  }
}

function renderLiveMetrics(m) {
  if (!m) return;

  // CPU
  const cpu = m.cpu;
  const cpuTempEl = document.getElementById("live-cpu-temp");
  cpuTempEl.textContent = cpu.package_temp_c != null ? `${cpu.package_temp_c}°C` : "N/A";
  cpuTempEl.className = `pill ${cpu.package_temp_c >= 85 ? "pill-danger" : cpu.package_temp_c >= 72 ? "pill-warn" : "pill-ok"}`;

  document.getElementById("live-cpu-total").textContent =
    `${cpu.total_percent}% (Load ${cpu.load_avg.join(" / ")})`;
  const cpuBar = document.getElementById("live-cpu-bar");
  cpuBar.style.width = `${Math.min(100, cpu.total_percent)}%`;
  cpuBar.style.backgroundColor = barColorForPct(cpu.total_percent);

  document.getElementById("live-cores-list").innerHTML = (cpu.cores || [])
    .map(
      (c) => `
      <div class="core-row">
        <span><strong>Core ${c.core}</strong></span>
        <div class="progress-track">
          <div class="progress-fill" style="width:${Math.min(100, c.percent)}%;background-color:${barColorForPct(c.percent)}"></div>
        </div>
        <span class="core-meta">${c.percent.toFixed(1)}% • ${c.mhz}MHz${c.temp_c ? ` • ${Math.round(c.temp_c)}°C` : ""}</span>
      </div>`
    )
    .join("");

  // GPU
  const gpu = m.gpu;
  document.getElementById("live-gpu-name").textContent = gpu.name || "Integrated Graphics";
  document.getElementById("live-gpu-clock").textContent = `${gpu.act_mhz} / ${gpu.max_mhz} MHz`;
  document.getElementById("live-gpu-pct").textContent = `${gpu.percent}%`;
  const gpuBar = document.getElementById("live-gpu-bar");
  gpuBar.style.width = `${Math.min(100, gpu.percent)}%`;
  gpuBar.style.backgroundColor = barColorForPct(gpu.percent);

  document.getElementById("live-gpu-details").innerHTML = `
    <div class="kv-mini-row"><span class="text-muted">Active Clock</span><span>${gpu.act_mhz} MHz</span></div>
    <div class="kv-mini-row"><span class="text-muted">Requested Clock</span><span>${gpu.cur_mhz} MHz</span></div>
    <div class="kv-mini-row"><span class="text-muted">Max Boost Clock</span><span>${gpu.max_mhz} MHz</span></div>
  `;

  // Network rates
  document.getElementById("live-net-rates").innerHTML = (m.network || [])
    .map(
      (n) => `
      <div class="kv-mini-row">
        <span><strong>${esc(n.iface)}</strong></span>
        <span>↓ ${esc(n.rx_human)} &nbsp; ↑ ${esc(n.tx_human)}</span>
      </div>`
    )
    .join("");

  // Memory
  const mem = m.memory;
  document.getElementById("live-mem-pct").textContent = `${mem.percent}%`;
  document.getElementById("live-mem-used").textContent = `${mem.used_human} / ${mem.total_human}`;
  const memBar = document.getElementById("live-mem-bar");
  memBar.style.width = `${Math.min(100, mem.percent)}%`;
  memBar.style.backgroundColor = barColorForPct(mem.percent);

  document.getElementById("live-swap-used").textContent =
    `${mem.swap_used_human} / ${mem.swap_total_human} (${mem.swap_percent}%)`;
  document.getElementById("live-swap-bar").style.width = `${Math.min(100, mem.swap_percent)}%`;

  document.getElementById("live-mem-breakdown").innerHTML = `
    <div class="kv-mini-row"><span class="text-muted">Available</span><span>${esc(mem.available_human)}</span></div>
    <div class="kv-mini-row"><span class="text-muted">Page Cache / Slab</span><span>${esc(mem.cached_human)}</span></div>
    <div class="kv-mini-row"><span class="text-muted">Buffers</span><span>${esc(mem.buffers_human)}</span></div>
  `;

  // Processes
  document.getElementById("live-procs-body").innerHTML = (m.processes || [])
    .map(
      (p) => `
      <tr>
        <td>${p.pid}</td>
        <td><strong>${esc(p.name)}</strong></td>
        <td class="text-muted">${esc(p.user)}</td>
        <td><span class="pill">${esc(p.state)}</span></td>
        <td>${p.threads}</td>
        <td>
          <div class="inline-bar-cell">
            <div class="inline-bar-track">
              <div class="inline-bar-fill" style="width:${Math.min(100, p.cpu_pct)}%"></div>
            </div>
            <span>${p.cpu_pct.toFixed(1)}%</span>
          </div>
        </td>
        <td>${p.mem_pct.toFixed(1)}%</td>
        <td>${esc(p.rss_human)}</td>
      </tr>`
    )
    .join("");
}

function esc(str) {
  const div = document.createElement("div");
  div.textContent = str == null ? "" : String(str);
  return div.innerHTML;
}

async function postAction(action, payload = {}) {
  try {
    const res = await fetch("/api/action", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action, ...payload }),
    });
    const data = await res.json();
    if (data.message) showToast(data.message);
    if (data.report) renderReport(data.report);
  } catch (err) {
    showToast(`Action error: ${err}`);
  }
}

function renderReport(r) {
  if (!r) return;
  currentReport = r;

  // Sidebar helper status
  const helperBox = document.getElementById("helper-status-box");
  if (r.helper_active) {
    helperBox.innerHTML = `<span style="color:var(--green)">●</span> Deep Socket &amp; Cache Helper Active`;
  } else {
    helperBox.innerHTML = `
      <div style="margin-bottom:6px;color:var(--yellow)">● Unprivileged Mode (PIDs hidden for root sockets)</div>
      <button class="btn btn-outline btn-sm btn-block" onclick="postAction('install-sudoers')">Authorize Root Helper</button>
    `;
  }

  document.getElementById("last-scan-time").textContent = `Last scan: ${r.timestamp.replace("T", " ").slice(0, 19)} (${r.duration_ms}ms)`;

  // Score Ring
  const score = r.health_score;
  document.getElementById("health-score-val").textContent = score;
  const ringFg = document.getElementById("score-ring-fg");
  const circumference = 314.16;
  ringFg.style.strokeDashoffset = circumference - (score / 100) * circumference;
  ringFg.style.stroke = score >= 90 ? "var(--green)" : score >= 75 ? "var(--yellow)" : "var(--red)";

  document.getElementById("health-status-title").textContent = r.status_label;

  const ov = r.overview;
  document.getElementById("reboot-pill").classList.toggle("hidden", !ov.reboot_required);
  document.getElementById("system-meta-line").textContent =
    `${ov.hostname} • Omarchy ${ov.omarchy_version} • Kernel ${ov.kernel} • Uptime ${ov.uptime_human}`;

  const findingsEl = document.getElementById("findings-list");
  findingsEl.innerHTML = (r.findings || []).map((f) => `<li>${esc(f)}</li>`).join("");

  // Overview Metric Cards & Sidebar Badges
  const up = r.updates;
  const net = r.network;
  const dm = r.daemons;
  const st = r.storage;

  // Badges
  const bUp = document.getElementById("badge-updates");
  bUp.textContent = up.deferred.active ? "Deferred" : up.total_count > 0 ? up.total_count : "";
  bUp.className = `nav-badge ${!up.deferred.active && up.omarchy_update_available ? "warn" : ""}`;

  const netAlerts = net.unapproved_listeners_count + net.suspicious_connections_count;
  const bNet = document.getElementById("badge-network");
  bNet.textContent = netAlerts > 0 ? netAlerts : "";
  bNet.className = `nav-badge ${netAlerts > 0 ? "warn" : ""}`;

  const dmAlerts = dm.unmuted_failed_count + dm.high_severity_anomalies_count + dm.new_enabled_services.length;
  const bDm = document.getElementById("badge-daemons");
  bDm.textContent = dmAlerts > 0 ? dmAlerts : "";
  bDm.className = `nav-badge ${dmAlerts > 0 ? "warn" : ""}`;

  // Overview cards
  document.getElementById("ov-updates-val").textContent =
    up.deferred.active ? `${up.total_count} (Deferred)` : `${up.total_count} Packages`;
  document.getElementById("ov-updates-sub").textContent =
    up.omarchy_update_available
      ? "Omarchy release update ready!"
      : `${up.repo_count} repo, ${up.aur_count} AUR`;

  document.getElementById("ov-net-val").textContent =
    netAlerts === 0 ? "All Trusted" : `${netAlerts} Flagged`;
  document.getElementById("ov-net-sub").textContent =
    net.tailscale.active
      ? `Tailscale UP (${net.tailscale.ip})`
      : `${net.listeners.length} listening ports`;

  document.getElementById("ov-daemons-val").textContent =
    dm.unmuted_failed_count === 0 ? "All Healthy" : `${dm.unmuted_failed_count} Failed Unit(s)`;
  document.getElementById("ov-daemons-sub").textContent =
    `${dm.enabled_services_count} enabled services • ${dm.recent_crashes.length} crashes (7d)`;

  document.getElementById("ov-storage-val").textContent = `${st.disk.percent}% Used`;
  document.getElementById("ov-storage-sub").textContent =
    `${st.disk.free_human} free • ${st.cleanup.reclaimable_total_human} cache`;

  // Overview Resource Bars
  document.getElementById("ov-load-badge").textContent =
    `${ov.load_avg.join(" / ")} (${ov.cpu_count} cores)`;
  document.getElementById("ov-mem-text").textContent =
    `${ov.memory.used_human} / ${ov.memory.total_human} (${ov.memory.percent}%)`;
  document.getElementById("ov-mem-bar").style.width = `${Math.min(100, ov.memory.percent)}%`;

  document.getElementById("ov-disk-text").textContent =
    `${st.disk.used_human} / ${st.disk.total_human} (${st.disk.percent}%)`;
  document.getElementById("ov-disk-bar").style.width = `${Math.min(100, st.disk.percent)}%`;

  // TAB 2: UPDATES
  const deferBanner = document.getElementById("defer-banner");
  const btnUndefer = document.getElementById("btn-undefer");
  if (up.deferred.active) {
    deferBanner.classList.remove("hidden");
    deferBanner.innerHTML = `<strong>Updates Deferred:</strong> Alerts and top-bar badge are muted for ${esc(up.deferred.remaining_human)} (since ${esc(up.deferred.deferred_at.slice(0, 16))}).`;
    btnUndefer.classList.remove("hidden");
  } else {
    deferBanner.classList.add("hidden");
    btnUndefer.classList.add("hidden");
  }

  const omBox = document.getElementById("omarchy-release-box");
  if (up.omarchy_update_available) {
    omBox.classList.remove("hidden");
    omBox.innerHTML = `<strong>Omarchy System Update Available:</strong> ${esc(up.omarchy_update_lines.join(", "))}`;
  } else {
    omBox.classList.add("hidden");
  }

  document.getElementById("up-total-count").textContent = up.total_count;
  document.getElementById("up-repo-pill").textContent = `${up.repo_count} Repo`;
  document.getElementById("up-aur-pill").textContent = `${up.aur_count} AUR`;
  document.getElementById("up-crit-pill").textContent = `${up.critical_count} Core`;

  const upBody = document.getElementById("up-table-body");
  if (up.packages.length === 0) {
    upBody.innerHTML = `<tr><td colspan="5" class="text-muted">System is completely up to date.</td></tr>`;
  } else {
    upBody.innerHTML = up.packages
      .map(
        (p) => `
        <tr>
          <td><strong>${esc(p.name)}</strong></td>
          <td><span class="pill">${esc(p.source.toUpperCase())}</span></td>
          <td class="text-muted">${esc(p.old_version)}</td>
          <td style="color:var(--green)">${esc(p.new_version)}</td>
          <td>${p.critical ? '<span class="pill pill-warn">Core / System</span>' : '<span class="text-muted">Standard</span>'}</td>
        </tr>`
      )
      .join("");
  }

  // TAB 3: NETWORK & LISTENERS
  const tsPill = document.getElementById("net-ts-pill");
  tsPill.textContent = net.tailscale.active ? "Connected" : "Offline";
  tsPill.className = `pill ${net.tailscale.active ? "pill-ok" : "pill-warn"}`;
  document.getElementById("net-ts-ip").textContent = net.tailscale.ip || "Not Connected";
  document.getElementById("net-ts-peers").textContent = `${net.tailscale.online_peers} online peer(s) on tailscale0`;

  const lPill = document.getElementById("net-listen-pill");
  lPill.textContent = net.unapproved_listeners_count === 0 ? "Baseline OK" : `${net.unapproved_listeners_count} Unapproved`;
  lPill.className = `pill ${net.unapproved_listeners_count === 0 ? "pill-ok" : "pill-warn"}`;
  document.getElementById("net-listen-val").textContent = `${net.listeners.length} Active Listeners`;
  document.getElementById("net-listen-sub").textContent =
    `${net.unapproved_listeners_count} non-loopback/non-Tailscale ports unapproved`;

  const cPill = document.getElementById("net-conn-pill");
  cPill.textContent = net.suspicious_connections_count === 0 ? "Clean" : `${net.suspicious_connections_count} Flagged`;
  cPill.className = `pill ${net.suspicious_connections_count === 0 ? "pill-ok" : "pill-danger"}`;
  document.getElementById("net-conn-val").textContent = `${net.connections.length} Established`;
  document.getElementById("net-fw-sub").textContent = net.firewall.status;

  document.getElementById("net-listeners-body").innerHTML = net.listeners
    .map((l) => {
      let badge = `<span class="pill pill-ok">Trusted (${esc(l.scope)})</span>`;
      if (l.scope === "Tailscale") {
        badge = `<span class="pill pill-ts">Tailscale Trusted</span>`;
      } else if (l.flagged) {
        badge = `<span class="pill pill-warn">Unapproved Listener</span>`;
      } else if (l.approved) {
        badge = `<span class="pill pill-ok">Baseline Approved</span>`;
      }

      let actionBtn = `<span class="text-muted">Auto-Trusted</span>`;
      if (!l.auto_trusted) {
        if (l.approved) {
          actionBtn = `<button class="btn btn-secondary btn-sm" onclick="postAction('unapprove-listener', {signature: '${esc(l.signature)}'})">Remove Approval</button>`;
        } else {
          actionBtn = `<button class="btn btn-outline btn-sm" onclick="postAction('approve-listener', {signature: '${esc(l.signature)}'})">Approve Baseline</button>`;
        }
      }

      return `
        <tr>
          <td>${esc(l.proto.toUpperCase())}</td>
          <td>${esc(l.local_ip)}${l.interface ? "%" + esc(l.interface) : ""}</td>
          <td><strong>:${esc(l.port)}</strong></td>
          <td>${esc(l.process)}${l.pid ? ` (${l.pid})` : ""}</td>
          <td>${esc(l.scope)}</td>
          <td>${badge}</td>
          <td>${actionBtn}</td>
        </tr>`;
    })
    .join("");

  const connsBody = document.getElementById("net-conns-body");
  if (net.connections.length === 0) {
    connsBody.innerHTML = `<tr><td colspan="6" class="text-muted">No active established connections.</td></tr>`;
  } else {
    connsBody.innerHTML = net.connections
      .map((c) => {
        let badge = `<span class="pill pill-ok">${esc(c.reason)}</span>`;
        if (c.tailscale) badge = `<span class="pill pill-ts">Tailscale Mesh</span>`;
        else if (c.flagged) badge = `<span class="pill pill-danger">${esc(c.reason)}</span>`;
        return `
          <tr>
            <td>${esc(c.proto.toUpperCase())}</td>
            <td><strong>${esc(c.process)}</strong>${c.pid ? ` (${c.pid})` : ""}</td>
            <td class="text-muted">${esc(c.local)}</td>
            <td>${esc(c.remote_ip)}:${esc(c.remote_port)}</td>
            <td>${esc(c.scope)}</td>
            <td>${badge}</td>
          </tr>`;
      })
      .join("");
  }

  // TAB 4: DAEMONS & SECURITY
  const failedBody = document.getElementById("dm-failed-body");
  if (dm.failed_units.length === 0) {
    failedBody.innerHTML = `<tr><td colspan="5" class="text-muted">0 failed systemd units across system and user scopes.</td></tr>`;
  } else {
    failedBody.innerHTML = dm.failed_units
      .map((u) => {
        const badge = u.muted
          ? `<span class="pill">Muted (Known)</span>`
          : `<span class="pill pill-danger">Failed</span>`;
        const btn = u.muted
          ? `<button class="btn btn-secondary btn-sm" onclick="postAction('unmute-unit', {unit: '${esc(u.unit)}'})">Unmute</button>`
          : `<button class="btn btn-outline btn-sm" onclick="postAction('mute-unit', {unit: '${esc(u.unit)}'})">Mute Known Unit</button>`;
        return `
          <tr>
            <td><span class="pill">${esc(u.scope)}</span></td>
            <td><strong>${esc(u.unit)}</strong></td>
            <td class="text-muted">${esc(u.description)}</td>
            <td>${badge}</td>
            <td>${btn}</td>
          </tr>`;
      })
      .join("");
  }

  const anomBody = document.getElementById("dm-anomalies-body");
  if (dm.process_anomalies.length === 0) {
    anomBody.innerHTML = `<tr><td colspan="4" class="text-muted">No processes running from temporary or deleted binaries.</td></tr>`;
  } else {
    anomBody.innerHTML = dm.process_anomalies
      .map(
        (a) => `
        <tr>
          <td>${a.pid}</td>
          <td><strong>${esc(a.name)}</strong></td>
          <td class="text-muted">${esc(a.exe)}</td>
          <td><span class="pill ${a.severity === "high" ? "pill-danger" : "pill-warn"}">${esc(a.reason)}</span></td>
        </tr>`
      )
      .join("");
  }

  document.getElementById("dm-services-summary").textContent =
    `${dm.enabled_services_count} enabled systemd services • ${dm.auth_failures_7d} auth failure warnings (7d)`;

  const newSvcBox = document.getElementById("dm-new-services-box");
  const btnApproveSvc = document.getElementById("btn-approve-services");
  if (dm.new_enabled_services.length > 0) {
    newSvcBox.classList.remove("hidden");
    btnApproveSvc.classList.remove("hidden");
    newSvcBox.innerHTML = `<strong>Newly Enabled Services Since Baseline:</strong><br/>${dm.new_enabled_services.map(esc).join(", ")}`;
  } else {
    newSvcBox.classList.add("hidden");
    btnApproveSvc.classList.add("hidden");
  }

  const crashBody = document.getElementById("dm-crashes-body");
  if (dm.recent_crashes.length === 0) {
    crashBody.innerHTML = `<tr><td colspan="4" class="text-muted">No core dumps recorded in the past 7 days.</td></tr>`;
  } else {
    crashBody.innerHTML = dm.recent_crashes
      .map(
        (c) => `
        <tr>
          <td class="text-muted">${esc(c.time)}</td>
          <td>${esc(c.pid)}</td>
          <td><span class="pill pill-warn">${esc(c.signal)}</span></td>
          <td><strong>${esc(c.exe)}</strong></td>
        </tr>`
      )
      .join("");
  }

  // TAB 5: STORAGE & CACHE
  document.getElementById("st-reclaim-pill").textContent =
    `${st.cleanup.reclaimable_total_human} Reclaimable`;
  document.getElementById("st-paccache-sub").textContent =
    `Total: ${st.cleanup.paccache_total_human} (${st.cleanup.paccache_reclaim_human} older than 2 versions)`;
  document.getElementById("st-yay-sub").textContent =
    `Reclaimable: ${st.cleanup.yay_cache_human}`;
  document.getElementById("st-journal-sub").textContent =
    `Current size: ${st.cleanup.journal_human}`;
  document.getElementById("st-orphans-sub").textContent =
    st.cleanup.orphans_count === 0
      ? "0 orphaned packages"
      : `${st.cleanup.orphans_count} orphans: ${st.cleanup.orphans.slice(0, 6).join(", ")}`;

  const btrfsPill = document.getElementById("st-btrfs-pill");
  btrfsPill.textContent = st.disk.btrfs_status;
  btrfsPill.className = `pill ${st.disk.btrfs_errors === 0 ? "pill-ok" : "pill-danger"}`;

  const maxHomeBytes = Math.max(1, ...st.home_breakdown.map((d) => d.bytes));
  document.getElementById("st-home-bars").innerHTML = st.home_breakdown
    .map((d) => {
      const pct = Math.max(3, Math.round((d.bytes / maxHomeBytes) * 100));
      return `
        <div class="progress-group">
          <div class="progress-label">
            <span><strong>${esc(d.path)}</strong></span>
            <span>${esc(d.human)}</span>
          </div>
          <div class="progress-track"><div class="progress-fill" style="width:${pct}%"></div></div>
        </div>`;
    })
    .join("");
}

async function loadInitialReport() {
  try {
    const res = await fetch("/api/report");
    const data = await res.json();
    if (data.theme) applyTheme(data.theme);
    if (data.report) renderReport(data.report);
    if (data.fastfetch) renderFastfetch(data.fastfetch, data.report);
  } catch (err) {
    showToast(`Failed to load report: ${err}`);
  }
}

async function triggerFullScan() {
  const btn = document.getElementById("btn-run-scan");
  const txt = document.getElementById("scan-btn-text");
  btn.disabled = true;
  txt.textContent = "Auditing System...";
  try {
    const res = await fetch("/api/scan", { method: "POST" });
    const data = await res.json();
    if (data.theme) applyTheme(data.theme);
    if (data.report) renderReport(data.report);
    if (data.fastfetch) renderFastfetch(data.fastfetch, data.report);
    showToast("Full system audit completed.");
  } catch (err) {
    showToast(`Scan failed: ${err}`);
  } finally {
    btn.disabled = false;
    txt.textContent = "Run Full Audit";
  }
}

// Event Listeners
document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".nav-item").forEach((btn) => {
    btn.addEventListener("click", () => switchTab(btn.dataset.tab));
  });

  document.querySelectorAll("[data-goto]").forEach((card) => {
    card.addEventListener("click", () => switchTab(card.dataset.goto));
  });

  const btnPause = document.getElementById("btn-live-pause");
  btnPause.addEventListener("click", () => {
    livePaused = !livePaused;
    btnPause.textContent = livePaused ? "Resume" : "Pause";
    document.getElementById("live-proc-meta").textContent = livePaused
      ? "Paused"
      : "Refreshing every 1.5s";
    syncLivePolling();
  });

  const btnSortCpu = document.getElementById("btn-sort-cpu");
  const btnSortMem = document.getElementById("btn-sort-mem");
  btnSortCpu.addEventListener("click", () => {
    liveSortBy = "cpu";
    btnSortCpu.className = "btn btn-primary btn-sm";
    btnSortMem.className = "btn btn-secondary btn-sm";
    fetchLiveMetrics();
  });
  btnSortMem.addEventListener("click", () => {
    liveSortBy = "mem";
    btnSortMem.className = "btn btn-primary btn-sm";
    btnSortCpu.className = "btn btn-secondary btn-sm";
    fetchLiveMetrics();
  });

  document.getElementById("btn-run-scan").addEventListener("click", triggerFullScan);

  document.getElementById("btn-install-updates").addEventListener("click", () => {
    postAction("install-updates");
  });

  document.getElementById("btn-defer-24h").addEventListener("click", () => {
    const omTarget = currentReport?.updates?.omarchy_target || "";
    const count = currentReport?.updates?.total_count || 0;
    postAction("defer-updates", { duration: "24h", omarchy_target: omTarget, package_count: count });
  });

  document.getElementById("btn-defer-7d").addEventListener("click", () => {
    const omTarget = currentReport?.updates?.omarchy_target || "";
    const count = currentReport?.updates?.total_count || 0;
    postAction("defer-updates", { duration: "7d", omarchy_target: omTarget, package_count: count });
  });

  document.getElementById("btn-undefer").addEventListener("click", () => {
    postAction("undefer-updates");
  });

  document.getElementById("btn-approve-services").addEventListener("click", () => {
    postAction("approve-services-baseline");
  });

  document.querySelectorAll("[data-action]").forEach((btn) => {
    btn.addEventListener("click", () => postAction(btn.dataset.action));
  });

  loadInitialReport();

  // Heartbeat every 5 seconds; also hot-reloads theme if colors.toml mtime changed
  setInterval(async () => {
    try {
      const res = await fetch("/api/heartbeat", { method: "POST", keepalive: true });
      const data = await res.json();
      if (data.theme_mtime && lastThemeMtime && data.theme_mtime !== lastThemeMtime) {
        const tRes = await fetch("/api/theme");
        const tData = await tRes.json();
        applyTheme(tData);
      }
    } catch (_) {}
  }, 5000);

  // Notify server when window closes
  window.addEventListener("pagehide", () => {
    if (navigator.sendBeacon) {
      navigator.sendBeacon("/api/shutdown", "{}");
    }
  });
});
