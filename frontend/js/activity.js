/**
 * Activity Monitor & Telemetry Pipeline Controller for AI-DT-CyberShield (Modules 5.1 & 5.2).
 * Manages:
 * 1. Real-Time Intercepted HTTP Request Telemetry Stream (The 10 Fields Pipeline)
 * 2. Pipeline Operational Statistics (Throughput, Monitored Users, Anomalies)
 * 3. Security Events Audit Trail & Explainable Analysis Drilldown
 */

const Activity = {
  events: [],
  httpLogs: [],
  activeTab: "http_stream",

  init() {
    const searchInput = document.getElementById("activity-search-input");
    const filterSelect = document.getElementById("activity-filter-type");
    const resetBtn = document.getElementById("btn-reset-filters");
    const refreshBtn = document.getElementById("btn-refresh-telemetry-stream");

    const tabHttpBtn = document.getElementById("btn-tab-http-stream");
    const tabEventsBtn = document.getElementById("btn-tab-security-events");

    if (tabHttpBtn) {
      tabHttpBtn.addEventListener("click", () => this.switchTab("http_stream"));
    }
    if (tabEventsBtn) {
      tabEventsBtn.addEventListener("click", () => this.switchTab("security_events"));
    }
    if (refreshBtn) {
      refreshBtn.addEventListener("click", () => this.load());
    }

    if (searchInput) {
      searchInput.addEventListener("input", () => this.renderFilteredTable());
    }
    if (filterSelect) {
      filterSelect.addEventListener("change", () => this.loadEvents());
    }
    if (resetBtn) {
      resetBtn.addEventListener("click", () => {
        if (searchInput) searchInput.value = "";
        if (filterSelect) filterSelect.value = "";
        this.loadEvents();
      });
    }
  },

  switchTab(tab) {
    this.activeTab = tab;
    const secHttp = document.getElementById("section-http-stream");
    const secEvents = document.getElementById("section-security-events");
    const btnHttp = document.getElementById("btn-tab-http-stream");
    const btnEvents = document.getElementById("btn-tab-security-events");

    if (tab === "http_stream") {
      if (secHttp) secHttp.style.display = "block";
      if (secEvents) secEvents.style.display = "none";
      if (btnHttp) {
        btnHttp.className = "btn btn-primary btn-sm";
      }
      if (btnEvents) {
        btnEvents.className = "btn btn-secondary btn-sm";
      }
      this.loadHttpStream();
    } else {
      if (secHttp) secHttp.style.display = "none";
      if (secEvents) secEvents.style.display = "block";
      if (btnHttp) {
        btnHttp.className = "btn btn-secondary btn-sm";
      }
      if (btnEvents) {
        btnEvents.className = "btn btn-primary btn-sm";
      }
      this.loadEvents();
    }
  },

  async load() {
    await Promise.all([
      this.loadHttpStream(),
      this.loadEvents()
    ]);
  },

  async loadHttpStream() {
    const tbody = document.getElementById("http-stream-tbody");
    if (!tbody) return;

    try {
      // 1. Fetch raw intercepted HTTP request telemetry
      const res = await App.apiFetch("/api/resources/telemetry-logs?limit=50");
      if (res.ok) {
        const data = await res.json();
        this.httpLogs = data.logs || [];
        this.renderHttpStreamTable();
      }

      // 2. Fetch pipeline operational stats
      const statsRes = await App.apiFetch("/api/resources/pipeline-stats");
      if (statsRes.ok) {
        const statsData = await statsRes.json();
        const s = statsData.stats || {};
        const totalEl = document.getElementById("pipe-total-reqs");
        const usersEl = document.getElementById("pipe-active-users");
        const anomaliesEl = document.getElementById("pipe-anomalies");
        const scoreEl = document.getElementById("pipe-avg-score");

        if (totalEl) totalEl.textContent = s.total_requests_intercepted ?? 0;
        if (usersEl) usersEl.textContent = s.active_monitored_users ?? 0;
        if (anomaliesEl) anomaliesEl.textContent = s.anomalies_flagged ?? 0;
        if (scoreEl) scoreEl.textContent = Number(s.average_anomaly_score || 0).toFixed(3);
      }
    } catch (err) {
      console.error("[Activity] Error fetching telemetry stream:", err);
      tbody.innerHTML = `<tr><td colspan="10" style="text-align: center; color: var(--danger); padding: 20px;">Error loading telemetry stream: ${err.message}</td></tr>`;
    }
  },

  renderHttpStreamTable() {
    const tbody = document.getElementById("http-stream-tbody");
    if (!tbody) return;

    if (!this.httpLogs || this.httpLogs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="10" style="text-align: center; padding: 24px; color: var(--text-muted);">No intercepted HTTP API requests recorded yet. Click around the application to see live interception!</td></tr>`;
      return;
    }

    tbody.innerHTML = this.httpLogs.map(log => {
      const isAnomaly = log.prediction === "ANOMALY DETECTED" || (log.anomaly_score && log.anomaly_score >= 0.45);
      const scoreColor = isAnomaly ? "var(--danger)" : "var(--success)";
      const statusBadge = log.status_code < 400
        ? `<span class="badge normal" style="font-size: 11px;">${log.status_code} OK</span>`
        : `<span class="badge suspicious" style="font-size: 11px;">${log.status_code} ERR</span>`;

      const methodBadge = `<span style="font-family: var(--font-mono); font-size: 11px; font-weight: 700; padding: 2px 6px; border-radius: 4px; background: rgba(59, 130, 246, 0.15); color: #3b82f6;">${log.http_method}</span>`;

      // Format volume
      let volStr = `${log.response_bytes || 0} B`;
      if (log.response_bytes >= 1024 * 1024) {
        volStr = `${(log.response_bytes / (1024 * 1024)).toFixed(2)} MB`;
      } else if (log.response_bytes >= 1024) {
        volStr = `${(log.response_bytes / 1024).toFixed(1)} KB`;
      }

      // Truncate User-Agent nicely
      const shortUa = (log.user_agent || "Client").length > 32
        ? (log.user_agent.substring(0, 32) + "...")
        : log.user_agent;

      return `
        <tr>
          <td style="font-family: var(--font-mono); font-size: 11px; white-space: nowrap;">${log.timestamp}</td>
          <td><strong style="color: var(--text-primary);">${log.username}</strong></td>
          <td style="font-family: var(--font-mono); font-size: 11px;">
            ${methodBadge} <span style="margin-left: 4px;">${log.endpoint}</span>
          </td>
          <td>${statusBadge}</td>
          <td style="font-family: var(--font-mono); font-size: 11px;">${log.source_ip}</td>
          <td style="font-size: 11px; color: var(--text-secondary);" title="${log.user_agent}">${shortUa}</td>
          <td style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);">${log.session_id}</td>
          <td>
            <div style="font-weight: 600; font-size: 12px;">${log.resource_name}</div>
            <div style="font-size: 10px; color: var(--text-muted);">Tier ${log.resource_sensitivity || 1} Sensitivity</div>
          </td>
          <td style="font-family: var(--font-mono); font-size: 11px;">${volStr}</td>
          <td>
            <div style="display: flex; align-items: center; gap: 6px;">
              <span class="badge ${isAnomaly ? 'suspicious' : 'normal'}" style="font-size: 10px;">
                ${log.prediction || 'NORMAL'}
              </span>
              <span style="font-family: var(--font-mono); font-size: 11px; font-weight: 700; color: ${scoreColor};">
                ${Number(log.anomaly_score || 0.15).toFixed(3)}
              </span>
            </div>
          </td>
        </tr>
      `;
    }).join("");
  },

  async loadEvents() {
    const tbody = document.getElementById("activity-events-tbody");
    if (!tbody) return;

    const filterType = document.getElementById("activity-filter-type")?.value || "";
    let url = "/api/events?limit=100";
    if (filterType) {
      url += `&filter_type=${encodeURIComponent(filterType)}`;
    }

    try {
      const res = await App.apiFetch(url);
      if (!res.ok) throw new Error("Failed to load activity events");
      this.events = await res.json();
      this.renderFilteredTable();
    } catch (err) {
      console.error("[Activity] Error fetching events:", err);
      tbody.innerHTML = `<tr><td colspan="12" style="text-align: center; color: var(--danger); padding: 20px;">Error loading activity events: ${err.message}</td></tr>`;
    }
  },

  renderFilteredTable() {
    const tbody = document.getElementById("activity-events-tbody");
    if (!tbody) return;

    const query = (document.getElementById("activity-search-input")?.value || "").toLowerCase().trim();

    const filtered = this.events.filter(ev => {
      if (!query) return true;
      return (
        ev.username.toLowerCase().includes(query) ||
        ev.ip_address.toLowerCase().includes(query) ||
        ev.device_info.toLowerCase().includes(query) ||
        ev.action.toLowerCase().includes(query) ||
        ev.resource_name.toLowerCase().includes(query) ||
        (ev.event_source || "").toLowerCase().includes(query)
      );
    });

    if (filtered.length === 0) {
      tbody.innerHTML = `<tr><td colspan="12" style="text-align: center; padding: 24px; color: var(--text-muted);">No activity events match the current filter.</td></tr>`;
      return;
    }

    tbody.innerHTML = filtered.map(ev => {
      const isSuspicious = ev.prediction !== "NORMAL";
      const riskClass = (ev.risk_level || "low").toLowerCase();
      const isSim = ev.event_source === "SIMULATION";
      const sourceBadge = isSim
        ? `<span class="badge" style="font-size: 10px; background: rgba(147, 51, 234, 0.15); color: #9333ea; font-weight: 700;">SIMULATION</span>`
        : `<span class="badge normal" style="font-size: 10px; background: rgba(59, 130, 246, 0.15); color: #3b82f6; font-weight: 700;">LIVE ACTIVITY</span>`;

      return `
        <tr onclick="Activity.inspectEvent(${ev.id})">
          <td style="font-family: var(--font-mono); font-size: 11px;">#${ev.id}</td>
          <td style="font-family: var(--font-mono); font-size: 11px;">${ev.timestamp}</td>
          <td><strong>${ev.username}</strong></td>
          <td>${sourceBadge}</td>
          <td style="font-family: var(--font-mono); font-size: 11px;">${ev.ip_address}</td>
          <td style="font-family: var(--font-mono);">${ev.requests_per_minute.toFixed(0)}</td>
          <td>${ev.resource_name}</td>
          <td style="font-family: var(--font-mono);">${ev.records_accessed}</td>
          <td style="font-family: var(--font-mono);">${ev.data_download_mb.toFixed(1)} MB</td>
          <td><span class="badge ${isSuspicious ? 'suspicious' : 'normal'}">${ev.prediction}</span></td>
          <td><span class="badge-risk ${riskClass}">${ev.risk_score} (${ev.risk_level})</span></td>
          <td>
            <button class="btn btn-secondary btn-sm" onclick="event.stopPropagation(); Activity.inspectEvent(${ev.id})">Analyze</button>
          </td>
        </tr>
      `;
    }).join("");
  },

  inspectEvent(eventId) {
    if (window.Analysis) {
      Analysis.loadEvent(eventId);
    }
    App.switchView("analysis");
  }
};

window.Activity = Activity;
