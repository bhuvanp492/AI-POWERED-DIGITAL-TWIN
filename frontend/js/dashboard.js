/**
 * Dashboard Controller for AI-DT-CyberShield (Modules 5.1, 5.2, 5.3).
 * Manages cybersecurity KPI cards, live system status banner,
 * the recent security events table (with ACTUAL vs SIMULATION sources),
 * and the latest AI decision preview.
 */

const Dashboard = {
  init() {
    const refreshBtn = document.getElementById("btn-refresh-dashboard");
    if (refreshBtn) {
      refreshBtn.addEventListener("click", () => {
        this.load();
        App.showToast("Dashboard refreshed", "info");
      });
    }
  },

  async load() {
    await Promise.all([
      this.fetchStats(),
      this.fetchRecentEvents()
    ]);
  },

  async fetchStats() {
    try {
      const res = await App.apiFetch("/api/stats");
      if (!res.ok) throw new Error("Network error fetching stats");
      const stats = await res.json();

      // Update Topbar status pill
      const topPill = document.getElementById("topbar-status-pill");
      const topText = document.getElementById("topbar-status-text");
      const isAttention = stats.current_security_status.includes("ATTENTION");

      if (topPill && topText) {
        topText.textContent = stats.current_security_status;
        topPill.className = isAttention ? "status-pill attention" : "status-pill secure";
      }

      // Update Dashboard Status Banner
      const bannerBadge = document.getElementById("dashboard-status-badge");
      const bannerTitle = document.getElementById("dashboard-status-title");
      const bannerHeadline = document.getElementById("dashboard-status-headline");
      const bannerDesc = document.getElementById("dashboard-status-desc");

      if (bannerBadge && bannerTitle) {
        bannerTitle.textContent = stats.current_security_status;
        bannerBadge.className = isAttention ? "status-badge-lg attention" : "status-badge-lg secure";
      }

      if (bannerHeadline && bannerDesc) {
        if (isAttention) {
          bannerHeadline.textContent = "ATTENTION REQUIRED — Anomalous Activity Detected";
          bannerDesc.textContent = "Isolation Forest AI detected abnormal user behavior. Immediate analyst review or containment recommended.";
        } else {
          bannerHeadline.textContent = "All Monitored Cloud Systems Operational";
          bannerDesc.textContent = "Zero critical anomalies detected across active sessions. Isolation Forest model running nominal telemetry.";
        }
      }

      // Update KPI Metric Cards
      document.getElementById("kpi-total").textContent = stats.total_events || 0;
      document.getElementById("kpi-normal").textContent = stats.normal_events || 0;
      document.getElementById("kpi-suspicious").textContent = stats.suspicious_events || 0;
      document.getElementById("kpi-high-risk").textContent = stats.high_risk_events || 0;
      document.getElementById("kpi-risk-level").textContent = stats.current_risk_level || "Low";
      document.getElementById("kpi-avg-risk").textContent = `Avg score: ${stats.average_risk_score} / 100`;

    } catch (err) {
      console.error("[Dashboard] Error loading stats:", err);
    }
  },

  async fetchRecentEvents() {
    const tbody = document.getElementById("dashboard-events-tbody");
    if (!tbody) return;

    try {
      const res = await App.apiFetch("/api/events?limit=8");
      if (!res.ok) throw new Error("Failed to fetch recent events");
      const events = await res.json();

      if (events.length === 0) {
        tbody.innerHTML = `<tr><td colspan="9" style="text-align: center; padding: 20px; color: var(--text-muted);">No security events recorded yet.</td></tr>`;
        return;
      }

      // Update Latest AI Decision Card with the most recent event
      const latest = events[0];
      const isLatestAnomaly = latest.prediction !== "NORMAL";

      const scenarioEl = document.getElementById("dash-latest-scenario");
      const descEl = document.getElementById("dash-latest-desc");
      const predEl = document.getElementById("dash-latest-pred");
      const riskEl = document.getElementById("dash-latest-risk");

      if (scenarioEl) {
        const srcTag = latest.event_source === "SIMULATION" ? " [SIMULATION]" : " [ACTUAL ACTIVITY]";
        scenarioEl.textContent = (latest.detected_behaviour || latest.action) + srcTag;
      }
      if (descEl) {
        descEl.textContent = `User: ${latest.username} • Resource: ${latest.resource_name} • ${latest.timestamp}`;
      }
      if (predEl) {
        predEl.textContent = latest.prediction;
        predEl.className = `badge ${isLatestAnomaly ? 'suspicious' : 'normal'}`;
      }
      if (riskEl) {
        riskEl.textContent = `${latest.risk_score} / 100 (${latest.risk_level.toUpperCase()})`;
        riskEl.style.color = latest.risk_score > 60 ? "var(--danger)" : (latest.risk_score > 30 ? "var(--warning)" : "var(--success)");
      }

      // Render table rows with source distinction
      tbody.innerHTML = events.map(ev => {
        const isAnomaly = ev.prediction !== "NORMAL";
        const riskClass = (ev.risk_level || "low").toLowerCase();
        const isSim = ev.event_source === "SIMULATION";
        const sourceBadge = isSim
          ? `<span class="badge" style="font-size: 10px; background: rgba(147, 51, 234, 0.15); color: #9333ea; font-weight: 700;">SIMULATION</span>`
          : `<span class="badge normal" style="font-size: 10px; background: rgba(59, 130, 246, 0.15); color: #3b82f6; font-weight: 700;">LIVE ACTIVITY</span>`;

        return `
          <tr data-event-id="${ev.id}">
            <td style="font-family: var(--font-mono); font-size: 11px;">${ev.timestamp}</td>
            <td><strong>${ev.username}</strong></td>
            <td>${sourceBadge}</td>
            <td style="font-family: var(--font-mono); font-size: 11px;">${ev.action}</td>
            <td>${ev.resource_name}</td>
            <td><span class="badge-risk ${riskClass}">${ev.risk_score}/100 (${ev.risk_level})</span></td>
            <td><span class="badge ${isAnomaly ? 'suspicious' : 'normal'}">${ev.prediction}</span></td>
            <td>
              <button class="btn btn-secondary btn-sm" onclick="Dashboard.inspectEvent(${ev.id})">Inspect</button>
            </td>
          </tr>
        `;
      }).join("");

    } catch (err) {
      console.error("[Dashboard] Error loading events:", err);
      tbody.innerHTML = `<tr><td colspan="9" style="text-align: center; color: var(--danger); padding: 20px;">Error loading events: ${err.message}</td></tr>`;
    }
  },

  inspectEvent(eventId) {
    if (window.Analysis) {
      Analysis.loadEvent(eventId);
    }
    App.switchView("analysis");
  }
};

window.Dashboard = Dashboard;
