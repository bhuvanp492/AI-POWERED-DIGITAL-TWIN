/**
 * Digital Twin View Controller for AI-DT-CyberShield.
 * Manages the 2D visual application & threat topology,
 * dynamic node status telemetry, and protected asset integrity.
 */

const DigitalTwin = {
  async init() {
    await this.load();
  },

  async load() {
    try {
      const res = await App.apiFetch("/api/digital-twin");
      if (!res.ok) throw new Error("Failed to fetch Digital Twin state");
      const twin = await res.json();
      this.renderState(twin);
    } catch (err) {
      console.error("[DigitalTwin] Error loading state:", err);
    }
  },

  renderState(twin) {
    const isAttention = twin.security_state.includes("ATTENTION") || twin.current_risk === "Critical" || twin.current_risk === "High";

    // Top status banner
    const badge = document.getElementById("twin-status-badge");
    const text = document.getElementById("twin-status-text");
    const condTitle = document.getElementById("twin-condition-title");
    const recentAnomaly = document.getElementById("twin-recent-anomaly");
    const riskScore = document.getElementById("twin-risk-score");

    if (badge && text) {
      text.textContent = isAttention ? "● ATTENTION REQUIRED" : "● SECURE";
      badge.className = isAttention ? "status-badge-lg attention" : "status-badge-lg secure";
    }

    if (condTitle) {
      condTitle.textContent = `Application State: ${twin.application_status} • User Session: ${twin.nodes?.find(n => n.id === 'users_pool')?.status || 'ACTIVE'} • Security State: ${twin.security_state}`;
    }
    if (recentAnomaly) {
      recentAnomaly.textContent = `Recent Anomaly: ${twin.recent_anomaly}`;
    }
    if (riskScore) {
      riskScore.textContent = `${twin.risk_numeric} / 100 (${twin.current_risk})`;
      riskScore.style.color = twin.risk_numeric > 60 ? "var(--danger)" : (twin.risk_numeric > 30 ? "var(--warning)" : "var(--success)");
    }

    // Render Nodes Telemetry
    if (twin.nodes && twin.nodes.length > 0) {
      twin.nodes.forEach(node => {
        const el = document.getElementById(`twin-node-${node.id}`);
        const statusBadge = document.getElementById(`node-status-${node.id}`);
        const meta = document.getElementById(`node-meta-${node.id}`);

        if (el) {
          const statusClass = (node.status || "healthy").toLowerCase();
          el.className = `twin-node ${statusClass}`;
        }

        if (statusBadge) {
          statusBadge.textContent = node.status;
          let badgeRisk = "low";
          if (node.status === "WARNING" || node.status === "ELEVATED" || node.status === "TARGETED" || node.status === "MONITORING") badgeRisk = "medium";
          if (node.status === "CRITICAL" || node.status === "SUSPICIOUS" || node.status === "UNDER_ATTACK" || node.status === "HIGH RISK") badgeRisk = "critical";
          statusBadge.className = `node-status-badge badge-risk ${badgeRisk}`;
        }

        if (meta && node.details) {
          if (node.id === "app_gateway") {
            meta.innerHTML = `Active Conn: ${node.details.active_connections}<br>Throughput: ${node.details.throughput}<br>Egress: ${node.details.egress_rate}`;
          } else if (node.id === "users_pool") {
            meta.innerHTML = `User: ${node.details.latest_user}<br>IP: ${node.details.ip}<br>Auth: ${node.details.auth_condition}`;
          } else if (node.id === "protected_dbs") {
            meta.innerHTML = `Target: ${node.details.active_resource}<br>Records: ${node.details.records_accessed}<br>Level: ${node.details.sensitivity_level}`;
          } else if (node.id === "ai_engine") {
            meta.innerHTML = `Engine: ${node.details.inference_engine}<br>Score: ${node.details.anomaly_score}<br>Eval: ${node.details.eval_latency_ms} ms`;
          } else if (node.id === "security_state") {
            meta.innerHTML = `State: ${node.details.condition}<br>Risk: ${node.details.risk_score}<br>${node.details.posture}`;
          }
        }
      });
    }

    // Render Protected Resources List
    const resGrid = document.getElementById("twin-resources-grid");
    if (resGrid && twin.protected_resources) {
      resGrid.innerHTML = twin.protected_resources.map(res => {
        let statusColor = "var(--success)";
        let statusBg = "var(--success-bg)";
        if (res.status === "ELEVATED" || res.status === "INVESTIGATING") {
          statusColor = "var(--warning)";
          statusBg = "var(--warning-bg)";
        } else if (res.status === "CRITICAL_ALERT" || res.status === "UNDER_ATTACK") {
          statusColor = "var(--danger)";
          statusBg = "var(--danger-bg)";
        }

        return `
          <div class="res-card">
            <div>
              <div class="res-name">${res.name}</div>
              <div class="res-tier">Sensitivity Tier ${res.sensitivity}/5 • ${res.queries_min} queries/min</div>
            </div>
            <span style="font-size: 11px; font-weight: 700; color: ${statusColor}; background-color: ${statusBg}; padding: 3px 8px; border-radius: 4px;">
              ${res.status}
            </span>
          </div>
        `;
      }).join("");
    }
  }
};

window.DigitalTwin = DigitalTwin;
