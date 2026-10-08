/**
 * Simulation Suite Controller for AI-DT-CyberShield.
 * Drives real-time security demonstrations, displaying input feature tables,
 * true Isolation Forest anomaly classifications, and calibrated risk assessments.
 */

const Simulation = {
  init() {
    const buttons = document.querySelectorAll(".sim-btn");
    buttons.forEach(btn => {
      btn.addEventListener("click", () => {
        const scenarioId = btn.getAttribute("data-scenario");
        this.runScenario(scenarioId, btn);
      });
    });
  },

  async runScenario(scenarioId, buttonEl) {
    const origText = buttonEl ? buttonEl.innerHTML : "";
    if (buttonEl) {
      buttonEl.innerHTML = "Evaluating ML Pipeline... ⏳";
      buttonEl.disabled = true;
    }

    try {
      const res = await App.apiFetch("/api/simulation/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scenario_id: scenarioId })
      });

      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.detail || "Simulation failed");
      }

      const simResult = await res.json();
      this.renderLiveOutput(simResult);

      const isAnomaly = simResult.analysis.prediction !== "NORMAL";
      App.showToast(
        `Simulation '${simResult.scenario_title}' executed! AI Prediction: ${simResult.analysis.prediction}`,
        isAnomaly ? "danger" : "success"
      );

      // Refresh Dashboard, Digital Twin, and Activity streams in background
      await App.refreshAll();

    } catch (err) {
      console.error("[Simulation] Execution error:", err);
      App.showToast("Simulation error: " + err.message, "danger");
    } finally {
      if (buttonEl) {
        buttonEl.innerHTML = origText;
        buttonEl.disabled = false;
      }
    }
  },

  renderLiveOutput(sim) {
    const outContainer = document.getElementById("sim-live-output");
    const titleEl = document.getElementById("sim-result-scenario-title");
    const badgeEl = document.getElementById("sim-result-badge");
    const bodyEl = document.getElementById("sim-result-body");

    if (!outContainer || !bodyEl) return;

    outContainer.style.display = "block";
    titleEl.textContent = `Scenario Result: ${sim.scenario_title} (Event #${sim.event.id})`;

    const isAnomaly = sim.analysis.prediction !== "NORMAL";
    badgeEl.textContent = sim.analysis.prediction;
    badgeEl.className = isAnomaly ? "badge suspicious" : "badge normal";

    const riskLevelClass = (sim.analysis.risk_level || "low").toLowerCase();
    const ev = sim.event;

    bodyEl.innerHTML = `
      <!-- 1. Behavioural Features Input to Isolation Forest -->
      <div style="background-color: var(--bg-subtle); border: 1px solid var(--border-color); border-radius: var(--radius-sm); padding: 14px 18px; margin-bottom: 20px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
          <span style="font-size: 12px; font-weight: 700; text-transform: uppercase; color: var(--text-primary); letter-spacing: 0.05em;">
            📋 Behavioural Features Sent to Isolation Forest Model
          </span>
          <span style="font-size: 11px; color: var(--text-muted);">Scaled via StandardScaler & Evaluated Unsupervised</span>
        </div>
        
        <table class="feature-input-table">
          <thead>
            <tr>
              <th>Feature Name</th>
              <th>Observed Value</th>
              <th>Baseline Norm</th>
              <th>Signal Status</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><strong>Requests / Minute</strong></td>
              <td><code>${ev.requests_per_minute.toFixed(1)} req/min</code></td>
              <td>10 – 35 req/min</td>
              <td>${ev.requests_per_minute > 100 ? '<span style="color: var(--danger); font-weight: 700;">Elevated Burst</span>' : '<span style="color: var(--success);">Normal</span>'}</td>
            </tr>
            <tr>
              <td><strong>Failed Login Count</strong></td>
              <td><code>${ev.failed_login_count} failures</code></td>
              <td>0 – 1 failure</td>
              <td>${ev.failed_login_count >= 2 ? '<span style="color: var(--danger); font-weight: 700;">Suspicious Failures</span>' : '<span style="color: var(--success);">Normal</span>'}</td>
            </tr>
            <tr>
              <td><strong>Login Frequency</strong></td>
              <td><code>${ev.login_frequency_per_hr.toFixed(1)} / hour</code></td>
              <td>0.5 – 2.5 / hour</td>
              <td>${ev.login_frequency_per_hr > 5.0 ? '<span style="color: var(--warning); font-weight: 700;">High Frequency</span>' : '<span style="color: var(--success);">Normal</span>'}</td>
            </tr>
            <tr>
              <td><strong>Resource Sensitivity</strong></td>
              <td><code>Tier ${ev.resource_sensitivity_level} / 5 (${ev.resource_name})</code></td>
              <td>Tier 1 – 2 (Catalog / Portal)</td>
              <td>${ev.resource_sensitivity_level >= 4 ? '<span style="color: var(--danger); font-weight: 700;">Restricted Asset</span>' : '<span style="color: var(--success);">Nominal</span>'}</td>
            </tr>
            <tr>
              <td><strong>Records Accessed</strong></td>
              <td><code>${ev.records_accessed} records</code></td>
              <td>1 – 25 records</td>
              <td>${ev.records_accessed >= 100 ? '<span style="color: var(--danger); font-weight: 700;">Bulk Query</span>' : '<span style="color: var(--success);">Normal</span>'}</td>
            </tr>
            <tr>
              <td><strong>Data Download</strong></td>
              <td><code>${ev.data_download_mb.toFixed(1)} MB</code></td>
              <td>0.1 – 4.5 MB</td>
              <td>${ev.data_download_mb >= 50.0 ? '<span style="color: var(--danger); font-weight: 700;">Heavy Transfer</span>' : '<span style="color: var(--success);">Normal</span>'}</td>
            </tr>
            <tr>
              <td><strong>New Device Fingerprint</strong></td>
              <td><code>${ev.is_new_device ? 'Yes (Unrecognized)' : 'No (Known Workstation)'}</code></td>
              <td>Known Workstation (0)</td>
              <td>${ev.is_new_device ? '<span style="color: var(--warning); font-weight: 700;">New Device</span>' : '<span style="color: var(--success);">Verified</span>'}</td>
            </tr>
            <tr>
              <td><strong>New IP Address</strong></td>
              <td><code>${ev.is_new_ip ? 'Yes (' + ev.ip_address + ')' : 'No (' + ev.ip_address + ')'}</code></td>
              <td>Campus Subnet (10.0.4.x)</td>
              <td>${ev.is_new_ip ? '<span style="color: var(--warning); font-weight: 700;">External IP</span>' : '<span style="color: var(--success);">Verified Subnet</span>'}</td>
            </tr>
            <tr>
              <td><strong>Unusual API Access</strong></td>
              <td><code>${ev.unusual_api_access ? 'Yes (Admin/Export)' : 'No (Standard)'}</code></td>
              <td>Standard Client (0)</td>
              <td>${ev.unusual_api_access ? '<span style="color: var(--warning); font-weight: 700;">Unusual Route</span>' : '<span style="color: var(--success);">Standard</span>'}</td>
            </tr>
            <tr>
              <td><strong>Session Duration</strong></td>
              <td><code>${ev.session_duration_minutes.toFixed(1)} min</code></td>
              <td>10 – 60 min</td>
              <td><span style="color: var(--text-secondary);">Recorded</span></td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- 2. AI Diagnostic & Risk Assessment Breakdown -->
      <div style="display: grid; grid-template-columns: 260px 1fr; gap: 24px;">
        <!-- Left Summary Box -->
        <div class="verdict-box">
          <div class="kpi-label">AI Behaviour Classification</div>
          <div class="verdict-badge badge ${isAnomaly ? 'suspicious' : 'normal'}" style="font-size: 15px; margin: 8px 0;">
            ${sim.analysis.prediction}
          </div>
          
          <div class="kpi-label" style="margin-top: 10px;">Security Risk Assessment</div>
          <div class="risk-dial">
            <span class="risk-number" style="color: ${sim.analysis.risk_score > 60 ? 'var(--danger)' : (sim.analysis.risk_score > 30 ? 'var(--warning)' : 'var(--success)')};">
              ${sim.analysis.risk_score}
            </span>
            <span class="risk-denom">/ 100</span>
          </div>
          <span class="badge-risk ${riskLevelClass}">${sim.analysis.risk_level} Risk</span>
          
          <div class="anomaly-score-tag">
            Anomaly Score: ${sim.analysis.anomaly_score}
          </div>
          <div style="font-size: 11px; color: var(--text-muted); margin-top: 8px;">
            Isolation Forest (150 trees)
          </div>
        </div>

        <!-- Right Explanation Rows -->
        <div>
          <div class="analysis-rows">
            <div class="info-row">
              <div class="info-row-label">Detected Behaviour</div>
              <div class="info-row-value">${sim.analysis.detected_behaviour}</div>
            </div>

            <div class="info-row reason">
              <div class="info-row-label">Reason / AI Feature Deviation Explanation</div>
              <div class="info-row-value">${sim.analysis.reason}</div>
            </div>

            <div class="info-row action">
              <div class="info-row-label">Recommended Security Action</div>
              <div class="info-row-value">${sim.analysis.recommended_action}</div>
            </div>
          </div>

          <!-- Quick Navigation Actions -->
          <div style="display: flex; gap: 12px; margin-top: 18px; flex-wrap: wrap;">
            <button class="btn btn-secondary btn-sm" onclick="Analysis.loadEvent(${sim.event.id}); App.switchView('analysis');">
              Deep AI Feature Diagnostics 🔍
            </button>
            <button class="btn btn-secondary btn-sm" onclick="App.switchView('digital-twin');">
              View Digital Twin Impact 🌐
            </button>
            <button class="btn btn-secondary btn-sm" onclick="App.switchView('dashboard');">
              Return to Dashboard 📊
            </button>
          </div>
        </div>
      </div>
    `;

    // Smooth scroll to output
    outContainer.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }
};

window.Simulation = Simulation;
