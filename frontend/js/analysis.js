/**
 * Explainable AI Security Analysis Controller for AI-DT-CyberShield (Module 5.3).
 * Visualizes ML Isolation Forest anomaly diagnostic metrics,
 * feature deviation breakdowns (z-score variance from baseline),
 * multi-dimensional risk scores (0-100), and prescriptive remediation.
 */

const Analysis = {
  currentEventId: null,

  init() {
    const select = document.getElementById("analysis-event-select");
    const inspectBtn = document.getElementById("btn-analyze-selected");

    if (inspectBtn && select) {
      inspectBtn.addEventListener("click", () => {
        const val = select.value;
        if (val) this.loadEvent(parseInt(val, 10));
      });
      select.addEventListener("change", () => {
        const val = select.value;
        if (val) this.loadEvent(parseInt(val, 10));
      });
    }
  },

  async populateDropdown() {
    const select = document.getElementById("analysis-event-select");
    if (!select) return;

    try {
      const res = await App.apiFetch("/api/events?limit=30");
      if (!res.ok) return;
      const events = await res.json();

      if (events.length === 0) {
        select.innerHTML = `<option value="">No behavioural analysis is available yet.</option>`;
        this.renderEmptyState();
        return;
      }

      const currentVal = select.value;
      select.innerHTML = `<option value="">-- Select an event from audit history (${events.length} available) --</option>` +
        events.map(ev => {
          const srcTag = ev.event_source === "SIMULATION" ? " [SIM]" : " [LIVE]";
          return `<option value="${ev.id}" ${ev.id == currentVal ? 'selected' : ''}>
            Event #${ev.id}${srcTag} | ${ev.timestamp} | ${ev.username} | ${ev.prediction} (Risk: ${ev.risk_score}/100)
          </option>`;
        }).join("");

      // If no event currently selected, pick the first one
      if (!this.currentEventId && events.length > 0) {
        this.loadEvent(events[0].id);
      }
    } catch (err) {
      console.error("[Analysis] Error populating dropdown:", err);
    }
  },

  async loadEvent(eventId) {
    this.currentEventId = eventId;
    const select = document.getElementById("analysis-event-select");
    if (select) select.value = eventId;

    try {
      // Fetch both event details and fresh AI analysis
      const [evRes, anRes] = await Promise.all([
        App.apiFetch(`/api/events/${eventId}`),
        App.apiFetch(`/api/analysis/${eventId}`)
      ]);

      if (!evRes.ok || !anRes.ok) throw new Error("Failed to fetch event analysis data");
      const event = await evRes.json();
      const analysis = await anRes.json();

      this.renderAnalysis(event, analysis);
    } catch (err) {
      console.error("[Analysis] Error loading event:", err);
      App.showToast("Failed to load event analysis: " + err.message, "danger");
    }
  },

  renderEmptyState() {
    const cardBody = document.getElementById("analysis-main-card");
    if (cardBody) {
      document.getElementById("analysis-card-event-id").textContent = "No Event Selected";
      document.getElementById("analysis-detected-behaviour").textContent = "No behavioural analysis is available yet.";
      document.getElementById("analysis-reason-text").textContent = "Perform an application action or run a security test to observe real-time AI anomaly evaluation.";
      document.getElementById("analysis-recommended-action").textContent = "Awaiting telemetry stream.";
    }
  },

  renderAnalysis(event, analysis) {
    const isSim = event.event_source === "SIMULATION";
    const sourceLabel = isSim ? "Controlled Benchmark Simulation" : "Actual Authenticated User Activity";
    const sourceTagEl = document.getElementById("analysis-source-tag");
    if (sourceTagEl) {
      sourceTagEl.textContent = sourceLabel;
      sourceTagEl.className = isSim ? "badge" : "badge normal";
      sourceTagEl.style.backgroundColor = isSim ? "rgba(147, 51, 234, 0.15)" : "rgba(59, 130, 246, 0.15)";
      sourceTagEl.style.color = isSim ? "#9333ea" : "#3b82f6";
    }

    document.getElementById("analysis-card-event-id").textContent = `Event #${event.id} • ${event.timestamp} • User: ${event.username} • Source: ${event.event_source || 'ACTUAL_ACTIVITY'}`;

    const isSuspicious = analysis.prediction !== "NORMAL";
    const predBadge = document.getElementById("analysis-prediction-badge");
    if (predBadge) {
      predBadge.textContent = analysis.prediction;
      predBadge.className = isSuspicious ? "verdict-badge badge suspicious" : "verdict-badge badge normal";
    }

    const riskNum = document.getElementById("analysis-risk-number");
    const riskTag = document.getElementById("analysis-risk-level-tag");
    if (riskNum) {
      riskNum.textContent = analysis.risk_score;
      riskNum.style.color = analysis.risk_score > 60 ? "var(--danger)" : (analysis.risk_score > 30 ? "var(--warning)" : "var(--success)");
    }
    if (riskTag) {
      riskTag.textContent = `${analysis.risk_level} Risk`;
      riskTag.className = `badge-risk ${(analysis.risk_level || 'low').toLowerCase()}`;
    }

    const anomalyScoreEl = document.getElementById("analysis-anomaly-score");
    if (anomalyScoreEl) {
      anomalyScoreEl.textContent = `${analysis.anomaly_score} (Raw Decision: ${analysis.raw_score})`;
    }

    document.getElementById("analysis-detected-behaviour").textContent = analysis.detected_behaviour;
    document.getElementById("analysis-affected-resource").textContent = `${analysis.affected_resource} (Sensitivity Tier ${event.resource_sensitivity_level}/5)`;
    document.getElementById("analysis-reason-text").textContent = analysis.reason;
    document.getElementById("analysis-recommended-action").textContent = analysis.recommended_action;

    // Render Feature Deviations Breakdown
    this.renderFeatureBars(analysis.feature_deviations || []);
  },

  renderFeatureBars(deviations) {
    const container = document.getElementById("analysis-feature-bars");
    if (!container) return;

    if (!deviations || deviations.length === 0) {
      container.innerHTML = `<div style="font-size: 12px; color: var(--text-muted);">No deviation data available for this event.</div>`;
      return;
    }

    // Top 8 features sorted by absolute z-score
    const topDevs = deviations.slice(0, 8);

    container.innerHTML = topDevs.map(d => {
      const absZ = Math.abs(d.z_score);
      const widthPct = Math.min(100, Math.max(8, (absZ / 4.0) * 100));
      let fillClass = "";
      if (d.is_extreme) fillClass = "extreme";
      else if (d.is_elevated) fillClass = "elevated";

      return `
        <div class="feature-bar-row">
          <div class="feature-bar-label" title="${d.feature}">${d.feature}</div>
          <div class="feature-bar-track">
            <div class="feature-bar-fill ${fillClass}" style="width: ${widthPct}%;"></div>
          </div>
          <div class="feature-bar-val" style="color: ${d.is_extreme ? 'var(--danger)' : (d.is_elevated ? 'var(--warning)' : 'var(--text-secondary)')};">
            z = ${d.z_score >= 0 ? '+' : ''}${d.z_score.toFixed(1)} (raw: ${d.raw_value}, norm: ${d.mean_baseline})
          </div>
        </div>
      `;
    }).join("");
  }
};

window.Analysis = Analysis;
