/**
 * Core Application Controller for AI-DT-CyberShield (Modules 5.1, 5.2, 5.3).
 * Handles:
 * - SPA navigation and dual-theme toggling (Light/Dark).
 * - Authentication & Bearer token session lifecycle.
 * - Authenticated API fetch wrapper (apiFetch) with 401 handling.
 * - Live user action execution & real-time behavioural telemetry pipeline.
 * - Global state synchronization and toast notifications.
 */

const App = {
  currentView: "dashboard",
  theme: localStorage.getItem("cybershield_theme") || "light",
  authToken: localStorage.getItem("cybershield_auth_token") || null,
  currentUser: JSON.parse(localStorage.getItem("cybershield_auth_user") || "null"),

  init() {
    this.applyTheme(this.theme);
    this.bindThemeToggle();
    this.bindAuth();
    this.bindNavigation();

    // Check if valid session exists
    if (this.isAuthenticated()) {
      this.showAppWorkspace();
    } else {
      this.showLoginScreen();
    }
  },

  isAuthenticated() {
    return Boolean(this.authToken && this.currentUser);
  },

  /**
   * Authenticated HTTP Fetch wrapper.
   * Injects Bearer token in headers. Automatically handles 401 Unauthorized responses.
   */
  async apiFetch(url, options = {}) {
    options.headers = options.headers || {};
    if (this.authToken) {
      options.headers["Authorization"] = `Bearer ${this.authToken}`;
    }
    const res = await fetch(url, options);
    if (res.status === 401) {
      this.handleUnauthorized();
      throw new Error("Session expired or authentication required. Please log in.");
    }
    return res;
  },

  handleUnauthorized() {
    this.authToken = null;
    this.currentUser = null;
    localStorage.removeItem("cybershield_auth_token");
    localStorage.removeItem("cybershield_auth_user");
    this.showLoginScreen();
    this.showToast("Session expired or unauthorized. Please re-authenticate.", "danger");
  },

  showLoginScreen() {
    const loginContainer = document.getElementById("login-container");
    const appContainer = document.getElementById("app-container");
    if (loginContainer) loginContainer.style.display = "flex";
    if (appContainer) appContainer.style.display = "none";
  },

  showAppWorkspace() {
    const loginContainer = document.getElementById("login-container");
    const appContainer = document.getElementById("app-container");
    if (loginContainer) loginContainer.style.display = "none";
    if (appContainer) appContainer.style.display = "flex";

    // Update User Profile in UI
    if (this.currentUser) {
      const unameEl = document.getElementById("sidebar-user-name");
      const uroleEl = document.getElementById("sidebar-user-role");
      const stimeEl = document.getElementById("sidebar-session-time");
      const liveUname = document.getElementById("live-user-badge");

      if (unameEl) unameEl.textContent = this.currentUser.username;
      if (uroleEl) uroleEl.textContent = this.currentUser.role || "Security Analyst";
      if (stimeEl) stimeEl.textContent = `Active since: ${this.currentUser.login_time || "Now"}`;
      if (liveUname) liveUname.textContent = this.currentUser.username;
    }

    // Initialize View Controllers
    this.bindNavigation();
    this.bindLiveUserActions();

    if (window.Dashboard) window.Dashboard.init();
    if (window.Activity) window.Activity.init();
    if (window.Analysis) window.Analysis.init();
    if (window.DigitalTwin) window.DigitalTwin.init();
    if (window.Simulation) window.Simulation.init();

    // Initial data refresh
    this.refreshAll();

    // Bind Quick Test & Reset buttons
    const quickSimBtn = document.getElementById("btn-quick-simulate");
    if (quickSimBtn) {
      quickSimBtn.addEventListener("click", () => this.switchView("simulation"));
    }

    const resetDbBtn = document.getElementById("btn-reset-db");
    if (resetDbBtn) {
      resetDbBtn.addEventListener("click", () => this.resetDatabase());
    }
  },

  bindAuth() {
    const loginForm = document.getElementById("login-form");
    const autofillAdmin = document.getElementById("fill-admin");
    const autofillAnalyst = document.getElementById("fill-analyst");
    const autofillStudent = document.getElementById("fill-student");
    const autofillDemo = document.getElementById("btn-autofill-demo");
    const topbarLogout = document.getElementById("btn-topbar-logout");
    const sidebarLogout = document.getElementById("btn-sidebar-logout");

    if (loginForm) {
      loginForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const usernameInput = document.getElementById("login-username");
        const passwordInput = document.getElementById("login-password");
        const errorBanner = document.getElementById("login-error-banner");
        const errorText = document.getElementById("login-error-text");
        const submitBtn = document.getElementById("btn-login-submit");

        const username = usernameInput ? usernameInput.value.trim() : "";
        const password = passwordInput ? passwordInput.value.trim() : "";

        if (!username || !password) {
          if (errorBanner && errorText) {
            errorText.textContent = "Please enter both username and password.";
            errorBanner.style.display = "flex";
          }
          return;
        }

        if (submitBtn) {
          submitBtn.disabled = true;
          submitBtn.textContent = "Authenticating... 🔒";
        }

        try {
          const res = await fetch("/api/auth/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password })
          });

          const data = await res.json();

          if (!res.ok) {
            throw new Error(data.detail || "Authentication failed.");
          }

          // Successful authentication
          this.authToken = data.token;
          this.currentUser = data.user;
          localStorage.setItem("cybershield_auth_token", data.token);
          localStorage.setItem("cybershield_auth_user", JSON.stringify(data.user));

          if (errorBanner) errorBanner.style.display = "none";
          this.showToast(`Authenticated as ${data.user.username} (${data.user.role})`, "success");

          // Open application workspace
          this.showAppWorkspace();
          this.switchView("dashboard");

        } catch (err) {
          if (errorBanner && errorText) {
            errorText.textContent = err.message;
            errorBanner.style.display = "flex";
          }
        } finally {
          if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.textContent = "Sign In to CyberShield ➔";
          }
        }
      });
    }

    const setCreds = (u, p) => {
      const uEl = document.getElementById("login-username");
      const pEl = document.getElementById("login-password");
      if (uEl) uEl.value = u;
      if (pEl) pEl.value = p;
      this.showToast(`Credentials filled: ${u}`, "info");
    };

    if (autofillAdmin) autofillAdmin.addEventListener("click", () => setCreds("admin", "admin123"));
    if (autofillAnalyst) autofillAnalyst.addEventListener("click", () => setCreds("analyst", "analyst123"));
    if (autofillStudent) autofillStudent.addEventListener("click", () => setCreds("student01", "student123"));
    if (autofillDemo) autofillDemo.addEventListener("click", () => setCreds("admin", "admin123"));

    const logoutHandler = async () => {
      try {
        if (this.authToken) {
          await fetch("/api/auth/logout", {
            method: "POST",
            headers: { "Authorization": `Bearer ${this.authToken}` }
          });
        }
      } catch (err) {
        console.error("Logout API call error:", err);
      } finally {
        this.authToken = null;
        this.currentUser = null;
        localStorage.removeItem("cybershield_auth_token");
        localStorage.removeItem("cybershield_auth_user");

        const pwdInput = document.getElementById("login-password");
        if (pwdInput) pwdInput.value = "";

        const errBanner = document.getElementById("login-error-banner");
        if (errBanner) errBanner.style.display = "none";

        this.showLoginScreen();
        this.showToast("Security analyst session terminated.", "info");
      }
    };

    if (topbarLogout) topbarLogout.addEventListener("click", logoutHandler);
    if (sidebarLogout) sidebarLogout.addEventListener("click", logoutHandler);
  },

  bindLiveUserActions() {
    const btns = document.querySelectorAll(".live-action-btn");
    btns.forEach(btn => {
      btn.addEventListener("click", async () => {
        const actionType = btn.getAttribute("data-action");
        const simDevice = document.getElementById("toggle-live-device")?.checked || false;
        const simIp = document.getElementById("toggle-live-ip")?.checked || false;
        await this.executeUserAction(actionType, simDevice, simIp, btn);
      });
    });
  },

  async executeUserAction(actionType, simDevice, simIp, buttonEl) {
    const origText = buttonEl ? buttonEl.innerHTML : "";
    if (buttonEl) {
      buttonEl.innerHTML = "Processing Telemetry... ⏳";
      buttonEl.disabled = true;
    }

    try {
      const res = await this.apiFetch("/api/resources/execute-action", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          action_type: actionType,
          simulate_new_device: simDevice,
          simulate_new_ip: simIp
        })
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Action failed.");

      this.renderLiveActionResult(data);

      const isAnomaly = data.analysis.prediction !== "NORMAL";
      this.showToast(
        `Live Action Recorded: ${data.analysis.prediction} (Risk: ${data.analysis.risk_score}/100)`,
        isAnomaly ? "danger" : "success"
      );

      // Refresh Dashboard, Activity, Digital Twin, and Analysis streams
      await this.refreshAll();

    } catch (err) {
      console.error("[App] Action execution error:", err);
      this.showToast("Action execution error: " + err.message, "danger");
    } finally {
      if (buttonEl) {
        buttonEl.innerHTML = origText;
        buttonEl.disabled = false;
      }
    }
  },

  renderLiveActionResult(data) {
    const outBox = document.getElementById("live-action-result-box");
    if (!outBox) return;

    outBox.style.display = "block";
    const ev = data.event;
    const an = data.analysis;
    const isAnomaly = an.prediction !== "NORMAL";

    const titleEl = document.getElementById("live-res-title");
    if (titleEl) titleEl.textContent = `Executed Action: ${ev.action} (Event #${ev.id})`;

    const badgeEl = document.getElementById("live-res-badge");
    if (badgeEl) {
      badgeEl.textContent = an.prediction;
      badgeEl.className = isAnomaly ? "badge suspicious" : "badge normal";
    }

    const riskEl = document.getElementById("live-res-risk");
    if (riskEl) {
      riskEl.textContent = `${an.risk_score} / 100 (${an.risk_level.toUpperCase()})`;
      riskEl.className = `badge-risk ${(an.risk_level || 'low').toLowerCase()}`;
    }

    const userEl = document.getElementById("live-res-user");
    if (userEl) userEl.textContent = `${ev.username} • Origin: ${ev.ip_address} • Device: ${ev.is_new_device ? 'New Device' : 'Verified Workstation'}`;

    const resEl = document.getElementById("live-res-resource");
    if (resEl) resEl.textContent = `${ev.resource_name} (Sensitivity Tier ${ev.resource_sensitivity_level}/5)`;

    const teleEl = document.getElementById("live-res-telemetry");
    if (teleEl) teleEl.textContent = `${ev.requests_per_minute.toFixed(0)} req/min • ${ev.records_accessed} records • ${ev.data_download_mb.toFixed(1)} MB`;

    const reasonEl = document.getElementById("live-res-reason");
    if (reasonEl) reasonEl.textContent = an.reason;

    const actionEl = document.getElementById("live-res-action");
    if (actionEl) actionEl.textContent = an.recommended_action;

    const inspectBtn = document.getElementById("btn-inspect-live-action");
    if (inspectBtn) {
      inspectBtn.onclick = () => {
        if (window.Analysis) Analysis.loadEvent(ev.id);
        App.switchView("analysis");
      };
    }

    outBox.scrollIntoView({ behavior: "smooth", block: "nearest" });
  },

  applyTheme(theme) {
    this.theme = theme;
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("cybershield_theme", theme);

    const themeIcon = document.getElementById("theme-icon");
    const themeLabel = document.getElementById("theme-label");
    if (theme === "dark") {
      if (themeIcon) themeIcon.textContent = "☀️";
      if (themeLabel) themeLabel.textContent = "Light Mode";
    } else {
      if (themeIcon) themeIcon.textContent = "🌙";
      if (themeLabel) themeLabel.textContent = "Dark Mode";
    }
  },

  bindThemeToggle() {
    const btn = document.getElementById("theme-toggle-btn");
    if (!btn) return;
    btn.addEventListener("click", () => {
      const newTheme = this.theme === "light" ? "dark" : "light";
      this.applyTheme(newTheme);
      this.showToast(`Switched to ${newTheme === "dark" ? "Dark" : "Light"} theme`, "info");
    });
  },

  bindNavigation() {
    if (this._navBound) return;
    this._navBound = true;

    document.addEventListener("click", (e) => {
      const link = e.target.closest(".nav-link");
      if (link) {
        e.preventDefault();
        const targetView = link.getAttribute("data-view");
        if (targetView) {
          this.switchView(targetView);
        }
      }
    });
  },

  switchView(viewName) {
    this.currentView = viewName;

    // Update nav links active class
    document.querySelectorAll(".nav-link").forEach(l => {
      l.classList.toggle("active", l.getAttribute("data-view") === viewName);
    });

    // Update view sections
    document.querySelectorAll(".view-section").forEach(s => {
      s.classList.remove("active");
    });
    const activeSection = document.getElementById(`view-${viewName}`);
    if (activeSection) {
      activeSection.classList.add("active");
    }

    // Update Topbar Breadcrumb
    const titles = {
      "dashboard": "Dashboard Overview",
      "activity": "Activity Monitor & Audit Stream",
      "analysis": "Explainable AI Security Diagnostics",
      "digital-twin": "2D Digital Twin Security Model",
      "simulation": "Controlled Benchmark Security Testing",
      "settings": "System Settings & Authentication Audit"
    };
    const breadcrumb = document.getElementById("breadcrumb-title");
    if (breadcrumb) {
      breadcrumb.textContent = titles[viewName] || "CyberShield";
    }

    // Trigger on-show hooks for views
    if (viewName === "dashboard" && window.Dashboard) window.Dashboard.load();
    if (viewName === "activity" && window.Activity) window.Activity.load();
    if (viewName === "digital-twin" && window.DigitalTwin) window.DigitalTwin.load();
    if (viewName === "analysis" && window.Analysis) window.Analysis.populateDropdown();
    if (viewName === "settings") this.loadAuthLogs();
  },

  async loadAuthLogs() {
    const tbody = document.getElementById("settings-auth-logs-tbody");
    if (!tbody) return;

    try {
      const res = await this.apiFetch("/api/auth/logs?limit=25");
      if (!res.ok) throw new Error("Failed to load auth logs");
      const logs = await res.json();

      if (logs.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; padding: 18px; color: var(--text-muted);">No authentication audit events recorded yet.</td></tr>`;
        return;
      }

      tbody.innerHTML = logs.map(l => {
        const isSuccess = l.auth_status === "SUCCESS";
        const isDenied = l.auth_status === "DENIED";
        const statusBadge = isSuccess
          ? `<span class="badge normal">SUCCESS</span>`
          : (isDenied ? `<span class="badge suspicious">DENIED</span>` : `<span class="badge" style="background: rgba(239, 68, 68, 0.15); color: #ef4444;">FAILURE</span>`);

        return `
          <tr>
            <td style="font-family: var(--font-mono); font-size: 11px;">#${l.id}</td>
            <td style="font-family: var(--font-mono); font-size: 11px;">${l.timestamp}</td>
            <td><strong>${l.username}</strong></td>
            <td><code style="font-size: 11px;">${l.event_type}</code></td>
            <td style="font-family: var(--font-mono); font-size: 11px;">${l.source_ip}</td>
            <td>${statusBadge}</td>
          </tr>
        `;
      }).join("");

    } catch (err) {
      console.error("[App] Error loading auth logs:", err);
    }
  },

  async refreshAll() {
    try {
      if (window.Dashboard) await window.Dashboard.load();
      if (window.DigitalTwin) await window.DigitalTwin.load();
      if (window.Activity) await window.Activity.load();
      if (window.Analysis) await window.Analysis.populateDropdown();
    } catch (err) {
      console.error("[App] Error refreshing data:", err);
    }
  },

  async resetDatabase() {
    if (!confirm("Are you sure you want to reset the database to clean baseline demo state?")) return;
    try {
      const res = await this.apiFetch("/api/stats/reset", { method: "POST" });
      const data = await res.json();
      this.showToast(data.message || "Database reset to initial baseline.", "success");
      await this.refreshAll();
      this.switchView("dashboard");
    } catch (err) {
      this.showToast("Failed to reset database: " + err.message, "danger");
    }
  },

  showToast(message, type = "info") {
    const container = document.getElementById("toast-container");
    if (!container) return;

    const toast = document.createElement("div");
    toast.className = `toast ${type}`;
    const icon = type === "success" ? "✅" : (type === "danger" ? "⚠️" : "ℹ️");
    toast.innerHTML = `<span>${icon}</span><span>${message}</span>`;

    container.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = "0";
      toast.style.transform = "translateX(100%)";
      toast.style.transition = "all 0.3s ease";
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  }
};

window.App = App;
window.addEventListener("DOMContentLoaded", () => App.init());
