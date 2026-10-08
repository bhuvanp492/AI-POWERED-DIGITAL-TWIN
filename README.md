# AI-DT-CyberShield: AI-Powered Digital Twin for Predictive Cybersecurity of Cloud Applications

**Final-Year B.Tech Computer Science & Engineering Capstone Project**  
**Phase 1 Prototype (7th Semester)**

---

## 1. Project Title & Overview

- **Full Project Title:** AI-Powered Digital Twin for Predictive Cybersecurity of Cloud Applications
- **Short Name:** `AI-DT-CyberShield`
- **Domain:** Cloud Security, Behavioral Anomaly Detection, Machine Learning, Digital Twins, Explainable AI (XAI)
- **Target OS:** Windows 10/11 (Local Execution)

---

## 2. Core Problem Statement & Research Motivation

Traditional cloud and application perimeter security heavily relies on static intrusion detection signatures and login-time authentication checks (e.g., alert if a user logs in from an unusual country or outside working hours).

However, modern adversaries frequently bypass perimeter defenses using:
1. Valid credentials obtained via phishing, credential stuffing, or stolen session tokens.
2. Infiltration during standard daytime working hours.
3. Legitimate authentication mechanisms.

**The Fundamental Flaw:** *Successful authentication is treated as trusted behavior.* Once authenticated, malicious actors conduct stealthy reconnaissance, automated endpoint scraping, privilege boundary violations, and massive database exfiltration unnoticed.

---

## 3. Proposed Solution & Core Philosophy

> **"Successful login does NOT automatically mean trusted behaviour."**

`AI-DT-CyberShield` solves this vulnerability by focusing strictly on **post-authentication behavioral analysis**. The system monitors continuous behavioral signals (request velocity, session duration, device fingerprint changes, external IP deviations, resource sensitivity levels, queried record volumes, and egress bandwidth) and feeds them into an unsupervised **Isolation Forest Machine Learning model** combined with an **Explainable Risk Engine**.

The operational state is mirrored in real time onto an interactive **2D Digital Twin**, providing security analysts with immediate visual feedback regarding application health, entity status, and compromised resources.

---

## 4. System Architecture & Workflow

```text
               +─────────────────────────────────────────────────────────────+
               |                 Security Analyst Login Screen               |
               |        (Demo Credentials: admin / admin123 -> Session)      |
               +─────────────────────────────────────────────────────────────+
                                              │
                                              ▼
               +─────────────────────────────────────────────────────────────+
               |                    Authenticated Session                    |
               |           (Continuous Telemetry & Activity Auditing)        |
               +─────────────────────────────────────────────────────────────+
                                              │
                                              ▼
               +─────────────────────────────────────────────────────────────+
               |              Post-Login Behavioral Feature Pipeline         |
               |     (12 Scaled Dimensions via StandardScaler Normalization) |
               +─────────────────────────────────────────────────────────────+
                                              │
                                              ▼
               +─────────────────────────────────────────────────────────────+
               |          Isolation Forest Unsupervised Machine Learning     |
               |     - Decision Function & Anomaly Score (0.0 to 1.0)        |
               |     - AI Classification (NORMAL vs. ANOMALY DETECTED)       |
               +─────────────────────────────────────────────────────────────+
                                              │
                                              ▼
               +─────────────────────────────────────────────────────────────+
               |            Contextual Risk & Explainability Engine          |
               |     - Multi-factor Risk Score Calculation (0 - 100)         |
               |     - Feature Deviation Attribution (Z-Scores)              |
               |     - Technically Sound Incident Explanation                |
               |     - Prescriptive Remediation Actions                      |
               +─────────────────────────────────────────────────────────────+
                                              │
                        ┌─────────────────────┴─────────────────────┐
                        ▼                                           ▼
       +─────────────────────────────────+         +─────────────────────────────────+
       |      SQLite Event Database      |         |      2D Digital Twin Model      |
       |    (Persistent Audit Trail)     |         |   (Real-time State & Nodes)     |
       +─────────────────────────────────+         +─────────────────────────────────+
                        │                                           │
                        └─────────────────────┬─────────────────────┘
                                              ▼
       +─────────────────────────────────────────────────────────────────────────────+
       |                     Cybersecurity Management Interface (SPA)                |
       |        - Dashboard KPIs & Banner  (● SECURE / ● ATTENTION REQUIRED)         |
       |        - Activity Monitor (Filterable Audit Log Stream)                     |
       |        - AI Security Analysis (Detailed Diagnostic Card & Z-Scores)         |
       |        - Digital Twin 2D Flow Topology (Nodes, Resources, Posture)          |
       |        - Security Testing Suite (Core Verification & Attack Scenarios)       |
       |        - Dual-Theme System (Light Mode ↔ Dark Mode)                         |
       +─────────────────────────────────────────────────────────────────────────────+
```

---

## 5. Technology Stack

### Backend
- **Language:** Python 3.12
- **Web Framework:** FastAPI (High performance asynchronous REST API)
- **Server:** Uvicorn (ASGI server)
- **Database:** SQLite 3 (Persistent local event repository)
- **Validation:** Pydantic v2 (Strict request/response schema modeling)

### Machine Learning
- **Library:** `scikit-learn` (v1.8.0)
- **Primary Algorithm:** `IsolationForest` (Unsupervised decision tree ensemble anomaly detector)
- **Data Preprocessing:** `StandardScaler` (Z-score normalization)
- **Data Manipulation:** `pandas`, `numpy`
- **Model Serialization:** `joblib`

### Frontend
- **Structure:** Semantic HTML5 Single Page Application (SPA)
- **Styling:** Vanilla CSS3 with Custom Design Tokens (CSS Variables)
- **Theme:** Dynamic Light Mode / Dark Mode switchable with `localStorage` persistence
- **Client Logic:** Modern Vanilla JavaScript (ES6 Modules, Fetch API, no build step required)

---

## 6. Behavioral Features & True ML Guarantee

The Isolation Forest algorithm analyzes a 12-dimensional behavioral feature vector:

| # | Feature Name | Type | Normal Baseline | Anomalous Range |
|---|--------------|------|-----------------|-----------------|
| 1 | `requests_per_minute` | Float | 10.0 – 35.0 | 180.0 – 600.0+ |
| 2 | `failed_login_count` | Integer | 0 – 1 | 5 – 20+ |
| 3 | `login_frequency_per_hr` | Float | 0.5 – 2.5 | 8.0 – 25.0 |
| 4 | `resource_sensitivity_level`| Integer | Tier 1 – 3 | Tier 4 – 5 (Restricted DBs) |
| 5 | `records_accessed` | Integer | 1 – 25 records | 200 – 2,500+ records |
| 6 | `data_download_mb` | Float | 0.1 – 4.5 MB | 75.0 – 850.0 MB |
| 7 | `is_new_device` | Binary | 0 (Known Workstation) | 1 (Unrecognized / Script) |
| 8 | `is_new_ip` | Binary | 0 (Known Campus Subnet)| 1 (External Foreign IP) |
| 9 | `unusual_api_access` | Binary | 0 (Standard APIs) | 1 (Admin/Export Endpoints) |
| 10| `session_duration_minutes` | Float | 10.0 – 75.0 min | <2 min (Scan) or >350 min |
| 11| `access_time_hour` | Integer | 8 – 20 (Daytime) | 0 – 5 (Late Night) |
| 12| `behaviour_deviation_score`| Float | 0.01 – 0.20 | 0.65 – 0.98 |

### Zero Scenario Hardcoding Guarantee
The application does **NOT** determine predictions based on scenario names (e.g., `if scenario == "compromised_account": prediction = "SUSPICIOUS"` is strictly prohibited). The scenario generators merely synthesize realistic feature values, which are normalized by `StandardScaler` and evaluated by the trained `IsolationForest` model. The model's `decision_function` and isolation trees independently determine whether an event is `NORMAL` or an `ANOMALY DETECTED`.

### Separation of AI Classification and Risk Scoring
- **AI Behaviour Classification:** `NORMAL` or `ANOMALY DETECTED` (Output of Isolation Forest).
- **Anomaly Score:** Continuous metric calibrated from the model's raw decision function.
- **Risk Score (0 – 100):** Multi-factor score combining the ML anomaly score with objective contextual security modifiers:
  - **0 – 30 (Low Risk):** Normal authenticated activity.
  - **31 – 60 (Medium Risk):** Moderate variance or single-factor deviation.
  - **61 – 80 (High Risk):** Multi-factor anomaly detected.
  - **81 – 100 (Critical Risk):** Potential account compromise / mass data exfiltration.

---

## 7. Demo Authentication & Access Credentials

To reflect real-world cybersecurity platforms, the dashboard is protected by an academic authentication gateway:

- **Demo Username:** `admin`
- **Demo Password:** `admin123`
- **Role:** Lead Security Analyst
- **Department:** Cyber Defense Operations

*Note: For evaluation convenience, an "Auto-fill Demo Credentials" button is provided directly on the login screen.*

---

## 8. Digital Twin Component

The Phase 1 Digital Twin provides a real-time **2D operational state model** representing the cloud application's security posture:
- **Application State:** `NORMAL` vs. `UNDER THREAT`
- **User Session:** `ACTIVE` vs. `SUSPICIOUS`
- **Security State:** `LOW RISK` vs. `HIGH RISK`
- **API Gateway Node:** Tracks request velocity, active connections, and network egress rate.
- **User Sessions Node:** Monitors active identities, device fingerprints, and authentication status.
- **Protected Resources Node:** Reflects the integrity and query state of sensitive database assets (Course Catalog, Student Profile Portal, Financial Aid DB, Student Grade & Exam DB).
- **AI CyberShield Node:** Displays active Isolation Forest inference latency, current anomaly score, and model health.

---

## 9. Phase 1 vs. Phase 2 Scope

| Dimension | Phase 1 (7th Semester - Current Implementation) | Phase 2 (8th Semester - Future Scope) |
|---|---|---|
| **Environment** | 100% Local (Windows 10/11) | AWS Cloud (EC2, ECS / Fargate) |
| **Telemetry Ingestion**| Local SQLite Event Pipeline & Simulator | AWS CloudWatch Logs & EventBridge |
| **Identity & IAM** | Academic Session Gateway & Fingerprinting | AWS IAM Roles, Policies & Cognito |
| **Model Hosting** | Local Python process (FastAPI + joblib) | AWS SageMaker / Lambda Serverless Inference |
| **Remediation** | Prescriptive Action Recommendations | Automated AWS WAF IP blocking & IAM Session Revocation |
| **Digital Twin** | 2D Interactive Visual Topology & Telemetry | Multi-cloud graph twin with attack path simulation |

*Phase 1 runs locally on Windows without requiring an AWS account, ensuring zero operational cost and rock-solid offline reliability during academic project evaluations.*

---

## 10. Installation & Run Instructions

### Prerequisites
- Windows 10/11
- Python 3.12 (`py -3.12`)

### 1. Install Dependencies
```cmd
py -3.12 -m pip install -r requirements.txt
```

### 2. Run Automated Tests
Verify all 15 unit and integration tests pass:
```cmd
py -3.12 -m pytest tests/ -v
```

### 3. Launch Application Server
Execute the Windows batch launcher:
```cmd
run.bat
```
Or run directly via uvicorn:
```cmd
py -3.12 -m uvicorn backend.app:app --host 127.0.0.1 --port 8000 --reload
```

### 4. Access the Web Application
Open your browser and navigate to:
```text
http://127.0.0.1:8000
```
Interactive API documentation: `http://127.0.0.1:8000/docs`

---

## 11. Project Review Demonstration Script

Follow this step-by-step procedure during the B.Tech project review:

### Step 1: Authentication Gateway
1. Open `http://127.0.0.1:8000` in Chrome/Edge.
2. Demonstrate that the dashboard is protected by the login gateway.
3. Test invalid credentials (`admin` / `wrongpass`) -> Observe clear error message.
4. Click **Auto-fill Demo Credentials** (`admin` / `admin123`) and click **Sign In**.

### Step 2: Dashboard Baseline State
1. Observe the authenticated session: Topbar displays `● SECURE`, and sidebar shows `admin • Lead Security Analyst`.
2. Review the 5 KPI metric cards (Events Monitored, Normal Events, Anomalies Detected, High-Risk Events, Current Risk Score).
3. Review baseline nominal events in the Recent Security Events table.
4. Toggle the **🌙 Dark Mode / ☀️ Light Mode** button in the topbar.

### Step 3: Security Testing & Core Verification Benchmark
1. Navigate to **Security Testing** in the sidebar.
2. Point out the **Core AI Behaviour Verification** benchmark section:
   - Explain to the review panel: *Both tests use valid credentials. The difference lies in what the user does after logging in.*
3. Click **Run Normal User Activity**:
   - Observe the **Behavioural Features Sent to Isolation Forest Table**: 18 req/min, 0 failed logins, known workstation, campus IP, Course Catalog (Sensitivity 1), 1.2 MB download.
   - Show the AI Result:
     - **AI Classification:** `NORMAL`
     - **Risk Score:** `6 – 15 / 100 (LOW)`
     - **Reason:** Behaviour consistent with established baseline.

### Step 4: The Flagship Compromised Account Demonstration
1. Click **Simulate Compromised Account**:
   - Highlight the critical characteristics:
     - **Login Status:** `SUCCESSFUL` (Legitimate username & password during normal hours 14:15).
     - **Post-Login Telemetry:** New Device + New External IP (`185.220.101.5`) + 310 req/min API burst + Restricted Student Exam DB (Tier 5) + 850 records + 450 MB data exfiltration.
   - Show the immediate AI Result:
     - **AI Classification:** `ANOMALY DETECTED`
     - **Risk Score:** `88 – 100 / 100 (CRITICAL)`
     - **Anomaly Score:** Calibrated outlier score from Isolation Forest.
     - **Reason:** *Anomalous behaviour detected because the session was authenticated successfully with valid credentials, but subsequent post-login activity originated from a new device/IP, generated an unusually high request rate (310 req/min), accessed restricted records, and downloaded 450 MB.*
     - **Recommended Action:** *Temporarily restrict session, revoke active bearer token, and require step-up multi-factor authentication.*

### Step 5: Side-by-Side Behaviour Comparison
1. Navigate to **AI Security Analysis** (or scroll to the Behaviour Comparison table).
2. Review the side-by-side comparison table showing how normal baseline activity contrasts with the compromised account telemetry across all 10 monitored attributes.
3. Review the **Feature Deviation Breakdown (Z-Scores)** showing extreme deviation in data download, request rate, and resource sensitivity.

### Step 6: 2D Digital Twin Threat Reaction
1. Navigate to **Digital Twin**.
2. Show that the 2D topology has reacted to the compromised session:
   - **Application State:** `UNDER THREAT`
   - **User Session:** `SUSPICIOUS`
   - **Security State:** `HIGH RISK` / `ATTENTION REQUIRED`
   - The `API Gateway`, `User Sessions`, and `Protected DBs` nodes reflect elevated throughput, suspicious identity, and targeted assets.

### Step 7: Dashboard Update & Session Termination
1. Return to **Dashboard**:
   - Point out that the status banner now displays `● ATTENTION REQUIRED`.
   - The **Latest AI Behaviour Decision** card reflects the flagged anomaly.
   - Anomalies Detected and High-Risk KPI counters have incremented.
2. Click **Logout 🚪** in the topbar or sidebar:
   - The analyst session is terminated and the user is securely returned to the login screen.
