# LegacyTel v2.0.0: Central Console Administration & Management Manual

This guide provides security administrators, platform engineers, and systems operators with comprehensive operational instructions for setting up, monitoring, and managing the **LegacyTel Central Control Plane Console** and its agent fleet.

---

## 🏛️ 1. Architecture & Console Overview

LegacyTel v2.0.0 is managed through a single-page, high-performance glassmorphic administration console served natively from the Central Control Plane.

```
                  [ Central Control Plane (Port :9090) ]
                 /                  |                  \
                /                   |                   \
        [ Linux Agent ]     [ Windows Agent ]     [ Legacy NonStop Node ]
         Supervisor          Supervisor            OTel Syslog Receiver
              |                   |                         |
          Worker VM           Worker Service          EMS Distributor
```

### High-Availability Control Loop:
* **SSE (Server-Sent Events) Pipeline:** Active agent supervisors maintain persistent HTTP pipelines to `http://<control-plane>:9090/api/v1/stream` to receive instant binary upgrade notices and push real-time heartbeats.
* **Zero-Log-Loss Upgrade Pipeline:** Updates are pushed down from the control plane dynamically. The local supervisor intercepts the update, performs an atomic process handoff, verifies worker health, and rolls back instantly to a stable backup (`legacytel-worker.bak`) if any failure is detected.

---

## 📋 2. Installation & Setup of the Central Console

The Central Control Plane is packaged as a static, single-binary server with no external dependencies (compiled using standard library Go).

### A. Starting the Console
To launch the central console inside your workspace or management server:

1. **Start the Control Plane Binary:**
   ```bash
   ./v2/legacytel-controlplane
   ```
   *By default, the server will bind to port `9090` on all local interfaces.*

2. **Accessing the Console:**
   Open any modern, HTML5-compliant web browser and navigate to:
   ```text
   http://localhost:9090
   ```

### B. Configuration Parameters (`config.yaml`)
To customize ports, TLS keys, and outbound SIEM/Splunk exporter endpoints, edit the `config.yaml` file located in the console directory:

```yaml
server:
  host: "0.0.0.0"
  port: 9090
  tls_enabled: true
  cert_file: "./certs/server.crt"
  key_file: "./certs/server.key"

exporters:
  splunk_hec_url: "https://splunk-heavy-forwarder.local:8088/services/collector"
  splunk_token: "11111111-2222-3333-4444-555555555555"
  otlp_endpoint: "http://otel-collector.local:4317"
```

---

## 🖥️ 3. Dashboard Interface: Tab & Screen Directory

The LegacyTel Console is built using modern responsive CSS grids and features a transparent glassmorphic UI. Here is a guided breakdown of each screen element:

### 1. Global Performance Metrics (Top Bar)
Provides an instant security-operations snapshot:
* **Total Hosts:** The total count of registered servers (both modern v2 agents and legacy v1 mainframes).
* **Active Agents:** The number of agents actively sending heartbeats within the last 10 seconds.
* **Logs Processed:** Total cumulative log count received and forwarded to upstream SIEMs since boot.
* **Upgrade Readiness:** The percentage of modern v2 agents running the latest stable release.

### 2. Global OS Selection Panel
Directly below the header is the tab switcher that filters the agent fleet display:
* **🐧 Linux** / **🪟 Windows** / **🍏 macOS**: Displays v2.0.0 nodes. Shows real-time dynamic hardware inventory (CPU cores, RAM size, hypervisor details), active software inventory (installed agent version, OpenSSL/zlib layers), and real-time CPU/RAM usage micro-charts.
* **🏛️ Legacy (v1)**: Displays vintage legacy platforms running the lightweight, high-performance v1.x agent. Platforms shown here include **IBM z/OS Mainframe (SMF)**, **IBM i AS/400 (QAUDJRN)**, **HPE NonStop Tandem (EMS)**, **IBM AIX**, and **Solaris**.

### 3. Fleet Network Topology Map (Landscape Panel)
Spans the full width of the dashboard. Using a dynamic, hardware-accelerated SVG layout, it visually displays:
* **The Center Hub:** Representing the Central Control Plane.
* **Peripheral Spoke Nodes:** Radiating outwards, color-coded by platform and health status (Green for active heartbeats, Blue for active upgrades, Red for offline/unreachable states).
* **IP/Hostname Search Input:** Located at the top right of the topology map. Enter an IP (e.g. `192.168.1.50`) or hostname (e.g. `corp-win-ad`) to instantly highlight the node and display its detailed agent metrics.

### 4. Live Enterprise Security Log Auditor (Bottom-Left Area)
A real-time spreadsheet visualizing active security compliance audits stream. 
* **Custom Row Colorings:** Automatically highlights events based on priority (e.g., successful logins in soft green, privilege escalation failures in amber, user deletions `SA03` or account lockouts `SA08` in red/gray).
* **Taxonomy Codes:** Translates native logs to standard identifiers from `LL01` (successful login) to `CM04` (memory boundary updates).
* **Action Buttons:**
  * **Search Input:** Instantly filters logs by IP, email, username, domain, or raw content.
  * **Export to CSV:** Downloads the filtered dataset directly to your local workstation for spreadsheets or cold archives.

### 5. Central Binary Repository (Bottom-Right Grid)
The release database console.
* Displays all uploaded binaries mapped by platform (Linux, Windows, Darwin) and architecture.
* Automatically organizes releases into **Three Lifecycle Channels**:
  1. `stable` (production-ready deployment target).
  2. `previous` (fallback rollbacks).
  3. `beta` (pre-release testing).
* Includes the **➕ Upload New Package** action button.

---

## 🚀 4. Package Upload, Selective Push, & Fallback Workflows

### A. How to Upload the Latest Agent Binary

Depending on your environment phase, the console handles uploads in one of two ways:

#### 🧪 1. Evaluation & Mockup Mode (Current Environment)
To keep setup zero-dependency and instantly test fleet-wide orchestration, the current console runs in a **Metadata Registration Mode**:
1. Click the **➕ Upload New Package** button in the Central Binary Repository panel.
2. Fill out the popup modal fields (OS, Architecture, Version String, and Target Release Channel).
3. Click **Verify & Upload Binary**.
   * *Note: Instead of asking for a local file, the console registers this version directly into its active in-memory repository database, dynamically generating a unique SHA-256 checksum placeholder. This allows you to immediately schedule and simulate upgrades or rollbacks on any active host card.*

#### 🚀 2. Live Production Mode
In a production deployment, the Control Plane integrates a physical file manager:
1. The upload modal includes a **File Selector** (`<input type="file">`) accepting compiled binary files or zipped archive packages (e.g., `legacytel-worker` or `legacytel-worker.exe`).
2. Upon clicking **Verify & Upload Binary**, the console streams the binary payload to `/api/v1/admin/binaries` and writes the file directly to the Control Plane's host filesystem under the following release structure:
   ```text
   ./dist/binaries/<os>/<arch>/<version>/legacytel-worker
   ```
3. When an agent's Supervisor receives an upgrade command, it makes a secure HTTP/TLS request back to the Control Plane to download this specific executable directly.

---

### B. Pushing Upgrades to the Agent Fleet

#### Option 1: Selective Host Upgrade (Single Server)
1. Navigate to the target server card under the filtered OS tab.
2. Locate the **Current Version** field.
3. Click the blue **Schedule Upgrade** button.
4. Select your target release (e.g. `v2.0.2-stable`) and confirm.
   * *The agent status will instantly switch to **UPGRADING**.*

#### Option 2: Bulk Fleet Upgrade (All Modern Hosts)
1. Locate the **Bulk Upgrade Fleet** control panel.
2. Select the target version from the dropdown menu.
3. Click **Orchestrate Fleet Upgrade**.
   * *All registered v2 agent supervisors will immediately receive a SSE signal to download the payload.*

---

### C. Zero-Log-Loss Hot-Swap & Auto-Rollback Process

When an upgrade command is scheduled, the agent performs the following atomic transition sequence:

```
[ Active Worker PID 1045 ]  <-- (Holds open socket 4317)
           |
[ Supervisor PID 1044 ]     <-- Downloads update, backups PID 1045
           |
[ Swaps Binary Files ]      <-- Overwrites legacytel-worker atomically
           |
[ Spawn Worker PID 1055 ]   <-- Receives Socket via FD handoff
           |
[ Health Verification ]     -- (Failure detected?)
          / \
         /   \
  [YES: ROLLBACK] [NO: CLEANUP]
        |               |
 restores PID 1045   removes backup
```

1. **Backup Creation:** The supervisor copies the current stable binary `legacytel-worker` to `legacytel-worker.bak`.
2. **Atomic Swap:** The supervisor downloads the upgraded binary, writes it to a temporary file `legacytel-worker.tmp`, and renames it to `legacytel-worker` (an atomic file system operation).
3. **Descriptor Handoff:** The supervisor spawns the new worker process. Using Unix Domain Sockets or Windows IPC, the open listening sockets (e.g., Syslog UDP `514` or OTel TCP `4317`) are handed directly to the new worker process without ever closing the network socket. This ensures **zero packet drop** during upgrades.
4. **Health Check Window:** The supervisor monitors the new worker process for **5 seconds** to ensure it remains active, healthy, and accepts connections.
5. **Automated Rollback:** If the new worker crashes or fails health checks within this window:
   * The supervisor issues a termination signal to the failing process.
   * It deletes the corrupt binary.
   * It renames `legacytel-worker.bak` back to `legacytel-worker`.
   * It spawns the original stable worker process and logs the failure to the Control Plane.

---

## 🔍 5. Troubleshooting & Diagnostics

### Control Plane Troubleshooting

#### 1. Port Conflict (`Port 9090 already in use`)
* **Symptom:** Control plane server crashes on startup.
* **Resolution:** Find and terminate the process holding the port:
  ```bash
  lsof -i :9090
  kill -9 <PID>
  ```
  Or change the port in `config.yaml` under `server.port`.

#### 2. Duplicate Version Rejection
* **Symptom:** The console rejects a package upload with a `Status Conflict (409)` error.
* **Resolution:** Ensure the package you are uploading has a distinct version string (e.g. `v2.0.2`) from existing active binaries.

---

### Agent Troubleshooting

#### 1. Agent Status Shows `OFFLINE`
* **Symptom:** Target server does not appear active in the console and status is red.
* **Resolution:**
  * Verify firewalls allow outbound TCP connections to the control plane IP on port `9090`.
  * Check the local supervisor log file:
    * Linux/macOS: `/opt/legacytel/logs/supervisor.log`
    * Windows: `C:\Program Files\LegacyTel\logs\supervisor.log`
  * Test connectivity manually:
    * `curl -v http://<control-plane-ip>:9090/api/v1/register`

#### 2. Log Ingestion Port Conflicts (Syslog `514` or OTel `4317` blocked)
* **Symptom:** Worker agent starts but cannot collect local logs.
* **Resolution:**
  * Check if another syslog daemon (like `rsyslog` or `syslog-ng`) is already bound to port `514`:
    ```bash
    netstat -tulpn | grep 514
    ```
  * Either disable the conflicting daemon, or configure the conflicting daemon to forward local logs to `127.0.0.1:514` instead.

#### 3. Continuous Crash Loops and Rollbacks
* **Symptom:** Worker agent repeatedly rolls back to the `.bak` binary.
* **Resolution:**
  * Inspect the worker's crash dump logs:
    ```bash
    cat /opt/legacytel/logs/worker_stderr.log
    ```
  * Confirm target library dependencies (such as libc or OpenSSL) match the compiled agent binary architecture and platform.
