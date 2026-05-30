# LegacyTel Central: Observability Control Plane & Fleet Management Console

**LegacyTel Central** is a high-performance, lightweight, open-source centralized control plane, fleet orchestrator, and SIEM gateway written in pure Go. It is designed to register, monitor, secure, and dynamically upgrade the **LegacyTel Observability Agent** fleet across enterprise multi-generation operating systems (Linux, Windows, macOS, IBM z/OS Mainframe, IBM i AS/400, and HPE NonStop Tandem).

Served as a static single binary with zero external runtime dependencies, LegacyTel Central provides a robust, security-first, unprivileged control node that handles high-throughput log aggregation and active fleet lifecycle orchestration.

---

## 🏛️ Core Features

* **Central Fleet Management Console:** A stunning single-page glassmorphic dashboard showcasing real-time hardware specs (CPUs, RAM, hypervisor vendor), active software inventory packages, and dynamic CPU/RAM resource utilization micro-charts for all connected nodes.
* **Interactive Spoke Topology Map:** A hardware-accelerated, dynamic SVG network topology visualizer mapping target servers (spokes) to the Central Control Plane (hub), featuring an instant IP/hostname search highlight filter.
* **Live Enterprise Security Log Auditor:** A real-time tabular SIEM-neutral audit stream normalizer translating raw logs into standard security taxonomy codes (from `LL01` login to `CM04` memory shift). Supports custom warning highlight colorings, direct log content searching, and one-click local CSV export.
* **Central Binary Repository:** An active package manager that hosts and deploys agent binaries organized into three structured lifecycle channels: `stable` (Latest Production), `previous` (Stable Rollback), and `beta` (Pre-Release Testing).
* **Zero-Log-Loss Handoff Orchestrator:** Works in tandem with the edge Supervisor. During scheduled upgrades, the Control Plane pushes updates that the agent supervisor applies atomically, sharing open listening descriptors (Syslog port `514` or OTel port `4317`) so **no network packets are dropped** during restarts.
* **Self-Healing & Auto-Rollback:** Features a persistent health-verification loop. If an upgraded agent fails validation checks within 5 seconds of boot, the control plane logs the failure, and the supervisor automatically reverts to the backup binary (`legacytel-worker.bak`).
* **SIEM-Neutral Exporters:** Direct native out-of-the-box pipeline support for forwarding telemetry securely over HTTPS/gRPC to **Splunk Cloud (HEC)**, **Microsoft Sentinel (Azure Log Analytics)**, **Google SecOps (Chronicle)**, and **Cribl Stream**.

---

## 🚀 Getting Started

LegacyTel Central runs as a standalone Go binary with an embedded HTTP/SSE web interface.

### 1. Compile the Control Plane
Ensure you have the Go compiler installed (Go v1.20+ recommended), and compile the binary in the root directory:
```bash
go build -o legacytel-controlplane cmd/controlplane/main.go
```

### 2. Configure the Control Plane (`config.yaml`)
Establish server bounds and outbound SIEM ingestion endpoints inside the local configuration:
```yaml
server:
  host: "0.0.0.0"
  port: 9090
  tls_enabled: true
  cert_file: "./certs/server.crt"
  key_file: "./certs/server.key"

exporters:
  splunk_hec_url: "https://splunk-hec.domain.com:8088/services/collector"
  splunk_token: "${SPLUNK_HEC_TOKEN}"
  otlp_endpoint: "http://otel-collector.domain.com:4317"
```

### 3. Run the Control Plane Server
```bash
./legacytel-controlplane
```
*Access the control plane console in your browser at:* **`http://localhost:9090`**

---

## 🔒 Security & Data Encryption (mTLS)

LegacyTel Central strictly enforces **Mutual TLS (mTLS 1.2 / 1.3)** for all incoming agent connections, registration requests, SSE heartbeat signals, and log telemetry:
* Every target node agent must present a valid client certificate signed by your enterprise Root CA to establish communications.
* Private keys are secured locally on the host under strict permissions (`chmod 600`).
* Sensitive API tokens or shared access keys are loaded dynamically from target OS Environment variables at runtime rather than stored cleartext inside `config.yaml`.

---

## 📂 Project Structure

```text
├── cmd/
│   ├── controlplane/   # Central dashboard, registry database, and API endpoints
│   ├── supervisor/     # Edge agent supervisor (upgrades, rollbacks, and health loops)
│   └── worker/         # Active unprivileged OTel log collector and telemetry worker
├── docs/               # Enterprise manual repository (Deployment, Security, SIEM, Cribl)
├── pkg/
│   ├── dashboard/      # Glassmorphic CSS/HTML console template and assets
│   └── inventory/      # Hardware inventory sweeps and registry scanning scripts
├── scripts/            # Automated Linux/PowerShell deployment bootstrap scripts
└── go.mod              # Standard dependency-free module definition
```

---

## 💻 System Resource Sizing Recommendations

Recommended specs for hosting the Centralized Control Plane and SIEM Gateway based on your daily data volume requirements:

* **Small (Dev/Test - < 5k EPS):** 2 vCPUs, 4 GB RAM, 500 write IOPS SSD storage.
* **Medium (Enterprise - < 25k EPS):** 4 vCPUs, 8 GB RAM, 2,500 write IOPS SSD storage.
* **Large (Hyperscale - 100k+ EPS):** 8–16 vCPUs, 16–32 GB RAM, 10,000+ write IOPS NVMe storage.
