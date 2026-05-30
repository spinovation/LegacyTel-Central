# LegacyTel v2.0.0: Unified SIEM Ingestion & Fleet Deployment Manual
## Splunk, Microsoft Sentinel, and Google SecOps Ingest Architectures

This manual provides security engineers, platform operators, and cloud architects with exact technical workflows, architecture paths, and deployment steps for integrating the **LegacyTel Observability Agent** with modern enterprise Security Information and Event Management (SIEM) systems.

---

## 🏛️ 1. Ingestion Paths: Direct Agent vs. Collector Gateway

LegacyTel supports two structural models for forwarding telemetry to downstream SIEMs.

### Model A: Direct Agent-to-SIEM Ingestion (Decentralized)
Each target server (Linux, Windows, macOS) runs the unprivileged Supervisor-Worker split agent. The active worker packages local system audits and forwards them directly to the cloud-hosted SIEM endpoint over secure HTTPS/OTLP.

* **Pros:** Highly resilient, zero single point of failure in the network pipeline.
* **Cons:** Requires target hosts to have direct outbound internet access to SIEM cloud endpoints, increasing security perimeter exposure.

```
 [ Local Host Server ] --( HTTPS / OTLP Outbound )--> [ Cloud SIEM (Splunk/Sentinel/SecOps) ]
```

---

### Model B: Gateway Ingestion (Centralized - Recommended)
Target hosts on private corporate subnets stream their normalized audit records locally over encrypted mTLS to a centralized **LegacyTel Collector Gateway** (running on a hardened local Linux server). The Gateway acts as the sole outbound bridge, bundling and forwarding the entire fleet's data to the SIEM.

* **Pros:** Secure; target servers require zero direct outbound internet access. Enables local log caching, volume throttling, and central key management.
* **Cons:** Intermediate collector servers require high-availability configurations.

```
 [ Fleet Node 1 ] --( Local mTLS )--> [ LegacyTel Gateway ] --( HTTPS / OTLP )--> [ Cloud SIEM ]
 [ Fleet Node 2 ] --( Local mTLS )-->
```

---

## 📊 2. SIEM Integration Workflows

Follow these platform configurations to set up ingestion at the destination SIEM.

### Ingestion Scheme: Normalized Event Checklist
Regardless of the target SIEM, LegacyTel normalizes all legacy and modern operating system audits to standard event compliance taxonomy codes (e.g. `LL01` login, `SA03` user deletion, `PA02` authority violation, `CM04` memory shift).

---

### A. Splunk Enterprise & Splunk Cloud (HEC)
Splunk ingests events via the **HTTP Event Collector (HEC)** using JSON payloads.

#### 1. Setup Splunk HEC:
1. Log in to your Splunk console. Navigate to **Settings** > **Data Inputs** > **HTTP Event Collector**.
2. Click **New Token**. Define a name (e.g., `LegacyTel-Ingest`), choose your source type (recommended: `_json` or custom `legacytel:audit`), and select the target index.
3. Save and copy the generated **Token Value**.

#### 2. Configure LegacyTel Gateway or Direct Agent (`config.yaml`):
```yaml
exporters:
  splunk:
    enabled: true
    hec_url: "https://splunk-heavy-forwarder.local:8088/services/collector/event"
    hec_token: "${SPLUNK_HEC_TOKEN}" # Dynamically loaded from OS Env
    batch_size: 100
    flush_interval_ms: 1000
```

---

### B. Microsoft Sentinel (Azure Log Analytics)
Microsoft Sentinel ingests data using the **Log Analytics Workspace Data Collector API** or the modern **Azure Monitor Agent (AMA) OTLP pipeline**.

#### 1. Setup Azure Log Analytics Ingestion:
1. Open your **Azure Portal** and navigate to your **Log Analytics Workspace** (linked to Sentinel).
2. Go to **Settings** > **Agents** > **Log Analytics agent instructions**.
3. Copy the **Workspace ID** and the **Primary Key (Shared Key)**.

#### 2. Configure LegacyTel Gateway or Direct Agent (`config.yaml`):
```yaml
exporters:
  azure_sentinel:
    enabled: true
    workspace_id: "${SENTINEL_WORKSPACE_ID}"
    shared_key: "${SENTINEL_SHARED_KEY}"
    custom_log_table: "LegacyTel_CL" # Automatically creates LegacyTel_CL custom table in Azure
```

---

### C. Google SecOps (Chronicle)
Google SecOps (Chronicle) ingests telemetry via standard **gRPC OTLP Ingestion** or through the **Google Chronicle Ingestion API** / **Chronicle Forwarder**.

#### 1. Setup Ingestion via Google Chronicle Forwarder:
1. Deploy a standard **Chronicle Forwarder** container or virtual appliance within your environment.
2. Configure a forwarder configuration block mapping an open syslog port (e.g. `10514`) or OTLP port (e.g. `4317`):
   ```json
   {
     "sources": [
       {
         "connection": {
           "port": 10514,
           "protocol": "TCP"
         },
         "data_type": "OTEL_LOGS",
         "source_type": "SYSLOG"
       }
     ]
   }
   ```

#### 2. Configure LegacyTel Gateway or Direct Agent (`config.yaml`):
```yaml
exporters:
  otlp_http:
    enabled: true
    endpoint: "http://google-chronicle-forwarder.local:4318/v1/logs"
```

---

## 🚀 3. Agent Platform Installation & Log Harvesting Guide

The LegacyTel agent runs seamlessly across multiple platforms, compiling dynamic inventories and harvesting operational logs to stream back to the Central Control Plane or Gateway.

---

### A. Linux Node Deployment
* **Installation:** Run the automated installer: `curl -s http://localhost:9090/scripts/deploy_agent.sh | bash`.
* **Log Harvesting Mechanism:**
  * **System Audits:** TTT (Transaction Tracking Tool), PAM authentication module stack, and native syslog files are watched by the worker process utilizing persistent file watchers (`tail` implementation).
  * **Application Log Pulling:** The worker targets custom log files defined in `/opt/legacytel/config/agent.yaml` under `harvest_paths` (e.g. `/var/log/nginx/access.log`, `/var/log/mysql/error.log`).
* **Inventory Compilation:**
  * **Hardware Inventory:** Reads from `/sys/class/dmi/id/` (falls back to native Go-CPUID assembly sweeps to extract exact CPU registers and L1/L2 cache specs if access is restricted).
  * **Software Inventory:** Parses package registries using local package indexes (`dpkg -l` on Debian/Ubuntu, `rpm -qa` on RHEL/SLES).

---

### B. Hypervisor (Bare-Metal ESXi) Deployment
* **Installation:** In bare-metal virtualization platforms, LegacyTel runs inside the hypervisor management console (or as a secure virtual appliance).
* **Log Harvesting Mechanism:**
  * Pulls VM creation, termination, migration, and hypervisor console access commands directly from `/var/log/hostd.log` and `/var/log/vobd.log`.
* **Inventory Compilation:**
  * **Hardware Inventory:** Reads Bare-Metal CPU cores, hypervisor motherboard specs, RAM topologies, and physical network adapters from standard ESXi management APIs.
  * **Software Inventory:** Lists active virtual machine descriptors, ESXi operating version, and hypervisor patches.

---

### C. Windows Server & Desktop Deployment
* **Installation:** Deploy via PowerShell: `Set-ExecutionPolicy Bypass ... Invoke-Expression ... deploy_agent.ps1`.
* **Log Harvesting Mechanism:**
  * **Event Log Harvesting:** Subscribes to the **Windows Event Log API** to capture security event journals, application error registries, and system configurations.
  * **Application Log Pulling:** Watches local logs (e.g. IIS logs, SQL Server traces) via directory-tailing loops.
* **Inventory Compilation:**
  * **Hardware Inventory:** Executes WMI (Windows Management Instrumentation) queries to determine RAM profiles and processor details.
  * **Software Inventory:** Performs recursive Registry scans on `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` (and `Wow6432Node`) to list all installed enterprise products.

---

### D. macOS Workstation Deployment
* **Installation:** Run the CLI installer and load the system PLIST daemon: `sudo launchctl load -w /Library/LaunchDaemons/com.legacytel.supervisor.plist`.
* **Log Harvesting Mechanism:**
  * **System Audits:** Tailors native `/var/log/system.log` and PAM authentication actions.
  * **Application Log Pulling:** Watches developer directories (e.g., local server traces or container runtime logs).
* **Inventory Compilation:**
  * **Hardware Inventory:** Executes native system profile frameworks (`system_profiler SPHardwareDataType`) to query CPU, RAM, and battery wear.
  * **Software Inventory:** Scans local applications folders (`/Applications` and `~/Applications`) and homebrew installation indices.

---

### E. Legacy Systems (Mainframe & Midrange) Deployment
* **Installation:** Compiled as a native static binary (e.g., `GOOS=nonstop` for HPE NonStop Tandem, compiled using IBM Open Enterprise SDK for Go for IBM z/OS).
* **Log Harvesting Mechanism:**
  * **IBM z/OS:** Captures native binary **SMF (System Management Facility)** logs (SMF 80 RACF and SMF 30 job steps). Decodes binary EBCDIC strings automatically to ASCII.
  * **IBM i AS/400:** Hooks into the **QAUDJRN** security audit journal via an exit program to stream auditing queues.
  * **HPE NonStop Tandem:** Binds to the **EMS ($ZEMS)** distributor queue to consume TACL, SAFE, and TMF subsystem logs.
* **Inventory Compilation:**
  * **Hardware Inventory:** Queries native LPAR hardware architectures (zEnterprise, AS/400 models, NonStop Itanium/x86 modules).
  * **Software Inventory:** Scans Guardian and Safeguard profile lists, mainframe program library indices (PDS members), and LPAR configurations.
