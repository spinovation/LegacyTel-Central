# LegacyTel: macOS Platform Standalone Deployment Guide

This document is a standalone, self-contained deployment manual for **macOS Platform Administrators** and **SecOps Engineers**. It details how to install, configure, secure, and manage the **LegacyTel v2.0.0 Observability Agent** on macOS Server and Workstation environments.

---

## 1. Supported Releases & Prerequisites

LegacyTel is compiled into a lightweight native binary and supports the following Apple macOS versions (Intel x86_64 and Apple Silicon M1/M2/M3 ARM64 architectures):
* macOS 10.15 (Catalina)
* macOS 11 (Big Sur)
* macOS 12 (Monterey)
* macOS 13 (Ventura)
* macOS 14 (Sonoma)
* macOS 15 (Sequoia)

### Network Port Requirements:
Ensure target macs can connect bidirectionally with local log systems and the Control Plane:
* **Port `9090` (TCP):** Outbound communication to the Central Control Plane for SSE heartbeats and dynamic binaries updates.
* **Port `4317` / `4318` (TCP):** Inbound gRPC / HTTP active worker listener sockets.

---

## 2. Ingestion & Security Entitlements

The macOS agent operates under an unprivileged split-process design comprising a **Supervisor** and a active observability **Worker** subprocess.

For security classification, target nodes require access to the hardware descriptor values:
* If running as a privileged daemon, the supervisor reads standard DMI values.
* If executing as a standard user, the agent automatically executes a fast command-line fallback utilizing the native `system_profiler SPHardwareDataType` compiler.

---

## 3. Installation Methods

Select the appropriate installation workflow based on target environment privileges.

### Method A: Automated CLI Installation (Recommended)
From a standard Terminal console, run this single-line download command:

```bash
curl -s http://localhost:9090/scripts/deploy_agent.sh | bash
```

> [!TIP]
> **Privilege Auto-Detection Rules:**
> * If executed as **root (`sudo`)**, the installer places the files under `/opt/legacytel`, registers a native launchd plist under `/Library/LaunchDaemons`, and starts the service.
> * If executed as a **standard user**, the files are placed under `$HOME/legacytel`, and launched as a background user process using `nohup` or a user-level launchd plist under `$HOME/Library/LaunchAgents`.

---

### Method B: Manual Installation & launchd Service Setup

Follow these exact steps to register the agent as a system-wide daemon:

1. **Create the Installation Directory Structures:**
   ```bash
   sudo mkdir -p /opt/legacytel/{bin,config,certs,logs}
   ```

2. **Download Target Executables:**
   ```bash
   sudo curl -s http://localhost:9090/binaries/darwin/amd64/stable/legacytel-supervisor -o /opt/legacytel/bin/legacytel-supervisor
   sudo curl -s http://localhost:9090/binaries/darwin/amd64/stable/legacytel-worker -o /opt/legacytel/bin/legacytel-worker
   sudo chmod +x /opt/legacytel/bin/legacytel-*
   ```

3. **Bypass Apple Gatekeeper Quarantine Policies:**
   Because enterprise binary binaries are downloaded directly via curl, strip the macOS quarantine attribute to prevent execution blocks:
   ```bash
   sudo xattr -rd com.apple.quarantine /opt/legacytel/bin/
   ```

4. **Configure the Agent Settings (`/opt/legacytel/config/agent.yaml`):**
   ```yaml
   control_plane: "http://<control-plane-ip>:9090"
   node_id: "node-mac-dev-01"
   ingest:
     otlp_grpc_port: 4317
   ```

5. **Create the launchd Plist Config File:**
   Create `/Library/LaunchDaemons/com.legacytel.supervisor.plist`:
   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
   <plist version="1.0">
   <dict>
       <key>Label</key>
       <string>com.legacytel.supervisor</string>
       <key>ProgramArguments</key>
       <array>
           <string>/opt/legacytel/bin/legacytel-supervisor</string>
       </array>
       <key>RunAtLoad</key>
       <true/>
       <key>KeepAlive</key>
       <true/>
       <key>WorkingDirectory</key>
       <string>/opt/legacytel</string>
       <key>StandardOutPath</key>
       <string>/opt/legacytel/logs/launchd_stdout.log</string>
       <key>StandardErrorPath</key>
       <string>/opt/legacytel/logs/launchd_stderr.log</string>
   </dict>
   </plist>
   ```

6. **Load and Start the Service Daemon:**
   ```bash
   sudo launchctl load -w /Library/LaunchDaemons/com.legacytel.supervisor.plist
   ```

---

## 4. Securing Data in Transit (mTLS Proxy Setup)

To encrypt communications with the Central Control Plane over corporate networks, place the keys in the local directory:

1. **Copy Certificates:**
   Deploy these files to `/opt/legacytel/certs/`:
   * `root_ca.crt` (Control Plane Root CA)
   * `darwin_client.crt` (Client Certificate)
   * `darwin_client.key` (Client Private Key)

2. **Restrict Key Access Permissions:**
   Restrict file reading rights strictly to the system owner:
   ```bash
   sudo chown -R root:wheel /opt/legacytel/certs/
   sudo chmod 600 /opt/legacytel/certs/darwin_client.key
   sudo chmod 644 /opt/legacytel/certs/darwin_client.crt
   ```

---

## 5. Verification & Diagnostics

### Check Service Status (launchd)
```bash
sudo launchctl list | grep com.legacytel
```

### Inspect Output Logs
View active metric telemetry and crash reports directly:
```bash
# Live supervisor status
tail -f /opt/legacytel/logs/supervisor.log

# Worker stderr crashes
tail -n 50 /opt/legacytel/logs/worker_stderr.log
```

### Stopping and Removing the Service
If you need to halt and remove the daemon:
```bash
sudo launchctl unload -w /Library/LaunchDaemons/com.legacytel.supervisor.plist
sudo rm /Library/LaunchDaemons/com.legacytel.supervisor.plist
```

### Common Issues:
1. **Quarantine Block (`Operation not permitted` or `developer cannot be verified`):**
   * **Cause:** macOS Gatekeeper blocking execution of downloaded binaries.
   * **Solution:** Strip quarantine attributes:
     ```bash
     sudo xattr -d com.apple.quarantine /opt/legacytel/bin/legacytel-supervisor
     ```
2. **Launchd Fails to Load Plist (`Service is disabled`):**
   * **Cause:** The plist configuration is loaded but has the disabled flag set in database.
   * **Solution:** Force enable the service by using the `-w` flag during loading:
     ```bash
     sudo launchctl load -w /Library/LaunchDaemons/com.legacytel.supervisor.plist
     ```
