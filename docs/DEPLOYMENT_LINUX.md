# LegacyTel: Linux Platform Standalone Deployment Guide

This document is a standalone, self-contained deployment manual for **Linux Systems Administrators** and **SecOps Engineers**. It details how to install, configure, secure, and manage the **LegacyTel v2.0.0 Observability Agent** on Linux platforms.

---

## 1. Supported Distributions & Prerequisites

LegacyTel is designed to be extremely lightweight (written in Go standard-library) and supports all major modern enterprise Linux distributions:
* **Ubuntu** 18.04 LTS, 20.04 LTS, 22.04 LTS, and 24.04 LTS
* **Red Hat Enterprise Linux (RHEL)** 7, 8, and 9 (and derivatives like Rocky Linux, AlmaLinux, and CentOS)
* **SUSE Linux Enterprise Server (SLES)** 12 and 15
* **Debian** 10, 11, and 12

### Network & Port Requirements:
Ensure target Linux nodes can communicate bidirectionally with the Control Plane and local logging services:
* **Port `9090` (TCP):** Outbound communication to the Central Control Plane for heartbeats and binary upgrades.
* **Port `514` (UDP/TCP):** Local syslog ingestion listener port (if capturing from local engines like `rsyslog`).
* **Port `4317` / `4318` (TCP):** OpenTelemetry gRPC / HTTP active worker ingress sockets.

---

## 2. Ingestion & Process Architecture (Supervisor-Worker Split)

LegacyTel v2.0.0 operates as an unprivileged dual-process service:
1. **Supervisor Process (`legacytel-supervisor`):** Acts as the process supervisor and communications proxy. It monitors the active worker's health, handles live hot-swap upgrades, and manages file descriptors.
2. **Worker Process (`legacytel-worker`):** Ingests raw local logs (syslog, system audits), normalizes them to OTel format, and streams them upstream.

---

## 3. Installation Methods

Select the appropriate installation workflow based on your environment's privilege standard.

### Method A: Automated Bash Installation (Recommended)
Run the following zero-dependency curl installer to download, place, and register the service:

```bash
curl -s http://localhost:9090/scripts/deploy_agent.sh | bash
```

> [!TIP]
> **Privilege Detection Rules:**
> * If executed as **root (`sudo`)**, the installer places the binaries under `/opt/legacytel`, registers a native `systemd` daemon, and sets automatic startup.
> * If executed as a **standard user**, the installer installs local binaries under `$HOME/legacytel`, creates background service scripts using `nohup`, and maps unprivileged paths.

---

### Method B: Manual Installation & Service Registration

For environments requiring strict compliance control, follow these step-by-step commands to install as root:

1. **Create the Installation Directories:**
   ```bash
   sudo mkdir -p /opt/legacytel/{bin,config,certs,logs}
   ```

2. **Download the Stable Binaries:**
   ```bash
   sudo wget http://localhost:9090/binaries/linux/amd64/stable/legacytel-supervisor -O /opt/legacytel/bin/legacytel-supervisor
   sudo wget http://localhost:9090/binaries/linux/amd64/stable/legacytel-worker -O /opt/legacytel/bin/legacytel-worker
   sudo chmod +x /opt/legacytel/bin/legacytel-*
   ```

3. **Configure the Agent (`/opt/legacytel/config/agent.yaml`):**
   ```yaml
   control_plane: "http://<control-plane-ip>:9090"
   node_id: "node-linux-web-01"
   ingest:
     syslog_port: 514
     otlp_grpc_port: 4317
   ```

4. **Register the Native Systemd Daemon:**
   Create the service configuration `/etc/systemd/system/legacytel-supervisor.service`:
   ```ini
   [Unit]
   Description=LegacyTel Agent Supervisor
   After=network.target

   [Service]
   Type=simple
   User=nobody
   WorkingDirectory=/opt/legacytel
   ExecStart=/opt/legacytel/bin/legacytel-supervisor
   Restart=always
   RestartSec=5
   LimitNOFILE=65535

   [Install]
   WantedBy=multi-user.target
   ```

5. **Start and Enable the Daemon:**
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable legacytel-supervisor
   sudo systemctl start legacytel-supervisor
   ```

---

## 4. Operating System Performance Tuning

For high-concurrency production Linux nodes handling high log volumes (exceeding 15,000 events/sec), tune the following kernel parameters:

### File Descriptor Boundaries
Configure the socket boundary limits inside `/etc/security/limits.conf`:
```text
nobody          soft    nofile          65535
nobody          hard    nofile          65535
```

### UDP Network Buffer Inodes
Tune TCP/UDP socket buffer sizes in `/etc/sysctl.conf` to prevent dropped frames during heavy utilization spikes:
```text
net.core.rmem_max = 16777216
net.core.rmem_default = 8388608
net.core.netdev_max_backlog = 10000
```
*Apply changes immediately:* `sudo sysctl -p`

---

## 5. Security & mTLS Proxy Setup

To encrypt communications with the Central Control Plane, place the standard cryptographic certificates in the local directory:

1. **Deploy Certificates:**
   Copy these keys generated from the control plane to `/opt/legacytel/certs/`:
   * `root_ca.crt` (Control Plane Root CA)
   * `linux_client.crt` (Client Certificate)
   * `linux_client.key` (Client Private Key)

2. **Secure Key Permissions:**
   Restrict certificate access rules strictly:
   ```bash
   sudo chown -R nobody:nogroup /opt/legacytel/certs/
   sudo chmod 600 /opt/legacytel/certs/linux_client.key
   sudo chmod 644 /opt/legacytel/certs/linux_client.crt
   ```

---

## 6. Verification & Troubleshooting

### Check Service Status
```bash
sudo systemctl status legacytel-supervisor
```

### Inspect Live Logs
Monitor the stdout and stderr streams of the supervisor and worker:
```bash
# Supervisor Logs
tail -n 50 /opt/legacytel/logs/supervisor.log

# Worker Logs
tail -n 50 /opt/legacytel/logs/worker_stderr.log
```

### Common Issues:
1. **Permission Denied binding to port `514`:**
   * **Cause:** Standard unprivileged users (like `nobody`) cannot bind to well-known ports below 1024.
   * **Solution:** Assign capabilities to the supervisor binary:
     ```bash
     sudo setcap 'cap_net_bind_service=+ep' /opt/legacytel/bin/legacytel-supervisor
     ```
2. **Control Plane Connection Timeouts:**
   * **Cause:** Networking or firewalls blocking port 9090.
   * **Solution:** Verify the path using `curl` or `nc`:
     ```bash
     nc -zv <control-plane-ip> 9090
     ```
