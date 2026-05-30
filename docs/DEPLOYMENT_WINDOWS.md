# LegacyTel: Windows Platform Standalone Deployment Guide

This document is a standalone, self-contained deployment manual for **Windows Systems Administrators** and **SecOps Operators**. It details how to install, configure, secure, and manage the **LegacyTel v2.0.0 Observability Agent** on Windows Server and Desktop platforms.

---

## 1. Supported Versions & Prerequisites

LegacyTel supports the following Microsoft Windows releases (x86_64 and ARM64 architectures):
* **Windows Server:** 2012 R2, 2016, 2019, 2022, and Core variations
* **Windows Desktop:** Windows 10 and 11

### Network Port Requirements:
Confirm local host and network firewalls permit bidirectional sockets:
* **Port `9090` (TCP):** Outbound communication to the Central Control Plane for SSE heartbeats and dynamic binaries updates.
* **Port `4317` / `4318` (TCP):** Inbound gRPC / HTTP active worker listener sockets.

---

## 2. Ingestion & Registry Permissions

The Windows LegacyTel agent utilizes an unprivileged process model split between a **Supervisor** service and a active OTel **Worker** subprocess. 

For the worker to scan hardware assets and installed packages (Software Inventory), ensure the executing user account (or the default `NT AUTHORITY\LocalService` account) possesses read permissions for the following Registry directories:
* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
* `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall`

---

## 3. Installation Methods

Select the appropriate installation workflow based on target environment privilege levels.

### Method A: Automated PowerShell Installation (Recommended)
From an elevated or user-level PowerShell terminal, run this self-contained script:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
Invoke-Expression (Invoke-WebRequest -Uri "http://localhost:9090/scripts/deploy_agent.ps1" -UseBasicParsing)
```

> [!TIP]
> **Privilege Auto-Detection:**
> * **Administrator Command:** LegacyTel is installed under `C:\Program Files\LegacyTel`, registered as a native Windows Service named `LegacyTelSupervisor`, and configured to boot automatically on system launch.
> * **Standard User Command:** Installed under `%LOCALAPPDATA%\LegacyTel` and registered inside the current user's registry startup run key to launch silently in the background on user login.

---

### Method B: Manual Command-Line Installation

For managed enterprise environments (e.g. SCCM, Intune, Active Directory GPO), follow these manual commands:

1. **Create the Installation Directories:**
   Create these folders from a command prompt:
   ```cmd
   mkdir "C:\Program Files\LegacyTel\bin"
   mkdir "C:\Program Files\LegacyTel\config"
   mkdir "C:\Program Files\LegacyTel\certs"
   mkdir "C:\Program Files\LegacyTel\logs"
   ```

2. **Acquire the Executable Packages:**
   Download the stable Windows binaries:
   ```powershell
   Invoke-WebRequest -Uri "http://localhost:9090/binaries/windows/amd64/stable/legacytel-supervisor.exe" -OutFile "C:\Program Files\LegacyTel\bin\legacytel-supervisor.exe"
   Invoke-WebRequest -Uri "http://localhost:9090/binaries/windows/amd64/stable/legacytel-worker.exe" -OutFile "C:\Program Files\LegacyTel\bin\legacytel-worker.exe"
   ```

3. **Configure the Agent Settings (`C:\Program Files\LegacyTel\config\agent.yaml`):**
   ```yaml
   control_plane: "http://<control-plane-ip>:9090"
   node_id: "node-win-ad-01"
   ingest:
     otlp_grpc_port: 4317
   ```

4. **Register the Service using `sc.exe`:**
   In an elevated cmd terminal, register the service:
   ```cmd
   sc.exe create LegacyTelSupervisor binPath= "C:\Program Files\LegacyTel\bin\legacytel-supervisor.exe" start= auto DisplayName= "LegacyTel Agent Supervisor"
   sc.exe description LegacyTelSupervisor "Monitors LegacyTel active observability workers and handles live upgrades."
   ```

5. **Start the Service:**
   ```cmd
   sc.exe start LegacyTelSupervisor
   ```

---

## 4. Securing Data in Transit (mTLS Proxy Setup)

To secure communications with the Central Control Plane over public or shared private networks, copy the target certs and restrict access:

1. **Copy Certificates:**
   Place the certificate files in `C:\Program Files\LegacyTel\certs\`:
   * `root_ca.crt` (Control Plane Root CA)
   * `windows_client.crt` (Client Certificate)
   * `windows_client.key` (Client Private Key)

2. **Restrict ACL Access (File Security):**
   Right-click `windows_client.key` -> **Properties** -> **Security** -> **Advanced**.
   * Remove inherited permissions.
   * Assign read permissions strictly to `SYSTEM`, `Administrators`, and the specific account running the service (e.g. `LocalService`).

---

## 5. Verification & Diagnostics

### Check Service Status (PowerShell)
```powershell
Get-Service LegacyTelSupervisor
```

### Inspect Log Output
View active metrics and crash logs directly from the terminal or text editor:
```powershell
# Live supervisor status
Get-Content -Path "C:\Program Files\LegacyTel\logs\supervisor.log" -Tail 50 -Wait

# Worker stderr crashes
Get-Content -Path "C:\Program Files\LegacyTel\logs\worker_stderr.log" -Tail 50
```

### Common Issues:
1. **Service Fails to Start (Error 1053):**
   * **Cause:** The service binary is missing or cannot find the required `.yaml` configuration file.
   * **Solution:** Verify `agent.yaml` is correctly structured and placed inside `C:\Program Files\LegacyTel\config\`.
2. **Network Connection Refused:**
   * **Cause:** Local Windows Defender Firewall blocking outbound communication on port 9090.
   * **Solution:** Open PowerShell as Administrator and add an outbound rule:
     ```powershell
     New-NetFirewallRule -DisplayName "LegacyTel Outbound Control Plane" -Direction Outbound -LocalPort Any -Protocol TCP -RemotePort 9090 -Action Allow
     ```
3. **Registry Software Inventory Scans Fail:**
   * **Cause:** Executing user has restricted registry key permissions.
   * **Solution:** Verify the account running the service can read subkeys in `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`.
