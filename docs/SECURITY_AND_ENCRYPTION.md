# LegacyTel v2.0.0: Enterprise Security, Data Encryption, & Compliance Manual
## Complete Guide to Data In-Transit and At-Rest Cryptography

Security is the core foundation of LegacyTel. As an enterprise log collector designed to transport sensitive authentication, configuration, and privilege access logs, LegacyTel implements strict cryptographic controls to ensure complete confidentiality, integrity, and authenticity.

---

## 🏛️ 1. Cryptography Architecture Overview

LegacyTel enforces a strict security envelope from the moment a log is generated at the source down to its ingestion at the final SIEM index.

```
 [ Local Worker Agent ]                  [ LegacyTel Gateway ]                [ Destination / SIEM ]
 ======================                  =====================                ======================
  - Local Log Ingestion --[ AES-256 ]-->  - Spools to SQLite   --[ HTTPS ]-->   1. Splunk Cloud
  - Active Inventory    --[ mTLS 1.3 ]--> - Decodes & Bundles  --[ HTTPS ]-->   2. MS Sentinel Log Analytics
  - Environment Audit                     - Enforces Proxy                      3. Google SecOps (Chronicle)
```

---

## 🔒 2. Encryption in Transit (Data Protection)

All network traffic traversing intermediate subnets or public cloud environments must be encrypted. LegacyTel implements standard-library TLS configurations to guarantee zero-cleartext transmission.

### A. Agent-to-Gateway & Agent-to-Control Plane (mTLS)
LegacyTel enforces **Mutual TLS (mTLS)** for all agent heartbeats, inventory pushes, and log streams.
1. **Protocol Standards:** Hardcoded enforcement of **TLS 1.2** (minimum) and **TLS 1.3** (preferred). Standard insecure ciphers (RC4, 3DES, CBC) are strictly disabled.
2. **Identity Verification:** Both the client (agent) and the server (control plane/gateway) must present valid X.509 cryptographic certificates signed by the enterprise Root CA.
3. **Certificate Setup Configuration (`config.yaml`):**
   ```yaml
   server:
     tls_enabled: true
     cert_file: "/etc/legacytel/certs/server.crt"
     key_file: "/etc/legacytel/certs/server.key"
     client_ca_file: "/etc/legacytel/certs/root_ca.crt" # Enforces mTLS validation
   ```
4. **Certificate Permissive Boundaries:**
   * Keys must be stored under `/etc/legacytel/certs/` (Linux), `C:\Program Files\LegacyTel\certs\` (Windows), or `/opt/legacytel/certs/` (macOS).
   * Permissions on private keys (`.key`) must be restricted to owner-read-only (`chmod 600` / Windows ACL System-Only).

---

### B. Gateway-to-SIEM & Gateway-to-Cribl (HTTPS & OTLP Secure)
Outgoing telemetry forwarded from the LegacyTel Gateway or Cribl Stream is piped exclusively over secure application-layer protocols:
* **Splunk Cloud (HEC):** Encrypted HTTPS via port `8088` utilizing enterprise-grade TLS.
* **Microsoft Sentinel:** Azure Log Analytics Data Collector Ingestion API over secure TLS/HTTPS via port `443`.
* **Google SecOps (Chronicle):** Secure gRPC / TLS (port `443`) or standard HTTPS ingestion.
* **Cribl Stream Worker:** OpenTelemetry gRPC secure protocol over TLS via port `4317` or HTTP via port `4318`.

---

### C. Legacy Systems Transport Wrapper (Mainframe, AS/400, Tandem)
Because vintage operating systems may lack modern native TLS libraries, secure tunnels are configured at the OS level:
1. **IBM z/OS Mainframe:** Secure transport is managed through **AT-TLS (Application Transparent TLS)** utilizing System SSL within the RACF keyring.
2. **IBM i AS/400:** Auditing exits utilize IBM Digital Certificate Manager (DCM) to wrap socket transactions in TLS.
3. **HPE NonStop Tandem:** EMS log streams are wrapped locally via **comForte SecurITy** or an SSH/Stunnel secure loopback bridge before egress.

---

## 💾 3. Encryption at Rest (Data Storage Protection)

Telemetry stored locally in spool databases, configuration directories, or log buffers must be encrypted to prevent data extraction during physical host compromise.

### A. Local Ingestion Database & File Spooling
During network connectivity drops or control plane upgrades, agents spool logs to a local disk queue to prevent log loss.
1. **Spool SQLite Encrypted Cache:** SQLite log caches utilize the **SQLCipher** extension to encrypt the database file using **AES-256-GCM**.
2. **Encrypted Spool File Setup:**
   * The local spool is initialized using a randomly generated 256-bit passphrase stored securely inside the OS Secrets vault (e.g. systemd Credentials, Windows DPAPI Credential Manager, or macOS Keychain).
   * Active memory buffers are scrubbed immediately after flush to prevent heap exploitation.

---

### B. Security File Vaults & Operating System Partitioning
To safeguard the persistent installation directories:
1. **Linux:** The `/opt/legacytel/` filesystem partition is encrypted using **LUKS (dm-crypt)**.
2. **Windows:** The installation drive `C:\Program Files\LegacyTel\` is protected under **BitLocker Drive Encryption**.
3. **macOS:** FileVault is enabled on workstations hosting development agents.

---

### C. Configuration Secrets Management
Never hardcode API tokens, Splunk HEC keys, or database passwords in `config.yaml`. LegacyTel dynamically loads credentials from system environment variables at runtime.

#### Secure `config.yaml` Reference:
```yaml
exporters:
  splunk:
    hec_url: "https://splunk-hec.domain.com:8088/services/collector"
    # Dynamically read from OS Environment variable at boot
    hec_token: "${SPLUNK_HEC_TOKEN}"
    
  azure_sentinel:
    workspace_id: "${SENTINEL_WORKSPACE_ID}"
    shared_key: "${SENTINEL_SHARED_KEY}"
```

#### Injecting Variables via systemd (Linux):
Add a secure environment file `/etc/legacytel/secrets.env` (restricted to `chmod 600`):
```text
SPLUNK_HEC_TOKEN=11111111-2222-3333-4444-555555555555
SENTINEL_SHARED_KEY=AbCdEfGhIjKlMnOpQrStUvWxYz==
```
And reference it in `/etc/systemd/system/legacytel.service`:
```ini
[Service]
EnvironmentFile=/etc/legacytel/secrets.env
```

#### Injecting Variables via Windows Service:
Store secrets using PowerShell DPAPI credentials or configure environment variables strictly under system-level context:
```powershell
[System.Environment]::SetEnvironmentVariable("SPLUNK_HEC_TOKEN", "11111111-2222-3333-4444-555555555555", [System.EnvironmentVariableTarget]::Machine)
```
