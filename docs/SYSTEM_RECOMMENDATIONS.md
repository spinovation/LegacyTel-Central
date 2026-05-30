# LegacyTel v2.0.0: Hardware, Software, & System Sizing Recommendations
## Enterprise Infrastructure Specifications & Architecture Sizing Guide

This guide provides potential customers, systems architects, and infrastructure engineers with comprehensive hardware and software recommendations for deploying **LegacyTel v2.0.0 Agents** and the centralized **Collector Gateway / Control Plane** across enterprise environments.

---

## 📊 1. Workload Sizing & Hardware Resource Matrix

LegacyTel's zero-dependency Go architecture is engineered for high throughput with a tiny resource footprint. Sizing recommendations are divided into three standard workload tiers:

| Workload Tier | Events Per Second (EPS) | Est. Daily Volume (GB/Day) | Gateway CPU Cores | Gateway RAM | Gateway Disk IOPS | Edge Agent CPU / RAM |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Small (Dev/Test)** | < 5,000 EPS | < 100 GB/day | 2 vCPUs | 4 GB | 500 IOPS | 0.1 Core / 150 MB |
| **Medium (Enterprise)** | < 25,000 EPS | < 500 GB/day | 4 vCPUs | 8 GB | 2,500 IOPS | 0.2 Core / 250 MB |
| **Large (Hyperscale)** | 100,000+ EPS | 2.0+ TB/day | 8 - 16 vCPUs | 16 - 32 GB | 10,000+ IOPS | 0.5 Core / 500 MB |

---

## 🖥️ 2. Centralized Collector Gateway & Control Plane Specifications

The **LegacyTel Central Control Plane & Collector Gateway** runs as a high-concurrency centralized receiver and forwarder.

### A. Recommended Operating Systems (64-bit)
* **Linux (Preferred):** Red Hat Enterprise Linux (RHEL) 8 or 9, Rocky Linux 9, SUSE Linux Enterprise Server (SLES) 15, Ubuntu Server 22.04 LTS or 24.04 LTS.
* **Virtualization/Containerization:** VMware ESXi 7.0+, Nutanix AHV, Docker 24.0+, or Kubernetes (K8s).

### B. Storage & IOPS Sizing
To prevent log loss during downstream SIEM connection outages, the Gateway utilizes a high-speed SQLite/SQLCipher disk cache queue.
* **Storage Type:** SSD or NVMe drives.
* **Sizing Formula:** `Disk Size = (Daily Volume GB * Outage Buffer Days) * 1.5`
  * *Example (Medium Tier, 3-day buffer):* `(500 GB * 3) * 1.5 = 2.25 TB` of local SSD storage.
* **IOPS Profile:** 
  * Small: Standard SATA SSD (minimum 500 write IOPS).
  * Large: NVMe SSD or high-performance SAN (minimum 10,000 write/read IOPS).

### C. Network Bandwidth Requirements
* **Small/Medium Tiers:** 1 Gbps NIC (redundant bonded pairs).
* **Large Tier:** 10 Gbps NIC (redundant bonded pairs).
* **Estimated Bandwidth (Average 400-byte log size):**
  * 5,000 EPS $\rightarrow$ ~16 Mbps outbound.
  * 25,000 EPS $\rightarrow$ ~80 Mbps outbound.
  * 100,000 EPS $\rightarrow$ ~320 Mbps outbound.

---

## 🚀 3. Edge Observability Agent Specifications (Target Nodes)

The edge agent runs locally as a background process or system service on your host servers. Because it relies on the unprivileged **Supervisor-Worker Process Split**, its footprint is extremely light and designed to cause zero disruption to core business applications.

---

### A. Modern Target Environments (v2 Agent)

#### 🐧 1. Linux Nodes
* **Software Prerequisites:** Linux Kernel 3.10+ (Ubuntu 18.04+, RHEL 7+, SLES 12+). Standard `glibc` library.
* **Resource Bounds:** 
  * CPU: Configurable throttle (Default limits: max 5% CPU capacity).
  * RAM: ~120 MB baseline, spikes to 250 MB under heavy peak log buffers.

#### 🪟 2. Windows Server & Desktop Nodes
* **Software Prerequisites:** Windows Server 2012 R2+ or Windows 10+; PowerShell 5.1+ (for automated deployment scripts).
* **Resource Bounds:**
  * CPU: 1-2% average CPU utilization.
  * RAM: ~150 MB baseline.

#### 🍏 3. macOS Workstations
* **Software Prerequisites:** macOS 10.15 (Catalina) to 15 (Sequoia).
* **Resource Bounds:**
  * CPU: ~1% CPU utilization.
  * RAM: ~100 MB baseline.

---

### B. Legacy Platforms & Midrange Environments (v1 Agent)

LegacyTel's v1 agents are designed with low-overhead C-level compatibility hooks to operate safely on vintage hypervisors without impacting system operations.

#### 📘 1. IBM z/OS Mainframe (SMF Ingestion)
* **Software Prerequisites:** IBM z/OS v2.3, v2.4, v2.5, or v3.1; IBM Open Enterprise SDK for Go (or standard Syslogd/CDP pipelines).
* **Resource Bounds:**
  * CPU/MIPS: < 0.5 MIPS utilization during peak SMF 80 record sweeps.
  * RAM: ~80 MB baseline inside USS (Unix System Services) address spaces.

#### 📗 2. IBM i AS/400 (QAUDJRN Ingestion)
* **Software Prerequisites:** OS/400 V7R2, V7R3, V7R4, or V7R5 running the PASE environment.
* **Resource Bounds:**
  * CPU: < 1% CPU utilization on a single LPAR thread.
  * RAM: ~100 MB memory boundary.

#### 📙 3. HPE NonStop Tandem (EMS Ingestion)
* **Software Prerequisites:** NonStop J-Series or L-Series; Guardian OS environment.
* **Resource Bounds:**
  * CPU/PIN: Runs as a single unprivileged process pin; consumes < 1% CPU capacity.
  * RAM: ~60 MB memory allocation.

---

## 🔀 4. High-Availability Load Balancing & Network Ingress

For large and hyperscale deployments with thousands of distributed agents, we recommend deploying a Layer 4 (TCP/UDP) Load Balancer in front of the centralized Gateway servers to distribute mTLS traffic evenly.

```
 [ Fleet Agents ] --( mTLS TCP:9090 )--> [ Layer 4 Load Balancer ]
                                            /           |           \
                                           /            |            \
                                  [ Gateway 1 ]   [ Gateway 2 ]   [ Gateway 3 ]
```

### Load Balancer Best Practices:
1. **Protocol Configuration:** Standard TCP Pass-Through (Layer 4). Do not terminate TLS/mTLS at the Load Balancer layer unless the load balancer possesses client certificate verification capabilities and holds the required root CA validation keys.
2. **Recommended Hardware Load Balancers:** F5 BIG-IP, HAProxy (High Performance), NGINX Plus, or AWS Network Load Balancer (NLB).
3. **Session Persistence:** Source-IP session persistence should be enabled to optimize SSE connection pipelines between agents and the Control Plane.
