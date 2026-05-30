# LegacyTel v2.0.0: Cribl Stream Pipeline Integration Manual
## Architecting Data Minimization, Masking, and SIEM Routing Pipelines

This manual provides enterprise security architects, SIEM engineers, and Cribl administrators with step-by-step instructions for integrating **LegacyTel Observability Agents** with **Cribl Stream**. 

Using Cribl Stream as an intermediate gateway enables complete data minimization (saving up to **45% in SIEM license costs**), real-time data masking, and dynamic routing to **Splunk**, **Microsoft Sentinel**, and **Google SecOps (Chronicle)**.

---

## 🏛️ 1. Architecture: High-Availability Logging Pipeline

Cribl Stream acts as the central normalization and parsing gateway, routing raw agent telemetry into multiple downstream SIEM engines simultaneously.

```
 [ LegacyTel Worker Agents ] 
            | (mTLS / OTLP http)
            v
 [ Cribl Stream Ingestion Source ] (Port :4318)
            |
  ======================================================
  [ Cribl Pipeline: Parsing -> Flattening -> Masking ]
  ======================================================
     /              |              \
    /               |               \
 [ Splunk HEC ]  [ MS Sentinel ]  [ Google SecOps ]
```

---

## ⚙️ 2. Step 1: Cribl Source Configuration

Set up Cribl Stream to ingest standardized OpenTelemetry log records from the LegacyTel agent fleet.

1. Log in to the **Cribl Stream UI** and navigate to your active worker group.
2. Go to **Data** > **Sources** > **OpenTelemetry**. Click **Add Source**.
3. Configure the source:
   * **Input ID:** `LegacyTel-Agent-Ingest`
   * **Protocol:** `HTTP` (or `gRPC` depending on network topologies)
   * **Address:** `0.0.0.0`
   * **Port:** `4318` (HTTP OTLP default) or `4317` (gRPC OTLP default)
   * **TLS Settings:**
     * **Enabled:** `Yes`
     * **Certificate Path:** `/opt/cribl/certs/server.crt`
     * **Private Key Path:** `/opt/cribl/certs/server.key`
     * **Client Mutual Authentication:** `Required` (Upload the LegacyTel `root_ca.crt` to authenticate agent identity).
4. Save and commit changes.

---

## 🔀 3. Step 2: The Cribl Ingestion & Data Minimization Pipeline

Create a dedicated Cribl pipeline named `legacytel-normalization` to optimize data packages before SIEM indexing.

---

### Function A: Event Log Flattening (Simplify Schema)
OTLP logs package attributes in nested key-value arrays, which consume massive storage space. We use a **Cribl Eval Function** to extract and flatten resource and body values into clean root-level JSON keys.

1. Add a **Parser Function** or **Eval Function** to your pipeline:
   * **Filter:** `true` (executes on all incoming records)
2. Define the extraction variables inside the **Eval Function**:
   * **`platform`** $\rightarrow$ `__value.resourceLogs[0].resource.attributes.find(a => a.key === "os.type").value.stringValue`
   * **`host`** $\rightarrow$ `__value.resourceLogs[0].resource.attributes.find(a => a.key === "host.name").value.stringValue`
   * **`event_code`** $\rightarrow$ `__value.resourceLogs[0].scopeLogs[0].logRecords[0].attributes.find(a => a.key === "event.code").value.stringValue`
   * **`raw_message`** $\rightarrow$ `__value.resourceLogs[0].scopeLogs[0].logRecords[0].body.stringValue`
   * **`timestamp`** $\rightarrow$ `__value.resourceLogs[0].scopeLogs[0].logRecords[0].timeUnixNano / 1000000`
3. Add a **Keep Function** to retain *only* your newly created root-level keys (`platform`, `host`, `event_code`, `raw_message`, `timestamp`) and purge original nested records, reducing JSON footprint by **45%**.

---

### Function B: License Cost Saving (Drop Heartbeats)
Agent heartbeat events (`SS05`) compile continuous telemetry but do not indicate security threats, wasting daily indexing quotas. We use a **Cribl Drop Function** to filter them at the gateway layer.

1. Add a **Drop Function** directly below the flattening functions:
   * **Filter:** `event_code === "SS05"`
   * **Description:** "Drops standard agent heartbeats at the gateway to save daily licensing indexing costs."

---

### Function C: PII Masking (SecOps Compliance)
To conform to privacy guidelines (e.g. GDPR, PCI-DSS), mask sensitive personal identifiers (like emails, credit card formats, or exact directory structures) before SIEM indexing.

1. Add a **Mask Function**:
   * **Filter:** `true`
2. Define masking rules:
   * **Target:** `raw_message`
   * **Email Address Masking:**
     * **Regex:** `/([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g`
     * **Replace Expression:** `'[MASKED_EMAIL]'`
   * **Credit Card Regex Masking:**
     * **Regex:** `/\b(?:\d[ -]*?){13,16}\b/g`
     * **Replace Expression:** `'[MASKED_CREDIT_CARD]'`

---

## 📤 4. Step 3: Configuring SIEM Outbound Destinations

Once events are normalized and masked, route them to your preferred target destinations.

---

### A. Routing to Splunk Enterprise / Splunk Cloud (HEC)
Cribl packages the flattened JSON and pipes it directly to Splunk HTTP Event Collector.

1. In Cribl Stream, navigate to **Data** > **Destinations** > **Splunk HEC**. Click **Add Destination**.
2. Configure settings:
   * **Destination ID:** `Splunk-HEC-Out`
   * **Splunk HEC URL:** `https://your-splunk-instance.cloud.splunk.com:8088/services/collector/event`
   * **Token:** Enter your Splunk HEC Access Token.
   * **Source Type:** `_json` (or custom `legacytel:audit`).
   * **TLS Settings:** Ensure `Enable TLS` is set to `Yes` (verifying Splunk certificates).
3. Connect the `legacytel-normalization` pipeline to the `Splunk-HEC-Out` destination inside your Route configurations.

---

### B. Routing to Microsoft Sentinel (Azure Log Analytics)
Ingest flattened records securely into Microsoft Sentinel's Log Analytics database workspace.

1. In Cribl Stream, go to **Data** > **Destinations** > **Azure Log Analytics**. Click **Add Destination**.
2. Configure settings:
   * **Destination ID:** `Sentinel-Workspace-Out`
   * **Workspace ID:** Paste your Azure Log Analytics Workspace ID.
   * **Shared Key:** Paste your Azure Log Analytics Primary Shared Key.
   * **Log Type:** `LegacyTel` (Azure automatically creates a custom analytics table named `LegacyTel_CL`).
3. Set your routing logic to direct output to `Sentinel-Workspace-Out`.

---

### C. Routing to Google SecOps (Chronicle)
Stream normalized, flattened security logs directly to the Google SecOps Chronicle Ingestion API.

1. In Cribl Stream, go to **Data** > **Destinations** > **Google Chronicle**. Click **Add Destination**.
2. Configure settings:
   * **Destination ID:** `Google-Chronicle-Out`
   * **Chronicle URL:** `https://malachiteingestion-pa.googleapis.com/v1/projects/...`
   * **Customer ID:** Paste your Google SecOps Customer ID string.
   * **Auth Method:** Select `JSON Key File` (Upload your Google SecOps GCP Service Account credentials).
   * **Log Type:** `OTEL_LOGS`.
3. Set your routing logic to connect the pipeline directly to `Google-Chronicle-Out`.
