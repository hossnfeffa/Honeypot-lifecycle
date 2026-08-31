# Honeypot Lifecycle: Threat Hunting & Breach Investigation

An end-to-end cybersecurity lab exercise detailing the deployment of an intentionally exposed host (honeypot), capture of attacker activity via Microsoft Defender for Endpoint (MDE) Live Response, threat hunting with Kusto Query Language (KQL), and visualization of inbound authentication attempts using Azure Sentinel Workbooks.

---

## 📌 Project Overview

This project simulates a full incident response and threat hunting lifecycle:
1. **Deployment:** Exposed a cloud-hosted asset to capture real-world brute-force and post-exploitation activity.
2. **Collection:** Extracted forensic artifacts (pre- and post-breach) using MDE Live Response packages.
3. **Analysis:** Authored KQL queries against Microsoft Sentinel and Advanced Hunting logs to analyze attacker TTPs and SQL/MySQL audit events.
4. **Visualization:** Configured an Azure Workbook to map geolocation metrics and inbound attack traffic.

---

## 📁 Repository Structure

```text
Honeypot-lifecycle/
├── evidence/                            # Pre- and post-breach MDE Live Response investigation packages (.zip)
├── queries/                             # KQL query exports and raw telemetry CSVs (MySQL Audit & SQL Logons)
├── reports/                             # Incident Response (IR) reports and breach analysis documentation
├── workbooks/                           # Azure Sentinel Workbook JSON templates (InboundAuth.json)
├── Advanced Honey Pot w_Live Breach Checklist.pdf  # Detailed step-by-step lab walkthrough & methodology
└── README.md                            # Project documentation
---
```
## 🔍 Key Findings & Telemetry

* **Inbound Auth Telemetry:** Captured brute-force and credential stuffing activity across exposed ports, parsing out IP addresses, failure counts, and targeted account names.
* **Geolocation Mapping:** Aggregated source IPs by geographic region to map global attack sources.
* **Post-Exploitation Forensics:** Examined MDE forensic packages for spawned processes, persistence attempts, and lateral movement post-compromise.

---

## 🚀 Azure Workbook Deployment

To load the included workbook into your Azure Sentinel environment:
1. Navigate to **Microsoft Sentinel** > **Workbooks**.
2. Click **Add workbook** > **Edit** > **Advanced Editor** (`</>`).
3. Copy the contents of [`workbooks/InboundAuth.json`](./workbooks/InboundAuth.json) and paste them into the editor.
4. Click **Apply** and save the workbook.
