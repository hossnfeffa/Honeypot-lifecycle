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
├── Advanced Honey Pot w_Live Breach.md  # Detailed step-by-step lab walkthrough & methodology
└── README.md                            # Project documentation
