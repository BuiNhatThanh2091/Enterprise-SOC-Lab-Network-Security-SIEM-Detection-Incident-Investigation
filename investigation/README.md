# Incident Investigation Portfolio & Case Studies

## 1. Overview & Forensic Philosophy

In an enterprise Security Operations Center (SOC), detection alerts do not represent the conclusion of a security event; they mark the operational starting point for **forensic investigation, causal hypothesis testing, and threat containment**.

This directory presents the authoritative **Incident Investigation Case Studies** derived from live red-team attack simulations conducted in the Enterprise SOC Lab. Each case study documents the empirical workflow of a SOC Tier-2 / Tier-3 incident response analyst moving through:

```text
Initial Alert (ESM) ──► Entity Triage ──► Causal Hypotheses ──► Deep Logger Query ──► Cross-Telemetry Pivots
                                                                                           │
    Remediation & Hardening ◄── Scope Assessment ◄── Attack Chain ◄── Timeline Assembly ◄──┘
```

---

## 2. Core Methodological Principles

### 2.1. Grounded in Empirical Evidence (Zero Fiction)
Every observation, query, timestamp, and conclusion in these case studies corresponds strictly to verified evidence recorded in the canonical project Source of Truth (`Báo cáo đề tài SOC.pdf` and `toan-bo-he-thong-kien_truc_lab.txt`). Where telemetry does not provide definitive proof, it is explicitly classified as `INFERRED` or `UNVERIFIED`.

### 2.2. Defensive Process Focus (Not an Exploitation Guide)
These case studies are structured from the perspective of **defensive detection and response**. Attack activities are described only to the extent necessary to explain host observables, telemetry footprints, SIEM correlation triggers, and investigative reasoning.

### 2.3. The Decoupled SIEM Paradigm
Investigations leverage the explicit separation of responsibilities between **ArcSight ESM** and **ArcSight Logger**:
* **ArcSight ESM (Real-Time Correlation)**: Signals that an anomalous threshold, sequence, or composite pattern has manifested across real-time Active Channels (`"Something high-priority has occurred on host X"`).
* **ArcSight Logger (Immutable Forensic Store)**: Serves as the primary analytical workhorse where analysts execute ad-hoc CEF and SQL queries across sliding temporal windows to answer: *"What happened immediately before and after the alert? What child processes were spawned? What data left the network?"*

---

## 3. Evidence Classification Taxonomy

To ensure legal-grade forensic rigor and prevent analytic overreach, all evidentiary artifacts in these case studies are categorized under five standardized classifications:

| Classification | Definition & Operational Weight | Example from Laboratory |
| :--- | :--- | :--- |
| **`DIRECT`** | Low-level, immutable artifact directly recording the specific malicious or suspicious action. | Sysmon Event ID 1 recording `mshta.exe` spawning `powershell.exe` with exact `ProcessGuid`. |
| **`CORRELATED`** | High-confidence finding confirmed through the temporal and contextual convergence of multiple independent data sources. | Perimeter IPS download alert (`A02`) + Endpoint process launch (`A03`) + Outbound TCP callback (`A04`) on host `10.10.35.18`. |
| **`CONTEXTUAL`** | Authoritative log confirming operational background or environmental facts without proving compromise in isolation. | Postfix mail delivery log (`A01`) proving that an email with QueueID `718FC8006A` was placed into the user's inbox. |
| **`INFERRED`** | Logical deduction supported by strong circumstantial telemetry, but lacking direct packet payload or memory capture. | Deducing that an outbound raw TCP stream on port 9999 represents the transfer of `firefox_profile.zip` based on file creation timestamps. |
| **`UNVERIFIED`** | Hypothesis or action suspected to have occurred, but unsupported by current telemetry or omitted from lab logging. | Confirming the exact plaintext passwords decrypted offline on the attacker's machine (offline actions generate zero telemetry). |

---

## 4. Timeline Reconstruction Methodology

Each case study incorporates a dual-layer timeline structure:
1. **Observed Telemetry Fact**: The exact event recorded by the producing sensor, including source subsystem, raw event ID, and normalized CEF attributes.
2. **Analytical Interpretation**: The defensive hypothesis or tactical meaning of that event within the overarching intrusion campaign.

Timelines utilize normalized relative time anchors ($T_0, T+2\text{m}, T+5\text{m}$) anchored to the initial compromise signal, ensuring consistent cross-referencing across case studies without leaking non-public raw timestamps.

---

## 5. Public-Safe Sanitization Standards

In strict compliance with the **Phase 2 Sanitization Specification**, all investigation documentation, Logger queries, and diagrams utilize standardized public aliases:
* **External Threat Subnet**: `203.0.113.0/24` (RFC 5737 TEST-NET-3). External Attacker is `203.0.113.25` (`Kali`).
* **Security Transit**: `10.10.36.0/24`. Suricata Transit IP is `10.10.36.11`; pfSense Transit IP is `10.10.36.10`.
* **Internal Core Subnet**: `10.10.35.0/24`. Workstation victim is `10.10.35.18` (`IT-ADMIN01`); Database is `10.10.35.19` (`DB01`).
* **DMZ Subnet**: `10.10.34.0/24`. Web Application is `10.10.34.13` (`WEB01`); Mail Gateway is `10.10.34.14` (`MAIL01`).
* **Logging Subnet**: `10.10.40.0/24`. SmartConnector is `10.10.40.4`; ArcSight Logger is `10.10.40.5`.
* **Zero Private Leaks**: Internal private addressing, personal intern/supervisor names, and production credential hashes are fully purged and replaced with canonical public representations.

---

## 6. Case Studies Index

The investigation portfolio is organized into five sequential, highly detailed case studies reflecting the progression of the intrusion campaign:

| Case ID | Scenario / Focus | Initial Trigger Signal | Main Detection Rules | Primary Telemetry Sources | Investigation Objective | Technical Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| [**Case 001**](file:///e:/project_ca_nhan/lab_cty/investigation/case-001/README.md) | **Initial Compromise Investigation** | Composite Alert `C01` (Severity 9) | `A02`, `A03`, `A04`, `C01`, `A01` | Suricata IPS, Sysmon ID 1, Zeek `conn.log`, Postfix Syslog | Trace initial ingress from phishing lure to HTA execution and persistent TCP reverse shell foothold. | `VALIDATED` |
| [**Case 002**](file:///e:/project_ca_nhan/lab_cty/investigation/case-002/README.md) | **Post-Compromise Host Discovery** | Burst Alert `A05` (Severity 6) | `A05`, `A04` (Context) | Microsoft Sysmon (Event ID 1) | Reconstruct host reconnaissance sequence (`where ssh`, `netstat`, `sc query`) and analyze sliding window limits. | `VALIDATED` |
| [**Case 003**](file:///e:/project_ca_nhan/lab_cty/investigation/case-003/README.md) | **Credential Harvesting & Staging** | Critical Alert `A06` (Severity 8) | `A06`, `A07`, `A08` | Sysmon ID 1 & 3, PowerShell 4104, Zeek `conn.log` | Investigate browser profile theft via `xcopy`, raw socket staging on port 9999, and ingress of `agent.exe`. | `VALIDATED` |
| [**Case 004**](file:///e:/project_ca_nhan/lab_cty/investigation/case-004/README.md) | **Inter-Zone Pivoting & DB Dump** | Correlated Alerts `A09` $\rightarrow$ `A12` | `A09`, `A10`, `A11`, `A12` | Zeek, Suricata, Linux Auditd, MariaDB `SERVER_AUDIT` | Pivot across Ligolo tunnel, DMZ SSH, container config extraction (`site_config.json`), and database dump. | `VALIDATED` |
| [**Case 005**](file:///e:/project_ca_nhan/lab_cty/investigation/case-005/README.md) | **DMZ Outbound Exfiltration & Response** | Critical Alert `A13` (Severity 10) | `A13`, `A12` (Context) | Suricata Inline IPS, pfSense Filterlog, Linux Auditd | Quantify egress exfiltration stream over port 9999, execute host containment, and enforce firewall egress blocking. | `VALIDATED` |

---

## 7. Directory Organization

```text
investigation/
├── README.md                      <-- You are here
├── CASE_DETECTION_MATRIX.md       <-- Comprehensive Case-to-Detection cross-reference
├── CASE_TELEMETRY_MATRIX.md       <-- Case-to-Telemetry source mapping
│
├── case-001/                      <-- Initial Compromise (Spearphishing, HTA, C2, C01)
│   ├── README.md                  <-- Comprehensive 20-section investigation report
│   ├── timeline.md                <-- Chronological event reconstruction
│   ├── evidence.md                <-- Structured evidence catalog (E01-E08)
│   ├── detection.md               <-- Detection coverage & gap analysis
│   └── investigation-flow.mmd     <-- Visual investigation pivot graph
│
├── case-002/                      <-- Host Discovery Burst (Sysmon, A05)
│   ├── README.md
│   ├── timeline.md
│   ├── evidence.md
│   ├── detection.md
│   └── investigation-flow.mmd
│
├── case-003/                      <-- Credential Harvesting & Staging (A06, A07, A08)
│   ├── README.md
│   ├── timeline.md
│   ├── evidence.md
│   ├── detection.md
│   └── investigation-flow.mmd
│
├── case-004/                      <-- Pivoting, Container Scraping & DB Collection (A09-A12)
│   ├── README.md
│   ├── timeline.md
│   ├── evidence.md
│   ├── detection.md
│   └── investigation-flow.mmd
│
└── case-005/                      <-- DMZ Egress Exfiltration & Remediation (A13)
    ├── README.md
    ├── timeline.md
    ├── evidence.md
    ├── detection.md
    └── investigation-flow.mmd
```
