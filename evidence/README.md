# Forensic Evidence Repository & Verification Manifest

## 1. Overview & Evidentiary Standard

This directory serves as the centralized evidentiary clearinghouse for the **Enterprise SOC Lab**. Every architectural claim, telemetry pipeline, detection alert, forensic pivot, and incident containment action documented in the portfolio is backed by verifiable, traceable digital evidence.

In strict compliance with digital forensics standards (NIST SP 800-86) and public documentation ethics:
1. **Verifiable Proof**: Evidence is drawn directly from empirical lab artifacts (ArcSight ESM Active Channel logs, ArcSight Logger CEF events, Sysmon XML records, Linux Auditd syscall logs, MariaDB audit tables, and firewall filterlogs).
2. **Standardized Identification**: Every artifact possesses an immutable identifier (`ARCH-xxx`, `TEL-xxx`, `DET-xxx`, `INV-xxx`, `RESP-xxx`, or case-specific `CASE00x-Exx`).
3. **Complete Sanitization**: Raw sensitive artifacts containing internal private addressing, student/supervisor names, or proprietary production secrets have been redacted and normalized into canonical public representations in `evidence/sanitized/`.
4. **No Raw Screenshot Dumps**: This repository contains zero uncurated screenshot dumps. Every evidence entry documents: **What it is, Why it matters, Which Case/Detection it supports, and Where it originates in the Source of Truth.**

---

## 2. Evidence Directory Structure

```text
evidence/
├── README.md                      <-- You are here (Evidentiary standard & policy)
├── EVIDENCE_INDEX.md              <-- Master inventory of all confirmed evidence items
├── CLAIM_EVIDENCE_MATRIX.md       <-- Cross-reference linking technical claims to proof
│
├── architecture/                  <-- Proof of network topology, static routing & zones
│   └── README.md                  <-- Topology evidence manifests (ARCH-001 to ARCH-003)
│
├── telemetry/                     <-- Proof of log generation, parsers & CEF normalization
│   └── README.md                  <-- Telemetry evidence manifests (TEL-001 to TEL-004)
│
├── detection/                     <-- Proof of rule configurations & Active Channel firings
│   └── README.md                  <-- Detection evidence manifests (DET-001 to DET-005)
│
├── investigation/                 <-- Proof of Logger queries, process trees & timelines
│   └── README.md                  <-- Forensic evidence manifests (INV-001 to INV-005)
│
└── sanitized/                     <-- Public-safe evidence cards, logs & visual mockups
    └── README.md                  <-- Curated, public-safe evidence cards
```

---

## 3. Evidence Classification Taxonomy

All evidentiary items are cataloged under the standardized five-tier confidence taxonomy established in Phase 5:

| Classification | Evidentiary Weight | Criteria for Inclusion |
| :--- | :--- | :--- |
| **`DIRECT`** | Highest | Direct sensor or operating system audit record capturing the action (e.g., Sysmon Event ID 1 process command line). |
| **`CORRELATED`** | High | Multi-sensor agreement confirming causality (e.g., ESM composite join `C01` linking download, execution, and callback). |
| **`CONTEXTUAL`** | Supporting | Environmental or baseline logs establishing time, identity, or delivery without proving malice in isolation (e.g., Postfix delivery log). |
| **`INFERRED`** | Analytical | Logical conclusion derived from verified telemetry, but lacking byte-level PCAP or memory payload capture. |
| **`UNVERIFIED`** | Informational | Actions suspected to have occurred outside the sensor boundary (e.g., offline cryptanalysis on the attacker's Kali machine). |

---

## 4. Chain of Custody & Traceability Matrix

Every evidence entry in `evidence/` cross-references:
* **The Source Document**: Exact page and section in `Báo cáo đề tài SOC.pdf` or `toan-bo-he-thong-kien_truc_lab.txt`.
* **The Telemetry Sensor**: Producing daemon and Generator ID on SmartConnector (`10.10.40.4`).
* **The Storage Index**: ArcSight Logger query syntax for historical reproduction.
* **The Public Alias**: Canonical mapping ensuring zero exposure of private infrastructure.
