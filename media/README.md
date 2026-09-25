# Media & Demonstration Assets Specification

## 1. Overview & YouTube Unlisted Video Strategy

The **Enterprise SOC Lab** provides high-definition technical recordings documenting both **Red Team Attack Simulations** and **Blue Team Incident Investigations**.

### 1.1. Video Hosting Decision: YouTube Unlisted
Demonstration videos are hosted externally on **YouTube with visibility set to Unlisted**:
* **Zero Repository Bloat**: Large video binary files (`.mp4`, `.mkv`) are not committed into the Git tree, keeping the repository lightweight, fast to clone, and strictly focused on engineering documentation, code, rules, and curated evidence.
* **Direct Access for Technical Evaluators**: Unlisted videos are viewable via direct URL links provided in this documentation, allowing hiring managers and technical interviewers to inspect live workflows directly.
* **Search Suppression**: Unlisted videos do not appear in public YouTube search results, channel uploads, or recommendation feeds.
* **Security & Privacy Boundary**: Setting a video to Unlisted does **not** grant cryptographic access control or privacy guarantees; anyone with the link can view it. Therefore, all recordings must strictly pass the [Pre-Upload Video Sanitization Checklist](VIDEO_SANITIZATION_CHECKLIST.md) before upload.

---

## 2. Official 3-Video Architecture

The laboratory features exactly **3 official technical videos**, structured around the defensive engineering lifecycle:

```text
               ┌────────────────────────────────────────────────────────┐
               │ VIDEO-01: Attack Simulation                            │
               │ Red Team Intrusion Execution & Telemetry Generation    │
               │ (External Kali 203.0.113.25 ──► Enterprise Targets)    │
               └──────────────────────────┬─────────────────────────────┘
                                          │
                        Telemetry Ingestion & SIEM Correlation
                                          │
                                          ▼
               ┌────────────────────────────────────────────────────────┐
               │ VIDEO-02: Full Incident Investigation Walkthrough      │
               │ Primary Blue Team Investigation (End-to-End Triage,    │
               │ ESM Composite C01 Alert ──► Host/Network/Containment)  │
               └──────────────────────────┬─────────────────────────────┘
                                          │
                  Direct Technical Expansion & Forensic Deep-Dive
                                          │
                                          ▼
               ┌────────────────────────────────────────────────────────┐
               │ VIDEO-03: Supplementary Investigation Walkthrough      │
               │ Granular Forensics: ScriptBlock 4104 Decompression,    │
               │ Auditd Syscalls, L2 ARP Bypass Defense, MariaDB Dumps  │
               └────────────────────────────────────────────────────────┘
```

---

## 3. Master Demonstration & Investigation Video Index

> [!NOTE]
> Video publication is pending. Sanitized YouTube links will be added after final review; all core technical documentation and artifacts are already available in this repository. All recordings are currently staged locally. Video URLs will be updated from `YOUTUBE_URL_PENDING` to active links upon completion of the pre-upload sanitization audit.

| Video ID & Standardized Title | Type | Case Studies Covered | Detection Rules Validated | Analytical Workflow & Scope | YouTube Status | Public-Safe Status |
| :--- | :--- | :--- | :--- | :--- | :---: | :---: |
| [**`VIDEO-01.md`**](file:///e:/project_ca_nhan/lab_cty/media/attack-simulation/VIDEO-01.md)<br/>`[SOC Attack Simulation] Multi-Stage Adversary Intrusion & Detection Validation` | Red Team Simulation | [**Case 001**](file:///e:/project_ca_nhan/lab_cty/investigation/case-001/README.md) to [**Case 005**](file:///e:/project_ca_nhan/lab_cty/investigation/case-005/README.md) | `A01`–`A13`, `C01` | Multi-stage adversary simulation: Phishing delivery, LOLBin HTA execution, reverse shell callback, host discovery burst, credential harvesting, tool staging, SSH lateral pivot, container abuse, and DMZ data exfiltration. | `Pending Upload`<br/>`YOUTUBE_URL_PENDING` | `REVIEW_REQUIRED` |
| [**`VIDEO-02-FULL.md`**](file:///e:/project_ca_nhan/lab_cty/media/investigation/VIDEO-02-FULL.md)<br/>`[SOC Investigation] Full Incident Investigation Walkthrough: From Ingress to Containment` | Blue Team Primary Investigation | [**Case 001**](file:///e:/project_ca_nhan/lab_cty/investigation/case-001/README.md) to [**Case 005**](file:///e:/project_ca_nhan/lab_cty/investigation/case-005/README.md) | `C01`, `A01`–`A13` | Complete end-to-end incident investigation: ESM Active Channel triage of composite alert `C01`, Sysmon `ProcessGuid` lineage reconstruction, Zeek reverse shell validation, Postfix mail backtracking, lateral pivot triage, and perimeter firewall drop verification. | `Pending Upload`<br/>`YOUTUBE_URL_PENDING` | `REVIEW_REQUIRED` |
| [**`VIDEO-03-SUPPLEMENT.md`**](file:///e:/project_ca_nhan/lab_cty/media/investigation/VIDEO-03-SUPPLEMENT.md)<br/>`[SOC Investigation] Supplementary Walkthrough: Deep Forensics & Secondary Pivots` | Blue Team Supplementary Deep-Dive | [**Case 003**](file:///e:/project_ca_nhan/lab_cty/investigation/case-003/README.md), [**Case 004**](file:///e:/project_ca_nhan/lab_cty/investigation/case-004/README.md), [**Case 005**](file:///e:/project_ca_nhan/lab_cty/investigation/case-005/README.md) | `A07`, `A08`, `A11`, `A12`, `A13` | Technical deep-dive directly expanding on Video 02: PowerShell ScriptBlock 4104 payload reassembly, Linux Auditd `execve` container tracing, hardware Layer-2 ARP bypass analysis and host `iptables` defense on `DB01`, MariaDB `SERVER_AUDIT` query extraction, and microsecond pfSense filterlog drop inspection. | `Pending Upload`<br/>`YOUTUBE_URL_PENDING` | `REVIEW_REQUIRED` |

---

## 4. Relationship Between Video 02 and Video 03

To maintain forensic rigor without unnecessary narrative clutter:
* **`VIDEO-02` (Primary Walkthrough)** delivers the continuous, end-to-end incident response story from initial alert detection through timeline assembly and firewall containment.
* **`VIDEO-03` (Supplementary Walkthrough)** is **not an independent case study** (not "Case 06"); rather, it expands upon secondary queries, system call audits, and technical compensatory controls that could not be fully explored within the runtime of Video 02.

---

## 5. Standardized YouTube Description Templates

When publishing demonstration videos to YouTube, copy and populate the appropriate standardized metadata template into the YouTube description box:

### 5.1. Description Template for Video 01 (Attack Simulation)

```markdown
# [SOC Attack Simulation] Multi-Stage Adversary Intrusion & Detection Validation

## Overview
This technical video records the empirical Red Team Attack Simulation conducted in the Enterprise SOC Lab, demonstrating the observable activities and telemetry footprints that trigger defensive detections across network and endpoint sensors.

## Attack Progression
- Stage 1: Inbound SMTP Spearphishing & HTA Living-off-the-Land Execution
- Stage 2: Reverse Shell Callback to External Kali (203.0.113.25:4444)
- Stage 3: High-Frequency Host Discovery Burst & Browser Credential Staging
- Stage 4: Ingress Tool Transfer (certutil / ligolo-agent) & Reverse Tunneling
- Stage 5: Inter-Zone SSH Lateral Movement (Internal -> DMZ WEB01)
- Stage 6: Docker Container Privilege Abuse & MariaDB Database Extraction
- Stage 7: DMZ Outbound Staging Exfiltration (TCP:9999)

## Related Detection Rules
- Atomic Rules: A01, A02, A03, A04, A05, A06, A07, A08, A09, A10, A11, A12, A13
- Composite Correlation Rule: C01 (Stateful Multi-Source Correlation)

## Related Case Studies & Documentation
- Full Documentation: media/attack-simulation/VIDEO-01.md
- Incident Cases: investigation/case-001/ to investigation/case-005/
- Architecture: architecture/enterprise-soc-overview.svg

## Laboratory Environment
- Threat Actor: Kali Linux (203.0.113.25)
- Monitored Targets: IT-ADMIN01 (10.10.35.18), MAIL01 (10.10.34.14), WEB01 (10.10.34.13), DB01 (10.10.35.19)
- Transit Choke Point: pfSense (10.10.36.10), Suricata IPS (10.10.36.11)

## Public-Safe Sanitization Notice
All displayed IP addresses, hostnames, usernames, and database records have been sanitized according to RFC 1918 / RFC 5737 standards. Zero production or personal data is present.

## Repository
GitHub Repository: GITHUB_URL_PENDING
```

---

### 5.2. Description Template for Video 02 (Full Investigation Walkthrough)

```markdown
# [SOC Investigation] Full Incident Investigation Walkthrough: From Ingress to Containment

## Overview
This technical video presents the complete, end-to-end Blue Team Forensic Investigation conducted by the SOC analyst, tracking an enterprise intrusion from the initial ArcSight ESM composite correlation alert (C01) through multi-source pivots to perimeter containment.

## Demonstrated Analytical Workflow
- Phase 1: Active Channel Alert Triage & Entity Priority Assessment (Alert C01)
- Phase 2: Logger Query Formulation & Immutable Process Lineage Extraction (Sysmon ProcessGuid)
- Phase 3: Network Callback Correlation with Zeek conn.log Metadata (ZeekUID: C9xKa811)
- Phase 4: Ingress Root-Cause Analysis via Postfix Mail Logs (QueueID: 718FC8006A)
- Phase 5: Multi-Stage Lateral Movement, Container, and Database Triage
- Phase 6: Perimeter Firewall Containment & Drop Rule Validation (pfSense filterlog)

## Validated Evidence Manifests
- DET-001 to DET-005 (Atomic Detections & ESM Correlation)
- INV-001 (Postfix Mail Delivery Backtrack)
- INV-002 (Sysmon Parent-Child Process Lineage)
- INV-003 (Reconnaissance Command Burst Timeline)
- INV-005 (Linux auth.log Lateral SSH Pivoting)
- RESP-001 & RESP-002 (pfSense Perimeter Drop Logs)

## Related Case Studies & Documentation
- Full Documentation: media/investigation/VIDEO-02-FULL.md
- Primary Incident Case: investigation/case-001/README.md
- Deep Forensics Companion: media/investigation/VIDEO-03-SUPPLEMENT.md

## Technical Environment
- SIEM Platforms: Micro Focus ArcSight ESM & ArcSight Logger
- Sensor Array: Microsoft Sysmon, Zeek NDR, Suricata IPS, Linux Auditd, MariaDB Audit

## Public-Safe Sanitization Notice
All telemetry, IP addresses, analyst accounts, and hostnames strictly comply with the project's public-safe sanitization baseline.

## Repository
GitHub Repository: GITHUB_URL_PENDING
```

---

### 5.3. Description Template for Video 03 (Supplementary Investigation Walkthrough)

```markdown
# [SOC Investigation] Supplementary Walkthrough: Deep Forensics & Secondary Pivots

## Overview
This video is the official technical supplement to Video 02 (Full Incident Investigation Walkthrough). It provides granular deep-dives into low-level telemetry, script block reassembly, container system calls, Layer-2 switching bypass defense, and microsecond packet drop validation.

## Supplementary Modules Demonstrated
- Module 1: PowerShell ScriptBlock 4104 De-obfuscation & Memory Socket Exfiltration (INV-004)
- Module 2: Linux Auditd execve Syscall Inspection for Container Command Injection (INV-006)
- Module 3: Hardware Layer-2 ARP Bypass Analysis & Host iptables Defense on DB01 (ARCH-003)
- Module 4: MariaDB SERVER_AUDIT Query Extraction Forensics & Customer Schema Dumps (INV-007)
- Module 5: Microsecond pfSense filterlog Egress Packet Drop Validation (RESP-002)

## Architectural Role
Note: This video is NOT an independent incident case study; it directly expands upon the forensic evidence and secondary queries originating from Cases 003, 004, and 005.

## Related Documentation & Evidence
- Supplementary Guide: media/investigation/VIDEO-03-SUPPLEMENT.md
- Primary Investigation: media/investigation/VIDEO-02-FULL.md
- Evidence Manifests: INV-004, INV-006, INV-007, ARCH-003, RESP-002

## Public-Safe Sanitization Notice
All screen captures, command outputs, and database rows have been verified against the project's 4-pass sanitization standard.

## Repository
GitHub Repository: GITHUB_URL_PENDING
```

---

## 6. Pre-Upload Sanitization Verification

Prior to publishing any Unlisted link, every recording must be audited against the [Pre-Upload Video Sanitization Checklist](VIDEO_SANITIZATION_CHECKLIST.md) to ensure:
* [x] **IPAM Compliance**: Zero real internal IP addresses; exclusively sanitized subnets (`10.10.34.0/24`, `10.10.35.0/24`, `10.10.36.0/24`, `203.0.113.25`).
* [x] **User Identity**: Zero personal usernames, student IDs, or faculty names; exclusively sanitized accounts (`user01`, `admin`, `thanh`).
* [x] **Credential Protection**: Zero plaintext credentials, private keys, or API tokens; exclusively demo tokens (`P@ssw0rd2024!_DEMO`).
* [x] **Host OS Environment**: Zero private host operating system directories, desktop items, or browser bookmarks.
