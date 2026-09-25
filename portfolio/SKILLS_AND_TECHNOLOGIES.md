# Verified Technical Skills & Technology Matrix

This document provides the authoritative inventory of technical skills, platforms, and methodologies validated by concrete evidence within the **Enterprise SOC Lab**.

---

## 1. Implemented Technology & Evidence Matrix

| Technology / Product | Operational Domain | Laboratory Implementation Scope | Primary Evidence in Repository |
| :--- | :--- | :--- | :--- |
| **pfSense** | Perimeter Routing & Firewall | Multi-interface routing, NAT, perimeter egress rules, and filterlog syslog. | [`docs/03_NETWORK_ARCHITECTURE.md`](file:///e:/project_ca_nhan/lab_cty/docs/03_NETWORK_ARCHITECTURE.md), [`evidence/architecture/README.md#arch-002`](file:///e:/project_ca_nhan/lab_cty/evidence/architecture/README.md#arch-002) |
| **Suricata** | Inline Intrusion Prevention (IPS) | NFQUEUE inline bridging, Layer-7 HTTP inspection, custom SID rules, and drop verification. | [`docs/04_SECURITY_ARCHITECTURE.md`](file:///e:/project_ca_nhan/lab_cty/docs/04_SECURITY_ARCHITECTURE.md), [`evidence/detection/README.md#det-001`](file:///e:/project_ca_nhan/lab_cty/evidence/detection/README.md#det-001) |
| **Zeek (Bro)** | Network Detection & Response (NDR) | Passive traffic analysis, protocol session metadata, connection duration tracking (`conn.log`). | [`docs/05_TELEMETRY_ARCHITECTURE.md`](file:///e:/project_ca_nhan/lab_cty/docs/05_TELEMETRY_ARCHITECTURE.md), [`evidence/detection/README.md#det-003`](file:///e:/project_ca_nhan/lab_cty/evidence/detection/README.md#det-003) |
| **Microsoft Sysmon** | Windows Endpoint Telemetry | Modular XML schema, Process Create (Event ID 1), Network Connect (ID 3), Process Terminate (ID 5). | [`evidence/telemetry/README.md#tel-001`](file:///e:/project_ca_nhan/lab_cty/evidence/telemetry/README.md#tel-001), [`evidence/investigation/README.md#inv-002`](file:///e:/project_ca_nhan/lab_cty/evidence/investigation/README.md#inv-002) |
| **PowerShell Auditing** | Windows Host Auditing | Group Policy ScriptBlock Logging (Event ID 4104) capturing de-obfuscated script payloads. | [`evidence/telemetry/README.md#tel-002`](file:///e:/project_ca_nhan/lab_cty/evidence/telemetry/README.md#tel-002), [`evidence/investigation/README.md#inv-004`](file:///e:/project_ca_nhan/lab_cty/evidence/investigation/README.md#inv-004) |
| **Active Directory DS** | Identity & Governance | Windows Server 2019 Domain Controller, Kerberos ticket logging (4768/4769), domain authentication. | [`docs/05_TELEMETRY_ARCHITECTURE.md`](file:///e:/project_ca_nhan/lab_cty/docs/05_TELEMETRY_ARCHITECTURE.md) |
| **Linux Auditd** | Linux Kernel Auditing | System call rule configuration (`execve`), tracking `sudo` executions and Docker container commands. | [`evidence/investigation/README.md#inv-006`](file:///e:/project_ca_nhan/lab_cty/evidence/investigation/README.md#inv-006) |
| **MariaDB Server** | Database Activity Monitoring | MariaDB Server 10.x with Audit Plugin (`SERVER_AUDIT`), logging `CONNECT`, `QUERY`, and `TABLE` actions. | [`evidence/telemetry/README.md#tel-004`](file:///e:/project_ca_nhan/lab_cty/evidence/telemetry/README.md#tel-004), [`evidence/investigation/README.md#inv-007`](file:///e:/project_ca_nhan/lab_cty/evidence/investigation/README.md#inv-007) |
| **Postfix / Dovecot** | Mail Gateway Services | Inbound SMTP routing, DKIM/SPF checking, local mailbox delivery, and Queue ID tracking. | [`evidence/investigation/README.md#inv-001`](file:///e:/project_ca_nhan/lab_cty/evidence/investigation/README.md#inv-001) |
| **ArcSight SmartConnector** | Log Normalization Engine | Multi-listener daemon configuration (Generator IDs 2002–2009) and CEF schema field mapping. | [`docs/05_TELEMETRY_ARCHITECTURE.md`](file:///e:/project_ca_nhan/lab_cty/docs/05_TELEMETRY_ARCHITECTURE.md), [`architecture/telemetry-flow.svg`](file:///e:/project_ca_nhan/lab_cty/architecture/telemetry-flow.svg) |
| **ArcSight Logger** | Forensic Log Retention & Search | Indexed storage, SHA-256 event integrity hashing, ad-hoc CEF query formulation, and SQL search. | [`docs/06_SOC_OPERATING_MODEL.md`](file:///e:/project_ca_nhan/lab_cty/docs/06_SOC_OPERATING_MODEL.md), [`detection/queries/README.md`](file:///e:/project_ca_nhan/lab_cty/detection/queries/README.md) |
| **ArcSight ESM** | Real-Time Correlation Engine | In-memory correlation matrix, rules `A01`–`A13`, composite rule `C01`, and Active Channels. | [`detection/README.md`](file:///e:/project_ca_nhan/lab_cty/detection/README.md), [`detection/C01/README.md`](file:///e:/project_ca_nhan/lab_cty/detection/C01/README.md) |
| **Kali Linux** | Adversary Simulation | Red Team attack execution (phishing lure generation, HTA stagers, Ligolo tunneling, Netcat). | [`media/attack-simulation/VIDEO-01.md`](file:///e:/project_ca_nhan/lab_cty/media/attack-simulation/VIDEO-01.md) |
| **VMware ESXi** | Infrastructure Virtualization | Virtual switch port groups, VLAN broadcast domains, and virtual machine hardware resource allocation. | [`docs/02_SYSTEM_ARCHITECTURE.md`](file:///e:/project_ca_nhan/lab_cty/docs/02_SYSTEM_ARCHITECTURE.md) |

---

## 2. CV Skill Groupings (Directly Supported by Evidence)

When adding skills to your resume, select from these groupings:

### Security Architecture & Engineering
* Multi-Zone Network Segmentation (VLANs / vSwitches)
* Security Transit Architecture & Choke Point Enforcement
* Defense-in-Depth Design & Compensatory Host Controls
* Out-of-Band Management & Logging Isolation
* Zero-Trust Interface Design Concepts

### Network Security & Perimeter Defense
* pfSense Firewall Policy Configuration & Stateful Inspection
* Network Address Translation (DNAT / SNAT / Egress Control)
* Suricata Inline Intrusion Prevention System (`NFQUEUE` / Layer-7 DPI)
* Network Detection & Response (Zeek Metadata Extraction & Session Analysis)
* Host-Based Linux Firewalling (`iptables` Rule Design)

### SIEM Engineering & Telemetry Operations
* ArcSight ESM Real-Time Correlation & Active Channel Triage
* ArcSight Logger Administration, Indexing & SHA-256 Storage Integrity
* ArcSight SmartConnector & FlexConnector Deployment
* Common Event Format (CEF) Schema Field Mapping & Parser Optimization
* Windows Event Forwarding (WEC / WEF) & Syslog Architecture

### Detection Engineering
* Atomic Behavioral Rule Design (MITRE ATT&CK Alignment)
* Multi-Source Stateful Temporal Correlation Logic
* Sliding-Window Threshold Burst Detection
* SIEM Query Formulation & CEF Filter Tuning
* Alert Fatigue Mitigation & Console Triage Optimization

### Incident Investigation & Digital Forensics
* Hypothesis-Driven SOC Triage & Root-Cause Analysis
* Endpoint Process Lineage Reconstruction (`ProcessGuid` Tracking)
* Network Session & Socket Correlation (`ZeekUID` / Sysmon Event ID 3)
* Forensic Email Backtracking (SMTP Queue ID Tracing)
* Database Query Audit Forensics (MariaDB `SERVER_AUDIT`)
* Linux Host & Container Forensics (Auditd `execve` Syscalls)
* Timeline Assembly & Attack Chain Reconstruction

### Systems & Platform Administration
* Windows Server 2019 & Active Directory Domain Services (AD DS)
* Windows Endpoint Auditing (Sysmon Modular XML & Group Policy)
* Linux System Administration (Debian / Ubuntu / Rsyslog)
* Docker Container Auditing & Runtime Inspection
* Relational Database Administration (MariaDB / MySQL)
