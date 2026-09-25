# Key Engineering Highlights

This document highlights the concrete engineering achievements, architectural decisions, and analytical capabilities demonstrated throughout the **Enterprise SOC Lab**.

---

## 1. Security Architecture Highlights

* **Multi-Zone VLAN Broadcast Domain Segmentation**:
  Isolated the enterprise estate into five dedicated subnets (`EXTERNAL_NET`, `DMZ_NET`, `INTERNAL_NET`, `SECURITY_TRANSIT`, `LOGGING_NET`, and `MANAGEMENT_NET`), preventing direct, un-monitored inter-zone routing across virtual switches.
* **Deterministic Security Transit Choke Point**:
  Engineered an isolated intermediate transit subnet (`10.10.36.0/24`) positioned strictly between the perimeter firewall (`pfSense`, `.10`) and monitored enterprise networks, forcing all cross-zone traffic through deep packet inspection on Suricata (`.11`).
* **Hardware-Level Layer-2 Bypass Defense**:
  Identified that co-located internal hosts (`IT-ADMIN01` and `DB01`) communicate via Layer-2 ARP switching, bypassing the default gateway. Successfully deployed host-level `iptables` on `DB01` as a verified compensatory control to block unauthorized local access.
* **Dual-Sensor Inspection Strategy (Suricata + Zeek)**:
  Positioned Suricata in inline IPS mode (`NFQUEUE`) for active Layer-7 payload blocking alongside Zeek in passive tap mode for protocol session state extraction, achieving simultaneous blocking capability and behavioral metadata retention.
* **Out-of-Band Management & Logging Isolation**:
  Isolated SIEM correlation, log aggregation, and administrative consoles onto dedicated non-routable subnets accessible only via an authenticated bastion jump host (`MGMT-JUMPHOST`).

---

## 2. Detection Engineering Highlights

* **Composite Stateful Correlation (`C01`)**:
  Engineered an in-memory temporal correlation rule in ArcSight ESM joining three independent data sources—perimeter HTTP download (`A02`), host `mshta.exe` execution (`A03`), and outbound TCP port 4444 callback (`A04`)—on a matching host entity within a 20-minute sliding window.
* **13 Verified Atomic Detection Rules (`A01`–`A13`)**:
  Authored and validated detection logic across multiple MITRE ATT&CK stages:
  * Mail Delivery Context (`A01`)
  * Ingress Executable Web Download (`A02`)
  * LOLBin Script Execution (`A03`)
  * Outbound C2 Callback (`A04`)
  * Discovery Command Burst (`A05`)
  * Browser Profile Staging (`A06`)
  * PowerShell Socket Exfiltration (`A07`)
  * Living-off-the-Land Tool Ingress (`A08`)
  * External Tunnel Establishment (`A09`)
  * Inter-Zone SSH Lateral Movement (`A10`)
  * Privileged Docker Container Abuse (`A11`)
  * Relational Database Schema Enumeration (`A12`)
  * DMZ Staging Data Exfiltration (`A13`)
* **Sliding-Window Frequency Thresholding (`A05`)**:
  Implemented high-frequency threshold logic detecting adversary reconnaissance bursts ($\ge 3\text{ diagnostic commands in } 5\text{ minutes}$) under the same parent process tree.
* **Active Channel Alert Volume Management**:
  Tuned the primary ESM monitoring console by applying targeted display filters (`Name != A04*`) to suppress repetitive reverse shell heartbeat updates, mitigating analyst alert fatigue while preserving rule evaluation in memory.

---

## 3. Incident Investigation & Forensics Highlights

* **Hypothesis-Driven Forensic Investigation**:
  Structured all incident responses around formal causal hypothesis testing rather than passive alert viewing, proving or disproving attacker activities through multi-source correlation.
* **Immutable Process Tree Reconstruction**:
  Overcame operating system PID recycling by tracking immutable 128-bit Sysmon `ProcessGuid` values across ArcSight Logger queries, reconstructing the genealogical chain: `explorer.exe` $\rightarrow$ `mshta.exe` $\rightarrow$ `cmd.exe /c` $\rightarrow$ `powershell.exe`.
* **Multi-Source Cross-Telemetry Pivoting**:
  Demonstrated advanced investigative pivots across heterogenous data silos:
  * Pivoted from a Suricata download alert to Postfix mail gateway delivery logs to discover the original spearphishing lure (QueueID `718FC8006A`).
  * Correlated Sysmon Event ID 3 socket bindings with passive Zeek `conn.log` metadata (`ZeekUID = C9xKa811`) to verify interactive session longevity.
  * Correlated Linux `auth.log` SSH logins with Linux Auditd `execve` syscalls and MariaDB `SERVER_AUDIT` logs to prove cross-zone database extraction.
* **Attack Chain & Timeline Assembly**:
  Reconstructed unified, second-by-second chronological incident timelines across 5 comprehensive case studies, validating adversary containment and eradication.

---

## 4. Engineering & Operational Highlights

* **Architectural Decoupling of SIEM Operations**:
  Separated SIEM responsibilities between ArcSight Logger (high-capacity indexed storage with SHA-256 tamper-evident event hashing) and ArcSight ESM (in-memory real-time rule correlation), preventing query I/O contention from impacting real-time detection latency.
* **Common Event Format (CEF) Schema Engineering**:
  Engineered SmartConnector parser mappings across 8 distinct source groups, ensuring critical investigation parameters (`CommandLine`, `ParentProcessGuid`, `ZeekUID`, `QueueID`) are normalized into standard CEF fields.
* **Transparent Recognition of Technical Limitations**:
  Maintained engineering integrity by formally identifying operational boundaries: documenting same-L2 visibility gaps, threshold evasion risks on sliding windows, and the dependency of rules `A04`, `A09`, and `A13` on specific scenario test ports.
* **Closed-Loop Hardening & Remediation**:
  Translated forensic findings into concrete defensive controls: deploying GPO file association restrictions for `.hta`, applying host-based database `iptables` rules, and converting Suricata exfiltration signatures from alert to drop mode.

---

## 5. Technical Demonstration & Walkthrough Highlights

* **Prepared for YouTube Unlisted Hosting (3 Official Videos)**:
  The laboratory's technical screen recordings are structured into 3 official videos hosted externally on YouTube as Unlisted:
  * **Video 01 — Attack Simulation**: Red Team multi-stage intrusion execution and observable telemetry generation.
  * **Video 02 — Full Investigation Walkthrough**: End-to-end incident investigation from composite alert `C01` triage to perimeter containment.
  * **Video 03 — Supplementary Investigation Walkthrough**: Technical deep-dive on low-level forensics, script block decoding, and secondary pivots.
* **Process-Driven Investigation Recordings**:
  Video walkthroughs capture the dynamic analytical process of the SOC analyst—moving from alert notification through hypothesis formulation, Logger deep search queries, process tree lineage extraction, and firewall drop validation.

