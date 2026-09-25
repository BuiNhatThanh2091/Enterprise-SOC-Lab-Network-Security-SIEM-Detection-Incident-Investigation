# Portfolio Strategy & Professional Positioning

## 1. Project Positioning & Identity

The **Enterprise SOC Lab** is positioned as:

> **An enterprise-style security operations and architecture laboratory integrating perimeter firewall enforcement, inline intrusion prevention (IPS), passive network monitoring (NDR), multi-tier endpoint and host auditing, centralized log normalization, real-time SIEM correlation, and evidence-driven incident investigation.**

### What It IS
* An **implemented, empirically validated laboratory environment** deployed on VMware ESXi hypervisors.
* A demonstration of **system-level security thinking**: showing how network segmentation, sensor instrumentation, CEF normalization, SIEM rules, and forensic pivoting operate together as an integrated defensive workflow.
* A structured portfolio of **13 atomic detections (`A01`–`A13`)**, **1 multi-source composite correlation rule (`C01`)**, and **5 forensic incident investigation case studies** backed by verified log artifacts.

### What It IS NOT (Prohibited Positioning)
* It is **NOT** a "production-grade enterprise SOC" (it operates in a controlled lab environment without 24/7 SLA shifts or multi-tenant production traffic).
* It is **NOT** "military-grade", "cutting-edge AI-powered", or "100% breach-proof".
* It does **NOT** feature commercial enterprise tools not present in the lab (such as EDR agents, SOAR platforms, commercial Threat Intelligence Platforms, or cloud security posture tooling).
* It is **NOT** an abstract theoretical design; every claim is grounded in physical and logical implementation facts.

---

## 2. Primary Technical Themes

The project demonstrates technical competence across eight cohesive security domains:

```text
┌─────────────────────────────────┬─────────────────────────────────┐
│ TECHNICAL THEME                 │ CONCRETE LAB DEMONSTRATION      │
├─────────────────────────────────┼─────────────────────────────────┤
│ 1. Security Architecture        │ Multi-zone VLAN segmentation, zero-bypass Security Transit choke │
│                                 │ point, out-of-band management plane, and L2 bypass defense.    │
├─────────────────────────────────┼─────────────────────────────────┤
│ 2. Network Security Enforcement │ pfSense stateful packet filtering, DNAT/SNAT, egress control,   │
│                                 │ and Suricata inline IPS (NFQUEUE) deep packet inspection.       │
├─────────────────────────────────┼─────────────────────────────────┤
│ 3. Passive Network Monitoring   │ Zeek (Bro) metadata extraction, protocol analysis (conn.log),   │
│                                 │ session duration metrics, and flow volumetrics.                 │
├─────────────────────────────────┼─────────────────────────────────┤
│ 4. Full-Stack Telemetry         │ Microsoft Sysmon (XML), PowerShell ScriptBlock (4104), Linux   │
│                                 │ Auditd (execve), MariaDB SERVER_AUDIT, and Postfix syslog.      │
├─────────────────────────────────┼─────────────────────────────────┤
│ 5. SIEM Normalization & Storage │ ArcSight SmartConnector CEF parsing, decoupled ArcSight Logger  │
│                                 │ immutable retention (SHA-256) vs. real-time ArcSight ESM.       │
├─────────────────────────────────┼─────────────────────────────────┤
│ 6. Detection Engineering        │ Atomic rule design (A01–A13), sliding-window threshold bursts,  │
│                                 │ and stateful multi-source temporal correlation (C01).           │
├─────────────────────────────────┼─────────────────────────────────┤
│ 7. Incident Investigation       │ Hypothesis-driven triage, Logger ad-hoc search queries,         │
│                                 │ process tree lineage extraction, timeline assembly, and pivots. │
├─────────────────────────────────┼─────────────────────────────────┤
│ 8. Defensive Attack Simulation  │ Red Team attack execution (phishing lure, LOLBins, tunneling,   │
│                                 │ database extraction) used strictly to validate defensive alert. │
└─────────────────────────────────┴─────────────────────────────────┘
```

---

## 3. Target Technical Roles & Competency Mapping

The project provides concrete, portfolio-grade evidence for several technical security career paths without artificial ranking:

### 3.1. SOC Analyst (Tier-1 / Tier-2)
* **Demonstrated Competencies**:
  * Triage of high-priority ESM Active Channel alerts.
  * Formulating testable investigative hypotheses rather than passively accepting alerts.
  * Deep forensic searching on ArcSight Logger using CEF field filtering.
  * Genealogical process tracing (`ProcessGuid` and `ParentProcessGuid`) to unravel Living-off-the-Land execution.
  * Cross-source timeline reconstruction combining Postfix mail logs, Suricata alerts, Sysmon process creation, and Zeek flow durations.
* **Key Portfolio Assets to Showcase**:
  * [Case 001: Initial Compromise Investigation](file:///e:/project_ca_nhan/lab_cty/investigation/case-001/README.md)
  * [Case 004: Lateral Movement & DB Dump](file:///e:/project_ca_nhan/lab_cty/investigation/case-004/README.md)
  * [Investigation Workflow Diagram](file:///e:/project_ca_nhan/lab_cty/architecture/investigation-workflow.svg)

### 3.2. Detection Engineer / SIEM Content Developer
* **Demonstrated Competencies**:
  * Engineering atomic behavioral detections for specific MITRE ATT&CK techniques.
  * Developing multi-source composite correlation rules in ArcSight ESM joining perimeter, host, and network streams.
  * Understanding CEF normalization and identifying mandatory schema fields (`deviceCustomString`, `destinationPort`, `externalId`).
  * Evaluating sliding temporal windows ($\Delta t \le 20\text{m}$) and sliding threshold counts (6 commands in 60s).
  * Documenting detection limitations, threshold evasion risks, and tuning active channel filters to reduce alert fatigue.
* **Key Portfolio Assets to Showcase**:
  * [Detection Engineering Hub](file:///e:/project_ca_nhan/lab_cty/detection/README.md)
  * [Rule C01: Initial Compromise Correlation](file:///e:/project_ca_nhan/lab_cty/detection/C01/README.md)
  * [Detection Validation Matrix](file:///e:/project_ca_nhan/lab_cty/detection/VALIDATION_MATRIX.md)
  * [Detection Limitations Specification](file:///e:/project_ca_nhan/lab_cty/docs/08_DETECTION_LIMITATIONS.md)

### 3.3. Network Security / Perimeter Defense Engineer
* **Demonstrated Competencies**:
  * Designing multi-zone network segmentation across DMZ, Internal, Security Transit, and Logging VLANs.
  * Configuring pfSense stateful firewall policies, NAT port forwarding, and egress filtering.
  * Deploying Suricata in inline IPS mode (`NFQUEUE`) to enforce active packet inspection.
  * Identifying and mitigating hardware-level broadcast domain blind spots (Layer-2 switching bypass) using host-level compensatory firewalls (`iptables` on `DB01`).
* **Key Portfolio Assets to Showcase**:
  * [Network Architecture Specification](file:///e:/project_ca_nhan/lab_cty/docs/03_NETWORK_ARCHITECTURE.md)
  * [Network Security Flow Diagram](file:///e:/project_ca_nhan/lab_cty/architecture/network-security-flow.svg)
  * [Engineering Decisions: Security Transit](file:///e:/project_ca_nhan/lab_cty/docs/ENGINEERING_DECISIONS.md)

### 3.4. Security Operations & Telemetry Engineer
* **Demonstrated Competencies**:
  * Building multi-tier log forwarding pipelines spanning Windows (WEC/Sysmon), Linux (Auditd/Rsyslog), and network appliances.
  * Configuring ArcSight SmartConnector listeners across dedicated ports with specific Generator IDs.
  * Architecturally decoupling SIEM operations: balancing real-time memory-bound correlation (ESM) against cold, immutable disk storage (Logger).
  * Validating tamper-evident storage integrity via SHA-256 event hashing.
* **Key Portfolio Assets to Showcase**:
  * [Full-Stack Telemetry Architecture](file:///e:/project_ca_nhan/lab_cty/docs/05_TELEMETRY_ARCHITECTURE.md)
  * [Telemetry Flow Diagram](file:///e:/project_ca_nhan/lab_cty/architecture/telemetry-flow.svg)
  * [Curated Telemetry Manifests](file:///e:/project_ca_nhan/lab_cty/evidence/telemetry/README.md)
