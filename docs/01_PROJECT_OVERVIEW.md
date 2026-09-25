# Enterprise SOC Lab — Project Overview

## 1. Project Summary

The **Enterprise SOC Lab: Network Security, SIEM Detection & Incident Investigation** is an integrated security operations and architecture laboratory designed, implemented, and empirically validated to replicate an enterprise-scale defensive ecosystem. Rather than functioning as an arbitrary assortment of disconnected virtual machines, the environment represents a cohesive, multi-layered security infrastructure engineered around three foundational pillars:

```text
                        ENTERPRISE SOC LAB ECOSYSTEM
┌─────────────────────────────────┬─────────────────────────────────┬─────────────────────────────────┐
│     ENFORCED TRAFFIC PATH       │     MULTI-TIER TELEMETRY        │      CENTRALIZED SIEM & SOC     │
│   Network Security & Transit    │   Full-Stack Log Normalization  │    Correlation & Investigation  │
├─────────────────────────────────┼─────────────────────────────────┼─────────────────────────────────┤
│ • Multi-zone segmentation       │ • Perimeter firewall logs       │ • Decoupled Logger vs ESM roles │
│ • Zero-bypass Security Transit  │ • Inline IPS alert telemetry    │ • Real-time correlation (A01-13)│
│ • Suricata Inline IPS (NFQUEUE) │ • Passive NDR network metadata  │ • Multi-source correlation (C01)│
│ • Stateful perimeter filtering  │ • Kernel-level endpoint logs    │ • Storage data integrity hashes │
│ • L2 intra-subnet host control  │ • Identity & authentication logs│ • Black-box trigger-driven triage│
│ • Controlled outbound egress    │ • Application & database audits │ • Time & ProcessGuid pivoting   │
└─────────────────────────────────┴─────────────────────────────────┴─────────────────────────────────┘
```

The laboratory integrates **network security enforcement**, **inline traffic inspection**, **passive network detection**, **endpoint auditing**, **identity governance**, **application telemetry**, **database activity monitoring**, **centralized event normalization (CEF)**, **real-time SIEM correlation**, and **evidence-based incident investigation**.

---

## 2. Problem Statement

In modern enterprise IT environments, security events and attacker traces do not manifest within a single isolated device or log stream. Sophisticated intrusions operate across distinct functional boundaries—leveraging email gateways for initial delivery, abusing endpoint interpreters for code execution, establishing outbound command-and-control channels, utilizing network tunnels for lateral movement, and ultimately compromising databases to harvest intellectual property.

This operational reality introduces three fundamental challenges:

1. **The Distributed Evidence Dilemma**: A perimeter firewall may see an outbound connection but cannot determine what process spawned it. An inline IPS may detect an attack signature but lacks visibility into intra-subnet lateral movement. A database audit plugin records an unauthorized SQL dump but cannot determine how the adversary bridged the perimeter. Single-source monitoring creates operational blind spots.
2. **The Bypass & Segmentation Failure**: In flat or improperly segmented architectures, perimeter defenses are easily bypassed once an attacker establishes a local foothold. If a perimeter firewall can resolve endpoints directly across Layer 2, security devices placed in parallel become non-enforcing spectators.
3. **The Alert-to-Evidence Gap**: Real-time correlation engines generate point-in-time alerts, but an individual alert does not constitute a complete incident narrative. SOC analysts require the ability to rapidly pivot from an alert trigger to full-fidelity raw logs, reconstructing the attacker's trajectory backward to the point of entry and forward to data exfiltration.

The Enterprise SOC Lab was built to solve these specific architectural and operational challenges.

---

## 3. Project Objectives

The project addresses these challenges through five concrete, engineering-driven objectives:

1. **Enforce Mandatory Traffic Choke Points**: Design and validate a dedicated **Security Transit** network architecture that guarantees all traffic passing between the untrusted perimeter and protected internal zones traverses an inline Deep Packet Inspection (DPI) engine (`SURICATA-IPS01`), eliminating direct routing bypasses.
2. **Establish Multi-Tier Telemetry Ingestion**: Deploy, configure, and operate a centralized telemetry pipeline ingesting disparate event streams from network, operating system, directory service, and application layers over an isolated logging plane.
3. **Implement Full-Fidelity CEF Normalization**: Construct custom FlexConnector parsers to normalize disparate raw logs into the **Common Event Format (CEF)**, preserving critical correlation keys (`sourceAddress`, `destinationAddress`, `ProcessGuid`, `QueueID`, `connection_id`).
4. **Demonstrate Decoupled SIEM Operations**: Architect and operate **ArcSight ESM** for real-time sub-second correlation and **ArcSight Logger** for high-compression raw storage, forensic query analysis, and cryptographic evidence preservation adhering to **NIST SP 800-86**.
5. **Execute Empirical Attack & Investigation Cycles**: Subject the architecture to a multi-stage attack campaign mapped to the **MITRE ATT&CK for Enterprise** framework, validate detection rules (`A01–A13`, `C01`), perform forensic timeline reconstruction, apply targeted system hardening, and conduct empirical re-verification.

---

## 4. Security Objectives

* **Zero Implicit Route Bypass**: Ensure that perimeter firewall routing tables have no direct Layer-2 or Layer-3 adjacencies to internal or DMZ assets.
* **Fail-Close Inline Posture**: Configure kernel-level packet inspection via Netfilter Queue (NFQUEUE) such that failure of the inspection daemon results in a closed failure mode, preventing uninspected packets from entering protected segments.
* **Defense-in-Depth Beyond Layer 3**: Mitigate same-subnet Layer-2 blind spots (where endpoints communicate directly over switch fabric without hitting gateways) using host-based firewalls, database access controls, and endpoint auditing.
* **Separation of Planes**: Completely decouple business traffic (Data Plane) from telemetry collection (Logging Plane) and administrative access (Management Plane) using non-routable dedicated network interfaces.
* **Cryptographic Evidence Integrity**: Enforce role-based access control and block-level hash validation on central log storage to prevent tampering by unauthorized users or compromised service accounts.

---

## 5. Architecture at a Glance

The lab is organized into six strictly segregated logical network zones:

```text
       Simulated Public Internet (203.0.113.0/24)
           │
           ▼
    [PFSENSE-01]  (Perimeter Firewall / NAT Gateway)
           │
           ▼ (Static Route via 10.10.36.11)
    [SECURITY TRANSIT (10.10.36.0/24)]
           │
           ▼ (NFQUEUE Inline DPI & L3 Routing)
    [SURICATA-IPS01]
           │
     ┌─────┴─────────────────────────┐
     ▼                               ▼
 [DMZ (10.10.34.0/24)]     [INTERNAL (10.10.35.0/24)]
  • WEB01 (Frappe HRMS)     • DC01 (AD Domain & DNS)
  • MAIL01 (Postfix Mail)   • DB01 (MariaDB Database)
                            • IT-ADMIN01 (Privileged Workstation)
                            • WIN10-01..03 (Corporate Endpoints)

 ════════════════════ DEDICATED PLANES ════════════════════
 [LOGGING PLANE (10.10.40.0/24)]    [MANAGEMENT PLANE (10.10.21.0/24)]
  • SmartConnector (10.10.40.4)      • Bastion Jump Host (10.10.21.100)
  • ArcSight Logger (10.10.40.5)     • Out-of-band device admin NICs
```

---

## 6. Technology Stack

| Domain | Technology / Platform | Version / Details | Architectural Role |
| :--- | :--- | :--- | :--- |
| **Virtualization** | VMware vSphere | Multi-VM ESXi Environment | Infrastructure hypervisor hosting isolated portgroups and vSwitches |
| **Perimeter Security** | pfSense | CE Appliance | Stateful packet filter, NAT/DNAT for public VIPs, static inter-zone routing |
| **Inline IPS / Router**| Suricata | 7.0.x on Ubuntu Linux | Layer-3 router, NFQUEUE inline Deep Packet Inspection, Fail-Close enforcement |
| **Network Visibility** | Zeek (formerly Bro) | 7.2.x on Linux | Passive network detection & response, application protocol extraction via SPAN |
| **Directory & Identity**| Microsoft Active Directory | Windows Server 2019 Standard | Domain Services (`soclab.test`), LDAPS (`TCP/636`), Kerberos, GPO, Internal DNS |
| **Core Application** | Frappe HRMS / ERPNext | v16 on Docker / Traefik v3.6 | Containerized human resource application, integrated with AD via LDAPS |
| **Database Engine** | MariaDB | 10.11 on Ubuntu 24.04 LTS | Relational database backend, protected by iptables, audited via `SERVER_AUDIT` |
| **Mail Services** | Postfix / Dovecot | Ubuntu Linux | Inbound/outbound SMTP (`TCP/25`), IMAP, Roundcube webmail interface |
| **Public Services** | BIND9 / Forward Proxy | Linux / Squid | Public authoritative DNS (`DNS-PUB01`), outbound web control proxy (`:8132`) |
| **Endpoint Auditing** | Microsoft Sysmon / PowerShell | Schema v4.91 / Win 10 Pro | Process genealogy (`ProcessGuid`), network connect (Event 3), ScriptBlock (4104) |
| **Host Auditing** | Linux Auditd | Audit subsystem on WEB01 | Kernel system call monitoring (`execve`) tagged with key `-k web_exec` |
| **SIEM & Ingestion** | Micro Focus ArcSight | SmartConnector / FlexConnector | Ingests 8 raw log feeds, applies regex parsing, outputs encrypted CEF SmartMessages |
| **Raw Event Storage** | Micro Focus ArcSight Logger | 7.2.x Appliance | High-compression compressed event storage, Verify Storage data hash validation |
| **Real-Time SIEM** | Micro Focus ArcSight ESM | 7.2.x Appliance | Real-time correlation rules engine, Active Lists, Active Channels live monitoring |
| **Adversary Testing** | Kali Linux | Rolling Distribution | External testing host running phishing scripts, HTA payloads, Ligolo-ng, Netcat |

---

## 7. Detection and Investigation Capability

The SOC architecture pairs automated real-time alert generation with deep forensic query capabilities:

* **Detection Layer (ArcSight ESM)**: Evaluates normalized CEF events against 13 Atomic Rules (`A01–A13`) spanning delivery, execution, persistence, discovery, lateral movement, database abuse, and exfiltration. A Multi-Source Correlation Rule (`C01`) correlates external web download (`A02`), script execution (`A03`), and reverse shell callback (`A04`) within a sliding 20-minute time window ($\Delta t \le 20\text{ min}$).
* **Investigation Layer (ArcSight Logger)**: Enables trigger-driven, black-box retrospective investigation. Analysts pivot on unique forensic keys:
  * **Network Session**: `ZeekUID` (`cs2`), Suricata `FlowID` (`cs1`).
  * **Mail Lifecycle**: Postfix `Queue ID` (`cs3` = `718FC8006A`).
  * **Process Lineage**: Sysmon `ProcessGuid` (`cs5`) and `ParentProcessGuid`, circumventing OS Process ID (PID) reuse limitations.
  * **Database Context**: MariaDB `connection_id` and raw query strings (`cs3`).

---

## 8. Attack Simulation Scope

To validate the defense and monitoring architecture against realistic adversary tactics, the lab was subjected to an end-to-end, multi-stage cyber attack scenario executed from external infrastructure (`203.0.113.25`):

```text
    STAGE 1                 STAGE 2                 STAGE 3                 STAGE 4                 STAGE 5
Initial Delivery      Execution & Callback    Discovery & Harvesting    Pivoting & Movement     Database Exfiltration
┌──────────────┐       ┌──────────────┐       ┌──────────────┐       ┌──────────────┐       ┌──────────────┐
│Spear-phishing│ ----> │mshta.exe runs│ ----> │Local recon & │ ----> │Deploy Ligolo │ ----> │sudo docker   │
│email spoofing│       │powershell.exe│       │Firefox theft │       │reverse tunnel│       │exec reads DB │
│security update│      │Reverse Shell │       │Netsocket send│       │SSH into WEB01│       │config. Dump  │
│KB504991.zip  │       │to :4444 (C2) │       │profile to :9999      │via DMZ tunnel│       │tabEmployee   │
└──────────────┘       └──────────────┘       └──────────────┘       └──────────────┘       │Netcat to :9999
                                                                                            └──────────────┘
```

Every stage of this campaign was observed across multiple telemetry layers, correlated in ESM, investigated in Logger, and contained through validated countermeasures.

---

## 9. Key Engineering Characteristics

1. **Deterministic Traffic Routing**: No packet moves between trust zones without explicit traversal of `SURICATA-IPS01`.
2. **Normalized Schema Compliance**: 100% of collected security data is mapped to the standard CEF schema, preserving essential forensic parameters across heterogeneous source platforms.
3. **Separation of Functional Planes**: Administrative access and telemetry pipelines remain completely independent of the production data path.
4. **Empirical Verification Methodology**: Every security control is tested using a two-stage evaluation methodology—demonstrating failure/compromise prior to hardening, followed by strict verification of mitigation post-hardening while confirming normal business operations remain unaffected.

---

## 10. Known Limitations

In the interest of technical accuracy, the documentation explicitly records the following architectural boundaries:

1. **Intra-Subnet L2 Blind Spot**: Suricata does not inspect communications occurring between devices sharing the same broadcast domain (`10.10.35.0/24`). Host-based firewalls and endpoint logs serve as compensatory controls.
2. **Encrypted Payload DPI Boundary**: Suricata operates without active SSL/TLS interception; inspection of encrypted sessions (SSH, TLS, HTTPS) is limited to transport metadata, session volume, and certificate exchanges.
3. **Stateless UDP Ingestion Risk**: Most log streams utilize Syslog over UDP to reach the SmartConnector. Socket queue exhaustion or oversized SQL audit strings exceeding standard MTU (1500 bytes) risk dropped or truncated records during bursts.
4. **Manual Response Orchestration**: Although an `ArcSight-SOAR` virtual machine exists on the hypervisor, incident containment (firewall rule insertion, process termination, credential rotation) was executed manually. Automated SOAR playbooks were not implemented in this phase.

---

## 11. Project Status

* **Architecture & Network Implementation**: **COMPLETE & CONFIRMED**
* **Telemetry Pipeline & CEF Normalization**: **COMPLETE & CONFIRMED**
* **SIEM Operations (Logger & ESM)**: **COMPLETE & CONFIRMED**
* **Rule Engineering & Attack Simulation**: **COMPLETE & EMPIRICALLY VALIDATED**
* **Incident Response & Hardening Re-testing**: **COMPLETE & CONFIRMED**
* **Public Documentation & Sanitization**: **CURRENT PHASE (PHASE 3)**
