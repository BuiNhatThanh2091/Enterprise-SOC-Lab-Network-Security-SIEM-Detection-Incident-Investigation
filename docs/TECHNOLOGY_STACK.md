# Technology Stack Specification

## 1. Overview & Verification Scope

The **Enterprise SOC Lab** incorporates an enterprise-grade defensive and analytical technology stack deployed across physical VMware ESXi hypervisors. Every component documented in this specification has been empirically installed, interconnected, and validated through real-world attack simulations and telemetry collection.

No speculative, unconfirmed, or theoretical products (such as EDR, SOAR, or commercial Threat Intelligence Platforms) are included.

---

## 2. Implemented Technology Matrix

| Architectural Layer | Product / Technology | Version / Release | Primary Operational Role in Laboratory | Telemetry & Normalization Format |
| :--- | :--- | :--- | :--- | :--- |
| **Boundary Routing & Firewall** | **pfSense** | Community Edition | State tracking, inter-zone routing, perimeter egress filtering, and NAT. | Filterlog via Syslog $\rightarrow$ SmartConnector |
| **Inline Intrusion Prevention** | **Suricata** | IPS Mode (NFQUEUE) | Layer 7 deep packet inspection, signature enforcement, and inline payload blocking. | EVE JSON alerts via Syslog $\rightarrow$ SmartConnector |
| **Network Detection & Analysis** | **Zeek (Bro)** | Network Security Monitor | Passive session protocol analysis, session duration metrics, and flow metadata extraction. | `conn.log` TSV via SmartConnector |
| **Windows Endpoint Telemetry** | **Microsoft Sysmon** | Modular XML Schema | Kernel-level process creation (ID 1), network connections (ID 3), file creation, and image loads. | Windows Event Log (WEC) $\rightarrow$ SmartConnector |
| **PowerShell Auditing** | **Windows ScriptBlock** | PowerShell 5.1 / GPO | De-obfuscated script block content logging (Event ID 4104) and transcription. | Windows Event Log (WEC) $\rightarrow$ SmartConnector |
| **Identity & Access Governance** | **Active Directory DS** | Windows Server 2019 | Domain authentication, Kerberos ticket auditing (4768/4769), and account logon events (4624). | Security Event Log $\rightarrow$ SmartConnector |
| **Linux Host Auditing** | **Linux Auditd** | Kernel subsystem | System call interception (`execve`), privileged escalation tracking, and container execution. | `audit.log` via Rsyslog $\rightarrow$ SmartConnector |
| **Operating System Syslog** | **Linux Rsyslog / Auth** | Debian / Ubuntu Core | Secure shell login tracking (`auth.log`), sudo executions, and service status updates. | RFC 3164 Syslog $\rightarrow$ SmartConnector |
| **Mail Gateway & Delivery** | **Postfix / Dovecot** | Debian Core | Inbound SMTP mail routing, SPF/DKIM verification, and user mailbox delivery. | Postfix Syslog $\rightarrow$ SmartConnector |
| **Database Activity Monitoring** | **MariaDB Server** | Server 10.x + Audit Plugin | Relational data storage and database query logging (`SERVER_AUDIT` plugin: CONNECT, QUERY, TABLE). | Syslog $\rightarrow$ SmartConnector |
| **Event Normalization Engine** | **ArcSight SmartConnector**| FlexConnector Suite | High-speed log collection, parsing, field mapping, and CEF encapsulation. | Common Event Format (CEF) over Syslog/TCP |
| **Immutable Log Storage & Search**| **ArcSight Logger** | Enterprise Appliance | Cold log retention, tamper-evident SHA-256 event hashing, and ad-hoc forensic searching. | Indexed CEF Store / SQL Search |
| **Real-Time SIEM Correlation** | **ArcSight ESM** | Real-Time Engine | Stateful multi-source correlation, sliding temporal windows, and Active Channel dispatch. | In-Memory Correlation Matrix |
| **Management Jumphost** | **Linux / Windows** | Core Workstation | Centralized administrative interface for ESM Console, Logger UI, and firewall management. | Operational Console |
| **Adversary Simulation Platform** | **Kali Linux** | Security Suite | Structured red-team attack simulation (phishing generation, LOLBin stagers, Ligolo tunneling, Netcat). | External Attacker (`203.0.113.25`) |

---

## 3. Technology Integration Architecture

The components do not operate in silos; they form a cohesive, multi-stage detection and verification pipeline:

```text
[ Endpoint & Network Sensors ]
   ├── Sysmon & PowerShell (IT-ADMIN01, DC01)
   ├── Postfix & Dovecot (MAIL01)
   ├── Linux Auditd & Auth (WEB01)
   ├── MariaDB Audit Plugin (DB01)
   ├── Suricata IPS Inline (Transit 10.10.36.11)
   └── Zeek Passive Tap (Transit 10.10.36.11)
                 │
                 ▼
[ Collection & Normalization ]
   └── ArcSight SmartConnector (10.10.40.4) ──► Normalizes all events to Common Event Format (CEF)
                 │
                 ├───► [ Retention & Forensics ] ──► ArcSight Logger (10.10.40.5)
                 │                                    • Long-term storage & SHA-256 data hashing
                 │                                    • Ad-hoc SQL & CEF deep investigation search
                 │
                 └───► [ Real-Time Correlation ] ──► ArcSight ESM (10.10.21.10)
                                                      • In-memory rule engine (A01–A13, C01)
                                                      • Active Channels & Real-time incident dispatch
```
