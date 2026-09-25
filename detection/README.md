# Detection Engineering Portfolio & Rules Index

## 1. Overview & Detection Philosophy

Threat detection is not an isolated capability; it is a logical analysis layer that depends fundamentally on the underlying network architecture, telemetry instrumentation, and data normalization pipeline. 

In the Enterprise SOC Lab, detection engineering is structured around **atomic event verification** coupled with **multi-source temporal correlation**. The detection portfolio comprises:
* **13 Atomic Detection Rules (`A01–A13`)**: Purpose-built detections evaluating specific observable behaviors across network, endpoint, application, and database event streams.
* **1 Multi-Source Correlation Rule (`C01`)**: A stateful correlation rule linking ingress download, host-based execution, and outbound command-and-control callback across three independent data sources within a sliding time window.

```text
       ====================== DETECTION ARCHITECTURE FLOW ======================

  [RAW EVENT SOURCES]                [INGESTION & CEF]                [DETECTION & CORRELATION]
  • Postfix Syslog             ──►  ArcSight SmartConnector    ──►  A01: Postfix Mail Delivery (Context)
  • Suricata eve.json (DPI)    ──►  (CEF Normalization)        ──►  A02: External Web Download (SID 1101002) ──┐
  • Microsoft Sysmon (XML)     ──►  Preserves keys:            ──►  A03: Script Exec mshta.exe (Event ID 1) ───┼──► C01: Initial
  • Zeek conn.log (Metadata)   ──►  ProcessGuid, QueueID,      ──►  A04: Outbound C2 Callback (TCP/4444)   ───┘    Compromise
  • PowerShell ScriptBlock     ──►  ZeekUID, FlowID            ──►  A05: Post-Compromise Discovery Burst
  • Linux Auditd (web_exec)    ──►                             ──►  A06: Firefox Profile Staging (xcopy)
  • MariaDB SERVER_AUDIT       ──►                             ──►  A07: Data Staging / Raw Socket
                                                               ──►  A08: Tool Transfer / Execution
                                                               ──►  A09: Ligolo-ng Tunnel Session
                                                               ──►  A10: Inter-Zone SSH to DMZ (Context)
                                                               ──►  A11: Privileged Sudo Docker Exec
                                                               ──►  A12: Database Structural Enumeration
                                                               ──►  A13: DMZ Exfiltration Stream (SID 1101021)
```

---

## 2. Detection Coverage Matrix

| ID | Detection Name | Telemetry Source | Observable Behavior | Detection Type | Threshold / Window | Real-Time? | Validation Status | Core Limitation |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **A01** | Mail Delivered to Internal User | Postfix Syslog | Mailbox local delivery to internal recipient | Contextual / Baseline | None (Single event) | Yes | **OBSERVED FIRING** | Proves local delivery only; does not prove external threat |
| **A02** | Suspicious External Web Download | Suricata IPS | HTTP GET downloading executable archive | Network Ingress | None (SID match) | Yes | **OBSERVED FIRING** | Relies on signature SID 1101002; blind to encrypted HTTPS |
| **A03** | Suspicious Script Execution | Sysmon Event ID 1 | `mshta.exe` executing `.hta` file | Host Endpoint | None (Single event) | Yes | **OBSERVED FIRING** | Specific to mshta/.hta execution pattern |
| **A04** | Suspicious Outbound Callback | Zeek `conn.log` | Persistent outbound TCP session on port 4444 | Network Egress | None (Single flow) | Yes | **OBSERVED FIRING** | High alert volume; relies on known test port 4444 |
| **A05** | Post-Compromise Discovery Burst | Sysmon Event ID 1 | Recon commands (`where ssh`, `netstat`, `qwinsta`) | Host Burst | $\ge 3\text{ events} / 5\text{ min}$ | Yes | **OBSERVED FIRING** | Evaded by low-and-slow execution exceeding 5 minutes |
| **A06** | Credential Material Collection | Sysmon Event ID 1 | `xcopy.exe` copying Firefox profile to `\Public\` | Host Endpoint | None (Single event) | Yes | **OBSERVED FIRING** | Severity 8 alert; specific to Firefox profile directory |
| **A07** | Suspicious Data Staging / Transfer | PowerShell (4104) | `Compress-Archive` or `.NET TcpClient` socket | Host ScriptBlock | None (Single event) | Yes | **OBSERVED FIRING** | Requires PowerShell ScriptBlock logging enabled via GPO |
| **A08** | Suspicious Tool Transfer / Exec | PS 4104 / Sysmon 1| `Invoke-WebRequest` of agent / execution of agent | Host Tool Ingress | None (Single event) | Yes | **OBSERVED FIRING** | Dual-branch detection; matches specific binary naming |
| **A09** | Suspicious External Tunnel | Sysmon ID 3 / Zeek | Outbound connection to port 11601 (Ligolo-ng) | Network Tunnel | None (Single flow) | Yes | **OBSERVED FIRING** | Scenario-dependent; relies on default Ligolo port 11601 |
| **A10** | Internal Remote Access to Web | Suricata IPS | Inter-zone SSH (`TCP/22`) from Internal to DMZ | Contextual / Lateral | None (Flow allowed) | Yes | **OBSERVED FIRING** | Severity 3; authorized path used as lateral movement proof |
| **A11** | Sensitive Privileged Web Activity | Linux Auditd | `sudo docker exec` reading `site_config.json` | Host Application | None (System call) | Yes | **OBSERVED FIRING** | Captures one-line docker exec; blind inside interactive bash |
| **A12** | Suspicious Database Collection | MariaDB Audit | SQL queries: `SHOW DATABASES`, `mysqldump` | Database Audit | $\ge 2\text{ events} / 5\text{ min}$ | Yes | **OBSERVED FIRING** | Threshold dependent; targeted single queries bypass rule |
| **A13** | Suspicious DMZ External Transfer | Suricata IPS | Outbound TCP data transfer on port 9999 | Network Egress | None (SID match) | Yes | **OBSERVED FIRING** | Scenario-dependent; relies on non-standard port 9999 |
| **C01** | Initial Compromise Correlation | ArcSight ESM Core | Correlated chain: A02 (Download) + A03 + A04 | Multi-Source Correl | Window $\Delta t \le 20\text{ min}$| Yes | **OBSERVED FIRING** | Requires all three components on same host within 20m |

---

## 3. Attack-Lifecycle Mapping (MITRE ATT&CK for Enterprise)

```text
┌───────────────────────────────┬──────────────┬──────────────────────────────┬───────────────────────────────┐
│ Attack Phase / Technique      │ Detection ID │ Primary Telemetry Source     │ Normalized Evidence           │
├───────────────────────────────┼──────────────┼──────────────────────────────┼───────────────────────────────┤
│ Phishing Lure Delivery        │ A01          │ Postfix Mail Syslog          │ QueueID: 718FC8006A, sent     │
│ Malicious Archive Ingress     │ A02          │ Suricata Inline IPS          │ SID 1101002, HTTP GET zip     │
│ Script-Based Execution        │ A03          │ Microsoft Sysmon (Event 1)   │ mshta.exe executing .hta      │
│ Command-and-Control Callback  │ A04          │ Zeek conn.log                │ Persistent TCP to :4444       │
│ Initial Compromise Triangle   │ C01          │ ArcSight ESM Correlation     │ A02 + A03 + A04 (Delta t<=20m)│
│ Host & Service Discovery      │ A05          │ Microsoft Sysmon (Event 1)   │ where ssh, sc query, qwinsta  │
│ Browser Credential Harvesting │ A06          │ Microsoft Sysmon (Event 1)   │ xcopy Firefox\Profiles        │
│ Data Staging & Raw Socket Send│ A07          │ PowerShell ScriptBlock (4104)│ Compress-Archive, TcpClient   │
│ Tool Ingress & Staging        │ A08          │ PowerShell 4104 / Sysmon 1   │ Invoke-WebRequest agent.exe   │
│ Adversary Tunneling (Pivoting)│ A09          │ Sysmon Event 3 / Zeek        │ Outbound TCP to :11601        │
│ Inter-Zone Lateral Movement   │ A10          │ Suricata Inline IPS          │ SSH TCP/22 from .35 to .34    │
│ Container Credential Scraping │ A11          │ Linux Host Auditd            │ sudo docker exec site_config  │
│ Database Schema Dump          │ A12          │ MariaDB SERVER_AUDIT         │ mysqldump, SHOW DATABASES     │
│ DMZ Data Exfiltration         │ A13          │ Suricata Inline IPS          │ SID 1101021, Netcat to :9999  │
└───────────────────────────────┴──────────────┴──────────────────────────────┴───────────────────────────────┘
```

---

## 4. Directory Structure

Each detection rule is documented in its dedicated directory adhering to a standardized 20-section engineering template:

```text
detection/
├── README.md                          <-- You are here
├── VALIDATION_MATRIX.md               <-- Empirical validation status table
├── queries/                           <-- Public-safe ArcSight Logger queries
│   ├── A01.logger.query
│   ├── A02.logger.query
│   └── ... (A01 - A13, C01)
├── A01/README.md                      <-- Mail Delivered to Internal User
├── A02/README.md                      <-- Suspicious External Web Download
├── A03/README.md                      <-- Suspicious Script Execution
├── A04/README.md                      <-- Suspicious Outbound Callback
├── A05/README.md                      <-- Post-Compromise Discovery Burst
├── A06/README.md                      <-- Credential Material Collection
├── A07/README.md                      <-- Suspicious Data Staging / Raw Transfer
├── A08/README.md                      <-- Suspicious Tool Transfer or Execution
├── A09/README.md                      <-- Suspicious External Tunnel (Ligolo)
├── A10/README.md                      <-- Internal Remote Access to WEB Tier
├── A11/README.md                      <-- Sensitive Privileged WEB Activity
├── A12/README.md                      <-- Suspicious Database Collection
├── A13/README.md                      <-- Suspicious DMZ External Transfer
└── C01/README.md                      <-- Initial Compromise Correlation
```
