# Detection Engineering Architecture & Telemetry Model

## 1. Detection Engineering Philosophy

In the Enterprise SOC Lab, detection engineering is not treated as an exercise in collecting uncontextualized indicator rules. Instead, it is established as a formal discipline that bridges **security architecture**, **raw telemetry generation**, **CEF field normalization**, **stateful real-time correlation**, and **forensic query pivoting**.

```text
    SECURITY EVENT          TELEMETRY PIPELINE          CEF SCHEMA            SIEM DETECTION            SOC PIVOT
┌─────────────────────┐    ┌─────────────────────┐    ┌─────────────┐    ┌─────────────────────┐    ┌─────────────────┐
│ Adversary / Business│───►│ Dedicated Logging   │───►│ Normalized  │───►│ ArcSight ESM        │───►│ ArcSight Logger │
│ System Activity     │    │ Network (10.10.40.4)│    │ CEF Fields  │    │ Rules (A01-A13, C01)│    │ Forensic Query  │
└─────────────────────┘    └─────────────────────┘    └─────────────┘    └─────────────────────┘    └─────────────────┘
```

The core detection philosophy adheres to five foundational engineering principles:

1. **Atomic Evidence Integrity**: An atomic detection rule evaluates strictly the evidence inherently contained within an individual event record. A rule never assumes unrecorded context. For instance, `Postfix Local Delivery` proves successful delivery to a local mailbox; it does not in isolation prove an external phishing campaign unless correlated with an upstream SMTP ingress record.
2. **Decoupled Detection from Forensic Storage**: Real-time evaluation is isolated within **ArcSight ESM** to ensure sub-second response times, while raw historical evidence and deep query pivoting are offloaded to **ArcSight Logger**.
3. **Multi-Source Correlation for High-Fidelity Alerting**: Isolated atomic alerts (e.g., an external file download or script execution) are treated as tactical indicators. High-severity incident generation (`C01`) requires multi-source temporal correlation across the perimeter (`Suricata`), host (`Sysmon`), and network transport (`Zeek`).
4. **Field-Preserving Normalization**: Disparate log formats (CSV, JSON, TSV, XML, Syslog) are mapped into the Common Event Format (CEF) via dedicated FlexConnector parsers, strictly preserving unique correlation keys (`ProcessGuid`, `QueueID`, `connection_id`, `FlowID`, `ZeekUID`).
5. **Empirical Validation**: Detection rules are documented according to their observed operational status (Configured, Fired in Lab, Scenario-Dependent, or Historical), avoiding unsubstantiated claims of generic enterprise production readiness.

---

## 2. Telemetry Source Matrix

The following matrix identifies all confirmed telemetry sources contributing to the detection and investigation framework:

| Telemetry Source | Technology | Observable Behavior | Important Normalized Fields | Destination | Detection IDs | Investigation Use |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Postfix** | Enterprise Mail Gateway | Inbound/internal email delivery, queue processing | `name`, `deviceAction`, `destinationUserName`, `cs3` (QueueID) | Logger / ESM | `A01` | Phishing timeline anchor; pivots to email lure & sender headers |
| **Suricata** | Inline IPS / Layer-3 Router | Ingress archive download, inter-zone SSH, exfiltration | `deviceCustomNumber1` (SID), `message`, `cs1` (FlowID), `src`, `dst`, `dpt` | Logger / ESM | `A02`, `A10`, `A13` | Network perimeter evidence, signature validation, byte counters |
| **Microsoft Sysmon** | Host Endpoint Driver | Process execution hierarchy, outbound network sockets | `externalId`, `cs5` (ProcessGuid), `cs4` (CommandLine), `destinationProcessName` | Logger / ESM | `A03`, `A05`, `A06`, `A08`, `A09` | Endpoint process genealogy, discovery commands, tool staging |
| **PowerShell** | Windows Script Engine | ScriptBlock execution, in-memory payloads | `externalId` (4104), `message` (ScriptBlock Text), `deviceHostName` | Logger / ESM | `A07`, `A08` | De-obfuscated script analysis, raw socket exfiltration tracing |
| **Zeek (Bro)** | Passive NDR Sensor | Long-lived TCP flows, DNS lookups, protocol metadata | `cs2` (ZeekUID), `src`, `dst`, `dpt`, `transportProtocol`, `duration` | Logger / ESM | `A04`, `A09`, `A13` | Protocol metadata reconstruction, non-signature C2 session tracking |
| **Linux Auditd** | Linux Kernel Audit Subsystem | System call `execve` on web host, sudo container escape | `deviceProcessName`, `destinationUserName`, `deviceAction`, `message` | Logger / ESM | `A11` | Host privilege escalation, container boundary inspection, config theft |
| **MariaDB Audit** | Relational Database Engine | Database connections, structural enumeration, table dump | `sourceAddress`, `destinationUserName`, `cs3` (Query), `deviceAction="query"` | Logger / ESM | `A12` | SQL transaction proof, data harvesting verification, exfiltration scope |
| **pfSense** | Perimeter Stateful Firewall | Boundary filtering, DNAT translation, egress drops | `src`, `dst`, `spt`, `dpt`, `transportProtocol`, `deviceAction` | Logger | Supporting Evidence | Network boundary timeline, perimeter state verification, egress policy |

---

## 3. Field Evidence Matrix

The field evidence matrix establishes strict traceability between raw source fields and normalized CEF schema targets, distinguishing empirically confirmed fields from inferred constructs:

| Detection Rule | Telemetry Source | CEF Schema Field | Example Semantic Value | Required? | Source Confirmation Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **A01** | Postfix Syslog | `deviceProduct` | `Postfix Mail Server` | Yes | **CONFIRMED** `[Source: Báo cáo đề tài SOC.pdf, p.91]` |
| **A01** | Postfix Syslog | `name` | `Postfix Local Delivery` | Yes | **CONFIRMED** `[Source: Báo cáo đề tài SOC.pdf, p.91]` |
| **A01** | Postfix Syslog | `deviceAction` | `sent` | Yes | **CONFIRMED** `[Source: Báo cáo đề tài SOC.pdf, p.91]` |
| **A01** | Postfix Syslog | `destinationUserName` | `user01@soclab.test` | Yes | **CONFIRMED** `[Source: Báo cáo đề tài SOC.pdf, p.91]` |
| **A01** | Postfix Syslog | `deviceCustomString3` | `718FC8006A` (`cs3Label="QueueID"`) | Yes | **CONFIRMED** `[Source: Báo cáo đề tài SOC.pdf, p.63]` |
| **A02** | Suricata IPS | `deviceProduct` | `Suricata IDS IPS` | Yes | **CONFIRMED** `[Source: Báo cáo đề tài SOC.pdf, p.92]` |
| **A02** | Suricata IPS | `deviceCustomNumber1` | `1101002` (`cn1Label="SID"`) | Yes | **CONFIRMED** `[Source: Báo cáo đề tài SOC.pdf, p.92]` |
| **A02** | Suricata IPS | `sourceAddress` | `10.10.35.18` (Internal Subnet) | Yes | **CONFIRMED** `[Source: Báo cáo đề tài SOC.pdf, p.92]` |
| **A02** | Suricata IPS | `destinationAddress` | `203.0.113.25` (External Subnet) | Yes | **CONFIRMED** `[Source: Báo cáo đề tài SOC.pdf, p.92]` |
| **A03** | Sysmon Event ID 1 | `externalId` | `1` (Process Create) | Yes | **CONFIRMED** `[Source: Báo cáo đề tài SOC.pdf, p.93]` |
| **A03** | Sysmon Event ID 1 | `destinationProcessName` | `C:\Windows\System32\mshta.exe` | Yes | **CONFIRMED** `[Source: Báo cáo đề tài SOC.pdf, p.93]` |
| **A03** | Sysmon Event ID 1 | `deviceCustomString4` | `.hta` (`cs4Label="CommandLine"`) | Yes | **CONFIRMED** `[Source: Báo cáo đề tài SOC.pdf, p.93]` |
| **A03** | Sysmon Event ID 1 | `deviceCustomString5` | `{ecec360d-d71c-6aab-3400-000000...}` | Yes | **CONFIRMED** `[Source: Báo cáo đề tài SOC.pdf, p.50, 62]` |
| **A04** | Zeek `conn.log` | `deviceProduct` | `Zeek` | Yes | **CONFIRMED** `[Source: Báo cáo đề tài SOC.pdf, p.94]` |
| **A04** | Zeek `conn.log` | `transportProtocol` | `TCP` | Yes | **CONFIRMED** `[Source: Báo cáo đề tài SOC.pdf, p.94]` |
| **A04** | Zeek `conn.log` | `destinationPort` | `4444` | Yes | **CONFIRMED** `[Source: Báo cáo đề tài SOC.pdf, p.94]` |
| **A04** | Zeek `conn.log` | `deviceCustomString2` | `C9xKa811` (`cs2Label="ZeekUID"`) | Yes | **CONFIRMED** `[Source: Báo cáo đề tài SOC.pdf, p.62]` |
| **A05** | Sysmon Event ID 1 | `deviceCustomString4` | `where ssh`, `sc query`, `netstat` | Yes | **CONFIRMED** `[Source: Báo cáo đề tài SOC.pdf, p.94, 95]` |
| **A06** | Sysmon Event ID 1 | `destinationProcessName` | `xcopy.exe` | Yes | **CONFIRMED** `[Source: Báo cáo đề tài SOC.pdf, p.95]` |
| **A06** | Sysmon Event ID 1 | `deviceCustomString4` | `Firefox\Profiles`, `\Users\Public\`| Yes | **CONFIRMED** `[Source: Báo cáo đề tài SOC.pdf, p.95]` |
| **A07** | PowerShell (4104) | `externalId` | `4104` (ScriptBlock Logging) | Yes | **CONFIRMED** `[Source: Báo cáo đề tài SOC.pdf, p.96]` |
| **A07** | PowerShell (4104) | `message` | `Compress-Archive`, `TcpClient` | Yes | **CONFIRMED** `[Source: Báo cáo đề tài SOC.pdf, p.96]` |
| **A08** | PowerShell / Sysmon | `message` / `cs4` | `Invoke-WebRequest`, `agent.exe` | Yes | **CONFIRMED** `[Source: Báo cáo đề tài SOC.pdf, p.97]` |
| **A09** | Sysmon ID 3 / Zeek | `destinationPort` | `11601` (Ligolo-ng Protocol) | Yes | **CONFIRMED** `[Source: Báo cáo đề tài SOC.pdf, p.98]` |
| **A10** | Suricata IPS | `destinationPort` | `22` (SSH Ingress to DMZ) | Yes | **CONFIRMED** `[Source: Báo cáo đề tài SOC.pdf, p.99]` |
| **A11** | Linux Auditd | `message` | `docker exec`, `site_config.json` | Yes | **CONFIRMED** `[Source: Báo cáo đề tài SOC.pdf, p.100]` |
| **A11** | Linux Auditd | `deviceProcessName` | `/usr/bin/docker` | Yes | **CONFIRMED** `[Source: Báo cáo đề tài SOC.pdf, p.100]` |
| **A12** | MariaDB Audit | `deviceCustomString3` | `SHOW DATABASES`, `mysqldump` | Yes | **CONFIRMED** `[Source: Báo cáo đề tài SOC.pdf, p.101]` |
| **A13** | Suricata IPS | `deviceCustomNumber1` | `1101021` (Large outbound flow) | Yes | **CONFIRMED** `[Source: Báo cáo đề tài SOC.pdf, p.102]` |
| **A13** | Suricata IPS | `destinationPort` | `9999` (Raw Exfiltration Port) | Yes | **CONFIRMED** `[Source: Báo cáo đề tài SOC.pdf, p.102]` |
| **C01** | ArcSight ESM Core | Multi-rule Join | `sourceAddress`, $\Delta t \le 20\text{ min}$| Yes | **CONFIRMED** `[Source: Báo cáo đề tài SOC.pdf, p.103]` |

---

## 4. Detection Engineering Pipeline

The end-to-end detection engineering lifecycle is structured across five sequential stages:

```text
    STAGE 1                 STAGE 2                 STAGE 3                 STAGE 4                 STAGE 5
Telemetry Design        Parser Engineering      Atomic Detection       Correlation Logic       Operational Validation
┌──────────────┐        ┌──────────────┐        ┌──────────────┐        ┌──────────────┐        ┌──────────────┐
│Enable Sysmon │───────►│Construct     │───────►│Formulate     │───────►│Join Atomic   │───────►│Execute Red   │
│Event 3 & 4104│        │FlexConnector │        │Rules A01-A13 │        │Detections into│       │Team Exercise;│
│Configure DB  │        │Regex Parsers;│        │in ESM using  │        │Multi-Source  │        │Validate Active│
│SERVER_AUDIT  │        │Map to CEF    │        │Single Events │        │Rule C01      │        │Channel Alerts│
└──────────────┘        └──────────────┘        └──────────────┘        └──────────────┘        └──────────────┘
```

1. **Telemetry Instrumentation**: Critical logging flags must be explicitly enabled at the source. For example, Sysmon Event ID 3 (Network Connect) is disabled by default in Microsoft's baseline schema and must be activated via XML configuration. Similarly, PowerShell ScriptBlock Logging (Event ID 4104) requires explicit local group policy activation.
2. **Parser Construction**: FlexConnector regex patterns parse incoming lines into standard CEF attributes. Generator IDs isolate parsing daemons, ensuring single-source failures do not affect other pipelines.
3. **Atomic Rule Formulation**: Rules are configured to detect atomic actions without over-fitting to attack scripts. Rules leverage exact numeric identifiers (`deviceCustomNumber1 = 1101002`) rather than text string matches where possible to optimize memory lookups.
4. **Multi-Source Correlation**: Correlation rules combine cross-tier detections to produce high-confidence incidents. Entity keys (`sourceAddress`, `deviceHostName`) tie perimeter indicators to host-level executions within sliding temporal boundaries.
5. **Operational Triage & Validation**: Rules are tested in real time. High-volume alerts (e.g., persistent TCP reverse shells) are filtered out of main triage views to protect operator attention.

---

## 5. Architectural Separation: ArcSight Logger vs ArcSight ESM

The separation of roles between ArcSight Logger and ArcSight ESM is fundamental to the operational performance of the SOC:

```text
┌────────────────────────────────────────────────────────┬────────────────────────────────────────────────────────┐
│ ARCSIGHT LOGGER (Storage & Forensics)                  │ ARCSIGHT ESM (Correlation & Real-Time Alerting)        │
├────────────────────────────────────────────────────────┼────────────────────────────────────────────────────────┤
│ • Ingests 100% of raw events across all 8 sources      │ • Ingests an optimized, filtered stream of CEF events  │
│ • Long-term compressed storage in local Storage Groups │ • In-memory rules engine evaluating real-time windows  │
│ • Software-level immutability; no individual event edit│ • Stateful Active Lists tracking entity context        │
│ • Storage Data Validation (periodic SHA-256 hashes)   │ • Real-time Active Channels for live operator triage   │
│ • Ad-hoc search engine for retrospective investigation │ • Evaluates Atomic Rules A01-A13 and Correlation C01   │
│ • Evidence export compliant with NIST SP 800-86        │ • Sub-second notification dispatch on high-risk threats│
└────────────────────────────────────────────────────────┴────────────────────────────────────────────────────────┘
```

By decoupling these workloads, the system guarantees that massive log surges (such as full database dumps or active port scans) do not degrade the real-time detection latency of the correlation engine.
