# Telemetry Architecture

## 1. Telemetry Sources

The Enterprise SOC Lab ingests event data across the full infrastructure stack. Telemetry is collected from boundary devices, inline network sensors, passive analyzers, operating system kernels, identity providers, application servers, and relational databases.

```text
┌─────────────────┬──────────────────────┬───────────────────────────────────────────┬───────────────────────────────┐
│ Source          │ Telemetry Type       │ Security Value                            │ Ingestion Destination         │
├─────────────────┼──────────────────────┼───────────────────────────────────────────┼───────────────────────────────┤
│ PFSENSE-01      │ CSV Filterlog        │ Perimeter allow/block, NAT mappings       │ SmartConnector UDP/5515       │
│ SURICATA-IPS01  │ EVE JSON Alerts      │ Inline signature hits (SID), flow metrics │ SmartConnector TCP/5521       │
│ ZEEK-NDR01      │ TSV Protocol Logs    │ State metrics, DNS/HTTP/TLS, ZeekUID      │ SmartConnector UDP/5518       │
│ WEB01           │ Nginx & Frappe Logs  │ Web access, HTTP methods, URIs, errors    │ SmartConnector UDP/5519       │
│ WEB01 (Auditd)  │ Linux Auditd Exec    │ System call execve, sudo docker abuse     │ SmartConnector UDP/5519       │
│ DB01            │ MariaDB SERVER_AUDIT │ Raw SQL queries, tables accessed, users   │ SmartConnector UDP/5520       │
│ MAIL01          │ Postfix Mail Syslog  │ SMTP envelope, Queue ID, recipient status │ SmartConnector UDP/5516       │
│ DNS-PUB01       │ BIND9 Query Syslog   │ External DNS lookups for corporate VIPs   │ SmartConnector UDP/5517       │
│ IT-ADMIN01      │ Windows Event XML    │ Sysmon (Event 1, 3), PowerShell (4104)    │ Windows Connector API/2009    │
│ DC01            │ Windows Security XML │ Kerberos, NTLM, LDAPS authentications     │ Windows Connector API/2009    │
└─────────────────┴──────────────────────┴───────────────────────────────────────────┴───────────────────────────────┘
```

---

## 2. Telemetry Collection

Collection is executed across the isolated **Logging Plane (`10.10.40.0/24`)**:

```text
  DISTRIBUTED SOURCES                    COLLECTION SUBSYSTEM               STORAGE & SIEM
┌─────────────────────┐                 ┌──────────────────────┐         ┌───────────────────┐
│ pfSense (Filterlog) │──UDP/5515──────►│ SmartConnector Linux │         │  ArcSight Logger  │
│ Suricata (eve.json) │──TCP/5521──────►│ (10.10.40.4)         │         │   (10.10.40.5)    │
│ Zeek (TSV logs)     │──UDP/5518──────►│                      │         │  Storage Groups   │
│ Web / Linux Auditd  │──UDP/5519──────►│ • FlexConnector      │──TLS───►│  Verify Storage   │
│ MariaDB Audit       │──UDP/5520──────►│   Parsers (2002-2008)│  TCP/443│  Forensic Search  │
│ Postfix Mail Syslog │──UDP/5516──────►│ • CEF Normalization  │         └─────────┬─────────┘
│ BIND9 DNS Queries   │──UDP/5517──────►│ • Secure Transport   │                   │
└─────────────────────┘                 └──────────────────────┘                   │ Filtered
                                                                                   │ Forwarding
┌─────────────────────┐                 ┌──────────────────────┐                   │ Stream
│ IT-ADMIN01 (Sysmon) │──WEC API───────►│ SmartConnector Win   │                   ▼
│ DC01 (AD Security)  │──Native Logs───►│ (10.10.40.23) (2009) ├─────────►┌───────────────────┐
└─────────────────────┘                 └──────────────────────┘         │   ArcSight ESM    │
                                                                         │  Real-Time Engine │
                                                                         │  Rules A01 - A13  │
                                                                         │  Correlation C01  │
                                                                         │  Active Channels  │
                                                                         └───────────────────┘
```

### Ingestion Port & Process Mapping
* **Generator ID 2002 (Suricata EVE)**: Listens on `TCP/5521` (Remote Management `TCP/9102`). TCP is utilized due to the high volume and critical alert nature of Suricata JSON outputs.
* **Generator ID 2003 (Zeek Metadata)**: Listens on `UDP/5518` (Remote Management `TCP/9103`). Zeek logs (`conn.log`, `dns.log`, `http.log`) are monitored locally via `rsyslog imfile` and forwarded over UDP.
* **Generator ID 2004 (Web Application & Host Audit)**: Listens on `UDP/5519` (Remote Management `TCP/9104`). Ingests Nginx access logs and Linux auditd logs tagged with `-k web_exec`.
* **Generator ID 2005 (Database Audit)**: Listens on `UDP/5520` (Remote Management `TCP/9105`). Ingests raw SQL query events emitted by MariaDB's `SERVER_AUDIT` plugin.
* **Generator ID 2006 (Perimeter Firewall)**: Listens on `UDP/5515` (Remote Management `TCP/9106`). Ingests pfSense CSV filterlog records.
* **Generator ID 2007 (Mail Gateway)**: Listens on `UDP/5516` (Remote Management `TCP/9107`). Ingests Postfix transaction and queue logs.
* **Generator ID 2008 (Public DNS)**: Listens on `UDP/5517` (Remote Management `TCP/9108`). Ingests BIND9 query and resolution logs.
* **Generator ID 2009 (Windows Native / WEC)**: Reads directly from the Windows Event Forwarding (`ForwardedEvents`) channel via the Windows API (Remote Management `TCP/9109`).

---

## 3. Data Normalization & The CEF Schema

### Why Normalization Matters
Without schema normalization, security analysts and correlation engines must craft unique queries for each technology vendor. For instance, a client IP is labeled `id.orig_h` in Zeek, `src` in pfSense, `src_ip` in Suricata, `SourceIp` in Sysmon, and `ip` in MariaDB Audit.

Normalization translates vendor-specific fields into the **Common Event Format (CEF)** standard, enabling unified querying, cross-source correlation, and streamlined incident investigation.

```text
┌─────────────────┬──────────────────────┬───────────────────────────────┬───────────────────────────────┐
│ Original Log    │ Vendor Field         │ Standardized CEF Field        │ Canonical Field Label         │
├─────────────────┼──────────────────────┼───────────────────────────────┼───────────────────────────────┤
│ pfSense (CSV)   │ Source IP in payload │ sourceAddress (src)           │ Source Address                │
│ pfSense (CSV)   │ Destination IP       │ destinationAddress (dst)      │ Destination Address           │
│ pfSense (CSV)   │ Destination Port     │ destinationPort (dpt)         │ Destination Port              │
│ Suricata (JSON) │ alert.signature_id   │ deviceCustomNumber1 (cn1)     │ cn1Label="SID"                │
│ Suricata (JSON) │ flow_id              │ deviceCustomString1 (cs1)     │ cs1Label="FlowID"             │
│ Zeek (TSV)      │ uid                  │ deviceCustomString2 (cs2)     │ cs2Label="ZeekUID"            │
│ Sysmon (XML)    │ ProcessGuid          │ deviceCustomString5 (cs5)     │ cs5Label="ProcessGuid"        │
│ Sysmon (XML)    │ CommandLine          │ deviceCustomString4 (cs4)     │ cs4Label="CommandLine"        │
│ Sysmon (XML)    │ Image                │ destinationProcessName        │ Target Process Name           │
│ MariaDB Audit   │ query                │ deviceCustomString3 (cs3)     │ cs3Label="Query"              │
│ Postfix Syslog  │ Queue ID             │ deviceCustomString3 (cs3)     │ cs3Label="QueueID"            │
│ BIND9 Syslog    │ Query Domain         │ requestUrl                    │ Request URL                   │
└─────────────────┴──────────────────────┴───────────────────────────────┴───────────────────────────────┘
```

---

## 4. ArcSight Logger Architecture

**ArcSight Logger (`10.10.40.5`)** serves as the central, high-volume forensic repository:

### Storage Architecture & Immutability
* **Storage Groups & Storage Files**: Incoming CEF events are compressed and written into localized storage files within designated storage groups. Compression maximizes retention efficiency while maintaining index speed.
* **Role-Based Immutability**: Logger software architecture enforces write-once, read-many semantics. There is no API or user interface capability to selectively edit or delete single event records. Log retention policies purge data solely on global storage threshold exhaustion or predefined retention time limits.
* **Storage Data Validation (Cryptographic Hashing)**:
  * To satisfy legal and regulatory forensic standards (**NIST SP 800-86**), Logger computes and stores cryptographic hash digests across closed storage files.
  * Administrators run the *Verify Storage* utility periodically. If an unauthorized actor gains root access to the underlying Linux filesystem and modifies a storage file, the recalculated hash fails, triggering an integrity violation alarm.

### Query Engine for Retrospective Forensics
Logger provides the ad-hoc search engine used during incident investigations. It allows analysts to execute deep boolean searches across historical data without impacting real-time correlation processing:
```text
deviceProduct="MariaDB Server Audit" AND sourceAddress=10.10.34.13 AND deviceCustomString3 CONTAINS "SHOW DATABASES"
```

---

## 5. ArcSight ESM Architecture

**ArcSight Enterprise Security Manager (ESM)** is the stateful, real-time correlation engine:

### Operational Role & Separation from Logger
* **Decoupled Workload**: ArcSight ESM does not store massive volumes of raw historical logs. It receives an optimized, pre-filtered event stream from SmartConnectors/Logger, preserving its memory and CPU resources exclusively for real-time rule evaluation.
* **Dynamic Context (Active Lists)**:
  * ESM maintains in-memory tracking structures called **Active Lists**.
  * When a host performs port scanning or triggers a lower-tier signature, its IP address is added to an Active List. Subsequent activities from that entity (such as privileged file access or database logins) are evaluated within the context of that list.
* **Active Channels (Operational SOC Console)**:
  * Active Channels provide live, streaming event monitoring consoles for SOC analysts.
  * Configured with operational filters to suppress event floods (e.g., filtering out high-frequency reverse shell keepalives `Name != "A04*"` to maintain analyst visibility across other incident phases).

---

## 6. Detection Architecture

The detection architecture operates within ESM using a two-tier rule structure:

### Tier 1: Atomic Rules (`A01–A13`)
Thirteen individual rules detect specific tactical adversary behaviors across network, endpoint, application, and database layers:
* `A01`: Postfix mail delivered to internal user (Baseline context).
* `A02`: Suspicious external archive download detected by Suricata SID `1101002`.
* `A03`: `mshta.exe` executing an `.hta` payload captured by Sysmon Event ID 1.
* `A04`: Persistent outbound TCP callback on port 4444 captured by Zeek `conn.log`.
* `A05`: Rapid burst of system discovery commands (`where ssh`, `netstat`) captured by Sysmon.
* `A06`: Staging browser credential profiles via `xcopy.exe` captured by Sysmon.
* `A07`: Data compression and raw socket staging captured by PowerShell Event ID 4104.
* `A08`: Ingress tool transfer of `agent.exe` via PowerShell.
* `A09`: Outbound network tunnel session on port 11601 captured by Sysmon Event ID 3.
* `A10`: Inter-zone SSH session from Internal to DMZ Web Server (`10.10.34.13:22`).
* `A11`: Privileged `sudo docker exec` reading configuration files captured by Linux Auditd.
* `A12`: Database structural enumeration and dumping captured by MariaDB `SERVER_AUDIT`.
* `A13`: Large outbound data exfiltration stream on port 9999 captured by Suricata SID `1101021`.

### Tier 2: Multi-Source Correlation Rule (`C01`)
Combines indicators across disparate devices to confirm high-confidence intrusions:
$$\text{Condition: } [A02 \text{ (Suricata Ingress)}] \text{ AND } [A03 \text{ (Sysmon Execution)}] \text{ AND } [A04 \text{ (Zeek Callback)}]$$
* **Entity Join**: Matches on common host address `sourceAddress = 10.10.35.18`.
* **Sliding Window**: Requires all three events to execute within $\Delta t \le 20\text{ minutes}$.
* **Operational Value**: Eliminates false positives resulting from benign file downloads or internal script execution without external network callbacks.

---

## 7. Forensic Investigation & Evidence Pivoting

When an incident occurs, analysts utilize normalized correlation keys to navigate raw logs in ArcSight Logger:

```text
                              CROSS-SOURCE EVIDENCE PIVOTING
┌──────────────────┐               ┌──────────────────┐               ┌──────────────────┐
│  SURICATA / ZEEK │               │  WINDOWS SYSMON  │               │ MARIADB AUDIT    │
│  Network Layer   │               │  Endpoint Layer  │               │ Database Layer   │
├──────────────────┤               ├──────────────────┤               ├──────────────────┤
│ • sourceAddress  │◄─────────────►│ • deviceHostName │               │ • sourceAddress  │
│ • targetAddress  │   Anchor:     │ • ProcessGuid    │◄─────────────►│ • connection_id  │
│ • FlowID (cs1)   │   10.10.35.18 │ • ParentGuid     │   Anchor:     │ • Query (cs3)    │
│ • ZeekUID (cs2)  │               │ • CommandLine    │   10.10.34.13 │                  │
└────────┬─────────┘               └────────┬─────────┘               └────────┬─────────┘
         │                                  │                                  │
         │ Pivot: 203.0.113.25:80           │ Pivot: firefox_profile.zip       │ Pivot: tabEmployee
         ▼                                  ▼                                  ▼
┌──────────────────┐               ┌──────────────────┐               ┌──────────────────┐
│ POSTFIX MAIL     │               │ POWERSHELL SCRIPT│               │ SURICATA EXFIL   │
│ Email Gateway    │               │ Staging / Socket │               │ Perimeter Inspec │
├──────────────────┤               ├──────────────────┤               ├──────────────────┤
│ • QueueID (cs3)  │               │ • Event ID 4104  │               │ • SID 1101021    │
│ • 718FC8006A     │               │ • TcpClient.Write│               │ • Port 9999      │
└──────────────────┘               └──────────────────┘               └──────────────────┘
```

1. **Patient Zero Identification (Backtracking)**:
   * Alert `C01` identifies victim IP `10.10.35.18`.
   * Analyst queries Logger for ingress connections to `.35.18` prior to the alert, discovering Suricata alert `1101002` (download of `SecurityPatch_KB504991.zip` from `203.0.113.25:80`).
   * Analyst queries Postfix mail logs on `MAIL01` for recipient `user01@soclab.test`, identifying **Queue ID `718FC8006A`** carrying the phishing lure from `security@microsoft.com`.
2. **Execution Hierarchy Reconstruction (Forward Tracking)**:
   * Querying Sysmon Event ID 1 on `IT-ADMIN01` reveals `explorer.exe` spawned `mshta.exe` with `ProcessGuid` `{ecec360d-d71c-6aab-3400-000000...}`.
   * Filtering on `ParentProcessGuid` equal to that GUID reveals child execution of `cmd.exe /c` spawning `powershell.exe`.
   * Sysmon Event ID 3 confirms `powershell.exe` opened outbound socket `10.10.35.18:49715 -> 203.0.113.25:4444`.

---

## 8. Evidence Flow & Preservation

The lifecycle of forensic evidence satisfies the core requirements of **NIST SP 800-86 (Guide to Integrating Forensic Techniques into Incident Response)**:

1. **Source Generation**: Events are stamped with the local host system clock (`deviceCustomDate1`) at the exact millisecond of occurrence, distinguishing event creation time from SIEM ingestion time (`receiptTime`).
2. **Cryptographic Transit**: SmartConnectors encapsulate parsed records into binary SmartMessages transmitted over TLS (`TCP/443`) to ArcSight Logger.
3. **Repository Validation**: Logger seals daily storage groups and computes SHA-256 verification hashes.
4. **Forensic Export**: When evidence is exported for case files, Logger outputs records in CSV/CEF accompanied by an investigator audit header, extraction timestamp, and export hash.
