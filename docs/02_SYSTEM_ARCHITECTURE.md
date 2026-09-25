# System Architecture

## 1. Architecture Overview

The **Enterprise SOC Lab** is organized into seven distinct architectural layers designed to deliver end-to-end security enforcement, granular visibility, centralized correlation, and structured incident investigation. 

Rather than relying on isolated security controls, the architecture enforces a strict progression of trust boundaries, ensuring that every transaction across the network and host estate generates verifiable telemetry.

```text
       ====================== 7-LAYER SYSTEM ARCHITECTURE ======================

  ┌────────────────────────────────────────────────────────────────────────────┐
  │ LAYER 7: SOC OPERATIONS & INCIDENT RESPONSE                                │
  │ • Real-time Triage • Forensic Timeline • Threat Hunting • System Hardening │
  └─────────────────────────────────────▲──────────────────────────────────────┘
                                        │
  ┌─────────────────────────────────────┴──────────────────────────────────────┐
  │ LAYER 6: SIEM (ARCSIGHT ESM & LOGGER)                                      │
  │ • ArcSight ESM (Real-Time Rules A01-A13, C01) • Logger (Forensic Queries)   │
  └─────────────────────────────────────▲──────────────────────────────────────┘
                                        │
  ┌─────────────────────────────────────┴──────────────────────────────────────┐
  │ LAYER 5: TELEMETRY COLLECTION & NORMALIZATION                              │
  │ • SmartConnectors (Linux & Windows WEC) • FlexConnector Parsers • CEF      │
  └─────────────────────────────────────▲──────────────────────────────────────┘
                                        │
  ┌─────────────────────────────────────┴──────────────────────────────────────┐
  │ LAYER 4: APPLICATION & DATA                                                │
  │ • Frappe HRMS (WEB01) • MariaDB (DB01) • Postfix (MAIL01) • BIND9 • Proxy  │
  └─────────────────────────────────────▲──────────────────────────────────────┘
                                        │
  ┌─────────────────────────────────────┴──────────────────────────────────────┐
  │ LAYER 3: IDENTITY & ENDPOINT AUDITING                                      │
  │ • Active Directory (DC01) • Workstations (WIN10/IT-ADMIN) • Sysmon • Auditd│
  └─────────────────────────────────────▲──────────────────────────────────────┘
                                        │
  ┌─────────────────────────────────────┴──────────────────────────────────────┐
  │ LAYER 2: PASSIVE NETWORK VISIBILITY (NDR)                                  │
  │ • Zeek Network Sensor (conn.log, dns.log, http.log via SPAN / gretap)      │
  └─────────────────────────────────────▲──────────────────────────────────────┘
                                        │
  ┌─────────────────────────────────────┴──────────────────────────────────────┐
  │ LAYER 1: NETWORK SECURITY & TRANSIT (EDGE ENFORCEMENT)                     │
  │ • pfSense (Stateful Firewall / NAT) • Suricata Inline IPS (NFQUEUE Router) │
  └────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Security Zones

The infrastructure partitions assets into six logical security zones defined by explicit trust levels and functional roles:

1. **External Zone (`203.0.113.0/24`)**: Untrusted public network segment hosting simulated external threat actors (`KALI-ATTACKER`), public authoritative DNS (`DNS-PUB01`), forward web egress proxy (`FORWARD-PROXY:8132`), and perimeter Virtual IPs (VIPs).
2. **Security Transit Zone (`10.10.36.0/24`)**: Non-routable point-to-point transit link dedicated exclusively to routing inter-zone traffic between `PFSENSE-01` (`10.10.36.10`) and `SURICATA-IPS01` (`10.10.36.11`). Contains no user endpoints or business services.
3. **DMZ (`10.10.34.0/24`)**: Semi-trusted perimeter network hosting public-facing business applications: Web Server `WEB01` (`10.10.34.13`) and Mail Server `MAIL01` (`10.10.34.14`). Default gateway points to `10.10.34.11` on Suricata.
4. **Internal Zone (`10.10.35.0/24`)**: High-trust corporate asset segment containing Active Directory Domain Controller `DC01` (`10.10.35.12`), Relational Database `DB01` (`10.10.35.19`), domain-joined workstations `WIN10-01..03` (`10.10.35.13`, `.16`, `.17`), and privileged standalone workstation `IT-ADMIN01` (`10.10.35.18`). Default gateway points to `10.10.35.11` on Suricata.
5. **Logging Zone (`10.10.40.0/24`)**: Isolated, non-routable telemetry transport plane. Connects dedicated logging network interfaces directly to `SMARTCONNECTOR` (`10.10.40.4`) and `ARCSIGHT-LOGGER` (`10.10.40.5`).
6. **Management Zone (`10.10.21.0/24`)**: Isolated administrative plane providing out-of-band access to hypervisors, firewalls, and security daemons via `MGMT-JUMPHOST` (`10.10.21.100`).

---

## 3. Core Components

```text
┌──────────────────────┬──────────────────────┬────────────────────────────────────────────────────────┐
│ Asset Identifier     │ Logical Zone         │ Core Function & Implementation                         │
├──────────────────────┼──────────────────────┼────────────────────────────────────────────────────────┤
│ PFSENSE-01           │ Perimeter / Transit  │ Stateful packet filter, NAT/DNAT, static inter-zone GW │
│ SURICATA-IPS01       │ Transit / Core       │ Inline IPS, NFQUEUE packet interception, L3 router     │
│ ZEEK-NDR01           │ Passive Core         │ Application protocol metadata extraction via SPAN      │
│ DC01                 │ Internal             │ Active Directory Domain Services, LDAPS, Internal DNS  │
│ WEB01                │ DMZ                  │ Frappe HRMS / ERPNext Docker Stack, Nginx/Traefik      │
│ DB01                 │ Internal             │ MariaDB 10.11 Server, iptables L2 shield, SERVER_AUDIT │
│ MAIL01               │ DMZ                  │ Postfix SMTP, Dovecot IMAP, Roundcube Webmail          │
│ DNS-PUB01            │ External             │ BIND9 Authoritative Server for public VIP resolution   │
│ FORWARD-PROXY        │ External             │ Outbound web caching and HTTP/HTTPS egress controller  │
│ IT-ADMIN01           │ Internal             │ Standalone Win10 Pro workstation, SSH management keys  │
│ WIN10-01..03         │ Internal             │ Domain-joined corporate user desktop environments      │
│ KALI-ATTACKER        │ External             │ Red team offensive attack platform                     │
│ SMARTCONNECTOR       │ Logging / Mgmt       │ Multi-feed parser, regex extractor, CEF normalizer     │
│ ARCSIGHT-LOGGER      │ Logging              │ Compressed forensic storage, Verify Storage validator  │
│ ARCSIGHT-ESM         │ Logging / Mgmt       │ Real-time correlation rules engine, Active Channels    │
└──────────────────────┴──────────────────────┴────────────────────────────────────────────────────────┘
```

---

## 4. Layer 1 — Network Security Layer

The network security layer operates as the first line of prevention and policy enforcement:

* **Perimeter Firewall (`PFSENSE-01`)**:
  * **Ingress Filtering**: Default-deny posture against unsolicited external traffic. Only ports explicitly mapped via Virtual IPs (HTTP/HTTPS `TCP 80/443` and SMTP `TCP 25/587`) are translated via Destination NAT (DNAT).
  * **Static Route Choke Point**: pfSense routes traffic destined for protected subnets (`10.10.34.0/24` and `10.10.35.0/24`) exclusively through the `GW_SURICATA` gateway (`10.10.36.11`).
* **Inline Intrusion Prevention (`SURICATA-IPS01`)**:
  * **Kernel-to-Userspace Interception**: Employs Netfilter Queue (`NFQUEUE`) rules in iptables/nftables to divert passing packets into userspace for deep packet inspection.
  * **Fail-Close Architecture**: In production mode, the `--queue-bypass` flag is disabled. If the Suricata process crashes or buffer overruns occur, traffic halts completely, preventing uninspected bypass.
  * **Signature Matching**: Inspects packet headers and payload contents against curated rulesets (e.g., SID `1101002` for malicious archive downloads and SID `1101021` for large outbound transfers).

---

## 5. Layer 2 — Monitoring Layer

The monitoring layer provides non-intrusive, deep protocol visibility operating in parallel to inline enforcement:

* **Passive Network Detection (`ZEEK-NDR01`)**:
  * **Non-Blocking Architecture**: Receives mirrored copies of network traffic via virtual switch SPAN/port-mirroring and gretap tunnels (`gretap34`, `gretap35`, `gretap36`), ensuring zero latency impact on production data flows.
  * **Stateful Protocol Analysis**: Reconstructs sessions across TCP/UDP, extracting granular transaction metadata into structured tab-separated logs:
    * `conn.log`: Connection state, byte counts, flow duration (crucial for detecting long-lived C2 callbacks like TCP port 4444).
    * `dns.log`: Queries, response codes, record types.
    * `http.log` / `ssl.log`: Methods, URIs, User-Agents, TLS ciphers, and certificate validation parameters.
  * **Session Identifier Normalization**: Assigns a unique global connection identifier (`uid`) to every network flow, mapped to CEF `deviceCustomString2` (`ZeekUID`).

---

## 6. Layer 3 — Identity and Endpoint Layer

The identity and endpoint layer establishes access controls, manages corporate credentials, and captures system execution telemetry:

* **Centralized Directory Services (`DC01`)**:
  * Hosts Active Directory Domain Services (`soclab.test`), managing Kerberos authentication, centralized user accounts, and Group Policy Objects (GPO).
  * Exposes secure directory access over **LDAPS (`TCP/636`)** to validate web application logins without cleartext password transmission.
* **Privileged Administration Separation (`IT-ADMIN01`)**:
  * Engineered as a standalone workgroup machine (non-domain joined) dedicated to web server maintenance via SSH. This decoupling ensures that compromising the administrative workstation does not directly yield Active Directory Domain Admin credentials.
* **Endpoint Telemetry Subsystems**:
  * **Microsoft Sysmon**: Configured to capture process creation (Event ID 1) with complete command-line parameters (`cs4`) and parent-child process relationships using globally unique `ProcessGuid` values (`cs5`). Network connections are captured via Event ID 3.
  * **PowerShell ScriptBlock Logging**: Configured via GPO (Event ID 4104) to de-obfuscate and capture dynamic script blocks executed in memory.
  * **Linux Auditd (`WEB01`)**: Monitors kernel system calls (`execve`) executed on the web host. Tagged with `-k web_exec`, capturing `sudo` escalations and container escapes.

---

## 7. Layer 4 — Application and Data Layer

The application and data layer represents the core business workflow and primary target assets:

* **HR Web Application (`WEB01`)**:
  * Operates a multi-container Frappe HRMS / ERPNext v16 stack managed via Docker Compose behind Traefik v3.6 and Nginx.
  * Authenticates corporate employees against Active Directory using LDAPS.
  * Retrieves application records from `DB01` over MySQL protocol (`TCP/3306`).
* **Enterprise Database (`DB01`)**:
  * Runs MariaDB 10.11 housing sensitive employee and payroll tables (`tabEmployee`).
  * **Host-Based Layer-2 Firewall**: Implements strict local iptables filtering:
    ```bash
    sudo iptables -A INPUT -p tcp -s 10.10.34.13 --dport 3306 -j ACCEPT
    sudo iptables -A INPUT -p tcp --dport 3306 -j DROP
    ```
    This firewall enforces least privilege, blocking direct access from workstations in `10.10.35.0/24`.
  * **Database Auditing Plugin**: Operates `SERVER_AUDIT` to log every executed SQL query (`cs3`), user identity, and client IP.
* **Enterprise Email Server (`MAIL01`)**:
  * Operates Postfix for SMTP receiving and delivery, Dovecot for IMAP, and Roundcube for webmail access within the `soclab.test` domain.

---

## 8. Layer 5 — Logging and SIEM Layer

This layer ingests raw logs, transforms them into standardized schemas, and archives them for analysis:

* **ArcSight SmartConnector Subsystem**:
  * Deployed on the isolated Logging Plane (`10.10.40.4`).
  * Runs dedicated FlexConnector listener processes mapped by Generator IDs (2002–2009) to parse incoming UDP, TCP, and Windows WEC feeds.
  * Normalizes heterogeneous logs into **Common Event Format (CEF)**, ensuring common semantic fields across all event types.
* **ArcSight Logger (`10.10.40.5`)**:
  * Ingests CEF SmartMessages over encrypted TLS (`TCP/443`).
  * Compresses and partitions data into Storage Groups and Storage Files.
  * Enforces **Storage Data Validation**: generates cryptographic hash digests across storage blocks. Administrators run *Verify Storage* to detect any unauthorized modifications at the filesystem layer.
  * Provides an ad-hoc query engine for retrospective forensic investigation adhering to **NIST SP 800-86**.

---

## 9. Layer 6 — Detection Layer

The detection layer executes in real-time within **ArcSight ESM**:

* **Stateful Real-Time Correlation**:
  * Evaluates incoming events against boolean logic, threshold counters, and temporal windows.
  * Implements dynamic **Active Lists** to track state across events (e.g., maintaining lists of IPs executing discovery commands).
* **Detection Rules Suite**:
  * **Atomic Rules (`A01–A13`)**: Purpose-built detections for distinct kill chain actions (e.g., `A02` for malicious archive downloads, `A03` for `mshta.exe` execution, `A04` for reverse shells, `A11` for privileged docker container access, `A12` for database schema dumps).
  * **Correlation Rule (`C01`)**: Correlates three independent indicators across different layers:
    $$\text{A02 (Suricata Download)} + \text{A03 (Sysmon mshta Execution)} + \text{A04 (Zeek C2 Callback)}$$
    All three conditions must match the same host entity within a sliding 20-minute window ($\Delta t \le 20\text{ min}$) to trigger a High/Critical severity incident.

---

## 10. Layer 7 — Investigation Layer

The investigation layer defines the structured methodology used by SOC analysts to reconstruct security incidents:

* **Trigger-Driven Workflow**: Analysts do not hunt blindly; investigations begin when an ESM Active Channel alert fires.
* **Dual-Directional Pivoting**:
  * **Backtracking (Truy vết ngược)**: Anchors on alert time $T_0$ and pivots backward to discover initial delivery vectors (e.g., tracking from a reverse shell alert back to an HTTP download, then back to a Postfix Queue ID).
  * **Forward Tracking (Lần vết xuôi dòng)**: Uses endpoint `ProcessGuid` values to trace spawned child processes, credential theft, pivoting tool execution, and lateral movement.
* **Cross-Source Evidence Correlation**: Correlates network sessions (Suricata/Zeek) with operating system process logs (Sysmon), authentication logs (`auth.log`), and database query records (`SERVER_AUDIT`) to build a definitive incident timeline.

---

## 11. End-to-End Security Workflow

The complete operational lifecycle of a security event flows deterministically through the architecture:

```text
  1. TRAFFIC GENERATION
     Adversary transmits payload / Employee accesses corporate service.
          │
          ▼
  2. SECURITY ENFORCEMENT & INSPECTION
     pfSense checks stateful firewall rules -> forwards via Security Transit.
     Suricata intercepts packet via NFQUEUE -> performs DPI -> evaluates signatures.
          │
          ▼
  3. TELEMETRY GENERATION
     Network devices, host agents, and applications write local audit logs
     (eve.json, conn.log, filterlog, Sysmon XML, auditd, MariaDB audit).
          │
          ▼
  4. COLLECTION & PARSING
     Rsyslog and WEC push events across isolated Logging Plane (10.10.40.0/24).
     SmartConnector receives raw streams -> FlexConnector parsers extract fields into CEF.
          │
          ▼
  5. STORAGE & FORWARDING
     CEF SmartMessages sent over TLS/443 to ArcSight Logger (compressed, hashed).
     Logger forwards filtered event stream to ArcSight ESM.
          │
          ▼
  6. REAL-TIME CORRELATION & DETECTION
     ESM rules engine evaluates conditions.
     Rule C01 fires on correlated ingress download + mshta execution + C2 callback.
          │
          ▼
  7. SOC TRIAGE & ALERT DISPATCH
     Alert displays on Active Channel console. Analyst validates context.
          │
          ▼
  8. FORENSIC INVESTIGATION & PIVOTING
     Analyst queries ArcSight Logger.
     Pivots across ProcessGuid, ZeekUID, Postfix QueueID, and MySQL connection_id.
          │
          ▼
  9. INCIDENT CONTAINMENT & HARDENING
     Analyst blocks attacker IP on pfSense, terminates malicious processes on endpoint,
     revokes application sudo privileges, and hardens file permissions.
          │
          ▼
  10. EMPIRICAL VERIFICATION & LESSONS LEARNED
      Repeat tests confirm the attack path is severed while business applications
      continue operating normally.
```
