# Security Architecture

## 1. Security Design Principles

The security architecture of the Enterprise SOC Lab is constructed upon fundamental information security principles, with each principle explicitly differentiated across four engineering dimensions:

```text
┌─────────────────────────┬──────────────────────────┬──────────────────────────┬─────────────────────────┐
│ Design Intent           │ Implemented Control      │ Observed Limitation      │ Future Improvement      │
├─────────────────────────┼──────────────────────────┼──────────────────────────┼─────────────────────────┤
│ Enforce mandatory path  │ Security Transit &       │ Does not inspect intra-  │ Micro-segmentation with │
│ inspection for all      │ static routing via       │ subnet Layer-2 frames    │ dedicated per-tier      │
│ inter-zone traffic      │ Suricata Inline IPS      │ in 10.10.35.0/24         │ VLANs / private VLANs   │
├─────────────────────────┼──────────────────────────┼──────────────────────────┼─────────────────────────┤
│ Default Deny on all     │ pfSense firewall rules;  │ Outbound non-standard    │ Full Forward Proxy      │
│ network boundaries      │ iptables host firewall   │ egress was open prior    │ enforcement for all     │
│ and services            │ on database DB01         │ to post-incident hardening outbound traffic        │
├─────────────────────────┼──────────────────────────┼──────────────────────────┼─────────────────────────┤
│ Principle of Least      │ Standalone IT-Admin;     │ Sudo rights on WEB01     │ Centralized secrets     │
│ Privilege across hosts  │ DB restricted to Web IP; │ initially allowed docker │ management; ephemeral   │
│ and administrative roles│ chmod 600 config files   │ root container escape    │ just-in-time access     │
├─────────────────────────┼──────────────────────────┼──────────────────────────┼─────────────────────────┤
│ Out-of-band operational│ Dedicated Logging (.40)  │ Syslog over UDP risks    │ TLS/TCP syslog for all  │
│ isolation for telemetry │ & Management (.21)       │ dropped packets during   │ endpoints; redundant    │
│ and management planes   │ planes with no gateways  │ high-volume bursts       │ dual-homed collectors   │
├─────────────────────────┼──────────────────────────┼──────────────────────────┼─────────────────────────┤
│ Defense-in-Depth across │ 12 complementary layers   │ Encrypted traffic (TLS/  │ Dedicated TLS/SSL       │
│ the cyber kill chain    │ from perimeter to host   │ SSH) obscures payload    │ decryption mirror for   │
│                         │ audit and central SIEM   │ inspection at inline IPS │ inline security sensors │
└─────────────────────────┴──────────────────────────┴──────────────────────────┴─────────────────────────┘
```

---

## 2. Segmentation Architecture

Segmentation enforces cryptographic and logical boundaries between assets based on exposure risk and asset valuation:

1. **Perimeter vs. DMZ**:
   * External users have zero visibility into internal network structures.
   * Inbound traffic terminates on public Virtual IPs (`203.0.113.13`, `203.0.113.14`) and is translated via DNAT to DMZ hosts (`WEB01`, `MAIL01`).
2. **DMZ vs. Internal Core**:
   * Services hosted in the DMZ (`10.10.34.0/24`) cannot communicate arbitrarily with the Internal zone (`10.10.35.0/24`).
   * Explicit, granular pinholes permit only required operational dependencies:
     * `WEB01` to `DC01`: LDAPS (`TCP/636`) for Active Directory credential verification.
     * `WEB01` to `DB01`: MySQL (`TCP/3306`) for application queries.
     * All other connection attempts from DMZ into Internal are dropped at the Suricata router.
3. **Internal Core vs. Management/Logging**:
   * Management interfaces (`10.10.21.0/24`) and Logging interfaces (`10.10.40.0/24`) exist on isolated vSwitch portgroups.
   * Internal workstations and DMZ servers have no routing paths into the management plane. Management is conducted strictly out-of-band via `MGMT-JUMPHOST` (`10.10.21.100`).

---

## 3. Firewall Enforcement

Firewall controls are implemented at the network perimeter via `PFSENSE-01`:

* **Stateful Connection Tracking**: Evaluates TCP sequence numbers, flags, and connection states (`SYN`, `ESTABLISHED`, `FIN`). Unsolicited packets not matching an active state table entry are dropped.
* **Perimeter Ingress Policy**:
  * Rules on `WAN` interface restrict inbound traffic exclusively to public VIP destinations:
    * `WAN -> 203.0.113.13:80, 443` -> DNAT to `WEB01` (`10.10.34.13:80, 443`).
    * `WAN -> 203.0.113.14:25, 587` -> DNAT to `MAIL01` (`10.10.34.14:25, 587`).
  * Inbound connections attempting to target internal subnets directly are discarded by the default-deny rule.
* **Security Transit Policy**:
  * The `LAN01` interface corresponds to the Security Transit network (`10.10.36.0/24`).
  * Firewall rules targeting internal workstations match explicit IP subnets (`Source: 10.10.35.0/24`), preventing rule matching errors associated with default interface aliases.

---

## 4. Inline Intrusion Prevention (IPS)

`SURICATA-IPS01` operates as an inline Deep Packet Inspection (DPI) engine and inter-zone Layer-3 router:

* **Kernel Netfilter Queue Integration**:
  * Packets routed across network interfaces (`ens256` Transit, `ens193` Internal, `ens225` DMZ) are matched by iptables forward chain rules and pushed into userspace queue 0 (`NFQUEUE`).
* **Fail-Close Reliability**:
  * In hardened operational mode, the `--queue-bypass` flag is omitted. If the Suricata process terminates, the Linux kernel drops queued packets rather than allowing uninspected traffic to pass.
* **Signature-Based Inspection**:
  * Analyzes protocols, headers, and payloads against custom signatures:
    * **SID 1101002**: Triggers on HTTP GET requests downloading executable archives (`.zip` containing malicious `.hta` files).
    * **SID 1101021**: Triggers on large outbound data transfers across high non-standard ports (`TCP/9999`).
  * In the lab environment, signatures are configured with the `alert` action to generate telemetry for SIEM correlation without disrupting baseline services during training exercises.

---

## 5. Passive Network Monitoring (NDR)

Operating alongside inline enforcement, `ZEEK-NDR01` provides passive Network Detection and Response:

* **Zero Latency Impact**: Ingests mirrored packet streams via virtual switch SPAN/port-mirroring and gretap interfaces (`gretap34`, `gretap35`, `gretap36`). Zeek never delays or drops production traffic.
* **Protocol State Machine & Metadata Extraction**:
  * Assembles bidirectional TCP streams, extracting granular protocol transactions into structured logs (`conn.log`, `dns.log`, `http.log`, `ssl.log`).
* **Long-Lived Session Anomaly Detection**:
  * Detects persistent, non-interactive reverse shell sessions (e.g., PowerShell reverse shell on `TCP/4444`) that evade signature-based pattern matchers due to continuous stream encoding.
  * Every session is stamped with a unique, globally consistent identifier (`uid`), enabling instant pivoting across DNS, HTTP, and connection logs.

---

## 6. Host-Based Visibility & Telemetry

Because network perimeters are blind to local process execution and intra-subnet frames, host-based auditing is deployed across key endpoints:

* **Microsoft Sysmon (IT-ADMIN01 & Windows Endpoints)**:
  * **Event ID 1 (Process Create)**: Captures process execution hierarchy, full command-line parameters (`cs4`), user context, and hashes.
  * **ProcessGuid (`cs5`)**: Utilizes globally unique GUIDs generated by Sysmon to track parent-child process lineage (`ParentProcessGuid` $\rightarrow$ `ProcessGuid`), overcoming operating system PID reuse flaws.
  * **Event ID 3 (Network Connect)**: Explicitly enabled in Sysmon configuration to log local process-initiated outbound connections (e.g., `powershell.exe` connecting to port 4444, `agent.exe` connecting to port 11601).
* **PowerShell ScriptBlock Logging (Event ID 4104)**:
  * Enforced via local GPO on `IT-ADMIN01`. Captures the complete de-obfuscated content of executed script blocks, revealing malicious staging scripts (`Compress-Archive`, `TcpClient` raw socket streams).
* **Linux Auditd (`WEB01`)**:
  * Configured with rule `-a always,exit -F arch=b64 -S execve -k web_exec` to monitor execution of system calls.
  * Captures administrative privilege escalation commands, such as `sudo docker exec` targeting backend containers.

---

## 7. Application Controls

Security controls at the application layer safeguard web services and business logic:

* **Web Application Architecture (`WEB01`)**:
  * Multi-container architecture runs frontend, backend, and background workers as separate Docker containers behind Nginx and Traefik reverse proxies.
  * Application authentication is offloaded to central directory services over encrypted **LDAPS (`TCP/636`)**, eliminating locally stored user credential databases on the web host.
* **Post-Incident Application Hardening**:
  * **Sudoers Privilege Revocation**: Removed user `thanh` from the `/etc/sudoers` group with permission to run `/usr/bin/docker`. Even with compromised SSH credentials, an attacker cannot execute `docker exec` to access application containers.
  * **File System Access Control**: Restricted permissions on `site_config.json` containing database credentials to `chmod 600`, owned exclusively by the unprivileged `frappe` service user.

---

## 8. Database Security Controls

The relational database (`DB01`) implements multiple layers of protection to shield core assets:

* **Host-Based Layer-2 Firewall**:
  * Solves the intra-subnet blind spot within `10.10.35.0/24`. Local Linux iptables rules reject all connection requests to port 3306 unless originating from the exact IP of the web server:
    ```bash
    sudo iptables -A INPUT -p tcp -s 10.10.34.13 --dport 3306 -j ACCEPT
    sudo iptables -A INPUT -p tcp --dport 3306 -j DROP
    ```
* **Database Activity Auditing (`SERVER_AUDIT`)**:
  * MariaDB audit plugin records all connection attempts, authenticated database usernames, client network addresses, and full SQL query texts.
  * Captures structural enumeration queries (`SHOW DATABASES`, `INFORMATION_SCHEMA.FILES`) and automated table dumping activities (`mysqldump`).

---

## 9. Egress Control Architecture

Unrestricted outbound traffic provides adversaries with reliable command-and-control (C2) and data exfiltration channels:

* **Forward Proxy Enforcement**:
  * Outbound HTTP and HTTPS traffic from internal endpoints must pass through `FORWARD-PROXY` (`203.0.113.252:8132`).
* **Perimeter Egress Filtering (`PFSENSE-01`)**:
  * In the baseline testing phase, egress restrictions were loose, permitting direct outbound connections on raw ports (4444, 11601, 9999).
  * In post-incident hardening, pfSense firewall rules on `LAN01` enforce strict egress filtering: all outbound connections directly targeting external IPs on non-standard ports are blocked, forcing traffic through the proxy.

---

## 10. Logging Isolation (Telemetry Plane)

* **Physical / Logical Separation**:
  * Telemetry is transported over a dedicated broadcast domain (`10.10.40.0/24`) completely isolated from production user traffic.
* **Non-Routable Architecture**:
  * Logging interfaces on all monitored servers are configured **without a default gateway**.
  * Prevents compromised hosts from utilizing logging interfaces as secondary exit routes to bypass perimeter firewalls.
* **Tamper-Resistant Log Storage**:
  * `ARCSIGHT-LOGGER` (`10.10.40.5`) enforces role-based access control and strict data immutability. Individual event deletion or modification is prohibited at the software level.
  * **Storage Data Validation**: Generates periodic SHA-256 cryptographic hashes across raw storage blocks, allowing administrators to audit storage integrity via the *Verify Storage* command.

---

## 11. Management Isolation (Management Plane)

* **Out-of-Band Administrative Access**:
  * Hypervisor, firewall, IPS, and SIEM management interfaces reside on a dedicated segment (`10.10.21.0/24`).
* **Bastion Jump Host (`MGMT-JUMPHOST`)**:
  * All administrative sessions (SSH, WebGUI) must originate from the designated management bastion (`10.10.21.100`).
* **Workstation Isolation**:
  * Internal workstations (including `IT-ADMIN01`) have no network path into `10.10.21.0/24`, preventing compromised endpoint malware from accessing hypervisors or security appliances.

---

## 12. Defense-in-Depth Functional Allocation

The defense-in-depth model coordinates prevention, detection, visibility, and investigation evidence across twelve layers:

```text
┌───────┬──────────────────────────┬─────────────────────────────┬─────────────────────────────────────┐
│ Layer │ Technology / Mechanism   │ Primary Security Function   │ Operational Contribution            │
├───────┼──────────────────────────┼─────────────────────────────┼─────────────────────────────────────┤
│ 1     │ Network Segmentation     │ Prevention (Isolation)      │ Restricts attack blast radius       │
│ 2     │ pfSense Firewall & NAT   │ Prevention (Boundary Block) │ Blocks unsolicited ingress traffic  │
│ 3     │ Security Transit Path    │ Prevention (Bypass Defense) │ Forces traffic through inline IPS   │
│ 4     │ Suricata Inline IPS      │ Detection & Prevention      │ Signature matching & alert/drop DPI │
│ 5     │ Zeek Passive Sensor      │ Visibility & Detection      │ Application metadata & session logs │
│ 6     │ Host-Based Firewall (DB) │ Prevention (L2 Shield)      │ Neutralizes intra-subnet blind spot │
│ 7     │ Windows Sysmon & Audit   │ Visibility & Evidence       │ Captures process genealogy & C2     │
│ 8     │ Linux Auditd (Host)      │ Detection & Evidence        │ Audits container escapes & sudo     │
│ 9     │ MariaDB SERVER_AUDIT     │ Visibility & Evidence       │ Records raw SQL queries & dumps     │
│ 10    │ Isolated Logging Plane   │ Evidence Preservation       │ Secures telemetry against tampering │
│ 11    │ ArcSight ESM Correlation │ Detection (Real-Time)       │ Correlates cross-layer alerts (C01) │
│ 12    │ ArcSight Logger Queries  │ Forensic Investigation      │ Reconstructs timeline & kill chain  │
└───────┴──────────────────────────┴─────────────────────────────┴─────────────────────────────────────┘
```

---

## 13. Architectural Limitations & Trade-Offs

1. **Intra-Subnet L2 Direct Switching**:
   * *Limitation*: Inline network devices cannot inspect same-subnet frames.
   * *Compensatory Control*: Relies on host-based iptables on `DB01`, local Sysmon, and database audit logs.
2. **Encrypted Session Inspection**:
   * *Limitation*: Suricata does not perform SSL/TLS decryption; payload contents of SSH and HTTPS streams cannot be inspected for inline signatures.
   * *Compensatory Control*: Zeek extracts unencrypted TLS handshake metadata (certificates, SNI); endpoint agents capture decrypted data prior to transmission or after reception.
3. **Stateless UDP Telemetry Ingestion**:
   * *Limitation*: Heavy burst traffic or database dumps generating large syslog strings risk packet drops or fragmentation over UDP.
   * *Compensatory Control*: Forensic validity is established strictly upon events verified as successfully received and indexed within ArcSight Logger.
4. **Manual Response Execution**:
   * *Limitation*: No automated SOAR playbooks were deployed; incident containment actions were executed manually by analysts.
