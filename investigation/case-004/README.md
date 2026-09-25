# Case 004 — Inter-Zone Pivoting, Privileged Container Access & Database Collection Investigation

## 1. Case Summary
Following the deployment of the Ligolo-ng reverse tunneling agent on workstation `IT-ADMIN01` (Case 003), the adversary initiated lateral movement into the enterprise Demilitarized Zone (DMZ) and Core Database tier. ArcSight ESM detected a multi-stage sequence across four detection rules: `SOC-LAB A09 Suspicious External Tunnel` (Severity 7), `SOC-LAB A10 Internal Remote Access to WEB Tier` (Severity 3), `SOC-LAB A11 Sensitive Privileged WEB Activity` (Severity 7), and `SOC-LAB A12 Suspicious Database Collection` (Severity 8).

Tier-2 SOC analysts executed a cross-tier digital investigation on ArcSight Logger, pivoting from network flow telemetry (Zeek, Suricata) to Linux host authentication logs (`/var/log/auth.log`), container execution audits (Linux Auditd), and relational database audit trails (MariaDB `SERVER_AUDIT`). The investigation proved that the attacker routed traffic through the Ligolo tunnel, authenticated as user `thanh` via SSH into web server `WEB01` (`10.10.34.13`), abused passwordless `sudo docker` privileges to extract database credentials from container `hrms-backend-1`, and executed `mysqldump` against internal database `DB01` (`10.10.35.19`) to steal employee records.

---

## 2. Investigation Objective
1. Validate whether the outbound Ligolo-ng session on port 11601 (`A09`) was actively utilized to route interactive lateral traffic.
2. Confirm the identity, credentials, and network origin of the SSH session established to DMZ web server `WEB01` (`A10`).
3. Reconstruct privileged commands executed on `WEB01` to determine how the adversary accessed container configurations (`A11`).
4. Audit database queries executed against `DB01` via MariaDB `SERVER_AUDIT` to quantify the scope of database records harvested (`A12`).
5. Examine the efficacy of compensatory host-based firewalls (`iptables` on `DB01`) in blocking direct lateral attacks from the workstation subnet.

---

## 3. Initial Alert Sequence
* **Alert 1 ($T_0 + 8\text{m } 50\text{s}$)**: `SOC-LAB A09 Suspicious External Tunnel` (TCP port 11601 session active on `10.10.35.18`).
* **Alert 2 ($T_0 + 9\text{m } 15\text{s}$)**: `SOC-LAB A10 Internal Remote Access to WEB Tier` (SSH `TCP/22` from `10.10.35.18` to `10.10.34.13`).
* **Alert 3 ($T_0 + 10\text{m } 30\text{s}$)**: `SOC-LAB A11 Sensitive Privileged WEB Activity` (`sudo docker exec` targeting `site_config.json`).
* **Alert 4 ($T_0 + 11\text{m } 45\text{s}$)**: `SOC-LAB A12 Suspicious Database Collection` (Threshold $\ge 2$ schema dump queries within 5 minutes on `DB01`).

---

## 4. Initial Evidence
* **Network IPS Telemetry (`A10`)**: Suricata IPS records an allowed inter-zone TCP connection from `10.10.35.18` (Internal) to `10.10.34.13:22` (DMZ).
* **Linux Auditd Telemetry (`A11`)**: Auditd on `WEB01` logs `sudo: thanh : TTY=pts/1 ; USER=root ; COMMAND=/usr/bin/docker exec -it hrms-backend-1 cat sites/hrms.soclab.test/site_config.json`.
* **Database Audit Telemetry (`A12`)**: MariaDB `SERVER_AUDIT` on `DB01` (`10.10.35.19`) records rapid schema queries (`SHOW DATABASES`, `TABLESPACE_NAME`) originating from source IP `10.10.34.13` under database user `_6f9beb897020ebe5`.

---

## 5. Investigation Hypotheses

| Hypothesis ID | Formulation | Validation Status | Evidence Base |
| :--- | :--- | :---: | :--- |
| **H1** | The SSH connection to `WEB01` was tunneled through the Ligolo-ng proxy running on `IT-ADMIN01`. | **SUPPORTED** | Zeek session metadata shows active multiplexed tunnel traffic on port 11601 concurrent with SSH initiation. |
| **H2** | The adversary authenticated to `WEB01` using the credentials recovered from the Firefox profile in Case 003. | **SUPPORTED** | `/var/log/auth.log` on `WEB01` confirms `Accepted password for thanh` matching username harvested in Case 003. |
| **H3** | Attacker attempted to connect directly from `IT-ADMIN01` to `DB01:3306`, but was dropped by host-based firewall. | **SUPPORTED** | Host `iptables` log on `DB01` confirms dropped SYN packets from `10.10.35.18`; Suricata IPS saw zero traffic due to same-L2 switching. |
| **H4** | The adversary dumped the human resources employee table from `DB01` using `mysqldump` executed from `WEB01`. | **SUPPORTED** | MariaDB audit trail records full schema enumeration and table read of `tabEmployee` via connection ID `142`. |

---

## 6. Investigation Method
1. **Network Transit Analysis**: Query Suricata and Zeek telemetry on Logger to track inter-zone traffic passing across the Security Transit segment (`10.10.36.0/24`).
2. **Authentication Audit**: Query Linux Syslog `/var/log/auth.log` on `WEB01` to verify user accounts, source IPs, and authentication mechanisms.
3. **Host Process & Container Inspection**: Query Linux Auditd logs tagged with `-k web_exec` to reconstruct commands executed inside or against Docker containers.
4. **Database Audit Extraction**: Query MariaDB `SERVER_AUDIT` records on `DB01` to analyze SQL statement text (`deviceCustomString3`) and assess data compromise scope.

---

## 7. Evidence Pivot 1: Inter-Zone SSH & Authentication (`A09` & `A10`)
* **Objective**: Determine whether the SSH connection to `WEB01` was authorized maintenance or adversary lateral movement.
* **Logger Query (Linux Auth Log)**:
  ```text
  deviceProduct="Linux Syslog" AND deviceHostName="WEB01" AND message CONTAINS "sshd" AND message CONTAINS "Accepted"
  ```
* **Observed Artifacts**:
  At $T_0 + 9\text{m } 15\text{s}$, `WEB01` recorded:
  ```text
  Accepted password for thanh from 10.10.35.18 port 48122 ssh2
  ```
* **Network NDR Cross-Verification**:
  Zeek `conn.log` shows an active session (`uid=C9xKa812`) from `10.10.35.18` to `10.10.34.13:22`. Crucially, volumetric telemetry confirms concurrent packet surges inside the Ligolo tunnel (`203.0.113.25:11601`).
* **Analytic Conclusion**: The adversary utilized the Ligolo-ng virtual routing interface on Kali to inject an SSH connection through the compromised `IT-ADMIN01` workstation into DMZ host `WEB01`. The stolen password for user `thanh` (harvested in Case 003) granted immediate interactive shell access.

---

## 8. Evidence Pivot 2: Container Credential Scraping (`A11`)
* **Objective**: Reconstruct the attacker's actions within the SSH session on `WEB01`.
* **Logger Query (Linux Auditd)**:
  ```text
  deviceProduct="WEB01 Web Stack" AND message CONTAINS "docker exec"
  ```
* **Observed Artifacts**:
  At $T_0 + 10\text{m } 30\text{s}$, Linux Auditd (`-k web_exec`) captured:
  ```text
  type=EXECVE msg=audit(...): argc=6 a0="sudo" a1="docker" a2="exec" a3="-it" a4="hrms-backend-1" a5="cat sites/hrms.soclab.test/site_config.json"
  ```
* **Interpretation of Disclosed Credentials**:
  The target file `site_config.json` contained Frappe HRMS production database connection parameters:
  * Database Host: `10.10.35.19` (`DB01`, Internal Core Network)
  * Database Name / User: `_6f9beb897020ebe5`
  * Database Password: `[REDACTED_DATABASE_SECRET]`
* **Analytic Conclusion**: The attacker abused passwordless `sudo docker` rights to bypass container isolation, scraping sensitive cleartext database credentials directly from the application's configuration volume.

---

## 9. Evidence Pivot 3: Layer-2 Direct Access Failure & Database Dump (`A12`)
* **Objective**: Determine how the adversary accessed `DB01` and verify what data was queried.
* **Workstation Direct Access Attempt**:
  At $T_0 + 10\text{m } 55\text{s}$, attacker attempted `nc -vz 10.10.35.19 3306` directly from `IT-ADMIN01`.
  * *Network Telemetry*: Zero packets observed on Suricata IPS (due to same-L2 switching within `10.10.35.0/24`).
  * *Host Telemetry*: `DB01` iptables audit confirms connection dropped (`IPTABLES-DROP: IN=ens192 SRC=10.10.35.18 DST=10.10.35.19 DPT=3306`). The compensatory host firewall successfully protected `DB01` from intra-subnet lateral movement.
* **Web-to-Database Query Execution**:
  The adversary pivoted back to `WEB01` (which is whitelisted on `DB01` iptables) and ran:
  ```bash
  mysqldump -h 10.10.35.19 -u _6f9beb897020ebe5 -p... _6f9beb897020ebe5 tabEmployee | gzip > /tmp/_6f9beb897020ebe5.sql.gz
  ```
* **Logger Query (MariaDB Audit)**:
  ```text
  deviceProduct="MariaDB Server Audit" AND sourceAddress=10.10.34.13 AND deviceCustomString3 CONTAINS "tabEmployee"
  ```
* **Result**:
  MariaDB `SERVER_AUDIT` logs show connection ID `142` executing schema metadata queries (`SHOW DATABASES`, `INFORMATION_SCHEMA.FILES`) triggering rule `A12`, followed by a full sequential read of table `tabEmployee`.
* **Analytic Conclusion**: The attacker successfully bypassed the Layer-2 network restriction by utilizing `WEB01` as an application proxy, dumping the entire corporate employee database to `/tmp/` in compressed format.

---

## 10. Timeline of Events

```text
[T0 + 8m 45s]  SYSMON: agent.exe initiates Ligolo-ng tunnel to 203.0.113.25:11601 (Rule A09 fires).
[T0 + 9m 15s]  SURICATA / AUTH.LOG: SSH session from 10.10.35.18 to WEB01 (10.10.34.13) accepted for user thanh (Rule A10 fires).
[T0 + 10m 30s] AUDITD: sudo docker exec targeting site_config.json executed on WEB01 (Rule A11 fires).
[T0 + 10m 55s] DB01 IPTABLES: Host firewall drops direct MySQL connection attempt from IT-ADMIN01 (10.10.35.18).
[T0 + 11m 20s] WEB01: Attacker tests MySQL reachability to DB01 (10.10.35.19:3306) via nc -vz (Successful).
[T0 + 11m 45s] MARIADB AUDIT: mysqldump metadata queries execute against tabEmployee (Rule A12 fires).
[T0 + 11m 58s] WEB01: Gzip database archive written to /tmp/_6f9beb897020ebe5.sql.gz.
```

---

## 11. Reconstructed Attack Chain
```text
1. Tunneling Established  ──► Ligolo-ng TUN interface routed through IT-ADMIN01 (A09)
2. Lateral Movement (SSH) ──► SSH login to WEB01 (10.10.34.13:22) using stolen user 'thanh' (A10)
3. Privileged Scraping    ──► sudo docker exec extracts DB password from site_config.json (A11)
4. Intra-Subnet Probing   ──► Direct connection from IT-ADMIN01 to DB01 blocked by host iptables
5. Application Pivoting   ──► Connection to DB01 (3306) initiated from whitelisted WEB01 IP
6. Database Exfiltration  ──► mysqldump tabEmployee dumped to /tmp/_6f9beb897020ebe5.sql.gz (A12)
```

---

## 12. Detection Coverage Analysis

| Detection ID | Fired? | Evidence Found | Operational Role in Investigation | Known Detection Limitations |
| :--- | :---: | :--- | :--- | :--- |
| **A09** | **YES** | Sysmon ID 3 / Zeek `conn.log` port 11601. | Tunneling Anchor: Signals active proxy bridge. | Scenario-dependent; relies on default Ligolo port 11601. |
| **A10** | **YES** | Suricata flow + Linux `/var/log/auth.log`. | Lateral Movement Anchor: Proves SSH access. | Payload encrypted; Suricata cannot read keystrokes. |
| **A11** | **YES** | Linux Auditd (`-k web_exec`) event. | Privilege Escalation Anchor: Captures config read. | Captures single exec; blind inside interactive container shells. |
| **A12** | **YES** | MariaDB Audit query logs (mysqldump pattern). | Data Collection Anchor: Identifies dumped tables. | Threshold-dependent ($\ge 2$ in 5m); single queries bypass rule. |

---

## 13. Detection Gaps & Architectural Blind Spots
1. **Intra-Subnet Layer-2 Blind Spot**: When the attacker attempted to connect directly from `IT-ADMIN01` to `DB01:3306`, Suricata Inline IPS on Gateway `10.10.35.11` observed **zero packets**. The traffic switched directly across the virtual switch backplane. Protection succeeded solely because host-level `iptables` had been explicitly configured on `DB01`.
2. **Interactive Container Namespace Blindness**: Linux Auditd captured `docker exec ... cat site_config.json` because it was executed as a one-line command from the host OS. If the adversary had spawned an interactive shell (`docker exec -it hrms-backend-1 /bin/bash`) and viewed the file from within the container shell, host auditd would not have logged the file access.

---

## 14. Impact Assessment
* **Confidentiality**: **CRITICAL BREACH**. Entire corporate employee database table (`tabEmployee`), containing personal identities, salaries, and corporate metadata, was dumped into a local archive.
* **Integrity**: **COMPROMISED**. Application configuration secrets and database credentials exposed.
* **Availability**: **NORMAL**. Database and web service remained online.
* **Compromise Scope**: Lateral movement successfully crossed security zones, expanding from an internal workstation (`Internal`) to the DMZ web cluster (`DMZ`) and the core relational database (`Internal`).

---

## 15. Containment & Remediation Actions
1. **Sudo Privilege Revocation**: Removed `NOPASSWD: /usr/bin/docker` from `/etc/sudoers.d/` on `WEB01`. Docker management restricted to dedicated operational service accounts.
2. **Database Credential Rotation**: Rotated password for user `_6f9beb897020ebe5` on MariaDB and updated `site_config.json` with strict file permissions (`chmod 600`).
3. **SSH Access Restriction**: Hardened `sshd_config` on `WEB01` to reject password authentication, requiring SSH key pairs with compulsory passphrases.
4. **Temporary Host Isolation**: Revoked network routing for `WEB01` pending full forensic sweep.

---

## 16. Lessons Learned
1. **The Danger of Passwordless Sudo for Docker**: Granting a non-root user `sudo docker` is equivalent to granting full root access, as the user can mount any host filesystem or interact with container secrets at will.
2. **Compensatory Controls Work**: The host-based `iptables` firewall on `DB01` was the only defense layer that successfully prevented direct intra-subnet database access from `IT-ADMIN01`.

---

## 17. Detection Improvements
1. **Docker Execution Anomaly Alert**: Create an ESM correlation rule triggering immediately whenever `docker exec` accesses files matching `*config*.json` or `*.env`.
2. **Database Velocity Thresholds**: Implement an alert on MariaDB Audit detecting queries returning $> 1,000$ rows or invoking `mysqldump` outside scheduled backup maintenance windows.

---

## 18. Investigation Limitations
* Auditd does not log container stdout. The exact database password string was not preserved in logs, but confirmed compromised based on subsequent authenticated queries.

---

## 19. Final Assessment
Case 004 demonstrates an advanced multi-tier lateral intrusion. By combining stolen browser credentials with living-off-the-land container commands, the adversary bridged network segments and dumped core corporate data. Detection rules across four independent telemetry tiers provided full forensic accountability.

---

## 20. Evidence References
* **Primary Report**: `Báo cáo đề tài SOC.pdf`, Trang 84–87, 98–104, 126–128.
* **Architecture Runbook**: `toan-bo-he-thong-kien_truc_lab.txt`, Mục 52–53.
* **Logger Evidence Artifacts**: EV-06, EV-07, EV-08, EV-09.

---

## 21. Related Visual & Evidentiary Assets

### Architecture & Forensic Workflow Diagrams
* [**Enterprise SOC Overview Diagram**](file:///e:/project_ca_nhan/lab_cty/architecture/enterprise-soc-overview.svg): High-level system architecture with DMZ and Internal zones.
* [**Network Security Flow Diagram**](file:///e:/project_ca_nhan/lab_cty/architecture/network-security-flow.svg): Transit gateway routing between DMZ and Internal, illustrating the same-L2 bypass risk and host iptables defense.
* [**Telemetry Pipeline Flow Diagram**](file:///e:/project_ca_nhan/lab_cty/architecture/telemetry-flow.svg): Linux syslog (auth.log), Auditd, and MariaDB SERVER_AUDIT log collection.
* [**Case 004 Forensic Investigation Flowchart**](file:///e:/project_ca_nhan/lab_cty/investigation/case-004/investigation-flow.mmd): Sequence diagram of cross-zone SSH triage, Auditd container analysis, and database audit queries.

### Curated Evidence Manifests
* [**ARCH-001 Manifest**](file:///e:/project_ca_nhan/lab_cty/evidence/architecture/README.md#arch-001): Multi-zone VLAN segmentation and perimeter isolation layout.
* [**ARCH-002 Manifest**](file:///e:/project_ca_nhan/lab_cty/evidence/architecture/README.md#arch-002): Security Transit Gateway routing policies and inter-zone inspection.
* [**ARCH-003 Manifest**](file:///e:/project_ca_nhan/lab_cty/evidence/architecture/README.md#arch-003): Database host (`DB01`) compensatory iptables ingress access control.
* [**INV-005 Manifest**](file:///e:/project_ca_nhan/lab_cty/evidence/investigation/README.md#inv-005): Linux `auth.log` SSH root login traceback on DMZ `WEB01`.
* [**INV-006 Manifest**](file:///e:/project_ca_nhan/lab_cty/evidence/investigation/README.md#inv-006): Linux Auditd `execve` container command execution (`docker exec`).
* [**INV-007 Manifest**](file:///e:/project_ca_nhan/lab_cty/evidence/investigation/README.md#inv-007): MariaDB `SERVER_AUDIT` query logs showing schema extraction and table dumps.
* [**TEL-004 Manifest**](file:///e:/project_ca_nhan/lab_cty/evidence/telemetry/README.md#tel-004): MariaDB Audit Plugin (`SERVER_AUDIT`) schema and syslog CEF mapping.

### Demonstration & Investigation Videos
* [**VIDEO-01: Attack Simulation Walkthrough**](file:///e:/project_ca_nhan/lab_cty/media/attack-simulation/VIDEO-01.md): Red-team execution of Ligolo tunneling, SSH lateral movement, Docker credential scraping, and database extraction.
* [**VIDEO-02: Full Incident Investigation Walkthrough**](file:///e:/project_ca_nhan/lab_cty/media/investigation/VIDEO-02-FULL.md): Primary screen recording of cross-zone SSH triage, Auditd container inspection, and MariaDB query log forensics.
* [**VIDEO-03: Supplementary Investigation Walkthrough**](file:///e:/project_ca_nhan/lab_cty/media/investigation/VIDEO-03-SUPPLEMENT.md): Technical deep-dive on Module 2 (Auditd `docker exec`), Module 3 (Layer-2 ARP bypass & iptables defense), and Module 4 (MariaDB `SERVER_AUDIT` query syntax).

---

## 22. Video Demonstration

* **Hosting:** YouTube  
* **Visibility:** Unlisted  
* **Status:** Pending Upload  
* **URL:** `YOUTUBE_URL_PENDING`  
* **Demonstration Documents:**
  * Primary Walkthrough: [**`VIDEO-02-FULL.md`**](file:///e:/project_ca_nhan/lab_cty/media/investigation/VIDEO-02-FULL.md)
  * Deep Forensics Companion: [**`VIDEO-03-SUPPLEMENT.md`**](file:///e:/project_ca_nhan/lab_cty/media/investigation/VIDEO-03-SUPPLEMENT.md)

Under the unified laboratory incident workflow, this case study's triage is demonstrated within **Video 02** (Full Incident Investigation Walkthrough), while **Video 03** (Supplementary Walkthrough) provides deep forensic analyses of Linux Auditd container command tracing, Layer-2 ARP bypass defense on `DB01`, and detailed MariaDB `SERVER_AUDIT` query extraction records.


