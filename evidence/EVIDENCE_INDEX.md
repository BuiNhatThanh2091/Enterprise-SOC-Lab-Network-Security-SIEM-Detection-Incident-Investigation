# Master Evidence Inventory Index

This index serves as the single source of truth for all verified technical, architectural, and forensic evidence items cataloged across the Enterprise SOC Lab.

---

## 1. Core System & Architectural Evidence

| Evidence ID | Evidence Type | Related Phase | Related Case | Technical Description | Public Safe | Source Reference |
| :--- | :--- | :---: | :---: | :--- | :---: | :--- |
| **`ARCH-001`** | Architecture | Phase 1–3 | All Cases | Multi-Zone Network Segmentation Blueprint (6 Subnets: External, Transit, DMZ, Internal, Logging, Mgmt). | **YES** | `Báo cáo đề tài SOC.pdf`, p. 23–25, 31 |
| **`ARCH-002`** | Architecture | Phase 1–3 | Case 001–005 | Security Transit Forced Choke Point (`10.10.36.0/24`) with static routes on pfSense to Suricata (`10.10.36.11`). | **YES** | `Báo cáo đề tài SOC.pdf`, p. 27–29; `toan-bo-he-thong-kien_truc_lab.txt`, Sec 5, 13 |
| **`ARCH-003`** | Architecture | Phase 1–3 | Case 004 | Compensatory Host-based Firewall (`iptables` on `DB01`) protecting against Layer-2 intra-subnet bypass. | **YES** | `Báo cáo đề tài SOC.pdf`, p. 34, 57; `toan-bo-he-thong-kien_truc_lab.txt`, Sec 29, 43 |

---

## 2. Telemetry Pipeline & Normalization Evidence

| Evidence ID | Evidence Type | Related Phase | Related Case | Technical Description | Public Safe | Source Reference |
| :--- | :--- | :---: | :---: | :--- | :---: | :--- |
| **`TEL-001`** | Telemetry | Phase 4 | Case 001–003 | Windows Sysmon Event ID 1 & 3 XML configuration preserving `ProcessGuid` and network socket tuples. | **YES** | `Báo cáo đề tài SOC.pdf`, p. 48–51, 62 |
| **`TEL-002`** | Telemetry | Phase 4 | Case 003 | PowerShell ScriptBlock Logging (Event ID 4104) activated via Local Group Policy for script extraction. | **YES** | `Báo cáo đề tài SOC.pdf`, p. 52, 96 |
| **`TEL-003`** | Telemetry | Phase 4 | Case 001, 005 | Suricata Inline IPS EVE JSON alert stream forwarded via Syslog TCP/5521 (Generator ID 2002). | **YES** | `Báo cáo đề tài SOC.pdf`, p. 37–38, 62 |
| **`TEL-004`** | Telemetry | Phase 4 | Case 004 | MariaDB `SERVER_AUDIT` plugin configuration logging raw SQL queries and connections via UDP/5520. | **YES** | `Báo cáo đề tài SOC.pdf`, p. 44–45, 63 |

---

## 3. Detection Rule & Alert Evidence

| Evidence ID | Evidence Type | Related Phase | Related Case | Technical Description | Public Safe | Source Reference |
| :--- | :--- | :---: | :---: | :--- | :---: | :--- |
| **`DET-001`** | Detection | Phase 4 | Case 001 | Rule `A02`: Suricata SID `1101002` matching inbound ZIP download from external web server. | **YES** | `Báo cáo đề tài SOC.pdf`, p. 92, 114 |
| **`DET-002`** | Detection | Phase 4 | Case 001 | Rule `A03`: Sysmon Event ID 1 matching `mshta.exe` executing `SecurityPatch_KB504991.hta`. | **YES** | `Báo cáo đề tài SOC.pdf`, p. 93, 115 |
| **`DET-003`** | Detection | Phase 4 | Case 001 | Rule `A04`: Zeek `conn.log` session matching persistent TCP connection to `203.0.113.25:4444`. | **YES** | `Báo cáo đề tài SOC.pdf`, p. 94, 116 |
| **`DET-004`** | Detection | Phase 4 | Case 001 | Rule `C01`: ArcSight ESM composite correlation alert joining `A02` + `A03` + `A04` ($\Delta t \le 20\text{m}$). | **YES** | `Báo cáo đề tài SOC.pdf`, p. 108, 125 |
| **`DET-005`** | Detection | Phase 4 | Case 002 | Rule `A05`: Sysmon Event ID 1 threshold alert ($\ge 3$ discovery commands in 5m on `IT-ADMIN01`). | **YES** | `Báo cáo đề tài SOC.pdf`, p. 95, 117 |
| **`DET-006`** | Detection | Phase 4 | Case 003 | Rule `A06`: Sysmon Event ID 1 alert for `xcopy.exe` scraping Firefox profile directory. | **YES** | `Báo cáo đề tài SOC.pdf`, p. 95, 117 |
| **`DET-007`** | Detection | Phase 4 | Case 003 | Rule `A07`: PowerShell 4104 alert for `Compress-Archive` and raw .NET `TcpClient` stream. | **YES** | `Báo cáo đề tài SOC.pdf`, p. 96, 118 |
| **`DET-008`** | Detection | Phase 4 | Case 003 | Rule `A08`: PowerShell 4104 / Sysmon 1 alert for `Invoke-WebRequest` downloading `agent.exe`. | **YES** | `Báo cáo đề tài SOC.pdf`, p. 97, 119 |
| **`DET-009`** | Detection | Phase 4 | Case 004 | Rule `A09`: Sysmon ID 3 / Zeek alert for Ligolo-ng reverse tunnel connection to port 11601. | **YES** | `Báo cáo đề tài SOC.pdf`, p. 98, 120 |
| **`DET-010`** | Detection | Phase 4 | Case 004 | Rule `A10`: Suricata flow alert for inter-zone SSH connection from `10.10.35.18` to `10.10.34.13:22`. | **YES** | `Báo cáo đề tài SOC.pdf`, p. 99, 121 |
| **`DET-011`** | Detection | Phase 4 | Case 004 | Rule `A11`: Linux Auditd alert for `sudo docker exec` targeting `site_config.json`. | **YES** | `Báo cáo đề tài SOC.pdf`, p. 102, 122 |
| **`DET-012`** | Detection | Phase 4 | Case 004 | Rule `A12`: MariaDB Audit threshold alert ($\ge 2$ dump queries in 5m, `SHOW DATABASES`). | **YES** | `Báo cáo đề tài SOC.pdf`, p. 104, 123 |
| **`DET-013`** | Detection | Phase 4 | Case 005 | Rule `A13`: Suricata SID `1101021` alert for high-volume DMZ data exfiltration on port 9999. | **YES** | `Báo cáo đề tài SOC.pdf`, p. 106, 124 |

---

## 4. Forensic Investigation & Evidence Pivots

| Evidence ID | Evidence Type | Related Phase | Related Case | Technical Description | Public Safe | Source Reference |
| :--- | :--- | :---: | :---: | :--- | :---: | :--- |
| **`INV-001`** | Investigation | Phase 5 | Case 001 | Postfix delivery log on `MAIL01`: Queue ID `718FC8006A` confirming phishing delivery to `user01`. | **YES** | `Báo cáo đề tài SOC.pdf`, p. 91, 124 |
| **`INV-002`** | Investigation | Phase 5 | Case 001 | Process tree reconstruction on Logger using Sysmon `ProcessGuid` (`mshta` $\rightarrow$ `cmd` $\rightarrow$ `powershell`). | **YES** | `Báo cáo đề tài SOC.pdf`, p. 62, 125 |
| **`INV-003`** | Investigation | Phase 5 | Case 002 | Sysmon Event ID 1 command sequence matching `where`, `sc`, `netstat`, `qwinsta` under reverse shell. | **YES** | `Báo cáo đề tài SOC.pdf`, p. 95, 126 |
| **`INV-004`** | Investigation | Phase 5 | Case 003 | PowerShell ScriptBlock 4104 extracting de-obfuscated script creating `firefox_profile.zip` and socket. | **YES** | `Báo cáo đề tài SOC.pdf`, p. 96–97, 126 |
| **`INV-005`** | Investigation | Phase 5 | Case 004 | Linux `/var/log/auth.log` record confirming SSH accepted password for `thanh` from `10.10.35.18`. | **YES** | `Báo cáo đề tài SOC.pdf`, p. 100, 127 |
| **`INV-006`** | Investigation | Phase 5 | Case 004 | Linux Auditd execve log capturing `docker exec -it hrms-backend-1 cat ... site_config.json`. | **YES** | `Báo cáo đề tài SOC.pdf`, p. 102, 127 |
| **`INV-007`** | Investigation | Phase 5 | Case 004 | MariaDB `SERVER_AUDIT` query log extracting table `tabEmployee` via connection ID 142. | **YES** | `Báo cáo đề tài SOC.pdf`, p. 104, 128 |
| **`INV-008`** | Investigation | Phase 5 | Case 005 | Netcat exfiltration command line and volumetric flow calculation (4.19 MB in 3.42s). | **YES** | `Báo cáo đề tài SOC.pdf`, p. 106, 128 |

---

## 5. Containment & Remediation Evidence

| Evidence ID | Evidence Type | Related Phase | Related Case | Technical Description | Public Safe | Source Reference |
| :--- | :--- | :---: | :---: | :--- | :---: | :--- |
| **`RESP-001`** | Response | Phase 5 | Case 001, 005 | pfSense Filterlog drop records proving post-containment egress blocking on ports 4444 and 9999. | **YES** | `Báo cáo đề tài SOC.pdf`, p. 133, 154 |
| **`RESP-002`** | Response | Phase 5 | Case 001 | Sysmon Event ID 5 (Process Terminate) verifying termination of rogue `powershell.exe` process. | **YES** | `Báo cáo đề tài SOC.pdf`, p. 125, 154 |
| **`RESP-003`** | Response | Phase 5 | Case 004 | Linux sudoers audit confirming removal of `NOPASSWD: /usr/bin/docker` on `WEB01`. | **YES** | `Báo cáo đề tài SOC.pdf`, p. 154–155 |
