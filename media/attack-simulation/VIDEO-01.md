# [SOC Attack Simulation] Multi-Stage Adversary Intrusion & Detection Validation

## 1. Overview & Demonstration Purpose

This technical demonstration records the execution of the laboratory's end-to-end **Red Team Attack Simulation** conducted against the enterprise virtual infrastructure. 

The demonstration is structured strictly as an empirical validation baseline to show:
```text
Adversary Execution (Kali: 203.0.113.25)
                  │
                  ▼
Observable Host & Network Activity
                  │
                  ▼
Telemetry Generation (Sysmon, Zeek, Suricata, Auditd, MariaDB, Postfix)
                  │
                  ▼
Detection Rule Triggering (Atomic A01–A13, Composite C01)
```

This recording is not designed as an offensive exploitation tutorial; rather, it provides defensible, empirical proof that the simulated adversary actions generated the exact telemetry signatures captured by the SOC's detection and investigation pipeline.

> [!NOTE]
> Video publication is pending. Sanitized YouTube links will be added after final review; all core technical documentation and artifacts are already available in this repository.

---

## 2. Technical Metadata & Repository Mapping

* **Video ID**: `VIDEO-01`
* **Title**: `[SOC Attack Simulation] Multi-Stage Adversary Intrusion & Detection Validation`
* **Adversary Platform**: `203.0.113.25` (`Kali Linux`, External Threat Network)
* **Target Enterprise Subnets**:
  * `DMZ_NET` (`10.10.34.0/24`): `MAIL01` (`.14`), `WEB01` (`.13`)
  * `INTERNAL_NET` (`10.10.35.0/24`): `IT-ADMIN01` (`.18`), `DB01` (`.19`), `DC01` (`.12`)
* **Monitored Transit Gateway**: `SECURITY_TRANSIT` (`10.10.36.0/24`): `pfSense` (`.10`), `Suricata` (`.11`)
* **Related Case Studies**: [Case 001](file:///e:/project_ca_nhan/lab_cty/investigation/case-001/README.md), [Case 002](file:///e:/project_ca_nhan/lab_cty/investigation/case-002/README.md), [Case 003](file:///e:/project_ca_nhan/lab_cty/investigation/case-003/README.md), [Case 004](file:///e:/project_ca_nhan/lab_cty/investigation/case-004/README.md), [Case 005](file:///e:/project_ca_nhan/lab_cty/investigation/case-005/README.md)
* **Associated Detection Rules**: `A01`, `A02`, `A03`, `A04`, `A05`, `A06`, `A07`, `A08`, `A09`, `A10`, `A11`, `A12`, `A13`, and Composite Rule `C01`
* **Key Evidence Manifests**: `DET-001`–`DET-005`, `INV-001`–`INV-008`, `TEL-001`–`TEL-004`
* **Hosting Platform**: YouTube (Unlisted)
* **YouTube Publication Status**: `Pending Upload`
* **YouTube Video URL**: `YOUTUBE_URL_PENDING`
* **Public-Safe Verification**: `REVIEW_REQUIRED` (Pending [Video Sanitization Checklist](file:///e:/project_ca_nhan/lab_cty/media/VIDEO_SANITIZATION_CHECKLIST.md) frame-by-frame audit)

---

## 3. Multi-Stage Simulation Scenario & Observable Behaviors

The video demonstrates the complete progression of the simulated adversary campaign:

```text
[ Phase 1: Ingress & Foothold ]
  1. Inbound SMTP Spearphishing: Spoofed bulletin delivered from 203.0.113.25 to MAIL01.
  2. Executable Payload Ingress: IT-ADMIN01 downloads SecurityPatch_KB504991.zip via HTTP.
  3. Living-off-the-Land Execution: User executes .hta; mshta.exe spawns background PowerShell.
  4. C2 Callback: IT-ADMIN01 establishes persistent TCP reverse shell on port 4444 to Kali.

[ Phase 2: Host Reconnaissance & Credential Scraping ]
  5. Discovery Burst: Attacker executes rapid host commands (whoami, ipconfig, net user, qwinsta).
  6. Credential Harvesting: Staging Firefox/Chrome profile database via xcopy.
  7. Exfiltration via Socket: Streaming compressed archive to Kali on TCP:9999 / TCP:11601.

[ Phase 3: Lateral Movement & Pivoting ]
  8. Tool Ingress: IT-ADMIN01 downloads ligolo-agent.exe via certutil -urlcache.
  9. Tunnel Establishment: Reverse proxy tunnel established to Kali on TCP:11601.
 10. Cross-Zone SSH Pivoting: Attacker pivots from Internal (.18) to DMZ WEB01 (.13) over port 22.

[ Phase 4: Container Abuse & Data Exfiltration ]
 11. Container Privilege Abuse: Sudo docker exec invoked on WEB01 to extract environment credentials.
 12. Database Enumeration: Direct SQL queries against DB01 (10.10.35.19) dumping customer records.
 13. Staging Exfiltration: Netcat socket transfer of database dump from DMZ to Kali on TCP:9999.
```

---

## 4. Telemetry Generated Across Infrastructure

Every simulated action emits concrete telemetry across the lab's sensor array:

| Intrusion Stage | Generating Host / Sensor | Observable Telemetry Produced | Target Detection Rule |
| :--- | :--- | :--- | :---: |
| **Phishing Delivery** | `MAIL01` (`Postfix`) | Mail delivery syslog: `to=<user01@soclab.test>`, `relay=local` | `A01` |
| **Payload Download** | `Suricata IPS` (`Transit`) | HTTP EVE JSON event: `url="/SecurityPatch_KB504991.zip"` | `A02` |
| **HTA LOLBin Launch** | `IT-ADMIN01` (`Sysmon`) | Event ID 1: `mshta.exe` spawning `powershell.exe -enc` | `A03` |
| **Reverse Shell** | `Zeek NDR` (`Transit`) | `conn.log` event: `proto=tcp`, `id.resp_p=4444`, high duration | `A04` |
| **Stateful Correlation**| `ArcSight ESM` | Composite rule joins `A02` + `A03` + `A04` on matching host entity | `C01` |
| **Discovery Burst** | `IT-ADMIN01` (`Sysmon`) | 6 $\times$ Event ID 1 process creations in $< 60\text{ seconds}$ | `A05` |
| **Credential Staging**| `IT-ADMIN01` (`Sysmon`) | Event ID 1: `xcopy.exe` targeting `%APPDATA%\...` | `A06` |
| **Socket Exfil** | `IT-ADMIN01` (`PowerShell`)| Event ID 4104: ScriptBlock `.NET System.Net.Sockets.TcpClient` | `A07` |
| **Tool Ingress** | `IT-ADMIN01` (`Sysmon`) | Event ID 1: `certutil.exe -urlcache -split -f` | `A08` |
| **Reverse Tunnel** | `Zeek` / `Sysmon` | Event ID 3 socket binding to destination port 11601 | `A09` |
| **Lateral Pivot** | `Suricata IPS` / `auth.log`| SSH session initiated from `10.10.35.18` to `10.10.34.13` | `A10` |
| **Container Scraping**| `WEB01` (`Linux Auditd`) | `SYSCALL execve` / `docker exec` privilege inspection | `A11` |
| **Database Dump** | `DB01` (`MariaDB Audit`) | `SERVER_AUDIT` query log: `SELECT * FROM crm.customers` | `A12` |
| **DMZ Exfiltration** | `Suricata IPS` | IPS SID 1101021 alert: outbound TCP transfer on port 9999 | `A13` |

---

## 5. Evidence Artifacts Captured in Recording

The recording captures empirical terminal displays, tool responses, and network captures:
1. **Adversary Terminal (`Kali: 203.0.113.25`)**:
   * Execution of Python SMTP delivery script.
   * Netcat listener receiving inbound reverse shell connection from `10.10.35.18`.
   * Interactive discovery commands and command responses.
   * Receipt of staged browser archive and password decryption output.
   * `ligolo-ng` proxy interface establishment.
   * Sudo container commands and database extraction output.
2. **Victim Endpoints**:
   * Windows File Explorer on `IT-ADMIN01` showing ZIP extraction and payload launch.
   * Task Manager / Process Hacker showing hidden background `powershell.exe` execution.
   * Linux terminal on `WEB01` showing active SSH login from internal workstation.
3. **Perimeter Network Activity**:
   * Live packet capture showing cross-zone routing through `pfSense` (`10.10.36.10`) and `Suricata` (`10.10.36.11`).

---

## 6. Pre-Upload Sanitization Verification

Prior to public viewing, this video must be verified against [`VIDEO_SANITIZATION_CHECKLIST.md`](file:///e:/project_ca_nhan/lab_cty/media/VIDEO_SANITIZATION_CHECKLIST.md):
* [x] **Network IPAM**: Verified all displayed IP addresses conform strictly to public-safe RFC 1918 / RFC 5737 values (`203.0.113.25`, `10.10.34.0/24`, `10.10.35.0/24`, `10.10.36.0/24`). Zero original lab IPs exposed.
* [x] **Hostnames & Domains**: Verified enterprise domain appears as `soclab.test` and Kali threat host as `update.kali.test`.
* [x] **PII & Credentials**: Verified all user accounts are standardized (`user01`, `admin`, `thanh`). All demo passwords adhere to synthetic patterns (`P@ssw0rd2024!_DEMO`).
* [x] **Host OS Environment**: Verified zero host desktop background, personal browser bookmarks, or local file explorer tabs visible in screen recording frame.
