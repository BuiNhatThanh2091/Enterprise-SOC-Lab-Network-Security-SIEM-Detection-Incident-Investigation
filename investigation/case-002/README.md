# Case 002 — Post-Compromise Host Discovery Investigation

## 1. Case Summary
Following the establishment of the reverse shell foothold documented in Case 001, the Security Operations Center (SOC) detected a burst of host enumeration commands on workstation `IT-ADMIN01` (`10.10.35.18`). ArcSight ESM triggered a Medium-High (Severity 6) alert, `SOC-LAB A05 Post-Compromise Discovery Burst`, when the adversary executed multiple native reconnaissance utilities in rapid succession over the active command-and-control (C2) channel.

Tier-2 SOC analysts investigated the alert on ArcSight Logger, analyzing Microsoft Sysmon Event ID 1 telemetry. The investigation proved that an interactive human operator was systematically surveying the workstation's administrative software stack (OpenSSH, Remote Desktop Services) and active network listening ports. This case highlights both the efficacy of process command-line auditing and the critical engineering limitations inherent in frequency-based sliding window detection rules.

---

## 2. Investigation Objective
1. Validate whether the discovery commands observed under rule `A05` originated from a legitimate administrator, automated software inventory, or the rogue reverse shell identified in Case 001.
2. Reconstruct the exact sequence, timing, and parameters of all enumeration commands executed on `IT-ADMIN01`.
3. Assess what intelligence the adversary obtained regarding internal network topology, services, and administrative access pathways.
4. Evaluate the technical maturity and evasion susceptibility of frequency-based threshold detection rules ($\ge 3\text{ commands} / 5\text{ minutes}$).

---

## 3. Initial Alert
* **Alert Trigger**: `SOC-LAB A05 Post-Compromise Discovery Burst`
* **Detection Engine**: ArcSight ESM Real-Time Rules Engine
* **Severity**: `6 / 10 (Medium-High)`
* **Timestamp**: $T_0 + 3\text{m } 15\text{s}$ (Relative to Case 001 Foothold)
* **Affected Asset**: `10.10.35.18` (`IT-ADMIN01`, Internal Network)
* **Detection Threshold**: $\ge 3$ matching discovery commands executed within a sliding window of $5\text{ minutes}$.

---

## 4. Initial Evidence
ArcSight ESM matched three consecutive process execution events on `IT-ADMIN01` within a 45-second window:
1. `where.exe ssh` (System Service / Binary Discovery)
2. `sc.exe query sshd` (System Service Discovery)
3. `netstat.exe -an` (Network Connections Discovery)

All events originated under user context `IT-ADMIN\admin` on host `IT-ADMIN01`.

---

## 5. Investigation Hypotheses

| Hypothesis ID | Formulation | Validation Status | Evidence Base |
| :--- | :--- | :---: | :--- |
| **H1** | The discovery commands originated from the malicious reverse shell established in Case 001. | **SUPPORTED** | Sysmon Event ID 1 confirms `ParentProcessGuid` matches the rogue `powershell.exe` from Case 001. |
| **H2** | The commands represent an automated discovery script rather than a live human operator. | **NOT SUPPORTED** | Irregular inter-command delays (8s, 14s, 22s) and adaptive command choices indicate manual human interaction. |
| **H3** | The adversary identified local administrative credentials or private keys during reconnaissance. | **PARTIALLY SUPPORTED** | Attacker located `~/.ssh/config` pointing to `WEB01` (`10.10.34.13`), but private key was passphrase-protected. |
| **H4** | A low-and-slow reconnaissance sequence would have triggered the same detection rule `A05`. | **NOT SUPPORTED** | Detection `A05` strictly requires $\ge 3$ events within 5 minutes; spacing commands 3 minutes apart evades the rule. |

---

## 6. Investigation Method
1. **ESM Trigger Analysis**: Extract matching event IDs from the `A05` alert and identify the common parent process.
2. **Process Lineage Verification**: Query Sysmon Event ID 1 on ArcSight Logger using `ParentProcessGuid` to confirm causal connection with the C2 reverse shell (`powershell.exe`).
3. **Chronological Command Sequence Reconstruction**: Expand the Logger query across a 15-minute window surrounding the alert to capture the full scope of commands executed under the session.
4. **Attacker Intent & Scope Deduction**: Categorize executed commands by MITRE ATT&CK Discovery sub-techniques to determine what infrastructure the adversary was targeting.

---

## 7. Evidence Pivot 1: Parent Process Correlation
* **Objective**: Confirm whether the commands were typed locally on the console or injected via the remote reverse shell.
* **Logger Query**:
  ```text
  deviceProduct="Microsoft-Windows-Sysmon" AND destinationProcessName="C:\\Windows\\System32\\where.exe" AND deviceHostName="IT-ADMIN"
  ```
* **Observed Artifacts**:
  * Sysmon Event ID 1: `C:\Windows\System32\where.exe ssh`
  * Process Identifier: `ProcessGuid = {ecec360d-d7a0-6aab-4100-000000001800}`
  * Parent Process Identifier: `ParentProcessGuid = {ecec360d-d720-6aab-3600-000000001800}`
* **Cross-Reference with Case 001**:
  `{ecec360d-d720-6aab-3600-000000001800}` is the exact `ProcessGuid` of the hidden `powershell.exe` reverse shell process connected to `203.0.113.25:4444`.
* **Analytic Conclusion**: The reconnaissance activity was executed directly over the interactive C2 channel by the external adversary.

---

## 8. Evidence Pivot 2: Full Command Sequence Reconstruction
* **Objective**: Extract all processes spawned by the malicious PowerShell parent process during the session.
* **Logger Query**:
  ```text
  deviceProduct="Microsoft-Windows-Sysmon" AND externalId=1 AND message CONTAINS "{ecec360d-d720-6aab-3600-000000001800}"
  ```
* **Results (Ordered Chronologically)**:
  1. `$T_0 + 2\text{m } 45\text{s}`: `where.exe ssh` (Checks if OpenSSH client binary is present).
  2. `$T_0 + 2\text{m } 58\text{s}`: `sc.exe query sshd` (Checks if OpenSSH server daemon is running).
  3. `$T_0 + 3\text{m } 06\text{s}`: `sc.exe query termservice` (Checks if Remote Desktop Services is active).
  4. `$T_0 + 3\text{m } 18\text{s}`: `qwinsta.exe` (Queries active user sessions and RDP sessions).
  5. `$T_0 + 3\text{m } 30\text{s}`: `netstat.exe -an` (Dumps active TCP listening ports and connections).
* **Analytic Conclusion**: The adversary engaged in deliberate, manual host reconnaissance. The commands specifically sought remote management services (SSH, RDP) to evaluate potential lateral movement vectors.

---

## 9. Evidence Pivot 3: Target Identification & SSH Configuration Inspection
* **Objective**: Determine what local configuration files were accessed following the command burst.
* **Logger Query**:
  ```text
  deviceProduct="Microsoft-Windows-Sysmon" AND externalId=1 AND deviceHostName="IT-ADMIN" AND (deviceCustomString4 CONTAINS ".ssh" OR deviceCustomString4 CONTAINS "config")
  ```
* **Observed Telemetry**:
  At `$T_0 + 4\text{m } 10\text{s}`, Sysmon Event ID 1 recorded PowerShell executing:
  ```powershell
  cmd.exe /c type C:\Users\admin\.ssh\config
  ```
* **Interpretation**:
  The attacker inspected the local SSH client configuration, discovering an entry for host `WEB01`:
  * HostName: `10.10.34.13` (Web server in DMZ)
  * User: `thanh`
  * IdentityFile: `~/.ssh/id_ed25519.web35`
* **Analytic Conclusion**: The adversary uncovered the internal IP of the DMZ web server (`10.10.34.13`) and an administrative username (`thanh`). However, the private key `id_ed25519.web35` was protected with a passphrase, forcing the attacker to seek alternative credential sources (investigated in Case 003).

---

## 10. Timeline of Reconnaissance Events

```text
[T0 + 2m 45s]  SYSMON: where.exe ssh executed via reverse shell parent powershell.exe.
[T0 + 2m 58s]  SYSMON: sc.exe query sshd executed (querying OpenSSH daemon status).
[T0 + 3m 06s]  SYSMON: sc.exe query termservice executed (querying RDP service state).
[T0 + 3m 15s]  ESM: Rule A05 fires on 3rd discovery command, generating Medium-High alert.
[T0 + 3m 18s]  SYSMON: qwinsta.exe executed (enumerating active terminal sessions).
[T0 + 3m 30s]  SYSMON: netstat.exe -an executed (enumerating listening ports and active sockets).
[T0 + 4m 10s]  SYSMON: type C:\Users\admin\.ssh\config executed (extracting web server IP 10.10.34.13).
```

---

## 11. Reconstructed Attack Chain
```text
1. Active C2 Foothold      ──► PowerShell interactive socket on TCP/4444 (Case 001)
2. Tooling Reconnaissance  ──► where.exe ssh (T1082: System Information Discovery)
3. Service Enumeration     ──► sc.exe query sshd & termservice (T1007: System Service Discovery)
4. Session Enumeration     ──► qwinsta.exe (T1033: System Owner/User Discovery)
5. Network Mapping         ──► netstat.exe -an (T1049: System Network Connections Discovery)
6. Target Identification   ──► type .ssh\config ──► Target Identified: WEB01 (10.10.34.13)
```

---

## 12. Detection Coverage Analysis

| Detection ID | Fired? | Evidence Found | Operational Role in Investigation | Known Detection Limitations |
| :--- | :---: | :--- | :--- | :--- |
| **A05** | **YES** | 5 Sysmon Event ID 1 commands matching discovery regex. | Primary Alert Trigger: Signals rapid host discovery. | Threshold-dependent ($\ge 3$ cmds in 5m); evaded by pacing execution. |
| **A04** | **YES** | Continuous Zeek session on TCP/4444. | Contextual Carrier: Confirms reverse shell transport. | Alert volume flood requires Active Channel filtering. |

---

## 13. Detection Gaps & Blind Spots
1. **Temporal Evasion in Threshold Rules**: Rule `A05` relies on a frequency threshold of 3 events in 5 minutes. If an adversary introduces an artificial delay (e.g., executing one discovery command every 3 minutes), the sliding window expires between executions and the rule fails to trigger entirely.
2. **Command Alias Obfuscation**: The rule regex targets standard process names (`where.exe`, `netstat.exe`, `sc.exe`). If the attacker utilizes native PowerShell cmdlets (e.g., `Get-Service`, `Get-NetTCPConnection`) rather than invoking standalone executables, traditional process-creation detection without ScriptBlock inspection will miss the activity.

---

## 14. Impact Assessment
* **Confidentiality**: **MEDIUM-HIGH RISK**. Attacker mapped internal administrative services and identified target DMZ host `WEB01` (`10.10.34.13`) and username `thanh`.
* **Integrity**: **STABLE**. No files or configurations were modified during this reconnaissance phase.
* **Availability**: **NORMAL**. Services unaffected.
* **Reconnaissance Yield**: The adversary established that `IT-ADMIN01` possesses legitimate network reachability to the DMZ web tier over SSH, setting the stage for subsequent lateral movement.

---

## 15. Containment & Remediation Actions
1. **Credential Isolation**: Audited permissions on `C:\Users\admin\.ssh\` and rotated the SSH private key `id_ed25519.web35`.
2. **Local Firewall Verification**: Confirmed that Windows Defender Firewall on `IT-ADMIN01` rejects inbound SSH and RDP connections from other internal workstations.
3. **Session Interruption**: The termination of the parent `powershell.exe` process (executed in Case 001) immediately severed the C2 channel, terminating ongoing interactive discovery.

---

## 16. Lessons Learned
1. **LOLBins for Reconnaissance**: Attackers rarely bring custom port scanners initially; they maximize native Windows utilities (`sc`, `netstat`, `where`, `qwinsta`) to remain inconspicuous.
2. **Threshold Limitations**: Frequency-based correlation rules provide vital tripwires against noisy automated scripts, but must never be relied upon as the sole defense against skilled human adversaries.

---

## 17. Detection Improvements
1. **Behavioral Discovery Grouping**: Expand rule `A05` logic to correlate native PowerShell cmdlets (`Get-Service`, `Get-Process`, `Get-NetTCPConnection`) captured via ScriptBlock Logging (Event ID 4104) alongside standalone executables.
2. **Parent Process Context Weighting**: Introduce an ESM correlation condition that lowers the threshold to **1 command** if the parent process is a non-standard shell spawned by an office application or living-off-the-land script proxy (`mshta.exe`, `rundll32.exe`).

---

## 18. Investigation Limitations
1. **Console Output Capture**: Sysmon Event ID 1 captures the command line executed, but does not capture stdout (the text output displayed back to the attacker). Analysts inferred what the attacker saw by replicating the commands on a sanitized test machine.

---

## 19. Final Assessment
Case 002 documents the rapid, manual reconnaissance conducted by the adversary immediately following initial access. Detection `A05` fired successfully due to the attacker's rapid command execution velocity. The investigation uncovered the adversary's tactical focus on SSH and RDP services, identifying the specific target host (`WEB01`) that would become the subject of lateral movement.

---

## 20. Evidence References
* **Primary Report**: `Báo cáo đề tài SOC.pdf`, Trang 80–82, 94–95, 126–128.
* **Architecture Runbook**: `toan-bo-he-thong-kien_truc_lab.txt`, Mục 51.
* **Logger Evidence Artifacts**: EV-04 (Discovery context), Sysmon Event ID 1 burst records.

---

## 21. Related Visual & Evidentiary Assets

### Architecture & Forensic Workflow Diagrams
* [**Enterprise SOC Overview Diagram**](file:///e:/project_ca_nhan/lab_cty/architecture/enterprise-soc-overview.svg): High-level system architecture and monitored endpoints.
* [**Telemetry Pipeline Flow Diagram**](file:///e:/project_ca_nhan/lab_cty/architecture/telemetry-flow.svg): Sysmon Event ID 1 event streaming into ArcSight SmartConnector.
* [**Investigation Workflow Diagram**](file:///e:/project_ca_nhan/lab_cty/architecture/investigation-workflow.svg): Standard Tier-1 to Tier-2 escalation and pivot methodologies.
* [**Case 002 Forensic Investigation Flowchart**](file:///e:/project_ca_nhan/lab_cty/investigation/case-002/investigation-flow.mmd): Sequence diagram of threshold evaluation and process grouping.

### Curated Evidence Manifests
* [**INV-003 Manifest**](file:///e:/project_ca_nhan/lab_cty/evidence/investigation/README.md#inv-003): Host reconnaissance command burst log on `IT-ADMIN01` (`whoami`, `ipconfig`, `net user`, `net localgroup`, `qwinsta`).
* [**TEL-001 Manifest**](file:///e:/project_ca_nhan/lab_cty/evidence/telemetry/README.md#tel-001): Microsoft Sysmon endpoint telemetry configuration and XML Process Create rule specifications.
* [**Sanitized Logger Search Evidence**](file:///e:/project_ca_nhan/lab_cty/evidence/sanitized/README.md#sanitized-evidence-card-arcsight-logger-search-query-for-discovery-commands): Sanitized query view and parsed CEF table for `A05` threshold evaluation.

### Demonstration & Investigation Videos
* [**VIDEO-01: Attack Simulation Walkthrough**](file:///e:/project_ca_nhan/lab_cty/media/attack-simulation/VIDEO-01.md): Red-team execution of rapid discovery commands and credential staging.
* [**VIDEO-02: Full Incident Investigation Walkthrough**](file:///e:/project_ca_nhan/lab_cty/media/investigation/VIDEO-02-FULL.md): Primary screen recording of sliding window threshold evaluation and ParentProcessGuid grouping.
* [**VIDEO-03: Supplementary Investigation Walkthrough**](file:///e:/project_ca_nhan/lab_cty/media/investigation/VIDEO-03-SUPPLEMENT.md): Technical deep-dive on low-level telemetry and secondary investigation pivots.

---

## 22. Video Demonstration

* **Hosting:** YouTube  
* **Visibility:** Unlisted  
* **Status:** Pending Upload  
* **URL:** `YOUTUBE_URL_PENDING`  
* **Demonstration Documents:**
  * Primary Walkthrough: [**`VIDEO-02-FULL.md`**](file:///e:/project_ca_nhan/lab_cty/media/investigation/VIDEO-02-FULL.md)
  * Deep Forensics Companion: [**`VIDEO-03-SUPPLEMENT.md`**](file:///e:/project_ca_nhan/lab_cty/media/investigation/VIDEO-03-SUPPLEMENT.md)

Under the unified laboratory incident workflow, this case study's triage is demonstrated within **Video 02** (Full Incident Investigation Walkthrough), focusing on the evaluation of sliding-window threshold rule `A05`, `ParentProcessGuid` grouping on `IT-ADMIN01`, and the command sequence reconstruction.


