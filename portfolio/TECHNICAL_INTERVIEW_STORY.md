# Technical Interview Story & Model Q&A

This guide prepares you to discuss the **Enterprise SOC Lab** during technical interviews for SOC Analyst, Detection Engineer, Network Security, and SIEM engineering roles.

---

## 1. Interview Storytelling Versions

### 1.1. The 30-Second Elevator Pitch
> *"I designed, implemented, and empirically validated an enterprise-style security operations laboratory across five segmented network zones on VMware ESXi. Rather than deploying disconnected tools, I built an integrated defensive pipeline: routing inter-zone traffic through a Security Transit segment enforcing pfSense firewalling and Suricata inline IPS, normalizing heterogenous telemetry from Windows Sysmon, Linux Auditd, and MariaDB into CEF via ArcSight SmartConnector, and authoring 13 atomic detection rules and a composite correlation rule in ArcSight ESM. I then validated the environment through red-team attack simulations, conducting 5 forensic investigations to reconstruct timelines, trace process trees, and verify containment."*

---

### 1.2. The 2-Minute Technical Summary
> *"The core problem I wanted to tackle was understanding how perimeter network security, host telemetry, and SIEM correlation truly interact during an intrusion—especially where theoretical designs fail in practice.*
>
> *I designed a multi-zone architecture separating DMZ, Internal, Logging, and Management segments, enforcing all inter-zone traffic through an isolated Security Transit segment where pfSense handles stateful routing and Suricata operates inline via NFQUEUE for Layer-7 deep packet inspection. Simultaneously, Zeek extracts passive session metadata.*
>
> *To solve the visibility gap on the endpoint, I instrumented Sysmon with modular XML rules, enabled PowerShell ScriptBlock Logging, and deployed Linux Auditd to capture system calls. All logs stream to ArcSight SmartConnectors, which normalize fields into Common Event Format (CEF) and bifurcate the data: sending events to ArcSight Logger for immutable long-term storage and to ArcSight ESM for in-memory correlation.*
>
> *I engineered 13 atomic detection rules and a composite correlation rule (`C01`) that joins web downloads, LOLBin HTA executions, and outbound C2 callbacks within a 20-minute sliding window. To prove it works, I executed controlled attack simulations from Kali, generating 5 forensic case studies where I pivoted across process trees via `ProcessGuid`, correlated Zeek sessions with Sysmon sockets, and validated firewall containment."*

---

### 1.3. The 5-Minute Deep-Dive Technical Walkthrough

* **Step 1: Problem & Objective**: Security tools often operate in isolated silos where network alerts lack endpoint context and host logs lack network flow validation. My objective was to engineer an integrated, multi-layered defensive ecosystem to evaluate end-to-end detection and forensic pivoting.
* **Step 2: Architecture & Segmentation**: I segmented the physical ESXi hypervisor into 5 distinct broadcast domains: `EXTERNAL_NET` (`203.0.113.0/24`), `SECURITY_TRANSIT` (`10.10.36.0/24`), `DMZ_NET` (`10.10.34.0/24`), `INTERNAL_NET` (`10.10.35.0/24`), `LOGGING_NET` (`10.10.40.0/24`), and `MANAGEMENT_NET` (`10.10.21.0/24`).
* **Step 3: Network Security Controls**: pfSense acts as the perimeter router and firewall. By forcing all inter-zone communication through the Security Transit segment, traffic is subjected to inline Layer-7 inspection via Suricata before entering or leaving internal networks. To address the hardware reality that hosts on the same Layer-2 subnet switch directly without hitting the gateway, I deployed host-based `iptables` rules on `DB01` as a compensatory control.
* **Step 4: Telemetry Pipeline**: Disparate event sources generate high-fidelity logs: Windows Sysmon (Process Create & Network Connect), PowerShell ScriptBlock 4104 (de-obfuscated script payloads), Linux Auditd (`execve` syscalls and Docker executions), MariaDB Audit Plugin (SQL queries), Postfix (mail transport), and Zeek (`conn.log` session metadata).
* **Step 5: Centralized SIEM Normalization**: ArcSight SmartConnectors listen on dedicated ports (Generator IDs 2002–2009) to parse events into CEF, mapping critical correlation keys such as `deviceCustomString4` (`CommandLine`) and `deviceCustomString5` (`ProcessGuid`).
* **Step 6: Decoupled SIEM Architecture**: I decoupled SIEM operations between ArcSight Logger (storing immutable logs with SHA-256 integrity verification for ad-hoc searching) and ArcSight ESM (maintaining in-memory stateful tables for real-time alert correlation).
* **Step 7: Detection Engineering**: I developed 13 atomic rules (`A01`–`A13`) across MITRE ATT&CK tactics, plus composite rule `C01`, which correlates perimeter ingress (`A02`), host execution (`A03`), and network callback (`A04`) on matching entity IP within 20 minutes.
* **Step 8: Red Team Attack Simulation**: From Kali Linux (`203.0.113.25`), I simulated a multi-stage intrusion: spearphishing email $\rightarrow$ HTA execution $\rightarrow$ PowerShell reverse shell $\rightarrow$ host discovery burst $\rightarrow$ Chrome credential theft $\rightarrow$ Ligolo-ng proxy tunneling $\rightarrow$ SSH lateral movement $\rightarrow$ container command execution $\rightarrow$ MariaDB table dumping $\rightarrow$ Netcat staging exfiltration.
* **Step 9: Incident Investigation**: Rather than stopping at the alert, I executed 5 structured investigations. In Case 001, I triaged the `C01` alert, extracted the process lineage in Logger, linked Sysmon Event ID 3 to Zeek UID `C9xKa811`, and backtracked Postfix mail logs to identify the initial email lure.
* **Step 10: Technical Evidence**: Every claim is backed by indexed manifests, including raw parsed CEF logs, process GUID chains, and pfSense Filterlog drop records.
* **Step 11: Limitations & Hardening**: I documented operational trade-offs, such as same-L2 bypasses, threshold evasions on sliding windows, and scenario-dependent ports, implementing GPO hardening and iptables rules as remediations.

---

## 2. Interview Questions & Model Answers

### Category 1: Security Architecture

#### Q1: Why did you create an intermediate "Security Transit" segment instead of routing directly on pfSense?
* **Short Answer**: To enforce deterministic traffic paths, isolate Layer-7 deep packet inspection on Suricata from Layer-3/4 routing on pfSense, and guarantee that inter-zone packets cannot bypass inspection.
* **Technical Explanation**: Direct virtual switch routing between DMZ and Internal networks can allow misconfigurations where packets cross interfaces without full content inspection. By inserting `SECURITY_TRANSIT` (`10.10.36.0/24`) between pfSense (`.10`) and Suricata (`.11`), every cross-zone flow is routed through the Suricata inline bridge before reaching its destination gateway.
* **Evidence in Repository**: [`docs/03_NETWORK_ARCHITECTURE.md`](file:///e:/project_ca_nhan/lab_cty/docs/03_NETWORK_ARCHITECTURE.md), [`architecture/network-security-flow.svg`](file:///e:/project_ca_nhan/lab_cty/architecture/network-security-flow.svg).
* **Potential Follow-up**: *"What happens if Suricata crashes?"* $\rightarrow$ In Linux NFQUEUE inline mode, Suricata can be configured with `--fail-open` or `--fail-closed`. In our lab, it fails closed to prioritize security enforcement.

#### Q2: What happens to traffic between two hosts on the same Layer-2 subnet, and how did you address it?
* **Short Answer**: Intra-subnet packets switch directly across the virtual switch fabric via ARP and MAC addresses without hitting the default gateway, bypassing Suricata and pfSense completely. I addressed this by deploying host-based `iptables` on `DB01`.
* **Technical Explanation**: `IT-ADMIN01` (`10.10.35.18`) and `DB01` (`10.10.35.19`) share the `10.10.35.0/24` subnet. During lateral movement, direct connections switch at Layer 2. Because perimeter NIDS/IPS cannot see this traffic, host-based firewalls (iptables on `DB01` allowing MySQL only from `10.10.34.13`) and host-level audit plugins are mandatory compensatory controls.
* **Evidence in Repository**: [`architecture/network-security-flow.svg`](file:///e:/project_ca_nhan/lab_cty/architecture/network-security-flow.svg), [`evidence/architecture/README.md#arch-003`](file:///e:/project_ca_nhan/lab_cty/evidence/architecture/README.md#arch-003).

---

### Category 2: Telemetry & SIEM Engineering

#### Q3: Why decouple SIEM operations into ArcSight Logger and ArcSight ESM instead of running everything on one server?
* **Short Answer**: To separate memory-intensive, low-latency real-time correlation from high-volume disk I/O and heavy ad-hoc historical forensic queries.
* **Technical Explanation**: Monolithic SIEMs suffer severe event drops when analysts run complex multi-day regex queries while the system attempts to correlate live events. ArcSight ESM operates in-memory on active sliding windows ($\Delta t \le 20\text{m}$) for sub-second rule evaluation. ArcSight Logger ingests normalized CEF into an indexed, tamper-evident (SHA-256) disk archive, allowing deep investigative queries without impacting live triage.
* **Evidence in Repository**: [`docs/ENGINEERING_DECISIONS.md#decision-3`](file:///e:/project_ca_nhan/lab_cty/docs/ENGINEERING_DECISIONS.md), [`architecture/telemetry-flow.svg`](file:///e:/project_ca_nhan/lab_cty/architecture/telemetry-flow.svg).

#### Q4: Why deploy both Suricata and Zeek across the same transit link?
* **Short Answer**: They serve complementary roles: Suricata provides deterministic signature matching and inline payload blocking, while Zeek provides stateful protocol analysis and behavioral session metadata.
* **Technical Explanation**: Suricata excels at catching specific threats (e.g., HTTP payload matching SID 1101002 in rule `A02`). Zeek converts packet streams into structured connection records (`conn.log`), extracting session duration, byte volumetrics (`orig_bytes`, `resp_bytes`), and unique `ZeekUID` keys, allowing us to confirm persistent C2 sessions (Rule `A04`) where no signature exists.
* **Evidence in Repository**: [`docs/ENGINEERING_DECISIONS.md#decision-4`](file:///e:/project_ca_nhan/lab_cty/docs/ENGINEERING_DECISIONS.md), [`docs/05_TELEMETRY_ARCHITECTURE.md`](file:///e:/project_ca_nhan/lab_cty/docs/05_TELEMETRY_ARCHITECTURE.md).

---

### Category 3: Detection Engineering

#### Q5: How does composite correlation rule `C01` work, and why is it superior to isolated atomic alerts?
* **Short Answer**: `C01` is an in-memory stateful join requiring three distinct events—web download (`A02`), script execution (`A03`), and network callback (`A04`)—to fire on the same destination IP within 20 minutes, dramatically reducing false positives.
* **Technical Explanation**: An isolated download alert (`A02`) might be benign or quarantined. A script launch (`A03`) might be administrative. A non-standard TCP connection (`A04`) could be a service check. When ESM correlates all three sharing `destinationAddress = 10.10.35.18` within $\Delta t \le 20\text{m}$, the confidence elevates to a confirmed Critical P1 breach.
* **Evidence in Repository**: [`detection/C01/README.md`](file:///e:/project_ca_nhan/lab_cty/detection/C01/README.md), [`evidence/detection/README.md#det-004`](file:///e:/project_ca_nhan/lab_cty/evidence/detection/README.md#det-004).

#### Q6: How did you handle alert fatigue caused by persistent reverse shells in rule `A04`?
* **Short Answer**: I tuned the ArcSight ESM Active Channel triage view by applying a display filter (`Name != A04*`) on the main monitoring dashboard while preserving the underlying event in Logger and ESM correlation tables.
* **Technical Explanation**: An interactive TCP reverse shell continuously emits connection state updates on Zeek and Sysmon, flooding the console with duplicate `A04` alerts. Filtering the display view allows analysts to focus on new incident signals while composite rule `C01` continues evaluating `A04` events in memory.
* **Evidence in Repository**: [`investigation/case-001/README.md#17-detection-improvements`](file:///e:/project_ca_nhan/lab_cty/investigation/case-001/README.md).

---

### Category 4: Incident Investigation & Response

#### Q7: When investigating Case 001, how did you trace the initial execution if the process PID was already terminated?
* **Short Answer**: By tracking immutable Sysmon `ProcessGuid` values instead of ephemeral Windows Process IDs (PIDs).
* **Technical Explanation**: Windows routinely recycles PIDs. When `mshta.exe` launched and terminated, querying by PID yields false linkages. Sysmon generates a unique 128-bit `ProcessGuid` per execution. By copying `{ecec360d-d71c-6aab-3400-000000001800}` from the `A03` alert, I queried Logger for all child processes where `ParentProcessGuid` matched, revealing the execution of `cmd.exe /c` and subsequent hidden `powershell.exe`.
* **Evidence in Repository**: [`investigation/case-001/README.md#7-evidence-pivot-1`](file:///e:/project_ca_nhan/lab_cty/investigation/case-001/README.md), [`evidence/investigation/README.md#inv-002`](file:///e:/project_ca_nhan/lab_cty/evidence/investigation/README.md#inv-002).

#### Q8: How did you identify the initial spearphishing delivery vector if the user only downloaded the file via HTTP?
* **Short Answer**: I pivoted from the download timestamp on Suricata to Postfix mail server delivery logs on `MAIL01`.
* **Technical Explanation**: The Suricata alert recorded an HTTP GET for `SecurityPatch_KB504991.zip` at $T_0 - 2\text{m}$. Knowing user behavior typically follows email links, I established a search window on ArcSight Logger querying Postfix logs (`deviceProduct="Postfix"`) for recipient `user01@soclab.test`. Logger identified QueueID `718FC8006A` delivered 6 minutes prior from `security@microsoft.com` with subject `"URGENT: Critical Security Update"`.
* **Evidence in Repository**: [`investigation/case-001/README.md#9-evidence-pivot-3`](file:///e:/project_ca_nhan/lab_cty/investigation/case-001/README.md), [`evidence/investigation/README.md#inv-001`](file:///e:/project_ca_nhan/lab_cty/evidence/investigation/README.md#inv-001).

---

### Category 5: Operational Limitations & Honesty

#### Q9: What are the primary detection limitations of your laboratory?
* **Short Answer**: Same-L2 broadcast bypasses, threshold evasion on sliding windows, and scenario-dependent port rules (`A04`, `A09`, `A13`).
* **Technical Explanation**:
  1. *Same-L2 Traffic*: Inter-host traffic on the same subnet bypasses gateway inspection.
  2. *Threshold Evasion*: Rule `A05` detects $\ge 3$ commands in 5 minutes; an attacker spacing commands every 3 minutes avoids the rule.
  3. *Scenario Ports*: Detections `A04` (port 4444) and `A13` (port 9999) evaluate specific test ports rather than generalized protocol entropy or behavioral anomalies.
  4. *Encrypted Traffic*: In cleartext HTTP, Suricata inspected archive payloads, but without SSL/TLS inspection, HTTPS payloads remain opaque.
* **Evidence in Repository**: [`docs/08_DETECTION_LIMITATIONS.md`](file:///e:/project_ca_nhan/lab_cty/docs/08_DETECTION_LIMITATIONS.md), [`portfolio/PROJECT_LIMITATIONS.md`](file:///e:/project_ca_nhan/lab_cty/portfolio/PROJECT_LIMITATIONS.md).
