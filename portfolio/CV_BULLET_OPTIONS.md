# Tailored CV Bullet Point Options

This catalog provides modular, high-impact bullet points structured under the formula:  
**`Action Verb + Specific Technical Work + Concrete Outcome / Evidence Base`**

Select 3 to 6 bullet points tailored to the specific job description you are targeting (SOC Analyst, Detection Engineer, Network Security, SIEM Engineer).

---

## 1. Security Architecture & Network Segmentation

* **Designed and deployed a 5-zone enterprise network architecture** on VMware ESXi, enforcing broadcast domain isolation across DMZ, Internal, Security Transit, and Logging segments.
* **Engineered a zero-bypass Security Transit choke point** (`10.10.36.0/24`), requiring all inter-zone packets between DMZ and Internal networks to undergo stateful filtering and content inspection.
* **Identified and mitigated Layer-2 switching blind spots** between co-located internal hosts (`IT-ADMIN01` and `DB01`) by deploying host-based `iptables` rules as compensatory controls.
* **Separated administrative and logging management planes** from production traffic using dedicated virtual switches and isolated out-of-band bastion jump hosts.

---

## 2. Network Security & Inline Inspection (pfSense & Suricata)

* **Configured pfSense stateful firewall policies and NAT rules**, restricting perimeter ingress to designated DMZ services and enforcing strict outbound port filtering.
* **Deployed Suricata in inline IPS mode using Linux NFQUEUE**, inspecting Layer-7 HTTP payloads and enforcing automated drop actions on malicious archive transfers.
* **Integrated Zeek (Bro) network security monitoring** in parallel with inline IPS to passively extract protocol metadata, session durations, and TCP stream metrics (`conn.log`).
* **Analyzed operational trade-offs between IPS alert and drop modes**, demonstrating in live simulation how alert-only configurations permit exfiltration to finish prior to manual response.

---

## 3. Host Telemetry & Sensor Instrumentation (Windows & Linux)

* **Instrumented Microsoft Sysmon with a modular XML configuration**, capturing high-fidelity process creations (Event ID 1), parent-child process lineages, and network connections (Event ID 3).
* **Enabled Windows PowerShell ScriptBlock Logging (Event ID 4104)** via Group Policy, capturing de-obfuscated script payloads executed via encoded living-off-the-land commands.
* **Configured Linux Auditd kernel auditing**, intercepting `execve` system calls to monitor privileged `sudo` executions and administrative commands inside Docker web containers.
* **Implemented database activity monitoring via MariaDB Audit Plugin (`SERVER_AUDIT`)**, logging structural SQL schema enumerations and unauthorized table extractions to syslog.
* **Configured Postfix and Dovecot mail logging**, extracting SMTP envelope sender, recipient, and Queue ID metadata for spearphishing delivery backtracking.

---

## 4. SIEM Pipeline, Normalization & Storage (ArcSight)

* **Engineered an end-to-end log collection pipeline using ArcSight SmartConnector**, parsing heterogenous event streams across 8 data sources into standardized Common Event Format (CEF).
* **Architecturally decoupled SIEM operations** between ArcSight Logger for immutable, tamper-evident long-term storage (SHA-256) and ArcSight ESM for real-time in-memory correlation.
* **Mapped custom application and host fields into standardized CEF schema keys** (`deviceCustomString4` for command lines, `deviceCustomString5` for ProcessGuids, `externalId` for event codes).
* **Optimized SIEM ingestion performance** by assigning dedicated SmartConnector listener ports and unique Generator IDs (2002–2009) to prevent cross-source parsing collisions.

---

## 5. Detection Engineering (`A01`–`A13` & `C01`)

* **Authored and validated 13 atomic detection rules (`A01`–`A13`)** covering initial access, living-off-the-land execution, host discovery bursts, credential staging, and data exfiltration.
* **Engineered a composite correlation rule (`C01`) in ArcSight ESM**, joining perimeter download (`A02`), host execution (`A03`), and network C2 callback (`A04`) on a common host within a 20-minute sliding window.
* **Implemented sliding-window threshold logic for discovery detection (`A05`)**, triggering alerts upon detecting $\ge 3$ diagnostic commands (`whoami`, `net user`, `qwinsta`) within 5 minutes.
* **Tuned ESM Active Channel triage filters**, suppressing persistent reverse shell updates on port 4444 to reduce console alert volume without blinding detection.
* **Documented technical detection boundaries**, identifying scenario-dependent test ports (4444, 11601, 9999) and recommending generic behavioral rule improvements.

---

## 6. Incident Investigation & Timeline Reconstruction

* **Investigated 5 multi-stage incident case studies**, moving from initial high-priority SIEM alerts through testable hypotheses, Logger deep searches, and containment validation.
* **Reconstructed complete parent-child process execution trees** on Windows endpoints using immutable Sysmon `ProcessGuid` values to trace `explorer.exe` $\rightarrow$ `mshta.exe` $\rightarrow$ `cmd.exe` $\rightarrow$ `powershell.exe`.
* **Correlated passive Zeek session logs with endpoint network connections**, proving that an outbound TCP port 4444 connection represented an interactive shell based on session longevity and byte transfer.
* **Pivoted from perimeter download alerts to Postfix mail gateway logs**, identifying the originating spearphishing lure by matching email delivery timestamps and recipient addresses.
* **Traced cross-zone lateral movement from an internal workstation to a DMZ server**, correlating Linux `auth.log` SSH root sessions with subsequent Docker container commands in Auditd.

---

## 7. Red Team Attack Simulation & Validation

* **Executed controlled multi-stage attack simulations from Kali Linux (`203.0.113.25`)**, validating detection rule triggers across spearphishing, script execution, tunneling, and exfiltration.
* **Simulated living-off-the-land execution techniques** using `mshta.exe` and encoded PowerShell to evaluate endpoint auditing and SIEM correlation fidelity.
* **Emulated post-exploitation tunneling via Ligolo-ng and raw socket exfiltration**, generating verifiable network and host telemetry footprints for Blue Team triage.
* **Harvested container configuration secrets and executed direct relational database table dumps**, verifying that host-level audit plugins capture data access independently of network inspection.

---

## 8. Incident Containment & System Hardening

* **Enacted closed-loop containment workflows**, validating host network isolation, terminating malicious PowerShell processes, and deploying dynamic pfSense firewall drop rules.
* **Hardened Windows endpoint configurations via Group Policy**, de-associating the `.hta` extension from `mshta.exe` to neutralize living-off-the-land execution vectors.
* **Enforced database access controls on `DB01` using host-level iptables**, restricting MySQL connections strictly to the authorized DMZ web server interface.
* **Audited and updated SIEM correlation windows**, proposing dual-window correlation strategies to counter delayed adversary beaconing.
