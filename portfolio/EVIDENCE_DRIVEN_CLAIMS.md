# Evidence-Driven Technical Claims Matrix

This document provides rigorous traceability between major technical claims and the concrete empirical evidence preserved within the repository.

Every claim is audited against the standardized evidence classification taxonomy:
* **`DIRECT`**: Immutable log entry, configuration file, or system artifact directly recording the action.
* **`CORRELATED`**: High-confidence finding confirmed through the temporal convergence of multiple independent data streams.
* **`CONTEXTUAL`**: Authoritative record establishing operational background or environmental facts.
* **`INFERRED`**: Logical deduction supported by strong circumstantial telemetry.

---

## 1. Master Claims Traceability Table

| Claim | Verified Technical Claim | Primary Evidence ID & Artifact | Repository Evidence Location | Evidence Classification | Verification Status |
| :--- | :--- | :--- | :--- | :---: | :---: |
| **CLM-01** | Multi-zone broadcast domain segmentation isolates DMZ, Internal, Transit, and Logging. | `ARCH-001`: vSwitch port group configurations and VLAN assignments. | [`evidence/architecture/README.md#arch-001`](file:///e:/project_ca_nhan/lab_cty/evidence/architecture/README.md#arch-001) | `DIRECT` | **`SUPPORTED`** |
| **CLM-02** | Perimeter firewall enforces stateful ingress/egress filtering and NAT. | `ARCH-002`: pfSense interface routing tables and Filterlog drop records. | [`evidence/architecture/README.md#arch-002`](file:///e:/project_ca_nhan/lab_cty/evidence/architecture/README.md#arch-002) | `DIRECT` | **`SUPPORTED`** |
| **CLM-03** | Suricata operates in inline IPS mode (NFQUEUE) on transit link to inspect Layer-7 HTTP payloads. | `DET-001`: Suricata SID 1101002 alert on HTTP payload archive download. | [`evidence/detection/README.md#det-001`](file:///e:/project_ca_nhan/lab_cty/evidence/detection/README.md#det-001) | `DIRECT` | **`SUPPORTED`** |
| **CLM-04** | Zeek passively monitors traffic, extracting session duration, byte volumetrics, and UID. | `DET-003`: Zeek `conn.log` session record (`ZeekUID = C9xKa811`) on port 4444. | [`evidence/detection/README.md#det-003`](file:///e:/project_ca_nhan/lab_cty/evidence/detection/README.md#det-003) | `DIRECT` | **`SUPPORTED`** |
| **CLM-05** | Sysmon captures kernel-level process creation, ProcessGuids, and command lines. | `TEL-001`, `INV-002`: Sysmon Event ID 1 recording `mshta.exe` spawning `powershell.exe`. | [`evidence/telemetry/README.md#tel-001`](file:///e:/project_ca_nhan/lab_cty/evidence/telemetry/README.md#tel-001) | `DIRECT` | **`SUPPORTED`** |
| **CLM-06** | PowerShell ScriptBlock logging de-obfuscates encoded stagers and captures raw socket scripts. | `TEL-002`, `INV-004`: PowerShell Event ID 4104 recording `.NET TcpClient` socket code. | [`evidence/telemetry/README.md#tel-002`](file:///e:/project_ca_nhan/lab_cty/evidence/telemetry/README.md#tel-002) | `DIRECT` | **`SUPPORTED`** |
| **CLM-07** | Linux Auditd captures system call executions (`execve`) inside Docker web containers. | `INV-006`: Linux Auditd log capturing `docker exec` command line invocations. | [`evidence/investigation/README.md#inv-006`](file:///e:/project_ca_nhan/lab_cty/evidence/investigation/README.md#inv-006) | `DIRECT` | **`SUPPORTED`** |
| **CLM-08** | MariaDB Audit Plugin logs relational table queries and schema extractions. | `TEL-004`, `INV-007`: MariaDB `SERVER_AUDIT` log showing table select queries on `DB01`. | [`evidence/telemetry/README.md#tel-004`](file:///e:/project_ca_nhan/lab_cty/evidence/telemetry/README.md#tel-004) | `DIRECT` | **`SUPPORTED`** |
| **CLM-09** | Disparate logs are collected and normalized into standardized CEF schemas via SmartConnectors. | `TEL-001`–`004`: Generator ID mappings (2002–2009) and CEF field keys. | [`evidence/telemetry/README.md`](file:///e:/project_ca_nhan/lab_cty/evidence/telemetry/README.md) | `DIRECT` | **`SUPPORTED`** |
| **CLM-10** | SIEM operations are decoupled between Logger (immutable storage) and ESM (real-time rules). | `docs/ENGINEERING_DECISIONS.md`: Architectural separation of Logger and ESM. | [`docs/ENGINEERING_DECISIONS.md`](file:///e:/project_ca_nhan/lab_cty/docs/ENGINEERING_DECISIONS.md) | `CONTEXTUAL` | **`SUPPORTED`** |
| **CLM-11** | ArcSight ESM evaluates 13 atomic rules (`A01`–`A13`) across multiple attack tactics. | `DET-001`–`005`, `detection/A01`–`A13`: Documented rule logic and firing conditions. | [`detection/README.md`](file:///e:/project_ca_nhan/lab_cty/detection/README.md) | `DIRECT` | **`SUPPORTED`** |
| **CLM-12** | ArcSight ESM executes multi-source composite correlation (`C01`) within a 20-minute window. | `DET-004`: Composite alert `C01` joining `A02` + `A03` + `A04` on matching destination IP. | [`evidence/detection/README.md#det-004`](file:///e:/project_ca_nhan/lab_cty/evidence/detection/README.md#det-004) | `CORRELATED` | **`SUPPORTED`** |
| **CLM-13** | Detection rules were empirically validated through live attack simulations. | `detection/VALIDATION_MATRIX.md`: Record of rule firings during Red Team simulation. | [`detection/VALIDATION_MATRIX.md`](file:///e:/project_ca_nhan/lab_cty/detection/VALIDATION_MATRIX.md) | `CORRELATED` | **`SUPPORTED`** |
| **CLM-14** | SOC investigations reconstruct multi-hop process trees using immutable `ProcessGuid` values. | `INV-002`: Logger query expanding `explorer.exe` $\rightarrow$ `mshta.exe` $\rightarrow$ `cmd.exe` $\rightarrow$ `powershell.exe`. | [`evidence/investigation/README.md#inv-002`](file:///e:/project_ca_nhan/lab_cty/evidence/investigation/README.md#inv-002) | `DIRECT` | **`SUPPORTED`** |
| **CLM-15** | Cross-source pivots link web downloads to antecedent Postfix mail delivery logs. | `INV-001`: Postfix delivery record for QueueID `718FC8006A` matching user01. | [`evidence/investigation/README.md#inv-001`](file:///e:/project_ca_nhan/lab_cty/evidence/investigation/README.md#inv-001) | `CORRELATED` | **`SUPPORTED`** |
| **CLM-16** | Cross-source pivots link endpoint network sockets to Zeek bidirectional flow metadata. | `INV-004`, `DET-003`: Sysmon Event 3 port 4444 correlated with ZeekUID `C9xKa811`. | [`evidence/detection/README.md#det-003`](file:///e:/project_ca_nhan/lab_cty/evidence/detection/README.md#det-003) | `CORRELATED` | **`SUPPORTED`** |
| **CLM-17** | End-to-end attack chains and unified timelines were reconstructed across 5 incident cases. | `investigation/case-001` to `case-005`: Chronological incident timelines ($T_0$). | [`investigation/README.md`](file:///e:/project_ca_nhan/lab_cty/investigation/README.md) | `CORRELATED` | **`SUPPORTED`** |
| **CLM-18** | Incident containment actions were verified via network drops and process termination logs. | `RESP-001`–`003`: Sysmon Event ID 5 process kills and pfSense Filterlog drop records. | [`evidence/EVIDENCE_INDEX.md`](file:///e:/project_ca_nhan/lab_cty/evidence/EVIDENCE_INDEX.md) | `DIRECT` | **`SUPPORTED`** |
| **CLM-19** | Same-L2 broadcast traffic between internal hosts bypasses perimeter gateway inspection. | `ARCH-003`, `network-security-flow.svg`: Analysis of ARP switching and compensatory iptables. | [`docs/03_NETWORK_ARCHITECTURE.md`](file:///e:/project_ca_nhan/lab_cty/docs/03_NETWORK_ARCHITECTURE.md) | `CONTEXTUAL` | **`SUPPORTED`** |
| **CLM-20** | Detection rules A04, A09, and A13 evaluate scenario-specific test ports rather than protocol anomalies. | `docs/08_DETECTION_LIMITATIONS.md`: Transparent documentation of port dependencies (4444, 11601, 9999). | [`docs/08_DETECTION_LIMITATIONS.md`](file:///e:/project_ca_nhan/lab_cty/docs/08_DETECTION_LIMITATIONS.md) | `CONTEXTUAL` | **`SUPPORTED`** |

---

## 2. Prohibited & Unsupported Claims Audit

The following theoretical claims are formally classified as **`UNSUPPORTED`** by laboratory evidence and are strictly excluded from all public portfolio documents:

| Prohibited Claim | Reason for Exclusion | Enforcement Action Taken |
| :--- | :--- | :--- |
| *"The system provides 100% detection coverage of all MITRE ATT&CK techniques."* | Only 13 atomic techniques and 1 correlation rule were deployed and tested. | Prohibited; replaced with specific coverage matrix (`A01`–`A13`). |
| *"Deployed commercial EDR / SOAR automation across all endpoints."* | No EDR agent or SOAR platform was installed or licensed in the laboratory. | Prohibited; telemetry accurately attributed to Sysmon, Auditd, and manual SOC containment. |
| *"Suricata inspects 100% of east-west internal network traffic."* | Intra-subnet Layer-2 traffic bypasses the transit gateway; host iptables required. | Documented as an explicit architecture limitation. |
| *"The environment represents a certified production enterprise SOC."* | System operated in a controlled hypervisor lab for research and evaluation. | Clearly designated as an "enterprise-style security laboratory". |
| *"Reduced organizational false positives by 90%."* | No longitudinal multi-month production metric exists in the Source of Truth. | Prohibited; no artificial percentages used anywhere in portfolio. |
