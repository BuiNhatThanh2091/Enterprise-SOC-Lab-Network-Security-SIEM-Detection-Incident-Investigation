# Case-to-Detection Matrix

This matrix establishes the operational relationship between each **Incident Investigation Case Study** and the baseline ruleset (`A01`–`A13`, `C01`) deployed in ArcSight ESM and Logger.

## 1. Classification Definitions
* **`PRIMARY`**: The central detection trigger or core evidentiary artifact investigated within the case study.
* **`SUPPORTING`**: Corroborating detection rules that validate the hypothesis or provide vital collateral evidence.
* **`CONTEXT`**: Informational rules or preceding baseline events that establish environmental anchors and chronological context.
* **`NOT USED`**: The detection rule was not part of the active investigative scope for that specific incident phase.

---

## 2. Cross-Reference Matrix

| Case ID & Title | A01 | A02 | A03 | A04 | A05 | A06 | A07 | A08 | A09 | A10 | A11 | A12 | A13 | C01 |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Case 001: Initial Compromise** | `CONTEXT` | `PRIMARY` | `PRIMARY` | `PRIMARY` | `NOT USED` | `NOT USED` | `NOT USED` | `NOT USED` | `NOT USED` | `NOT USED` | `NOT USED` | `NOT USED` | `NOT USED` | `PRIMARY` |
| **Case 002: Host Discovery Burst** | `NOT USED` | `NOT USED` | `CONTEXT` | `SUPPORTING` | `PRIMARY` | `NOT USED` | `NOT USED` | `NOT USED` | `NOT USED` | `NOT USED` | `NOT USED` | `NOT USED` | `NOT USED` | `CONTEXT` |
| **Case 003: Credential Harvesting & Staging** | `NOT USED` | `NOT USED` | `CONTEXT` | `SUPPORTING` | `CONTEXT` | `PRIMARY` | `PRIMARY` | `PRIMARY` | `NOT USED` | `NOT USED` | `NOT USED` | `NOT USED` | `NOT USED` | `NOT USED` |
| **Case 004: Lateral Movement & DB Dump** | `NOT USED` | `NOT USED` | `NOT USED` | `NOT USED` | `NOT USED` | `CONTEXT` | `NOT USED` | `SUPPORTING` | `PRIMARY` | `PRIMARY` | `PRIMARY` | `PRIMARY` | `NOT USED` | `NOT USED` |
| **Case 005: DMZ Exfiltration & Remediation** | `NOT USED` | `NOT USED` | `NOT USED` | `NOT USED` | `NOT USED` | `NOT USED` | `NOT USED` | `NOT USED` | `CONTEXT` | `CONTEXT` | `CONTEXT` | `SUPPORTING` | `PRIMARY` | `NOT USED` |

---

## 3. Analytical Insights
1. **Multi-Source Convergence (`Case 001`)**: Serves as the prime exemplar of ArcSight ESM correlation, uniting perimeter network (`A02`), endpoint execution (`A03`), and network session metadata (`A04`) into composite rule `C01`.
2. **Endpoint High-Fidelity Auditing (`Case 002` & `Case 003`)**: Demonstrates how endpoint instrumentation (Sysmon ID 1 & 3, PowerShell 4104) captures malicious behavior that is completely invisible to network security gateways (such as local directory enumeration and memory-safe archive staging).
3. **Cross-Zone Pivoting (`Case 004` & `Case 005`)**: Demonstrates multi-tier investigation, tracing adversary movement from Windows client through encrypted tunnels to Linux container hosts and backend relational database audit tables.
