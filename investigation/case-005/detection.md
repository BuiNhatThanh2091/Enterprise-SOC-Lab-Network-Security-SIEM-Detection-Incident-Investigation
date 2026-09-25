# Case 005 — Detection Coverage & Engineering Analysis

This document evaluates the detection performance, query verification, and engineering boundaries associated with the data exfiltration and containment phase in Case 005.

---

## 1. Detection Performance Matrix

| Detection ID | Rule Name | Fired? | Evidence Found | Operational Investigation Use | Known Engineering Limitations |
| :--- | :--- | :---: | :--- | :--- | :--- |
| **A13** | Suspicious DMZ External Transfer | **YES** | Suricata IPS alert: SID `1101021`, TCP port `9999` from `10.10.34.13` to `203.0.113.25`. | Primary Alert Trigger: Warns SOC of active data exfiltration. | Strictly scenario-dependent on test port 9999; blind to TLS/HTTPS or DNS exfiltration. |
| **A12** | Suspicious Database Collection | **YES** | MariaDB audit logs (`mysqldump` context). | Contextual Antecedent: Confirms database origin of the staged archive. | Does not observe network transmission. |

---

## 2. Engineering Evaluation & Detection Hardening
1. **The Scenario-Dependency Caveat**:
   * Detection `A13` is an effective tripwire for the specific laboratory simulation, but **cannot be generalized** as an enterprise-wide Data Loss Prevention (DLP) mechanism.
   * If an adversary channels exfiltration through an encrypted HTTPS tunnel (`TCP/443`) or embeds data inside DNS queries (`TCP/UDP 53`), signature SID `1101021` will remain dormant.
2. **Recommended Defensive Architecture**:
   * **Mandatory Egress Filtering on DMZ**: Web servers must not possess arbitrary outbound access to the public Internet. Egress must be strictly restricted to internal DNS (`10.10.21.20`), NTP, and official software repositories via Forward Proxy (`10.10.25.252:8132`).
   * **Volumetric Flow Anomalies in ESM**: Create an ArcSight correlation rule monitoring Zeek `conn.log` sessions where `orig_bytes > 2,000,000` (2 MB) originating from DMZ subnets to external non-proxy destinations.
   * **Inline IPS Drop Mode**: Transition Suricata from `alert` mode to `drop` mode (NFQUEUE Fail-Close) for non-standard outbound ports.
