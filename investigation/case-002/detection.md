# Case 002 — Detection Coverage & Engineering Analysis

This document evaluates the detection performance, query verification, and engineering limitations associated with the reconnaissance activity in Case 002.

---

## 1. Detection Performance Matrix

| Detection ID | Rule Name | Fired? | Evidence Found | Operational Investigation Use | Known Engineering Limitations |
| :--- | :--- | :---: | :--- | :--- | :--- |
| **A05** | Post-Compromise Discovery Burst | **YES** | 5 Sysmon Event ID 1 commands matching discovery regex (`where`, `sc`, `netstat`, `qwinsta`). | Primary Alert Trigger: Warns SOC of rapid post-compromise reconnaissance. | Sliding window threshold ($\ge 3$ cmds in 5m); easily bypassed if adversary introduces $\ge 3\text{-minute}$ delays. |
| **A04** | Suspicious Outbound Callback | **YES** | Zeek `conn.log` persistent TCP session `:4444`. | Transport Carrier: Confirms commands entered remotely via C2. | Session keep-alive noise requires active channel filtering. |

---

## 2. Engineering Evaluation of Sliding Window Thresholds
1. **The Temporal Vulnerability**: Rule `A05` relies on the mathematical condition `EventCount >= 3` within `TimeWindow = 5 minutes`. During the simulation, the adversary typed 3 commands within 30 seconds, immediately triggering ESM. However, an attacker aware of burst-based detections can throttle execution to 1 command every 3 minutes (e.g., `where ssh` at 00:00, `sc query` at 03:00, `netstat` at 06:00). In this scenario, the rule will reset its counter between events and **never fire**.
2. **Recommended Defensive Hardening**:
   * Implement **Stateful Active Lists** tracking reconnaissance commands executed by non-interactive shells over a 24-hour baseline.
   * Weight parent process identity: If parent is `powershell.exe` or `cmd.exe` spawned from `mshta.exe`, lower the threshold to **1 command**.
