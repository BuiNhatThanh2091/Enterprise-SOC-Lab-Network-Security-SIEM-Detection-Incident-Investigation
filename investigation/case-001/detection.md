# Case 001 — Detection Coverage & Engineering Analysis

This document evaluates the operational performance, evidentiary yield, and defensive limitations of each detection rule involved in the investigation of Case 001.

---

## 1. Detection Performance Matrix

| Detection ID | Rule Name | Fired? | Evidence Found | Operational Investigation Use | Known Engineering Limitations |
| :--- | :--- | :---: | :--- | :--- | :--- |
| **A01** | Mail Delivered to Internal User | **YES** | Postfix log: `QueueID=718FC8006A`, sender `security@microsoft.com`, recipient `user01@soclab.test`. | Backtracking anchor: Identifies phishing delivery vector and establishes entry timestamp. | Baseline contextual rule only; cannot analyze email body or determine whether attachment is malicious. |
| **A02** | Suspicious External Web Download | **YES** | Suricata alert: SID `1101002`, HTTP GET `SecurityPatch_KB504991.zip` from `203.0.113.25`. | Initial ingress anchor: Identifies download URL, external threat server IP, and archive filename. | Relies on cleartext HTTP and specific signature SID; blind to TLS-encrypted HTTPS downloads without SSL inspection. |
| **A03** | Suspicious Script Execution | **YES** | Sysmon Event ID 1: `mshta.exe` executing `.hta` file from Downloads folder. | Host execution anchor: Captures `ProcessGuid` and reveals child process lineage (`cmd.exe` $\rightarrow$ `powershell.exe`). | Dependent on host Sysmon agent health; can be bypassed if adversary executes raw shellcode via unmonitored binaries. |
| **A04** | Suspicious Outbound Callback | **YES** | Zeek `conn.log` + Sysmon Event ID 3: Persistent TCP session on port `4444`. | C2 callback anchor: Confirms active bidirectional communication between host and attacker. | Generates massive repetitive alert volume during long-lived sessions; requires active channel triage filtering. |
| **C01** | Initial Compromise Correlation | **YES** | ESM Correlated Event (Severity 9): Multi-source join (`A02` + `A03` + `A04`) on `10.10.35.18`. | Primary Incident Trigger: Elevates priority to Critical (P1) and mobilizes emergency response. | Fixed 20-minute sliding window; will fail to join events if adversary introduces a deliberate sleep delay $> 20\text{m}$. |

---

## 2. Detection Gap & Engineering Takeaways
1. **Correlation Resilience**: Composite rule `C01` successfully eliminated single-event false positives. An isolated download (`A02`) or an administrative script (`A03`) does not trigger a Critical incident; only the full causal progression from download to execution and external callback raises a P1 alert.
2. **Volume Suppression Requirement**: Rule `A04` (monitoring TCP/4444) generated over 2,000 repetitive event updates within 30 minutes due to persistent socket keep-alives. A triage filter (`Name != A04*`) was permanently integrated into the ESM Active Channel to protect analyst attention without disabling underlying event logging.
3. **Defense-in-Depth Validation**: The combination of network perimeter inspection (`Suricata`), network NDR session metadata (`Zeek`), and host kernel tracing (`Sysmon`) ensured that no single blind spot allowed the intrusion to proceed undetected.
