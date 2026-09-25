# Case 003 — Detection Coverage & Engineering Analysis

This document evaluates detection performance, field mappings, and detection boundaries associated with the credential collection and tool staging phase in Case 003.

---

## 1. Detection Performance Matrix

| Detection ID | Rule Name | Fired? | Evidence Found | Operational Investigation Use | Known Engineering Limitations |
| :--- | :--- | :---: | :--- | :--- | :--- |
| **A06** | Credential Material Collection | **YES** | Sysmon Event ID 1: `xcopy.exe` copying `Firefox\Profiles` to `\Public\`. | Primary Alert Trigger: Warns SOC of browser credential theft. | Path specific (`Firefox\Profiles`); blind to Chromium/Edge profile paths unless rule expanded. |
| **A07** | Suspicious Data Staging / Raw Transfer | **YES** | PowerShell 4104 (`Compress-Archive`, `TcpClient`) + Zeek `conn.log` (port 9999). | Exfiltration Anchor: Identifies staging archive and confirms socket transmission to external IP. | Requires PowerShell ScriptBlock logging enabled via GPO; cannot inspect encrypted TLS transfers. |
| **A08** | Suspicious Tool Transfer or Execution | **YES** | PowerShell 4104 (`Invoke-WebRequest`) + Sysmon 1 (`agent.exe`). | Tool Ingress Pivot: Identifies deployment of reverse tunneling client (`agent.exe`). | Matches string `agent.exe` or download keywords; easily evaded if attacker renames binary to a benign system name. |

---

## 2. Engineering Evaluation & Detection Hardening
1. **The LOLBin Staging Paradox**: The adversary avoided dropping custom malware to collect credentials, relying instead on legitimate administrative executables (`xcopy.exe`) and native PowerShell cmdlets (`Compress-Archive`, `TcpClient`). Traditional antivirus engines ignore `xcopy.exe`. Detection was achieved solely through behavior-based process command-line auditing (Sysmon Event ID 1) and ScriptBlock logging (Event ID 4104).
2. **Defensive Hardening Strategy**:
   * Deploy Group Policy Software Restriction Policies (AppLocker) to block executable execution from `C:\Users\Public\*.exe`.
   * Enforce default-deny egress filtering on the perimeter firewall (`pfSense`), blocking direct outbound connections from internal client subnets to unapproved destination ports ($9999, 11601$).
