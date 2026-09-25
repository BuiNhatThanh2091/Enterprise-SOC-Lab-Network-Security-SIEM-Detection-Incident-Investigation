# Case 001 — Chronological Timeline Reconstruction

This document reconstructs the minute-by-minute timeline of the initial intrusion campaign targeting workstation `IT-ADMIN01` (`10.10.35.18`). All times are normalized relative to anchor $T_0$ (the timestamp when correlation rule `C01` triggered on ArcSight ESM).

---

## 1. Chronological Timeline Table

| Relative Time | Source Subsystem | Event / Detection ID | Observed Telemetry Evidence (Facts Only) | Analytical Interpretation |
| :--- | :--- | :--- | :--- | :--- |
| **$T_0 - 8\text{m } 00\text{s}$** | `MAIL01` Postfix | `A01` | Postfix syslog: `status=sent`, `queue_id=718FC8006A`, `from=<security@microsoft.com>`, `to=<user01@soclab.test>`. | External adversary transmits spearphishing lure to internal user with fake urgent patch advisory. |
| **$T_0 - 2\text{m } 30\text{s}$** | `SURICATA-IPS01` | `A02` | Suricata EVE JSON: SID `1101002`, HTTP GET `http://update.kali.test/SecurityPatch_KB504991.zip` from `203.0.113.25:80` to `10.10.35.18`. | User clicks phishing link in email; web browser downloads weaponized ZIP archive to local workstation. |
| **$T_0 - 1\text{m } 45\text{s}$** | `IT-ADMIN01` Sysmon | `A03` | Sysmon Event ID 1: Parent `explorer.exe` launches `C:\Windows\System32\mshta.exe "C:\Users\admin\Downloads\SecurityPatch_KB504991.hta"`. `ProcessGuid={ecec360d-d71c-6aab-3400-000000001800}`. | User manually extracts archive and executes the `.hta` script payload via Windows Explorer. |
| **$T_0 - 1\text{m } 40\text{s}$** | `IT-ADMIN01` Sysmon | — | Sysmon Event ID 1: `mshta.exe` launches `cmd.exe /c`, which spawns `powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -enc ...`. | Living-off-the-land script proxy execution; HTA unpacks and executes hidden base64 PowerShell stager. |
| **$T_0 - 1\text{m } 10\text{s}$** | `IT-ADMIN01` Sysmon | `A04` (Host) | Sysmon Event ID 3: `powershell.exe` (`ProcessGuid={ecec360d-d720-6aab-3600-000000001800}`) initiates TCP connection from `10.10.35.18:49211` to `203.0.113.25:4444`. | Malicious PowerShell payload initiates outbound network callback to external attacker listener. |
| **$T_0 - 1\text{m } 08\text{s}$** | `ZEEK-SENSOR01` | `A04` (Network) | Zeek `conn.log`: New TCP connection on port `4444`, `uid=C9xKa811`, `duration > 1800s`, continuous traffic (`orig_bytes > 0`). | Network session metadata confirms establishment of persistent interactive reverse shell. |
| **$T_0 - 0\text{m } 00\text{s}$** | `ARCSIGHT-ESM` | `C01` | ArcSight ESM Active Channel: Correlated Event `SOC-LAB C01 Initial Compromise Correlation` fires (Severity 9). | ESM in-memory correlation engine detects full attack sequence (`A02` + `A03` + `A04`) on host `10.10.35.18`. |
| **$T_0 + 2\text{m } 00\text{s}$** | SOC Analyst | Response | Analyst reviews Active Channel, verifies tri-party telemetry alignment, and flags confirmed intrusion. | Triage complete: Analyst confirms true positive breach and transitions case to emergency containment. |
| **$T_0 + 5\text{m } 00\text{s}$** | Infrastructure | Containment | Disconnected virtual network interface for `IT-ADMIN01`; pfSense firewall drops outbound port 4444. | Host network isolation successfully severs C2 channel; lateral movement vector frozen. |

---

## 2. Key Chronological Takeaways
1. **Intrusion Velocity**: Total elapsed time from user payload execution ($T_0 - 1\text{m } 45\text{s}$) to interactive C2 establishment ($T_0 - 1\text{m } 08\text{s}$) was only **37 seconds**.
2. **Detection Latency**: ArcSight ESM synthesized the correlation alert at exactly $T_0$, less than **70 seconds** after reverse shell callback initiation.
3. **Forensic Alignment**: The temporal delta ($\Delta t$) between ingress download (`A02`) and network callback (`A04`) was **82 seconds**, well within the 20-minute sliding window of rule `C01`.
