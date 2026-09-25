# Case 002 — Chronological Timeline Reconstruction

This document details the precise timeline of host and service reconnaissance commands executed on workstation `IT-ADMIN01` (`10.10.35.18`). All timestamps are indexed relative to $T_0$ (Case 001 reverse shell establishment).

---

## 1. Chronological Timeline Table

| Relative Time | Source Subsystem | Event / Detection ID | Observed Telemetry Evidence (Facts Only) | Analytical Interpretation |
| :--- | :--- | :--- | :--- | :--- |
| **$T_0 + 2\text{m } 45\text{s}$** | `IT-ADMIN01` Sysmon | Event ID 1 | `where.exe ssh`, Parent: `powershell.exe` (`ProcessGuid={ecec360d-d720-6aab-3600-000000001800}`). | Attacker tests whether OpenSSH client binary is installed on the system. |
| **$T_0 + 2\text{m } 58\text{s}$** | `IT-ADMIN01` Sysmon | Event ID 1 | `sc.exe query sshd`, Parent: `powershell.exe`. | Attacker checks whether local OpenSSH server daemon is registered or active. |
| **$T_0 + 3\text{m } 06\text{s}$** | `IT-ADMIN01` Sysmon | Event ID 1 | `sc.exe query termservice`, Parent: `powershell.exe`. | Attacker checks status of Remote Desktop Services daemon. |
| **$T_0 + 3\text{m } 15\text{s}$** | `ARCSIGHT-ESM` | `A05` | ArcSight ESM Alert: `SOC-LAB A05 Post-Compromise Discovery Burst` fires (3 events within 5 minutes). | ESM detection engine correlates the 3rd reconnaissance command within the sliding window. |
| **$T_0 + 3\text{m } 18\text{s}$** | `IT-ADMIN01` Sysmon | Event ID 1 | `qwinsta.exe`, Parent: `powershell.exe`. | Attacker enumerates active console and RDP user sessions. |
| **$T_0 + 3\text{m } 30\text{s}$** | `IT-ADMIN01` Sysmon | Event ID 1 | `netstat.exe -an`, Parent: `powershell.exe`. | Attacker dumps all active network sockets, established connections, and listening ports. |
| **$T_0 + 4\text{m } 10\text{s}$** | `IT-ADMIN01` Sysmon | Event ID 1 | `cmd.exe /c type C:\Users\admin\.ssh\config`, Parent: `powershell.exe`. | Attacker reads client SSH configuration, discovering target DMZ server `10.10.34.13` and user `thanh`. |

---

## 2. Chronological Analysis
* **Command Inter-Arrival Times**: Commands arrived with intervals of 13s, 8s, 12s, 12s, and 40s. This pattern represents interactive manual command entry by an operator rather than an automated discovery script.
* **Window Duration**: The initial 3 commands spanned 30 seconds, effortlessly crossing the `A05` rule threshold ($\ge 3$ commands in 5 minutes).
