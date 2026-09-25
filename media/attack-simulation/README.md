# Red Team Attack Simulation Video Catalog

This directory documents the technical metadata and behavioral walkthrough of the recorded **Red Team Attack Simulation Sessions** conducted during the laboratory exercise.

---

## 1. Official Simulation Video

The multi-stage adversary campaign is consolidated into **Video 01**, hosted externally on **YouTube as an Unlisted video**:

| Video ID | Title | MITRE ATT&CK Techniques | Producing Attack Host | Target Enterprise Assets | YouTube Status | Public-Safe Status |
| :--- | :--- | :--- | :--- | :--- | :---: | :---: |
| [**`VIDEO-01.md`**](file:///e:/project_ca_nhan/lab_cty/media/attack-simulation/VIDEO-01.md) | `[SOC Attack Simulation] Multi-Stage Adversary Intrusion & Detection Validation` | `T1566.002`, `T1218.005`, `T1059.001`, `T1071.001`, `T1082`, `T1555.003`, `T1105`, `T1572`, `T1021.004`, `T1552.001`, `T1213.006`, `T1048.003` | `203.0.113.25` (`Kali`) | `MAIL01` (`.14`), `IT-ADMIN01` (`.18`), `WEB01` (`.13`), `DB01` (`.19`) | `Pending Upload`<br/>`YOUTUBE_URL_PENDING` | `REVIEW_REQUIRED` |

---

## 2. Defensive Purpose of Simulation Recording

This recording is presented strictly to illustrate **observable attack behaviors and telemetry footprints**. It is not structured as an exploitation tutorial, but rather as an empirical baseline artifact demonstrating why specific detection rules (`A01`–`A13`, `C01`) fired in the SOC.

---

## 3. Intrusion Scope Covered in VIDEO-01

The single unified demonstration [`VIDEO-01.md`](file:///e:/project_ca_nhan/lab_cty/media/attack-simulation/VIDEO-01.md) captures all four stages of the intrusion campaign:
* **Stage 1 — Initial Access & Reverse Shell Execution**: Inbound spearphishing email delivery, Living-off-the-Land HTA execution, and reverse shell callback.
* **Stage 2 — Host Discovery & Credential Staging**: High-frequency host reconnaissance burst (`whoami`, `net user`), browser profile harvesting, and socket exfiltration.
* **Stage 3 — Tool Ingress & Inter-Zone Lateral Movement**: Reverse proxy tunnel establishment via `ligolo-agent.exe` and lateral SSH pivoting into DMZ `WEB01`.
* **Stage 4 — Container Scraping, Database Dump & DMZ Exfiltration**: Privileged container credential inspection, MariaDB table extraction, and Netcat socket exfiltration.
