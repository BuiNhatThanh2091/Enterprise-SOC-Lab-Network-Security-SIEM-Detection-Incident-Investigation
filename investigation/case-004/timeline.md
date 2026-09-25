# Case 004 — Chronological Timeline Reconstruction

This document reconstructs the minute-by-minute timeline of adversary pivoting, inter-zone SSH lateral movement, container credential scraping, and database dumping across `WEB01` (`10.10.34.13`) and `DB01` (`10.10.35.19`). All timestamps are indexed relative to $T_0$ (Case 001 reverse shell establishment).

---

## 1. Chronological Timeline Table

| Relative Time | Source Subsystem | Event / Detection ID | Observed Telemetry Evidence (Facts Only) | Analytical Interpretation |
| :--- | :--- | :--- | :--- | :--- |
| **$T_0 + 8\text{m } 45\text{s}$** | `IT-ADMIN01` Sysmon / Zeek | `A09` | `agent.exe` establishes TCP session to `203.0.113.25:11601` (`duration > 1200s`). | Ligolo-ng reverse tunnel activated, enabling external adversary to proxy traffic into the internal subnet. |
| **$T_0 + 9\text{m } 15\text{s}$** | `WEB01` Auth / Suricata | `A10` | `/var/log/auth.log`: `Accepted password for thanh from 10.10.35.18 port 48122 ssh2`. | Attacker uses stolen credentials for `thanh` to establish an interactive SSH session to `WEB01` via the tunnel. |
| **$T_0 + 10\text{m } 30\text{s}$** | `WEB01` Auditd | `A11` | Auditd (`-k web_exec`): `sudo docker exec -it hrms-backend-1 cat ... site_config.json`. | Attacker abuses passwordless sudo permissions on Docker to extract database credentials from container volume. |
| **$T_0 + 10\text{m } 55\text{s}$** | `DB01` iptables | Security Control | `DB01` kernel: `IPTABLES-DROP: IN=ens192 SRC=10.10.35.18 DST=10.10.35.19 DPT=3306`. | Attacker attempts direct connection from workstation to database; successfully blocked by host-based firewall. |
| **$T_0 + 11\text{m } 20\text{s}$** | `WEB01` Shell | Bash History | `nc -vz 10.10.35.19 3306` returns open connection. | Attacker verifies database port 3306 is reachable from the whitelisted DMZ web server. |
| **$T_0 + 11\text{m } 45\text{s}$** | `DB01` MariaDB Audit | `A12` | MariaDB Audit: User `_6f9beb897020ebe5` from `10.10.34.13` executes `SHOW DATABASES` & `INFORMATION_SCHEMA.FILES`. | Rule A12 fires on threshold ($\ge 2$ schema dump queries in 5m); `mysqldump` begins table export. |
| **$T_0 + 11\text{m } 58\text{s}$** | `WEB01` Filesystem | File Artifact | `/tmp/_6f9beb897020ebe5.sql.gz` written to disk with size 4.1 MB. | Complete employee table (`tabEmployee`) compressed and staged on `WEB01` filesystem. |

---

## 2. Chronological Analysis
* **Lateral Traversal Time**: The adversary moved from establishing the tunnel ($T+8\text{m } 45\text{s}$) to SSH login ($T+9\text{m } 15\text{s}$) in **30 seconds**.
* **Credential Scraping to DB Dump**: The elapsed time from extracting container secrets ($T+10\text{m } 30\text{s}$) to dumping database tables ($T+11\text{m } 45\text{s}$) was **75 seconds**, demonstrating rapid target acquisition.
