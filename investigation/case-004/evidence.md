# Case 004 — Evidentiary Artifacts Catalog

This catalog documents all forensic evidence items collected, normalized, and evaluated during the investigation of Case 004.

---

## 1. Structured Evidence Table

| Evidence ID | Producing Source | Detection / Event Class | Normalized Telemetry Observation | Evidence Classification | Supports Hypothesis |
| :--- | :--- | :--- | :--- | :---: | :---: |
| **E30** | `ZEEK-SENSOR01` / Sysmon | `A09` (Tunnel Metadata) | Persistent TCP session on `203.0.113.25:11601`, matching process `agent.exe` on `IT-ADMIN01`. | `DIRECT` | H1 |
| **E31** | `WEB01` (`auth.log`) | `A10` (SSH Authentication)| `/var/log/auth.log`: `Accepted password for thanh from 10.10.35.18 port 48122 ssh2`. | `DIRECT` | H1, H2 |
| **E32** | `SURICATA-IPS01` | `A10` (Inter-Zone Flow) | Suricata flow log: Allowed TCP/22 from `10.10.35.18` (Internal) to `10.10.34.13` (DMZ). | `DIRECT` | H1 |
| **E33** | `WEB01` (Linux Auditd) | `A11` (Privileged Exec) | Auditd tag `-k web_exec`: `sudo docker exec -it hrms-backend-1 cat ... site_config.json`. | `DIRECT` | H2 |
| **E34** | `DB01` (Kernel / iptables)| Host Firewall Audit | `IPTABLES-DROP: IN=ens192 SRC=10.10.35.18 DST=10.10.35.19 DPT=3306`. | `DIRECT` | H3 |
| **E35** | `DB01` (MariaDB Audit) | `A12` (Database Collection)| MariaDB `SERVER_AUDIT`: User `_6f9beb897020ebe5` from `10.10.34.13` executes `SHOW DATABASES`, `TABLESPACE_NAME`, `tabEmployee`. | `DIRECT` | H4 |
| **E36** | `WEB01` (Filesystem) | Staged File Artifact | Compressed file `/tmp/_6f9beb897020ebe5.sql.gz` created on `WEB01` (4.1 MB). | `DIRECT` | H4 |

---

## 2. Evidence Assessment Summary
* **Total Direct Evidentiary Artifacts**: 7 (`E30`, `E31`, `E32`, `E33`, `E34`, `E35`, `E36`).
* **Multi-Tier Alignment**: Telemetry spans network tunnels (Zeek), perimeter IPS (Suricata), host PAM auth (Linux Syslog), container syscalls (Auditd), host firewalls (iptables), and application databases (MariaDB Audit).
