# Case 004 — Detection Coverage & Engineering Analysis

This document evaluates the detection performance, query verification, and engineering boundaries associated with the lateral movement and database collection phase in Case 004.

---

## 1. Detection Performance Matrix

| Detection ID | Rule Name | Fired? | Evidence Found | Operational Investigation Use | Known Engineering Limitations |
| :--- | :--- | :---: | :--- | :--- | :--- |
| **A09** | Suspicious External Tunnel | **YES** | Sysmon ID 3 / Zeek `conn.log` session on port 11601. | Tunneling Pivot: Identifies established reverse proxy bridge. | Scenario-dependent; relies on default Ligolo-ng port 11601. |
| **A10** | Internal Remote Access to WEB Tier | **YES** | Suricata flow + Linux `/var/log/auth.log` (SSH port 22 to DMZ). | Lateral Movement Pivot: Proves interactive administrative access. | Severity 3 informational alert; payload encrypted, cannot read commands typed. |
| **A11** | Sensitive Privileged WEB Activity | **YES** | Linux Auditd (`-k web_exec`): `sudo docker exec ... site_config.json`. | Privilege Escalation Pivot: Catches container config scraping. | Captures one-line commands from host OS; blind inside interactive container shells. |
| **A12** | Suspicious Database Collection | **YES** | MariaDB `SERVER_AUDIT` query logs (`SHOW DATABASES`, `TABLESPACE_NAME`). | Data Collection Pivot: Signals automated schema dump via `mysqldump`. | Threshold-dependent ($\ge 2$ in 5m); single ad-hoc SQL queries bypass rule. |

---

## 2. Engineering Evaluation & Defense-in-Depth Analysis
1. **The Layer-2 Blind Spot in Practice**:
   * When the attacker executed `nc -vz 10.10.35.19 3306` from `IT-ADMIN01`, Suricata Inline IPS observed **zero packets**. Because both hosts share broadcast domain `10.10.35.0/24`, frames switched directly across the virtual switch.
   * If `DB01` had relied solely on the network firewall or IPS, the database would have been breached directly from the workstation.
   * The host-based `iptables` rule on `DB01` (`-s 10.10.34.13 -p tcp --dport 3306 -j ACCEPT; -p tcp --dport 3306 -j DROP`) proved indispensable.
2. **Container Security Boundaries**:
   * Docker containers sharing the host daemon inherit significant risks when host users have sudo permissions. Security policies must prevent host users from invoking `docker exec` against production database containers without dedicated change tickets.
