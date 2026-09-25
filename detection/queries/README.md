# ArcSight Logger Forensic Query Specifications

## 1. Overview & Query Execution Framework

This directory contains the production-grade **ArcSight Logger Search Queries** corresponding to the laboratory's 13 atomic detection rules (`A01`–`A13`) and composite correlation rule (`C01`).

In the laboratory's decoupled SIEM architecture:
* **ArcSight ESM** evaluates real-time streaming events in memory across sliding temporal windows.
* **ArcSight Logger** stores the tamper-evident, SHA-256 indexed event repository where analysts formulate targeted CEF/SQL search queries during incident investigation.

---

## 2. Logger Query Inventory & Rule Mapping

| Query File | Detection Rule | Target Telemetry Source | Primary CEF Search Criteria | Rule Detail Link |
| :--- | :--- | :--- | :--- | :---: |
| [**`A01.logger.query`**](A01.logger.query) | **A01: Mail Delivery Context** | Postfix Syslog | `deviceProduct="Postfix Mail Server" AND destinationUserName="user01@soclab.test"` | [A01](../A01/README.md) |
| [**`A02.logger.query`**](A02.logger.query) | **A02: Payload Web Download** | Suricata IPS | `deviceProduct="Suricata IDS IPS" AND deviceCustomNumber1=1101002` | [A02](../A02/README.md) |
| [**`A03.logger.query`**](A03.logger.query) | **A03: LOLBin mshta Execution** | Sysmon Event ID 1 | `destinationProcessName="C:\Windows\System32\mshta.exe" AND deviceCustomString4 CONTAINS ".hta"` | [A03](../A03/README.md) |
| [**`A04.logger.query`**](A04.logger.query) | **A04: TCP:4444 Callback** | Zeek `conn.log` | `deviceProduct="Zeek Network Monitor" AND destinationPort=4444` | [A04](../A04/README.md) |
| [**`A05.logger.query`**](A05.logger.query) | **A05: Discovery Burst** | Sysmon Event ID 1 | `destinationProcessName IN ["whoami.exe", "net.exe", "ipconfig.exe", "qwinsta.exe"]` | [A05](../A05/README.md) |
| [**`A06.logger.query`**](A06.logger.query) | **A06: Browser Profile Staging** | Sysmon Event ID 1 | `destinationProcessName="C:\Windows\System32\xcopy.exe" AND deviceCustomString4 CONTAINS "\Public\"` | [A06](../A06/README.md) |
| [**`A07.logger.query`**](A07.logger.query) | **A07: ScriptBlock Exfiltration**| PowerShell 4104 | `deviceEventClassId="4104" AND deviceCustomString1 CONTAINS "TcpClient"` | [A07](../A07/README.md) |
| [**`A08.logger.query`**](A08.logger.query) | **A08: Living-off-the-Land Ingress**| Sysmon Event ID 1 | `destinationProcessName="C:\Windows\System32\certutil.exe" AND deviceCustomString4 CONTAINS "-urlcache"` | [A08](../A08/README.md) |
| [**`A09.logger.query`**](A09.logger.query) | **A09: Reverse Proxy Tunnel** | Sysmon ID 3 / Zeek | `destinationPort=11601 AND destinationAddress="203.0.113.25"` | [A09](../A09/README.md) |
| [**`A10.logger.query`**](A10.logger.query) | **A10: Inter-Zone SSH Lateral** | Suricata IPS | `sourceAddress="10.10.35.18" AND destinationAddress="10.10.34.13" AND destinationPort=22` | [A10](../A10/README.md) |
| [**`A11.logger.query`**](A11.logger.query) | **A11: Container Privilege Abuse**| Linux Auditd | `deviceProduct="WEB01 Web Stack" AND deviceCustomString1 CONTAINS "docker exec"` | [A11](../A11/README.md) |
| [**`A12.logger.query`**](A12.logger.query) | **A12: Database Schema Extraction**| MariaDB Audit Plugin| `deviceVendor="MariaDB" AND deviceEventClassId="QUERY" AND deviceCustomString1 CONTAINS "SHOW TABLES"` | [A12](../A12/README.md) |
| [**`A13.logger.query`**](A13.logger.query) | **A13: DMZ Data Exfiltration** | Suricata IPS | `deviceProduct="Suricata IDS IPS" AND destinationPort=9999 AND deviceCustomNumber1=1101021` | [A13](../A13/README.md) |
| [**`C01.logger.query`**](C01.logger.query) | **C01: Composite Correlation** | ArcSight ESM Correl | `deviceVendor="ArcSight" AND deviceEventClassId="CORR-01" AND name CONTAINS "Initial Compromise"` | [C01](../C01/README.md) |

---

## 3. Query Usage Guidelines

* **Immutable Key Extraction**: When evaluating process queries (`A03`, `A05`, `A06`, `A08`), analysts extract the 128-bit `deviceCustomString5` (`ProcessGuid`) rather than the volatile OS PID to reconstruct genealogical execution trees.
* **Session ID Correlation**: For network callbacks (`A04`, `A09`), analysts extract `deviceCustomString2` (`ZeekUID`) to pivot between ArcSight Logger and Zeek connection logs.
