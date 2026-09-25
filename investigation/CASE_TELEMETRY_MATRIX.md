# Case-to-Telemetry Matrix

This matrix documents the empirical utilization of confirmed telemetry sources across the five **Incident Investigation Case Studies**. Only telemetry pipelines with verified evidentiary contributions are marked as active (`YES`).

---

## 1. Cross-Source Utilization Matrix

| Case ID & Investigation Scope | Suricata IPS | Zeek NDR | Microsoft Sysmon | PowerShell (4104) | Postfix Syslog | Linux Auditd | MariaDB Audit | ArcSight ESM | ArcSight Logger |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Case 001: Initial Compromise** | **YES** | **YES** | **YES** | **YES** | **YES** | NO | NO | **YES** | **YES** |
| **Case 002: Host Discovery Burst** | NO | **YES** | **YES** | NO | NO | NO | NO | **YES** | **YES** |
| **Case 003: Credential Harvesting & Staging** | NO | **YES** | **YES** | **YES** | NO | NO | NO | **YES** | **YES** |
| **Case 004: Lateral Movement & DB Dump** | **YES** | **YES** | **YES** | NO | NO | **YES** | **YES** | **YES** | **YES** |
| **Case 005: DMZ Exfiltration & Remediation**| **YES** | **YES** | NO | NO | NO | **YES** | **YES** | **YES** | **YES** |

---

## 2. Telemetry Role in Investigations

### 2.1. Network Perimeter & Transit (`Suricata IPS` & `Zeek NDR`)
* **Suricata IPS** provides deterministic signature alerts (`SID 1101002`, `SID 1101021`) and protocol flow enforcement on the Security Transit segment (`10.10.36.0/24`).
* **Zeek NDR** provides continuous session metadata (`conn.log`), protocol attribution, and volumetric byte counts (`orig_bytes`, `resp_bytes`), critically revealing persistent interactive reverse shells (`TCP/4444`) and outbound protocol tunnels (`TCP/11601`).

### 2.2. Endpoint Visibility (`Microsoft Sysmon` & `PowerShell 4104`)
* **Sysmon (Event ID 1 & 3)** bridges the visibility gap caused by encrypted network sessions, providing the immutable process genealogy (`ProcessGuid`, `ParentProcessGuid`, `CommandLine`) that ties network connections directly to executing binaries.
* **PowerShell ScriptBlock Logging (Event ID 4104)** reconstructs in-memory script execution without requiring binary drops, capturing raw socket creations and file compression parameters.

### 2.3. Application & Database Layers (`Linux Auditd` & `MariaDB SERVER_AUDIT`)
* **Linux Auditd** tracks privileged container interactions (`sudo docker exec`) on the web tier that bypass traditional network inspection.
* **MariaDB SERVER_AUDIT** provides application-layer forensic proof of database enumeration (`SHOW DATABASES`) and exfiltration queries, establishing the exact data assets targeted by the adversary.

### 2.4. SIEM Infrastructure (`ArcSight ESM` & `ArcSight Logger`)
* **ArcSight ESM** acts as the real-time alerting engine, executing stateful in-memory joins (`C01`) and threshold evaluations (`A05`, `A12`).
* **ArcSight Logger** serves as the central evidentiary repository, enabling analysts to pivot across time windows, hosts, users, and correlation keys in compliance with NIST SP 800-86 digital forensics standards.
