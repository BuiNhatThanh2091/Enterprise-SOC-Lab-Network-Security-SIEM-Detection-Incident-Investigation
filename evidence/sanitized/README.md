# Sanitized Public Evidence Cards & Transformation Log

## 1. Overview & Redaction Policy
This directory documents the public-safe sanitization and evidence normalization procedures applied across all laboratory artifacts.

Raw screenshots and un-redacted text files containing internal private subnets, university or corporate identity markers, student intern identifiers, or production passwords have been purged from public distribution. In their place, this directory provides **high-fidelity, sanitized textual evidence cards** preserving complete syntactic, structural, and forensic validity.

---

## 2. Master Sanitization Mapping Table

| Protected Infrastructure Component | Canonical Public Alias | Justification & Public Standard |
| :--- | :--- | :--- |
| External Threat Network | `203.0.113.0/24` | RFC 5737 TEST-NET-3 (Dedicated for documentation and public education). |
| Adversary Host (Kali) | `203.0.113.25` | Standardized external adversary host across all diagrams and case studies. |
| Perimeter Firewall External Interface | `203.0.113.11` | Perimeter gateway external interface. |
| Security Transit Segment | `10.10.36.0/24` | RFC 1918 Security Transit Segment (Isolated point-to-point choke point). |
| Transit Gateways (pfSense / Suricata)| `10.10.36.10` / `10.10.36.11` | pfSense Transit Gateway &amp; Suricata Transit Gateway. |
| Demilitarized Zone (DMZ Subnet) | `10.10.34.0/24` | RFC 1918 Demilitarized Zone (DMZ). |
| Web Application Server (WEB01) | `10.10.34.13` | Frappe HRMS Web Application Server. |
| Corporate Mail Gateway (MAIL01) | `10.10.34.14` | Postfix Corporate Mail Gateway. |
| Internal Core Network | `10.10.35.0/24` | RFC 1918 Internal Core Network. |
| Administrator Workstation (IT-ADMIN01)| `10.10.35.18` | Victim technical administrator workstation. |
| Production Database Server (DB01) | `10.10.35.19` | Production MariaDB Database Server. |
| Domain Controller (DC01 / AD01) | `10.10.35.12` | Windows Server 2019 Active Directory Domain Controller. |
| Isolated Telemetry &amp; Logging Plane | `10.10.40.0/24` | RFC 1918 Isolated Telemetry &amp; Logging Plane. |
| SIEM Collectors (Connector / Logger) | `10.10.40.4` / `10.10.40.5` | ArcSight SmartConnector &amp; ArcSight Logger Appliance. |
| Out-of-Band Management Plane | `10.10.21.0/24` | RFC 1918 Out-of-Band Management Plane (`MGMT-JUMPHOST`: `10.10.21.100`). |
| Corporate / Academic Domain | `soclab.test` | RFC 2606 Reserved Top-Level Test Domain. |
| User &amp; Administrative Accounts | `user01`, `admin`, `thanh` | Standardized role-based account tokens. |
| Database Password Strings | `[REDACTED_DATABASE_SECRET]` | Cryptographic and application secret sanitization. |

---

## 3. Sanitized Evidence Card 01: ArcSight ESM Active Channel (C01 Incident)
```text
====================================================================================================
ARCSIGHT ESM ACTIVE CHANNEL CONSOLE — REAL-TIME MONITORING GRID
Filter: (Name != "A04*") | Sort: EndTime DESC | Mode: Real-Time Stateful Correlation
====================================================================================================
Event ID | End Time            | Rule Name / Event Display             | Pri | Src Address  | Dst Address
----------------------------------------------------------------------------------------------------
1009412  | 2026-09-17 14:24:10 | SOC-LAB C01 Initial Compromise        | 9   | 10.10.35.18  | 203.0.113.25
1009408  | 2026-09-17 14:23:02 | SOC-LAB A04 Suspicious Callback       | 7   | 10.10.35.18  | 203.0.113.25
1009385  | 2026-09-17 14:22:27 | SOC-LAB A03 Suspicious Script Exec    | 7   | 10.10.35.18  | IT-ADMIN
1009371  | 2026-09-17 14:21:42 | SOC-LAB A02 Suspicious Web Download   | 5   | 10.10.35.18  | 203.0.113.25
1009304  | 2026-09-17 14:14:30 | SOC-LAB A01 Mail Delivered to User    | 3   | 203.0.113.25 | 10.10.34.14
====================================================================================================
[C01 CORRELATION SUMMARY DETAILS]:
Correlated Event: C01 Initial Compromise Correlation (Composite Join)
Composite Triggers: A02 (Ingress Download) -> A03 (mshta Execution) -> A04 (TCP/4444 Callback)
Anchor Entity: SourceAddress=10.10.35.18 (IT-ADMIN01) | Window Elapsed: 02m 28s (Limit <= 20m)
====================================================================================================
```

---

## 4. Sanitized Evidence Card 02: ArcSight Logger Forensic Query Output (A12 & A13)
```text
====================================================================================================
ARCSIGHT LOGGER FORENSIC SEARCH RESULTS — NIST SP 800-86 EVIDENCE EXTRACTION
Query: deviceProduct="MariaDB Server Audit" AND sourceAddress=10.10.34.13
Search Range: 2026-09-17 14:30:00 to 2026-09-17 14:40:00 | Total Matches: 2
====================================================================================================
Time                | Host | User              | Client IP   | Query String
----------------------------------------------------------------------------------------------------
2026-09-17 14:34:05 | DB01 | _6f9beb897020ebe5 | 10.10.34.13 | SHOW DATABASES
2026-09-17 14:34:06 | DB01 | _6f9beb897020ebe5 | 10.10.34.13 | SELECT /*!40001 SQL_NO_CACHE */ * FROM `tabEmployee`
====================================================================================================
Storage Validation: SHA-256 Hash verified intact across Storage Group 'Database_Security_Store'.
====================================================================================================
```
