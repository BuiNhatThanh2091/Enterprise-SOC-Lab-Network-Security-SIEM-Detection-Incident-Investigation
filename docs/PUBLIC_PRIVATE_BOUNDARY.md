# Public vs. Private Asset Boundary Specification

## 1. Overview & Purpose

A fundamental principle of the **Enterprise SOC Lab** portfolio is the strict separation between public-facing technical documentation and internal operational secrets. While the repository provides full transparency into security architecture, detection logic, telemetry pipelines, and investigative workflows, it enforces rigorous sanitization boundaries to protect internal infrastructure identities, credentials, and institutional privacy.

---

## 2. Public vs. Private Asset Classification Matrix

The following matrix formally defines the publication boundary for all project assets:

| Asset Category | Public Repository | Private / Internal Only | Operational Rationale |
| :--- | :---: | :---: | :--- |
| **System & Network Architecture Diagrams** | **YES** | | Public-safe SVG and Mermaid diagrams sanitized with RFC 1918 / RFC 5737 addresses. |
| **Public IP Mapping Model** | **YES** | | Normalized synthetic IPAM (`10.10.x.x`, `203.0.113.x`) reflecting true multi-zone topology. |
| **Real Internal IPAM & Subnets** | | **YES** | Sensitive infrastructure addresses must remain unexposed. |
| **Detection Engineering Logic (`A01`–`A13`, `C01`)** | **YES** | | Fully detailed ArcSight ESM rule conditions, threshold parameters, and CEF fields. |
| **Sanitized SIEM Search Queries** | **YES** | | Logger queries and parsed CEF search parameters mapped to synthetic entities. |
| **Raw SIEM & System Logs** | | **YES** | Raw log files (`*.log`, `*.audit`, `*.evtx`) contain un-sanitized headers and hashes. |
| **Authentication Credentials & Tokens** | | **NEVER COMMIT** | Plaintext passwords, service accounts, and API keys are strictly excluded. |
| **Incident Investigation Case Studies** | **YES** | | End-to-end forensic cases (001–005) sanitized with synthetic hostnames and usernames. |
| **Raw Native GUI Screenshots** | | **REVIEW** | Original bitmap screenshots from ESM/Logger may leak real hostnames or PII; sanitized cards used instead. |
| **Demonstration Screen Recordings** | **REVIEW** | | Videos must be reviewed for zero PII/IP leakage before publishing externally. |
| **Suricata IPS & Zeek Telemetry Schemas** | **YES** | | Structural configuration files, EVE JSON schemas, and conn.log parsing rules. |
| **Raw Packet Captures (`*.pcap`, `*.pcapng`)** | | **NEVER COMMIT** | May contain unencrypted session data and payload streams. |
| **Academic & Internal Source Documents** | | **YES** | Original reports (`*.docx`, `*.pdf`, `toan-bo-*.txt`) retained locally for Source of Truth only. |

---

## 3. Sanitization & Abstraction Principles

To ensure technical depth without compromising real-world privacy:
1. **Structural Topology Preservation**: All router interfaces, firewall rules, VLAN boundaries, and transit paths are identical to the physical implementation; only the addressing octets are abstracted.
2. **Defensive Telemetry Fidelity**: Normalized CEF field keys (`deviceCustomString4`, `ProcessGuid`, `ZeekUID`, `QueueID`) and rule triggers remain 100% faithful to ArcSight ESM engine logic.
3. **Synthetic Identity Standard**:
   * Internal Workstation: `IT-ADMIN01` (`10.10.35.18`)
   * Mail Gateway: `MAIL01` (`10.10.34.14`)
   * Web Server: `WEB01` (`10.10.34.13`)
   * Database Server: `DB01` (`10.10.35.19`)
   * Domain Controller: `DC01` (`10.10.35.12`)
   * Security Transit: pfSense (`10.10.36.10`), Suricata (`10.10.36.11`)
   * External Attacker: `203.0.113.25` (`Kali`)
   * Internal Domain: `soclab.test`
   * Target User: `user01@soclab.test`
