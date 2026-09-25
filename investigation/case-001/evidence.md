# Case 001 — Evidentiary Artifacts Catalog

This catalog documents all forensic evidence items collected, normalized, and evaluated during the investigation of Case 001. Evidence IDs remain immutable across all reports, queries, and architectural diagrams.

---

## 1. Structured Evidence Table

| Evidence ID | Producing Source | Detection / Event Class | Normalized Telemetry Observation | Evidence Classification | Supports Hypothesis |
| :--- | :--- | :--- | :--- | :---: | :---: |
| **E01** | `MAIL01` (Postfix) | `A01` (Mail Syslog) | QueueID `718FC8006A`, sender `security@microsoft.com`, recipient `user01@soclab.test`, `status=sent`. | `CONTEXTUAL` | H4 (Refutes USB) |
| **E02** | `SURICATA-IPS01` | `A02` (Suricata IPS) | SID `1101002`, HTTP GET `http://update.kali.test/SecurityPatch_KB504991.zip` from `203.0.113.25:80` to `10.10.35.18`. | `DIRECT` | H1 |
| **E03** | `IT-ADMIN01` (Sysmon) | `A03` (Event ID 1) | `destinationProcessName="C:\Windows\System32\mshta.exe"`, `ProcessGuid={ecec360d-d71c-6aab-3400-000000001800}`, file `SecurityPatch_KB504991.hta`. | `DIRECT` | H1 |
| **E04** | `IT-ADMIN01` (Sysmon) | Process Genealogy | Parent `mshta.exe` launches `cmd.exe /c` which launches `powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -enc ...`. | `DIRECT` | H2 |
| **E05** | `IT-ADMIN01` (Sysmon) | `A04` (Event ID 3) | Initiating process `powershell.exe` (`ProcessGuid={ecec360d-d720-6aab-3600-000000001800}`) connects to `203.0.113.25:4444`. | `DIRECT` | H2, H3 |
| **E06** | `ZEEK-SENSOR01` | `A04` (`conn.log`) | `ZeekUID=C9xKa811`, `transportProtocol=TCP`, destination `203.0.113.25:4444`, `duration > 1800s`, `orig_bytes=48210`, `resp_bytes=124890`. | `DIRECT` | H2, H3 |
| **E07** | `ARCSIGHT-ESM` | `C01` (Correlation) | ESM Correlated Event `SOC-LAB C01 Initial Compromise Correlation` uniting `A02`, `A03`, and `A04` on host `10.10.35.18` within $\Delta t \le 20\text{m}$. | `CORRELATED` | H1, H2, H3 |
| **E08** | Analyst Memory Audit | Volatile Artifact | Raw in-memory command stream decodes to interactive reverse TCP client socket. | `INFERRED` | H2 |

---

## 2. Evidence Assessment Summary
* **Total Direct Evidentiary Artifacts**: 5 (`E02`, `E03`, `E04`, `E05`, `E06`).
* **Total Correlated Artifacts**: 1 (`E07`).
* **Total Contextual Artifacts**: 1 (`E01`).
* **Total Inferred Artifacts**: 1 (`E08`).
* **Chain of Custody Assessment**: Unbroken digital custody verified from perimeter mail delivery through network transit, host execution, and outbound session beaconing.
