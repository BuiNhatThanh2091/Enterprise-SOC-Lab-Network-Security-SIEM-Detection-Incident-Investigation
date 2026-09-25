# Case 002 — Evidentiary Artifacts Catalog

This catalog documents all forensic evidence items collected, normalized, and evaluated during the investigation of Case 002.

---

## 1. Structured Evidence Table

| Evidence ID | Producing Source | Detection / Event Class | Normalized Telemetry Observation | Evidence Classification | Supports Hypothesis |
| :--- | :--- | :--- | :--- | :---: | :---: |
| **E10** | `IT-ADMIN01` (Sysmon) | Event ID 1 (Discovery) | `destinationProcessName="where.exe"`, `deviceCustomString4="where ssh"`, `ParentProcessGuid={ecec360d-d720-6aab-3600-000000001800}`. | `DIRECT` | H1, H2 |
| **E11** | `IT-ADMIN01` (Sysmon) | Event ID 1 (Discovery) | `destinationProcessName="sc.exe"`, `deviceCustomString4="sc query sshd"`, `ParentProcessGuid={ecec360d-d720-6aab-3600-000000001800}`. | `DIRECT` | H1, H2 |
| **E12** | `IT-ADMIN01` (Sysmon) | Event ID 1 (Discovery) | `destinationProcessName="sc.exe"`, `deviceCustomString4="sc query termservice"`, `ParentProcessGuid={ecec360d-d720-6aab-3600-000000001800}`. | `DIRECT` | H1, H2 |
| **E13** | `ARCSIGHT-ESM` | `A05` (Threshold Alert) | ESM Alert `SOC-LAB A05 Post-Compromise Discovery Burst` triggered on threshold $\ge 3$ commands in 5 minutes. | `CORRELATED` | H1 |
| **E14** | `IT-ADMIN01` (Sysmon) | Event ID 1 (Discovery) | `destinationProcessName="qwinsta.exe"`, `deviceCustomString4="qwinsta"`, `ParentProcessGuid={ecec360d-d720-6aab-3600-000000001800}`. | `DIRECT` | H1, H2 |
| **E15** | `IT-ADMIN01` (Sysmon) | Event ID 1 (Discovery) | `destinationProcessName="netstat.exe"`, `deviceCustomString4="netstat -an"`, `ParentProcessGuid={ecec360d-d720-6aab-3600-000000001800}`. | `DIRECT` | H1, H2 |
| **E16** | `IT-ADMIN01` (Sysmon) | Event ID 1 (File Access) | `destinationProcessName="cmd.exe"`, `deviceCustomString4="cmd.exe /c type C:\Users\admin\.ssh\config"`. | `DIRECT` | H3 |

---

## 2. Evidence Assessment Summary
* **Total Direct Evidentiary Artifacts**: 6 (`E10`, `E11`, `E12`, `E14`, `E15`, `E16`).
* **Total Correlated Artifacts**: 1 (`E13`).
* **Verification**: All commands verified to share identical `ParentProcessGuid` matching the active C2 reverse shell identified in Case 001.
