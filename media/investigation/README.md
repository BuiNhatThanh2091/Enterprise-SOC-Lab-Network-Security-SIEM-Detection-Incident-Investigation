# SOC Investigation Video Sessions Catalog

This directory contains metadata and process walkthroughs for the recorded **Blue Team Forensic Investigation Sessions**.

---

## 1. Official Investigation Videos

The incident investigation is presented across **two official videos**, hosted externally on **YouTube as Unlisted videos**:

| Video ID | Title | Target Scope | Primary SIEM Workflows Demonstrated | YouTube Status | Public-Safe Status |
| :--- | :--- | :--- | :--- | :---: | :---: |
| [**`VIDEO-02-FULL.md`**](file:///e:/project_ca_nhan/lab_cty/media/investigation/VIDEO-02-FULL.md) | `[SOC Investigation] Full Incident Investigation Walkthrough: From Ingress to Containment` | **Full End-to-End Incident** ([Case 001](file:///e:/project_ca_nhan/lab_cty/investigation/case-001/README.md) to [Case 005](file:///e:/project_ca_nhan/lab_cty/investigation/case-005/README.md)) | ESM Active Channel composite alert `C01` triage; Sysmon `ProcessGuid` lineage reconstruction; Zeek callback validation; Postfix QueueID backtrack; lateral movement analysis; pfSense perimeter drop verification. | `Pending Upload`<br/>`YOUTUBE_URL_PENDING` | `REVIEW_REQUIRED` |
| [**`VIDEO-03-SUPPLEMENT.md`**](file:///e:/project_ca_nhan/lab_cty/media/investigation/VIDEO-03-SUPPLEMENT.md) | `[SOC Investigation] Supplementary Walkthrough: Deep Forensics & Secondary Pivots` | **Supplementary Deep Forensics** (Expands [Case 003](file:///e:/project_ca_nhan/lab_cty/investigation/case-003/README.md), [Case 004](file:///e:/project_ca_nhan/lab_cty/investigation/case-004/README.md), [Case 005](file:///e:/project_ca_nhan/lab_cty/investigation/case-005/README.md)) | Technical deep-dive directly expanding on Video 02: PowerShell ScriptBlock 4104 payload reassembly; Linux Auditd `execve` container command tracing; hardware Layer-2 ARP bypass analysis and host `iptables` defense on `DB01`; MariaDB `SERVER_AUDIT` query dump forensics; microsecond pfSense filterlog drop inspection. | `Pending Upload`<br/>`YOUTUBE_URL_PENDING` | `REVIEW_REQUIRED` |

---

## 2. Relationship Between Video 02 and Video 03

> [!IMPORTANT]
> **Video 03 is NOT an independent incident case study (not "Case 06").**
> * **`VIDEO-02`** delivers the end-to-end incident response story, following the analyst from the initial ESM `C01` correlation alert through multi-tier pivots and final containment.
> * **`VIDEO-03`** is a direct technical companion to Video 02, focusing on low-level system call traces, script block de-obfuscation, database audit syntax, and Layer-2 switching bypass mechanisms that could not fit into the primary video runtime.

---

## 3. Standard 6-Phase Analytical Process

Both investigation recordings demonstrate the structured 6-phase analytical process:
1. **Initial Alert Inspection**: Viewing fired alerts in the ArcSight ESM Active Channel console.
2. **Formulating the Analyst Question**: Stating the core hypothesis to test.
3. **Logger Search Execution**: Entering targeted CEF/SQL search queries on ArcSight Logger.
4. **Telemetry Interpretation**: Analyzing returned fields (`ProcessGuid`, `ZeekUID`, `deviceCustomString3`).
5. **Cross-Source Pivot**: Moving from network to endpoint or host to database logs.
6. **Remediation & Validation**: Applying containment measures and confirming cessation in firewall logs.

---

## 4. Correlating Case Study Documentation

The video walkthroughs validate the five documented incident investigation case studies:
* [**Case 001: Initial Compromise Investigation**](file:///e:/project_ca_nhan/lab_cty/investigation/case-001/README.md): Spearphishing delivery, Living-off-the-Land HTA execution, and reverse shell callback.
* [**Case 002: Post-Compromise Host Discovery**](file:///e:/project_ca_nhan/lab_cty/investigation/case-002/README.md): Sliding-window discovery burst triage and parent process grouping.
* [**Case 003: Credential Staging & Ingress Tool Download**](file:///e:/project_ca_nhan/lab_cty/investigation/case-003/README.md): Browser credential extraction, ScriptBlock 4104 decoding, and raw socket exfiltration.
* [**Case 004: Inter-Zone Lateral Movement & DB Dump**](file:///e:/project_ca_nhan/lab_cty/investigation/case-004/README.md): Reverse proxy tunneling, SSH pivot, container privilege abuse, and database schema theft.
* [**Case 005: DMZ Exfiltration & Remediation**](file:///e:/project_ca_nhan/lab_cty/investigation/case-005/README.md): Suricata exfiltration triage, flow volumetrics, and perimeter firewall containment.
