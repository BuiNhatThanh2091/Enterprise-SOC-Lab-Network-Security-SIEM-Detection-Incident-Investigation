# [SOC Investigation] Supplementary Walkthrough: Deep Forensics & Secondary Pivots

## 1. Overview & Demonstration Purpose

This technical demonstration serves as the **official supplementary walkthrough** directly expanding upon the main incident investigation presented in [**`VIDEO-02-FULL.md`**](file:///e:/project_ca_nhan/lab_cty/media/investigation/VIDEO-02-FULL.md).

### Crucial Architectural Scope Note
> [!IMPORTANT]
> **This video is NOT an independent incident case study (it is NOT "Case 06").**
> Rather, it is a technical deep-dive companion to **Video 02**, designed to walk evaluators through granular forensic queries, low-level system call traces, secondary pivots, and compensatory control validations that could not be fully demonstrated within the primary runtime of Video 02.

> [!NOTE]
> Video publication is pending. Sanitized YouTube links will be added after final review; all core technical documentation and artifacts are already available in this repository.

```text
               ┌────────────────────────────────────────────────────────┐
               │ VIDEO-02: Full Incident Investigation Walkthrough      │
               │ (End-to-End Triage, Active Channel, C01 Alert Pivot)   │
               └──────────────────────────┬─────────────────────────────┘
                                          │
                  Direct Technical Expansion & Forensic Deep-Dive
                                          │
                                          ▼
               ┌────────────────────────────────────────────────────────┐
               │ VIDEO-03: Supplementary Walkthrough                    │
               │ • PowerShell ScriptBlock 4104 Decompression            │
               │ • Linux Auditd execve Syscall Container Tracing        │
               │ • Hardware-Level Layer-2 ARP Bypass & iptables Defense │
               │ • MariaDB SERVER_AUDIT Query Extraction Forensics      │
               │ • Microsecond pfSense Filterlog Egress Drop Inspection │
               └────────────────────────────────────────────────────────┘
```

---

## 2. Technical Metadata & Repository Mapping

* **Video ID**: `VIDEO-03`
* **Standardized Title**: `[SOC Investigation] Supplementary Walkthrough: Deep Forensics & Secondary Pivots`
* **Role in Portfolio**: Supplementary technical deep-dive directly supporting [**`VIDEO-02`**](file:///e:/project_ca_nhan/lab_cty/media/investigation/VIDEO-02-FULL.md) and expanding forensic analyses across [**Case 003**](file:///e:/project_ca_nhan/lab_cty/investigation/case-003/README.md), [**Case 004**](file:///e:/project_ca_nhan/lab_cty/investigation/case-004/README.md), and [**Case 005**](file:///e:/project_ca_nhan/lab_cty/investigation/case-005/README.md).
* **Target Enterprise Systems**:
  * `IT-ADMIN01` (`10.10.35.18`): Windows workstation endpoint forensics
  * `WEB01` (`10.10.34.13`): Linux host and Docker container execution runtime
  * `DB01` (`10.10.35.19`): MariaDB database audit engine & host iptables firewall
  * `pfSense` (`10.10.36.10`): Perimeter packet filtering engine
* **Primary Platforms Demonstrated**: PowerShell ScriptBlock Logging (EID 4104), Linux Auditd (`ausearch`, `aureport`), MariaDB `SERVER_AUDIT` Plugin, Linux Netfilter (`iptables`), pfSense Packet Capture / Filterlog.
* **Key Evidence Manifests**: `INV-004`, `INV-006`, `INV-007`, `INV-008`, `ARCH-003`, `RESP-001`, `RESP-002`
* **Associated Detection Rules**: `A07`, `A08`, `A11`, `A12`, `A13`
* **Hosting Platform**: YouTube (Unlisted)
* **YouTube Publication Status**: `Pending Upload`
* **YouTube Video URL**: `YOUTUBE_URL_PENDING`
* **Public-Safe Verification**: `REVIEW_REQUIRED` (Pending [Video Sanitization Checklist](file:///e:/project_ca_nhan/lab_cty/media/VIDEO_SANITIZATION_CHECKLIST.md) frame-by-frame audit)

---

## 3. Supplementary Forensic Modules Demonstrated

The video walks through five specific, highly technical deep-dive modules:

### Module 1: PowerShell ScriptBlock 4104 De-obfuscation & Memory Analysis (Case 003)
* **Analytical Problem**: In Video 02, the attacker's PowerShell reverse shell execution was identified via Sysmon Event ID 1. However, the interactive commands passed encoded strings in memory.
* **Deep-Dive Walkthrough**:
  * Formulate Logger query targeting `Microsoft-Windows-PowerShell` Event ID 4104.
  * Extract the raw multi-part script block chunks.
  * Reassemble the decompressed payload: demonstrate that the adversary invoked `.NET` reflection (`[System.Net.Sockets.TcpClient]`) to stream stolen browser profiles out to port 11601.
  * Correlate with evidence artifact [**`INV-004`**](file:///e:/project_ca_nhan/lab_cty/evidence/investigation/README.md#inv-004).

### Module 2: Linux Auditd `execve` Container Command Attribution (Case 004)
* **Analytical Problem**: Standard Linux shell history (`.bash_history`) is easily erased or bypassed by attackers using `docker exec` container escapes.
* **Deep-Dive Walkthrough**:
  * Execute targeted Auditd query via `ausearch -k container_exec -i` on `WEB01` (`10.10.34.13`).
  * Inspect kernel-level `SYSCALL` records for `execve` system calls:
    ```text
    type=SYSCALL arch=c000003e syscall=59 success=yes exit=0 a0=55e... a1=55e... a2=55e...
    type=EXECVE argc=5 a0="docker" a1="exec" a2="-u" a3="0" a4="crm-web"
    ```
  * Correlate container command injection with evidence artifact [**`INV-006`**](file:///e:/project_ca_nhan/lab_cty/evidence/investigation/README.md#inv-006).

### Module 3: Hardware Layer-2 ARP Bypass Analysis & Host `iptables` Defense (Case 004 / Architecture)
* **Analytical Problem**: In virtualized or switched environments, co-located hosts on the same subnet (`INTERNAL_NET`: `.18` and `.19`) communicate directly via Layer-2 ARP switching, completely bypassing perimeter firewalls (`pfSense`) and network IPS sensors (`Suricata`).
* **Deep-Dive Walkthrough**:
  * Demonstrate why network IPS cannot observe direct L2 traffic between internal workstations.
  * Inspect the host-level compensatory control deployed on `DB01` (`10.10.35.19`):
    ```bash
    iptables -A INPUT -p tcp -s 10.10.34.13 --dport 3306 -j ACCEPT
    iptables -A INPUT -p tcp -s 10.10.35.18 --dport 3306 -j REJECT --reject-with icmp-port-unreachable
    ```
  * Validate that unauthorized queries from `IT-ADMIN01` are blocked locally at the kernel network stack, generating local syslog alerts verified in [**`ARCH-003`**](file:///e:/project_ca_nhan/lab_cty/evidence/architecture/README.md#arch-003).

### Module 4: MariaDB `SERVER_AUDIT` Query Extraction Forensics (Case 004)
* **Analytical Problem**: Network inspection can detect SQL connection attempts, but cannot reliably parse complex parameterized queries or large result sets when database traffic is compressed or encrypted.
* **Deep-Dive Walkthrough**:
  * Query normalized CEF events from `MariaDB Audit Plugin` on ArcSight Logger:
    ```sql
    deviceVendor = "MariaDB" AND deviceEventClassId = "QUERY" AND destinationAddress = "10.10.35.19"
    ```
  * Reconstruct the adversary's exact SQL sequence:
    1. `SHOW DATABASES;`
    2. `USE crm;`
    3. `SHOW TABLES;`
    4. `SELECT customer_id, full_name, credit_card_num, balance FROM customers;`
  * Correlate query timestamps with evidence manifest [**`INV-007`**](file:///e:/project_ca_nhan/lab_cty/evidence/investigation/README.md#inv-007).

### Module 5: Microsecond-Level pfSense Filterlog Egress Drop Verification (Case 005)
* **Analytical Problem**: Claiming an adversary exfiltration channel was contained requires verifiable proof that perimeter drop rules actively stopped packet transmission.
* **Deep-Dive Walkthrough**:
  * Inspect raw pfSense `filterlog` entries streamed into Logger:
    ```csv
    filterlog: 120,,,1000000104,igb1,match,block,in,4,0x0,,64,48201,0,DF,6,tcp,60,10.10.34.13,203.0.113.25,49182,9999,0,S,284918291,,1024,,mss;sackOK;ts
    ```
  * Verify rule match ID `1000000104` rejecting SYN packets to destination port 9999.
  * Cross-reference against evidence manifest [**`RESP-002`**](file:///e:/project_ca_nhan/lab_cty/evidence/EVIDENCE_INDEX.md#resp-002).

---

## 4. Evidence Artifacts Validated in Video

* **`INV-004`**: Decompressed PowerShell ScriptBlock 4104 code and raw TCP socket exfiltration stream.
* **`INV-006`**: Linux Auditd `SYSCALL` and `EXECVE` logs for container command execution.
* **`INV-007`**: MariaDB `SERVER_AUDIT` query extraction records.
* **`ARCH-003`**: Host-level `iptables` compensatory rule definition and reject verification on `DB01`.
* **`RESP-002`**: Perimeter pfSense `filterlog` drop records confirming egress containment.

---

## 5. Relationship with Primary Investigation (Video 02)

| Aspect | `VIDEO-02` (Full Investigation) | `VIDEO-03` (Supplementary Walkthrough) |
| :--- | :--- | :--- |
| **Role** | Primary incident investigation narrative | Technical deep-dive on secondary forensic evidence |
| **Trigger Point** | ArcSight ESM Composite Correlation Alert `C01` | Detailed inspection of alerts `A07`, `A08`, `A11`, `A12`, `A13` |
| **Scope** | End-to-end incident triage across all stages | Deep inspection of specific forensic subsystems |
| **Target Audience** | Hiring managers, SOC leads, incident responders | Senior detection engineers, forensic analysts, technical evaluators |

---

## 6. Pre-Upload Sanitization Verification

Prior to public release, this video must be verified against [`VIDEO_SANITIZATION_CHECKLIST.md`](file:///e:/project_ca_nhan/lab_cty/media/VIDEO_SANITIZATION_CHECKLIST.md):
* [x] **Network IPAM**: Verified all IP addresses displayed in terminal sessions, Auditd logs, and pfSense filterlog strings strictly match public-safe subnets (`10.10.34.0/24`, `10.10.35.0/24`, `10.10.36.0/24`, `203.0.113.25`).
* [x] **Host Identities**: Auditd output and MariaDB query logs display sanitized user accounts (`thanh`, `crm_user`, `admin`).
* [x] **Database Dump Sanitization**: Verified SQL result sets in MariaDB audit logs contain strictly synthetic test records (`DEMO-001`, `John Doe`).
