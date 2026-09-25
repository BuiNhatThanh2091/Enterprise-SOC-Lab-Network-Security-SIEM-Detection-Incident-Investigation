# [SOC Investigation] Full Incident Investigation Walkthrough: From Ingress to Containment

## 1. Overview & Investigative Philosophy

This technical demonstration presents the complete, end-to-end **Blue Team Forensic Incident Investigation Walkthrough** conducted by the SOC analyst in response to an enterprise intrusion campaign.

### Core Investigative Philosophy
> [!IMPORTANT]
> **The analyst is not given the attack story. The attack story is reconstructed from the evidence.**
>
> In an authentic Security Operations Center (SOC) environment, detection rules and alerts do not deliver a pre-packaged, chronological narrative. The investigator begins with limited initial signals, ambiguous alerts, and partial visibility. The investigation progresses through structured question formation, hypothesis formulation, entity isolation, cross-telemetry pivoting, and empirical artifact correlation.
>
> This demonstration illustrates how an analyst moves from an isolated correlation alert to a fully reconstructed intrusion timeline and verified perimeter containment without prior knowledge of the adversary's playbook.

> [!NOTE]
> Video publication is pending. Sanitized YouTube links will be added after final review; all core technical documentation and artifacts are already available in this repository.

---

## 2. Technical Metadata & Repository Mapping

* **Video ID**: `VIDEO-02`
* **Standardized Title**: `[SOC Investigation] Full Incident Investigation Walkthrough: From Ingress to Containment`
* **Investigation Scenario**: Full SOC incident triage and multi-source correlation following a multi-stage intrusion from external adversary `203.0.113.25` into the corporate network.
* **Initial Trigger Alert**: ArcSight ESM Composite Correlation Alert `C01` (`A02` + `A03` + `A04`, $\Delta t \le 20\text{ min}$)
* **Affected Enterprise Assets**:
  * `IT-ADMIN01` (`10.10.35.18`): Internal IT administration workstation (initial breach point)
  * `MAIL01` (`10.10.34.14`): DMZ Postfix mail transfer agent (ingress vector)
  * `WEB01` (`10.10.34.13`): DMZ web application server (lateral pivot target)
  * `DB01` (`10.10.35.19`): Internal database server (data extraction target)
  * `pfSense` (`10.10.36.10`): Perimeter security transit gateway & firewall (containment boundary)
* **Primary Platforms Demonstrated**: Micro Focus ArcSight ESM (Console), ArcSight Logger (Web GUI), Sysmon, Zeek, Suricata, Postfix, Linux Auditd, MariaDB Audit Plugin
* **Related Case Studies**: [Case 001](file:///e:/project_ca_nhan/lab_cty/investigation/case-001/README.md), [Case 002](file:///e:/project_ca_nhan/lab_cty/investigation/case-002/README.md), [Case 003](file:///e:/project_ca_nhan/lab_cty/investigation/case-003/README.md), [Case 004](file:///e:/project_ca_nhan/lab_cty/investigation/case-004/README.md), [Case 005](file:///e:/project_ca_nhan/lab_cty/investigation/case-005/README.md)
* **Associated Detection Rules**: `C01`, `A01`–`A13`
* **Evidence Manifests Referenced**: `DET-001`–`005`, `INV-001`–`008`, `TEL-001`–`004`, `RESP-001`–`002`
* **Supplementary Walkthrough Document**: [`VIDEO-03-SUPPLEMENT.md`](file:///e:/project_ca_nhan/lab_cty/media/investigation/VIDEO-03-SUPPLEMENT.md) (Deep forensics and secondary technical pivots)
* **Hosting Platform**: YouTube (Unlisted)
* **YouTube Publication Status**: `Pending Upload`
* **YouTube Video URL**: `YOUTUBE_URL_PENDING`
* **Public-Safe Verification**: `REVIEW_REQUIRED` (Pending [Video Sanitization Checklist](file:///e:/project_ca_nhan/lab_cty/media/VIDEO_SANITIZATION_CHECKLIST.md) frame-by-frame audit)

---

## 3. Demonstrated 10-Step Investigation Workflow

Rather than executing a pre-scripted alert checklist, the recording guides the evaluator through the 10-step analytical journey of an incident responder:

```text
[1. Limited Initial Signal]       ──► ArcSight ESM triggers composite correlation alert C01
          │
[2. Initial Triage]              ──► Analyst evaluates alert parameters, priority, and victim entity
          │
[3. Question Formation]          ──► Formulate initial hypotheses: Is this an active shell or false positive?
          │
[4. Entity Identification]       ──► Isolate primary victim entity (IT-ADMIN01 / 10.10.35.18) & user account
          │
[5. Evidence Search]             ──► Query ArcSight Logger for raw endpoint and network telemetry
          │
[6. Telemetry Pivoting]          ──► Extract Sysmon ProcessGuid, pivot to Zeek conn.log and Postfix mail logs
          │
[7. Timeline Reconstruction]     ──► Chronologically order pre-compromise, execution, and beaconing events
          │
[8. Attack Chain Reconstruction] ──► Map end-to-end kill chain from spearphishing ingress to lateral pivoting
          │
[9. Scope Assessment]            ──► Determine blast radius across DMZ (WEB01, MAIL01) and Internal (DB01)
          │
[10. Containment & Validation]   ──► Enforce perimeter firewall blocks and verify zero egress traffic
```

### Step 1: Limited Initial Signal (Active Channel Trigger)
* **Operational Reality**: The analyst is monitoring the ArcSight ESM Active Channel when composite alert `C01` fires (`Priority: Very High`, `Manager Receipt Time: 2026-03-30 08:35:12`).
* **Initial Observation**: The alert does not describe an entire attack story. It merely reports a time-correlated bundle of 3 atomic rules triggered within a 20-minute sliding window on destination IP `10.10.35.18`.

### Step 2: Initial Triage (Parameters & Severity Evaluation)
* **Analyst Action**: Inspect the composite join fields:
  * Atomic rule 1: `A02` (HTTP ZIP download from external IP `203.0.113.25`).
  * Atomic rule 2: `A03` (Living-off-the-Land binary `mshta.exe` execution).
  * Atomic rule 3: `A04` (Outbound TCP connection to `203.0.113.25:4444`).
* **Triage Assessment**: This is not an isolated network probe or benign LOLBin test. The temporal proximity and causal relationship warrant immediate escalation from Tier 1 triage to active incident handling.

### Step 3: Question Formation & Hypothesis Generation
* **Hypotheses Formulated**:
  1. *Hypothesis 1 (Execution)*: Did `mshta.exe` successfully spawn an interactive payload, or did endpoint protections terminate it?
  2. *Hypothesis 2 (Network)*: Is the connection to port 4444 a transient SYN drop or an established, bidirectional C2 session?
  3. *Hypothesis 3 (Ingress)*: How did the malicious ZIP file arrive on the host? Was it user-initiated browsing or email spearphishing?

### Step 4: Entity Identification & Asset Context
* **Analyst Action**: Query asset database and ESM network model for `10.10.35.18`:
  * Hostname: `IT-ADMIN01` (Internal Administration Workstation).
  * Subnet: `INTERNAL_NET` (`10.10.35.0/24`).
  * Logged-in User: `user01`.
  * Asset Criticality: High (workstation possesses administrative SSH keys and intranet routing).

### Step 5: Evidence Search (ArcSight Logger Deep Query)
* **Analyst Action**: Pivot from ESM console to ArcSight Logger Web UI to inspect granular, raw event streams without pre-filtering:
  ```sql
  deviceCustomString1 = "Microsoft-Windows-Sysmon" AND deviceEventClassId = "1" AND destinationAddress = "10.10.35.18"
  ```
* **Raw Findings**: Sysmon Event ID 1 captures `explorer.exe` launching `mshta.exe "C:\Users\user01\Downloads\SecurityPatch_KB504991.hta"`.

### Step 6: Telemetry Pivoting (Cross-Source Correlation)
* **Process Lineage Pivot**: Instead of relying on volatile OS PIDs (which can be recycled), the analyst extracts the immutable 128-bit `ProcessGuid` (`{A1B2C3D4-...}`) from Sysmon.
  * Traced lineage: `explorer.exe` $\longrightarrow$ `mshta.exe` $\longrightarrow$ `cmd.exe /c` $\longrightarrow$ `powershell.exe -enc ...`
* **Network Pivot (Zeek NDR)**: Query Zeek `conn.log` for outbound connections matching `id.orig_h = 10.10.35.18` and `id.resp_h = 203.0.113.25`:
  * Found session `ZeekUID = C9xKa811`: `proto=tcp`, `id.resp_p=4444`, `conn_state=SF` (normal SYN/FIN handshake), `orig_bytes=1420`, `resp_bytes=8940`, duration 428 seconds.
  * *Confirmation*: The reverse shell is active, bidirectional, and interactive.
* **Ingress Pivot (Postfix Mail Logs)**: Search `MAIL01` (`10.10.34.14`) logs around the download timestamp:
  * Identified Postfix QueueID `718FC8006A`: `from=<security@microsoft.com>`, `to=<user01@soclab.test>`, delivering a phishing lure with a link to the malicious payload.

### Step 7: Timeline Reconstruction
* **Analyst Action**: Assemble disparate log timestamps into a single chronological event sequence:
  * `08:14:02 UTC` — Inbound spearphishing email delivered to `MAIL01` (`QueueID: 718FC8006A`).
  * `08:19:45 UTC` — User clicks link; `IT-ADMIN01` downloads `SecurityPatch_KB504991.zip` via HTTP (`A02`).
  * `08:21:10 UTC` — User extracts and executes `.hta`; `mshta.exe` spawns hidden PowerShell (`A03`).
  * `08:21:14 UTC` — Outbound TCP connection established to `203.0.113.25:4444` (`A04`).
  * `08:21:30 UTC` — Composite correlation rule `C01` triggers on ArcSight ESM.

### Step 8: Attack Chain Reconstruction (Post-Compromise Discovery & Pivoting)
* **Analyst Action**: Query all activity on `IT-ADMIN01` following the C2 connection:
  * **Reconnaissance Burst**: Sysmon captures 6 rapid command executions in $< 60\text{ seconds}$ (`whoami`, `ipconfig /all`, `net user`, `qwinsta`, `net localgroup administrators`, `systeminfo`) triggering alert `A05`.
  * **Credential Harvesting**: Attacker executes `xcopy` targeting Chrome and Firefox profile folders (`A06`), followed by PowerShell memory exfiltration (`A07`).
  * **Tunnel Ingress**: Attacker downloads `ligolo-agent.exe` via `certutil -urlcache` (`A08`) and connects to `203.0.113.25:11601` (`A09`).
  * **Lateral Movement**: Correlating `auth.log` on DMZ server `WEB01` (`10.10.34.13`) reveals an inbound SSH root login originating directly from `10.10.35.18` (`A10`).

### Step 9: Scope Assessment (Blast Radius Determination)
* **Analyst Action**: Broaden investigation scope to all systems touched by the lateral pivot:
  * `WEB01` (`10.10.34.13`): Linux Auditd reveals attacker executed `docker exec -u 0 crm-web` to extract database credentials (`A11`).
  * `DB01` (`10.10.35.19`): MariaDB Audit Plugin logs confirm the attacker queried sensitive customer records from `crm.customers` (`A12`).
  * DMZ Gateway (`10.10.36.10`): Suricata triggers alert `A13` on outbound TCP port 9999 from `WEB01` to `203.0.113.25`.
* **Blast Radius Summary**: 1 internal endpoint compromised (`IT-ADMIN01`), 1 DMZ server breached (`WEB01`), 1 internal database accessed (`DB01`), customer database records staged for egress.

### Step 10: Containment & Remediation Validation
* **Analyst Action**: Enforce containment controls and empirically verify their efficacy:
  1. **Firewall Drop Enforcement**: Push immediate drop rule to `pfSense` (`10.10.36.10`) blocking all egress traffic to `203.0.113.25` and terminating ports 4444, 9999, and 11601.
  2. **Filterlog Verification**: Inspect pfSense `filterlog` in Logger to confirm SYN packets from `10.10.34.13` and `10.10.35.18` are actively matched and dropped (`action = "block"`).
  3. **Host Isolation**: Disconnect `IT-ADMIN01` network interface; terminate malicious `powershell.exe` and `ligolo-agent.exe` processes.
  4. **Credential Revocation**: Force enterprise-wide password resets across Active Directory and MariaDB service accounts.

---

## 4. Key Evidence Artifacts Validated in Video

The investigation video visually inspects and validates the following repository evidence artifacts:
* **`DET-001`–`DET-004`**: Atomic detection events and the composite correlation join in ArcSight ESM.
* **`INV-001`**: Postfix mail log entry confirming spearphishing delivery (`QueueID: 718FC8006A`).
* **`INV-002`**: Sysmon Event ID 1 process tree expansion showing `mshta.exe` spawning hidden PowerShell.
* **`INV-003`**: Discovery command burst timeline showing 6 diagnostic commands executed in $< 60\text{ seconds}$.
* **`INV-005`**: Linux `auth.log` SSH root session records establishing lateral pivot from Internal to DMZ.
* **`RESP-001` & `RESP-002`**: pfSense perimeter firewall drop logs confirming immediate block of C2 and exfiltration channels.

---

## 5. Relationship with Supplementary Walkthrough (Video 03)

This video (`VIDEO-02`) represents the primary, end-to-end incident investigation narrative. Due to time constraints and narrative flow, specific deep forensic analyses—such as complete PowerShell ScriptBlock de-obfuscation decoding, raw Linux Auditd `execve` syscall parsing, and hardware-level Layer-2 ARP bypass testing—are detailed in the accompanying companion video:
* [**`VIDEO-03-SUPPLEMENT.md`**](file:///e:/project_ca_nhan/lab_cty/media/investigation/VIDEO-03-SUPPLEMENT.md): Supplementary Walkthrough: Deep Forensics & Secondary Pivots.

---

## 6. Pre-Upload Sanitization Verification

Prior to public release, this video must be verified against [`VIDEO_SANITIZATION_CHECKLIST.md`](file:///e:/project_ca_nhan/lab_cty/media/VIDEO_SANITIZATION_CHECKLIST.md):
* [x] **Network IPAM**: Verified all IP addresses displayed in ESM Active Channel, Logger grids, and terminal consoles strictly reflect sanitized subnets (`10.10.34.0/24`, `10.10.35.0/24`, `10.10.36.0/24`, `203.0.113.25`).
* [x] **Console Identities**: ArcSight analyst logins and terminal prompts sanitized to standard generic accounts (`soc_analyst01`, `root@sec-transit`).
* [x] **Zero Plaintext PII**: Confirmed customer database records extracted in the demonstration use synthetic demo data (`Customer_ID: DEMO-001`, `John Doe`).
