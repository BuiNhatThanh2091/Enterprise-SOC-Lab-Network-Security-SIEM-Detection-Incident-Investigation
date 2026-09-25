# CV Project Entry & Portfolio Narratives

## 1. Project Title

```text
Enterprise SOC Lab: Network Security, SIEM Detection & Incident Investigation
```

---

## 2. One-Line Project Summary (For Resume Header / Concise Project Line)

```text
Hands-on security laboratory integrating multi-zone network segmentation, inline IPS, full-stack endpoint/network telemetry, ArcSight SIEM correlation, and evidence-driven incident investigation.
```

---

## 3. Resume Project Descriptions by Length

### 3.1. Short Version (2–3 Lines for Dense 1-Page CVs)
> Engineered a multi-zone SOC lab integrating pfSense firewalling, Suricata inline IPS (NFQUEUE), and Zeek NDR with centralized ArcSight SIEM event collection. Developed 13 atomic detection rules (`A01`–`A13`) and a multi-source composite correlation rule (`C01`), validating detection fidelity across 5 forensic incident investigations.

### 3.2. Medium Version (4–6 Lines for Standard Technical CVs)
> **Enterprise SOC Lab: Network Security, SIEM Detection & Incident Investigation**
> * Designed a segmented enterprise-style network on VMware ESXi, enforcing traffic routing through a dedicated Security Transit segment equipped with pfSense and inline Suricata IPS.
> * Implemented a centralized telemetry pipeline normalizing Windows Sysmon, PowerShell ScriptBlock (4104), Linux Auditd, MariaDB Audit, and network metadata into CEF via ArcSight SmartConnector.
> * Engineered real-time correlation in ArcSight ESM (`C01`) and cold-retention forensic querying in ArcSight Logger, validating detection across 4 red-team attack simulation phases.
> * Demonstrated attack simulation and incident investigation workflows through documented case studies and recorded technical walkthroughs.

### 3.3. Long Version (Full Paragraph for Portfolio Websites & Project Portals)
> **Enterprise SOC Lab: Network Security, SIEM Detection & Incident Investigation**  
> Designed, deployed, and empirically validated a comprehensive security operations and defensive architecture laboratory to evaluate how network controls, host instrumentation, and SIEM correlation operate as a unified system. Virtualized across VMware ESXi, the environment enforces strict multi-zone segmentation (DMZ, Internal, Security Transit, Logging) using pfSense stateful firewalling, Suricata inline IPS (`NFQUEUE`), and passive Zeek monitoring. Engineered a multi-tier telemetry pipeline utilizing ArcSight SmartConnector to ingest and normalize heterogenous event streams—including Windows Sysmon (Process Create & Network Connect), PowerShell ScriptBlock Logging (4104), Linux Auditd (`execve`), MariaDB Audit Plugin (`SERVER_AUDIT`), and Postfix mail logs—into Common Event Format (CEF). Architecturally decoupled SIEM operations between ArcSight Logger for immutable, tamper-evident SHA-256 storage and ArcSight ESM for in-memory, real-time correlation. Authored and tuned 13 atomic detection rules (`A01`–`A13`) and a multi-source stateful correlation rule (`C01`) joining perimeter, host, and network alerts within a 20-minute sliding window. Demonstrated attack simulation and incident investigation workflows through 5 documented case studies and recorded technical walkthroughs, utilizing hypothesis testing, Logger ad-hoc querying, and process tree reconstruction to identify threat actors and verify containment.

### 3.4. Optional Demonstration Link Line (For Personal Portfolio Websites)
> * **Technical Demonstrations**: Recorded attack simulations and investigation walkthroughs are hosted on YouTube as unlisted videos, linked directly from their respective repository case studies.

---


## 4. Canonical Project Narrative (System-Level Story)

Use this narrative during interview presentations, portfolio cover letters, or personal blog introductions:

```text
The Enterprise SOC Lab was engineered to study how network security controls, host telemetry, 
SIEM detection, and incident response operate together as a single defensive system. 

The architecture enforces strict network segmentation, requiring all inter-zone communication 
to traverse a dedicated Security Transit segment equipped with stateful firewalling and inline 
deep packet inspection. Where network hardware constraints create Layer-2 switching blind spots 
within the same broadcast domain, host-based firewalls serve as compensatory controls.

Host and network activities emit structured telemetry across multiple layers: kernel process 
creations, de-obfuscated script executions, database queries, and network connection metadata. 
These disparate streams are ingested, parsed, and normalized into Common Event Format (CEF) 
before reaching the SIEM.

SIEM responsibilities are architecturally decoupled: ArcSight Logger provides high-capacity, 
tamper-evident immutable retention for ad-hoc searching, while ArcSight ESM maintains active 
in-memory temporal windows for real-time correlation.

Threat detection combines atomic behavioral indicators with multi-source composite correlation. 
When high-priority alerts fire, the SOC workflow does not stop at the alert: analysts formulate 
causal hypotheses, pivot across Logger telemetry, assemble forensic timelines using ProcessGuids 
and session identifiers, reconstruct the attack chain, and validate firewall containment.

Finally, the laboratory documents its own technical limitations—such as same-L2 visibility gaps, 
scenario-dependent test ports, and threshold evasion intervals—ensuring that detection engineering 
is grounded in empirical reality rather than theoretical assumptions.
```
