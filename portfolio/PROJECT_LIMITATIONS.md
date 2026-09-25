# Operational Limitations & Engineering Boundaries

## 1. Overview & Professional Transparency

A core hallmark of senior security engineering is the objective, transparent identification of operational boundaries and technical limitations. Rather than presenting the **Enterprise SOC Lab** as an impenetrable or all-seeing defensive platform, this document outlines the specific architectural, detection, and telemetry trade-offs observed during its implementation and validation.

---

## 2. Architectural & Network Visibility Limitations

### 2.1. Intra-Subnet Layer-2 Direct Switching Bypass
* **Technical Reality**: Hosts situated within the same broadcast domain (such as `IT-ADMIN01` at `10.10.35.18` and `DB01` at `10.10.35.19` on `INTERNAL_NET`) resolve each other's MAC addresses via ARP and communicate directly across the virtual switch fabric.
* **Operational Impact**: These packets do not traverse the default gateway interfaces (`pfSense` or `Suricata`). Therefore, **Suricata must not be described as providing complete visibility over all east-west internal network traffic**.
* **Implemented Mitigation**: Acknowledging this blind spot, host-level `iptables` rules were deployed directly on `DB01` to restrict MySQL access to authorized DMZ web interfaces (`10.10.34.13`), serving as an essential compensatory control.

### 2.2. Encrypted Traffic Payload Blind Spot (HTTPS)
* **Technical Reality**: Detection rule `A02` (Suricata SID `1101002`) triggered because the adversary delivered the malicious payload archive over unencrypted HTTP.
* **Operational Impact**: In the absence of an enterprise TLS-terminating forward proxy performing active SSL/TLS inspection, Suricata can only observe TLS handshake metadata (SNI, IP, cipher suites) and is blind to encrypted file contents or HTTP request URIs.

---

## 3. Detection Engineering Limitations

### 3.1. Scenario-Dependent Network Parameter Rules
* **Technical Reality**: Several atomic detection rules evaluate specific network parameters utilized during the attack simulation:
  * `A04`: Outbound connection to TCP port `4444` (reverse shell callback).
  * `A09`: Outbound connection to TCP port `11601` (default Ligolo-ng proxy port).
  * `A13`: Outbound connection to TCP port `9999` (Netcat staging exfiltration).
* **Operational Impact**: These rules represent tactical indicator detections tied to known simulation ports rather than generalized behavioral anomalies or statistical protocol inspection. If an adversary redirected traffic over standard ports (such as `TCP/443` or `TCP/80`), these specific rules would not fire without secondary protocol analysis.

### 3.2. Temporal Sliding-Window & Threshold Evasions
* **Rule `A05` (Discovery Burst)**: Detects $\ge 3$ diagnostic commands within a 5-minute sliding window. An adversary executing discovery commands slowly (e.g., one command every 6 minutes) effectively evades the threshold logic.
* **Rule `C01` (Composite Compromise)**: Requires all three constituent steps (`A02` $\rightarrow$ `A03` $\rightarrow$ `A04`) to occur within a 20-minute sliding window. If an adversary introduces a 30-minute sleep interval between payload execution and reverse shell callback, composite rule `C01` will not fire, leaving only disconnected atomic alerts.

---

## 4. Telemetry Pipeline Dependencies

### 4.1. Strict Ingestion & Normalization Dependency Chain
Threat detection in this architecture is not autonomous; it depends on an unbroken multi-tier pipeline:
```text
Event Generation (OS Kernel) ──► Collection (Agent/Syslog) ──► Normalization (CEF) ──► SIEM Rules Engine
```
* If a host audit agent (such as Sysmon or Linux Auditd) fails or is terminated by an adversary, the SIEM receives zero event data.
* If a SmartConnector parser fails to map a required correlation key (e.g., omitting `ProcessGuid` or `CommandLine`), real-time ESM rules will fail to join events even if the raw log arrived at the connector.

---

## 5. Forensic Investigation Boundaries

### 5.1. Absence of Volatile RAM Memory Dumps
* Due to hypervisor storage constraints and immediate containment requirements during testing, full volatile memory dumps (`.vmem` / `.raw`) of workstation `IT-ADMIN01` were not preserved prior to process termination.
* Forensic analysis relies on historical telemetry preserved in ArcSight Logger: Sysmon Event ID 1 (Process Create), Event ID 5 (Process Terminate), and PowerShell Event ID 4104 (ScriptBlock Logging).

### 5.2. Postfix Mail Body Retention Limitations
* Mail delivery logs from Postfix capture critical envelope metadata: sender, recipient, QueueID, and delivery status.
* Due to standard enterprise privacy and storage policies, the actual plaintext body of the email was not archived in syslog, requiring analysts to correlate the delivery timestamp with subsequent endpoint download events.

### 5.3. Offline Credential Decryption
* In Case 003, the adversary staged and exfiltrated the Chrome SQLite `Login Data` file via a raw socket stream. Because the actual decryption of the DPAPI-encrypted passwords occurred offline on the adversary's machine, the SIEM could observe the file staging and egress, but generated zero telemetry regarding the offline decryption process.

---

## 6. Laboratory vs. Production Enterprise Boundaries

This project documents a **controlled security engineering laboratory**, not a multi-tenant commercial SOC. Therefore:
* It does **NOT** operate under commercial production Service Level Agreements (SLAs) or 24/7 follow-the-sun analyst shifts.
* It does **NOT** process production enterprise traffic volumes (millions of events per second) or multi-terabyte daily log ingestion.
* It does **NOT** incorporate commercial SOAR automated playbooks or commercial cloud-native security platforms.
* It should be evaluated as an **authoritative demonstration of hands-on security architecture, telemetry engineering, SIEM correlation, and forensic investigation methodologies**.
