# Detection Engineering Limitations & Operational Boundaries

## 1. Overview

A critical requirement of professional security engineering is the transparent documentation of operational boundaries and technical trade-offs. The detection suite deployed in the Enterprise SOC Lab was designed for a controlled simulation environment and demonstrated significant detection efficacy across the multi-stage attack lifecycle. However, several inherent limitations must be formally recognized to avoid overstating the system's capabilities in a production enterprise context.

---

## 2. Scenario-Dependent Detection Constraints

Several network-layer detection rules rely on specific, pre-determined network indicators observed during the red team exercise:

* **Rule A04 (Suspicious Outbound Callback)**:
  * *Constraint*: Specifically monitors outbound TCP connections destined for external port `4444`.
  * *Limitation*: If an adversary configures their reverse shell listener on a common allowed port (e.g., `TCP/443` or `TCP/80`) or encapsulates traffic within standard HTTPS sessions, Rule `A04` will not trigger.
* **Rule A09 (Suspicious External Tunnel - Ligolo-ng)**:
  * *Constraint*: Matches connections targeting destination port `11601`, the default listening port of Ligolo-ng proxy.
  * *Limitation*: An advanced adversary can easily modify the listening port of the proxy server to standard web ports, bypassing this specific port-based rule.
* **Rule A13 (DMZ External Data Transfer)**:
  * *Constraint*: Detects high-volume outbound data streams over non-standard port `9999`.
  * *Limitation*: Exfiltration tunneled over encrypted HTTPS sessions or slow data staging via DNS tunneling will not trigger this signature.
* *Classification*: **Scenario-Dependent Network Detections**. They validate that the telemetry pipeline functions under known test conditions, but do not represent generic, protocol-agnostic anomaly detectors.

---

## 3. Threshold and Temporal Window Constraints

Rules utilizing sliding time windows and frequency thresholds introduce distinct evasion opportunities:

* **Rule A05 (Post-Compromise Discovery Burst)**:
  * *Condition*: Triggers when three or more discovery commands (`where ssh`, `sc query`, `netstat`, `qwinsta`) occur within a **5-minute sliding window** ($\text{Matches} \ge 3 \text{ in } 5\text{ min}$).
  * *Evasion*: If an attacker spaces reconnaissance commands ten minutes apart ("low-and-slow" discovery), the event frequency never breaches the threshold, and Rule `A05` fails to fire.
* **Rule A12 (Suspicious Database Collection)**:
  * *Condition*: Triggers on two or more structural query events (`SHOW DATABASES`, `INFORMATION_SCHEMA.FILES`) within a **5-minute window** ($\text{Matches} \ge 2 \text{ in } 5\text{ min}$).
  * *Evasion*: Single-query targeted extractions (e.g., executing a direct `SELECT * FROM tabEmployee` without invoking structural metadata commands) will bypass this threshold.

---

## 4. Alert Volume and Flood Limitations

* **Rule A04 Alert Volume Impact**:
  * *Behavior*: Zeek's `conn.log` emits status records periodically for persistent TCP sessions. For a long-lived interactive reverse shell on port `4444`, Zeek generates a continuous stream of connection updates.
  * *Operational Consequence*: Rule `A04` fires repeatedly, flooding the real-time Active Channel console and burying single-event alerts (`A05`, `A06`, `A07`, `A11`).
  * *Operational Workaround*: SOC analysts were forced to configure a temporary filter expression on the primary monitoring console (`Name != "A04*"`) to maintain visibility over subsequent attack phases, routing `A04` alerts to a separate secondary channel.

---

## 5. Event Semantic Boundaries (Atomic Isolation)

A recurring architectural lesson in this project is that **an atomic log event contains only the evidence of its immediate transaction**:

* **Postfix Local Delivery (`A01`)**:
  * Proves: An email message reached a local mailbox (`user01@soclab.test`).
  * Does Not Prove: The email is malicious or sent by an external attacker. External origin is recorded in upstream SMTP handshake events, not in the local delivery syslog.
* **Sysmon Script Execution (`A03`)**:
  * Proves: `mshta.exe` executed an `.hta` file.
  * Does Not Prove: A reverse shell was successfully established. Network connectivity is captured downstream by Sysmon Event ID 3 or Zeek.
* **Linux Auditd Container Access (`A11`)**:
  * Proves: A user ran `sudo docker exec` to inspect `site_config.json`.
  * Does Not Prove: Database records were exfiltrated. Exfiltration is proven only by database query audits (`A12`) and network stream metrics (`A13`).
* *Conclusion*: Designing detection rules that attempt to force full attack narratives into a single atomic event leads to fragile, failing detections. Correlation across events is non-negotiable.

---

## 6. Layer-2 Intra-Subnet Blind Spot

As established in the network architecture documentation:
* Traffic exchanged directly between hosts sharing the `10.10.35.0/24` subnet (e.g., `IT-ADMIN01` to `DB01`) switches locally across virtual switches and never hits the default gateway (`SURICATA-IPS01`).
* **Suricata Inline IPS is completely blind to intra-subnet Layer-2 communications**.
* *Compensatory Dependence*: Detection of same-subnet lateral movement relies entirely on host-based firewalls (iptables on DB01), database query audits, and endpoint telemetry agents (Sysmon).

---

## 7. Encrypted Traffic Payload Boundaries

* **Lack of SSL/TLS Decryption**:
  * `SURICATA-IPS01` does not perform active SSL/TLS decryption (man-in-the-middle proxying).
  * Payload signatures cannot inspect the contents of encrypted protocols:
    * SSH sessions (`TCP/22`) between `IT-ADMIN01` and `WEB01`.
    * HTTPS transactions (`TCP/443`) between endpoints and web applications.
    * Encrypted TLS tunnels (`TCP/11601`) established by Ligolo-ng.
* *Visibility Boundary*: Inspection on encrypted streams is limited to transport layer metadata (IP addresses, ports, timing, packet sizes) and unencrypted TLS handshake parameters (SNI, server certificates).

---

## 8. Stateless UDP Telemetry Transport Risks

* **Reliability Gap**:
  * Log transport from pfSense, Zeek, Web servers, MariaDB, and Postfix relies on Syslog over UDP directed to the SmartConnector (`10.10.40.4`).
  * UDP provides no delivery acknowledgment, flow control, or retransmission.
* **Buffer Overflow & Fragmentation**:
  * Heavy burst activity can saturate Linux kernel socket receive buffers on the SmartConnector host, causing silent packet drops.
  * Extended SQL queries emitted by MariaDB `SERVER_AUDIT` or long command-line strings from Linux Auditd can exceed the standard network MTU (1500 bytes), causing IP fragmentation or truncation.
* *Operational Boundary*: Forensic conclusions are bounded strictly to the events successfully received, parsed, and indexed within ArcSight Logger.
