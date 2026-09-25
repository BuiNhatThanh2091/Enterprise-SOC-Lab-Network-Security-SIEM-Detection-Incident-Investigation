# Key Architecture & Engineering Decisions

## 1. Overview

The design of the **Enterprise SOC Lab** reflects intentional engineering trade-offs made during its implementation. Rather than deploying security products arbitrarily, every structural placement, data pipeline routing, and isolation boundary addresses specific operational requirements and real-world security challenges.

This document details five foundational architecture decisions implemented and verified in the laboratory.

---

## 2. Decision 1: Dedicated Security Transit Network

### Architectural Context
In traditional flat or simple routed networks, inter-zone traffic is frequently routed directly across virtual switches without traversing an inspection choke point. 

### Decision
Deploy an isolated intermediate broadcast domain—**SECURITY TRANSIT (`10.10.36.0/24`)**—positioned strictly between the perimeter firewall (`pfSense`, `10.10.36.10`) and the monitored enterprise networks (DMZ `10.10.34.0/24` and Internal `10.10.35.0/24`).

### Why It Exists
* **Deterministic Traffic Enforcement**: Inter-zone routing requires traffic to transit the gateway interfaces (`10.10.36.10` / `10.10.36.11`), guaranteeing that packets crossing between DMZ and Internal zones must pass through stateful inspection.
* **Separation of Perimeter Routing from Content Inspection**: Decouples pfSense Layer-3/4 packet filtering from compute-intensive Layer-7 deep packet inspection on Suricata.

---

## 3. Decision 2: Suricata Inline IPS Placement (NFQUEUE)

### Architectural Context
Network intrusion detection systems (NIDS) are commonly deployed in passive promiscuous SPAN/mirror mode. While passive monitoring generates zero latency, it cannot actively prevent payload delivery or terminate rogue sessions mid-stream.

### Decision
Position **Suricata** as an inline intrusion prevention system (IPS) using Linux `NFQUEUE` bridging inside the Security Transit segment (`10.10.36.11`).

### Why It Exists
* **Active Blocking Capability**: Enables the security engine to enforce drop actions (e.g., dropping malicious HTA downloads or terminating unauthorized egress connections) rather than merely generating delayed alerts.
* **Empirical Demonstration of Alert vs. Drop Realities**: As demonstrated in Case 005, configuring rule `A13` in `alert` mode allowed the exfiltration stream to complete before manual containment was initiated, proving the operational necessity of inline drop enforcement for high-confidence signatures.

---

## 4. Decision 3: Decoupled SIEM Operation (ArcSight ESM vs. ArcSight Logger)

### Architectural Context
Many SIEM implementations attempt to run high-volume raw event ingestion, long-term disk indexing, complex analytical searches, and real-time correlation on a single monolithic server, leading to severe resource contention, dropped events, and alert lag.

### Decision
Architecturally decouple the SIEM into two specialized, dedicated tiers:
* **ArcSight ESM (`10.10.21.10`)**: An in-memory real-time stateful correlation engine.
* **ArcSight Logger (`10.10.40.5`)**: A high-capacity, indexed, immutable forensic event repository.

### Why Both Exist
* **Resource Optimization**: ESM maintains only the active events required for sliding-window evaluation (e.g., the 20-minute join window for rule `C01`), operating with sub-second alert latency without disk I/O bottlenecks.
* **Forensic Search Freedom**: Analysts executing multi-pivot forensic investigations (e.g., querying broad process trees or extracting weeks of Postfix history) run heavy ad-hoc queries against Logger without impacting real-time alert triage on ESM.
* **Tamper-Evident Storage**: Logger provides verifiable SHA-256 event integrity hashing for regulatory compliance and legal-grade chain of custody.

---

## 5. Decision 4: Complementary Co-existence of Zeek and Suricata

### Architectural Context
Suricata and Zeek are often viewed as competing network security tools, leading some engineers to deploy only one.

### Decision
Deploy both **Suricata (Inline IPS)** and **Zeek (Passive NDR)** in parallel across the Security Transit segment.

### Why Both Are Used
* **Suricata (Signature & Pattern Matching)**: Excels at payload inspection, regular expression matching, and deterministic signature enforcement (e.g., detecting specific HTTP GET downloads via SID `1101002`).
* **Zeek (Protocol State & Session Metadata)**: Converts raw packet streams into structured behavioral metadata (`conn.log`, `dns.log`, `http.log`). Zeek provides long-term session duration tracking, cumulative byte counts (`orig_bytes`, `resp_bytes`), and unique connection identifiers (`ZeekUID`) that allow analysts to confirm persistent reverse shells (Rule `A04`) even when no known attack signature is triggered.

---

## 6. Decision 5: Public Network Abstraction & Sanitization Model

### Architectural Context
Directly publishing raw internal IP addresses, server hostnames, employee email addresses, and university infrastructure details in a public portfolio exposes real-world assets to external reconnaissance and violates institutional confidentiality.

### Decision
Abstract all infrastructure into canonical, standardized RFC 1918 (`10.10.0.0/16`) and RFC 5737 (`203.0.113.0/24`) public aliases while strictly preserving 100% of the physical network topology, interface routing relationships, and telemetry formats.

### Why It Exists
* **Security & Privacy**: Prevents information disclosure regarding internal IPAM and operational assets.
* **Technical Readability**: Standardized CIDR blocks (`10.10.34.0/24` for DMZ, `10.10.35.0/24` for Internal, `10.10.36.0/24` for Transit, `10.10.40.0/24` for Logging) make the architecture immediately intuitive for external reviewers and hiring managers.
