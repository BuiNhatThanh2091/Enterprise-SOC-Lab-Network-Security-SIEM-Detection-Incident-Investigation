# Architecture Diagrams Specification

This directory houses the authoritative architectural diagrams for the **Enterprise SOC Lab: Network Security, SIEM Detection & Incident Investigation**. All diagrams are maintained as plain-text **Mermaid (`.mmd`)** source files, enabling automated rendering, version-controlled diffs, and embedding across portfolio and technical documentation.

---

## 1. Diagram Directory & Functional Classification

| Diagram Files (MMD / SVG) | Classification | Primary Scope & Engineering Focus |
| :--- | :--- | :--- |
| **`enterprise-soc-overview.mmd`**<br/>[`enterprise-soc-overview.svg`](file:///e:/project_ca_nhan/lab_cty/architecture/enterprise-soc-overview.svg) | **High-Level System View (Level 1)** | Comprehensive topological overview illustrating all six network zones, perimeter security, core inline inspection, passive monitoring, telemetry pipeline, and management planes. |
| **`network-security-flow.mmd`**<br/>[`network-security-flow.svg`](file:///e:/project_ca_nhan/lab_cty/architecture/network-security-flow.svg) | **Data & Inspection Flow (Level 2)** | Packet-level traffic trajectory detailing ingress NAT, forced Security Transit traversal, inline Suricata DPI, stateful return symmetry, and the intra-subnet Layer-2 direct switching blind spot with host-based iptables defense. |
| **`telemetry-flow.mmd`**<br/>[`telemetry-flow.svg`](file:///e:/project_ca_nhan/lab_cty/architecture/telemetry-flow.svg) | **Telemetry & SIEM Pipeline (Level 3)** | Full-fidelity log transmission pipeline showing 8 confirmed source groups, SmartConnector listener ports/Generator IDs, CEF normalization, storage immutability in ArcSight Logger, real-time correlation in ArcSight ESM, and SOC closed-loop response. |
| **`detection-flow.mmd`**<br/>[`detection-flow.svg`](file:///e:/project_ca_nhan/lab_cty/architecture/detection-flow.svg) | **Detection & Correlation Graph (Level 4)** | Complete dependency mapping from 7 telemetry sources into 13 atomic rules (A01–A13) and composite multi-source correlation rule (C01), leading to incident dispatch and forensic drill-down. |
| **`investigation-workflow.mmd`**<br/>[`investigation-workflow.svg`](file:///e:/project_ca_nhan/lab_cty/architecture/investigation-workflow.svg) | **Investigation Workflow (Level 5)** | Standard operating procedure showing closed-loop SOC investigation: Real-time alert triage, hypothesis formulation, deep Logger search, cross-telemetry pivoting, timeline reconstruction, scope containment, and detection improvement. |

---

## 2. Recommended Diagram Reading Order

For an optimal understanding of the laboratory, review the diagrams in this logical progression:
1. [**`enterprise-soc-overview.svg`**](file:///e:/project_ca_nhan/lab_cty/architecture/enterprise-soc-overview.svg) (**Level 1**): Understand the physical zones, perimeter placement, and core component relationships.
2. [**`network-security-flow.svg`**](file:///e:/project_ca_nhan/lab_cty/architecture/network-security-flow.svg) (**Level 2**): Examine how packets move through pfSense and Suricata, and where Layer-2 switching bypasses occur.
3. [**`telemetry-flow.svg`**](file:///e:/project_ca_nhan/lab_cty/architecture/telemetry-flow.svg) (**Level 3**): Follow how raw host and network events are ingested, normalized via CEF, and dispatched to Logger and ESM.
4. [**`detection-flow.svg`**](file:///e:/project_ca_nhan/lab_cty/architecture/detection-flow.svg) (**Level 4**): Trace how normalized events trigger atomic rules A01–A13 and join into composite correlation rule C01.
5. [**`investigation-workflow.svg`**](file:///e:/project_ca_nhan/lab_cty/architecture/investigation-workflow.svg) (**Level 5**): Understand the SOC analyst's cognitive and technical process during incident triage.

---

## 3. Diagram Descriptions & Interpretation Guide


### 2.1. High-Level View: `enterprise-soc-overview.mmd`
* **Purpose**: Serves as the executive technical blueprint of the entire laboratory.
* **Key Elements Represented**:
  * The six core broadcast domains: `EXTERNAL_NET` (`203.0.113.0/24`), `SECURITY_TRANSIT` (`10.10.36.0/24`), `DMZ_NET` (`10.10.34.0/24`), `INTERNAL_NET` (`10.10.35.0/24`), `LOGGING_NET` (`10.10.40.0/24`), and `MANAGEMENT_NET` (`10.10.21.0/24`).
  * Inter-zone boundaries connecting the perimeter firewall (`PFSENSE-01`) through the transit segment to `SURICATA-IPS01`.
  * Physical and logical separation of the Telemetry/Logging Plane from production business data paths.
  * Out-of-band administrative access anchored from the bastion jump host (`MGMT-JUMPHOST`).

### 2.2. Traffic & Security Flow: `network-security-flow.mmd`
* **Purpose**: Demonstrates engineering rigor by detailing how network packets traverse the security stack, explicitly highlighting both enforced choke points and hardware-level blind spots.
* **Key Elements Represented**:
  * **Ingress Data Path**: External client $\rightarrow$ pfSense WAN $\rightarrow$ DNAT $\rightarrow$ Security Transit $\rightarrow$ Suricata NFQUEUE $\rightarrow$ DMZ Web Server.
  * **Stateful Return Path**: Shows that return packets from DMZ/Internal symmetrically re-traverse Suricata before hitting pfSense, preserving TCP state tables.
  * **Egress Data Path**: Shows outbound connections from internal endpoints traversing Suricata and pfSense, directed strictly toward the Forward Proxy (`:8132`).
  * **Intra-Subnet Layer-2 Limitation**: Accurately depicts that same-subnet communications (e.g., `IT-ADMIN01` $\rightarrow$ `DB01`) switch directly over virtual switch fabric without hitting the default gateway. Illustrates the compensatory host-based `iptables` firewall on `DB01` that drops unauthorized local connections.

### 2.3. Telemetry & SIEM Pipeline: `telemetry-flow.mmd`
* **Purpose**: Illustrates the end-to-end event data pipeline from origin to SOC investigation.
* **Key Elements Represented**:
  * 8 confirmed telemetry sources: pfSense, Suricata, Zeek, Web (Nginx/Auditd), MariaDB, Postfix, BIND9, and Windows WEC.
  * Dedicated listener processes on SmartConnector (`10.10.40.4`) mapped by Generator IDs (2002–2009).
  * CEF field mapping preserving vital correlation parameters (`ProcessGuid`, `QueueID`, `ZeekUID`, `FlowID`).
  * Structural decoupling between **ArcSight Logger** (immutable raw storage and forensic query engine) and **ArcSight ESM** (in-memory real-time rules engine and Active Channels).
  * Closed-loop SOC workflow: Alert Triage $\rightarrow$ Deep Logger Pivoting $\rightarrow$ Containment & Hardening.

### 2.4. Detection & Correlation Flow: `detection-flow.mmd`
* **Purpose**: Maps the full detection graph, demonstrating how low-level events feed atomic detection rules and converge into multi-source composite incident alerts.
* **Key Elements Represented**:
  * Telemetry source-to-rule linkages: Postfix ($\rightarrow$ `A01`), Suricata ($\rightarrow$ `A02`, `A10`, `A13`), Sysmon ($\rightarrow$ `A03`, `A05`, `A06`, `A08`, `A09`), Zeek ($\rightarrow$ `A04`, `A09`), PowerShell ($\rightarrow$ `A07`, `A08`), Auditd ($\rightarrow$ `A11`), and MariaDB Audit ($\rightarrow$ `A12`).
  * ArcSight ESM Composite Correlation (`C01`): Joins perimeter ingress (`A02`), endpoint execution (`A03`), and network C2 callback (`A04`) on entity key `10.10.35.18` within $\Delta t \le 20\text{ min}$.
  * Incident drill-down and investigation pivot paths linking the initial P1 alert to subsequent lateral movement, privilege escalation, database collection, and exfiltration detections.

### 2.5. Incident Investigation Workflow: `investigation-workflow.mmd`
* **Purpose**: Details the procedural lifecycle of incident investigation within the SOC, illustrating how an alert triggers hypotheses, forensic Logger searches, multi-source pivoting, and validated containment.
* **Key Elements Represented**:
  * Six operational phases: Detection & Initial Triage, Hypothesis & Evidence Gathering, Logger Forensic Search & Cross-Telemetry Pivot, Timeline & Attack Reconstruction, Scope Assessment & Containment, and Post-Incident Detection Engineering.
  * Bidirectional relationship between high-level ESM alerts and low-level Logger search queries.
  * Clear criteria for hypothesis validation, evidence classification, and containment verification.

---

## 3. Why Public Aliases & Sanitized IP Ranges Are Used

All diagrams in this directory intentionally utilize **public sanitized IP addressing and asset tags**:
1. **Confidentiality & Infrastructure Masking**: Prevents exposing internal private subnets, hypervisor naming conventions, or specific host environments associated with the author's original laboratory environment.
2. **RFC Compliance**:
   * External Internet simulation utilizes **RFC 5737 (`203.0.113.0/24` - TEST-NET-3)**, standardizing documentation and preventing accidental conflict with routable public networks.
   * Internal subnets utilize standard enterprise **RFC 1918 (`10.10.0.0/16`)** addressing.
3. **Isomorphic Mapping**:
   * The public addressing maintains an isomorphic 1-to-1 structural mapping with the original infrastructure topology, preserving all subnet boundaries, gateway relationships, firewall rules, and SIEM correlation conditions without distortion.
