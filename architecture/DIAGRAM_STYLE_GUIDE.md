# Architecture Diagram Style Guide & Engineering Standards

## 1. Overview & Visual Philosophy
Visual documentation within the **Enterprise SOC Lab** must adhere to the same engineering rigor, consistency, and verifiable precision as the underlying code and network configurations. Diagrams serve as authoritative technical blueprints, not artistic embellishments.

Every diagram in the `architecture/` directory must answer a specific technical question without ambiguity, maintain strict alignment with the canonical Source of Truth, and comply 100% with the **Public Sanitization Specification**.

---

## 2. Diagram Hierarchy & Categorization

The visual architecture is structured across five distinct hierarchical levels. **No single diagram should attempt to depict all five levels simultaneously.**

```text
┌────────────────────────────────────────────────────────────────────────┐
│ LEVEL 1: Executive & Topology Blueprint (enterprise-soc-overview)       │
│ Question: What is the system? What are the zones? Where is SIEM?       │
├────────────────────────────────────────────────────────────────────────┤
│ LEVEL 2: Network Security & Traffic Trajectory (network-security-flow) │
│ Question: How do packets flow? Where is DPI? What is Security Transit?  │
├────────────────────────────────────────────────────────────────────────┤
│ LEVEL 3: Telemetry Pipeline & Normalization (telemetry-flow)           │
│ Question: How do logs travel from producing sensors into SIEM?         │
├────────────────────────────────────────────────────────────────────────┤
│ LEVEL 4: Detection & Correlation Dependency Graph (detection-flow)     │
│ Question: Which telemetry feeds which atomic rule? How does C01 join?  │
├────────────────────────────────────────────────────────────────────────┤
│ LEVEL 5: Incident Investigation Lifecycle (investigation-workflow)     │
│ Question: How does an analyst move from alert to verified containment? │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Canonical Naming Conventions

### 3.1. Network Broadcast Domains (Zones)
All zone identifiers must be written in **UPPERCASE** with standard public subnet annotations:
* `EXTERNAL_NET` (`203.0.113.0/24`, RFC 5737 TEST-NET-3)
* `SECURITY_TRANSIT` (`10.10.36.0/24`, RFC 1918)
* `DMZ_NET` (`10.10.34.0/24`, RFC 1918)
* `INTERNAL_NET` (`10.10.35.0/24`, RFC 1918)
* `LOGGING_NET` (`10.10.40.0/24`, RFC 1918)
* `MANAGEMENT_NET` (`10.10.21.0/24`, RFC 1918)

### 3.2. Core System Components
Component names must use standard, standardized uppercase acronyms:
* `PFSENSE`: Perimeter Stateful Firewall & NAT Gateway (`PFSENSE-01`)
* `SURICATA`: Core Layer-3 Router & Inline NFQUEUE IPS (`SURICATA-IPS01`)
* `ZEEK`: Passive Network Detection & Response Sensor (`ZEEK-NDR01`)
* `LOGGER`: Immutable Long-Term Forensics & Storage Store (`ArcSight Logger`)
* `ESM`: Real-Time Stateful In-Memory Correlation Engine (`ArcSight ESM`)
* `SMARTCONNECTOR`: CEF Normalization Engine & Log Receivers
* `WEB01`: Production DMZ Web Server (Frappe HRMS Docker Stack)
* `MAIL01`: Production DMZ Mail Gateway (Postfix / Dovecot)
* `DB01`: Production Internal Database Server (MariaDB 10.11)
* `AD01` / `DC01`: Internal Active Directory Domain Controller (`soclab.test`)
* `WIN10` / `IT-ADMIN01`: Internal Workstations

---

## 4. Flow Direction & Layout Conventions

To preserve intuitive cognitive reading patterns across documentation:
1. **Network Data Flow Diagrams**:
   * Orient primarily from **Top to Bottom** (Ingress / Egress) or **Left to Right** (Client $\rightarrow$ DMZ $\rightarrow$ Internal Core).
   * Inbound traffic traverses perimeter before hitting internal segments.
2. **Telemetry Pipeline Diagrams**:
   * Orient strictly from **Top to Bottom**:
     `Log Sources (Top) ──► SmartConnectors (Mid) ──► Storage & SIEM (Bottom)`
3. **Investigation Workflow Diagrams**:
   * Orient strictly from **Top to Bottom**:
     `Alert (Top) ──► Triage ──► Logger Pivot ──► Timeline ──► Containment (Bottom)`
4. **Arrowhead Semantics**:
   * Solid arrows (`-->`): Active, inline, or direct physical/logical data traffic.
   * Dashed arrows (`-.->`): Passive SPAN/mirror traffic, out-of-band telemetry, or evidentiary pivots.
   * Bold arrows (`==>`): High-priority correlation joins or critical state transitions.

---

## 5. Visual Styling & Color Palette

Diagrams utilize semantic color coding designed for high contrast, accessibility, and readability across both light and dark markdown themes:

| Semantic Classification | Palette Hex Codes | Intended Element Scope |
| :--- | :--- | :--- |
| **Untrusted / External** | `fill: #ffebee, stroke: #c62828` (Red) | External threat actor, malicious URLs, untrusted WAN. |
| **Perimeter & Transit** | `fill: #fff3e0, stroke: #e65100` (Orange) | pfSense firewall, Security Transit link. |
| **Inspection & NDR** | `fill: #e8f5e9, stroke: #2e7d32` (Green) | Suricata Inline IPS, Zeek NDR, packet filtering. |
| **Enterprise Internal** | `fill: #e1f5fe, stroke: #0288d1` (Blue) | Internal endpoints, Active Directory, DMZ servers. |
| **Telemetry & SIEM** | `fill: #f3e5f5, stroke: #7b1fa2` (Purple) | SmartConnectors, CEF normalization, ArcSight Logger. |
| **Correlation & Alert** | `fill: #fce4ec, stroke: #d81b60` (Pink/Magenta) | In-memory rules, composite join `C01`, Active Channels. |

---

## 6. Public Sanitization & Validation Checklist

Before any diagram (`.mmd` or `.svg`) is approved for public release, verify that:
* [x] **Zero Private Addressing**: No occurrence of real internal subnets or VMware vSphere internal naming.
* [x] **Zero Plaintext Credentials**: No real production passwords, API tokens, or SSH private keys.
* [x] **No Personal Identifiers**: Student intern names, instructor identities, and internal email domains replaced with public tokens (`user01@soclab.test`).
* [x] **Explicit Layer-2 Acknowledgment**: Diagrams depicting network traffic must clearly acknowledge the same-L2 direct switching bypass for hosts sharing the `10.10.35.0/24` subnet.
* [x] **Dual Format Availability**: Every architecture visual must exist as both editable plain-text Mermaid (`.mmd`) and pre-rendered vector graphic (`.svg`).
