# Technical Documentation Index

## 1. Overview

This directory contains the authoritative, in-depth architectural and operational specifications for the **Enterprise SOC Lab**. The documentation is organized into modular engineering chapters that trace the system from high-level objectives down to packet inspection boundaries, telemetry normalization, SIEM correlation mechanics, and documented limitations.

---

## 2. Documentation Directory

| Document | Title & Core Focus | Primary Engineering Topics Covered |
| :--- | :--- | :--- |
| [**`01_PROJECT_OVERVIEW.md`**](file:///e:/project_ca_nhan/lab_cty/docs/01_PROJECT_OVERVIEW.md) | **Project Overview & Objectives** | Executive summary, core defensive pillars, laboratory scope, and validation methodology. |
| [**`02_SYSTEM_ARCHITECTURE.md`**](file:///e:/project_ca_nhan/lab_cty/docs/02_SYSTEM_ARCHITECTURE.md) | **7-Layer System Architecture** | Comprehensive overview of the 7 functional layers from hardware virtualization to SOC operations. |
| [**`03_NETWORK_ARCHITECTURE.md`**](file:///e:/project_ca_nhan/lab_cty/docs/03_NETWORK_ARCHITECTURE.md) | **Network Segmentation & Routing** | Multi-zone VLAN topology, routing tables, transit gateway enforcement, and L2 switching realities. |
| [**`04_SECURITY_ARCHITECTURE.md`**](file:///e:/project_ca_nhan/lab_cty/docs/04_SECURITY_ARCHITECTURE.md) | **Security Controls & Enforcements** | Defense-in-depth layout, perimeter filtering, inline IPS deployment, and compensatory controls. |
| [**`05_TELEMETRY_ARCHITECTURE.md`**](file:///e:/project_ca_nhan/lab_cty/docs/05_TELEMETRY_ARCHITECTURE.md) | **Full-Stack Telemetry Pipeline** | Sensor configurations, log collection agents, SmartConnector normalization, and CEF schemas. |
| [**`06_SOC_OPERATING_MODEL.md`**](file:///e:/project_ca_nhan/lab_cty/docs/06_SOC_OPERATING_MODEL.md) | **SOC Operating & Triage Model** | Tier-1 to Tier-3 escalation workflows, ESM Active Channel triage, and Logger deep search methodology. |
| [**`07_DETECTION_ENGINEERING.md`**](file:///e:/project_ca_nhan/lab_cty/docs/07_DETECTION_ENGINEERING.md) | **Detection Engineering Framework** | Detection engineering philosophy, event normalization models, and correlation dependencies. |
| [**`08_DETECTION_LIMITATIONS.md`**](file:///e:/project_ca_nhan/lab_cty/docs/08_DETECTION_LIMITATIONS.md) | **Operational Boundaries & Limits** | Scenario-dependent detection constraints, threshold blind spots, and architectural edge cases. |
| [**`TECHNOLOGY_STACK.md`**](file:///e:/project_ca_nhan/lab_cty/docs/TECHNOLOGY_STACK.md) | **Implemented Technology Matrix** | Detailed inventory of confirmed software versions, roles, and telemetry collection formats. |
| [**`ENGINEERING_DECISIONS.md`**](file:///e:/project_ca_nhan/lab_cty/docs/ENGINEERING_DECISIONS.md) | **Key Architectural Decisions** | Technical rationale behind Security Transit, inline IPS, decoupled SIEM, and dual-sensor monitoring. |
| [**`PUBLIC_PRIVATE_BOUNDARY.md`**](file:///e:/project_ca_nhan/lab_cty/docs/PUBLIC_PRIVATE_BOUNDARY.md) | **Public vs. Private Boundaries** | Classification matrix defining publication rules, sanitization policies, and IP abstraction. |

---

## 3. Recommended Reading Sequences

### High-Level Architectural Flow
```text
01_PROJECT_OVERVIEW.md ──► 02_SYSTEM_ARCHITECTURE.md ──► 03_NETWORK_ARCHITECTURE.md ──► 04_SECURITY_ARCHITECTURE.md
```

### Telemetry & Detection Engineering Flow
```text
05_TELEMETRY_ARCHITECTURE.md ──► 07_DETECTION_ENGINEERING.md ──► 08_DETECTION_LIMITATIONS.md ──► 06_SOC_OPERATING_MODEL.md
```

### Design Rationale & Governance Flow
```text
TECHNOLOGY_STACK.md ──► ENGINEERING_DECISIONS.md ──► PUBLIC_PRIVATE_BOUNDARY.md
```
