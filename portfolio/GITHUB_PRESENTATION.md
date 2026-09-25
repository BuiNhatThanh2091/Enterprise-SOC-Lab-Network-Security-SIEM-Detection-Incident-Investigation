# GitHub Presentation & Repository Showcase Guide

## 1. The First 30 Seconds: Immediate Visual & Technical Impact

When a technical recruiter, hiring manager, or senior security engineer clicks into this GitHub repository, they must grasp the core technical value within 30 seconds without having to scroll through dense walls of text.

### Critical Visual Elements in the Opening Viewport
1. **Clear Project Header**:
   * Title: `Enterprise SOC Lab: Network Security, SIEM Detection & Incident Investigation`
   * Subtitle: A factual, hype-free description stating the integration of network security, inline IPS, endpoint auditing, SIEM correlation, and evidence-driven investigation.
2. **Hero Architecture Graphic**:
   * The standalone vector diagram [`architecture/enterprise-soc-overview.svg`](file:///e:/project_ca_nhan/lab_cty/architecture/enterprise-soc-overview.svg) renders immediately, visually establishing the 5 segmented zones, security transit choke point, and decoupled SIEM layout.
3. **Project at a Glance Matrix**:
   * A concise table displaying confirmed technologies across 12 infrastructure layers (pfSense, Suricata, Zeek, Sysmon, Active Directory, Postfix, MariaDB, Auditd, ArcSight ESM, ArcSight Logger, Kali).
4. **Immediate Portfolio Numbers (Factual)**:
   * 5 Segmented Network Zones
   * 13 Atomic Detections (`A01`–`A13`) + 1 Multi-Source Correlation (`C01`)
   * 5 Comprehensive Incident Investigation Case Studies
   * 23 Curated Technical Evidence Manifests
   * 3 Documented Demonstration & Investigation Videos (YouTube Unlisted: Attack Simulation, Full Investigation, Supplementary Investigation)

---

## 2. The First 3 Minutes: The Recommended Engineering Reading Path

To lead a reviewer through the logical engineering story rather than a disjointed collection of tools, direct them through this sequential reading path:

```text
  1. ROOT README         ──► Executive overview, hero diagram, technology summary, limitations.
         │
  2. ARCHITECTURE        ──► Level 1 Overview & Level 2 Network Security Flow (Transit routing & L2 bypass).
         │
  3. TELEMETRY           ──► Full-Stack pipeline: Sysmon, Postfix, Suricata, Auditd -> SmartConnector (CEF).
         │
  4. DETECTION           ──► Detection Engineering Hub: Atomic rules A01-A13 & Composite Correlation C01.
         │
  5. INVESTIGATION       ──► Read Case 001 (Initial Compromise) & Case 004 (Lateral Movement & DB Dump).
         │
  6. EVIDENCE            ──► Inspect Claim-to-Evidence Matrix & verified log manifests (Process trees, CEF).
         │
  7. DEMONSTRATION       ──► Review Red Team simulation walkthroughs & Blue Team SOC investigation logs.
```

### Why This Sequence Tells the Engineering Story
* **Architecture First**: Demonstrates that the candidate understands network boundaries and traffic routing before attempting detection.
* **Telemetry Second**: Shows how raw packets and system calls are parsed into standardized SIEM schemas (CEF).
* **Detection Third**: Establishes how normalized telemetry is transformed into actionable alert logic.
* **Investigation Fourth**: Proves that the candidate can follow an alert through to deep forensic root-cause analysis.
* **Evidence & Demonstration Last**: Provides unassailable proof that every technical claim was empirically verified.

---

## 3. GitHub README Structural Layout

The repository root [`README.md`](file:///e:/project_ca_nhan/lab_cty/README.md) follows this verified structural hierarchy:

```markdown
1. Project Title & Executive Subtitle
2. Architecture Overview (Hero SVG Graphic)
3. Project at a Glance (12-Row Technology Implementation Matrix)
4. Security Architecture Summary
   • Enforced Traffic Path (Transit Choke Point & L2 Bypass Defense)
   • Decoupled SIEM Telemetry Pipeline (Logger vs. ESM)
5. What This Project Demonstrates (Verified Capabilities)
6. Detection Engineering Portfolio (Table of Rules A01–A13, C01 with Links)
7. Incident Investigation Case Studies (Previews of Cases 001–005)
8. Demonstrations & Media (Simulation & Investigation Video Guides)
9. Engineering Workflow (7-Step Lifecycle Diagram)
10. Recommended Reading Path (Fast Path vs. Deep Technical Path)
11. Known Limitations (Transparent Technical Edge Cases)
12. Public-Safe Design Statement (Sanitization & Public IPAM Model)
13. Repository Structure (Clean Directory Tree)
14. Project Status (Factual Milestone Table)
```

---

## 4. Video Demonstration Strategy: YouTube Unlisted

Long-form technical demonstrations are hosted externally on **YouTube as Unlisted videos**. GitHub provides the technical context, case study, evidence mapping, and navigation to each demonstration.

### Why Unlisted YouTube?
* **Suitable for Long-Form Walkthroughs**: Supports full 5- to 12-minute technical demonstrations and screen recordings at high resolutions (1080p/60fps).
* **Avoids Repository Bloat**: Prevents multi-gigabyte video binaries from polluting Git history and slowing repository cloning.
* **Direct Evaluator Access**: Keeps technical demonstrations directly accessible to hiring managers and interviewers via direct links inside case studies.
* **Focus on Engineering Evidence**: Allows the GitHub repository to remain strictly focused on documentation, schemas, code, and curated evidence artifacts.
* **Search Discovery Suppression**: Prevents lab recordings from being indexed in public YouTube search or recommendation algorithms.

> [!CAUTION]
> **Privacy Notice**: Unlisted YouTube links do **not** provide cryptographic access control or enterprise privacy; anyone with the link can view the video. Therefore, all screen captures must undergo frame-by-frame verification via [`media/VIDEO_SANITIZATION_CHECKLIST.md`](file:///e:/project_ca_nhan/lab_cty/media/VIDEO_SANITIZATION_CHECKLIST.md) before upload.

---

## 5. Repository Short Descriptions (For GitHub About Section)


Depending on the specific job focus, select one of these concise, factual descriptions for the GitHub repository "About" field (under 200 characters):

### Option A — Network Security & SIEM Focus
> Hands-on SOC lab integrating multi-zone network segmentation, pfSense routing, Suricata inline IPS, full-stack telemetry, and ArcSight ESM/Logger correlation.

### Option B — Detection Engineering & Incident Investigation Focus
> Detection engineering and forensic investigation lab featuring 13 atomic rules, multi-source ESM correlation (C01), and 5 evidence-driven case studies.

### Option C — Comprehensive SOC Systems Focus
> Enterprise-style SOC laboratory integrating network defense, endpoint auditing (Sysmon/Auditd), SIEM correlation, attack simulation, and incident investigation.

---

## 5. Professional Social Media / Portfolio Showcase Descriptions

Use these structured descriptions for a personal portfolio website, LinkedIn featured project, or technical blog post:

### Comprehensive Showcase Narrative
```text
Project: Enterprise SOC Lab: Network Security, SIEM Detection & Incident Investigation

I designed, implemented, and empirically validated an enterprise-style security operations and architecture laboratory to study how network security controls, full-stack telemetry, and SIEM correlation operate together during an intrusion.

Key Engineering Highlights:
• Architecture & Network Security: Implemented multi-zone segmentation (DMZ, Internal, Transit, Logging) on VMware ESXi, routing inter-zone traffic through a Security Transit segment enforcing pfSense stateful firewalling, Suricata inline IPS (NFQUEUE), and Zeek NDR monitoring.
• Compensatory Controls: Analyzed hardware-level Layer-2 switching bypasses for intra-subnet communications and deployed host-based iptables on database server DB01 as a compensatory defense.
• Telemetry & Normalization: Engineered a centralized telemetry pipeline ingesting Windows Sysmon (XML), PowerShell ScriptBlock (4104), Linux Auditd, MariaDB SERVER_AUDIT, and Postfix logs via ArcSight SmartConnector into Common Event Format (CEF).
• Decoupled SIEM: Structured the SIEM into two dedicated tiers: ArcSight Logger for immutable, tamper-evident long-term retention (SHA-256) and ArcSight ESM for sub-second, in-memory real-time correlation.
• Detection Engineering: Authored and validated 13 atomic detection rules (A01–A13) and a composite correlation rule (C01) joining perimeter ingress, host execution, and network C2 callback across a 20-minute sliding window.
• Forensic Investigation: Reconstructed end-to-end attack chains across 5 multi-stage incident case studies, formulating testable hypotheses, executing targeted Logger queries, expanding process trees via ProcessGuid, and validating firewall containment.
```
