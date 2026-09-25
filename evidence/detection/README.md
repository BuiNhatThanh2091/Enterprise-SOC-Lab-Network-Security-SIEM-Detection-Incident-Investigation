# Detection Rule & Alert Evidence

This directory documents the empirical evidence proving the configuration and live firing of ArcSight ESM detection rules during the attack simulation exercise.

---

## Evidence Manifest: DET-001 (Rule A02)
* **Evidence ID**: `DET-001`
* **Rule Name**: `SOC-LAB A02 Suspicious External Web Download`
* **Severity**: `5 / 10 (Medium)`
* **Source Reference**: `Báo cáo đề tài SOC.pdf`, Trang 92, 114; `toan-bo-he-thong-kien_truc_lab.txt`, Mục 47.
* **ESM Rule Condition**:
  ```text
  (Device Product = Suricata IDS IPS) AND 
  (Device Custom Number 1 = 1101002) AND 
  (Source Address InSubnet 10.10.35.0/24)
  ```
* **Active Channel Alert Artifact**:
  ```text
  [ALERT] SOC-LAB A02 Suspicious External Web Download
  Source: 10.10.35.18:49208 | Target: 203.0.113.25:80
  Signature: SOCLAB SUSPICIOUS Inbound Download from External Web
  URI: /SecurityPatch_KB504991.zip | Action: allowed
  ```

---

## Evidence Manifest: DET-002 (Rule A03)
* **Evidence ID**: `DET-002`
* **Rule Name**: `SOC-LAB A03 Suspicious Script Execution`
* **Severity**: `7 / 10 (High)`
* **Source Reference**: `Báo cáo đề tài SOC.pdf`, Trang 93, 115; `toan-bo-he-thong-kien_truc_lab.txt`, Mục 48.
* **ESM Rule Condition**:
  ```text
  (Device Product = Microsoft-Windows-Sysmon) AND 
  (External ID = 1) AND 
  (Destination Process Name ENDSWITH "mshta.exe") AND 
  (Device Custom String 4 CONTAINS ".hta")
  ```
* **Active Channel Alert Artifact**:
  ```text
  [ALERT] SOC-LAB A03 Suspicious Script Execution
  Host: IT-ADMIN | User: IT-ADMIN\admin
  Process: C:\Windows\System32\mshta.exe
  CommandLine: mshta.exe "C:\Users\admin\Downloads\SecurityPatch_KB504991.hta"
  Parent: explorer.exe | GUID: {ecec360d-d71c-6aab-3400-000000001800}
  ```

---

## Evidence Manifest: DET-003 (Rule A04)
* **Evidence ID**: `DET-003`
* **Rule Name**: `SOC-LAB A04 Suspicious Outbound Callback`
* **Severity**: `7 / 10 (High)`
* **Source Reference**: `Báo cáo đề tài SOC.pdf`, Trang 94, 116; `toan-bo-he-thong-kien_truc_lab.txt`, Mục 49.
* **ESM Rule Condition**:
  ```text
  (Device Product = Zeek) AND 
  (Transport Protocol = TCP) AND 
  (Target Port = 4444) AND 
  (Source Address InSubnet 10.10.35.0/24)
  ```
* **Active Channel Alert Artifact**:
  ```text
  [ALERT] SOC-LAB A04 Suspicious Outbound Callback
  Source: 10.10.35.18:49211 | Target: 203.0.113.25:4444
  Protocol: TCP | ZeekUID: C9xKa811 | Duration: >1800s
  Volume Note: Suppressed from main triage via filter Name != A04*
  ```

---

## Evidence Manifest: DET-004 (Rule C01 — Composite Correlation)
* **Evidence ID**: `DET-004`
* **Rule Name**: `SOC-LAB C01 Initial Compromise Correlation`
* **Severity**: `9 / 10 (Critical / Incident P1)`
* **Source Reference**: `Báo cáo đề tài SOC.pdf`, Trang 108, 125; `toan-bo-he-thong-kien_truc_lab.txt`, Mục 55.
* **ESM Composite Join Condition**:
  ```text
  Stateful Rule Join:
    Trigger 1: Rule A02 (Ingress Download)
    Trigger 2: Rule A03 (Host Script Execution)
    Trigger 3: Rule A04 (Network Outbound Callback)
  Matching Entity: Source Address = 10.10.35.18 (Host: IT-ADMIN)
  Sliding Window: Delta t <= 20 minutes
  ```
* **Active Channel Alert Artifact**:
  ```text
  ================================================================================
  [CRITICAL INCIDENT] SOC-LAB C01 Initial Compromise Correlation
  Severity: 9 | Stage: Initial Access & Command and Control Foothold
  Compromised Entity: 10.10.35.18 (IT-ADMIN01)
  External Threat Actor: 203.0.113.25 (Kali)
  Causal Chain:
    1. A02 Download: SecurityPatch_KB504991.zip (T0 - 2m 30s)
    2. A03 Execution: mshta.exe -> cmd -> powershell (T0 - 1m 45s)
    3. A04 Callback: TCP/4444 Active Reverse Shell (T0 - 1m 10s)
  Action: Immediate Host Quarantine & Tier-3 Incident Mobilization
  ================================================================================
  ```

---

## Evidence Manifest: DET-005 (Rule A13)
* **Evidence ID**: `DET-005`
* **Rule Name**: `SOC-LAB A13 Suspicious DMZ External Transfer`
* **Severity**: `10 / 10 (Critical / Data Exfiltration)`
* **Source Reference**: `Báo cáo đề tài SOC.pdf`, Trang 106, 124; `toan-bo-he-thong-kien_truc_lab.txt`, Mục 54.
* **ESM Rule Condition**:
  ```text
  (Device Product = Suricata IDS IPS) AND 
  (Device Custom Number 1 = 1101021) AND 
  (Source Address = 10.10.34.13) AND 
  (Target Address = 203.0.113.25) AND 
  (Target Port = 9999)
  ```
* **Active Channel Alert Artifact**:
  ```text
  [CRITICAL EXFILTRATION] SOC-LAB A13 Suspicious DMZ External Transfer
  Source: 10.10.34.13:54210 (WEB01) | Target: 203.0.113.25:9999
  Bytes Transferred: 4,194,304 bytes (4.19 MB in 3.42s)
  Signature: SOCLAB SUSPICIOUS DMZ Netcat Outbound Transfer to Port 9999
  Action: allowed (Passive Mode) -> Triggered Manual Egress Blocking
  ```
