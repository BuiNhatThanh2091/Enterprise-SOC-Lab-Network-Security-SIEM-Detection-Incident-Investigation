# Architecture & Infrastructure Evidence

This directory documents the empirical evidence supporting the network segmentation, forced security routing, and compensatory host firewall architecture of the Enterprise SOC Lab.

---

## Evidence Manifest: ARCH-001
* **Evidence ID**: `ARCH-001`
* **Title**: Multi-Zone Network Segmentation Blueprint
* **Evidence Classification**: `DIRECT`
* **Source Reference**: `Báo cáo đề tài SOC.pdf`, Trang 23–25, 31; `toan-bo-he-thong-kien_truc_lab.txt`, Mục 1–3.
* **Technical Fact Proven**: Demonstrates that the enterprise environment is partitioned into six distinct Layer-2 broadcast domains on VMware vSphere virtual switches:
  * `EXTERNAL_NET`: `203.0.113.0/24` (WAN / Untrusted)
  * `SECURITY_TRANSIT`: `10.10.36.0/24` (Enforced Inspection Segment)
  * `DMZ_NET`: `10.10.34.0/24` (Public-Facing Services: Web & Mail)
  * `INTERNAL_NET`: `10.10.35.0/24` (Core Assets: AD, Database & Workstations)
  * `LOGGING_NET`: `10.10.40.0/24` (Isolated Telemetry & SIEM Plane)
  * `MANAGEMENT_NET`: `10.10.21.0/24` (Out-of-Band Bastion Plane)
* **Sanitized Visual Representation**:
  ```text
  [WAN: 203.0.113.0/24] ──► pfSense (WAN: 203.0.113.11 | Transit: 10.10.36.10)
                                      │
                         [SECURITY_TRANSIT: 10.10.36.0/24]
                                      │
                           Suricata Inline IPS (10.10.36.11)
                                      ├──► [DMZ: 10.10.34.0/24] (WEB01, MAIL01)
                                      └──► [INTERNAL: 10.10.35.0/24] (AD01, DB01, IT-ADMIN01)
  ```

---

## Evidence Manifest: ARCH-002
* **Evidence ID**: `ARCH-002`
* **Title**: Security Transit Forced Choke Point & Static Routing
* **Evidence Classification**: `DIRECT`
* **Source Reference**: `Báo cáo đề tài SOC.pdf`, Trang 27–29; `toan-bo-he-thong-kien_truc_lab.txt`, Mục 5, 13.
* **Technical Fact Proven**: Proves that pfSense possesses zero direct Layer-2 connections to the DMZ or Internal subnets. All inter-zone routing is forced through Gateway `GW_SURICATA` (`10.10.36.11`).
* **pfSense Routing Table Evidence**:
  ```text
  Destination        Gateway          Flags    Netif
  10.10.34.0/24      10.10.36.11      UGS      LAN01 (Transit)
  10.10.35.0/24      10.10.36.11      UGS      LAN01 (Transit)
  10.10.36.0/24      link#2           U        LAN01 (Transit)
  default            203.0.113.1      UGS      WAN
  ```
* **Suricata Kernel Forwarding Configuration**:
  ```bash
  # /etc/sysctl.d/99-suricata-router.conf
  net.ipv4.ip_forward = 1
  ```

---

## Evidence Manifest: ARCH-003
* **Evidence ID**: `ARCH-003`
* **Title**: Compensatory Host-based Firewall (`iptables` on `DB01`)
* **Evidence Classification**: `DIRECT`
* **Source Reference**: `Báo cáo đề tài SOC.pdf`, Trang 34, 57; `toan-bo-he-thong-kien_truc_lab.txt`, Mục 29, 43.
* **Technical Fact Proven**: Proves that because same-subnet traffic (`10.10.35.x`) bypasses Suricata at Layer 2, `DB01` utilizes local kernel `iptables` to block direct database connections from workstations while permitting only web application server `WEB01` (`10.10.34.13`).
* **DB01 Host Firewall Policy**:
  ```bash
  # iptables -S INPUT
  -P INPUT DROP
  -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
  -A INPUT -i lo -j ACCEPT
  -A INPUT -s 10.10.34.13/32 -p tcp -m tcp --dport 3306 -j ACCEPT
  -A INPUT -s 10.10.21.0/24 -p tcp -m tcp --dport 22 -j ACCEPT
  -A INPUT -p tcp -m tcp --dport 3306 -j LOG --log-prefix "IPTABLES-DROP: "
  -A INPUT -j DROP
  ```
