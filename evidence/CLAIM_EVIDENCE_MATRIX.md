# Technical Claim-to-Evidence Matrix

This matrix establishes the verifiable link between every major architectural, defensive, and investigative claim made across the portfolio and its corresponding empirical evidence artifact.

---

## 1. Technical Claims & Supporting Evidence

| Technical Claim | Primary Evidence ID | Supporting Evidence | Evidence Type | Empirical Confidence Status |
| :--- | :---: | :---: | :---: | :---: |
| **All inter-zone traffic is forced through Suricata Inline IPS via Security Transit static routing.** | `ARCH-002` | `ARCH-001`, `DET-010` | `DIRECT` | **SUPPORTED** |
| **Same-L2 intra-subnet traffic bypasses Suricata Gateway and is shielded by host-based iptables on DB01.** | `ARCH-003` | `CASE004-E34` | `DIRECT` | **SUPPORTED** |
| **Suricata IPS successfully detected the external inbound malicious ZIP download.** | `DET-001` | `CASE001-E02` | `DIRECT` | **SUPPORTED** |
| **Workstation endpoint executed the HTA payload via living-off-the-land binary mshta.exe.** | `DET-002` | `INV-002`, `CASE001-E03` | `DIRECT` | **SUPPORTED** |
| **Outbound reverse shell callback succeeded and was established by spawned powershell.exe.** | `DET-003` | `INV-002`, `CASE001-E05` | `CORRELATED` | **SUPPORTED** |
| **ArcSight ESM correlated download, execution, and callback on IT-ADMIN01 within 20 minutes.** | `DET-004` | `CASE001-E07` | `CORRELATED` | **SUPPORTED** |
| **Phishing email lure was delivered to mailbox user01@soclab.test via Postfix.** | `INV-001` | `CASE001-E01` | `CONTEXTUAL` | **SUPPORTED** |
| **Adversary executed a burst of discovery commands over the active reverse shell.** | `DET-005` | `INV-003`, `CASE002-E10` | `DIRECT` | **SUPPORTED** |
| **Low-and-slow execution pacing would evade frequency threshold rule A05.** | `DET-005` | Rule Logic Spec | `ANALYTICAL` | **SUPPORTED** |
| **Adversary collected Firefox browser profile data using xcopy.exe to public staging directory.** | `DET-006` | `CASE003-E20` | `DIRECT` | **SUPPORTED** |
| **Harvested profile archive was exfiltrated via raw .NET TCP socket directly to external port 9999.** | `DET-007` | `INV-004`, `CASE003-E23` | `CORRELATED` | **SUPPORTED** |
| **Attacker recovered plaintext Linux credentials for user thanh from the stolen profile.** | `INV-005` | `CASE004-E31` | `INFERRED` (Offline) | **SUPPORTED INFERENCE** |
| **Attacker established an encrypted Ligolo-ng reverse tunnel through IT-ADMIN01.** | `DET-009` | `DET-008`, `CASE003-E25` | `DIRECT` | **SUPPORTED** |
| **Attacker authenticated to WEB01 over SSH via the tunnel using stolen credentials.** | `DET-010` | `INV-005`, `CASE004-E31` | `CORRELATED` | **SUPPORTED** |
| **Attacker scraped production database credentials using sudo docker exec on WEB01.** | `DET-011` | `INV-006`, `CASE004-E33` | `DIRECT` | **SUPPORTED** |
| **Attacker extracted employee table records from DB01 using mysqldump via whitelisted WEB01 IP.** | `DET-012` | `INV-007`, `CASE004-E35` | `DIRECT` | **SUPPORTED** |
| **Attacker exfiltrated 4.19 MB compressed database dump to external port 9999 using Netcat.** | `DET-013` | `INV-008`, `CASE005-E41` | `DIRECT` | **SUPPORTED** |
| **Rule A13 represents a scenario-dependent port match, not generic Data Loss Prevention (DLP).** | `DET-013` | Rule Logic Spec | `ANALYTICAL` | **SUPPORTED** |
| **Post-containment firewall rules on pfSense permanently blocked outbound egress on port 9999.** | `RESP-001` | `CASE005-E44` | `DIRECT` | **SUPPORTED** |

---

## 2. Confidence Level Definitions
* **`SUPPORTED`**: The technical claim is directly corroborated by low-level sensor logs, network packet captures, or verified SIEM alerts.
* **`SUPPORTED INFERENCE`**: The claim represents an analytical deduction backed by strong circumstantial telemetry, but lacking direct packet payload or memory capture (e.g., offline cryptanalysis on the attacker machine).
* **`PARTIALLY SUPPORTED`**: Evidence partially validates the behavior, but secondary parameters (such as plaintext password contents) were unlogged.
