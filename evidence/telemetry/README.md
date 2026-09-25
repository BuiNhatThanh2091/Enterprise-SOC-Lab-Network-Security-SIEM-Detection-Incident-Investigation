# Telemetry Pipeline & Normalization Evidence

This directory documents the empirical evidence proving the instrumentation, collection, and CEF normalization of multi-source telemetry in the Enterprise SOC Lab.

---

## Evidence Manifest: TEL-001
* **Evidence ID**: `TEL-001`
* **Title**: Microsoft Sysmon Event ID 1 & 3 XML Instrumentation
* **Evidence Classification**: `DIRECT`
* **Source Reference**: `Báo cáo đề tài SOC.pdf`, Trang 48–51, 62; `toan-bo-he-thong-kien_truc_lab.txt`, Mục 38–41.
* **Technical Fact Proven**: Demonstrates that Sysmon on `IT-ADMIN01` (`10.10.35.18`) was configured with explicit XML rules capturing SHA-256 process hashes, command-line arguments, parent process identifiers, and network connect sockets.
* **Sysmon XML Configuration Schema Snippet**:
  ```xml
  <Sysmon schemaversion="4.90">
    <EventFiltering>
      <RuleGroup name="ProcessCreation" groupRelation="or">
        <ProcessCreate onmatch="include">
          <CommandLine condition="contains">mshta</CommandLine>
          <CommandLine condition="contains">powershell</CommandLine>
          <CommandLine condition="contains">agent.exe</CommandLine>
          <CommandLine condition="contains">xcopy</CommandLine>
        </ProcessCreate>
      </RuleGroup>
      <RuleGroup name="NetworkConnect" groupRelation="or">
        <NetworkConnect onmatch="include">
          <DestinationPort condition="is">4444</DestinationPort>
          <DestinationPort condition="is">11601</DestinationPort>
          <DestinationPort condition="is">9999</DestinationPort>
        </NetworkConnect>
      </RuleGroup>
    </EventFiltering>
  </Sysmon>
  ```
* **CEF Mapping Yield**: `ProcessGuid` mapped to `deviceCustomString5` (`cs5`), `CommandLine` mapped to `deviceCustomString4` (`cs4`).

---

## Evidence Manifest: TEL-002
* **Evidence ID**: `TEL-002`
* **Title**: PowerShell ScriptBlock Logging (Event ID 4104)
* **Evidence Classification**: `DIRECT`
* **Source Reference**: `Báo cáo đề tài SOC.pdf`, Trang 52, 96; `toan-bo-he-thong-kien_truc_lab.txt`, Mục 41.
* **Technical Fact Proven**: Proves that Windows EventLog `Microsoft-Windows-PowerShell/Operational` Event ID 4104 was enabled via Local Group Policy, allowing ArcSight Logger to extract in-memory code blocks executed without binary drops.
* **Audit Policy Registry Verification**:
  ```text
  HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging:
    EnableScriptBlockLogging = 0x00000001 (DWORD: Enabled)
  ```
* **Sample Log Yield**: Captured de-obfuscated execution of `.NET` `System.Net.Sockets.TcpClient` and `Compress-Archive` in Case 003.

---

## Evidence Manifest: TEL-003
* **Evidence ID**: `TEL-003`
* **Title**: Suricata Inline IPS EVE JSON Stream (Generator ID 2002)
* **Evidence Classification**: `DIRECT`
* **Source Reference**: `Báo cáo đề tài SOC.pdf`, Trang 37–38, 62; `toan-bo-he-thong-kien_truc_lab.txt`, Mục 14, 18.
* **Technical Fact Proven**: Proves that Suricata on Security Transit forwards EVE JSON events via Syslog over TCP port `5521` to SmartConnector, preserving signature IDs (`cn1=1101002`, `cn1=1101021`) and flow byte counters.
* **Suricata EVE JSON Output Structure**:
  ```json
  {
    "timestamp": "2026-09-17T14:22:30.104218+0700",
    "flow_id": 1829038472910384,
    "event_type": "alert",
    "src_ip": "203.0.113.25",
    "src_port": 80,
    "dest_ip": "10.10.35.18",
    "dest_port": 49208,
    "proto": "TCP",
    "alert": {
      "action": "allowed",
      "gid": 1,
      "signature_id": 1101002,
      "rev": 1,
      "signature": "SOCLAB SUSPICIOUS Inbound Download from External Web",
      "category": "Potentially Bad Traffic",
      "severity": 2
    }
  }
  ```

---

## Evidence Manifest: TEL-004
* **Evidence ID**: `TEL-004`
* **Title**: MariaDB SERVER_AUDIT Plugin Configuration
* **Evidence Classification**: `DIRECT`
* **Source Reference**: `Báo cáo đề tài SOC.pdf`, Trang 44–45, 63; `toan-bo-he-thong-kien_truc_lab.txt`, Mục 27–28.
* **Technical Fact Proven**: Proves that MariaDB on `DB01` (`10.10.35.19`) was configured with the `SERVER_AUDIT` plugin logging all connection attempts and raw SQL queries to `/var/log/mysql/server_audit.log`, forwarded to SmartConnector UDP/5520 (Generator ID 2005).
* **Database Configuration File (`/etc/mysql/mariadb.conf.d/server_audit.cnf`)**:
  ```ini
  [mariadb]
  plugin_load_add = server_audit
  server_audit_logging = ON
  server_audit_events = CONNECT,QUERY
  server_audit_file_path = /var/log/mysql/server_audit.log
  server_audit_file_rotate_size = 100000000
  server_audit_file_rotations = 9
  ```
* **CEF Mapping**: Raw SQL query text mapped to `deviceCustomString3` (`cs3Label="Query"`).
