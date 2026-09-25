# Network Architecture

## 1. Public Network Model Overview

The network architecture of the Enterprise SOC Lab is engineered to enforce absolute traffic control between external entities, public services, and internal assets. By segregating functional requirements into dedicated physical and logical broadcast domains on VMware vSphere, the network establishes deterministic traffic flows where every inter-zone packet is subjected to mandatory inspection.

```text
                               EXTERNAL_NET (203.0.113.0/24)
                         [Simulated Public Internet / Adversary]
                                           │
                                           ▼ Ingress VIP / Egress
                                  +-----------------+
                                  |   PFSENSE-01    | (Perimeter Firewall / NAT)
                                  +--------+--------+
                                           │
                                           ▼ 10.10.36.0/24
                                 [SECURITY_TRANSIT]
                                           │
                                           ▼ Static Route Next-Hop
                                  +--------+--------+
                                  | SURICATA-IPS01  | (Inline IPS / Core L3 Router)
                                  +---+---------+---+
                                      │         │
                 ┌────────────────────┘         └───────────────────┐
                 │ 10.10.34.0/24                                    │ 10.10.35.0/24
                 ▼                                                  ▼
             [DMZ_NET]                                        [INTERNAL_NET]
     • WEB01 (HRMS Application)                        • DC01 (Active Directory & DNS)
     • MAIL01 (Enterprise Postfix Mail)                • DB01 (MariaDB Database Server)
                                                       • IT-ADMIN01 (Privileged Workstation)
                                                       • WIN10-01..03 (Corporate Desktops)

 ══════════════════════════════ DEDICATED ISOLATED PLANES ══════════════════════════════
               [LOGGING_NET (10.10.40.0/24)]        [MANAGEMENT_NET (10.10.21.0/24)]
               • SmartConnector (10.10.40.4)        • Bastion Jump Host (10.10.21.100)
               • ArcSight Logger (10.10.40.5)       • Out-of-band administrative NICs
```

---

## 2. Security Zones Specification

```text
┌──────────────────┬─────────────────┬──────────────────────────────────┬──────────────────────────────────────┐
│ Zone Name        │ CIDR Subnet     │ Trust Level & Access Policy      │ Typical Hosted Assets                │
├──────────────────┼─────────────────┼──────────────────────────────────┼──────────────────────────────────────┤
│ EXTERNAL_NET     │ 203.0.113.0/24  │ Zero Trust (Untrusted Internet)  │ KALI-ATTACKER, DNS-PUB01, Proxy, VIPs│
│ SECURITY_TRANSIT │ 10.10.36.0/24   │ Intermediate Inspection Plane    │ pfSense LAN01, Suricata Transit NIC  │
│ DMZ_NET          │ 10.10.34.0/24   │ Semi-Trusted (Public Services)   │ WEB01 (Frappe HRMS), MAIL01 (Postfix)│
│ INTERNAL_NET     │ 10.10.35.0/24   │ High Trust (Core Corporate)      │ DC01 (AD), DB01 (SQL), Workstations  │
│ LOGGING_NET      │ 10.10.40.0/24   │ Dedicated Telemetry Plane        │ SmartConnector, Logger, Logging NICs │
│ MANAGEMENT_NET   │ 10.10.21.0/24   │ Dedicated Administrative Plane   │ MGMT-JUMPHOST, Management NICs       │
└──────────────────┴─────────────────┴──────────────────────────────────┴──────────────────────────────────────┘
```

### Detailed Zone Breakdown

### 2.1. EXTERNAL_NET (`203.0.113.0/24`)
* **Purpose**: Simulates the untrusted public Internet. Acts as the staging area for adversary infrastructure, public DNS lookups, and web egress controls.
* **Assets**: `KALI-ATTACKER` (`203.0.113.25`), `DNS-PUB01` (`203.0.113.53`), `FORWARD-PROXY` (`203.0.113.252:8132`), and pfSense Virtual IPs (`203.0.113.13`, `203.0.113.14`).
* **Trust Relationship**: Completely untrusted. Inbound traffic is blocked by default and accepted only via explicit port forwarding to DMZ VIPs.
* **Security Controls**: Perimeter stateful packet filtering and DNAT translation on `PFSENSE-01`.
* **Telemetry**: pfSense CSV filterlog, BIND9 DNS query logs, Forward Proxy access logs.
* **Traffic Direction**: Inbound towards DMZ VIPs; outbound termination point for proxied internal web traffic.

### 2.2. SECURITY_TRANSIT (`10.10.36.0/24`)
* **Purpose**: An isolated point-to-point transit network connecting the internal interface of the perimeter firewall to the external interface of the inline IPS router.
* **Assets**: `PFSENSE-01` (`10.10.36.10` / labeled `LAN01`), `SURICATA-IPS01` (`10.10.36.11` / `ens256`).
* **Trust Relationship**: Controlled transit. No end-user devices or server applications may reside on this subnet.
* **Security Controls**: Non-routable broadcast domain; enforced static routes; NFQUEUE packet capture.
* **Telemetry**: Suricata transit flow logs (`eve.json`), Zeek passive metadata capture (`conn.log`).
* **Traffic Direction**: Bidirectional inter-zone transit (Perimeter $\leftrightarrow$ Core).

### 2.3. DMZ_NET (`10.10.34.0/24`)
* **Purpose**: Houses corporate services that must be accessible from external networks, isolated from internal assets.
* **Assets**: Web Application Server `WEB01` (`10.10.34.13`), Enterprise Mail Server `MAIL01` (`10.10.34.14`). Default gateway is `10.10.34.11` (`SURICATA-IPS01`).
* **Trust Relationship**: Semi-trusted. Inbound traffic from External is permitted only to designated application ports (HTTP/HTTPS, SMTP). Initiating outbound connections into `INTERNAL_NET` is denied by default, restricted exclusively to specific service dependencies.
* **Security Controls**: Suricata inline DPI, Linux Auditd process auditing, Postfix transport controls.
* **Telemetry**: Nginx access logs, Frappe application logs, Postfix mail logs, Linux auditd (`web_exec`).
* **Traffic Direction**: Inbound from External via DNAT; controlled outbound to `INTERNAL_NET` (LDAPS to DC01, MySQL to DB01).

### 2.4. INTERNAL_NET (`10.10.35.0/24`)
* **Purpose**: Hosts core business data, directory services, and corporate user workstations.
* **Assets**: Active Directory DC `DC01` (`10.10.35.12`), Database Server `DB01` (`10.10.35.19`), Workstations `WIN10-01..03` (`10.10.35.13`, `.16`, `.17`), Privileged Workstation `IT-ADMIN01` (`10.10.35.18`). Default gateway is `10.10.35.11` (`SURICATA-IPS01`).
* **Trust Relationship**: High trust. Direct inbound access from External is strictly blocked. Inbound access from DMZ is limited to explicit operational ports.
* **Security Controls**: Suricata inter-zone inspection, DB01 host-based iptables firewall, Active Directory GPO, Sysmon endpoint monitoring.
* **Telemetry**: Windows Security Event logs, Sysmon (Event 1, 3), PowerShell ScriptBlock (4104), MariaDB `SERVER_AUDIT` logs.
* **Traffic Direction**: Outbound to DMZ (HTTP/HTTPS to WEB01, SSH from IT-ADMIN01); outbound to External strictly via Forward Proxy.

### 2.5. LOGGING_NET (`10.10.40.0/24`)
* **Purpose**: An out-of-band network dedicated to the transmission of security event telemetry.
* **Assets**: `SMARTCONNECTOR` (`10.10.40.4`), `ARCSIGHT-LOGGER` (`10.10.40.5`), and dedicated secondary logging interfaces on all infrastructure components (`.40.13`, `.40.20`, `.40.21`, `.40.23`, `.40.113`, `.40.119`).
* **Trust Relationship**: Isolated operational plane.
* **Security Controls**: Non-routable network; **no default gateway** configured on connected interfaces to prevent routing loopbacks or bypass channels.
* **Telemetry**: Transports raw Syslog, Windows WEC events, and encrypted CEF SmartMessages over TLS (`TCP/443`).
* **Traffic Direction**: Ingress from source devices into SmartConnector; point-to-point TLS from SmartConnector to ArcSight Logger.

### 2.6. MANAGEMENT_NET (`10.10.21.0/24`)
* **Purpose**: An out-of-band network dedicated to administrative access for hypervisors, firewalls, and security sensors.
* **Assets**: `MGMT-JUMPHOST` (`10.10.21.100`), pfSense WebGUI (`10.10.21.10`), Suricata SSH (`10.10.21.11`), DNS-PUB01 SSH (`10.10.21.20`), SmartConnector MC (`10.10.21.31`).
* **Trust Relationship**: Administrative trust. Isolated from all production endpoints and data plane subnets.
* **Security Controls**: Out-of-band vSwitch isolation; SSH key-based authentication; management sessions restricted to bastion origin.
* **Telemetry**: SSH session logs and ArcSight Management Center audit logs.
* **Traffic Direction**: Admin workstation outward to infrastructure management interfaces.

---

## 3. The Security Transit Architecture

The **Security Transit** network (`10.10.36.0/24`) is not simply another IP subnet; it is a fundamental architectural choke point engineered to enforce mandatory packet inspection.

```text
                               THE BYPASS PROBLEM
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ TRADITIONAL / FLAWED SETUP:                                                           │
│ pfSense and Internal hosts share the same broadcast domain (e.g., 10.10.35.0/24).     │
│ -> pfSense resolves internal hosts via direct ARP.                                     │
│ -> An inline IPS placed in parallel can be bypassed by static routes or ARP poisoning. │
│ -> Traffic flows directly: External -> pfSense -> Internal Host (NO IPS INSPECTION!)   │
└────────────────────────────────────────────────────────────────────────────────────────┘

                               THE TRANSIT SOLUTION
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ SECURITY TRANSIT ARCHITECTURE:                                                         │
│ pfSense has NO interface in 10.10.35.0/24 or 10.10.34.0/24.                           │
│ -> pfSense is physically and logically confined to WAN and 10.10.36.0/24.              │
│ -> To reach 10.10.35.0/24, pfSense MUST route through Next-Hop 10.10.36.11 (Suricata).│
│ -> Suricata intercepts all forwarded packets via Linux Kernel NFQUEUE.                │
│ -> Packet reaches Internal/DMZ ONLY IF Suricata validates and re-injects it.           │
│ -> Return traffic must symmetrically traverse Suricata to reach pfSense (Stateful OK). │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### 3.1. Architectural Necessity & The Bypass Problem
If a perimeter firewall maintains a network interface directly on internal or DMZ broadcast domains:
1. The firewall can ARP directly for internal endpoints.
2. An inline IPS placed in the environment can be bypassed if routing tables are misconfigured or if host operating systems establish direct Layer-2 adjacencies.
3. Administrative error or rule omissions on the firewall immediately expose internal assets to the external network.

By placing a dedicated transit link between `PFSENSE-01` and `SURICATA-IPS01`:
* Direct Layer-2 broadcast adjacency between perimeter routing and protected assets is **physically and logically impossible**.
* All ingress packets destined for `10.10.34.0/24` or `10.10.35.0/24` must be handed off across the transit wire to `10.10.36.11`.
* `SURICATA-IPS01` controls the kernel forwarding table (`net.ipv4.ip_forward = 1`) and routes packets into userspace via `NFQUEUE`. Uninspected packets cannot physically cross from interface `ens256` (Transit) to `ens193` (Internal) or `ens225` (DMZ).

### 3.2. Return Traffic Behavior & Stateful Symmetry
Stateful inspection engines require bidirectional session visibility. If an ingress packet traverses an IPS but the egress response bypasses it, the IPS connection tracker experiences state desynchronization and drops legitimate connections.
* In this architecture, all protected hosts point their default gateways to Suricata (`10.10.34.11` for DMZ, `10.10.35.11` for Internal).
* Egress and return packets destined for External networks are routed through Suricata's kernel, evaluated via NFQUEUE in the reverse direction, forwarded out Suricata's transit interface (`10.10.36.11`), and received on pfSense's transit interface (`10.10.36.10`) for NAT translation.
* This guarantees **strict stateful symmetry** across both pfSense and Suricata.

### 3.3. Elimination of Multi-Homing Bypasses
Historical configurations in early lab prototypes featured a secondary external network card on the mail server. This configuration was explicitly dismantled:
* Multi-homing public-facing servers with both External (`203.0.113.x`) and Internal (`10.10.35.x`) interfaces creates an immediate routing bypass, allowing compromised internet-facing servers to bridge traffic directly into the internal network without traversing firewalls or IPS sensors.
* Current architecture enforces single-homed data plane attachments in the DMZ (`10.10.34.0/24`), requiring all inter-zone communication to route through the Security Transit choke point.

---

## 4. End-to-End Traffic Flows

### 4.1. Inbound Ingress Flow (External Client to DMZ Web Application)
```text
1. Client sends HTTP GET to public VIP: 203.0.113.13:80.
2. Ingress on pfSense WAN (203.0.113.11).
3. pfSense applies stateful firewall policy -> matches inbound allow rule.
4. pfSense executes DNAT: translates destination IP 203.0.113.13:80 to 10.10.34.13:80.
5. pfSense route lookup: 10.10.34.0/24 next-hop is GW_SURICATA (10.10.36.11).
6. Packet egresses pfSense LAN01 (10.10.36.10) into Security Transit (10.10.36.0/24).
7. Packet ingresses Suricata transit interface ens256 (10.10.36.11).
8. Linux kernel routing evaluates destination (10.10.34.13) -> egress interface ens225.
9. iptables FORWARD rule intercepts packet -> diverts to NFQUEUE (Queue 0).
10. Suricata userspace daemon performs stream reassembly and Deep Packet Inspection (DPI).
11. Packet passes inspection -> re-injected into kernel network stack.
12. Packet egresses ens225 (10.10.34.11) onto DMZ switch fabric.
13. Target host WEB01 (10.10.34.13) receives packet, processes HTTP request.
14. Return packet from WEB01 directed to default gateway (10.10.34.11).
15. Suricata tracks reverse flow state -> forwards out ens256 (10.10.36.11) to pfSense (10.10.36.10).
16. pfSense reverses DNAT -> transmits HTTP response back to external client.
```

### 4.2. Outbound Egress Flow (Internal Workstation to External Internet)
```text
1. Workstation WIN10-01 (10.10.35.13) initiates web connection to external server.
2. Client network settings route corporate web traffic via Forward Proxy (203.0.113.252:8132).
3. Packet sent to default gateway: 10.10.35.11 (Suricata Internal interface ens193).
4. Kernel routing matches destination (203.0.113.252) -> default route via 10.10.36.10.
5. iptables FORWARD rule diverts packet to NFQUEUE -> Suricata inspects outbound packet.
6. Packet passes inspection -> forwarded out ens256 (10.10.36.11) across Security Transit.
7. Packet arrives at pfSense Transit interface LAN01 (10.10.36.10).
8. pfSense checks egress filter rules:
   - Source: 10.10.35.0/24 (Note: matched explicitly, NOT via "LAN01 net" alias).
   - Destination: 203.0.113.252, Port: 8132 -> ALLOW.
   - Any attempt by malware to connect directly to external IPs on raw ports (e.g., TCP 4444, 11601, 9999)
     is dropped by pfSense egress filtering post-hardening.
9. pfSense applies Outbound NAT -> translates source IP to WAN IP (203.0.113.11).
10. Packet reaches Forward Proxy -> proxy fetches external web resource and returns stream.
```

### 4.3. Inter-Zone Flow (DMZ Web Server to Internal Database)
```text
1. WEB01 (10.10.34.13) requires employee data -> initiates MySQL query to DB01 (10.10.35.19:3306).
2. Packet sent to default gateway: 10.10.34.11 (Suricata DMZ interface ens225).
3. Suricata kernel matches route: 10.10.35.0/24 is directly connected on ens193.
4. iptables FORWARD rule sends packet to NFQUEUE -> Suricata inspects SQL connection.
5. Suricata verifies inter-zone policy (DMZ -> Internal port 3306 permitted for WEB01 IP).
6. Packet forwarded out ens193 (10.10.35.11) onto Internal switch fabric.
7. Packet arrives at DB01 (10.10.35.19).
8. DB01 host firewall (iptables) evaluates input rule:
   - Source: 10.10.34.13, Port: 3306 -> ACCEPT.
9. MariaDB processes query; SERVER_AUDIT logs the transaction.
10. Database response returns via 10.10.35.11 -> Suricata NFQUEUE -> ens225 -> WEB01.
```

---

## 5. East-West Intra-Subnet Traffic Limitation & Compensatory Controls

A critical architectural boundary documented in the project is the **Layer-2 intra-subnet communication boundary**.

```text
                        THE SAME-L2 VISIBILITY LIMITATION
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ Source: IT-ADMIN01 (10.10.35.18/24)  ───►  Target: DB01 (10.10.35.19/24)               │
│                                                                                        │
│ 1. Operating system identifies target IP 10.10.35.19 belongs to the local /24 subnet. │
│ 2. Windows issues ARP request for 10.10.35.19 MAC address.                             │
│ 3. Ethernet frame switches directly across virtual switch portgroup.                   │
│ 4. Frame NEVER reaches Default Gateway 10.10.35.11 (SURICATA-IPS01).                   │
│                                                                                        │
│ ARCHITECTURAL FACT:                                                                    │
│ Suricata Inline IPS CANNOT observe, inspect, or alert on intra-subnet L2 traffic.      │
│ Claiming "Suricata inspects all internal traffic" is technically false.                │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### Compensatory Security Controls for Intra-Subnet Isolation
Because the inline network gateway cannot inspect same-subnet frames, the architecture deploys four layers of compensatory host-based and passive controls:

1. **Host-Based Firewall Isolation (`DB01`)**:
   * An attacker on `IT-ADMIN01` (`10.10.35.18`) who attempts to connect directly to `DB01:3306` over Layer 2 is blocked at the destination kernel:
     ```bash
     sudo iptables -A INPUT -p tcp -s 10.10.34.13 --dport 3306 -j ACCEPT
     sudo iptables -A INPUT -p tcp --dport 3306 -j DROP
     ```
   * Result: Direct lateral database access across Layer 2 fails deterministically (`Connection timed out` / `Connection refused`).
2. **Database Engine Auditing (`DB01`)**:
   * MariaDB `SERVER_AUDIT` plugin captures all client connect events and query strings directly within the database daemon, ensuring unauthorized attempts generate audit records even if local firewalls were altered.
3. **Endpoint Process & Network Telemetry (`IT-ADMIN01`)**:
   * Microsoft Sysmon Event ID 1 captures command-line reconnaissance (`where ssh`, `netstat`).
   * Sysmon Event ID 3 captures local TCP connection attempts initiated by local processes, providing endpoint-side network visibility that perimeter firewalls miss.
4. **Passive Network Sensor Mirroring (`ZEEK-NDR01`)**:
   * Virtual switch port mirroring (SPAN) copies intra-subnet switch traffic to Zeek monitoring interfaces, providing metadata analysis (`conn.log`) independent of gateway routing.
