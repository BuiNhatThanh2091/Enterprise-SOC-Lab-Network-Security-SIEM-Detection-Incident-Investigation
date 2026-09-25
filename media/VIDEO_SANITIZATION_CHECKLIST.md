# Pre-Upload Video Sanitization & Security Checklist

## 1. Overview & Policy

To preserve the confidentiality of enterprise, academic, and personal data, all screen recordings and demonstration videos intended for hosting on **YouTube (Unlisted)** must undergo a mandatory frame-by-frame sanitization audit prior to upload.

> [!CAUTION]
> **UNLISTED IS NOT EQUIVALENT TO PRIVATE**  
> Anyone with the link can view an Unlisted YouTube video. Setting a video to Unlisted prevents it from appearing in search results, channel feeds, or recommendations, but provides **zero technical access control or cryptographic privacy**. If sensitive operational data or credentials are visible for even a single frame, the video **must not be uploaded** until redacted or re-recorded.

---

## 2. Four-Pass Review Methodology

Before approving any video for upload, complete this four-pass audit sequence:

```text
┌─────────────────────────┬────────────────────────────────────────────────────────────────────────┐
│ REVIEW PASS             │ MANDATORY AUDIT OBJECTIVE & FOCUS                                      │
├─────────────────────────┼────────────────────────────────────────────────────────────────────────┤
│ Pass 1: Normal Watch    │ Watch the video end-to-end at normal speed to evaluate flow, timing,   │
│                         │ clarity, and consistency with repository case studies.                 │
├─────────────────────────┼────────────────────────────────────────────────────────────────────────┤
│ Pass 2: Security Scan   │ Watch with the sole purpose of catching visual anomalies, background   │
│                         │ windows, prompts, and popups.                                          │
├─────────────────────────┼────────────────────────────────────────────────────────────────────────┤
│ Pass 3: Critical Pause  │ Pause every transition to inspect: network configurations, terminal    │
│                         │ outputs, SIEM query grids, browser bars, and firewall screens.         │
├─────────────────────────┼────────────────────────────────────────────────────────────────────────┤
│ Pass 4: Audio Audit     │ Listen to narration/audio to ensure no real IPs, usernames, domains,   │
│                         │ or organizational names are spoken.                                    │
└─────────────────────────┴────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Comprehensive Inspection Checklists

### 3.1. Network Addressing & Infrastructure
* [ ] **No Real Internal IP Addresses**: Zero instances of internal production subnets or private LANs. All displayed IPs must match normalized public aliases (`10.10.x.x` or `203.0.113.x`).
* [ ] **No Real Subnet Masks / Default Gateways**: Verify interface IP configurations in terminal outputs and firewall dashboards.
* [ ] **No Sensitive Public IPs**: Ensure author's residential public IP address or VPN egress IP is not exposed.
* [ ] **No Real DNS Server IPs**: Confirm DNS resolvers reflect lab values (`10.10.35.12` or synthetic upstream).

### 3.2. Hostnames, Usernames & Identity
* [ ] **No Real Hostnames**: Ensure computer names match standardized tags (`IT-ADMIN01`, `WEB01`, `DB01`, `DC01`, `PFSENSE-01`, `SURICATA-IPS01`).
* [ ] **No Real Usernames**: Confirm OS user accounts reflect generic tags (`admin`, `user01`, `thanh`).
* [ ] **No Real Corporate / Academic Domains**: All email addresses and domains must use `soclab.test` or `update.kali.test`.
* [ ] **Window Titles & Taskbars**: Check application title bars, taskbar buttons, and minimized application tabs for personal identifiers.
* [ ] **Shell & Terminal Prompts**: Inspect Bash/PowerShell prompts (e.g., `PS C:\Users\<name>>` or `user@hostname:~$`).

### 3.3. Credentials, Secrets & Tokens
* [ ] **No Plaintext Passwords**: Passwords in command lines, config files, or browser password managers must be masked or synthetic (`P@ssw0rd2024!_DEMO`).
* [ ] **No Cryptographic Keys**: No SSH private keys (`id_rsa`), SSL certificates (`.pfx`, `.key`), or `BEGIN PRIVATE KEY` blocks.
* [ ] **No API Keys / Session Tokens**: No active bearer tokens, cookies, or JWT headers displayed.
* [ ] **No Database Connection Strings**: Check environment files (`.env`) for live production passwords.

### 3.4. Filesystem Paths & Desktop Environment
* [ ] **No Personal User Paths**: Check Windows paths (e.g., `C:\Users\<real_name>\`) and Linux paths (`/home/<real_name>/`).
* [ ] **No Real Organization Paths**: Check shared drives or project directories (e.g., `E:\company_project\`).
* [ ] **Desktop & File Explorer**: Confirm desktop icons, recent files, and explorer quick-access lists contain no private documents.
* [ ] **Hypervisor / VM Console Headers**: Check VMware Workstation / vSphere client titles for host server names or internal cluster IPs.

### 3.5. Web Browser & Interface Sanitization
* [ ] **Browser Address Bar**: Check URLs in web browser navigation bars for internal corporate domain names.
* [ ] **Bookmarks & Favorites**: Ensure personal bookmarks toolbar is hidden or empty.
* [ ] **Browser History & Tabs**: Close all unneeded tabs before recording.
* [ ] **Browser Extensions & Notifications**: Disable desktop push notifications and personal extensions.

### 3.6. ArcSight ESM & Logger Specifics
* [ ] **Logger Search Bar**: Ensure query strings use synthetic hostnames and sanitized CIDR ranges.
* [ ] **Logger Results Grid**: Inspect parsed CEF fields (`sourceAddress`, `destinationAddress`, `deviceHostName`) across all displayed rows.
* [ ] **ESM Active Channels**: Verify asset names, zone designations, and rule names match public documentation.
* [ ] **ESM Console Tree**: Check left-hand navigation pane for internal test names or student IDs.

### 3.7. pfSense & Network Appliance Dashboards
* [ ] **System Information Widget**: Check WAN interface IP, Netgate serial numbers, and real hostnames.
* [ ] **Interface Assignments**: Verify interface names reflect standardized VLANs (`WAN`, `TRANSIT`, `DMZ`, `INTERNAL`).
* [ ] **Firewall & NAT Rules**: Confirm rule descriptions contain no confidential notes or employee names.

### 3.8. Diagnostic Command Output Review
Pause and scrutinize the output of diagnostic commands that frequently expose infrastructure:
* [ ] `ipconfig /all` / `ifconfig` / `ip addr`
* [ ] `netstat -ano` / `ss -tulnp`
* [ ] `route print` / `ip route`
* [ ] `whoami` / `whoami /all`
* [ ] `hostname`
* [ ] `Get-NetIPConfiguration` / `Get-ADUser` / `Get-ComputerInfo`

---

## 4. Video Public-Safe Status Classification

Before publishing any video URL, document its verification status using this four-tier taxonomy:

| Status Code | Definition | Publication Action |
| :--- | :--- | :--- |
| **`NOT_REVIEWED`** | Recording completed, but no systematic security audit performed. | **PROHIBITED FROM UPLOAD** |
| **`REVIEW_REQUIRED`** | Initial review indicated potential sensitive artifacts requiring blur or redaction. | **PROHIBITED FROM UPLOAD** |
| **`SANITIZED`** | Video passed 4-pass review; all sensitive fields blurred or re-recorded with synthetic data. | Ready for upload staging |
| **`APPROVED_FOR_UPLOAD`**| Lead author verified zero leaks; confirmed for Unlisted YouTube hosting. | **PERMITTED FOR UNLISTED UPLOAD** |
