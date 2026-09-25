# Security Policy

## 1. Project Purpose & Scope

The **Enterprise SOC Lab** is an educational, research, and defensive portfolio repository documenting a simulated enterprise security architecture, telemetry pipeline, detection engineering baseline, and incident investigation workflows.

This repository does not represent, manage, or operate a live production environment. All network topologies, domain names, hostnames, and IP addresses used throughout public documentation have been sanitized and mapped to canonical RFC 1918 private spaces (`10.10.0.0/16`) and RFC 5737 documentation test networks (`203.0.113.0/24`).

---

## 2. Prohibition of Sensitive Submissions

To preserve security and confidentiality:
* **Never submit real credentials**, plaintext passwords, cryptographic private keys, API tokens, or session secrets through GitHub issues, pull requests, or public comments.
* **Never submit raw, un-sanitized production logs** or proprietary corporate datasets.
* **Never submit real infrastructure identifiers**, internal production domain names, or personally identifiable information (PII).

Any pull request or issue containing real operational secrets or sensitive customer data will be closed and permanently purged.

---

## 3. Vulnerability Reporting & Contact

This project is a standalone technical research and portfolio laboratory maintained by the project author. It does not operate a commercial bug bounty program or formal 24/7 security operations center for external reporting.

If you identify a genuine security concern regarding this repository (such as an inadvertent exposure of sensitive data or an un-sanitized credential in documentation), please report it directly and privately to the repository maintainer via the GitHub profile contact details rather than opening a public issue.

---

## 4. Git History Safety Notice

Sensitive information must never be committed to the repository, including in Git history. All contributors and maintainers must ensure that local commits are audited for secrets before pushing to remote repositories.
