# Detection Validation Matrix

## 1. Overview & Validation Methodology

This matrix documents the empirical validation status of all detection rules implemented in the Enterprise SOC Lab. In accordance with rigorous security documentation principles, every rule is classified strictly upon documented evidence from:
1. **Configuration Evidence**: Verification that the rule is configured in ArcSight ESM.
2. **Logger Evidence**: Verification that normalized CEF events matching the rule conditions exist and were successfully queried on ArcSight Logger.
3. **ESM Alert Activation**: Verification that the rule fired in real time and generated alerts on the ESM Active Channel console.
4. **Observed in Attack Simulation**: Verification that the rule fired as part of the live multi-stage red team exercise.
5. **Replay Tested**: Verification that the rule or its underlying telemetry was re-tested during historical replay or post-hardening validation.

---

## 2. Empirical Validation Status Matrix

| Detection ID | Detection Name | Configured | Logger Evidence | ESM Fired | Observed in Attack | Replay Tested | Technical Maturity Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **A01** | Mail Delivered to Internal User | **YES** | **YES** | **YES** | **YES** | **YES** | `Contextual / Baseline` |
| **A02** | Suspicious External Web Download | **YES** | **YES** | **YES** | **YES** | **YES** | `Scenario Validated` |
| **A03** | Suspicious Script Execution | **YES** | **YES** | **YES** | **YES** | **YES** | `Operationally Observed` |
| **A04** | Suspicious Outbound Callback | **YES** | **YES** | **YES** | **YES** | **YES** | `Scenario-Dependent (Volume Limited)` |
| **A05** | Post-Compromise Discovery Burst | **YES** | **YES** | **YES** | **YES** | **UNVERIFIED** | `Threshold-Based` |
| **A06** | Credential Material Collection | **YES** | **YES** | **YES** | **YES** | **UNVERIFIED** | `Operationally Observed` |
| **A07** | Suspicious Data Staging / Raw Transfer | **YES** | **YES** | **YES** | **YES** | **UNVERIFIED** | `Operationally Observed` |
| **A08** | Suspicious Tool Transfer or Execution | **YES** | **YES** | **YES** | **YES** | **YES** | `Operationally Observed` |
| **A09** | Suspicious External Tunnel (Ligolo-ng) | **YES** | **YES** | **YES** | **YES** | **YES** | `Scenario-Dependent` |
| **A10** | Internal Remote Access to WEB Tier | **YES** | **YES** | **YES** | **YES** | **YES** | `Contextual / Lateral Movement` |
| **A11** | Sensitive Privileged WEB Activity | **YES** | **YES** | **YES** | **YES** | **YES** | `Operationally Observed` |
| **A12** | Suspicious Database Collection | **YES** | **YES** | **YES** | **YES** | **YES** | `Threshold-Based` |
| **A13** | Suspicious DMZ External Transfer | **YES** | **YES** | **YES** | **YES** | **YES** | `Scenario-Dependent` |
| **C01** | Initial Compromise Correlation | **YES** | **YES** | **YES** | **YES** | **YES** | `Correlation Validated` |

---

## 3. Explanatory Notes on Technical Statuses

* **`Contextual / Baseline` (A01, A10)**: Represents authorized, expected network or mail transactions. These rules provide critical timestamp anchors and lateral trajectory evidence, but do not represent malicious violations in isolation.
* **`Scenario-Dependent` (A02, A04, A09, A13)**: The detection logic targets specific network artifacts (ports 4444, 11601, 9999 or custom Suricata SIDs) established for the test scenario. While empirically validated, they require generalization before production deployment.
* **`Threshold-Based` (A05, A12)**: Relies on frequency counts within sliding time windows (e.g., 3 events in 5 minutes for A05; 2 events in 5 minutes for A12). Susceptible to evasion if an adversary deliberately delays actions beyond the window.
* **`Operationally Observed` (A03, A06, A07, A08, A11)**: Detects specific attacker behavior on the host via low-level kernel auditing (Sysmon, PowerShell 4104, Linux Auditd) and was observed firing with high fidelity during attack execution.
* **`Correlation Validated` (C01)**: Verified to fire both in real-time live monitoring and historical replay mode when perimeter ingress (`A02`), host execution (`A03`), and network callback (`A04`) occur within $\Delta t \le 20\text{ minutes}$ on the same entity.
