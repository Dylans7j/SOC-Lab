# SOC Lab — Active Directory Detection Engineering

**An evidence-driven security operations lab:** Active Directory • Windows event telemetry • Splunk SPL • Microsoft Sentinel KQL • Sigma.

Controlled lab activity → Windows telemetry → analyst investigation → validated detection → published case study.

[**Case Studies**](./case-studies/README.md) · [**Detection Library**](./detections/README.md) · [**Lab Architecture**](./lab/README.md) · [**Attack Simulations**](./attack-simulations/README.md) · [**Reference Docs**](./docs/README.md)

---

## Featured case study

### [DE-001 — Detecting Repeated Failed Active Directory Logons](./case-studies/DE-001-Repeated-Failed-AD-Logons/)

**Validated in Splunk · Windows Security 4625 · NTLM network logons**

A controlled Kali/NetExec exercise targeted a disposable domain account. DC01 produced failed-logon events, and a refined Splunk search identified **three incorrect-password failures from one source against one account in a five-minute window**. The report includes the event analysis, detection logic, limitations and six evidence screenshots.

[Read the full analyst report →](./case-studies/DE-001-Repeated-Failed-AD-Logons/)

**New:** [DE-003 — BadUSB-Initiated PowerShell Investigation](./case-studies/DE-003-BadUSB-PowerShell-Investigation/) — observed encoded PowerShell, Sysmon process/network correlation and PowerShell 4104; candidate alert validation and screenshot upload pending.\n\n[DE-002 — Password Spraying](./case-studies/DE-002-AD-Password-Spray-Detection/) — five failed logons against five distinct lab accounts, detected in Splunk.

## Browse the repository

| Section | Contents |
|---|---|
| [Case Studies](./case-studies/README.md) | Analyst reports, evidence, case timelines and historical investigations |
| [Detection Library](./detections/README.md) | Splunk SPL, Microsoft Sentinel KQL and portable Sigma rules, with validation status |
| [Lab Architecture](./lab/README.md) | VMware topology, Splunk onboarding and historical dual-SIEM documentation |
| [Attack Simulations](./attack-simulations/README.md) | Controlled lab exercises, including LLMNR/NBT-NS research |
| [Reference Docs](./docs/README.md) | Evidence standards, Windows onboarding and a Splunk detection cheat sheet |

## Verified lab milestones

| Component | Evidence-backed status |
|---|---|
| **DC01 → Splunk** | Windows Security logs indexed in `windows`; Event ID 4625 observed during DE-001 |
| **WIN11 → Splunk** | Security, System, PowerShell Operational and Sysmon Operational logs indexed in `main` |
| **Splunk receiver** | Universal Forwarders target TCP 9997 |
| **DE-001** | Three incorrect-password network logons identified within five minutes |
| **DE-002** | Five distinct test accounts, five incorrect-password network logons within ten minutes |\n| **DE-003** | Encoded PowerShell and TCP connection linked by Sysmon process GUID; expanded analytic pending |
| **Microsoft Sentinel** | Historical notes available; onboarding of current WIN11 endpoint **not verified** |

One captured WIN11 24-hour search returned **11,892 events** (9,703 Sysmon, 1,683 Security, 406 PowerShell and 100 System). These are historical observations, not live ingest rates.

## Public evidence and privacy

Public *text examples* use `192.169.70.x` as a **documentation-only placeholder**; it is not RFC 1918 private space or a working subnet. Screenshots and previous Git history require separate review before broader redistribution. Never commit credentials, tokens, personal identifiers or real internal network details.

**Project status:** This repository is an educational, isolated lab. Reported detection results apply to the documented test scenarios, not a production deployment.

[Portfolio project overview](https://dylans7j.github.io/Portfolio/projects.html)
