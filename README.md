# SOC–Active Directory Lab

Evidence-driven VMware cybersecurity lab for Windows event collection, Active Directory investigations and detection engineering. Technical reports and versioned detections are maintained here; [portfolio project summaries](https://dylans7j.github.io/Portfolio/projects.html) provide a recruiter-facing overview.

> Build → generate controlled activity → collect → detect → investigate → document.

## Detection Engineering Investigations

- [DE-001 — Detecting Repeated Failed Active Directory Logons](./investigations/INC-002-Active-Directory-Authentication-Investigation/) — validated Splunk/Sigma case study using controlled SMB authentication failures against a disposable AD account.
- DE-002 — Detecting Active Directory Password Spraying — planned next investigation.

## Verified September 2026 milestone: WIN11 → Splunk

The Windows 11 endpoint (`WIN-01-W11` VM; OS hostname `WIN11`) has a running Splunk Universal Forwarder, connected to SPLUNK-01's **TCP 9997** receiving port. Windows Security, System, PowerShell Operational and Sysmon Operational events are indexed in `main`.

One captured 24-hour Splunk search returned **11,892 events**, including **9,703 Sysmon events**. Those counts describe that search window, not continuous ingestion or performance.

| Telemetry channel | Observed count |
| --- | ---: |
| Sysmon Operational | 9,703 |
| Windows Security | 1,683 |
| PowerShell Operational | 406 |
| Windows System | 100 |

The Sysmon channel was locally enabled and generated Event ID 1. Initial Universal Forwarder ingestion failed with `errorCode=5` (access denied). Adding the dedicated service identity to **Event Log Readers** and restarting the service corrected the access problem; real Sysmon source events subsequently appeared in Splunk.

**Evidence status:** validated with local outputs and Splunk screenshots. Sanitized screenshots have not yet been committed to this repository.

## Public lab network notation

**All addresses in this repository use the documentation placeholder `192.169.70.x`; no actual lab IP addresses, NAT leases or gateways are published.** The placeholder is not a recommended routable or private network configuration. Substitute your own authorized addresses locally.

| Asset | Purpose | Current state |
| --- | --- | --- |
| DC-01 | Active Directory, DNS and authentication telemetry | LDAP reachable; queried DNS SRV record unresolved; current DC-01 Splunk ingestion still needs confirmation |
| WIN11 | Windows 11 endpoint with Sysmon and Universal Forwarder | **Verified**: four log channels indexed in Splunk |
| SPLUNK-01 | Ubuntu / Splunk Enterprise | **Verified**: receiver on TCP 9997; WIN11 events indexed |
| Kali | Isolated security-testing workstation | Authorized enumeration and planned controlled exercises |
| Microsoft Sentinel | Cloud investigation environment | Previous research documented; **current WIN11 onboarding deferred** |

Splunk Web uses a separate web port; **TCP 9997 is the forwarder receiver**, not the browser interface. The current WIN11 endpoint has no Azure Arc or Azure Monitor Agent installed.

## Current project track

- [x] Confirm DC-01 Windows Security events reach Splunk.
- [x] Produce a limited authentication-failure sample using a disposable non-administrative lab account.
- [x] Correlate Windows Security Event ID 4625 based on the observed SMB/NTLM activity.
- [x] Write and test an SPL rule, document extraction quirks and false-positive considerations.
- [x] Map confirmed behavior to MITRE ATT&CK and publish a Sigma rule plus sanitized report.
- [ ] Build DE-002 password spraying detection.
- [ ] Reproduce selected detections in Microsoft Sentinel after current onboarding is verified.

## Existing project documentation

- [DE-001 — Detecting Repeated Failed Active Directory Logons](./investigations/INC-002-Active-Directory-Authentication-Investigation/)
- [Dual-SIEM architecture and historical work](./Detection-engineering/Dual-Siem/README.md)
- [Lab setup notes](./Detection-engineering/Dual-Siem/lab-setup.md)
- [Detection queries](./Detection-engineering/Dual-Siem/detection-queries.md)
- [Previously documented authentication investigation](./investigations/INC-001-smb-authentication-failures.md)
- [LLMNR/NBT-NS poisoning study](./attack-scenarios/llmnr-nbtns-poisoning.md)
- [Evidence standard](./docs/EVIDENCE-STANDARD.md)

Historical dual-SIEM documentation is distinct from the current WIN11 deployment. WIN11-to-Sentinel data flow must not be described as verified.

## Publication standard

Each published investigation must describe scope, timestamps, commands, actual event sources, sanitized supporting evidence, detection results, assumptions, limitations and remediation. Never publish credentials, tokens, private keys, raw internal addresses or unsupported detection claims.
