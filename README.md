# SOC–Active Directory Lab

A VMware-based security operations lab for generating, collecting, and investigating Windows and Active Directory telemetry with Microsoft Sentinel and Splunk Enterprise.

> Controlled activity → telemetry → query → investigation → documentation.

## What this repository demonstrates

- Windows Server Active Directory in an isolated lab network
- A domain-joined Windows endpoint
- Kali Linux for authorized enumeration and controlled test activity
- Microsoft Sentinel and Splunk Enterprise for dual-SIEM analysis
- Windows Security Event Log and Sysmon investigation workflows
- KQL and SPL query development
- ATT&CK-aligned reporting with explicit evidence status

## Evidence status

| Status | Meaning |
| --- | --- |
| **Validated** | Reproduced in the lab with supporting output or screenshots |
| **Documented** | Configuration, method, or query is recorded but needs stronger result evidence |
| **Staged** | Planned or drafted; not presented as completed |

| Capability | Status | Evidence |
| --- | --- | --- |
| Active Directory services on DC-01 | Validated | Service enumeration and lab operation |
| Microsoft Sentinel ingestion | Validated | Windows events observed in the workspace |
| Splunk Enterprise deployment | Validated | Service and receiver connectivity confirmed |
| Failed-logon visibility | Validated | Windows Security Event ID 4625 |
| KQL and SPL query library | Documented | [Detection queries](./Detection-engineering/Dual-Siem/detection-queries.md) |
| LLMNR/NBT-NS scenario | Documented | [Attack scenario](./attack-scenarios/llmnr-nbtns-poisoning.md) |
| WIN-01 and expanded Sysmon coverage | Staged | Evidence package still being completed |
| Advanced Kerberos and lateral-movement detections | Staged | Not claimed as validated |

## Architecture

| Host | Platform | Role |
| --- | --- | --- |
| DC-01 | Windows Server | Domain controller and Windows event source |
| WIN-01 | Windows | Domain workstation and endpoint telemetry source |
| SPLUNK-01 | Ubuntu Server | Splunk Enterprise |
| Kali | Kali Linux | Authorized test and enumeration workstation |
| Microsoft Sentinel | Azure | Cloud SIEM and KQL investigations |

The lab uses a VMware host-only network for internal traffic and a separate NAT interface where outbound connectivity is required.

### Telemetry flow

```text
DC-01 / WIN-01
├── Windows Security Events ──> Azure monitoring ──> Microsoft Sentinel
└── Windows event forwarding ─> Splunk receiver ───> Splunk Enterprise

Kali ──> controlled lab activity ──> Windows telemetry ──> SIEM investigation
```

## Featured investigation

### INC-001 — SMB authentication failures

A controlled SMB authentication test from Kali generated Windows Security Event ID 4625 on the domain controller. The investigation focuses on source host, targeted account, logon type, failure reason, time range, and repeated attempts.

- [Investigation report](./investigations/INC-001-smb-authentication-failures.md)
- [Sentinel KQL](./detections/kql/failed-logons.kql)
- [Splunk SPL](./detections/spl/failed-logons.spl)

The query logic is published separately from validation evidence. A rule is not labeled validated until a sanitized result is attached and the expected fields are confirmed.

## Existing documentation

- [Dual-SIEM architecture](./Detection-engineering/Dual-Siem/README.md)
- [Lab setup](./Detection-engineering/Dual-Siem/lab-setup.md)
- [Detection query library](./Detection-engineering/Dual-Siem/detection-queries.md)
- [Splunk detection reference](./SPLUNK%20DETECTION%20CHEATSHEET.md)
- [LLMNR/NBT-NS poisoning scenario](./attack-scenarios/llmnr-nbtns-poisoning.md)
- [Evidence standard](./docs/EVIDENCE-STANDARD.md)

## Repository structure

```text
SOC-Lab/
├── README.md
├── Detection-engineering/
│   └── Dual-Siem/
├── attack-scenarios/
├── detections/
│   ├── kql/
│   └── spl/
├── investigations/
└── docs/
```

## Publication standard

Each project entry must include:

1. Objective and authorized scope
2. Environment and required data sources
3. Reproducible method
4. Sanitized supporting evidence
5. Analyst conclusion, limitations, and remediation

Credentials, tokens, private keys, flags, active-machine spoilers, and unsupported claims are excluded.

## Current roadmap

- Add sanitized Sentinel and Splunk results for INC-001
- Complete WIN-01 telemetry validation
- Add tested Sysmon process and registry hunts
- Convert one original Sigma rule into equivalent SPL
- Add one YARA rule with sample hash, test method, and result
- Publish additional attack scenarios only after evidence is captured
