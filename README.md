<div align="center">

# SOC-Lab

![Status](https://img.shields.io/badge/Status-Active%20Development-success?style=flat-square)
![Environment](https://img.shields.io/badge/Environment-VMware%20%7C%20Azure-orange?style=flat-square)
![Focus](https://img.shields.io/badge/Focus-Detection%20Engineering%20%7C%20DFIR-blue?style=flat-square)

**Production-grade Security Operations Center laboratory** — Active Directory security monitoring, detection engineering, and incident response workflows across Microsoft Sentinel and Splunk Enterprise.

`ATTACK → DETECT → INVESTIGATE → RESPOND`

</div>

---

## Overview

SOC-Lab is a **comprehensive security operations center environment** built on VMware and Azure. It demonstrates end-to-end security monitoring, detection engineering, and incident response capabilities through real attack scenarios, dual-SIEM analysis, and forensic investigation.

The lab is designed to develop **transferable skills** in detection engineering, threat hunting, and incident response — not just platform-specific knowledge. Every technique is documented with reproducible steps and cross-referenced to attack behavior and MITRE ATT&CK tactics.

---

## Quick Navigation

| Component | Purpose | Status |
|---|---|:---:|
| [Dual-SIEM AD Monitoring](#dual-siem-active-directory-monitoring) | Azure Sentinel + Splunk ingesting AD telemetry | ✅ Active |
| [Detection Queries](#detection-queries) | KQL and SPL query library | ✅ 10 queries |
| [Attack Scenarios](#attack-scenarios) | Reproducible attack walkthroughs | 🔜 Planned |
| [DFIR Workflows](#digital-forensics--incident-response) | Post-incident investigation procedures | 🔜 Planned |
| [Threat Hunting](#threat-hunting) | Proactive threat detection techniques | 🔜 Planned |
| [Lab Setup Guide](#lab-setup-guide) | VMware + Azure infrastructure | ✅ Documented |

---

## Architecture Overview

```
┌────────────────────────────────────────────────────────────────┐
│                        SOC-Lab Network                         │
│                    (VMware VMnet7 + Azure)                     │
└────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                      Offensive Segment (KALI01)                     │
│                         192.168.70.10                               │
│  - NetExec attacks (SMB, Kerberos, etc.)                           │
│  - Attack instrumentation & command execution                      │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                    ┌─────────────┴──────────────┐
                    │                            │
        ┌───────────v────────────┐   ┌──────────v──────────────┐
        │   Active Directory      │   │  Detection & Response   │
        │       (DC01)            │   │       Segment           │
        │   192.168.70.20         │   │                         │
        │                         │   │  ┌─────────────────┐    │
        │  - Windows Server 2022  │   │  │  SPLUNK-01      │    │
        │  - AD Domain: dc-01.lab │   │  │  192.168.70.80  │    │
        │  - Arc Agent            │   │  │  (Indexer)      │    │
        │  - UF Forwarder         │   │  │  TCP/1137       │    │
        │  - Sysmon               │   │  └─────────────────┘    │
        │                         │   │                         │
        └─────────┬───────────────┘   │  ┌─────────────────┐    │
                  │                   │  │    Sentinel     │    │
                  │                   │  │   (Cloud/Azure) │    │
                  │                   │  │                 │    │
                  │                   │  │ Log Analytics   │    │
                  │                   │  │ Workspace       │    │
                  │                   │  └─────────────────┘    │
                  │                   │                         │
                  └───────────┬───────┘                         │
                              │                                 │
                    ┌─────────v─────────┐                       │
                    │  Event Telemetry  │                       │
                    │  (Security, App,  │                       │
                    │   PowerShell,     │                       │
                    │   Sysmon)         │                       │
                    └───────────────────┘                       │
                                                                │
                    ┌──────────────────────────────────────────┘
                    │
        ┌───────────v─────────────┐
        │  Threat Hunting &       │
        │  Investigation          │
        │                         │
        │  - Detection Rules      │
        │  - Incident Timelines   │
        │  - DFIR Analysis        │
        │  - Root Cause Analysis  │
        └─────────────────────────┘
```

---

## Lab Environment

### Systems

| Hostname | IP | OS | Role | Status |
|---|---|---|---|:---:|
| **KALI01** | 192.168.70.10 | Kali Linux | Attack workstation | ✅ Active |
| **DC01** | 192.168.70.20 | Windows Server 2022 | Domain Controller | ✅ Active |
| **WIN-01** | 192.168.70.30 | Windows 10 | Domain workstation | 🔜 Planned |
| **SPLUNK-01** | 192.168.70.80 | Ubuntu Server 22.04 | Splunk Enterprise indexer | ✅ Active |

### Infrastructure

- **Hypervisor:** VMware Workstation Pro / ESXi
- **Network:** VMware VMnet7 (isolated lab, 192.168.70.0/24)
- **Internet:** Separate VMware NAT interface for outbound access
- **Cloud:** Microsoft Azure (Sentinel, Arc, Log Analytics)

---

## Dual-SIEM Active Directory Monitoring

### Overview

DC01 (Windows Server 2022 domain controller) sends Windows Event Log telemetry to **both** Microsoft Sentinel (cloud) and Splunk Enterprise (on-premises) simultaneously. This allows the same attack activity to be investigated using both **KQL** (Kusto Query Language) and **SPL** (Splunk Processing Language).

### Why Dual-SIEM?

- **Vendor-agnostic skills:** Techniques learned in one platform transfer to another
- **Platform comparison:** Understand strengths/weaknesses of each SIEM
- **Real-world scenarios:** Many enterprises run hybrid SIEM deployments
- **Skill depth:** Master query logic, not just UI navigation

### Pipeline

**Microsoft Sentinel:**
```
DC01 (Windows Event Logs)
  ↓
Azure Arc Agent
  ↓
Data Collection Rule (DCR)
  ↓
Log Analytics Workspace
  ↓
Microsoft Sentinel
```

**Splunk Enterprise:**
```
DC01 (Windows Event Logs)
  ↓
Splunk Universal Forwarder
  ↓
TCP/1137 (custom port)
  ↓
SPLUNK-01 Receiver
  ↓
Splunk Indexer
```

### Documentation

- **[Dual-SIEM README](./detection-engineering/dual-siem/README.md)** — Architecture, pipeline, validation
- **[Lab Setup Guide](./detection-engineering/dual-siem/lab-setup.md)** — Step-by-step configuration for Azure Arc, Splunk, UF
- **[Detection Queries](./detection-engineering/dual-siem/detection-queries.md)** — 10 queries in both KQL and SPL

### Attack-to-Detection Example

```bash
# Attack (from KALI01)
nxc smb 192.168.70.20 -u Administrator -p 'WrongPassword'

# Telemetry Generated
Event ID 4625 (Failed Logon)

# Investigated in Sentinel (KQL)
Event | where EventID == 4625 | sort by TimeGenerated desc

# Investigated in Splunk (SPL)
index=windows EventCode=4625 | sort - _time
```

---

## Detection Queries

### Available Queries

| Query | Type | Detects | KQL | SPL |
|---|---|---|:---:|:---:|
| Failed Logon Detection | Auth | Brute force, credential spray | ✅ | ✅ |
| Admin Activity Timeline | Access | RDP logons (type 10) | ✅ | ✅ |
| PowerShell Script Blocks | Execution | Suspicious PS commands (IEX, DownloadString) | ✅ | ✅ |
| SMB Share Access | Access | Unusual share enumeration | ✅ | ✅ |
| Account Creation | Persistence | New local/domain users | ✅ | ✅ |
| Kerberos Attacks | Lateral Movement | Golden tickets, AS-REP, RC4-HMAC | ✅ | ✅ |
| Process Execution | Execution | PsExec, WMI lateral movement | ✅ | ✅ |
| Privilege Escalation | Privilege Escalation | SeImpersonate/SeAssignPrimaryToken abuse | ✅ | ✅ |
| Scheduled Tasks | Persistence | Suspicious task creation | ✅ | ✅ |
| File Exfiltration | Exfiltration | Large SMB transfers | ✅ | ✅ |

**See:** [Detection Queries](./detection-engineering/dual-siem/detection-queries.md)

---

## Attack Scenarios

### Planned Attack Paths

| Scenario | Attack Chain | Detection Focus |
|---|---|---|
| **Credential Spray** | KALI → failed auth → account lockout → account enumeration | Event ID 4625, 4771 |
| **Kerberoasting** | GetUserSPNs → TGS request → offline crack → service account compromise | Event ID 4769, 4770 |
| **Golden Ticket** | DCSync → krbtgt hash → forged TGT → domain persistence | Event ID 4769, 4768 |
| **Lateral Movement** | Initial foothold → PsExec/WMI → admin workstations → C2 | Event ID 4688, 5145 |
| **Privilege Escalation** | Weak service perms → token impersonation → SYSTEM | Event ID 4673, 4697 |
| **Data Exfiltration** | Enumerate shares → bulk file copy → external upload | Event ID 5145, network flows |

**Status:** 🔜 Planned for Q4 2026

---

## Digital Forensics & Incident Response

### Planned DFIR Workflows

- [ ] **Post-Breach Timeline Construction** — Correlate logs across systems to build attack timeline
- [ ] **Lateral Movement Forensics** — Identify pivot points and persistence mechanisms
- [ ] **Memory Forensics** — Analyze LSASS dumps for credential theft
- [ ] **Filesystem Forensics** — Recover deleted artifacts, analyze MFT
- [ ] **Email Forensics** — Trace phishing campaigns, identify compromised accounts
- [ ] **USB Forensics** — Detect unauthorized device connections and data theft

**Status:** 🔜 Planned for Q1 2027

---

## Threat Hunting

### Proactive Detection Techniques

- [ ] **Behavior-based hunting** — Identify anomalous account and process behavior
- [ ] **Network-based hunting** — Detect C2 communications and data exfiltration
- [ ] **Log-based hunting** — Build detection rules from MITRE ATT&CK techniques
- [ ] **Hypothesis-driven hunting** — Test specific attack chains (e.g., AS-REPRoasting)
- [ ] **Compromise assessment** — Sweep for signs of past compromise

**Status:** 🔜 Planned for Q2 2027

---

## Lab Setup Guide

### Prerequisites

- VMware Workstation Pro or ESXi
- Azure subscription (free tier sufficient)
- 8+ GB RAM allocated to lab
- 100+ GB free disk space

### Quick Start

1. **Clone repo:** `git clone https://github.com/Dylans7j/SOC-Lab.git`
2. **Read:** [Dual-SIEM Setup Guide](./detection-engineering/dual-siem/lab-setup.md)
3. **Deploy:** Follow Azure Arc + Splunk configuration steps
4. **Validate:** Run test queries (KQL + SPL) to confirm data flow
5. **Attack:** Generate test events with `nxc` from KALI01

### Full Documentation

- [Dual-SIEM Lab Setup](./detection-engineering/dual-siem/lab-setup.md) — Azure Arc, DCR, Splunk UF configuration
- VMware Configuration (TODO)
- Active Directory Setup (TODO)

---

## Skills Developed

### Detection Engineering
- [ ] KQL (Kusto Query Language) for Microsoft Sentinel
- [ ] SPL (Splunk Processing Language)
- [ ] Query optimization and performance tuning
- [ ] Alert tuning (reducing false positives)
- [ ] Detection rule creation (MITRE ATT&CK mapping)

### Incident Response
- [ ] Timeline construction from multi-source logs
- [ ] Artifact correlation and enrichment
- [ ] Root cause analysis
- [ ] Containment and remediation procedures
- [ ] Post-incident reporting

### Threat Hunting
- [ ] Anomaly detection
- [ ] Behavior-based analysis
- [ ] Hypothesis-driven investigation
- [ ] MITRE ATT&CK framework application

### Infrastructure
- [ ] Active Directory security
- [ ] Windows Event Logging configuration
- [ ] Sysmon deployment and tuning
- [ ] Azure Arc and cloud agent management
- [ ] SIEM integration and troubleshooting

---

## Project Status

### ✅ Completed

- [x] Dual-SIEM architecture design
- [x] Microsoft Sentinel onboarding (Azure Arc)
- [x] Splunk Enterprise deployment
- [x] Windows Event Log forwarding (both platforms)
- [x] 10 detection queries (KQL + SPL)
- [x] Attack-to-detection validation (failed auth example)
- [x] Full documentation (README, setup, queries)

### 🔜 In Progress

- [ ] Sysmon telemetry ingestion
- [ ] PowerShell Script Block Logging
- [ ] WIN-01 workstation onboarding

### 🔜 Planned

- [ ] Additional attack scenarios (Kerberoasting, Golden Ticket, etc.)
- [ ] DFIR workflow documentation
- [ ] Threat hunting procedures
- [ ] Splunk dashboards
- [ ] Sentinel workbooks
- [ ] EDR comparison lab
- [ ] Network forensics segment
- [ ] USB forensics procedures

---

## Repository Structure

```
SOC-Lab/
├── README.md (this file)
│
├── detection-engineering/
│   └── dual-siem/
│       ├── README.md                    # Architecture & overview
│       ├── lab-setup.md                 # Azure Arc + Splunk config
│       ├── detection-queries.md         # KQL + SPL query library
│       │
│       ├── queries/
│       │   ├── sentinel/
│       │   │   ├── authentication.kql
│       │   │   ├── lateral-movement.kql
│       │   │   └── ...
│       │   └── splunk/
│       │       ├── authentication.spl
│       │       ├── lateral-movement.spl
│       │       └── ...
│       │
│       ├── configs/
│       │   ├── dc01-uf-inputs.conf      # Splunk UF config
│       │   ├── dc01-uf-outputs.conf
│       │   └── dcr-windows-security.json # Azure DCR definition
│       │
│       └── screenshots/
│           ├── sentinel-4625-events.png
│           └── splunk-windows-stats.png
│
├── attack-scenarios/ (planned)
│   ├── credential-spray/
│   ├── kerberoasting/
│   ├── golden-ticket/
│   └── ...
│
├── dfir-workflows/ (planned)
│   ├── post-breach-timeline/
│   ├── lateral-movement/
│   └── memory-forensics/
│
└── threat-hunting/ (planned)
    ├── anomaly-detection/
    ├── network-hunting/
    └── log-based-hunting/
```

---

## Getting Started

### 1. Read the Documentation

Start with the dual-SIEM documentation:

```bash
# Main overview
cat detection-engineering/dual-siem/README.md

# Setup instructions
cat detection-engineering/dual-siem/lab-setup.md

# Query examples
cat detection-engineering/dual-siem/detection-queries.md
```

### 2. Deploy the Lab

Follow [lab-setup.md](./detection-engineering/dual-siem/lab-setup.md) to:
- Onboard DC01 to Azure Arc
- Create Data Collection Rule
- Deploy Splunk Enterprise
- Configure Splunk Universal Forwarder

### 3. Validate Data Flow

Run validation queries:

**Sentinel (KQL):**
```kusto
Event
| where EventID == 4625
| sort by TimeGenerated desc
| take 10
```

**Splunk (SPL):**
```spl
index=windows EventCode=4625
| stats count by IpAddress, TargetUserName
```

### 4. Generate Test Events

From KALI01:
```bash
nxc smb 192.168.70.20 -u Administrator -p 'WrongPassword'
```

Then investigate the event in both Sentinel and Splunk.

---

## Contributing

This lab is a **living project**. As new attack techniques are tested and detection methods refined, documentation is updated to reflect real-world scenarios.

**Contributing guidelines:**
- Document attacks end-to-end (attack → telemetry → detection → investigation)
- Provide query examples in both KQL and SPL
- Test all procedures before committing
- Cross-reference MITRE ATT&CK tactics and techniques

---

## Resources

### Microsoft Sentinel & Azure
- [Azure Arc for Servers](https://learn.microsoft.com/en-us/azure/azure-arc/servers/overview)
- [Azure Monitor Agent](https://learn.microsoft.com/en-us/azure/azure-monitor/agents/agents-overview)
- [KQL Tutorial](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/tutorial)
- [Sentinel GitHub](https://github.com/Azure/Azure-Sentinel)

### Splunk
- [Splunk Enterprise Documentation](https://docs.splunk.com/Documentation/Splunk)
- [SPL Quick Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/SearchCommandsOverview)
- [Splunk Security Essentials](https://splunkbase.splunk.com/app/3435)

### Detection Engineering
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Detection Lab by Andrew Rathbun](https://github.com/clong/DetectionLab)
- [Splunk Boss of the SOC](https://www.splunk.com/en_us/training/splunk-boss-of-the-soc.html)

### DFIR & Forensics
- [SANS DFIR](https://www.sans.org/cyber-aces/forensics/)
- [Volatility Framework](https://github.com/volatilityfoundation/volatility3)
- [Linux Forensics Artifacts](https://github.com/Dylans7j/SOC-Lab/tree/main/detection-engineering/dual-siem)

---

## Contact & Support

- **Issues:** GitHub Issues (use `[lab-setup]`, `[detection-query]`, `[attack-scenario]` labels)
- **Discussions:** GitHub Discussions for architecture questions
- **Updates:** Star the repo to stay notified of new content

---

<div align="center">

**Last Updated:** August 2026  
**Maintainer:** [Dylans7j](https://github.com/Dylans7j)  
**License:** MIT  
**Status:** 🔴 Active Development

---

### 🎯 Goal

Develop **transferable security operations skills** through hands-on attack scenarios, detection engineering, and incident response workflows — not platform-specific knowledge.

</div>
