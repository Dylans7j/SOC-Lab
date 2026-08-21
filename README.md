<div align="center">

# Dual-SIEM Active Directory Monitoring Lab

![Status](https://img.shields.io/badge/Status-Active-success?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Microsoft%20Sentinel%20%7C%20Splunk-blue?style=flat-square)
![Environment](https://img.shields.io/badge/Environment-VMware%20%7C%20Azure%20Arc-orange?style=flat-square)

Real-time Active Directory security telemetry ingested simultaneously into Microsoft Sentinel and Splunk Enterprise for dual-platform detection and investigation.

`KALI ATTACK → DC TELEMETRY → DUAL SIEM → KQL + SPL QUERIES`

</div>

---

## Overview

This project demonstrates a production-grade dual-SIEM monitoring architecture built around a Windows Active Directory lab. Windows security telemetry from a VMware-hosted domain controller is collected simultaneously by **Microsoft Sentinel** (cloud) and **Splunk Enterprise** (on-prem), allowing the same attack activity to be investigated using both **KQL** (Kusto Query Language) and **SPL** (Splunk Processing Language).

**The goal:** Develop transferable detection and investigation skills rather than relying on a single security platform's interface or paradigm.

---

## Architecture

```
                         KALI01
                    192.168.70.10
                          |
                    Attack Activity
                    (SMB auth failures,
                     Kerberos attacks,
                     etc.)
                          |
                          v
                        DC01
                    192.168.70.20
                 Windows Server 2022
                   Active Directory
                          |
              +-----------+-----------+
              |                       |
              v                       v
        Microsoft Sentinel          Splunk
             (Cloud)             (On-Prem)
             / AMA               / UF
             / DCR               / Port 1137
              |                       |
              v                       v
        Log Analytics          SPLUNK-01
        Workspace            192.168.70.80
        (Event table)            (Indexer)
                                   |
                            (Both ingest
                             same events)
```

---

## Environment

| System | Purpose | Lab Address | OS/Role |
|---|---|---|---|
| **KALI01** | Offensive security workstation | 192.168.70.10 | Kali Linux |
| **DC01** | Domain Controller | 192.168.70.20 | Windows Server 2022 / AD |
| **WIN-01** | Domain workstation | 192.168.70.30 | Windows 10 (planned) |
| **SPLUNK-01** | Splunk Enterprise indexer | 192.168.70.80 | Ubuntu Server |

**Network:** Isolated lab network uses VMware VMnet7 on `192.168.70.0/24`. Systems requiring internet connectivity also use a separate VMware NAT interface.

---

## Microsoft Sentinel Pipeline

### Onboarding

DC01 was onboarded to Azure using **Azure Arc**. Once registered, the monitoring pipeline became:

```
DC01
  ↓
Windows Event Logs (Security, System, Application)
  ↓
Azure Monitor Agent (AMA)
  ↓
Data Collection Rule (DCR)
  ↓
Log Analytics Workspace
  ↓
Microsoft Sentinel
```

### Data Collection Rule

**Name:** `DCR-SOC-LAB-WINDOWS`

**Targets:** Windows Security audit events from DC01

**Validation:** Successful ingestion confirmed via the `Event` table in Log Analytics.

### Sentinel Query - Validation

```kusto
Event
| where EventID == 4625
| sort by TimeGenerated desc
| take 50
```

**Results:** Events originating from `DC01.dc-01.lab` with source `Microsoft-Windows-Security-Auditing` successfully ingested.

---

## Splunk Pipeline

### Splunk Infrastructure

| Component | Specification |
|---|---|
| Hostname | SPLUNK-01 |
| Lab IP | 192.168.70.80 |
| Web UI | TCP/8000 |
| Receiver Port | TCP/1137 (non-default, intentional) |

**Note:** Non-standard port 1137/TCP is used within the isolated lab environment and documented throughout for reproducibility.

### Splunk Universal Forwarder (DC01)

Installed on DC01 to transmit Windows event logs to SPLUNK-01.

**Output Configuration:**

```ini
[tcpout]
defaultGroup = lab_indexers

[tcpout:lab_indexers]
server = 192.168.70.80:1137
```

### Windows Event Inputs

**inputs.conf on DC01:**

```ini
[WinEventLog://Security]
disabled = 0
index = windows
renderXml = true

[WinEventLog://System]
disabled = 0
index = windows
renderXml = true

[WinEventLog://Application]
disabled = 0
index = windows
renderXml = true

[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = 0
index = powershell
renderXml = true

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = sysmon
renderXml = true
```

### Custom Indexes

Three indexes created on SPLUNK-01:

- `windows` — Windows Security, System, Application events
- `powershell` — PowerShell Script Block Logging
- `sysmon` — Sysmon operational telemetry

### Splunk Validation

**1. Forwarder Connectivity** (from DC01):

```powershell
Test-NetConnection 192.168.70.80 -Port 1137
```

**Output:**

```
TcpTestSucceeded : True
```

**2. Forwarder Status** (from DC01):

```
Active forwards:
192.168.70.80:1137
```

**3. Data in Splunk:**

```spl
index=windows
| stats count by host, source, sourcetype
```

**Results:** Confirmed telemetry from `DC01` across all three indexes.

---

## Attack-to-Detection Validation

### Test Attack

Failed SMB authentication from Kali Linux against DC01:

```bash
nxc smb 192.168.70.20 \
  -u Administrator \
  -p 'WrongPassword123!'
```

**Result:** `STATUS_LOGON_FAILURE`

**Telemetry Generated:** Windows Event ID **4625** (Failed Logon)

### Same Event, Dual Investigation

The same security event is visible in both platforms:

**Microsoft Sentinel (KQL):**

```kusto
Event
| where EventID == 4625
| sort by TimeGenerated desc
```

**Splunk Enterprise (SPL):**

```spl
index=windows EventCode=4625
| sort - _time
```

**Outcome:** Two different vendor interfaces, one source of truth (the attack). This demonstrates the core skill: **understanding telemetry and attacker behavior transcends platform**.

---

## Why This Matters

This lab is **not** about collecting two SIEM platforms for their own sake.

The objective is to understand the **detection workflow itself**:

```
Attack Activity
      ↓
Endpoint Telemetry (Windows Event Logs)
      ↓
Collection (AMA + UF)
      ↓
Ingestion (Sentinel + Splunk)
      ↓
Queryable Data (KQL + SPL)
      ↓
Detection (Alerts & Rules)
      ↓
Investigation (Correlation & Timeline)
      ↓
Response (Containment & Remediation)
```

Working with the same event across multiple SIEM platforms reinforces that **the core skill is understanding telemetry and attacker behavior**, not memorizing one vendor's interface.

---

## Skills Demonstrated

- **Infrastructure:** VMware network segmentation, Active Directory, Windows Server 2022
- **Offence:** Kali Linux, NetExec, attack instrumentation
- **Cloud:** Azure Arc, Azure Monitor Agent (AMA), Data Collection Rules
- **Detection (Microsoft):** Microsoft Sentinel, Log Analytics, KQL
- **Detection (Splunk):** Splunk Enterprise, Universal Forwarder, SPL
- **Monitoring:** Windows Event Logs, Sysmon, PowerShell Script Block Logging
- **Analysis:** Authentication monitoring, detection engineering, attack-to-detection correlation

---

## Next Steps (Roadmap)

### Short Term
- [ ] Enable Sysmon telemetry on DC01 and WIN-01
- [ ] Forward WIN-01 to both Sentinel and Splunk
- [ ] PowerShell Script Block Logging across all systems
- [ ] Create baseline authentication queries (KQL + SPL)
- [ ] Document password-spray detection correlation

### Medium Term
- [ ] Kerberoasting detection (AS-REP, RC4-HMAC)
- [ ] BloodHound-based Active Directory attack paths
- [ ] Splunk dashboards (login timeline, failed auth heatmap)
- [ ] Sentinel workbooks (threat hunting, incident response)
- [ ] CrowdSec monitoring on KALI01 and SPLUNK-01

### Long Term
- [ ] Complete DFIR workflows (attack → detection → investigation → response)
- [ ] Phishing simulation and detection
- [ ] USB forensics lab
- [ ] Network packet analysis (Wireshark + zeek)
- [ ] Endpoint Detection & Response (EDR) comparison
- [ ] Tuning rules to reduce false positives across both platforms

---

## Repository Structure

```
SOC-Lab/
├── detection-engineering/
│   └── dual-siem/
│       ├── README.md (this file)
│       ├── queries/
│       │   ├── sentinel/
│       │   │   ├── authentication-failures.kql
│       │   │   ├── failed-logon-timeline.kql
│       │   │   └── ...
│       │   └── splunk/
│       │       ├── authentication-failures.spl
│       │       ├── failed-logon-timeline.spl
│       │       └── ...
│       ├── configs/
│       │   ├── dc01-uf-inputs.conf
│       │   ├── dc01-uf-outputs.conf
│       │   └── dcr-windows-security.json
│       ├── screenshots/
│       │   ├── sentinel-4625-events.png
│       │   ├── splunk-windows-stats.png
│       │   └── attack-to-detection-flow.png
│       └── lab-setup.md (VMware/Azure configs)
```

---

## Key Resources

**Microsoft Sentinel & Log Analytics**
- [Azure Arc for servers](https://learn.microsoft.com/en-us/azure/azure-arc/servers/overview)
- [Azure Monitor Agent](https://learn.microsoft.com/en-us/azure/azure-monitor/agents/agents-overview)
- [Data Collection Rules](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/data-collection-rule-overview)
- [KQL Quick Reference](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/tutorial)

**Splunk Enterprise**
- [Universal Forwarder Admin Manual](https://docs.splunk.com/Documentation/Forwarder)
- [SPL Basics](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/SearchCommandsOverview)

**Detection Engineering**
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Splunk Security Essentials](https://splunkbase.splunk.com/app/3435)
- [Azure Sentinel GitHub](https://github.com/Azure/Azure-Sentinel)

---

<div align="center">

**Last Updated:** August 2026  
**Maintainer:** [Dylans7j](https://github.com/Dylans7j)  
**Status:** Active Lab Environment

*See [SOC-Lab](https://github.com/Dylans7j/SOC-Lab) for full project scope.*

</div>
