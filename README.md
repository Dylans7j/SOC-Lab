<div align="center">

# 🛡️ SOC-Lab

### Enterprise Active Directory Security Lab

![Platform](https://img.shields.io/badge/Platform-VMware%20Workstation-607078?style=flat-square)
![Domain](https://img.shields.io/badge/Domain-dc--01.lab-blue?style=flat-square)
![SIEM](https://img.shields.io/badge/SIEM-Microsoft%20Sentinel-0078D4?style=flat-square&logo=microsoftazure&logoColor=white)
![Status](https://img.shields.io/badge/Status-Active%20Build-yellow?style=flat-square)

`ACTIVE DIRECTORY` · `DETECTION ENGINEERING` · `SOC` · `DFIR` · `MITRE ATT&CK`

</div>

---

## // OVERVIEW

A multi-system cybersecurity home lab simulating a small enterprise environment — built for offensive security practice, SOC operations, detection engineering, and digital forensics.

The environment pairs an isolated Active Directory network with controlled internet access, so I can attack from Kali Linux, generate real Windows telemetry, investigate that activity in Microsoft Sentinel, and document the full **attack → detection → remediation** lifecycle end to end.

```
RECON → ENUMERATION → ATTACK/SIMULATION → TELEMETRY → DETECTION
   → INVESTIGATION → IMPACT ANALYSIS → REMEDIATION → DOCUMENTATION
```

---

## // LAB ARCHITECTURE

**Virtualization:** VMware Workstation

**Networks**

| Network | Purpose |
|---|---|
| `VMnet8` (NAT) | Internet access — updates, Azure connectivity, HTB VPN |
| `VMnet7` (host-only) | Isolated security lab network — `192.168.70.0/24`, no default gateway |

**Systems**

| Host | IP | Role |
|---|:---:|---|
| `KALI01` | `192.168.70.10` | Offensive security workstation |
| `DC-01` | `192.168.70.20` | Windows Server 2022 — Active Directory Domain Controller |
| `WIN-01` | `192.168.70.30` | Windows domain workstation |
| `WIN-02` | — | Secondary domain endpoint |

*Planned:* Splunk, Linux security monitoring, web application testing, phishing analysis, and DFIR nodes.

Kali runs dual interfaces so attack traffic stays isolated from the physical network while still allowing selected hosts a separate path to the internet:

```
eth0 → VMware NAT     → Internet / Updates / Hack The Box
eth1 → VMnet7          → 192.168.70.10/24 (internal lab, no gateway)
```

---

## // ACTIVE DIRECTORY ENVIRONMENT

Domain: **`dc-01.lab`**

The domain controller provides:

- Active Directory Domain Services
- DNS
- Kerberos authentication
- LDAP
- SMB
- Group Policy
- Organizational Units, domain users and groups

[**BadBlood**](https://github.com/davidprowe/BadBlood) is integrated to populate a larger, more realistic AD environment — built specifically for enumeration practice, BloodHound analysis, and attack-path discovery.

---

## // MICROSOFT SENTINEL INTEGRATION

The domain controller is connected via **Azure Arc** and the **Azure Monitor Agent**, forwarding Windows security telemetry into Microsoft Sentinel.

**Pipeline:**

```
KALI01
  ↓  attack / authentication activity
DC-01 / WIN-01
  ↓  Windows Security Events
Azure Monitor Agent
  ↓
Data Collection Rule  (DCR-SOC-LAB-WINDOWS)
  ↓
Log Analytics
  ↓
Microsoft Sentinel
```

The `DCR-SOC-LAB-WINDOWS` rule collects Windows Security audit **success and failure** events from every monitored host.

### Attack validation

Used **NetExec** to confirm connectivity and generate controlled authentication failures against the DC:

```bash
nxc smb 192.168.70.20 \
  -u Administrator \
  -p 'WrongPassword123!'
```

Result: `STATUS_LOGON_FAILURE` — confirming end-to-end communication between the attacker box and the AD environment, while generating telemetry investigable through Windows Event Logs and Sentinel.

Additional enumeration confirmed: Windows Server 2022, SMB on TCP/445, SMB signing enabled, SMBv1 disabled, and AD domain identification via NetExec's fingerprinting.

---

## // DETECTION ENGINEERING

The lab is built to correlate offensive actions directly with the defensive telemetry they generate.

**Planned Sentinel detections:**

- Failed authentication / password spraying
- Kerberos attacks
- Account creation & privileged group modification
- Suspicious PowerShell execution
- Lateral movement
- SMB activity
- Sysmon process execution
- Suspicious network connections

KQL powers the hunting queries, analytics rules, dashboards, and incident investigations built on top of this data.

### Endpoint telemetry — Sysmon

Sysmon is being layered onto Windows hosts for higher-fidelity endpoint visibility: process creation, network connections, file creation, registry modification, process access, and DNS queries — correlated against standard Windows Security events during investigations.

---

## // MULTI-SIEM EXPANSION

Designed to run more than one SIEM against the same telemetry, on purpose — the goal is translating detection logic across platforms rather than being locked into one:

| Platform | Query Language |
|---|:---:|
| Microsoft Sentinel | KQL |
| Splunk Enterprise | SPL |

---

## // DIGITAL FORENSICS & INCIDENT RESPONSE

Expanding into DFIR via a dedicated **CSI Linux** workstation. Planned investigation areas:

- Windows endpoint forensics
- USB device forensics
- Email and phishing analysis
- PCAP / network forensics
- File metadata analysis & timeline reconstruction
- Indicator-of-compromise extraction
- Incident reporting

### USB forensics

Controlled USB activity generated on Windows endpoints, investigated via:

`Registry hives` · `SetupAPI logs` · `LNK files` · `Jump Lists` · `Prefetch` · `ShellBags` · `$MFT` · `USN Journal`

Goal: identify which device connected, when, by which user, and what files were accessed or transferred.

### Email & phishing analysis

Controlled `.eml` investigations covering headers, Received chains, Return-Path, Reply-To, SPF/DKIM/DMARC, MIME structure, URLs, attachments, file hashes, and IOC extraction — each concluding in a formal incident report.

---

## // LINUX SECURITY

Ubuntu systems planned for: SSH monitoring, web-server logging, Linux privilege escalation, Docker security, `auditd`, and **CrowdSec** — used to demonstrate detection and automated remediation of hostile activity against Linux services.

---

## // OFFENSIVE TOOLKIT

`Nmap` · `NetExec` · `BloodHound` · `Impacket` · `Certipy` · `Burp Suite` · `Wireshark` · `ffuf` · `Gobuster` · `Hashcat` · `John the Ripper`

Hack The Box serves as the external training ground — techniques learned there get reproduced inside this lab so I can study both the offensive technique *and* the telemetry it generates.

---

## // METHODOLOGY

Every exercise documents:

1. Objective
2. Environment
3. Reconnaissance
4. Commands and methodology
5. Evidence
6. Telemetry
7. Detection logic
8. Investigation
9. MITRE ATT&CK mapping
10. Impact
11. Remediation
12. Lessons learned

---

## // SKILLS DEMONSTRATED

**Infrastructure:** Active Directory · Windows Server · DNS · Kerberos · LDAP · SMB · VMware networking · network segmentation

**Detection & SOC:** Microsoft Sentinel · Azure Arc · Azure Monitor Agent · Data Collection Rules · KQL · Sysmon · Windows Event Logs · Splunk · SPL

**Offensive:** Kali Linux · NetExec · BloodHound

**Blue team / Linux:** Linux security monitoring · CrowdSec

**DFIR:** Network forensics · USB forensics · phishing analysis · incident response

**Other:** Detection engineering · MITRE ATT&CK · technical documentation

---

## // PROJECT GOAL

This lab isn't about exploiting vulnerable systems for their own sake.

It's about understanding the **complete security lifecycle**: how an attacker discovers and abuses a weakness, what evidence that activity leaves behind, how a SOC analyst detects and investigates it, and how the weakness ultimately gets remediated.

<div align="center">

`BUILD // ATTACK // DETECT // DOCUMENT // REPEAT`

</div>
