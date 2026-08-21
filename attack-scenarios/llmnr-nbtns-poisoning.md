# Case Study 03: LLMNR/NBT-NS/mDNS Poisoning (Responder)

## Objective
Demonstrate credential capture via LLMNR/NBT-NS/mDNS poisoning against a domain-joined host, then validate detection coverage across Sentinel and Splunk using Sysmon and Windows Security event telemetry.

## Environment
- **Attacker:** KALI-01 (192.168.70.10) — Responder 3.2.2.0
- **Target:** DC-01 (192.168.70.20) — Windows Server 2022, domain `dc-01.lab`
- **Network:** VMware Workstation, VMnet7 host-only, 192.168.70.0/24, flat (no segmentation)
- **Telemetry:** Sysmon (olafhartong config) on DC-01 → Splunk Universal Forwarder (port 1137) + Azure Monitor Agent → Microsoft Sentinel (DCR-SOC-LAB-WINDOWS)
- **SIEM:** Splunk Enterprise 10.4.2 (indexes: `sysmon`, `windows`) and Microsoft Sentinel (KQL), dual-ingest from the same host

## Scope
Attack executed against DC-01 directly (not a dedicated workstation) because it was the only host in the lab with confirmed Sysmon + dual-SIEM ingestion at time of testing. Note: real-world LLMNR/NBT-NS poisoning typically targets end-user workstations, since DCs rarely generate ad-hoc mistyped-share lookups. This case study validates the detection pipeline; a follow-up run against WIN-01 (once domain-joined) will produce a more representative low-privilege-account result.

## Prerequisites
- Responder installed on KALI-01
- `/etc/responder/Responder.conf`: `LLMNR`, `NBTNS`, `MDNS` set to `On`
- KALI-01 and DC-01 on the same broadcast domain (VMnet7, flat — no bridging required)
- Sysmon + Splunk UF confirmed forwarding from DC-01 prior to test

## Recon
Confirmed via `-A` (analyze mode) that broadcast name-resolution traffic was visible on `eth0` before poisoning:
```bash
sudo responder -I eth0 -A
```

## Commands
Attacker (KALI-01):
```bash
sudo responder -I eth0
```

Victim trigger (DC-01, interactive session):
```powershell
dir \\fi1eshare\test
```

## Results
Responder poisoned MDNS/LLMNR/NBT-NS responses for the mistyped name `fi1eshare` and stood up a rogue SMB auth server. DC-01 authenticated to it, yielding a captured NTLMv2-SSP hash for `DC-01\Administrator`.

## Evidence
- Responder terminal output: poisoned answer log (MDNS/LLMNR/NBT-NS) + captured `NTLMv2-SSP Hash` for `DC-01\Administrator`
- Screenshot retained locally: Responder session showing full capture

## Telemetry
Two Sysmon/Security event sources confirmed the attack chain on the victim side:

| Event Source | Event ID | Purpose |
|---|---|---|
| Sysmon | 22 (DNS Query) | Captures the failed/mistyped hostname lookup that triggered LLMNR/NBT-NS fallback |
| Windows Security | 4648 (Explicit Credential Logon) | Captures the victim authenticating to the attacker-controlled rogue share |

## Splunk Detection
```spl
index=sysmon host=DC-01* EventCode=22
| table _time, Computer, User, Image, QueryName, QueryResults
```
```spl
index=windows host=DC-01* EventCode=4648
| table _time, EventCode, Source_Network_Address, Account_Name, Target_Server_Name
| sort 0 _time
```

## Sentinel Detection (KQL)
*Table/column names assumed from a standard AMA/DCR Windows Event ingestion — confirm against your actual Log Analytics schema (`Event` vs `SecurityEvent` table) before finalizing.*
```kql
Event
| where Computer == "DC-01.dc-01.lab"
| where EventID == 22
| project TimeGenerated, Computer, EventData
```
```kql
SecurityEvent
| where Computer == "DC-01.dc-01.lab"
| where EventID == 4648
| project TimeGenerated, EventID, IpAddress, TargetUserName, TargetServerName
| order by TimeGenerated asc
```

## Investigation
Correlating timestamps: Sysmon Event 22 (failed DNS resolution for `fi1eshare`) preceded Security Event 4648 (explicit logon to the rogue share) by a few seconds — consistent with the LLMNR/NBT-NS fallback → poisoned response → forced authentication chain. `Account_Name` on the 4648 event confirmed the compromised identity as `DC-01\Administrator`.

## MITRE ATT&CK Mapping
- **T1557.001** — Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay
- **T1552.001** (secondary, if hash is later cracked/relayed) — Unsecured Credentials

## Impact
Captured NTLMv2-SSP hash for a domain Administrator account. In a production environment, this is a critical finding — offline cracking or SMB relay against this credential could lead to full domain compromise.

## Remediation
- Disable LLMNR (Group Policy: Computer Configuration → Administrative Templates → Network → DNS Client → "Turn off multicast name resolution")
- Disable NetBIOS over TCP/IP where not required (per-adapter WINS settings, or DHCP option 001)
- Enforce SMB signing to prevent relay of captured hashes
- Restrict which accounts perform interactive/admin work on workstations vs. servers, reducing blast radius of a single poisoned response

## Lessons Learned
- Responder 3.1.3.0+ moved poisoner toggles (LLMNR/NBT-NS/MDNS) out of CLI flags and into `/etc/responder/Responder.conf` — the old `-wrf` combined-flag syntax no longer works
- Running the attack against a DC rather than a workstation produced a higher-severity but less realistic result (Administrator account exposure). Repeat against WIN-01 post-domain-join for a representative low-privilege case study
- Detection pipeline (Sysmon → dual SIEM) validated end-to-end on first attempt — no gaps found in Event 22 / 4648 capture on DC-01
