# 🛡️ Splunk Windows Attack Detection Cheat Sheet

![Splunk](https://img.shields.io/badge/Splunk-SPL-black?logo=splunk)
![Windows](https://img.shields.io/badge/Platform-Windows%20AD-blue?logo=windows)
![License](https://img.shields.io/badge/license-MIT-green)

> A field-reference collection of Splunk (SPL) detection queries for common Active Directory / Windows attack techniques — Kerberoasting, Golden/Silver Tickets, Pass-the-Hash/Ticket, delegation abuse, DCSync/DCShadow, C2 beaconing, ransomware, and more.
>
> Compiled from *"Detecting Windows Attacks with Splunk"* (CDSA path).

---

## 📑 Table of Contents

1. [Domain Recon](#1-domain-recon)
2. [Password Spraying](#2-password-spraying)
3. [Responder-like Attacks (LLMNR/NBT-NS/mDNS Poisoning)](#3-responder-like-attacks-llmnrnbt-nsmdns-poisoning)
4. [Kerberoasting / AS-REPRoasting](#4-kerberoasting--as-reproasting)
5. [Pass-the-Hash](#5-pass-the-hash)
6. [Pass-the-Ticket](#6-pass-the-ticket)
7. [Overpass-the-Hash](#7-overpass-the-hash-targeting-rubeus)
8. [Golden Tickets / Silver Tickets](#8-golden-tickets--silver-tickets)
9. [Unconstrained / Constrained Delegation](#9-unconstrained--constrained-delegation)
10. [DCSync / DCShadow](#10-dcsync--dcshadow)
11. [RDP / SSH Brute Force](#11-rdp--ssh-brute-force-zeekbro-logs)
12. [Nmap Port Scanning](#12-nmap-port-scanning)
13. [Beaconing Malware (Cobalt Strike C2)](#13-beaconing-malware-cobalt-strike-c2)
14. [Cobalt Strike PSExec / SharpNoPSExec](#14-cobalt-strike-psexec--sharpnopsexec)
15. [Zerologon (CVE-2020-1472)](#15-zerologon-cve-2020-1472)
16. [Exfiltration - HTTP(S)](#16-exfiltration---https)
17. [Exfiltration - DNS](#17-exfiltration---dns)
18. [Ransomware](#18-ransomware)
19. [Key Windows Event ID Reference](#quick-reference-key-windows-event-ids)

---

## 1. Domain Recon

**Native Windows executables (Sysmon EID 1)**
```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
| search process_name IN (arp.exe,chcp.com,ipconfig.exe,net.exe,net1.exe,nltest.exe,ping.exe,systeminfo.exe,whoami.exe) OR (process_name IN (cmd.exe,powershell.exe) AND process IN (*arp*,*chcp*,*ipconfig*,*net*,*net1*,*nltest*,*ping*,*systeminfo*,*whoami*))
| stats values(process) as process, min(_time) as _time by parent_process, parent_process_id, dest, user
| where mvcount(process) > 3
```

**BloodHound / SharpHound (SilkETW LDAP logging)**
```spl
index=main source="WinEventLog:SilkService-Log"
| spath input=Message
| rename XmlEventData.* as *
| table _time, ComputerName, ProcessName, ProcessId, DistinguishedName, SearchFilter
| sort 0 _time
| search SearchFilter="*(samAccountType=805306368)*"
| stats min(_time) as _time, max(_time) as maxTime, count, values(SearchFilter) as SearchFilter by ComputerName, ProcessName, ProcessId
| where count > 10
| convert ctime(maxTime)
```

---

## 2. Password Spraying

**EventCode 4625 (failed logons), 15-min bins**
```spl
index=main source="WinEventLog:Security" EventCode=4625
| bin span=15m _time
| stats values(user) as Users, dc(user) as dc_user by src, Source_Network_Address, dest, EventCode, Failure_Reason
```
Related Event IDs: `4768` (0x6 invalid user / 0x12 disabled), `4776` (0xC000006A invalid / 0xC0000064 wrong pw), `4648`, `4771`.

---

## 3. Responder-like Attacks (LLMNR/NBT-NS/mDNS Poisoning)

```spl
index=main SourceName=LLMNRDetection
| table _time, ComputerName, SourceName, Message
```
**Sysmon Event 22 — DNS query monitoring**
```spl
index=main EventCode=22
| table _time, Computer, user, Image, QueryName, QueryResults
```
**Explicit logon (Event 4648) to rogue shares**
```spl
index=main EventCode IN (4648)
| table _time, EventCode, source, name, user, Target_Server_Name, Message
| sort 0 _time
```

---

## 4. Kerberoasting / AS-REPRoasting

**Benign TGS requests baseline**
```spl
index=main EventCode=4648 OR (EventCode=4769 AND service_name=iis_svc)
| dedup RecordNumber
| rex field=user "(?<username>[^@]+)"
| table _time, ComputerName, EventCode, name, username, Account_Name, Account_Domain, src_ip, service_name, Ticket_Options, Ticket_Encryption_Type, Target_Server_Name, Additional_Information
```

**SPN querying (LDAP filter for Kerberoastable accounts)**
```spl
index=main source="WinEventLog:SilkService-Log"
| spath input=Message
| rename XmlEventData.* as *
| table _time, ComputerName, ProcessName, DistinguishedName, SearchFilter
| search SearchFilter="*(&(samAccountType=805306368)(servicePrincipalName=*)*"
```

**TGS requests without a following logon**
```spl
index=main EventCode=4648 OR (EventCode=4769 AND service_name=iis_svc)
| dedup RecordNumber
| rex field=user "(?<username>[^@]+)"
| bin span=2m _time
| search username!=*$
| stats values(EventCode) as Events, values(service_name) as service_name, values(Additional_Information) as Additional_Information, values(Target_Server_Name) as Target_Server_Name by _time, username
| where !match(Events,"4648")
```

**Same, using `transaction`**
```spl
index=main EventCode=4648 OR (EventCode=4769 AND service_name=iis_svc)
| dedup RecordNumber
| rex field=user "(?<username>[^@]+)"
| search username!=*$
| transaction username keepevicted=true maxspan=5s endswith=(EventCode=4648) startswith=(EventCode=4769)
| where closed_txn=0 AND EventCode=4769
| table _time, EventCode, service_name, username
```

**AS-REPRoasting — accounts with pre-auth disabled (LDAP)**
```spl
index=main source="WinEventLog:SilkService-Log"
| spath input=Message
| rename XmlEventData.* as *
| table _time, ComputerName, ProcessName, DistinguishedName, SearchFilter
| search SearchFilter="*(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304)*"
```

**AS-REPRoasting — TGT requests, Pre-Auth=0**
```spl
index=main source="WinEventLog:Security" EventCode=4768 Pre_Authentication_Type=0
| rex field=src_ip "(\:\:ffff\:)?(?<src_ip>[0-9\.]+)"
| table _time, src_ip, user, Pre_Authentication_Type, Ticket_Options, Ticket_Encryption_Type
```

**Kerberoasting via Zeek (rc4-hmac TGS requests)**
```spl
index="sharphound" sourcetype="bro:kerberos:json"
request_type=TGS cipher="rc4-hmac"
forwardable="true" renewable="true"
| table _time, id.orig_h, id.resp_h, request_type, cipher, forwardable, renewable, client, service
```
> Port: **88**

---

## 5. Pass-the-Hash

**runas /netonly (EID 4624, LogonType 9, Logon_Process=seclogo)**
```spl
index=main source="WinEventLog:Security" EventCode=4624 Logon_Type=9 Logon_Process=seclogo
| table _time, ComputerName, EventCode, user, Network_Account_Domain, Network_Account_Name, Logon_Type, Logon_Process
```

**Enhanced: correlate with LSASS memory access (Sysmon EID 10)**
```spl
index=main (source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10 TargetImage="C:\\Windows\\system32\\lsass.exe" SourceImage!="C:\\ProgramData\\Microsoft\\Windows Defender\\platform\\*\\MsMpEng.exe") OR (source="WinEventLog:Security" EventCode=4624 Logon_Type=9 Logon_Process=seclogo)
| sort _time, RecordNumber
| transaction host maxspan=1m endswith=(EventCode=4624) startswith=(EventCode=10)
| stats count by _time, Computer, SourceImage, SourceProcessId, Network_Account_Domain, Network_Account_Name, Logon_Type, Logon_Process
| fields - count
```

---

## 6. Pass-the-Ticket

```spl
index=main source="WinEventLog:Security" user!=*$ EventCode IN (4768,4769,4770)
| rex field=user "(?<username>[^@]+)"
| rex field=src_ip "(\:\:ffff\:)?(?<src_ip_4>[0-9\.]+)"
| transaction username, src_ip_4 maxspan=10h keepevicted=true startswith=(EventCode=4768)
| where closed_txn=0
| search NOT user="*$@*"
| table _time, ComputerName, username, src_ip_4, service_name, category
```
Logic: TGS/TGS-renewal (4769/4770) with no prior TGT request (4768) from the same host = imported ticket.

---

## 7. Overpass-the-Hash (targeting Rubeus)

```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode=3 dest_port=88 Image!=*lsass.exe) OR EventCode=1
| eventstats values(process) as process by process_id
| where EventCode=3
| stats count by _time, Computer, dest_ip, dest_port, Image, process
| fields - count
```
Indicator: unusual process making outbound connections to TCP/UDP 88 (Kerberos).

---

## 8. Golden Tickets / Silver Tickets

**Golden Ticket — "yet another ticket to pass" approach (same as PtT search)**
```spl
index=main source="WinEventLog:Security" user!=*$ EventCode IN (4768,4769,4770)
| rex field=user "(?<username>[^@]+)"
| rex field=src_ip "(\:\:ffff\:)?(?<src_ip_4>[0-9\.]+)"
| transaction username, src_ip_4 maxspan=10h keepevicted=true startswith=(EventCode=4768)
| where closed_txn=0
| search NOT user="*$@*"
| table _time, ComputerName, username, src_ip_4, service_name, category
```
> Port: **88**

**Golden Ticket via Zeek — TGS with no matching AS-REQ/AS-REP**
```spl
index="golden_ticket_attack" sourcetype="bro:kerberos:json"
| where client!="-"
| bin _time span=1m
| stats values(client), values(request_type) as request_types, dc(request_type) as unique_request_types by _time, id.orig_h, id.resp_h
| where request_types=="TGS" AND unique_request_types==1
```

**Silver Ticket — build users.csv lookup from account creation (EID 4720)**
```spl
index=main EventCode=4720
| stats min(_time) as _time, values(EventCode) as EventCode by user
| outputlookup users.csv
```

**Silver Ticket — logons (4624) not present in users.csv**
```spl
index=main EventCode=4624
| stats min(_time) as firstTime, values(ComputerName) as ComputerName, values(EventCode) as EventCode by user
| eval last24h=relative_time(now(),"-24h@h")
| where firstTime > last24h
| convert ctime(firstTime)
| convert ctime(last24h)
| lookup users.csv user as user OUTPUT EventCode as Events
| where isnull(Events)
```

**Silver Ticket — anomalous special privileges assigned (EID 4672)**
```spl
index=main EventCode=4672
| stats min(_time) as firstTime, values(ComputerName) as ComputerName by Account_Name
| eval last24h=relative_time(now(),"-24h@h")
| where firstTime > last24h
| table firstTime, ComputerName, Account_Name
| convert ctime(firstTime)
```

---

## 9. Unconstrained / Constrained Delegation

**Unconstrained Delegation recon (PowerShell 4104)**
```spl
index=main source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104 Message="*TrustedForDelegation*" OR Message="*userAccountControl:1.2.840.113556.1.4.803:=524288*"
| table _time, ComputerName, EventCode, Message
```

**Constrained Delegation recon — PowerShell logs (msDS-AllowedToDelegateTo)**
```spl
index=main source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104 Message="*msDS-AllowedToDelegateTo*"
| table _time, ComputerName, EventCode, Message
```

**Constrained Delegation — Sysmon, unusual process → port 88**
```spl
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| eventstats values(process) as process by process_id
| where EventCode=3 AND dest_port=88
| table _time, Computer, dest_ip, dest_port, Image, process
```

---

## 10. DCSync / DCShadow

**DCSync — replication rights request (EID 4662)**
```spl
index=main EventCode=4662 Message="*Replicating Directory Changes*"
| rex field=Message "(?P<property>Replicating Directory Changes.*)"
| table _time, user, object_file_name, Object_Server, property
```
Look for GUID `{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}` (DS-Replication-Get-Changes). Requires enabling DS Access auditing.

**DCShadow — rogue DC registration, Global Catalog SPN added (EID 4742)**
```spl
index=main EventCode=4742
| rex field=Message "(?P<gcspn>GC\/[a-zA-Z0-9\.\-\/]+)"
| table _time, ComputerName, Security_ID, Account_Name, user, gcspn
| search gcspn=*
```
(`GC` = Global Catalog SPN prefix — the field is literally named `gcspn`.)

---

## 11. RDP / SSH Brute Force (Zeek/Bro logs)

**RDP brute force**
```spl
index="rdp_bruteforce" sourcetype="bro:rdp:json"
| bin _time span=5m
| stats count values(cookie) by _time, id.orig_h, id.resp_h
| where count>30
```

**SSH brute force**
```spl
index="ssh_bruteforce" sourcetype="bro:ssh:json"
auth_success="false"
| bin _time span=5m
| stats sum(auth_attempts) as num_attempts by _time, id.orig_h, id.resp_h, client, server
| where num_attempts>30
```

**Kerberos brute force / user enumeration**
```spl
index="kerberos_bruteforce" sourcetype="bro:kerberos:json"
error_msg!=KDC_ERR_PREAUTH_REQUIRED
success="false" request_type=AS
| bin _time span=5m
| stats count dc(client) as "Unique users" values(error_msg) as "Error messages" by _time, id.orig_h, id.resp_h
| where count>30
```

---

## 12. Nmap Port Scanning

```spl
index="cobaltstrike_beacon" sourcetype="bro:conn:json" orig_bytes=0 dest_ip IN (192.168.0.0/16, 172.16.0.0/12, 10.0.0.0/8)
| bin span=5m _time
| stats dc(dest_port) as num_dest_port by _time, src_ip, dest_ip
| where num_dest_port >= 3
```

---

## 13. Beaconing Malware (Cobalt Strike C2)

```spl
index="cobaltstrike_beacon" sourcetype="bro:http:json"
| sort 0 _time
| streamstats current=f last(_time) as prevtime by src, dest, dest_port
| eval timedelta = _time - prevtime
| eventstats avg(timedelta) as avg, count as total by src, dest, dest_port
| eval upper=avg*1.1
| eval lower=avg*0.9
| where timedelta > lower AND timedelta < upper
| stats count, values(avg) as TimeInterval by src, dest, dest_port, total
| eval prcnt = (count/total)*100
| where prcnt > 90 AND total > 10
```
Detects consistent, regular time intervals between connections (the hallmark of beacon jitter/sleep timers). `timechart` is also a quick one-word way to visually spot this.

---

## 14. Cobalt Strike PSExec / SharpNoPSExec

**Classic PSExec — file drop to C$/ADMIN$**
```spl
index="cobalt_strike_psexec" sourcetype="bro:smb_files:json"
action="SMB::FILE_OPEN"
name IN ("*.exe", "*.dll", "*.bat")
path IN ("*\\c$", "*\\ADMIN$")
size>0
```
Runs over port **445** (SMB), requires local admin.

**SharpNoPSExec — abuses SVCCTL to reconfigure an existing service (no file drop)**
```spl
index="change_service_config" sourcetype="bro:dce_rpc:json"
endpoint="svcctl"
operation="ChangeServiceConfigW"
| table _time, id.orig_h, id.resp_h, endpoint, operation
```

---

## 15. Zerologon (CVE-2020-1472)

```spl
index="zerologon" endpoint="netlogon" sourcetype="bro:dce_rpc:json"
| bin _time span=1m
| where operation == "NetrServerReqChallenge" OR operation == "NetrServerAuthenticate3" OR operation == "NetrServerPasswordSet2"
| stats count values(operation) as operation_values dc(operation) as unique_operations by _time, id.orig_h, id.resp_h
| where unique_operations >= 2 AND count>100
```
Runs over DCE-RPC / Netlogon — **not** port 88.

---

## 16. Exfiltration - HTTP(S)

**HTTP POST body exfil**
```spl
index="cobaltstrike_exfiltration_http" sourcetype="bro:http:json" method=POST
| stats sum(request_body_len) as TotalBytes by src, dest, dest_port
| eval TotalBytes = TotalBytes/1024/1024
```

**HTTPS volume-based exfil**
```spl
index="cobaltstrike_exfiltration_https" sourcetype="bro:conn:json"
id.resp_p=443
| stats sum(orig_bytes) as bytes_sent count by id.orig_h, id.resp_h
| sort -bytes_sent
```

---

## 17. Exfiltration - DNS

**Quick frequency check**
```spl
index="dns_exf" sourcetype="bro:dns:json"
| stats count by query
| sort -count
```

**Refined — long/high-entropy queries, excluding noise**
```spl
index=dns_exf sourcetype="bro:dns:json"
| eval len_query=len(query)
| search len_query>=40 AND query!="*.ip6.arpa*" AND query!="*amazonaws.com*" AND query!="*._googlecast.*" AND query!="_ldap.*"
| bin _time span=24h
| stats count(query) as req_by_day by _time, id.orig_h, id.resp_h
| where req_by_day>60
| table _time, id.orig_h, id.resp_h, req_by_day
```

---

## 18. Ransomware

**Excessive file overwrite (open+rename pair, e.g. Sodinokibi)**
```spl
index="ransomware_open_rename_sodinokibi" sourcetype="bro:smb_files:json"
| where action IN ("SMB::FILE_OPEN", "SMB::FILE_RENAME")
| bin _time span=5m
| stats count by _time, source, action
| where count>30
| stats sum(count) as count values(action) dc(action) as uniq_actions by _time, source
| where uniq_actions==2 AND count>100
```

**Same pattern, modified to detect DELETE-based ransomware**
```spl
index="ransomware_excessive_delete_aleta" sourcetype="bro:smb_files:json"
| where action IN ("SMB::FILE_OPEN", "SMB::FILE_DELETE")
| bin _time span=5m
| stats count by _time, source, action
| where count>30
| stats sum(count) as count values(action) dc(action) as uniq_actions by _time, source
| where uniq_actions==2 AND count>100
```

**Excessive renaming with a new/consistent extension (e.g. CTB-Locker)**
```spl
index="ransomware_new_file_extension_ctbl_ocker" sourcetype="bro:smb_files:json" action="SMB::FILE_RENAME"
| bin _time span=5m
| rex field="name" "\.(?<new_file_name_extension>[^\.]*$)"
| rex field="prev_name" "\.(?<old_file_name_extension>[^\.]*$)"
| stats count by _time, id.orig_h, id.resp_p, name, source, old_file_name_extension, new_file_name_extension
| where new_file_name_extension!=old_file_name_extension
| stats count by _time, id.orig_h, id.resp_p, source, new_file_name_extension
| where count>20
| sort -count
```
Reference list of ransomware extensions: github.com/corelight/detect-ransomware-filenames, fsrm.experiant.ca

---

## Quick-Reference: Key Windows Event IDs

| EID | Meaning |
|---|---|
| 4104 | PowerShell script block logging |
| 4624 | Successful logon (LogonType 9 = NewCredentials/runas /netonly) |
| 4625 | Failed logon |
| 4648 | Explicit credential logon |
| 4662 | Object access (DCSync = `{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}`) |
| 4672 | Special privileges assigned |
| 4720 | User account created |
| 4742 | Computer account changed (DCShadow SPN) |
| 4768 | Kerberos TGT request |
| 4769 | Kerberos TGS (service ticket) request |
| 4770 | Kerberos service ticket renewed |
| 4771 | Kerberos pre-auth failed |
| 4776 | NTLM authentication |
| Sysmon 1 | Process creation |
| Sysmon 3 | Network connection |
| Sysmon 10 | Process access (e.g., LSASS memory read) |
| Sysmon 22 | DNS query |

## Notes on this Cheat Sheet
- Timeframes (`earliest=`/`latest=`) in the original searches are lab-specific epoch timestamps — drop them or set "All time" for live/other environments.
- Several searches assume Zeek/Bro JSON logs (`sourcetype=bro:*:json`) alongside native Windows Event Logs — check which log source your environment actually has before reusing.
- "One word" Cobalt Strike beaconing detector: **`timechart`** — worth double-checking against `transaction` depending on exactly what's being asked.

---

<sub>⚠️ For defensive/educational use in authorized environments only. Adapt index/sourcetype names to your own Splunk deployment before use.</sub>

