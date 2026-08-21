# Detection Queries - KQL vs SPL

Side-by-side queries showing the same detection logic implemented in both Microsoft Sentinel (KQL) and Splunk Enterprise (SPL).

---

## 1. Failed Logon Detection

### Scenario
Identify failed login attempts (Event ID 4625) by source IP and target user to detect brute force or credential spray attacks.

### Microsoft Sentinel (KQL)

```kusto
Event
| where EventID == 4625
| extend 
    SourceIP = tostring(parse_json(EventData).IpAddress),
    TargetUser = tostring(parse_json(EventData).TargetUserName),
    Status = tostring(parse_json(EventData).Status),
    SubStatus = tostring(parse_json(EventData).SubStatus)
| summarize 
    FailedAttempts = count(), 
    FirstFailure = min(TimeGenerated),
    LastFailure = max(TimeGenerated)
    by SourceIP, TargetUser
| where FailedAttempts >= 5
| project SourceIP, TargetUser, FailedAttempts, FirstFailure, LastFailure
| sort by FailedAttempts desc
```

### Splunk Enterprise (SPL)

```spl
index=windows EventCode=4625
| rename IpAddress as SourceIP, TargetUserName as TargetUser
| stats count as FailedAttempts, earliest(_time) as FirstFailure, latest(_time) as LastFailure by SourceIP, TargetUser
| where FailedAttempts >= 5
| table SourceIP, TargetUser, FailedAttempts, FirstFailure, LastFailure
| sort - FailedAttempts
```

**Key Differences:**
- **KQL:** `parse_json()` to extract from nested EventData
- **SPL:** `rename` for field mapping, `_time` is built-in
- **KQL:** `where` at the end
- **SPL:** `where` after stats for filtering aggregations

---

## 2. Administrative Activity Timeline

### Scenario
Show all administrative logons (Event ID 4624, logon type 10 = RDP) with time-series visualization.

### Microsoft Sentinel (KQL)

```kusto
Event
| where EventID == 4624
| extend 
    LogonType = tostring(parse_json(EventData).LogonType),
    TargetUserName = tostring(parse_json(EventData).TargetUserName),
    SourceIP = tostring(parse_json(EventData).IpAddress),
    TargetDomainName = tostring(parse_json(EventData).TargetDomainName)
| where LogonType == "10"
| where TargetDomainName != "NT AUTHORITY"
| summarize LogonCount = count() by bin(TimeGenerated, 1m), TargetUserName
| render timechart
```

### Splunk Enterprise (SPL)

```spl
index=windows EventCode=4624 LogonType=10
| search NOT TargetDomainName="NT AUTHORITY"
| timechart count as LogonCount by TargetUserName
```

**Key Differences:**
- **KQL:** `bin(TimeGenerated, 1m)` for time bucketing
- **SPL:** `timechart` automatically buckets by time (default 5m)
- **KQL:** `render timechart` for visualization
- **SPL:** `timechart` is both query and visualization

---

## 3. PowerShell Script Block Logging - Suspicious Commands

### Scenario
Detect PowerShell commands containing suspicious patterns (IEX, DownloadString, etc.).

### Microsoft Sentinel (KQL)

```kusto
Event
| where EventID == 4104
| extend ScriptContent = tostring(parse_json(EventData).ScriptBlockText)
| where ScriptContent has_any ("IEX", "Invoke-Expression", "DownloadString", "WebClient", "Runspace")
| project 
    TimeGenerated,
    Computer,
    UserName,
    ScriptContent,
    EventID
| sort by TimeGenerated desc
```

### Splunk Enterprise (SPL)

```spl
index=powershell EventCode=4104
| search ScriptBlockText IN ("IEX", "Invoke-Expression", "DownloadString", "WebClient", "Runspace")
| table _time, Computer, UserName, ScriptBlockText, EventCode
| sort - _time
```

**Key Differences:**
- **KQL:** `has_any()` operator for multiple conditions
- **SPL:** `IN()` operator for array matching
- **KQL:** `TimeGenerated`
- **SPL:** `_time`

---

## 4. SMB Share Access - File Operations

### Scenario
Identify unusual SMB file access (Event ID 5145 - share object access) on sensitive shares.

### Microsoft Sentinel (KQL)

```kusto
Event
| where EventID == 5145
| extend 
    ShareName = tostring(parse_json(EventData).ShareName),
    SourceIP = tostring(parse_json(EventData).IpAddress),
    AccountName = tostring(parse_json(EventData).AccountName),
    ObjectName = tostring(parse_json(EventData).ObjectName),
    AccessMask = tostring(parse_json(EventData).AccessMask)
| where ShareName in ("C$", "IPC$", "ADMIN$")
| summarize AccessCount = count() by SourceIP, AccountName, ShareName
| where AccessCount > 10
| sort by AccessCount desc
```

### Splunk Enterprise (SPL)

```spl
index=windows EventCode=5145
| search ShareName IN ("C$", "IPC$", "ADMIN$")
| stats count as AccessCount by IpAddress, AccountName, ShareName
| where AccessCount > 10
| sort - AccessCount
```

**Key Differences:**
- **KQL:** `in()` for array membership
- **SPL:** `IN()` for search filtering
- **KQL:** `summarize` for aggregation
- **SPL:** `stats` for aggregation

---

## 5. Account Creation - New User Detection

### Scenario
Detect new local or domain user accounts created (Event ID 4720 for user, 4722 for group).

### Microsoft Sentinel (KQL)

```kusto
Event
| where EventID in (4720, 4722)
| extend 
    NewAccountName = tostring(parse_json(EventData).TargetUserName),
    CreatorSID = tostring(parse_json(EventData).SubjectUserSid),
    Computer = Computer
| project 
    TimeGenerated,
    EventID,
    Computer,
    NewAccountName,
    CreatorSID
| order by TimeGenerated desc
```

### Splunk Enterprise (SPL)

```spl
index=windows EventCode IN (4720, 4722)
| rename TargetUserName as NewAccountName, SubjectUserSid as CreatorSID
| table _time, EventCode, Computer, NewAccountName, CreatorSID
| sort - _time
```

**Key Differences:**
- **KQL:** `in()` with parentheses
- **SPL:** `IN()` without parentheses
- **KQL:** `order by`
- **SPL:** `sort`

---

## 6. Kerberos Attacks - Golden Ticket Detection

### Scenario
Detect Kerberos TGT (Ticket Granting Ticket) events that may indicate pass-the-ticket or golden ticket attacks (Event ID 4769, 4770).

### Microsoft Sentinel (KQL)

```kusto
Event
| where EventID in (4769, 4770)
| extend 
    ServiceName = tostring(parse_json(EventData).ServiceName),
    ClientAddress = tostring(parse_json(EventData).ClientAddress),
    TicketEncryptionType = tostring(parse_json(EventData).TicketEncryptionType)
| where TicketEncryptionType == "0x17"  // RC4-HMAC (often suspicious in modern environments)
| summarize TicketCount = count(), FirstEvent = min(TimeGenerated), LastEvent = max(TimeGenerated)
    by ServiceName, ClientAddress
| where TicketCount > 5
| sort by TicketCount desc
```

### Splunk Enterprise (SPL)

```spl
index=windows EventCode IN (4769, 4770) TicketEncryptionType=0x17
| stats count as TicketCount, earliest(_time) as FirstEvent, latest(_time) as LastEvent by ServiceName, ClientAddress
| where TicketCount > 5
| sort - TicketCount
```

**Key Differences:**
- **KQL:** Complex nested field extraction with `parse_json()`
- **SPL:** Direct field reference (more straightforward if forwarder extracts fields)
- **KQL:** `where` condition on extended field
- **SPL:** `where` condition in search

---

## 7. Lateral Movement - PsExec/WMI Detection

### Scenario
Detect lateral movement via Process Execution (Event ID 4688) showing command-line execution from suspicious tools.

### Microsoft Sentinel (KQL)

```kusto
Event
| where EventID == 4688
| extend 
    CommandLine = tostring(parse_json(EventData).CommandLine),
    NewProcessName = tostring(parse_json(EventData).NewProcessName),
    ParentProcessName = tostring(parse_json(EventData).ParentProcessName)
| where CommandLine has_any ("psexec", "psexec.exe", "C:\\Windows\\System32\\wbem\\wmic.exe")
    or NewProcessName has_any ("cmd.exe", "powershell.exe", "nslookup.exe")
| project 
    TimeGenerated,
    Computer,
    CommandLine,
    NewProcessName,
    ParentProcessName
| sort by TimeGenerated desc
```

### Splunk Enterprise (SPL)

```spl
index=windows EventCode=4688
| search (CommandLine IN ("psexec", "psexec.exe", "wmic.exe") OR NewProcessName IN ("cmd.exe", "powershell.exe", "nslookup.exe"))
| table _time, Computer, CommandLine, NewProcessName, ParentProcessName
| sort - _time
```

**Key Differences:**
- **KQL:** `has_any()` for multiple string patterns
- **SPL:** `IN()` for exact match in array
- **KQL:** Comprehensive field extraction
- **SPL:** Field names must match Splunk schema

---

## 8. Privilege Escalation - SeImpersonate/SeAssignPrimaryToken

### Scenario
Detect privilege escalation attempts using token impersonation (Event ID 4673).

### Microsoft Sentinel (KQL)

```kusto
Event
| where EventID == 4673
| extend 
    PrivilegeList = tostring(parse_json(EventData).PrivilegeList),
    AccountName = tostring(parse_json(EventData).SubjectUserName),
    ProcessName = tostring(parse_json(EventData).ProcessName)
| where PrivilegeList contains "SeImpersonate" or PrivilegeList contains "SeAssignPrimaryToken"
| project 
    TimeGenerated,
    Computer,
    AccountName,
    ProcessName,
    PrivilegeList
| sort by TimeGenerated desc
```

### Splunk Enterprise (SPL)

```spl
index=windows EventCode=4673
| search PrivilegeList IN ("SeImpersonate", "SeAssignPrimaryToken")
| table _time, Computer, SubjectUserName, ProcessName, PrivilegeList
| sort - _time
```

---

## 9. Persistence - Scheduled Task Creation

### Scenario
Detect suspicious scheduled task creation (Event ID 4698, 4699, 4700, 4701).

### Microsoft Sentinel (KQL)

```kusto
Event
| where EventID in (4698, 4699, 4700, 4701)
| extend 
    TaskName = tostring(parse_json(EventData).TaskName),
    TaskContent = tostring(parse_json(EventData).TaskContentNew),
    CreatorSID = tostring(parse_json(EventData).SubjectUserSid)
| where TaskContent contains "powershell" or TaskContent contains "cmd.exe" or TaskContent contains "wscript"
| project 
    TimeGenerated,
    Computer,
    TaskName,
    TaskContent,
    EventID
| sort by TimeGenerated desc
```

### Splunk Enterprise (SPL)

```spl
index=windows EventCode IN (4698, 4699, 4700, 4701)
| search TaskContentNew IN ("powershell", "cmd.exe", "wscript")
| table _time, Computer, TaskName, TaskContentNew, EventCode
| sort - _time
```

---

## 10. Data Exfiltration - Large File Transfer Detection

### Scenario
Detect abnormally large SMB file transfers (Event ID 5145 with large sizes).

### Microsoft Sentinel (KQL)

```kusto
Event
| where EventID == 5145
| extend 
    ShareName = tostring(parse_json(EventData).ShareName),
    ObjectName = tostring(parse_json(EventData).ObjectName),
    AccessMask = tostring(parse_json(EventData).AccessMask),
    RelativeTargetName = tostring(parse_json(EventData).RelativeTargetName)
| where ShareName != "IPC$"
| summarize AccessCount = count() by ShareName, ObjectName
| where AccessCount > 100
| sort by AccessCount desc
```

### Splunk Enterprise (SPL)

```spl
index=windows EventCode=5145
| search NOT ShareName="IPC$"
| stats count as AccessCount by ShareName, ObjectName
| where AccessCount > 100
| sort - AccessCount
```

---

## Running Detections

### Schedule in Sentinel

1. **Create Analytics Rule** → **Scheduled Query Rule**
2. Paste KQL query
3. Set **Run query** to every 5 minutes (adjust as needed)
4. Configure **Trigger alert** threshold (e.g., > 5 results)
5. Assign incident **Severity** and **Tactics** (MITRE ATT&CK)

### Schedule in Splunk

1. **Saved Searches** → **New Search**
2. Paste SPL query
3. **Save As** → set **Search name** and **Description**
4. **Schedule this search** → set frequency
5. **Alert** → choose trigger condition
6. **Add action** (email, webhook, etc.)

---

<div align="center">

**Tip:** These queries are starting points. Tune thresholds and conditions based on your lab's baseline behavior.

See the main [README.md](./README.md) for architecture and [DUAL-SIEM-SETUP.md](./DUAL-SIEM-SETUP.md) for configuration steps.

</div>
