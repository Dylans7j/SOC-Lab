# WIN11 → Splunk: Onboarding and Troubleshooting

**Status:** verified through operator-provided PowerShell outputs and Splunk search screenshots in September 2026. Sanitized evidence images still need to be added to the repository.

**Public network notation:** `192.169.70.x` is a redaction placeholder, **not** the real configuration or a private network recommendation. No actual interface addresses, gateway addresses or NAT leases are published in this document.

## Validated components

- WIN-01-W11 is the VM label; `WIN11` is the hostname returned by Windows and indexed in Splunk.
- Windows 11 has separate lab-only and NAT virtual network interfaces.
- Local Sysmon service runs and its Operational channel is enabled.
- Splunk Universal Forwarder runs under `NT SERVICE\SplunkForwarder` and actively forwards to SPLUNK-01 on **TCP 9997**.
- Splunk indexed Windows Security, System, PowerShell Operational and Sysmon Operational in index `main`.

## Reproducible configuration

Confirm your **own** authorized lab addresses locally rather than pasting a documented example into production.

```powershell
Get-NetIPConfiguration
Get-Service Sysmon64, SplunkForwarder
Get-CimInstance Win32_Service -Filter "Name='SplunkForwarder'" |
    Select-Object Name, StartName, State
& 'C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe' list forward-server
```

The confirmed WIN11 event inputs in `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf` are:

```ini
[WinEventLog://Security]
disabled = 0
index = main
renderXml = 1

[WinEventLog://System]
disabled = 0
index = main
renderXml = 1

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = main
renderXml = 1

[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = 0
index = main
renderXml = 1
```

Reload after changes with `Restart-Service SplunkForwarder`, then inspect effective configuration:

```powershell
& 'C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe' btool inputs list --debug |
    Select-String 'Sysmon' -Context 2,8
```

## Sysmon subscription failure and resolution

Sysmon had more than 31,000 local events, including recent process-creation events (Event ID 1), but the forwarder initially logged:

```text
Could not subscribe to Windows Event Log channel
'Microsoft-Windows-Sysmon/Operational'
errorCode=5
```

Windows `wevtutil gl Microsoft-Windows-Sysmon/Operational` showed read permission for the built-in Event Log Readers group. The forwarder service identity was `NT SERVICE\SplunkForwarder`. The observed repair was to add that identity to the existing group and restart the forwarder:

```powershell
Add-LocalGroupMember -Group 'Event Log Readers' -Member 'NT SERVICE\SplunkForwarder'
Restart-Service SplunkForwarder
Get-LocalGroupMember -Group 'Event Log Readers'
```

The membership was verified. A subsequent log-tail check contained no new access-denied messages, and a Splunk search showed real Sysmon-source events. No broad Sysmon channel ACL rewrite was necessary.

## Actual ingestion validation

Do **not** confuse a search for the word `Sysmon` with real Sysmon ingestion: PowerShell logs can contain commands mentioning that word.

```spl
index=* host=WIN11
| stats count latest(_time) as lastEvent by index, source, sourcetype
| convert ctime(lastEvent)
| sort - count
```

| Actual source | Captured count over selected 24 hours |
| --- | ---: |
| `WinEventLog:Microsoft-Windows-Sysmon/Operational` | 9,703 |
| `WinEventLog:Security` | 1,683 |
| `WinEventLog:Microsoft-Windows-PowerShell/Operational` | 406 |
| `WinEventLog:System` | 100 |
| **Total** | **11,892** |

The data had XML event sourcetypes because `renderXml=1`. If searches by `Image`, `ParentImage` or `EventCode` fail, inspect actual indexed `_raw` data and field extractions first.

## Next evidence milestone

```powershell
Start-Process notepad.exe
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id = 1
    StartTime = (Get-Date).AddMinutes(-5)
} -ErrorAction SilentlyContinue |
    Select-Object -First 5 TimeCreated, Id
```

```spl
index=main host=WIN11 earliest=-15m
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
| table _time, host, source, sourcetype, _raw
| sort - _time
```

Attach a sanitized output screenshot with timestamp context. WIN11's Microsoft Sentinel onboarding is deferred; this write-up documents **Splunk**, not demonstrated simultaneous dual-SIEM ingestion.

## Hardening backlog

The forwarder logs indicated receiver-certificate verification was disabled and a Splunk default certificate was present. Replace the receiving certificate, configure an appropriate trusted certificate authority and test authentication before claiming encrypted transport is correctly authenticated.
