# Dual-SIEM Lab Setup — Current Configuration Guide

This file supersedes older examples that confused Splunk Web with Splunk's forwarding receiver. See [WIN11 Splunk onboarding](../../docs/WIN11-SPLUNK-ONBOARDING.md) for the verified September 2026 deployment and [Dual-SIEM overview](./README.md) for current versus deferred work.

**Address redaction:** `192.169.70.x` is an illustrative placeholder used across public documentation. It is **not** the actual lab address and not RFC 1918 private address space. Insert your own permitted network addresses locally; do not copy a placeholder into live configurations.

## Verified configuration

| Area | Observed configuration |
| --- | --- |
| Virtualization | VMware, isolated host-only network and separate NAT adapter |
| WIN-01-W11 | Windows 11, hostname WIN11 |
| SPLUNK-01 | Ubuntu, Splunk Enterprise 10.4.2 |
| WIN11 forwarder | Splunk Universal Forwarder; service running |
| Receiver | **TCP 9997**, separate from Splunk Web |
| WIN11 index | `main` |
| Enabled Windows inputs | Security, System, PowerShell Operational, Sysmon Operational |
| Sysmon read access | Forwarder service identity in Event Log Readers |
| Current WIN11 Sentinel | **Not deployed**; Azure Arc and AMA absent at last check |

A captured Splunk query returned 11,892 WIN11 events across four channels, including 9,703 Sysmon events. The source screenshot needs to be sanitized and committed.

## Confirm a new Windows endpoint

On the endpoint:

```powershell
Get-NetIPConfiguration
Get-Service Sysmon64, SplunkForwarder -ErrorAction SilentlyContinue
Get-CimInstance Win32_Service -Filter "Name='SplunkForwarder'" |
  Select-Object Name, StartName, State
& 'C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe' list forward-server
```

On the Ubuntu Splunk server, confirm the **receiving** port:

```bash
sudo ss -lntp | grep ':9997'
```

In the forwarder's `etc/system/local/inputs.conf`:

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

If the service account is `NT SERVICE\SplunkForwarder` and it receives access-denied errors when subscribing to Sysmon, check the Sysmon channel ACL and use the existing Event Log Readers group where permitted. Restart the forwarder to refresh its group token.

## Ingestion and content validation

```spl
index=main host=WIN11 earliest=-24h
| stats count latest(_time) as lastEvent by source, sourcetype
| convert ctime(lastEvent)
| sort - count
```

```spl
index=main host=WIN11 earliest=-15m
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
| table _time, host, sourcetype, _raw
```

Inspect XML fields in a real event before building process or authentication detections. Source counts and a successful TCP connection are separate validation steps.

## Azure / Sentinel: deferred for WIN11

The current WIN11 does not have Azure Connected Machine Agent or Azure Monitor Agent installed. Previous Sentinel notes relate to earlier lab work and should not be interpreted as current WIN11 telemetry integration.

When resumed, verify the currently supported Azure Arc or Windows client deployment option, associate an appropriate Data Collection Rule and confirm Security and Sysmon events in the **actual** destination tables. Do not assume all Windows Security events appear in the `Event` table.

## Pending Active Directory steps

1. Identify DC-01's actual configured domain and DNS zone.
2. Resolve the missing queried LDAP SRV record or document the correct domain name.
3. Verify DC-01 Windows Security events in Splunk before analyzing DC-side authentication.
4. Generate limited authorized lab authentication failures using a disposable test account.
5. Save sanitized evidence before marking a detection validated.

**Never commit credentials, authentication tokens or real internal IPs.**
