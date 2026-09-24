# Dual-SIEM Active Directory Monitoring Lab

> **Current status, September 2026:** WIN11 → Splunk event ingestion is verified. The existing Microsoft Sentinel work remains documented separately; the **new WIN11 endpoint has not been onboarded to Sentinel**. Simultaneous ingestion of WIN11 telemetry into both products has not been demonstrated.

## Architecture and address notation

Public documentation intentionally uses `192.169.70.x` as an **illustrative placeholder only**, not the actual lab subnet. It is not RFC 1918 private address space. Substitute authorized local IP addresses when configuring your own lab.

| Component | Role | Status |
| --- | --- | --- |
| Kali | Controlled offensive-testing workstation | Lab workstation |
| DC-01 | Domain controller, DNS and authentication telemetry | LDAP reachability verified; queried AD DNS SRV record unresolved; current Splunk forwarding needs verification |
| WIN-01-W11 / hostname WIN11 | Windows 11 endpoint | **Four log channels indexed in Splunk** |
| SPLUNK-01 | Ubuntu / Splunk Enterprise 10.4.2 | **Receiving on TCP 9997** |
| Microsoft Sentinel | Azure cloud SIEM | Prior research documented; **WIN11 integration deferred** |

```text
    VMware isolated lab (public address placeholder: 192.169.70.x)

    DC-01 ── LDAP connectivity confirmed ── WIN11
                                         │
                       Security / System / Sysmon / PowerShell
                                         │
                             Splunk Universal Forwarder
                                         │ TCP 9997
                                         ▼
                                     SPLUNK-01
                                         │
                                       Splunk

    WIN11 → Azure Monitor Agent / Sentinel: deferred
```

The verified receiver is **TCP 9997**. TCP 1137 was the server's configured Splunk Web port during setup, not its ingestion port. Earlier instructions conflating those ports are superseded by this document.

## WIN11 ingestion: observed evidence

The Windows 11 VM has two network interfaces (a lab-only adapter and a separate NAT adapter). The forwarder runs as `NT SERVICE\SplunkForwarder` and shows the Splunk server under **Active forwards**.

| Channel | Captured events in one 24-hour Splunk search |
| --- | ---: |
| Sysmon Operational | 9,703 |
| Security | 1,683 |
| PowerShell Operational | 406 |
| System | 100 |
| **Total** | **11,892** |

Sysmon Event ID 1 was present locally. Initial forwarder logs showed `errorCode=5` when subscribing to `Microsoft-Windows-Sysmon/Operational`. The service account was added to the local **Event Log Readers** group and the service restarted; a later search confirmed indexed Sysmon source events. Screenshots were shown during validation; sanitized evidence files still need to be committed.

### Current WIN11 inputs

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

With `renderXml=1`, verify actual source and sourcetype names before depending on automatic field extraction:

```spl
index=main host=WIN11 earliest=-24h
| stats count latest(_time) as lastEvent by source, sourcetype
| convert ctime(lastEvent)
| sort - count
```

```spl
index=main host=WIN11 earliest=-30m
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
| stats count by EventCode
```

If field-based searches return no results, inspect `_raw` for an actual indexed event and normalize field extraction. A text search for `Sysmon` may match PowerShell command history rather than Sysmon-source events.

## Microsoft Sentinel research

Previous lab documentation and KQL investigations are preserved as historical project work. However, WIN11 had neither Azure Arc Connected Machine Agent nor Azure Monitor Agent at the last check. Its Sentinel connection is postponed.

A future WIN11 onboarding project will verify the agent, Data Collection Rules, event destinations and applicable Log Analytics tables, then confirm identical controlled events in both SIEMs. **Do not label this new dual-SIEM correlation as completed yet.**

## Next controlled investigation

1. Verify the DNS zone/domain name on DC-01 and investigate the missing queried AD SRV record.
2. Check DC-01 Windows Security event collection in Splunk.
3. Generate a small number of failed authentications using an authorized disposable lab account, accounting for lockout thresholds.
4. Investigate the actual events: endpoint 4625 and DC-side 4771/4776 as applicable.
5. Validate SPL logic, build a Sigma counterpart and publish sanitized evidence, scope, timestamps, limitations and remediation.

## Additional resources

- [SOC-Lab overview](../../README.md)
- [Detection query documentation](./detection-queries.md)
- [Prior lab setup notes](./lab-setup.md) — historical examples; verify against this page before applying
- [Evidence requirements](../../docs/EVIDENCE-STANDARD.md)

**Security hardening backlog:** Splunk's forwarder log warned that its output connection did not verify the receiving certificate and that a default certificate was present. A trusted receiving certificate and tested forwarder verification remain future hardening tasks.
