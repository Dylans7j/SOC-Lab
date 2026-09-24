# INC-002 — Active Directory Authentication Investigation

## Executive Summary

This investigation validates detection of repeated failed Active Directory network logons in an isolated SOC lab. A disposable domain account was targeted from Kali using NetExec over SMB. DC01 recorded Windows Security Event ID `4625`, and Splunk successfully identified repeated incorrect-password failures within a five-minute window.

The final detection focuses on network logon failures where:

- `EventID = 4625`
- `LogonType = 3`
- `Status = 0xC000006D`
- `SubStatus = 0xC000006A`
- Threshold: three or more failures in five minutes by source and target user

> Public documentation note: screenshots and examples use `192.169.70.x` as a documentation placeholder. It is not the actual lab addressing scheme and should not be used as a working configuration.

---

## Scope and Authorization

This activity was performed in a controlled, isolated home lab for detection engineering practice. The test used a disposable Active Directory account, `soc.detect01`, and intentionally generated a limited number of failed authentication attempts.

---

## Lab Components

| Role | Host | Purpose |
|---|---|---|
| Domain Controller | `DC01` | Active Directory, Windows Security event source |
| Attacker VM | `KALI-01` | NetExec SMB authentication testing |
| SIEM | `SPLUNK-01` | Event collection, investigation, and detection |
| Test Account | `soc.detect01` | Disposable account for controlled authentication testing |

---

## Attack Simulation

Kali verified reachability to the domain controller and then used NetExec to attempt SMB authentication with an intentionally incorrect password.

![Kali NetExec failed SMB authentication](screenshots/01-kali-netexec-logon-failure.png)

The failed authentication attempts produced `STATUS_LOGON_FAILURE`, confirming that the activity reached the domain controller and was rejected.

---

## Event Evidence

Splunk captured Windows Security Event ID `4625` from DC01. The relevant fields included the target user, source address, logon type, status, and substatus.

![Splunk Event ID 4625 detail](screenshots/02-splunk-event-4625-detail.png)

![Splunk raw XML Event ID 4625 evidence](screenshots/03-splunk-4625-raw-event.png)

### Key Windows Event Fields

| Field | Observed Value | Meaning |
|---|---:|---|
| Event ID | `4625` | Failed logon |
| TargetUserName | `soc.detect01` | Targeted test account |
| LogonType | `3` | Network logon |
| LogonProcessName | `NtLmSsp` | NTLM logon process |
| AuthenticationPackageName | `NTLM` | Authentication package |
| Status | `0xC000006D` | Logon failure |
| SubStatus | `0xC000006A` | Incorrect password |

The investigation also captured earlier failures where `SubStatus = 0xC0000072`, indicating the test account was disabled before it was corrected. Those events were excluded from the final detection logic.

---

## Field Extraction

Because the Windows events were indexed as XML-formatted events, the SPL used `rex` commands to extract the fields directly from `_raw`.

![Splunk field extraction results](screenshots/04-splunk-field-extraction-results.png)

---

## Detection Development

An initial aggregation identified repeated failures, but it also returned unrelated historical Administrator activity when a broad time range was used.

![Initial aggregation results](screenshots/05-splunk-aggregation-initial.png)

The final query narrowed the detection to incorrect-password network logons and required at least three failures in a five-minute window.

![Refined repeated failed logon detection](screenshots/06-splunk-refined-detection.png)

### Validated SPL

```spl
index=windows host=DC01 source="WinEventLog:Security" earliest=-10m latest=now
| rex field=_raw "<EventID[^>]*>(?<event_id>\\d+)</EventID>"
| search event_id="4625"
| rex field=_raw "<Data Name='TargetUserName'>(?<target_user>[^<]+)</Data>"
| rex field=_raw "<Data Name='IpAddress'>(?<source_ip>[^<]+)</Data>"
| rex field=_raw "<Data Name='LogonType'>(?<logon_type>[^<]+)</Data>"
| rex field=_raw "<Data Name='Status'>(?<status>[^<]+)</Data>"
| rex field=_raw "<Data Name='SubStatus'>(?<substatus>[^<]+)</Data>"
| where logon_type="3"
    AND lower(status)="0xc000006d"
    AND lower(substatus)="0xc000006a"
| bin _time span=5m
| stats count AS failures by _time, host, target_user, source_ip
| where failures>=3
| sort - failures
```

---

## Sigma Rule

The Sigma rule in `detection/win_failed_ad_network_logon.yml` identifies the underlying Windows Security event pattern. The Splunk aggregation implements the repeated-failure threshold.

```yaml
title: Failed AD Network Logon - Incorrect Password
id: 0f8e896d-f897-4506-8b8d-c97910894b17
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
    LogonType: 3
    Status: '0xC000006D'
    SubStatus: '0xC000006A'
  condition: selection
level: low
tags:
  - attack.t1110
```

---

## False Positives

Expected benign causes include:

- Users mistyping passwords
- Stale saved credentials
- Expired service credentials
- Misconfigured scheduled tasks
- Devices repeatedly attempting access with outdated credentials

---

## Improvements

Recommended next improvements:

1. Add allowlisting for known administrative testing sources.
2. Add thresholds by unique target accounts to catch password spraying.
3. Correlate with Event ID `4771` and `4776` where applicable.
4. Convert this Splunk detection to a Sentinel KQL equivalent after Sentinel onboarding.
5. Add alert throttling by `source_ip` and `target_user`.

---

## Outcome

This investigation confirmed the end-to-end detection pipeline:

1. Kali generated controlled SMB authentication failures.
2. DC01 recorded Windows Security Event ID `4625`.
3. Splunk ingested the events from the `windows` index.
4. SPL extracted the required fields from XML.
5. A refined query detected three incorrect-password network logon failures in a five-minute window.
