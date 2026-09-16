# INC-001 — SMB Authentication Failures

## Status

**Documented.** Windows Security Event ID 4625 visibility was confirmed. Sanitized Sentinel and Splunk result captures are still required before the complete cross-platform investigation is labeled validated.

## Objective

Determine whether controlled SMB authentication attempts from the authorized Kali lab host are visible in Windows telemetry and can be summarized consistently in Microsoft Sentinel and Splunk.

## Authorized scope

- Isolated home-lab network
- Kali testing host
- Windows domain controller
- Microsoft Sentinel workspace
- Splunk Enterprise instance

No production or third-party systems were tested.

## Data sources

- Windows Security Event Log
- Event ID 4625: failed account logon
- Microsoft Sentinel `Event` table
- Splunk Windows Security sourcetype

## Test method

1. Confirm that Windows Security auditing and both collection paths are operating.
2. From Kali, perform a small number of controlled SMB authentication attempts using a lab-only test account or deliberately invalid credentials.
3. Record the test start and end time.
4. Search for Event ID 4625 in Sentinel and Splunk.
5. Correlate source address, targeted account, host, logon type, failure reason, and timestamp.
6. Preserve sanitized result evidence.

## Detection logic

- [KQL hunt](../detections/kql/failed-logons.kql)
- [SPL hunt](../detections/spl/failed-logons.spl)

The current queries summarize attempts by source address and targeted user. Thresholds are intentionally omitted until baseline activity is measured.

## Evidence

| ID | Evidence | Status |
| --- | --- | --- |
| EV-001 | Controlled SMB authentication command and timestamp | Pending sanitized capture |
| EV-002 | Windows Event ID 4625 on the domain controller | Confirmed |
| EV-003 | Sentinel query result with expected fields | Pending attachment |
| EV-004 | Splunk query result with expected fields | Pending attachment |

## Analyst assessment

The confirmed 4625 event demonstrates failed-authentication visibility on the Windows host. It does not, by itself, prove brute force or password spraying. Classification requires the attempt count, time window, account distribution, source context, and comparison with normal administrative activity.

## ATT&CK context

- T1110 — Brute Force
- T1110.003 — Password Spraying

These mappings describe behaviors the investigation can help identify; they are not claims that either technique occurred in this test.

## Triage questions

- Was one account targeted repeatedly or were many accounts targeted?
- Did all attempts originate from the expected lab host?
- Was there a successful logon after the failures?
- What logon type and status/substatus codes were recorded?
- Did endpoint or network telemetry show related enumeration?

## Defensive actions

- Confirm an appropriate account-lockout policy.
- Investigate distributed failures across many accounts or hosts.
- Correlate failures with successful Event ID 4624 logons.
- Exclude documented scanners and administrative systems only after validation.
- Tune thresholds using the environment's authentication baseline.

## Next validation step

Attach sanitized Sentinel and Splunk results showing the same controlled test window and expected fields, then update the status from **Documented** to **Validated**.
