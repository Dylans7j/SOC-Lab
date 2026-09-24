# DE-001 Timeline — Detecting Repeated Failed Active Directory Logons

> Former internal ID: INC-002 — Active Directory Authentication Investigation

| Time | Activity | Evidence |
|---|---|---|
| 06:07 | Kali verified reachability to DC01 and SMB service discovery. | `screenshots/01-kali-netexec-logon-failure.png` |
| 06:08 | NetExec generated controlled failed SMB/NTLM authentications against `soc.detect01`. | `screenshots/01-kali-netexec-logon-failure.png` |
| 06:08 | DC01 logged Windows Security Event ID 4625 with LogonType 3. | `screenshots/02-splunk-event-4625-detail.png`, `screenshots/03-splunk-4625-raw-event.png` |
| 06:04–06:12 | Splunk field extraction confirmed target user, source, logon type, status, and substatus. | `screenshots/04-splunk-field-extraction-results.png` |
| 06:05 window | Initial aggregation found repeated failures, but also showed unrelated historical Administrator failures when searched broadly. | `screenshots/05-splunk-aggregation-initial.png` |
| 06:05 window | Refined detection isolated three incorrect-password failures for `soc.detect01` from the Kali source. | `screenshots/06-splunk-refined-detection.png` |
