# Scenario 001 — Failed SMB Authentication (Password Guess)

`MITRE: T1110` · `Severity: Low (single attempt) / Medium (at volume)` · `Status: ✅ Validated`

## 1) Objective

Validate the attack → telemetry → Sentinel pipeline end to end using the simplest possible signal: a single failed authentication attempt against the domain controller. This is the "hello world" of the lab — confirming that an action taken from the attacker box is actually visible, in near-real-time, on the defensive side before building anything more complex on top of it.

## 2) Environment

- **Attacker host:** `KALI01` (`192.168.70.10`)
- **Target host:** `DC-01` (`192.168.70.20`) — Windows Server 2022, Active Directory Domain Controller
- **Domain:** `dc-01.lab`
- **Network:** `VMnet7` (host-only, `192.168.70.0/24`, no default gateway)

## 3) Reconnaissance

Before the auth attempt, NetExec's default SMB probe was used to fingerprint the target with no credentials required — this happens as part of any SMB connection attempt regardless of auth outcome:

```bash
nxc smb 192.168.70.20
```

Confirmed:
- Windows Server 2022
- SMB open on TCP/445
- SMB signing **enabled**
- SMBv1 **disabled**
- Domain identity resolvable (`dc-01.lab`)

## 4) Commands & Methodology

```bash
nxc smb 192.168.70.20 \
  -u Administrator \
  -p 'WrongPassword123!'
```

A single authentication attempt against a known-valid username (`Administrator`) with a deliberately incorrect password — the minimum viable action to generate a Windows logon-failure event.

## 5) Evidence

```
SMB   192.168.70.20   445   DC-01   [*] Windows Server 2022 ... (name:DC-01) (domain:dc-01.lab) (signing:True) (SMBv1:False)
SMB   192.168.70.20   445   DC-01   [-] dc-01.lab\Administrator:WrongPassword123! STATUS_LOGON_FAILURE
```

NetExec reports `STATUS_LOGON_FAILURE` — the attempt reached the DC, was evaluated against AD, and was correctly rejected.

## 6) Telemetry

| Source | Event ID / Table | What it shows |
|---|---|---|
| Windows Security Log (DC-01) | `4625` — An account failed to log on | Failed logon, includes source IP, account name, logon type, failure reason |
| Microsoft Sentinel | `SecurityEvent` table (via DCR-SOC-LAB-WINDOWS) | Same event, ingested via Azure Monitor Agent |

## 7) Detection Logic

```kql
SecurityEvent
| where EventID == 4625
| where Account has "Administrator"
| project TimeGenerated, Computer, Account, IpAddress, LogonType, FailureReason
| order by TimeGenerated desc
```

*(Baseline single-event query — the natural next iteration is a threshold version that fires on N failures from the same source within a rolling window, to catch spraying/brute-force rather than one-off failures.)*

## 8) Investigation

For a single 4625 event, an analyst would check:
- **Source IP** — internal (`192.168.70.x`) and expected, or external/unexpected?
- **Target account** — a real privileged account (`Administrator`) is higher priority than a service account typo
- **Frequency** — one failure is noise; repeated failures against the same account or a spray across many accounts from one source is the actual signal
- **Logon type** — `3` (network) here, consistent with SMB; other types (e.g. `10`, RDP) would shift the investigation path

In this case: single attempt, internal known-good source (the lab's own attacker box), attributable — closed as expected lab activity, but the *pipeline* itself is now validated.

## 9) MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Credential Access | Brute Force: Password Guessing | T1110.001 |

## 10) Impact

A single failed login is low-impact by itself. At volume (password spraying across many accounts, or brute-forcing one account), this technique is a common precursor to initial access or lateral movement — and is exactly the kind of activity that goes unnoticed without centralized logging and a threshold-based detection rule.

## 11) Remediation

- Account lockout policy tuned to block brute-force without enabling trivial DoS against real users
- Alerting on failure-count thresholds per account/source rather than relying on manual log review
- MFA on privileged accounts to reduce the value of a guessed password even if one succeeds

## 12) Lessons Learned

- The DCR/Azure Monitor Agent pipeline works as designed — event generated on `DC-01` was visible in Sentinel's `SecurityEvent` table without additional configuration beyond the existing `DCR-SOC-LAB-WINDOWS` rule.
- A single-event KQL query is a fine starting point, but the real value comes from a threshold/aggregation version — next scenario should build that out and test it against a simulated spray (multiple accounts, single source, short window).
- Worth confirming `IpAddress` populates correctly on internal host-only traffic before relying on it for source attribution in future scenarios.
