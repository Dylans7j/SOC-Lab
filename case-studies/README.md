# Detection Engineering Case Studies

Analyst-style reports with the question, test scope, telemetry, event evidence, detection, false-positive assessment and limitations.

| Case | Focus | Status |
|---|---|---|
| [DE-001 — Detecting Repeated Failed Active Directory Logons](./DE-001-Repeated-Failed-AD-Logons/) | Windows 4625 · SMB/NTLM · repeated incorrect passwords | **Validated in Splunk** |
| [DE-002 — Detecting Active Directory Password Spraying](./DE-002-AD-Password-Spray-Detection/) | One source → five disposable users; 4625, logon type 3 | **Splunk correlation validated**; screenshots pending |

## Earlier work

[INC-001 — SMB Authentication Visibility](./legacy/INC-001-smb-authentication-failures.md) is preserved as historical documentation. Its cross-SIEM correlation has **not** been validated on the current WIN11 deployment.

## Evidence conventions

Use screenshots only after inspecting them for exposed credentials, host-specific details and internal network addresses. Every report distinguishes a controlled simulation from a real compromise. See the [evidence standard](../docs/EVIDENCE-STANDARD.md).
