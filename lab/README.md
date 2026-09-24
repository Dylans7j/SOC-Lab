# Lab Architecture & Onboarding

| Guide | What it covers |
|---|---|
| [Dual-SIEM architecture and state](./dual-siem/README.md) | Verified Splunk work versus historical Sentinel work |
| [Setup notes](./dual-siem/lab-setup.md) | VMware and log-forwarding setup; validate examples against the current environment |
| [Historical detection-query notes](./dual-siem/detection-queries.md) | Explanations and examples; see the [detection library](../detections/README.md) for tracked rules |
| [WIN11 → Splunk onboarding](../docs/WIN11-SPLUNK-ONBOARDING.md) | Windows telemetry, Sysmon access troubleshooting and forwarding evidence |

**Current verification:** DC01 and WIN11 send Windows telemetry to Splunk. Current WIN11-to-Sentinel ingestion is not verified.
