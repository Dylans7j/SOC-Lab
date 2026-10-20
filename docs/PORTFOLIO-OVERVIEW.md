# Active Directory SOC Lab — Portfolio Overview

## Objective

Demonstrate an evidence-driven security workflow: controlled attack simulation, Windows event collection, analyst investigation, detection engineering, and documented limitations.

## Demonstrated capabilities

- Investigated Active Directory authentication failures using Windows Security Event ID 4625.
- Validated repeated-failure and password-spray correlation searches against controlled lab events in Splunk.
- Correlated endpoint process and network telemetry using Sysmon ProcessGuid for a PowerShell investigation.
- Examined LLMNR/NBT-NS poisoning behavior and related SMB network evidence without claiming an automated alert exists.

## Technologies

Active Directory, Windows Security auditing, Sysmon, PowerShell logging, Splunk SPL, Sigma, and draft Microsoft Sentinel KQL.

## Read the evidence

- [DE-001 — Repeated Failed Logons](../case-studies/DE-001-Repeated-Failed-AD-Logons/)
- [DE-002 — Password Spraying](../case-studies/DE-002-AD-Password-Spray-Detection/)
- [DE-003 — PowerShell Investigation](../case-studies/DE-003-BadUSB-PowerShell-Investigation/)
- [DE-004 — LLMNR/NBT-NS Investigation](../case-studies/DE-004-LLMNR-NBTNS-Poisoning/)
- [Detection Library](../detections/README.md)
- [Detection Validation Protocol](./DETECTION-VALIDATION-PROTOCOL.md)

## Scope and limitations

This is an educational, isolated lab, not a production deployment. DE-003 expanded alert validation and DE-004 automated network detection remain pending. Current Microsoft Sentinel onboarding has not been verified. Do not interpret historical event counts as ongoing ingestion.

## Professional competencies illustrated

Security monitoring, hypothesis-driven threat hunting, detection logic development, telemetry correlation, false-positive analysis, and technical reporting.
