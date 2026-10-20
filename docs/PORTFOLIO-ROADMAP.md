# SOC Lab — Portfolio Engineering Roadmap

This roadmap separates **verified evidence** from **planned work**. It is not a claim that pending tests have been executed.

## Current baseline

| Case | Observed evidence | Detection status | Next validation |
|---|---|---|---|
| DE-001 | DC01 Windows 4625 failed NTLM network logons | Splunk 3 failures / 5 min validated | Re-run on fresh lab events; record false-positive cases |
| DE-002 | DC01 Windows 4625 across five disposable users | Splunk 5 users / 10 min validated | Repeat with clean baseline and negative controls |
| DE-003 | Encoded PowerShell, Sysmon process/network correlation, PowerShell 4104 | Candidate SPL and draft Sigma | Validate candidate against saved events; retest alert |
| DE-004 | LLMNR/NBT-NS response, SMB connection and Sysmon network evidence | Network analytic design only | Implement and test alert with positive/negative packet traces |

## Phase 1 — Documentation and quality gates

- [x] Add this roadmap and a repeatable detection test protocol.
- [ ] Review screenshots and historical Git revisions for sensitive information before redistribution.
- [ ] Validate each Sigma YAML file using a pinned Sigma CLI version.
- [ ] Add a CI workflow for rule syntax, Markdown links and repository structure.
- [ ] Attach validation results to a dated test report; do not infer pass/fail from syntax checks.

## Phase 2 — Close existing detection gaps

- [ ] DE-003: capture SPL results and confirm ProcessGuid correlation with known positive and negative events.
- [ ] DE-003: test Sigma event selection and document its difference from the multi-event SPL correlation.
- [ ] DE-004: select a network telemetry source, implement the LLMNR-to-SMB analytic, and test with saved PCAPs.
- [ ] DE-004: distinguish attempted poisoning, NTLM negotiation, credential disclosure, and successful relay; never conflate these outcomes.

## Phase 3 — Expand coverage

Potential future cases (not yet implemented): Kerberoasting, privileged group membership changes, suspicious account creation, and anomalous PowerShell activity. Each must have an isolated authorized simulation, evidence, query, negative controls, and documented detection outcome.

## Release criteria

A detection is **validated** only when the exact version of its logic runs against known positive test data, expected matches are inspected, and limitations are recorded. A parser pass is **syntax checked**, not validated. Historical observations do not establish current ingestion.

See [Detection Validation Protocol](./DETECTION-VALIDATION-PROTOCOL.md).
