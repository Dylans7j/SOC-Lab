# Detection Validation Protocol

Use this protocol for every new or changed SPL, KQL, Sigma, or network analytic.

## Test record

| Field | Required value |
|---|---|
| Detection ID | DE-00X |
| Rule path and Git commit | Exact file and SHA |
| Analyst and date | Name or handle, UTC timestamp |
| Environment | Lab host roles, OS/build, SIEM version |
| Data source | Event channel, provider, event ID, index/table |
| Simulation | Authorized scenario, disposable accounts, bounded test window |
| Positive control | Event(s) that should match |
| Negative control | Benign event(s) that should not match |
| Query result | Count, event identifiers, search time window |
| False positives | Known legitimate behaviors and tuning |
| Outcome | Observed / syntax checked / validated / failed / not tested |
| Evidence | Sanitized screenshots, logs, PCAP excerpts, hashes where appropriate |

## Procedure

1. Confirm lab isolation and authorization; synchronize host clocks.
2. Capture the pre-test configuration and rule commit SHA.
3. Generate or replay bounded positive test events and collect source telemetry.
4. Execute the exact analytic with a recorded time window.
5. Compare expected and observed matches; investigate missing fields.
6. Run at least one negative control and record unexpected matches.
7. Document tuning, visibility gaps, and retest outcomes.
8. Preserve original evidence; publish only sanitized copies.

## Interpretation

- **Observed:** underlying activity or telemetry was captured; an alert may not exist.
- **Syntax checked:** parser accepted the rule; no behavioral claim.
- **Validated:** exact analytic matched known positive test events and controls were evaluated.
- **Not tested:** proposed logic only.
- **Failed:** expected behavior was not demonstrated; preserve the failure details.

Sigma event selection is not equivalent to threshold-based correlation in SPL. KQL examples must not be labeled validated without testing against the actual Sentinel schema and ingestion.
