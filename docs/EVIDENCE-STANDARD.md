# Evidence Standard

This repository separates working notes from validated portfolio evidence.

## Status labels

- **Validated:** Reproduced in the lab and supported by sanitized output or screenshots.
- **Documented:** The setup, method, or query is recorded, but the result evidence is incomplete.
- **Staged:** Drafted or planned work that is not presented as completed.

## Minimum evidence

| Artifact | Required evidence |
| --- | --- |
| SIEM query | Query text, data source, time range, relevant returned fields, interpretation |
| Detection rule | Rule, test procedure, expected match, observed result, false-positive notes |
| Investigation | Timeline, source events, affected host/account, conclusion, confidence |
| Attack scenario | Authorized scope, reproducible action, generated telemetry, detection opportunity |
| Architecture claim | Diagram or configuration excerpt showing the component and connection |

## Publication checklist

- Remove credentials, tokens, private keys, session data, and proof strings.
- Exclude active HTB machine spoilers.
- Sanitize tenant IDs, subscription IDs, personal email addresses, and unrelated usernames.
- Keep raw evidence separate from interpretation.
- State limitations and missing telemetry.
- Do not convert service exposure or version detection into a vulnerability claim without validation.
- Do not label a query validated until representative events produce the expected fields.

## Investigation conclusion format

1. **Finding:** What the evidence directly shows.
2. **Scope:** Hosts, accounts, and time range reviewed.
3. **Confidence:** High, medium, or low, with a short reason.
4. **Impact:** What was demonstrated—not what was merely possible.
5. **Next action:** Collection, containment, tuning, or hardening step.
