# Detection Library — SPL / KQL / Sigma

Browse reusable detections by query language. **Validation status matters:** a syntactically valid rule or historical hunt is not necessarily validated against the current lab.

| Language | Query / rule | Status |
|---|---|---|
| [Splunk SPL](./spl/DE-003-encoded-powershell-network-correlation.spl) | DE-003: encoded PowerShell plus TCP 4444 within 120 seconds, joined by ProcessGuid | **Candidate; test against captured events** |\n| [Sigma](./sigma/DE-003-encoded-powershell.yml) | DE-003: encoded-command PowerShell process creation | **Draft; CLI validation pending** |\n| [Splunk SPL](./spl/DE-002-ad-password-spraying.spl) | DE-002: five distinct accounts from one source in ten minutes | **Validated against five captured DC01 failures** |
| [Sigma](./sigma/DE-002-ad-password-spraying.yml) | DE-002: individual incorrect-password network logon | **Sigma CLI check passed**; 5-account correlation only in SPL |
| [Splunk SPL](./spl/DE-001-repeated-failed-ad-logons.spl) | DE-001: incorrect-password network logons, three in five minutes | **Validated against captured DC01 events** |
| [Sigma](./sigma/DE-001-repeated-failed-ad-logons.yml) | DE-001: individual 4625 incorrect-password network logon | **Sigma CLI check passed**; threshold aggregation is only in SPL |
| [Splunk SPL](./spl/failed-logons.spl) | Generic failed-logon investigation | Historical example; field normalization needs local verification |
| [Microsoft Sentinel KQL](./kql/failed-logons.kql) | Generic failed-logon investigation | Draft; current workspace schema and ingestion not verified |

**Note:** DE-001, DE-002 and DE-003 Sigma rules describe *event selection* only. Their validated SPL searches apply the separate 3-in-5-minutes and 5-users-in-10-minutes correlations.

[DE-001 report](../case-studies/DE-001-Repeated-Failed-AD-Logons/) · [DE-002 report](../case-studies/DE-002-AD-Password-Spray-Detection/) · [DE-003 report](../case-studies/DE-003-BadUSB-PowerShell-Investigation/).
