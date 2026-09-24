# Detection Library — SPL / KQL / Sigma

Browse reusable detections by query language. **Validation status matters:** a syntactically valid rule or historical hunt is not necessarily validated against the current lab.

| Language | Query / rule | Status |
|---|---|---|
| [Splunk SPL](./spl/DE-001-repeated-failed-ad-logons.spl) | DE-001: incorrect-password network logons, three in five minutes | **Validated against captured DC01 events** |
| [Sigma](./sigma/DE-001-repeated-failed-ad-logons.yml) | DE-001: individual 4625 incorrect-password network logon | **Sigma CLI check passed**; threshold aggregation is only in SPL |
| [Splunk SPL](./spl/failed-logons.spl) | Generic failed-logon investigation | Historical example; field normalization needs local verification |
| [Microsoft Sentinel KQL](./kql/failed-logons.kql) | Generic failed-logon investigation | Draft; current workspace schema and ingestion not verified |

**Note:** The DE-001 Sigma rule describes the *event selection*, not a three-failures-in-five-minutes correlation. The tested SPL performs that aggregation.

[Read the DE-001 investigation and screenshots](../case-studies/DE-001-Repeated-Failed-AD-Logons/).
