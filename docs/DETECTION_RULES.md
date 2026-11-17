# Detection rules

| Rule | Logic | Default severity |
|---|---|---|
| AUTH-001 | Failed authentication count from one source IP reaches threshold within selected time window | Medium; High at 2x threshold |
| NET-001 | Distinct destination ports from one source reaches threshold | Medium; High at 2x threshold |
| VOL-001 | At least 100 events from one source in the uploaded dataset | Medium |

These transparent starter heuristics will produce false positives. Tune against a known baseline and investigate with endpoint, identity, firewall and network telemetry.
