# Warden Anomaly Scoring

`warden-anomaly` publishes a compact statistical anomaly detection engine from WARDEN:

- baseline builder
- scoring engines (Z-Score, IQR, percentile, moving-average behavior)
- rule-based behavior classifier
- alert correlator

It is designed for telemetry quality and detection analytics. It does not include
execution primitives, exploit chains, or credential workflows.

## Public leaves and gates

- Test gate: module-focused anomaly tests are included in `tests/`.
- License gate: `LICENSE` present (MIT).
- Secret gate: no credentials, `.env`, keys, or auth files in this export.
- Claim gate: `PUBLIC-CLAIM.md` and `PUBLIC-DISCLAIMER.md` present.

## Build

```bash
cmake -S . -B build
cmake --build build
```
