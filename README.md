# anomaly-kernels

`anomaly-kernels` is a standalone, public blue-team telemetry-analytics
library. It publishes a compact set of statistical anomaly-detection kernels:

- baseline builder (per-metric mean / stddev / min / max profiling)
- scoring engine (z-score, IQR, percentile)
- temporal alert correlator (multi-signal fusion by time window)

It is designed for telemetry quality and detection analytics. It does not
include execution primitives, exploit chains, credential workflows, or any
host-intrusion / SOC threat taxonomy.

The C++ namespace for all public types is `anomaly`.

## Gates

- Test gate: module-focused unit tests in `tests/`, wired into CTest.
- License gate: `LICENSE` present (MIT).
- Secret gate: no credentials, `.env`, keys, or auth files in this export.
- Claim gate: `PUBLIC-CLAIM.md` and `PUBLIC-DISCLAIMER.md` present.

## Build

```bash
cmake -S . -B build
cmake --build build
```

## Test

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```
