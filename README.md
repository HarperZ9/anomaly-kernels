# Anomaly Kernels

> Header-only C++23 anomaly-detection kernels: baselines, z-score/IQR, and temporal correlation.

[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![C++23](https://img.shields.io/badge/C%2B%2B-23-blue.svg)
[![CI](https://github.com/HarperZ9/anomaly-kernels/actions/workflows/ci.yml/badge.svg)](https://github.com/HarperZ9/anomaly-kernels/actions/workflows/ci.yml)
![header-only](https://img.shields.io/badge/header--only-C%2B%2B23-success.svg)
[![part of: AI-accountability toolkit](https://img.shields.io/badge/part_of-AI--accountability_toolkit-7a5cff.svg)](https://harperz9.github.io)

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

---
**Zain Dana Harper** — small tools with explicit edges.
[Portfolio](https://harperz9.github.io) · [HarperZ9](https://github.com/HarperZ9)
<sub>Built with Claude Code; reviewed, tested, and owned by me.</sub>
