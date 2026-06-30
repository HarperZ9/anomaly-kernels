# AGENTS.md -- Anomaly Kernels

## Project Boundary

Anomaly Kernels is a standalone, public C++23 telemetry-analytics library. It
contains statistical anomaly-detection kernels only: baseline building, anomaly
scoring, and alert correlation. It does not include exploit code, credentials,
private infrastructure data, or response automation.

## Public Delivery Rules

- Keep `README.md`, `USAGE.md`, `CHANGELOG.md`, `PUBLIC-CLAIM.md`,
  `PUBLIC-DISCLAIMER.md`, `CONTRIBUTING.md`, `AUTHORS.md`, `LICENSE`, CI,
  headers, examples, and tests aligned.
- Public claims must be backed by CMake/CTest output, examples, or claim files.
- Do not commit generated `build/` output, credentials, `.env` files, private
  telemetry, or local investigation artifacts.

## Developer Verification

```powershell
cmake -S . -B build -DANOMALY_KERNELS_TESTS=ON
cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure
```
