# Public claim (anomaly-kernels)

- `anomaly-kernels` is a standalone, public blue-team telemetry-analytics
  library. It is independently usable and is not coupled to any larger product.
- Scope is limited to statistical primitives: baseline building, statistical
  deviation scoring (z-score / IQR / percentile), and temporal alert
  correlation.
- The exported surface is a Windows x64 C++23 CMake target with
  module-focused unit tests.
- No host-intrusion / SOC threat taxonomy, offensive workflow modules, private
  infrastructure data, or credential material is included in the public build.
