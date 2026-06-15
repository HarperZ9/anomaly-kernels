# Public claim (anomaly)

- `warden-anomaly` is a public telemetry analytics leaf derived from a private
  WARDEN anomaly module.
- Scope is limited to baseline building, scoring, classification, and alert
  correlation primitives.
- The exported surface is a standalone Windows x64 C++23 CMake target with
  module-focused tests.
- Offensive workflow modules, private infrastructure data, and credential
  material are not exported.
