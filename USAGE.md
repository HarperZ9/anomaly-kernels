# Usage

`anomaly-kernels` is a Windows x64, C++23 **static library**. You link
against it and include the headers under `include/anomaly/`. There is no
CLI and no console script -- the public surface is three C++ classes in the
`anomaly` namespace:

| Component         | Header                            | Role                                                        |
|-------------------|-----------------------------------|-------------------------------------------------------------|
| `BaselineBuilder` | `anomaly/baseline_builder.h`      | Accumulate metric samples; compute mean / stddev / min / max |
| `AnomalyScorer`   | `anomaly/anomaly_scorer.h`        | Score an observation vs. a baseline (z-score / IQR / percentile) |
| `AlertCorrelator` | `anomaly/alert_correlator.h`      | Fuse alerts by temporal proximity into correlated bundles    |

> Platform note: `CMakeLists.txt` hard-fails on non-Windows
> (`FATAL_ERROR "anomaly-kernels targets Windows x64 only."`). The MSVC
> generator is multi-config, so pass `--config Debug` (or `Release`) to
> build and `-C Debug` to `ctest`.

## Build the library

```bash
cmake -S . -B build
cmake --build build --config Debug
```

This produces `build/Debug/anomaly-kernels.lib`. Run the unit tests with:

```bash
ctest --test-dir build -C Debug --output-on-failure
```

## Linking into your own target

With CMake (after `add_subdirectory(anomaly-kernels)` or installing it):

```cmake
target_link_libraries(my_app PRIVATE anomaly-kernels)
# headers come in via the library's PUBLIC include directory:
#   #include <anomaly/baseline_builder.h>
```

The library requires `cxx_std_23` (MSVC: `/std:c++latest`), which it
propagates as a `PUBLIC` compile feature.

---

## Example 1 -- Build a baseline

`BaselineBuilder::build` returns `std::expected<Baseline, std::string>`;
it returns `std::unexpected(...)` when no samples exist for the metric.
`compute_stddev` is the **population** standard deviation and returns `0.0`
for fewer than two samples.

```cpp
#include <anomaly/baseline_builder.h>
#include <cstdio>

using namespace anomaly;

BaselineBuilder builder;
for (double v : {48.0, 50.0, 52.0, 49.0, 51.0, 50.0}) {
    builder.add_sample(MetricType::CpuUsage, v);
}

auto result = builder.build(MetricType::CpuUsage);
if (result) {
    const Baseline& b = *result;
    std::printf("mean=%.4f stddev=%.4f min=%.1f max=%.1f n=%u\n",
                b.mean, b.stddev, b.min, b.max, b.sample_count);
}
```

Output (verified against the built `Debug` library):

```
mean=50.0000 stddev=1.2910 min=48.0 max=52.0 n=6
```

## Example 2 -- Score an observation

`AnomalyScorer::score` uses the z-score path. `is_anomalous` is set when
`|z| >= threshold * sensitivity` (defaults: `threshold = 3.0`,
`sensitivity = 1.0`). `z_score` returns `0.0` when `stddev <= 0`.

```cpp
#include <anomaly/anomaly_scorer.h>

using namespace anomaly;

Baseline b;          // e.g. from Example 1
b.mean   = 50.0;
b.stddev = 1.2910;

ScoringConfig cfg;   // ZScore, threshold 3.0, sensitivity 1.0
AnomalyScorer scorer;
AnomalyScore s = scorer.score(95.0, b, cfg);
// s.z_score      ~= 34.8569
// s.severity     == 1.0   (|z| >= 3 maps into the high band, clamped to 1.0)
// s.is_anomalous == true
```

The static helpers can also be used directly without a `Baseline`:

```cpp
double z   = AnomalyScorer::z_score(10.0, 5.0, 2.0);          // 2.5
double iqr = AnomalyScorer::iqr_score(40.0, 10.0, 20.0);      // 0.5
double p25 = AnomalyScorer::percentile({10,20,30,40}, 0.25);  // 17.5 (interp.)
```

## Example 3 -- Correlate alerts

`add_alert` assigns and returns an incrementing `id` (starting at 1).
`correlate` groups pending alerts whose timestamps fall within
`time_window_ms`, keeps groups with at least `min_alerts` members whose
combined severity reaches `severity_threshold`, and tags each bundle
`correlation_type = "temporal"`. Combined severity is
`max(severities) + 0.1 * (count - 1)`, clamped to `1.0`.

```cpp
#include <anomaly/alert_correlator.h>

using namespace anomaly;

AlertCorrelator c;

Alert cpu;  cpu.source_module = "baseline-monitor";
            cpu.description   = "CpuUsage z-score 34.9";
            cpu.severity      = 1.0f;  cpu.timestamp = 1000;
(void)c.add_alert(cpu);

Alert net;  net.source_module = "net-monitor";
            net.description   = "NetworkConnectionRate spike";
            net.severity      = 0.7f;  net.timestamp = 1200;
(void)c.add_alert(net);

CorrelationConfig cc;
cc.time_window_ms     = 5000;
cc.min_alerts         = 2;
cc.severity_threshold = 0.5f;

auto bundles = c.correlate(cc);   // bundles.size() == 1
// bundles[0].correlation_type  == "temporal"
// bundles[0].combined_severity == 1.0
// bundles[0].time_span_ms      == 200
// bundles[0].narrative ==
//   "Correlated events: [baseline-monitor] CpuUsage z-score 34.9; "
//   "[net-monitor] NetworkConnectionRate spike"
```

## Example 4 -- Static helpers, no objects

Every component exposes pure static functions usable in isolation:

```cpp
BaselineBuilder::compute_mean({1.0, 2.0, 3.0});                 // 2.0
BaselineBuilder::metric_name(MetricType::DnsQueryRate);         // "DnsQueryRate"
AnomalyScorer::method_name(ScoringMethod::Iqr);                 // "Iqr"
AnomalyScorer::severity_from_zscore(4.0);                       // >= 0.66 (high band)
AlertCorrelator::combine_severity(alerts);                      // max + 0.1*(n-1)
```

---

## Running the demo

`examples/demo.cpp` exercises all three components end to end. After
building the library (above), compile and link it against the produced
`.lib` from a Developer Command Prompt (CRT flag must match the library --
`/MDd` for the `Debug` build):

```bat
cl /nologo /std:c++latest /EHsc /MDd /I include ^
   examples\demo.cpp /Fe:build\demo.exe ^
   /link build\Debug\anomaly-kernels.lib
build\demo.exe
```

Expected output (this is the actual program output):

```
=== Baseline (CpuUsage) ===
  samples = 6
  mean    = 50.0000
  stddev  = 1.2910
  min/max = 48.0 / 52.0

=== Anomaly score (method=ZScore) ===
  observed     = 95.0
  z_score      = 34.8569
  severity     = 1.0000
  is_anomalous = true

=== Correlation (pending=2) ===
  bundles = 1
  - type=temporal alerts=2 combined_severity=1.0000 span_ms=200
    narrative: Correlated events: [baseline-monitor] CpuUsage z-score 34.9; [net-monitor] NetworkConnectionRate spike
```
