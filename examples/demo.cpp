// =============================================================================
// Best-effort demo -- not runtime-verified by author.
//
// End-to-end walkthrough of the three anomaly-kernels public components:
//
//   1. BaselineBuilder  -- accumulate metric samples, build a statistical
//                         baseline (mean / stddev / min / max).
//   2. AnomalyScorer    -- score a live observation against that baseline
//                         (z-score, severity, anomalous/normal verdict).
//   3. AlertCorrelator  -- fuse multiple alerts by temporal proximity into
//                         a single correlated bundle with a narrative.
//
// Only public API declared in include/anomaly/*.h is used. Build via the
// instructions in USAGE.md (add this file as an executable target, or wire
// it into CMake; see the "Running the demo" section of USAGE.md).
//
// Namespace: anomaly
// =============================================================================

#include <anomaly/baseline_builder.h>
#include <anomaly/anomaly_scorer.h>
#include <anomaly/alert_correlator.h>

#include <cstdio>
#include <vector>

int main() {
    using namespace anomaly;

    // -------------------------------------------------------------------------
    // 1. Build a baseline for CPU usage from a handful of normal samples.
    // -------------------------------------------------------------------------
    BaselineBuilder builder;
    for (double v : {48.0, 50.0, 52.0, 49.0, 51.0, 50.0}) {
        builder.add_sample(MetricType::CpuUsage, v);
    }

    auto baseline_result = builder.build(MetricType::CpuUsage);
    if (!baseline_result.has_value()) {
        std::printf("baseline error: %s\n", baseline_result.error().c_str());
        return 1;
    }
    const Baseline& baseline = *baseline_result;

    std::printf("=== Baseline (%s) ===\n",
                BaselineBuilder::metric_name(baseline.metric).data());
    std::printf("  samples = %u\n", baseline.sample_count);
    std::printf("  mean    = %.4f\n", baseline.mean);
    std::printf("  stddev  = %.4f\n", baseline.stddev);
    std::printf("  min/max = %.1f / %.1f\n\n", baseline.min, baseline.max);

    // -------------------------------------------------------------------------
    // 2. Score a clearly anomalous live observation (95% CPU) against it.
    // -------------------------------------------------------------------------
    ScoringConfig config;          // defaults: ZScore, threshold 3.0, sens 1.0
    AnomalyScorer scorer;
    AnomalyScore score = scorer.score(95.0, baseline, config);

    std::printf("=== Anomaly score (method=%s) ===\n",
                AnomalyScorer::method_name(score.method).data());
    std::printf("  observed     = %.1f\n", score.value);
    std::printf("  z_score      = %.4f\n", score.z_score);
    std::printf("  severity     = %.4f\n", static_cast<double>(score.severity));
    std::printf("  is_anomalous = %s\n\n", score.is_anomalous ? "true" : "false");

    // -------------------------------------------------------------------------
    // 3. Correlate two alerts that land inside the same time window.
    // -------------------------------------------------------------------------
    AlertCorrelator correlator;

    Alert spike;
    spike.source_module = "baseline-monitor";
    spike.description   = "CpuUsage z-score 34.9";
    spike.severity      = score.severity;
    spike.timestamp     = 1000;
    static_cast<void>(correlator.add_alert(spike));

    Alert net;
    net.source_module = "net-monitor";
    net.description   = "NetworkConnectionRate spike";
    net.severity      = 0.7f;
    net.timestamp     = 1200;
    static_cast<void>(correlator.add_alert(net));

    CorrelationConfig cc;
    cc.time_window_ms     = 5000;
    cc.min_alerts         = 2;
    cc.severity_threshold = 0.5f;

    std::vector<CorrelatedAlert> bundles = correlator.correlate(cc);

    std::printf("=== Correlation (pending=%u) ===\n", correlator.pending_count());
    std::printf("  bundles = %zu\n", bundles.size());
    for (const CorrelatedAlert& b : bundles) {
        std::printf("  - type=%s alerts=%zu combined_severity=%.4f span_ms=%llu\n",
                    b.correlation_type.c_str(),
                    b.alerts.size(),
                    static_cast<double>(b.combined_severity),
                    static_cast<unsigned long long>(b.time_span_ms));
        std::printf("    narrative: %s\n", b.narrative.c_str());
    }

    return 0;
}
