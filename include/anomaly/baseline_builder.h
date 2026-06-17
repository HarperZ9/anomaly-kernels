// =============================================================================
// Anomaly: Baseline Builder
//
// Behavioral profiling engine that constructs normal-activity baselines
// from streaming metric samples.  Stores per-metric-type samples and
// computes statistical aggregates (mean, stddev, min, max) over a
// configurable time window.
//
// Namespace: anomaly
// =============================================================================

#pragma once
#ifndef ANOMALY_KERNELS_BASELINE_BUILDER_H
#define ANOMALY_KERNELS_BASELINE_BUILDER_H

#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace anomaly {

// ---------------------------------------------------------------------------
// MetricType — categories of observable host behavior
// ---------------------------------------------------------------------------

enum class MetricType : uint8_t {
    ProcessCreationRate,
    NetworkConnectionRate,
    FileAccessRate,
    RegistryAccessRate,
    DnsQueryRate,
    CpuUsage,
    MemoryUsage,
};

// ---------------------------------------------------------------------------
// BaselineSample — single point observation
// ---------------------------------------------------------------------------

struct BaselineSample {
    MetricType metric    = MetricType::ProcessCreationRate;
    double     value     = 0.0;
    uint64_t   timestamp = 0;
};

// ---------------------------------------------------------------------------
// Baseline — computed statistical summary for one metric type
// ---------------------------------------------------------------------------

struct Baseline {
    MetricType metric         = MetricType::ProcessCreationRate;
    double     mean           = 0.0;
    double     stddev         = 0.0;
    double     min            = 0.0;
    double     max            = 0.0;
    uint32_t   sample_count   = 0;
    uint32_t   window_seconds = 3600;
};

// ---------------------------------------------------------------------------
// BaselineBuilder — accumulates samples and computes baselines
// ---------------------------------------------------------------------------

class BaselineBuilder {
public:
    /// Record a new metric observation.
    void add_sample(MetricType metric, double value);

    /// Compute a baseline from accumulated samples for the given metric.
    [[nodiscard]] auto build(MetricType metric) const
        -> std::expected<Baseline, std::string>;

    /// Return a previously built baseline (builds on demand).
    [[nodiscard]] auto get_baseline(MetricType metric) const
        -> std::expected<Baseline, std::string>;

    /// Discard all accumulated samples.
    void reset();

    /// Number of samples stored for a given metric type.
    [[nodiscard]] auto sample_count(MetricType metric) const -> uint32_t;

    /// Human-readable name for a metric type.
    [[nodiscard]] static auto metric_name(MetricType m) -> std::string_view;

    /// Arithmetic mean of a sample vector.
    [[nodiscard]] static auto compute_mean(
        const std::vector<double>& samples) -> double;

    /// Population standard deviation given samples and their mean.
    [[nodiscard]] static auto compute_stddev(
        const std::vector<double>& samples, double mean) -> double;

private:
    std::unordered_map<uint8_t, std::vector<BaselineSample>> samples_;
};

} // namespace anomaly

#endif // ANOMALY_KERNELS_BASELINE_BUILDER_H
