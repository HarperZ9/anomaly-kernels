// =============================================================================
// Anomaly: Baseline Builder -- Implementation
//
// Accumulates per-metric-type samples and computes statistical baselines
// (mean, stddev, min, max) on demand.
// =============================================================================

#include <anomaly/baseline_builder.h>

#include <algorithm>
#include <cmath>
#include <limits>
#include <numeric>

namespace anomaly {

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

void BaselineBuilder::add_sample(MetricType metric, double value) {
    BaselineSample s;
    s.metric = metric;
    s.value  = value;
    samples_[static_cast<uint8_t>(metric)].push_back(s);
}

auto BaselineBuilder::build(MetricType metric) const
    -> std::expected<Baseline, std::string>
{
    auto key = static_cast<uint8_t>(metric);
    auto it  = samples_.find(key);
    if (it == samples_.end() || it->second.empty()) {
        return std::unexpected("no samples for metric: "
            + std::string(metric_name(metric)));
    }

    const auto& raw = it->second;
    std::vector<double> values;
    values.reserve(raw.size());
    for (const auto& s : raw) {
        values.push_back(s.value);
    }

    double mean   = compute_mean(values);
    double stddev = compute_stddev(values, mean);

    auto [mn, mx] = std::minmax_element(values.begin(), values.end());

    Baseline b;
    b.metric       = metric;
    b.mean         = mean;
    b.stddev       = stddev;
    b.min          = *mn;
    b.max          = *mx;
    b.sample_count = static_cast<uint32_t>(values.size());
    return b;
}

auto BaselineBuilder::get_baseline(MetricType metric) const
    -> std::expected<Baseline, std::string>
{
    return build(metric);
}

void BaselineBuilder::reset() {
    samples_.clear();
}

auto BaselineBuilder::sample_count(MetricType metric) const -> uint32_t {
    auto key = static_cast<uint8_t>(metric);
    auto it  = samples_.find(key);
    if (it == samples_.end()) return 0;
    return static_cast<uint32_t>(it->second.size());
}

auto BaselineBuilder::metric_name(MetricType m) -> std::string_view {
    switch (m) {
        case MetricType::ProcessCreationRate:   return "ProcessCreationRate";
        case MetricType::NetworkConnectionRate: return "NetworkConnectionRate";
        case MetricType::FileAccessRate:        return "FileAccessRate";
        case MetricType::RegistryAccessRate:    return "RegistryAccessRate";
        case MetricType::DnsQueryRate:          return "DnsQueryRate";
        case MetricType::CpuUsage:              return "CpuUsage";
        case MetricType::MemoryUsage:           return "MemoryUsage";
    }
    return "Unknown";
}

// ---------------------------------------------------------------------------
// Statistical helpers
// ---------------------------------------------------------------------------

auto BaselineBuilder::compute_mean(const std::vector<double>& samples)
    -> double
{
    if (samples.empty()) return 0.0;
    double sum = std::accumulate(samples.begin(), samples.end(), 0.0);
    return sum / static_cast<double>(samples.size());
}

auto BaselineBuilder::compute_stddev(const std::vector<double>& samples,
                                     double mean) -> double
{
    if (samples.size() < 2) return 0.0;
    double sq_sum = 0.0;
    for (double v : samples) {
        double diff = v - mean;
        sq_sum += diff * diff;
    }
    return std::sqrt(sq_sum / static_cast<double>(samples.size()));
}

} // namespace anomaly
