// =============================================================================
// Anomaly: Anomaly Scorer — Implementation
//
// Statistical deviation scoring.  Primary method is Z-score with fallback
// to IQR and percentile-based approaches.  Severity mapping:
//   |z| 0-2  => low   (0.0-0.33)
//   |z| 2-3  => medium (0.33-0.66)
//   |z| 3+   => high   (0.66-1.0)
// =============================================================================

#include <anomaly/anomaly_scorer.h>

#include <algorithm>
#include <cmath>

namespace anomaly {

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

auto AnomalyScorer::score(double value,
                          const Baseline& baseline,
                          const ScoringConfig& config) const -> AnomalyScore
{
    AnomalyScore result;
    result.value           = value;
    result.baseline_mean   = baseline.mean;
    result.baseline_stddev = baseline.stddev;
    result.method          = config.method;

    double z = z_score(value, baseline.mean, baseline.stddev);
    result.z_score = z;

    double abs_z = std::abs(z);
    result.severity    = severity_from_zscore(z);
    result.is_anomalous = abs_z >= config.threshold * config.sensitivity;

    return result;
}

// ---------------------------------------------------------------------------
// Static scoring functions
// ---------------------------------------------------------------------------

auto AnomalyScorer::z_score(double value,
                            double mean,
                            double stddev) -> double
{
    if (stddev <= 0.0) return 0.0;
    return (value - mean) / stddev;
}

auto AnomalyScorer::iqr_score(double value,
                               double q1,
                               double q3) -> double
{
    double iqr = q3 - q1;
    if (iqr <= 0.0) return 0.0;

    double lower = q1 - 1.5 * iqr;
    double upper = q3 + 1.5 * iqr;

    if (value < lower) return (lower - value) / iqr;
    if (value > upper) return (value - upper) / iqr;
    return 0.0;
}

auto AnomalyScorer::percentile(const std::vector<double>& sorted_values,
                                double pct) -> double
{
    if (sorted_values.empty()) return 0.0;
    if (sorted_values.size() == 1) return sorted_values[0];

    double clamped = std::clamp(pct, 0.0, 1.0);
    double idx = clamped * static_cast<double>(sorted_values.size() - 1);

    auto lo = static_cast<size_t>(std::floor(idx));
    auto hi = static_cast<size_t>(std::ceil(idx));

    if (lo == hi) return sorted_values[lo];

    double frac = idx - static_cast<double>(lo);
    return sorted_values[lo] * (1.0 - frac) + sorted_values[hi] * frac;
}

auto AnomalyScorer::method_name(ScoringMethod m) -> std::string_view {
    switch (m) {
        case ScoringMethod::ZScore:        return "ZScore";
        case ScoringMethod::Iqr:           return "Iqr";
        case ScoringMethod::MovingAverage: return "MovingAverage";
        case ScoringMethod::Percentile:    return "Percentile";
    }
    return "Unknown";
}

auto AnomalyScorer::severity_from_zscore(double z) -> float {
    double abs_z = std::abs(z);
    if (abs_z >= 3.0) return std::clamp(
        0.66f + static_cast<float>((abs_z - 3.0) / 3.0) * 0.34f,
        0.66f, 1.0f);
    if (abs_z >= 2.0) return 0.33f + static_cast<float>(
        (abs_z - 2.0) / 1.0) * 0.33f;
    return static_cast<float>(abs_z / 2.0) * 0.33f;
}

auto AnomalyScorer::is_anomalous(const AnomalyScore& s,
                                  double threshold) -> bool
{
    return std::abs(s.z_score) >= threshold;
}

} // namespace anomaly
