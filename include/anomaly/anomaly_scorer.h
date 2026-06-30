// =============================================================================
// Anomaly: Anomaly Scorer
//
// Statistical deviation scoring engine.  Given a live observation and a
// pre-computed baseline, produces a z-score, severity rating, and
// anomalous/normal classification.  Supports multiple scoring methods:
// Z-Score, IQR, Moving Average, and Percentile.
//
// Namespace: anomaly
// =============================================================================

#pragma once
#ifndef ANOMALY_KERNELS_ANOMALY_SCORER_H
#define ANOMALY_KERNELS_ANOMALY_SCORER_H

#include <cstdint>
#include <string_view>
#include <vector>

#include "baseline_builder.h"

namespace anomaly {

// ---------------------------------------------------------------------------
// ScoringMethod -- algorithm used to evaluate deviation
// ---------------------------------------------------------------------------

enum class ScoringMethod : uint8_t {
    ZScore,
    Iqr,
    MovingAverage,
    Percentile,
};

// ---------------------------------------------------------------------------
// AnomalyScore -- result of scoring a single observation
// ---------------------------------------------------------------------------

struct AnomalyScore {
    double        value           = 0.0;
    double        baseline_mean   = 0.0;
    double        baseline_stddev = 0.0;
    double        z_score         = 0.0;
    bool          is_anomalous    = false;
    float         severity        = 0.0f;
    ScoringMethod method          = ScoringMethod::ZScore;
};

// ---------------------------------------------------------------------------
// ScoringConfig -- tuning knobs for the scorer
// ---------------------------------------------------------------------------

struct ScoringConfig {
    ScoringMethod method      = ScoringMethod::ZScore;
    double        threshold   = 3.0;
    uint32_t      window_size = 100;
    float         sensitivity = 1.0f;
};

// ---------------------------------------------------------------------------
// AnomalyScorer -- stateless scoring engine
// ---------------------------------------------------------------------------

class AnomalyScorer {
public:
    /// Score a single observation against a baseline.
    [[nodiscard]] auto score(double value,
                             const Baseline& baseline,
                             const ScoringConfig& config) const
        -> AnomalyScore;

    /// Z-score: (value - mean) / stddev.
    [[nodiscard]] static auto z_score(double value,
                                      double mean,
                                      double stddev) -> double;

    /// IQR-based outlier score: distance outside [Q1-1.5*IQR, Q3+1.5*IQR].
    [[nodiscard]] static auto iqr_score(double value,
                                        double q1,
                                        double q3) -> double;

    /// Percentile via linear interpolation over sorted values.
    [[nodiscard]] static auto percentile(
        const std::vector<double>& sorted_values,
        double pct) -> double;

    /// Human-readable name for a scoring method.
    [[nodiscard]] static auto method_name(ScoringMethod m)
        -> std::string_view;

    /// Map absolute z-score to a 0.0-1.0 severity float.
    [[nodiscard]] static auto severity_from_zscore(double z) -> float;

    /// Check whether an anomaly score exceeds a threshold.
    [[nodiscard]] static auto is_anomalous(const AnomalyScore& s,
                                           double threshold) -> bool;
};

} // namespace anomaly

#endif // ANOMALY_KERNELS_ANOMALY_SCORER_H
