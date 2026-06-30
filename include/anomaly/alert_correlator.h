// =============================================================================
// Anomaly: Alert Correlator
//
// Multi-signal alert fusion engine.  Accumulates alerts from disparate
// detection modules and groups them by temporal proximity, producing
// correlated alert bundles with combined severity and human-readable
// narratives.
//
// Namespace: anomaly
// =============================================================================

#pragma once
#ifndef ANOMALY_KERNELS_ALERT_CORRELATOR_H
#define ANOMALY_KERNELS_ALERT_CORRELATOR_H

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace anomaly {

// ---------------------------------------------------------------------------
// Alert -- single detection signal
// ---------------------------------------------------------------------------

struct Alert {
    uint32_t    id              = 0;
    std::string source_module;
    std::string description;
    float       severity        = 0.0f;
    uint64_t    timestamp       = 0;
    std::string category;
    std::vector<std::pair<std::string, std::string>> metadata;
};

// ---------------------------------------------------------------------------
// CorrelatedAlert -- fused alert group
// ---------------------------------------------------------------------------

struct CorrelatedAlert {
    std::vector<Alert> alerts;
    float              combined_severity = 0.0f;
    uint64_t           time_span_ms      = 0;
    std::string        narrative;
    std::string        correlation_type;
};

// ---------------------------------------------------------------------------
// CorrelationConfig -- fusion parameters
// ---------------------------------------------------------------------------

struct CorrelationConfig {
    uint64_t time_window_ms    = 60000;
    uint32_t min_alerts        = 2;
    float    severity_threshold = 0.5f;
};

// ---------------------------------------------------------------------------
// AlertCorrelator -- accumulator + fusion engine
// ---------------------------------------------------------------------------

class AlertCorrelator {
public:
    /// Add an alert and return its assigned ID.
    [[nodiscard]] auto add_alert(Alert alert) -> uint32_t;

    /// Correlate pending alerts according to config.
    [[nodiscard]] auto correlate(const CorrelationConfig& config) const
        -> std::vector<CorrelatedAlert>;

    /// Number of un-correlated alerts in the buffer.
    [[nodiscard]] auto pending_count() const -> uint32_t;

    /// Discard all pending alerts.
    void clear();

    /// Compute combined severity: max + 0.1 * (count - 1).
    [[nodiscard]] static auto combine_severity(
        const std::vector<Alert>& alerts) -> float;

    /// Build a human-readable narrative from alert descriptions.
    [[nodiscard]] static auto build_narrative(
        const std::vector<Alert>& alerts) -> std::string;

    /// Group alerts into temporal windows.
    [[nodiscard]] static auto alerts_in_window(
        const std::vector<Alert>& alerts,
        uint64_t window_ms) -> std::vector<std::vector<Alert>>;

private:
    std::vector<Alert> pending_;
    uint32_t           next_id_ = 1;
};

} // namespace anomaly

#endif // ANOMALY_KERNELS_ALERT_CORRELATOR_H
