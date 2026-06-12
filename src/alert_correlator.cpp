// =============================================================================
// Anomaly: Alert Correlator — Implementation
//
// Temporal alert fusion.  Alerts are grouped by sliding time window,
// combined severity = max(severities) + 0.1 * (count - 1), and a
// narrative is assembled from concatenated descriptions.
// =============================================================================

#include <anomaly/alert_correlator.h>

#include <algorithm>
#include <numeric>

namespace we::anomaly {

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

auto AlertCorrelator::add_alert(Alert alert) -> uint32_t {
    alert.id = next_id_++;
    uint32_t id = alert.id;
    pending_.push_back(std::move(alert));
    return id;
}

auto AlertCorrelator::correlate(const CorrelationConfig& config) const
    -> std::vector<CorrelatedAlert>
{
    auto groups = alerts_in_window(pending_, config.time_window_ms);

    std::vector<CorrelatedAlert> results;
    for (auto& group : groups) {
        if (group.size() < config.min_alerts) continue;

        float combined = combine_severity(group);
        if (combined < config.severity_threshold) continue;

        CorrelatedAlert ca;
        ca.alerts            = std::move(group);
        ca.combined_severity = combined;
        ca.narrative         = build_narrative(ca.alerts);
        ca.correlation_type  = "temporal";

        if (ca.alerts.size() >= 2) {
            auto [mn, mx] = std::minmax_element(
                ca.alerts.begin(), ca.alerts.end(),
                [](const Alert& a, const Alert& b) {
                    return a.timestamp < b.timestamp;
                });
            ca.time_span_ms = mx->timestamp - mn->timestamp;
        }

        results.push_back(std::move(ca));
    }

    return results;
}

auto AlertCorrelator::pending_count() const -> uint32_t {
    return static_cast<uint32_t>(pending_.size());
}

void AlertCorrelator::clear() {
    pending_.clear();
    next_id_ = 1;
}

// ---------------------------------------------------------------------------
// Static helpers
// ---------------------------------------------------------------------------

auto AlertCorrelator::combine_severity(const std::vector<Alert>& alerts)
    -> float
{
    if (alerts.empty()) return 0.0f;

    float max_sev = 0.0f;
    for (const auto& a : alerts) {
        if (a.severity > max_sev) max_sev = a.severity;
    }

    float bonus = 0.1f * static_cast<float>(alerts.size() - 1);
    return std::min(max_sev + bonus, 1.0f);
}

auto AlertCorrelator::build_narrative(const std::vector<Alert>& alerts)
    -> std::string
{
    if (alerts.empty()) return {};

    std::string narrative = "Correlated events: ";
    for (size_t i = 0; i < alerts.size(); ++i) {
        if (i > 0) narrative += "; ";
        narrative += "[" + alerts[i].source_module + "] "
                   + alerts[i].description;
    }
    return narrative;
}

auto AlertCorrelator::alerts_in_window(
    const std::vector<Alert>& alerts,
    uint64_t window_ms) -> std::vector<std::vector<Alert>>
{
    if (alerts.empty()) return {};

    // Sort by timestamp
    std::vector<Alert> sorted = alerts;
    std::sort(sorted.begin(), sorted.end(),
        [](const Alert& a, const Alert& b) {
            return a.timestamp < b.timestamp;
        });

    std::vector<std::vector<Alert>> groups;
    std::vector<Alert> current_group;
    current_group.push_back(sorted[0]);

    for (size_t i = 1; i < sorted.size(); ++i) {
        uint64_t gap = sorted[i].timestamp - current_group.front().timestamp;
        if (gap <= window_ms) {
            current_group.push_back(sorted[i]);
        } else {
            groups.push_back(std::move(current_group));
            current_group.clear();
            current_group.push_back(sorted[i]);
        }
    }

    if (!current_group.empty()) {
        groups.push_back(std::move(current_group));
    }

    return groups;
}

} // namespace we::anomaly
