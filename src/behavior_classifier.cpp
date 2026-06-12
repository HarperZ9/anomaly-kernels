// =============================================================================
// Anomaly: Behavior Classifier — Implementation
//
// Rule-based classification.  Each rule specifies a condition_field,
// operator, and threshold.  classify() evaluates every rule against a
// metrics map, accumulates triggered rule weights per category, and
// picks the highest-weighted category as the result.
// =============================================================================

#include <anomaly/behavior_classifier.h>

#include <algorithm>
#include <cmath>

namespace we::anomaly {

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

void BehaviorClassifier::add_rule(BehaviorRule rule) {
    rules_.push_back(std::move(rule));
}

auto BehaviorClassifier::classify(
    const std::unordered_map<std::string, double>& metrics) const
    -> ClassificationResult
{
    ClassificationResult result;
    result.category = BehaviorCategory::Normal;

    // Weight accumulator per category
    std::unordered_map<uint8_t, float> category_weights;
    float total_weight = 0.0f;

    for (const auto& rule : rules_) {
        if (evaluate_rule(rule, metrics)) {
            result.triggered_rules.push_back(rule.name);
            auto key = static_cast<uint8_t>(rule.category);
            category_weights[key] += rule.weight;
            total_weight += rule.weight;
        }
    }

    if (result.triggered_rules.empty()) {
        result.confidence = 1.0f;
        return result;
    }

    // Pick highest-weighted category
    float best_weight = 0.0f;
    for (const auto& [cat, w] : category_weights) {
        if (w > best_weight) {
            best_weight = w;
            result.category = static_cast<BehaviorCategory>(cat);
        }
    }

    result.confidence = (total_weight > 0.0f)
        ? best_weight / total_weight
        : 0.0f;
    result.risk_score = std::clamp(total_weight / 10.0f, 0.0f, 1.0f);

    return result;
}

auto BehaviorClassifier::default_rules() -> std::vector<BehaviorRule> {
    std::vector<BehaviorRule> rules;

    rules.push_back({
        "high_process_creation", "Process creation rate exceeds threshold",
        BehaviorCategory::Suspicious, "process_creation_rate",
        OperatorType::Gt, 50.0, 2.0f
    });
    rules.push_back({
        "outbound_dns_flood", "DNS query rate indicates exfiltration",
        BehaviorCategory::Exfiltration, "dns_query_rate",
        OperatorType::Gt, 100.0, 3.0f
    });
    rules.push_back({
        "registry_run_key", "Registry run key access detected",
        BehaviorCategory::Persistence, "registry_run_key_access",
        OperatorType::Gt, 0.0, 2.5f
    });
    rules.push_back({
        "lateral_smb_spike", "SMB connection spike suggests lateral movement",
        BehaviorCategory::Lateral, "smb_connection_rate",
        OperatorType::Gt, 20.0, 2.0f
    });
    rules.push_back({
        "evasive_timestamp_modify", "Timestamp modification detected",
        BehaviorCategory::Evasive, "timestamp_modifications",
        OperatorType::Gt, 0.0, 1.5f
    });
    rules.push_back({
        "high_cpu_anomaly", "CPU usage exceeds safe threshold",
        BehaviorCategory::Suspicious, "cpu_usage",
        OperatorType::Gt, 95.0, 1.0f
    });

    return rules;
}

auto BehaviorClassifier::category_name(BehaviorCategory c)
    -> std::string_view
{
    switch (c) {
        case BehaviorCategory::Normal:       return "Normal";
        case BehaviorCategory::Suspicious:   return "Suspicious";
        case BehaviorCategory::Malicious:    return "Malicious";
        case BehaviorCategory::Evasive:      return "Evasive";
        case BehaviorCategory::Lateral:      return "Lateral";
        case BehaviorCategory::Exfiltration: return "Exfiltration";
        case BehaviorCategory::Persistence:  return "Persistence";
    }
    return "Unknown";
}

auto BehaviorClassifier::operator_name(OperatorType o)
    -> std::string_view
{
    switch (o) {
        case OperatorType::Gt:       return "Gt";
        case OperatorType::Lt:       return "Lt";
        case OperatorType::Eq:       return "Eq";
        case OperatorType::Contains: return "Contains";
    }
    return "Unknown";
}

auto BehaviorClassifier::rules_count() const -> uint32_t {
    return static_cast<uint32_t>(rules_.size());
}

void BehaviorClassifier::clear_rules() {
    rules_.clear();
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

auto BehaviorClassifier::evaluate_rule(
    const BehaviorRule& rule,
    const std::unordered_map<std::string, double>& metrics) -> bool
{
    auto it = metrics.find(rule.condition_field);
    if (it == metrics.end()) return false;

    double value = it->second;
    switch (rule.operator_type) {
        case OperatorType::Gt:       return value > rule.threshold;
        case OperatorType::Lt:       return value < rule.threshold;
        case OperatorType::Eq:       return std::abs(value - rule.threshold)
                                         < 1e-9;
        case OperatorType::Contains: return value != 0.0;
    }
    return false;
}

} // namespace we::anomaly
