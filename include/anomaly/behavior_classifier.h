// =============================================================================
// Anomaly: Behavior Classifier
//
// Rule-based process behavior classification engine.  Evaluates a set of
// named metric values against configurable rules and assigns a behavior
// category (Normal, Suspicious, Malicious, ...) with confidence and a
// list of triggered rule names.
//
// Namespace: we::anomaly
// =============================================================================

#pragma once
#ifndef ANOMALY_BEHAVIOR_CLASSIFIER_H
#define ANOMALY_BEHAVIOR_CLASSIFIER_H

#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace we::anomaly {

// ---------------------------------------------------------------------------
// BehaviorCategory — classification labels
// ---------------------------------------------------------------------------

enum class BehaviorCategory : uint8_t {
    Normal,
    Suspicious,
    Malicious,
    Evasive,
    Lateral,
    Exfiltration,
    Persistence,
};

// ---------------------------------------------------------------------------
// OperatorType — comparison operators for rule conditions
// ---------------------------------------------------------------------------

enum class OperatorType : uint8_t {
    Gt,
    Lt,
    Eq,
    Contains,
};

// ---------------------------------------------------------------------------
// BehaviorRule — single classification rule
// ---------------------------------------------------------------------------

struct BehaviorRule {
    std::string      name;
    std::string      description;
    BehaviorCategory category        = BehaviorCategory::Normal;
    std::string      condition_field;
    OperatorType     operator_type   = OperatorType::Gt;
    double           threshold       = 0.0;
    float            weight          = 1.0f;
};

// ---------------------------------------------------------------------------
// ClassificationResult — output of the classifier
// ---------------------------------------------------------------------------

struct ClassificationResult {
    BehaviorCategory     category        = BehaviorCategory::Normal;
    float                confidence      = 0.0f;
    std::vector<std::string> triggered_rules;
    float                risk_score      = 0.0f;
};

// ---------------------------------------------------------------------------
// BehaviorClassifier — rule engine
// ---------------------------------------------------------------------------

class BehaviorClassifier {
public:
    /// Register a classification rule.
    void add_rule(BehaviorRule rule);

    /// Evaluate all rules against the supplied metrics map.
    [[nodiscard]] auto classify(
        const std::unordered_map<std::string, double>& metrics) const
        -> ClassificationResult;

    /// Built-in rule set for common suspicious patterns.
    [[nodiscard]] static auto default_rules() -> std::vector<BehaviorRule>;

    /// Human-readable name for a behavior category.
    [[nodiscard]] static auto category_name(BehaviorCategory c)
        -> std::string_view;

    /// Human-readable name for an operator type.
    [[nodiscard]] static auto operator_name(OperatorType o)
        -> std::string_view;

    /// Number of registered rules.
    [[nodiscard]] auto rules_count() const -> uint32_t;

    /// Remove all rules.
    void clear_rules();

private:
    std::vector<BehaviorRule> rules_;

    /// Evaluate a single rule against the metrics.
    [[nodiscard]] static auto evaluate_rule(
        const BehaviorRule& rule,
        const std::unordered_map<std::string, double>& metrics) -> bool;
};

} // namespace we::anomaly

#endif // ANOMALY_BEHAVIOR_CLASSIFIER_H
