// =============================================================================
// Tests: Anomaly — BehaviorClassifier
//
// Validates category/operator naming, default rule generation,
// rule-based classification with triggered rules, and rule management.
// =============================================================================

#include <doctest/doctest.h>
#include <ostream>
#include "anomaly/behavior_classifier.h"

#include <unordered_map>
#include <string>

using namespace we::anomaly;

TEST_SUITE("anomaly::BehaviorClassifier") {

    TEST_CASE("category_name covers all 7 categories") {
        CHECK(BehaviorClassifier::category_name(BehaviorCategory::Normal)
              == "Normal");
        CHECK(BehaviorClassifier::category_name(BehaviorCategory::Suspicious)
              == "Suspicious");
        CHECK(BehaviorClassifier::category_name(BehaviorCategory::Malicious)
              == "Malicious");
        CHECK(BehaviorClassifier::category_name(BehaviorCategory::Evasive)
              == "Evasive");
        CHECK(BehaviorClassifier::category_name(BehaviorCategory::Lateral)
              == "Lateral");
        CHECK(BehaviorClassifier::category_name(BehaviorCategory::Exfiltration)
              == "Exfiltration");
        CHECK(BehaviorClassifier::category_name(BehaviorCategory::Persistence)
              == "Persistence");
    }

    TEST_CASE("operator_name covers all 4 operators") {
        CHECK(BehaviorClassifier::operator_name(OperatorType::Gt)
              == "Gt");
        CHECK(BehaviorClassifier::operator_name(OperatorType::Lt)
              == "Lt");
        CHECK(BehaviorClassifier::operator_name(OperatorType::Eq)
              == "Eq");
        CHECK(BehaviorClassifier::operator_name(OperatorType::Contains)
              == "Contains");
    }

    TEST_CASE("default_rules returns at least 5 rules") {
        auto rules = BehaviorClassifier::default_rules();
        CHECK(rules.size() >= 5);

        // Verify each rule has a name and condition_field
        for (const auto& r : rules) {
            CHECK_FALSE(r.name.empty());
            CHECK_FALSE(r.condition_field.empty());
            CHECK(r.weight > 0.0f);
        }
    }

    TEST_CASE("classify with triggered rules") {
        BehaviorClassifier classifier;
        classifier.add_rule({
            "test_rule_1", "High process creation",
            BehaviorCategory::Suspicious, "proc_rate",
            OperatorType::Gt, 10.0, 2.0f
        });
        classifier.add_rule({
            "test_rule_2", "DNS exfil",
            BehaviorCategory::Exfiltration, "dns_rate",
            OperatorType::Gt, 50.0, 3.0f
        });

        std::unordered_map<std::string, double> metrics;
        metrics["proc_rate"] = 5.0;   // below threshold
        metrics["dns_rate"]  = 100.0; // above threshold

        auto result = classifier.classify(metrics);
        CHECK(result.category == BehaviorCategory::Exfiltration);
        CHECK(result.triggered_rules.size() == 1);
        CHECK(result.triggered_rules[0] == "test_rule_2");
        CHECK(result.risk_score > 0.0f);
    }

    TEST_CASE("classify with no triggers returns Normal") {
        BehaviorClassifier classifier;
        classifier.add_rule({
            "never_fires", "Will not trigger",
            BehaviorCategory::Malicious, "missing_field",
            OperatorType::Gt, 100.0, 5.0f
        });

        std::unordered_map<std::string, double> metrics;
        metrics["some_other_field"] = 42.0;

        auto result = classifier.classify(metrics);
        CHECK(result.category == BehaviorCategory::Normal);
        CHECK(result.triggered_rules.empty());
        CHECK(result.confidence == doctest::Approx(1.0f));
    }

    TEST_CASE("classify picks highest-weighted category") {
        BehaviorClassifier classifier;
        classifier.add_rule({
            "low_weight", "Low",
            BehaviorCategory::Suspicious, "value",
            OperatorType::Gt, 0.0, 1.0f
        });
        classifier.add_rule({
            "high_weight", "High",
            BehaviorCategory::Malicious, "value",
            OperatorType::Gt, 0.0, 5.0f
        });

        std::unordered_map<std::string, double> metrics;
        metrics["value"] = 10.0;

        auto result = classifier.classify(metrics);
        CHECK(result.category == BehaviorCategory::Malicious);
        CHECK(result.triggered_rules.size() == 2);
    }

    TEST_CASE("rules_count tracks additions") {
        BehaviorClassifier classifier;
        CHECK(classifier.rules_count() == 0);

        classifier.add_rule({
            "r1", "desc", BehaviorCategory::Normal,
            "field", OperatorType::Gt, 0.0, 1.0f
        });
        CHECK(classifier.rules_count() == 1);

        classifier.add_rule({
            "r2", "desc", BehaviorCategory::Normal,
            "field", OperatorType::Lt, 100.0, 1.0f
        });
        CHECK(classifier.rules_count() == 2);
    }

    TEST_CASE("clear_rules empties rule set") {
        BehaviorClassifier classifier;
        classifier.add_rule({
            "r1", "desc", BehaviorCategory::Normal,
            "field", OperatorType::Gt, 0.0, 1.0f
        });
        CHECK(classifier.rules_count() == 1);

        classifier.clear_rules();
        CHECK(classifier.rules_count() == 0);
    }

    TEST_CASE("Lt and Eq operators evaluate correctly") {
        BehaviorClassifier classifier;
        classifier.add_rule({
            "lt_rule", "Below threshold",
            BehaviorCategory::Suspicious, "temp",
            OperatorType::Lt, 10.0, 1.0f
        });
        classifier.add_rule({
            "eq_rule", "Exact match",
            BehaviorCategory::Evasive, "code",
            OperatorType::Eq, 42.0, 2.0f
        });

        std::unordered_map<std::string, double> metrics;
        metrics["temp"] = 5.0;  // < 10 => triggers
        metrics["code"] = 42.0; // == 42 => triggers

        auto result = classifier.classify(metrics);
        CHECK(result.triggered_rules.size() == 2);
        // Evasive has higher weight (2.0 > 1.0)
        CHECK(result.category == BehaviorCategory::Evasive);
    }

} // TEST_SUITE
