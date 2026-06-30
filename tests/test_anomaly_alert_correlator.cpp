// =============================================================================
// Tests: Anomaly -- AlertCorrelator
//
// Validates alert ID assignment, severity combination, temporal grouping,
// narrative construction, pending count tracking, and buffer clearing.
// =============================================================================

#include <doctest/doctest.h>
#include <ostream>
#include "anomaly/alert_correlator.h"

#include <string>
#include <vector>

using namespace anomaly;

TEST_SUITE("anomaly::AlertCorrelator") {

    TEST_CASE("add_alert returns incrementing IDs") {
        AlertCorrelator correlator;

        Alert a1;
        a1.source_module = "recon";
        a1.description   = "Port scan detected";
        a1.severity      = 0.3f;

        Alert a2;
        a2.source_module = "sense";
        a2.description   = "Memory tamper detected";
        a2.severity      = 0.7f;

        uint32_t id1 = correlator.add_alert(a1);
        uint32_t id2 = correlator.add_alert(a2);

        CHECK(id1 == 1);
        CHECK(id2 == 2);
        CHECK(id2 > id1);
    }

    TEST_CASE("combine_severity uses max plus bonus") {
        std::vector<Alert> alerts;

        Alert a1;
        a1.severity = 0.5f;
        alerts.push_back(a1);

        Alert a2;
        a2.severity = 0.8f;
        alerts.push_back(a2);

        Alert a3;
        a3.severity = 0.3f;
        alerts.push_back(a3);

        // max=0.8, bonus=0.1*2=0.2, total=1.0 (clamped)
        float combined = AlertCorrelator::combine_severity(alerts);
        CHECK(combined == doctest::Approx(1.0f));
    }

    TEST_CASE("combine_severity single alert") {
        std::vector<Alert> alerts;
        Alert a;
        a.severity = 0.6f;
        alerts.push_back(a);

        // max=0.6, bonus=0.0, total=0.6
        float combined = AlertCorrelator::combine_severity(alerts);
        CHECK(combined == doctest::Approx(0.6f));
    }

    TEST_CASE("combine_severity empty returns zero") {
        std::vector<Alert> empty;
        CHECK(AlertCorrelator::combine_severity(empty)
              == doctest::Approx(0.0f));
    }

    TEST_CASE("correlate groups by time window") {
        AlertCorrelator correlator;

        // Group 1: timestamps 100, 150 (within 200ms window)
        Alert a1;
        a1.source_module = "recon";
        a1.description   = "Scan A";
        a1.severity      = 0.5f;
        a1.timestamp     = 100;
        static_cast<void>(correlator.add_alert(a1));

        Alert a2;
        a2.source_module = "sense";
        a2.description   = "Tamper B";
        a2.severity      = 0.6f;
        a2.timestamp     = 150;
        static_cast<void>(correlator.add_alert(a2));

        // Group 2: timestamp 500 (outside window from group 1)
        Alert a3;
        a3.source_module = "blue";
        a3.description   = "Oracle C";
        a3.severity      = 0.4f;
        a3.timestamp     = 500;
        static_cast<void>(correlator.add_alert(a3));

        CorrelationConfig config;
        config.time_window_ms = 200;
        config.min_alerts     = 2;
        config.severity_threshold = 0.0f;

        auto results = correlator.correlate(config);

        // Only the first group has >= 2 alerts
        CHECK(results.size() == 1);
        CHECK(results[0].alerts.size() == 2);
        CHECK(results[0].combined_severity > 0.0f);
        CHECK(results[0].time_span_ms == 50);
    }

    TEST_CASE("correlate respects min_alerts filter") {
        AlertCorrelator correlator;

        Alert a1;
        a1.severity  = 0.5f;
        a1.timestamp = 100;
        a1.source_module = "x";
        a1.description   = "event";
        static_cast<void>(correlator.add_alert(a1));

        CorrelationConfig config;
        config.time_window_ms = 1000;
        config.min_alerts     = 2;

        auto results = correlator.correlate(config);
        CHECK(results.empty());
    }

    TEST_CASE("build_narrative produces non-empty string") {
        std::vector<Alert> alerts;

        Alert a1;
        a1.source_module = "recon";
        a1.description   = "port scan";
        alerts.push_back(a1);

        Alert a2;
        a2.source_module = "sense";
        a2.description   = "memory tamper";
        alerts.push_back(a2);

        std::string narrative = AlertCorrelator::build_narrative(alerts);
        CHECK_FALSE(narrative.empty());
        CHECK(narrative.find("recon") != std::string::npos);
        CHECK(narrative.find("sense") != std::string::npos);
        CHECK(narrative.find("port scan") != std::string::npos);
    }

    TEST_CASE("build_narrative empty alerts returns empty") {
        std::vector<Alert> empty;
        CHECK(AlertCorrelator::build_narrative(empty).empty());
    }

    TEST_CASE("pending_count tracks additions") {
        AlertCorrelator correlator;
        CHECK(correlator.pending_count() == 0);

        Alert a;
        a.source_module = "test";
        a.description   = "test alert";
        static_cast<void>(correlator.add_alert(a));
        CHECK(correlator.pending_count() == 1);

        static_cast<void>(correlator.add_alert(a));
        CHECK(correlator.pending_count() == 2);
    }

    TEST_CASE("clear resets pending and IDs") {
        AlertCorrelator correlator;

        Alert a;
        a.source_module = "test";
        a.description   = "test";
        static_cast<void>(correlator.add_alert(a));
        CHECK(correlator.pending_count() == 1);

        correlator.clear();
        CHECK(correlator.pending_count() == 0);

        // After clear, IDs restart from 1
        uint32_t new_id = correlator.add_alert(a);
        CHECK(new_id == 1);
    }

    TEST_CASE("alerts_in_window groups correctly") {
        std::vector<Alert> alerts;

        Alert a1; a1.timestamp = 10; alerts.push_back(a1);
        Alert a2; a2.timestamp = 20; alerts.push_back(a2);
        Alert a3; a3.timestamp = 100; alerts.push_back(a3);
        Alert a4; a4.timestamp = 110; alerts.push_back(a4);

        auto groups = AlertCorrelator::alerts_in_window(alerts, 30);
        CHECK(groups.size() == 2);
        CHECK(groups[0].size() == 2);
        CHECK(groups[1].size() == 2);
    }

    TEST_CASE("correlate respects severity_threshold") {
        AlertCorrelator correlator;

        Alert a1;
        a1.source_module = "x";
        a1.description   = "low sev";
        a1.severity      = 0.1f;
        a1.timestamp     = 100;
        static_cast<void>(correlator.add_alert(a1));

        Alert a2;
        a2.source_module = "y";
        a2.description   = "low sev 2";
        a2.severity      = 0.1f;
        a2.timestamp     = 110;
        static_cast<void>(correlator.add_alert(a2));

        CorrelationConfig config;
        config.time_window_ms     = 200;
        config.min_alerts         = 2;
        config.severity_threshold = 0.5f;

        auto results = correlator.correlate(config);
        // combined = max(0.1) + 0.1*1 = 0.2, below 0.5 threshold
        CHECK(results.empty());
    }

} // TEST_SUITE
