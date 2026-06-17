// =============================================================================
// Tests: Anomaly — AnomalyScorer
//
// Validates z-score calculation, IQR scoring, percentile interpolation,
// severity mapping, method name resolution, and anomaly classification.
// =============================================================================

#include <doctest/doctest.h>
#include <ostream>
#include "anomaly/anomaly_scorer.h"

#include <cmath>
#include <vector>

using namespace anomaly;

TEST_SUITE("anomaly::AnomalyScorer") {

    TEST_CASE("z_score known calculation") {
        // z = (10 - 5) / 2 = 2.5
        double z = AnomalyScorer::z_score(10.0, 5.0, 2.0);
        CHECK(z == doctest::Approx(2.5));
    }

    TEST_CASE("z_score with zero stddev returns zero") {
        CHECK(AnomalyScorer::z_score(10.0, 5.0, 0.0)
              == doctest::Approx(0.0));
    }

    TEST_CASE("z_score negative deviation") {
        // z = (1 - 5) / 2 = -2.0
        double z = AnomalyScorer::z_score(1.0, 5.0, 2.0);
        CHECK(z == doctest::Approx(-2.0));
    }

    TEST_CASE("iqr_score value within bounds returns zero") {
        // Q1=10, Q3=20, IQR=10, lower=-5, upper=35
        CHECK(AnomalyScorer::iqr_score(15.0, 10.0, 20.0)
              == doctest::Approx(0.0));
    }

    TEST_CASE("iqr_score value above upper fence") {
        // Q1=10, Q3=20, IQR=10, upper=35, value=40 => (40-35)/10 = 0.5
        CHECK(AnomalyScorer::iqr_score(40.0, 10.0, 20.0)
              == doctest::Approx(0.5));
    }

    TEST_CASE("iqr_score value below lower fence") {
        // Q1=10, Q3=20, IQR=10, lower=-5, value=-10 => (-5-(-10))/10 = 0.5
        CHECK(AnomalyScorer::iqr_score(-10.0, 10.0, 20.0)
              == doctest::Approx(0.5));
    }

    TEST_CASE("percentile median of sorted values") {
        std::vector<double> sorted = {1.0, 2.0, 3.0, 4.0, 5.0};
        double med = AnomalyScorer::percentile(sorted, 0.5);
        CHECK(med == doctest::Approx(3.0));
    }

    TEST_CASE("percentile interpolation") {
        std::vector<double> sorted = {10.0, 20.0, 30.0, 40.0};
        // 0.25 => index 0.75 => 10*0.25 + 20*0.75 = 17.5
        double p25 = AnomalyScorer::percentile(sorted, 0.25);
        CHECK(p25 == doctest::Approx(17.5));
    }

    TEST_CASE("percentile edge cases") {
        std::vector<double> sorted = {5.0, 10.0};
        CHECK(AnomalyScorer::percentile(sorted, 0.0)
              == doctest::Approx(5.0));
        CHECK(AnomalyScorer::percentile(sorted, 1.0)
              == doctest::Approx(10.0));

        std::vector<double> empty;
        CHECK(AnomalyScorer::percentile(empty, 0.5)
              == doctest::Approx(0.0));
    }

    TEST_CASE("severity_from_zscore thresholds") {
        // z=0 => severity 0.0 (low range)
        CHECK(AnomalyScorer::severity_from_zscore(0.0)
              == doctest::Approx(0.0f));

        // z=1 => low range (< 0.33)
        float sev1 = AnomalyScorer::severity_from_zscore(1.0);
        CHECK(sev1 > 0.0f);
        CHECK(sev1 < 0.33f);

        // z=2.5 => medium range (0.33 - 0.66)
        float sev25 = AnomalyScorer::severity_from_zscore(2.5);
        CHECK(sev25 >= 0.33f);
        CHECK(sev25 <= 0.66f);

        // z=4.0 => high range (>= 0.66)
        float sev4 = AnomalyScorer::severity_from_zscore(4.0);
        CHECK(sev4 >= 0.66f);
        CHECK(sev4 <= 1.0f);
    }

    TEST_CASE("method_name covers all 4 methods") {
        CHECK(AnomalyScorer::method_name(ScoringMethod::ZScore)
              == "ZScore");
        CHECK(AnomalyScorer::method_name(ScoringMethod::Iqr)
              == "Iqr");
        CHECK(AnomalyScorer::method_name(ScoringMethod::MovingAverage)
              == "MovingAverage");
        CHECK(AnomalyScorer::method_name(ScoringMethod::Percentile)
              == "Percentile");
    }

    TEST_CASE("is_anomalous respects threshold") {
        AnomalyScore low;
        low.z_score = 1.5;
        CHECK_FALSE(AnomalyScorer::is_anomalous(low, 3.0));

        AnomalyScore high;
        high.z_score = 3.5;
        CHECK(AnomalyScorer::is_anomalous(high, 3.0));

        AnomalyScore exact;
        exact.z_score = 3.0;
        CHECK(AnomalyScorer::is_anomalous(exact, 3.0));
    }

    TEST_CASE("score integration — anomalous observation") {
        Baseline b;
        b.mean   = 50.0;
        b.stddev = 5.0;

        ScoringConfig cfg;
        cfg.method    = ScoringMethod::ZScore;
        cfg.threshold = 3.0;

        AnomalyScorer scorer;
        auto result = scorer.score(70.0, b, cfg);

        CHECK(result.value == doctest::Approx(70.0));
        CHECK(result.baseline_mean == doctest::Approx(50.0));
        CHECK(result.z_score == doctest::Approx(4.0));
        CHECK(result.is_anomalous == true);
        CHECK(result.severity >= 0.66f);
    }

} // TEST_SUITE
