// =============================================================================
// Tests: Anomaly -- BaselineBuilder
//
// Validates metric sample accumulation, statistical computation
// (mean, stddev), baseline building, and metric name resolution.
// =============================================================================

#include <doctest/doctest.h>
#include <ostream>
#include "anomaly/baseline_builder.h"

#include <cmath>
#include <vector>

using namespace anomaly;

TEST_SUITE("anomaly::BaselineBuilder") {

    TEST_CASE("compute_mean simple average") {
        std::vector<double> samples = {1.0, 2.0, 3.0};
        double mean = BaselineBuilder::compute_mean(samples);
        CHECK(mean == doctest::Approx(2.0));
    }

    TEST_CASE("compute_mean empty returns zero") {
        std::vector<double> empty;
        CHECK(BaselineBuilder::compute_mean(empty) == doctest::Approx(0.0));
    }

    TEST_CASE("compute_stddev known values") {
        // Population stddev of {2, 4, 4, 4, 5, 5, 7, 9} with mean=5 is 2.0
        std::vector<double> samples = {2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0};
        double mean = BaselineBuilder::compute_mean(samples);
        CHECK(mean == doctest::Approx(5.0));
        double sd = BaselineBuilder::compute_stddev(samples, mean);
        CHECK(sd == doctest::Approx(2.0));
    }

    TEST_CASE("compute_stddev single sample returns zero") {
        std::vector<double> single = {42.0};
        CHECK(BaselineBuilder::compute_stddev(single, 42.0)
              == doctest::Approx(0.0));
    }

    TEST_CASE("metric_name covers all 7 enum values") {
        CHECK(BaselineBuilder::metric_name(MetricType::ProcessCreationRate)
              == "ProcessCreationRate");
        CHECK(BaselineBuilder::metric_name(MetricType::NetworkConnectionRate)
              == "NetworkConnectionRate");
        CHECK(BaselineBuilder::metric_name(MetricType::FileAccessRate)
              == "FileAccessRate");
        CHECK(BaselineBuilder::metric_name(MetricType::RegistryAccessRate)
              == "RegistryAccessRate");
        CHECK(BaselineBuilder::metric_name(MetricType::DnsQueryRate)
              == "DnsQueryRate");
        CHECK(BaselineBuilder::metric_name(MetricType::CpuUsage)
              == "CpuUsage");
        CHECK(BaselineBuilder::metric_name(MetricType::MemoryUsage)
              == "MemoryUsage");
    }

    TEST_CASE("add_sample and build roundtrip") {
        BaselineBuilder builder;
        builder.add_sample(MetricType::CpuUsage, 10.0);
        builder.add_sample(MetricType::CpuUsage, 20.0);
        builder.add_sample(MetricType::CpuUsage, 30.0);

        auto result = builder.build(MetricType::CpuUsage);
        REQUIRE(result.has_value());
        CHECK(result->mean == doctest::Approx(20.0));
        CHECK(result->min  == doctest::Approx(10.0));
        CHECK(result->max  == doctest::Approx(30.0));
        CHECK(result->sample_count == 3);
        CHECK(result->stddev > 0.0);
    }

    TEST_CASE("build with no samples returns error") {
        BaselineBuilder builder;
        auto result = builder.build(MetricType::DnsQueryRate);
        CHECK_FALSE(result.has_value());
    }

    TEST_CASE("sample_count tracks per metric") {
        BaselineBuilder builder;
        CHECK(builder.sample_count(MetricType::CpuUsage) == 0);

        builder.add_sample(MetricType::CpuUsage, 5.0);
        builder.add_sample(MetricType::CpuUsage, 10.0);
        builder.add_sample(MetricType::MemoryUsage, 50.0);

        CHECK(builder.sample_count(MetricType::CpuUsage) == 2);
        CHECK(builder.sample_count(MetricType::MemoryUsage) == 1);
        CHECK(builder.sample_count(MetricType::DnsQueryRate) == 0);
    }

    TEST_CASE("reset clears all samples") {
        BaselineBuilder builder;
        builder.add_sample(MetricType::CpuUsage, 42.0);
        CHECK(builder.sample_count(MetricType::CpuUsage) == 1);

        builder.reset();
        CHECK(builder.sample_count(MetricType::CpuUsage) == 0);
    }

    TEST_CASE("get_baseline delegates to build") {
        BaselineBuilder builder;
        builder.add_sample(MetricType::FileAccessRate, 100.0);
        builder.add_sample(MetricType::FileAccessRate, 200.0);

        auto result = builder.get_baseline(MetricType::FileAccessRate);
        REQUIRE(result.has_value());
        CHECK(result->mean == doctest::Approx(150.0));
    }

} // TEST_SUITE
