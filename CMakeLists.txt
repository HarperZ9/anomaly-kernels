# =============================================================================
# anomaly-kernels: Statistical Telemetry Anomaly Detection -- Static Library
#
# A standalone blue-team telemetry-analytics library.  Ships the statistical
# kernels only: baseline profiling (BaselineBuilder), statistical deviation
# scoring (AnomalyScorer: z-score / IQR / percentile), and multi-signal
# temporal alert correlation (AlertCorrelator).
# =============================================================================

cmake_minimum_required(VERSION 3.24)

project(anomaly-kernels
    VERSION     1.0.0
    DESCRIPTION "Statistical telemetry anomaly-detection kernels"
    LANGUAGES   CXX
)

if(NOT WIN32)
    message(FATAL_ERROR "anomaly-kernels targets Windows x64 only.")
endif()

# -----------------------------------------------------------------------------
# Public library target -- statistical kernels only.
#
# The host-intrusion / SOC threat taxonomy (behavior classifier) is NOT part
# of the public surface and is intentionally not compiled here.
# -----------------------------------------------------------------------------

set(ANOMALY_HEADERS
    include/anomaly/baseline_builder.h
    include/anomaly/anomaly_scorer.h
    include/anomaly/alert_correlator.h
)

set(ANOMALY_SOURCES
    src/baseline_builder.cpp
    src/anomaly_scorer.cpp
    src/alert_correlator.cpp
)

add_library(anomaly-kernels STATIC ${ANOMALY_HEADERS} ${ANOMALY_SOURCES})
target_compile_features(anomaly-kernels PUBLIC cxx_std_23)

target_include_directories(anomaly-kernels PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_compile_definitions(anomaly-kernels PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _CRT_SECURE_NO_WARNINGS
)

if(MSVC)
    target_compile_options(anomaly-kernels PRIVATE
        /W4 /WX /permissive- /Zc:__cplusplus /MP
        /GS /sdl /guard:cf
        $<$<CONFIG:Release>:/O2 /GL>
    )
    target_link_options(anomaly-kernels PRIVATE
        /DYNAMICBASE /NXCOMPAT /guard:cf
        $<$<CONFIG:Release>:/LTCG>
    )
endif()

# -----------------------------------------------------------------------------
# Tests -- doctest, fetched on demand.  Disable with -DANOMALY_KERNELS_TESTS=OFF.
# -----------------------------------------------------------------------------

option(ANOMALY_KERNELS_TESTS "Build anomaly-kernels unit tests" ON)

if(ANOMALY_KERNELS_TESTS)
    enable_testing()

    include(FetchContent)

    # doctest v2.4.11 still declares cmake_minimum_required(VERSION 2.8.x),
    # which CMake >= 4.0 rejects.  Scope a policy floor to the fetched project.
    set(CMAKE_POLICY_VERSION_MINIMUM 3.5)

    FetchContent_Declare(
        doctest
        GIT_REPOSITORY https://github.com/doctest/doctest.git
        GIT_TAG        v2.4.11
    )
    FetchContent_MakeAvailable(doctest)

    unset(CMAKE_POLICY_VERSION_MINIMUM)

    set(ANOMALY_TESTS
        test_anomaly_baseline_builder
        test_anomaly_anomaly_scorer
        test_anomaly_alert_correlator
    )

    foreach(test_name IN LISTS ANOMALY_TESTS)
        add_executable(${test_name} tests/${test_name}.cpp tests/test_main.cpp)
        target_link_libraries(${test_name}
            PRIVATE anomaly-kernels doctest::doctest)
        target_include_directories(${test_name} PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include)
        add_test(NAME ${test_name} COMMAND ${test_name})
    endforeach()
endif()
