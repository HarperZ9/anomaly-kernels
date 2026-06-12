# =============================================================================
# Anomaly: Behavioral Anomaly Detection (we-anomaly) — Static Library
#
# Baseline profiling, statistical deviation scoring, rule-based behavior
# classification, and multi-signal alert correlation/fusion engine.
# =============================================================================

cmake_minimum_required(VERSION 3.24)

project(we-anomaly
    VERSION     1.0.0
    DESCRIPTION "Behavioral anomaly detection for Warden security assessments"
    LANGUAGES   CXX
)

if(NOT WIN32)
    message(FATAL_ERROR "we-anomaly targets Windows x64 only.")
endif()

set(ANOMALY_HEADERS
    include/anomaly/baseline_builder.h
    include/anomaly/anomaly_scorer.h
    include/anomaly/behavior_classifier.h
    include/anomaly/alert_correlator.h
)

set(ANOMALY_SOURCES
    src/baseline_builder.cpp
    src/anomaly_scorer.cpp
    src/behavior_classifier.cpp
    src/alert_correlator.cpp
)

add_library(we-anomaly STATIC ${ANOMALY_HEADERS} ${ANOMALY_SOURCES})
target_compile_features(we-anomaly PUBLIC cxx_std_23)

target_include_directories(we-anomaly PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_compile_definitions(we-anomaly PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _CRT_SECURE_NO_WARNINGS
)

if(MSVC)
    target_compile_options(we-anomaly PRIVATE
        /W4 /WX /permissive- /Zc:__cplusplus /MP
        /GS /sdl /guard:cf
        $<$<CONFIG:Release>:/O2 /GL>
    )
    target_link_options(we-anomaly PRIVATE
        /DYNAMICBASE /NXCOMPAT /guard:cf
        $<$<CONFIG:Release>:/LTCG>
    )
endif()
