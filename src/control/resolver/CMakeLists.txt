cmake_minimum_required(VERSION 3.15)
project(refuzz_resolver CXX)

add_library(refuzz_resolver STATIC
    src/resolver.cpp
)

target_include_directories(refuzz_resolver PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Resolver 组合 LaunchPlan + ProfileDefaults + CatalogSet → ResolvedPlan,
# 因此要看到所有 9 个领域的 catalog 头,以及 startup/profile/orchestrator 头。
target_link_libraries(refuzz_resolver PUBLIC
    refuzz_startup
    refuzz_profile
    refuzz_feedback
    refuzz_mutator
    refuzz_corpus
    refuzz_crash
    refuzz_channel
    refuzz_core
    refuzz_orchestrator
)
