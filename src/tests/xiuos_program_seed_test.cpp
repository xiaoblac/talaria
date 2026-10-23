// xiuos_program_seed_test.cpp
//
// Phase 2 §B #15 — JSON loader / encoder unit tests for XiuosProgramSeed.
// No QEMU: each test passes JSON text in-process, checks parser output and
// encoded byte-for-byte equality against XiuosEncodeProgram called by hand
// (the same encoder Python `worker_abi.py` is verified against).

#include "refuzz/program/xiuos/xiuos_program.hpp"
#include "refuzz/program/xiuos/xiuos_program_seed.hpp"

#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <vector>

namespace xiuos = refuzz::program::xiuos;

#define CHECK(cond)                                                                \
    do {                                                                           \
        if (!(cond)) {                                                             \
            std::fprintf(stderr, "CHECK failed: %s (line %d)\n", #cond, __LINE__); \
            return 1;                                                              \
        }                                                                          \
    } while (0)

namespace {

const char* kBootstrapSemCreateDelete = R"({
  "name": "sem_create_delete",
  "suite": "COMMON_KERNEL",
  "calls": [
    {"api": "SEM_CREATE", "args": [0, 1]},
    {"api": "SEM_DELETE", "args": [0]}
  ]
})";

const char* kGeneratedRawTimeout = R"({
  "name": "gen_raw_timeout_in_valid_path_001_ea57c208",
  "suite": "COMMON_KERNEL",
  "source": "generated_bounded_lifecycle_v1",
  "source_rule": "raw.timeout.in_valid_path",
  "purpose": "corpus_seed",
  "expected_status": "OK",
  "expected_min_calls": 2,
  "calls": [
    {"api": "SEM_CREATE", "args": [0, 1]},
    {"api": "SEM_OBTAIN", "args": [0, 4294967295]}
  ]
})";

int TestParseBootstrapSeed() {
    auto r = xiuos::ParseXiuosProgramSeedJson(kBootstrapSemCreateDelete);
    CHECK(r.ok());
    const auto& seed = r.value();
    CHECK(seed.name == "sem_create_delete");
    CHECK(seed.suite_id == xiuos::XiuosSuiteId::CommonKernel);
    CHECK(seed.calls.size() == 2);

    CHECK(seed.calls[0].api_id == xiuos::XiuosApiId::SemCreate);
    CHECK(seed.calls[0].argc == 2);
    CHECK(seed.calls[0].args[0] == 0);
    CHECK(seed.calls[0].args[1] == 1);

    CHECK(seed.calls[1].api_id == xiuos::XiuosApiId::SemDelete);
    CHECK(seed.calls[1].argc == 1);
    CHECK(seed.calls[1].args[0] == 0);

    // Metadata fields absent in bootstrap seeds.
    CHECK(!seed.source_rule.has_value());
    CHECK(!seed.expected_min_calls.has_value());
    return 0;
}

int TestParseGeneratedSeed() {
    auto r = xiuos::ParseXiuosProgramSeedJson(kGeneratedRawTimeout);
    CHECK(r.ok());
    const auto& seed = r.value();
    CHECK(seed.calls.size() == 2);
    CHECK(seed.calls[1].api_id == xiuos::XiuosApiId::SemObtain);
    CHECK(seed.calls[1].args[1] == 0xFFFFFFFFu);  // raw timeout
    CHECK(seed.source_rule.has_value());
    CHECK(*seed.source_rule == "raw.timeout.in_valid_path");
    CHECK(seed.expected_min_calls.has_value());
    CHECK(*seed.expected_min_calls == 2);
    return 0;
}

// Acceptance gate #2: encoder output must match XiuosEncodeProgram byte for
// byte (which is itself verified against Python worker_abi.py via the
// xiuos_uart_codec_test golden hex tests).
int TestEncodeMatchesDirectXiuosEncodeProgram() {
    auto r = xiuos::ParseXiuosProgramSeedJson(kBootstrapSemCreateDelete);
    CHECK(r.ok());

    const auto from_seed = r.value().Encode();

    std::vector<xiuos::XiuosProgramCall> manual;
    {
        xiuos::XiuosProgramCall c{};
        c.api_id = xiuos::XiuosApiId::SemCreate; c.argc = 2;
        c.args[0] = 0; c.args[1] = 1;
        manual.push_back(c);
    }
    {
        xiuos::XiuosProgramCall c{};
        c.api_id = xiuos::XiuosApiId::SemDelete; c.argc = 1;
        c.args[0] = 0;
        manual.push_back(c);
    }
    const auto from_manual = xiuos::XiuosEncodeProgram(
        std::span<const xiuos::XiuosProgramCall>(manual.data(), manual.size()),
        xiuos::XiuosSuiteId::CommonKernel, 0);

    CHECK(from_seed.size() == from_manual.size());
    for (std::size_t i = 0; i < from_seed.size(); ++i) {
        CHECK(from_seed[i] == from_manual[i]);
    }
    // Sanity-check layout: 4-byte header + 2 × 20-byte call records.
    CHECK(from_seed.size() == 4 + 2 * XIUOS_CALL_RECORD_SIZE);
    return 0;
}

int TestRejectsUnknownApi() {
    const char* json = R"({
      "name": "x", "suite": "COMMON_KERNEL",
      "calls": [{"api": "FROBNICATE", "args": [0]}]
    })";
    auto r = xiuos::ParseXiuosProgramSeedJson(json);
    CHECK(!r.ok());
    return 0;
}

int TestRejectsArgcMismatch() {
    // SEM_CREATE expects argc=2 per descriptor; passing 1 must reject.
    const char* json = R"({
      "name": "x", "suite": "COMMON_KERNEL",
      "calls": [{"api": "SEM_CREATE", "args": [0]}]
    })";
    auto r = xiuos::ParseXiuosProgramSeedJson(json);
    CHECK(!r.ok());
    return 0;
}

int TestRejectsUnknownSuite() {
    const char* json = R"({
      "name": "x", "suite": "ECALL_SUITE",
      "calls": []
    })";
    auto r = xiuos::ParseXiuosProgramSeedJson(json);
    CHECK(!r.ok());
    return 0;
}

int TestRejectsMalformedJson() {
    auto r = xiuos::ParseXiuosProgramSeedJson("{not json");
    CHECK(!r.ok());
    return 0;
}

int TestRejectsMissingFields() {
    auto r1 = xiuos::ParseXiuosProgramSeedJson(R"({"name":"x"})");
    CHECK(!r1.ok());
    auto r2 = xiuos::ParseXiuosProgramSeedJson(R"({"suite":"COMMON_KERNEL","calls":[]})");
    CHECK(!r2.ok());
    return 0;
}

int TestEmptyCallsListEncodes() {
    const char* json = R"({"name":"x","suite":"COMMON_KERNEL","calls":[]})";
    auto r = xiuos::ParseXiuosProgramSeedJson(json);
    CHECK(r.ok());
    const auto encoded = r.value().Encode();
    CHECK(encoded.size() == 4);             // header only
    CHECK(encoded[0] == XIUOS_PROGRAM_VERSION);
    CHECK(encoded[1] == 0);                 // suite_id = COMMON_KERNEL
    CHECK(encoded[2] == 0);                 // call_count = 0
    return 0;
}

int TestAllApiNamesRoundTrip() {
    // Every api_name in the descriptor must be accepted by the loader.
    struct Probe {
        const char* api;
        std::size_t argc;
        xiuos::XiuosApiId expected;
    };
    const Probe probes[] = {
        {"SEM_CREATE",    2, xiuos::XiuosApiId::SemCreate},
        {"SEM_DELETE",    1, xiuos::XiuosApiId::SemDelete},
        {"SEM_OBTAIN",    2, xiuos::XiuosApiId::SemObtain},
        {"SEM_ABANDON",   1, xiuos::XiuosApiId::SemAbandon},
        {"SEM_SET_VALUE", 2, xiuos::XiuosApiId::SemSetValue},
        {"MUTEX_CREATE",  1, xiuos::XiuosApiId::MutexCreate},
        {"MUTEX_DELETE",  1, xiuos::XiuosApiId::MutexDelete},
        {"MUTEX_OBTAIN",  2, xiuos::XiuosApiId::MutexObtain},
        {"MUTEX_ABANDON", 1, xiuos::XiuosApiId::MutexAbandon},
    };
    for (const auto& p : probes) {
        std::string json = std::string("{\"name\":\"x\",\"suite\":\"COMMON_KERNEL\",\"calls\":[{\"api\":\"") +
            p.api + "\",\"args\":[";
        for (std::size_t i = 0; i < p.argc; ++i) {
            if (i) json += ",";
            json += "0";
        }
        json += "]}]}";
        auto r = xiuos::ParseXiuosProgramSeedJson(json);
        CHECK(r.ok());
        CHECK(r.value().calls.size() == 1);
        CHECK(r.value().calls[0].api_id == p.expected);
        CHECK(r.value().calls[0].argc == p.argc);
    }
    return 0;
}

}  // namespace

int main() {
    std::fprintf(stdout, "Running xiuos_program_seed_test...\n");
    int run = 0, ok = 0;
    auto exec = [&](auto fn, const char* name) {
        ++run;
        std::fprintf(stderr, "  [RUN] %s\n", name);
        if (fn() == 0) { ++ok; std::fprintf(stderr, "  [PASS] %s\n", name); }
        else            { std::fprintf(stderr, "  [FAIL] %s\n", name); }
    };

    exec(TestParseBootstrapSeed,                    "ParseBootstrapSeed");
    exec(TestParseGeneratedSeed,                    "ParseGeneratedSeed");
    exec(TestEncodeMatchesDirectXiuosEncodeProgram, "EncodeMatchesDirectXiuosEncodeProgram");
    exec(TestRejectsUnknownApi,                     "RejectsUnknownApi");
    exec(TestRejectsArgcMismatch,                   "RejectsArgcMismatch");
    exec(TestRejectsUnknownSuite,                   "RejectsUnknownSuite");
    exec(TestRejectsMalformedJson,                  "RejectsMalformedJson");
    exec(TestRejectsMissingFields,                  "RejectsMissingFields");
    exec(TestEmptyCallsListEncodes,                 "EmptyCallsListEncodes");
    exec(TestAllApiNamesRoundTrip,                  "AllApiNamesRoundTrip");

    std::fprintf(stdout, "\nPassed %d/%d tests\n", ok, run);
    return (run == ok) ? 0 : 1;
}
