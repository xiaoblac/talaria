// diagnostic_store_history_persist_test.cpp
//
// [crash-execution-history-ring D5] DiagnosticStore must persist the Layer-2
// execution history alongside the crash program: prog0.bin = crash program,
// history0.bin .. historyN.bin = the recent COMPLETED-program sequence that
// preceded it, and meta.json must carry history_count. See
// docs/plans/crash-execution-history-ring.md. Bare assert harness.

#include "refuzz/crash/infra/diagnostic_artifact.hpp"
#include "refuzz/crash/infra/diagnostic_store.hpp"

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using refuzz::crash::CrashKind;
using refuzz::crash::DiagnosticArtifact;
using refuzz::crash::DiagnosticStore;
using refuzz::crash::SaveStatus;

namespace {

std::vector<uint8_t> ReadBin(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)),
                                std::istreambuf_iterator<char>());
}

std::string ReadText(const fs::path& p) {
    std::ifstream f(p);
    return std::string((std::istreambuf_iterator<char>(f)),
                       std::istreambuf_iterator<char>());
}

fs::path FindFile(const fs::path& root, const std::string& name) {
    for (auto& e : fs::recursive_directory_iterator(root)) {
        if (e.is_regular_file() && e.path().filename() == name) return e.path();
    }
    return {};
}

void TestHistoryPersisted() {
    fs::path root = fs::temp_directory_path() / "refuzz_dsh_persist_test";
    std::error_code ec;
    fs::remove_all(root, ec);
    fs::create_directories(root);

    DiagnosticStore store(root.string());

    DiagnosticArtifact art;
    art.kind          = CrashKind::kKernelCrash;
    art.artifact_hash = 0xabcdef0123456789ULL;  // deterministic dir
    art.description   = "BUG: KASAN: test-uaf";
    art.program_payload = {0xAA, 0xBB, 0xCC};            // crash program -> prog0.bin
    art.history_payloads = {                              // oldest first
        {0x01},
        {0x02, 0x02},
        {0x03, 0x03, 0x03},
    };

    SaveStatus st = store.SaveArtifact(art);
    assert(st == SaveStatus::kSaved);

    // prog0.bin == crash program
    fs::path prog0 = FindFile(root, "prog0.bin");
    assert(!prog0.empty());
    assert(ReadBin(prog0) == art.program_payload);

    // history0..2.bin == the three history payloads, in order
    for (std::size_t i = 0; i < art.history_payloads.size(); ++i) {
        fs::path h = FindFile(root, "history" + std::to_string(i) + ".bin");
        assert(!h.empty());
        assert(ReadBin(h) == art.history_payloads[i]);
    }
    // no spurious history3.bin
    assert(FindFile(root, "history3.bin").empty());

    // meta.json records history_count
    fs::path meta = FindFile(root, "meta.json");
    assert(!meta.empty());
    std::string mj = ReadText(meta);
    assert(mj.find("\"history_count\": 3") != std::string::npos);

    fs::remove_all(root, ec);
    std::fprintf(stdout, "  [ok] crash prog -> prog0.bin, history -> history{0..N}.bin, meta history_count\n");
}

void TestNoHistoryStillWritesProg() {
    fs::path root = fs::temp_directory_path() / "refuzz_dsh_nohist_test";
    std::error_code ec;
    fs::remove_all(root, ec);
    fs::create_directories(root);

    DiagnosticStore store(root.string());
    DiagnosticArtifact art;
    art.kind            = CrashKind::kKernelCrash;
    art.artifact_hash   = 0x1122334455667788ULL;
    art.description     = "BUG: no-history";
    art.program_payload = {0x10, 0x20};
    // history_payloads empty (no harvest / single-program crash)

    assert(store.SaveArtifact(art) == SaveStatus::kSaved);
    assert(!FindFile(root, "prog0.bin").empty());
    assert(FindFile(root, "history0.bin").empty());  // none written
    std::string mj = ReadText(FindFile(root, "meta.json"));
    assert(mj.find("\"history_count\": 0") != std::string::npos);

    fs::remove_all(root, ec);
    std::fprintf(stdout, "  [ok] empty history -> no history files, history_count=0\n");
}

} // namespace

int main() {
    std::fprintf(stdout, "Running diagnostic_store_history_persist_test...\n");
    TestHistoryPersisted();
    TestNoHistoryStillWritesProg();
    std::fprintf(stdout, "diagnostic_store_history_persist_test: ALL PASS\n");
    return 0;
}
