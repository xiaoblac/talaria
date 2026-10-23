// xiuos_archive_replay_smoke.cpp
//
// Replays a configurable list of archived wedge program.bin files. Each
// payload gets its own fresh XiUOS worker via VerifyWedgeOnFresh(), then the
// call-level oracle runs on another fresh worker.
// Used for upstream-fix verification: rebuild xiuos with new kernel, point
// XIUOS_VIRT_RV32_ELF to the new image, list wedge dirs in XIUOS_REPLAY_DIRS
// (colon-separated), see which bugs still reproduce.

#include "refuzz/control/xiuos/xiuos_fuzz_session.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace session = refuzz::control::xiuos;

namespace {

const char* GetEnvOr(const char* name, const char* fallback) {
    const char* v = std::getenv(name);
    return (v && *v) ? v : fallback;
}

unsigned GetEnvUnsigned(const char* name, unsigned fallback) {
    const char* v = std::getenv(name);
    if (!v || !*v) return fallback;
    char* end = nullptr;
    const auto x = std::strtoul(v, &end, 10);
    if (end == v) return fallback;
    return static_cast<unsigned>(x);
}

std::vector<std::string> Split(const std::string& s, char sep) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == sep) {
            if (!cur.empty()) out.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

std::vector<std::uint8_t> ReadFile(const std::filesystem::path& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f) return {};
    f.seekg(0, std::ios::end);
    auto n = static_cast<std::streamsize>(f.tellg());
    f.seekg(0);
    std::vector<std::uint8_t> buf(static_cast<std::size_t>(n));
    f.read(reinterpret_cast<char*>(buf.data()), n);
    return buf;
}

}  // namespace

int main() {
    session::XiuosFuzzSession::Config cfg;
    cfg.elf_path = GetEnvOr(
        "XIUOS_VIRT_RV32_ELF",
        "/workspace/xiuos-work/xiuos/Ubiquitous/XiZi_IIoT_Macro/"
        "build/XiZi-virt-rv32.elf");
    cfg.serial_port = static_cast<std::uint16_t>(
        GetEnvUnsigned("XIUOS_PORT", 32990));
    cfg.wedge_initial_drain_ms = GetEnvUnsigned(
        "XIUOS_WEDGE_INITIAL_DRAIN_MS", cfg.wedge_initial_drain_ms);
    cfg.wedge_verify_drain_ms  = GetEnvUnsigned(
        "XIUOS_WEDGE_VERIFY_DRAIN_MS",  cfg.wedge_verify_drain_ms);
    cfg.wedge_health_check_ms  = GetEnvUnsigned(
        "XIUOS_WEDGE_HEALTH_CHECK_MS",  cfg.wedge_health_check_ms);
    if (GetEnvUnsigned("XIUOS_WEDGE_HEALTH_CHECK_ENABLED", 1) == 0) {
        cfg.wedge_health_check_enabled = false;
    }

    const char* run_root = GetEnvOr(
        "XIUOS_RUN_ROOT",
        "/workspace/talaria/run/xiuos");
    char ts[32];
    const auto now = std::time(nullptr);
    struct tm tmv{};
    gmtime_r(&now, &tmv);
    std::strftime(ts, sizeof(ts), "replay-%Y%m%dT%H%M%SZ", &tmv);
    const std::filesystem::path workdir = std::filesystem::path(run_root) / ts;
    std::filesystem::create_directories(workdir);
    cfg.vm_workdir       = workdir;
    cfg.crash_bucket_dir = workdir / "crash_buckets";
    cfg.findings_archive_dir = "";  // disable archive write — read-only replay
    cfg.channel_id       = 31;
    cfg.corpus_root      = GetEnvOr(
        "XIUOS_GENERATED_CORPUS_DIR", XIUOS_GENERATED_CORPUS_DIR_DEFAULT);
    cfg.bootstrap_count  = 0;

    std::fprintf(stdout, "RUN_DIR %s\n", workdir.c_str());
    std::fprintf(stdout, "ELF %s\n", cfg.elf_path.c_str());

    const std::string dirs_csv = GetEnvOr("XIUOS_REPLAY_DIRS", "");
    const auto dirs = Split(dirs_csv, ':');
    std::fprintf(stdout, "REPLAY count=%zu\n", dirs.size());

    unsigned wedge_count = 0;
    unsigned ok_count    = 0;
    unsigned skip_count  = 0;
    unsigned boot_fail_count = 0;
    unsigned replay_index = 0;
    std::uint16_t next_port = cfg.serial_port;
    for (const auto& dir : dirs) {
        const auto pb = std::filesystem::path(dir) / "program.bin";
        const auto payload = ReadFile(pb);
        if (payload.empty()) {
            std::fprintf(stdout, "SKIP %s (program.bin missing/empty)\n", dir.c_str());
            ++skip_count;
            continue;
        }

        auto replay_cfg = cfg;
        replay_cfg.serial_port = next_port++;
        replay_cfg.vm_workdir = workdir / ("replay_" + std::to_string(replay_index++));
        replay_cfg.crash_bucket_dir = replay_cfg.vm_workdir / "crash_buckets";

        session::XiuosFuzzSession replay_sess(replay_cfg);
        const auto boot = replay_sess.Boot();
        if (boot != session::XiuosFuzzSession::BootStatus::kOk) {
            ++boot_fail_count;
            std::fprintf(stderr, "FAIL ReplayBoot %s (status=%d)\n",
                         dir.c_str(), static_cast<int>(boot));
            continue;
        }

        const auto t0 = std::chrono::steady_clock::now();
        const bool wedged = replay_sess.VerifyWedgeOnFresh(payload, /*orig_seed_id=*/0);
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0).count();
        if (wedged) {
            ++wedge_count;
            std::fprintf(stdout, "WEDGE  %s bytes=%zu elapsed_ms=%lld\n",
                         dir.c_str(), payload.size(), static_cast<long long>(elapsed));
        } else {
            ++ok_count;
            std::fprintf(stdout, "NO_WED %s bytes=%zu elapsed_ms=%lld\n",
                         dir.c_str(), payload.size(), static_cast<long long>(elapsed));
        }
        replay_sess.Close();
    }
    std::fprintf(stdout, "REPLAY_SUMMARY wedge=%u no_wedge=%u skipped=%u boot_fail=%u\n",
                 wedge_count, ok_count, skip_count, boot_fail_count);

    // XIUOS_REPLAY_SKIP_ORACLE=1 stops here, leaving only the candidate
    // replay. Used when attaching gdb to a candidate wedge: the oracle's
    // own waitqueue/delay findings would otherwise wedge a later fresh
    // worker and an attach could land on the wrong fault.
    if (GetEnvUnsigned("XIUOS_REPLAY_SKIP_ORACLE", 0) != 0) {
        std::fprintf(stdout, "ORACLE skipped (XIUOS_REPLAY_SKIP_ORACLE=1)\n");
        return 0;
    }

    auto oracle_cfg = cfg;
    oracle_cfg.serial_port = next_port++;
    oracle_cfg.vm_workdir = workdir / "oracle_session";
    oracle_cfg.crash_bucket_dir = oracle_cfg.vm_workdir / "crash_buckets";

    session::XiuosFuzzSession oracle_sess(oracle_cfg);
    const auto oracle_boot = oracle_sess.Boot();
    if (oracle_boot != session::XiuosFuzzSession::BootStatus::kOk) {
        std::fprintf(stderr, "FAIL OracleBoot (status=%d)\n",
                     static_cast<int>(oracle_boot));
        return 1;
    }
    const auto oracle_r = oracle_sess.RunOracleSelfTest();
    std::fprintf(stdout,
        "ORACLE cases=%lu failures=%lu (findings under %s/oracle/)\n",
        static_cast<unsigned long>(oracle_r.cases_run),
        static_cast<unsigned long>(oracle_r.failures),
        oracle_cfg.vm_workdir.c_str());

    oracle_sess.Close();
    return 0;
}
