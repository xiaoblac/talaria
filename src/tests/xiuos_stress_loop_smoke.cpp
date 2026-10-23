// xiuos_stress_loop_smoke.cpp
//
// Phase 2 §C #22 — configurable stress run for the XiUOS scheduler-driven
// fuzz loop, built on XiuosFuzzSession. Compared to scheduler_loop:
//   * default 500 iterations (knob: XIUOS_STRESS_ITERATIONS)
//   * progress lines every N iterations (knob: XIUOS_STRESS_PROGRESS_EVERY)
//   * mutator knobs (lifecycle violation %, invalid-arg %, max calls,
//     mut seed) all exposed as env vars
//   * abnormal_completion events get broken down by AbnormalKind
//   * liveness-only assertions — XiUOS's API surface plateaus quickly
//
// SKIPs (exit 0) when the worker ELF or generated corpus tree is absent.

#include "refuzz/control/xiuos/xiuos_fuzz_session.hpp"
#include "refuzz/core/channel_contract.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <string>

namespace cc      = refuzz::core::channel_contract;
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

std::uint64_t GetEnvU64(const char* name, std::uint64_t fallback) {
    const char* v = std::getenv(name);
    if (!v || !*v) return fallback;
    char* end = nullptr;
    const auto x = std::strtoull(v, &end, 0);
    if (end == v) return fallback;
    return static_cast<std::uint64_t>(x);
}

const char* AbnormalKindName(cc::AbnormalKind k) {
    switch (k) {
    case cc::AbnormalKind::kHang:        return "hang";
    case cc::AbnormalKind::kNoResult:       return "no_result";
    case cc::AbnormalKind::kWorkerCrashed:  return "worker_crashed";
    case cc::AbnormalKind::kWorkerSignaled: return "worker_signaled";
    case cc::AbnormalKind::kCancelled:      return "cancelled";
    case cc::AbnormalKind::kChildAborted:   return "child_aborted";
    case cc::AbnormalKind::kHarnessFatal:   return "harness_fatal";
    case cc::AbnormalKind::kHarnessRecovered:return "harness_recovered";
    case cc::AbnormalKind::kInfraFault:     return "infra_fault";
    case cc::AbnormalKind::kUnknown:        return "unknown";
    }
    return "?";
}

int RunSmoke() {
    session::XiuosFuzzSession::Config cfg;
    cfg.elf_path = GetEnvOr(
        "XIUOS_VIRT_RV32_ELF",
        "/workspace/xiuos-work/xiuos/Ubiquitous/XiZi_IIoT_Macro/"
        "build/XiZi-virt-rv32.elf");
    cfg.serial_port = static_cast<std::uint16_t>(
        GetEnvUnsigned("XIUOS_PORT", 32971));
    // 每次跑落到 <repo>/run/xiuos/<UTC_timestamp>/ 下;crash bucket / wedge
    // bucket 都跟 vm_workdir 同根。env XIUOS_RUN_ROOT 可覆盖 base path,
    // XIUOS_RUN_DIR 可指定具体子目录(otherwise auto-timestamp)。
    const char* run_root = GetEnvOr(
        "XIUOS_RUN_ROOT",
        "/workspace/talaria/run/xiuos");
    std::string run_dir = GetEnvOr("XIUOS_RUN_DIR", "");
    if (run_dir.empty()) {
        char ts[32];
        const auto now = std::time(nullptr);
        struct tm tmv{};
        gmtime_r(&now, &tmv);
        std::strftime(ts, sizeof(ts), "%Y%m%dT%H%M%SZ", &tmv);
        run_dir = ts;
    }
    const std::filesystem::path workdir =
        std::filesystem::path(run_root) / run_dir;
    std::filesystem::create_directories(workdir);
    cfg.vm_workdir       = workdir;
    cfg.crash_bucket_dir = workdir / "crash_buckets";
    // 永久档案默认放在 reFuzz 仓库 run/xiuos/findings/auto/ —— 跟 run dir
    // (run/xiuos/<UTC_ts>/) 同根,不污染被测对象。XIUOS_FINDINGS_ARCHIVE
    // 可覆盖,设成空字符串关掉跨 run 归档(只留 transient run/ bucket)。
    const std::filesystem::path archive_default =
        std::filesystem::path(run_root) / "findings" / "auto";
    const char* archive = GetEnvOr(
        "XIUOS_FINDINGS_ARCHIVE", archive_default.c_str());
    if (archive[0] != '\0') {
        cfg.findings_archive_dir = archive;
    }
    std::fprintf(stdout, "RUN_DIR %s\n", workdir.c_str());
    if (!cfg.findings_archive_dir.empty()) {
        std::fprintf(stdout, "ARCHIVE %s\n",
                     cfg.findings_archive_dir.c_str());
    }
    cfg.channel_id       = 31;
    cfg.corpus_root      = GetEnvOr(
        "XIUOS_GENERATED_CORPUS_DIR", XIUOS_GENERATED_CORPUS_DIR_DEFAULT);
    cfg.bootstrap_count  = GetEnvUnsigned("XIUOS_STRESS_BOOTSTRAP_COUNT", 12);

    cfg.mutator_cfg.rng_seed = GetEnvU64("XIUOS_STRESS_MUT_SEED", 0x22abcdefull);
    cfg.mutator_cfg.lifecycle_violation_pct =
        GetEnvUnsigned("XIUOS_STRESS_VIOLATION_PCT", 25);
    cfg.mutator_cfg.arg_invalid_value_pct =
        GetEnvUnsigned("XIUOS_STRESS_INVALID_ARG_PCT", 10);
    cfg.mutator_cfg.max_calls_per_program =
        GetEnvUnsigned("XIUOS_STRESS_MAX_CALLS", 16);

    // Wedge oracle drain windows — env override the Config defaults so
    // CTest can shorten without recompiling. Production default is 8s
    // initial / 12s verify (see XiuosFuzzSessionConfig comment).
    cfg.wedge_initial_drain_ms = GetEnvUnsigned(
        "XIUOS_WEDGE_INITIAL_DRAIN_MS", cfg.wedge_initial_drain_ms);
    cfg.wedge_verify_drain_ms  = GetEnvUnsigned(
        "XIUOS_WEDGE_VERIFY_DRAIN_MS",  cfg.wedge_verify_drain_ms);
    cfg.wedge_health_check_ms  = GetEnvUnsigned(
        "XIUOS_WEDGE_HEALTH_CHECK_MS",  cfg.wedge_health_check_ms);

    // Default 80 iter ≈ 5 minutes on virt-rv32 with full priority family
    // surface — programs containing blocking Event/Timer/MsgQ ops average
    // ~3s per submit (most due to kBusy retry exhaustion on chained
    // mutations). Operator runs against bigger numbers via env var.
    const unsigned iterations =
        GetEnvUnsigned("XIUOS_STRESS_ITERATIONS", 80);
    const unsigned progress_every =
        GetEnvUnsigned("XIUOS_STRESS_PROGRESS_EVERY", 100);

    std::fprintf(stdout,
        "CFG iter=%u bootstrap=%u progress_every=%u violation_pct=%u "
        "invalid_arg_pct=%u max_calls=%u mut_seed=0x%lx\n",
        iterations, cfg.bootstrap_count, progress_every,
        cfg.mutator_cfg.lifecycle_violation_pct,
        cfg.mutator_cfg.arg_invalid_value_pct,
        cfg.mutator_cfg.max_calls_per_program,
        static_cast<unsigned long>(cfg.mutator_cfg.rng_seed));

    session::XiuosFuzzSession sess(cfg);
    const auto boot = sess.Boot();
    if (boot == session::XiuosFuzzSession::BootStatus::kSkippedMissingElf) {
        std::fprintf(stdout,
            "SKIP xiuos_stress_loop_smoke: worker ELF not found at %s\n",
            cfg.elf_path.c_str());
        return 0;
    }
    if (boot == session::XiuosFuzzSession::BootStatus::kSkippedMissingCorpus) {
        std::fprintf(stdout,
            "SKIP xiuos_stress_loop_smoke: corpus dir not found at %s\n",
            cfg.corpus_root.string().c_str());
        return 0;
    }
    if (boot != session::XiuosFuzzSession::BootStatus::kOk) {
        std::fprintf(stderr, "FAIL: session Boot failed\n");
        return 1;
    }

    const std::size_t store_after_bootstrap = sess.Bootstrap();
    std::fprintf(stdout, "BOOTSTRAP store_after=%zu\n", store_after_bootstrap);
    if (store_after_bootstrap == 0) {
        std::fprintf(stderr, "FAIL: bootstrap admitted 0 seeds\n");
        return 1;
    }

    // v1 call-level oracle: run curated cases BEFORE the fuzz loop so any
    // wedge-invisible semantic bug (e.g., WorkSubmit_immediate UB) gets
    // flagged before mutator state diverges. Pure observation — does NOT
    // assertion-fail the test; counts go into the final RESULT line and
    // findings drop under <vm_workdir>/oracle/.
    if (GetEnvUnsigned("XIUOS_STRESS_ORACLE", 1) != 0) {
        const auto oracle_r = sess.RunOracleSelfTest();
        std::fprintf(stdout,
            "ORACLE cases=%lu failures=%lu (findings under %s/oracle/)\n",
            static_cast<unsigned long>(oracle_r.cases_run),
            static_cast<unsigned long>(oracle_r.failures),
            workdir.c_str());
    }

    const auto t0 = std::chrono::steady_clock::now();
    std::size_t prev_store = store_after_bootstrap;

    auto progress_cb = [&](unsigned iter,
                           const session::XiuosFuzzSession::Stats& s) {
        const auto now = std::chrono::steady_clock::now();
        const auto elapsed_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(now - t0).count();
        const auto mut = sess.MutatorStats();
        std::fprintf(stdout,
            "PROGRESS iter=%u/%u elapsed=%lldms "
            "store=%zu (+%zu since last) seen=%zu sched_none=%lu "
            "submits=%lu completions=%lu abnormals=%lu "
            "bucket={count=%zu seeds=%zu} "
            "oracle={statev=%lu leak=%lu} "
            "mut={ins=%lu del=%lu repl=%lu arg=%lu "
            "decode_fail=%lu encode_fail=%lu op_skip=%lu life_viol=%lu}\n",
            iter, iterations, static_cast<long long>(elapsed_ms),
            s.corpus_current, s.corpus_current - prev_store,
            s.unique_seed_ids_picked,
            static_cast<unsigned long>(s.scheduler_nones),
            static_cast<unsigned long>(s.loop_submits),
            static_cast<unsigned long>(s.total_completions),
            static_cast<unsigned long>(s.total_abnormals),
            s.bucket_count, s.bucket_seeds,
            static_cast<unsigned long>(s.state_violations),
            static_cast<unsigned long>(s.leak_leads),
            static_cast<unsigned long>(mut.produced[0]),
            static_cast<unsigned long>(mut.produced[1]),
            static_cast<unsigned long>(mut.produced[2]),
            static_cast<unsigned long>(mut.produced[3]),
            static_cast<unsigned long>(mut.decode_failed),
            static_cast<unsigned long>(mut.encode_failed),
            static_cast<unsigned long>(mut.op_skipped),
            static_cast<unsigned long>(mut.lifecycle_violations));
        prev_store = s.corpus_current;
    };

    sess.RunLoop(iterations, progress_every, progress_cb);
    sess.DrainTail();

    const auto t1 = std::chrono::steady_clock::now();
    const auto total_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    const auto snap = sess.Snapshot();
    const auto mut  = sess.MutatorStats();

    std::fprintf(stdout,
        "RESULT iter=%u elapsed=%lldms\n"
        "       store=%zu bootstrap=%zu growth=%zu seen=%zu sched_none=%lu\n"
        "       submits=%lu completions=%lu abnormals=%lu\n"
        "       bucket={count=%zu seeds=%zu}\n"
        "       wedges={detections=%lu persisted=%lu recoveries=%lu recovery_fail=%lu archived=%lu confirmed=%lu}\n"
        "       verify_not_reproduced={completed=%lu abnormal=%lu submit_failed=%lu health_failed=%lu}\n"
        "       per_program_oracle={state_violations=%lu sv_archived=%lu leak_leads=%lu leak_archived=%lu}\n"
        "       mut_total_calls=%lu produced={ins=%lu del=%lu repl=%lu arg=%lu}\n"
        "       mut_diag={decode_fail=%lu encode_fail=%lu op_skip=%lu life_viol=%lu empty_seed=%lu}\n",
        iterations, static_cast<long long>(total_ms),
        snap.corpus_current, snap.corpus_after_bootstrap,
        snap.corpus_current - snap.corpus_after_bootstrap,
        snap.unique_seed_ids_picked,
        static_cast<unsigned long>(snap.scheduler_nones),
        static_cast<unsigned long>(snap.loop_submits),
        static_cast<unsigned long>(snap.total_completions),
        static_cast<unsigned long>(snap.total_abnormals),
        snap.bucket_count, snap.bucket_seeds,
        static_cast<unsigned long>(snap.wedge_detections),
        static_cast<unsigned long>(snap.wedge_persisted),
        static_cast<unsigned long>(snap.wedge_recoveries),
        static_cast<unsigned long>(snap.wedge_recovery_failures),
        static_cast<unsigned long>(snap.findings_archived),
        static_cast<unsigned long>(snap.wedge_verify_confirmed),
        static_cast<unsigned long>(snap.wedge_verify_completed),
        static_cast<unsigned long>(snap.wedge_verify_abnormal),
        static_cast<unsigned long>(snap.wedge_verify_submit_failed),
        static_cast<unsigned long>(snap.wedge_verify_health_failed),
        static_cast<unsigned long>(snap.state_violations),
        static_cast<unsigned long>(snap.state_violations_archived),
        static_cast<unsigned long>(snap.leak_leads),
        static_cast<unsigned long>(snap.leak_leads_archived),
        static_cast<unsigned long>(mut.total_calls),
        static_cast<unsigned long>(mut.produced[0]),
        static_cast<unsigned long>(mut.produced[1]),
        static_cast<unsigned long>(mut.produced[2]),
        static_cast<unsigned long>(mut.produced[3]),
        static_cast<unsigned long>(mut.decode_failed),
        static_cast<unsigned long>(mut.encode_failed),
        static_cast<unsigned long>(mut.op_skipped),
        static_cast<unsigned long>(mut.lifecycle_violations),
        static_cast<unsigned long>(mut.empty_seed_skipped));

    if (snap.total_abnormals > 0) {
        std::fprintf(stdout, "       abnormal_breakdown=");
        for (std::size_t i = 0; i < snap.abnormal_by_kind.size(); ++i) {
            if (snap.abnormal_by_kind[i] == 0) continue;
            std::fprintf(stdout, "%s:%lu ",
                AbnormalKindName(static_cast<cc::AbnormalKind>(i)),
                static_cast<unsigned long>(snap.abnormal_by_kind[i]));
        }
        std::fprintf(stdout, "\n");
    }

    // Threshold scaled to 1/10 — see xiuos_scheduler_loop_e2e_smoke for
    // rationale. Blocking-call families (Event/Timer/MsgQ-Recv) inflate
    // per-program runtime; many submits hit kBusy retry exhaustion when
    // the prior mutated program is still pending. Forward progress
    // (≥1/10) is what we actually need to assert; a true wedge still fails.
    if (snap.loop_submits < iterations / 10) {
        std::fprintf(stderr,
            "FAIL: only %lu / %u iterations produced a submit\n",
            static_cast<unsigned long>(snap.loop_submits), iterations);
        return 1;
    }
    if (snap.total_completions + snap.total_abnormals == 0) {
        std::fprintf(stderr, "FAIL: 0 terminal events across the run\n");
        return 1;
    }
    if (snap.unique_seed_ids_picked < snap.corpus_after_bootstrap) {
        std::fprintf(stderr,
            "FAIL: scheduler handed out %zu distinct ids, expected >= %zu\n",
            snap.unique_seed_ids_picked, snap.corpus_after_bootstrap);
        return 1;
    }
    for (std::size_t i = 0; i < mut.produced.size(); ++i) {
        if (mut.produced[i] == 0) {
            std::fprintf(stderr, "FAIL: mutator op %zu never produced\n", i);
            return 1;
        }
    }

    std::fprintf(stdout, "XIUOS_STRESS_LOOP_SMOKE_OK\n");
    return 0;
}

}  // namespace

int main() {
    std::fprintf(stdout, "Running xiuos_stress_loop_smoke...\n");
    return RunSmoke();
}
