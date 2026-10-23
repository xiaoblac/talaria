// xiuos_scheduler_loop_e2e_smoke.cpp
//
// Phase 2 §C #21 acceptance gate — scheduler-driven closed fuzz loop.
// Wired through XiuosFuzzSession (control/xiuos/): bootstrap submits N
// generated seeds and admits the interesting ones, then a 60-iter loop
// drives PrioritySchedulerEngine.NextSeedId → store.GetSeed → mutator →
// Channel.Submit → admission + crash bucket → manager.Tick.
//
// The crucial property #21 proves: when a mutated seed is admitted during
// the loop, scheduler.NextSeedId() on a *later* iteration MUST be able to
// return it. We assert this by checking that the distinct seed_ids handed
// out by the scheduler exceed the post-bootstrap corpus size.
//
// SKIPs (exit 0) if the XiUOS worker ELF or the generated corpus tree is
// absent.

#include "refuzz/control/xiuos/xiuos_fuzz_session.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>

namespace session = refuzz::control::xiuos;

namespace {

const char* GetEnvOr(const char* name, const char* fallback) {
    const char* v = std::getenv(name);
    return (v && *v) ? v : fallback;
}

int RunSmoke() {
    session::XiuosFuzzSession::Config cfg;
    cfg.elf_path = GetEnvOr(
        "XIUOS_VIRT_RV32_ELF",
        "/workspace/xiuos-work/xiuos/Ubiquitous/XiZi_IIoT_Macro/"
        "build/XiZi-virt-rv32.elf");
    cfg.serial_port = static_cast<std::uint16_t>(
        std::atoi(GetEnvOr("XIUOS_PORT", "32871")));
    cfg.vm_workdir       = "/tmp/xiuos-scheduler-loop-e2e";
    cfg.crash_bucket_dir = "/tmp/xiuos-scheduler-loop-e2e/crash_buckets";
    cfg.channel_id       = 29;
    cfg.corpus_root      = GetEnvOr(
        "XIUOS_GENERATED_CORPUS_DIR", XIUOS_GENERATED_CORPUS_DIR_DEFAULT);
    cfg.bootstrap_count  = static_cast<unsigned>(
        std::atoi(GetEnvOr("XIUOS_LOOP_BOOTSTRAP_COUNT", "8")));

    cfg.mutator_cfg.rng_seed                = 0x21abcdef;
    cfg.mutator_cfg.lifecycle_violation_pct = 25;
    cfg.mutator_cfg.arg_invalid_value_pct   = 10;
    cfg.mutator_cfg.max_calls_per_program   = 16;

    const unsigned iterations = static_cast<unsigned>(
        std::atoi(GetEnvOr("XIUOS_LOOP_ITERATIONS", "60")));

    session::XiuosFuzzSession sess(cfg);
    const auto boot = sess.Boot();
    if (boot == session::XiuosFuzzSession::BootStatus::kSkippedMissingElf) {
        std::fprintf(stdout,
            "SKIP xiuos_scheduler_loop_e2e_smoke: worker ELF not found at %s\n",
            cfg.elf_path.c_str());
        return 0;
    }
    if (boot == session::XiuosFuzzSession::BootStatus::kSkippedMissingCorpus) {
        std::fprintf(stdout,
            "SKIP xiuos_scheduler_loop_e2e_smoke: corpus dir not found at %s\n",
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

    sess.RunLoop(iterations);
    sess.DrainTail();
    const auto snap = sess.Snapshot();
    const auto mut  = sess.MutatorStats();

    std::fprintf(stdout,
        "RESULT loop_iter=%u submits=%lu completions=%lu abnormals=%lu\n"
        "       store_final=%zu (growth=%zu) seen_ids=%zu sched_none=%lu\n"
        "       bucket={count=%zu seeds=%zu}\n"
        "       mut_ops_produced={insert=%lu del=%lu repl=%lu arg=%lu}\n",
        iterations,
        static_cast<unsigned long>(snap.loop_submits),
        static_cast<unsigned long>(snap.total_completions),
        static_cast<unsigned long>(snap.total_abnormals),
        snap.corpus_current,
        snap.corpus_current - snap.corpus_after_bootstrap,
        snap.unique_seed_ids_picked,
        static_cast<unsigned long>(snap.scheduler_nones),
        snap.bucket_count, snap.bucket_seeds,
        static_cast<unsigned long>(mut.produced[0]),
        static_cast<unsigned long>(mut.produced[1]),
        static_cast<unsigned long>(mut.produced[2]),
        static_cast<unsigned long>(mut.produced[3]));

    // Threshold scaled to 1/10 of iterations to accommodate the structural
    // throughput hit from KEvent/KTimer/KMsgQueue blocking calls — those
    // families' wait-with-timeout paths inflate per-program runtime and
    // many submits hit Channel kBusy retry exhaustion when an earlier
    // mutated program is still pending. We still require forward progress
    // (≥1/10 acceptance) so a truly wedged worker fails this test.
    if (snap.loop_submits < iterations / 10) {
        std::fprintf(stderr,
            "FAIL: only %lu/%u loop iterations produced a submit\n",
            static_cast<unsigned long>(snap.loop_submits), iterations);
        return 1;
    }
    if (snap.total_completions == 0) {
        std::fprintf(stderr, "FAIL: 0 loop completions\n");
        return 1;
    }
    if (snap.corpus_current <= snap.corpus_after_bootstrap) {
        std::fprintf(stderr,
            "FAIL: corpus did not grow during loop (bootstrap=%zu, final=%zu)\n",
            snap.corpus_after_bootstrap, snap.corpus_current);
        return 1;
    }
    if (snap.unique_seed_ids_picked <= snap.corpus_after_bootstrap) {
        std::fprintf(stderr,
            "FAIL: scheduler only handed out %zu distinct ids (expected > %zu)\n",
            snap.unique_seed_ids_picked, snap.corpus_after_bootstrap);
        return 1;
    }
    for (std::size_t i = 0; i < mut.produced.size(); ++i) {
        if (mut.produced[i] == 0) {
            std::fprintf(stderr, "FAIL: mutator op %zu never produced\n", i);
            return 1;
        }
    }

    std::fprintf(stdout, "XIUOS_SCHEDULER_LOOP_E2E_SMOKE_OK\n");
    return 0;
}

}  // namespace

int main() {
    std::fprintf(stdout, "Running xiuos_scheduler_loop_e2e_smoke...\n");
    return RunSmoke();
}
