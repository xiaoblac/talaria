// Copyright 2026 reFuzz project author -------youngkk.
//
// XiuosFuzzSession — Phase 2 §C #22 follow-up: lightweight orchestrator
// that bundles every XiUOS fuzz-loop component (Channel + InMemoryCorpusStore
// + PrioritySchedulerEngine + CorpusManager + CompositeFeedbackEngine +
// XiuosCrashBucket + XiuosMutatorEngine) behind one API.
//
// Lives in control/ — the orchestration tier, parallel to the syz-style
// FuzzerLoop. This is NOT the production v2 FuzzerLoop (no stage chain, no
// AsyncAdmitWorker, no metric publish, no policy switching). It is purposely
// minimal so XiUOS tests / one-off stress runs can spin up a closed loop
// in ~10 lines without re-wiring 70 lines of boilerplate. When XiUOS gets
// promoted onto the production FuzzerLoop the session API stays useful as
// the "test harness" entry point.
//
// Lifecycle:
//
//   XiuosFuzzSession sess(cfg);
//   if (sess.Boot() != BootStatus::kOk) return ...;   // SKIP / FAIL routes
//   sess.Bootstrap();                                  // submit N seeds, admit interesting
//   sess.RunLoop(iterations, progress_every, on_progress);
//   sess.Close();                                      // optional; dtor handles it
//
// The session keeps statistics (bootstrap vs loop, completions / abnormals
// by AbnormalKind, scheduler-null count, mutator stats, bucket count, etc.)
// so test assertions stay one-liners.

#pragma once

#include "refuzz/channel/channel.hpp"
#include "refuzz/core/channel_contract.hpp"
#include "refuzz/core/engine_handle.hpp"
#include "refuzz/corpus/corpus_manager.hpp"
#include "refuzz/corpus/corpus_store.hpp"
#include "refuzz/corpus/inbox.hpp"
#include "refuzz/corpus/seed_id_allocator.hpp"
#include "refuzz/feedback/bucket/xiuos_crash_bucket.hpp"
#include "refuzz/program/xiuos/xiuos_program.hpp"
#include "refuzz/feedback/engine/composite_feedback_engine.hpp"
#include "refuzz/mutator/xiuos/xiuos_mutator_engine.hpp"
#include "refuzz/scheduler/engine/priority_scheduler_engine.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

namespace refuzz::control::xiuos {

struct XiuosFuzzSessionConfig {
    // ── Channel / QEMU ────────────────────────────────────────────────
    std::string                    elf_path;
    std::string                    qemu_bin    = "qemu-system-riscv32";
    std::string                    serial_host = "127.0.0.1";
    std::uint16_t                  serial_port = 32500;
    std::filesystem::path          vm_workdir  = "/tmp/xiuos-fuzz-session";
    std::uint32_t                  channel_id  = 1;
    std::chrono::milliseconds      wait_ready_timeout{15000};
    std::chrono::milliseconds      loop_interval{20};
    std::size_t                    channel_inflight_capacity = 4;

    // ── Corpus bootstrap ──────────────────────────────────────────────
    // Discovered via DiscoverXiuosProgramSeedFiles. If empty/missing,
    // Boot() reports kSkippedMissingCorpus.
    std::filesystem::path          corpus_root;
    unsigned                       bootstrap_count = 12;

    // ── Crash bucket ──────────────────────────────────────────────────
    std::filesystem::path          crash_bucket_dir =
        "/tmp/xiuos-fuzz-session/buckets";
    // True = remove + recreate the bucket dir on Boot. False = preserve
    // existing buckets (useful for resuming a session).
    bool                           reset_bucket_dir_on_boot = true;

    // ── Wedge bucket ──────────────────────────────────────────────────
    // 单独的目录承接 wedge findings(worker 不回 RESULT)。XiuosCrashBucket
    // 只收 Trap;wedge 是另一类异常 program,落这里。每条记录写
    // <dir>/<hash>.{bin,json,c} (raw payload + 元信息 + 反编译出的 XiUOS C
    // 复现程序)。留空则 Boot() 自动 derive 为 `<vm_workdir>/wedges`,跟
    // crash_bucket_dir 同根,operator 不用再单独指定。每次 boot 会被
    // reset(若 reset_bucket_dir_on_boot=true),只代表本次 run。
    std::filesystem::path          wedge_bucket_dir;

    // ── Findings archive (跨 run 永久档案) ────────────────────────────
    // 留空 = 关闭,RecordWedge 不写档案。非空 = 启用,每个新 wedge 同时
    // 落到这个目录(同样 .bin/.json/.c 三件套,前缀 wedge_<hash>)。**不会**
    // 被 reset_bucket_dir_on_boot 清,Boot 时先 scan 已有 .bin 提取 hash
    // 加入 dedup,所以跨多次 campaign 累积同一个 unique payload 只存一份。
    // 推荐指到被测对象(XiUOS)repo 里的 refuzz_findings/auto/。
    std::filesystem::path          findings_archive_dir;

    // ── Mutator ───────────────────────────────────────────────────────
    refuzz::fuzzer::XiuosMutatorEngine::Config mutator_cfg;

    // ── Per-submit timeout ────────────────────────────────────────────
    std::uint32_t                  exec_timeout_ms = 5000;

    // ── Wedge oracle drain windows ────────────────────────────────────
    // Phase-H channel doesn't evict on per-request timeout, so wedge
    // detection is host-side wall-clock. These values are the budgets
    // the session waits for the offending submit to complete.
    //
    // Defaults raised 2026-05-23 after empirical run showed that
    // legitimate slow programs (Timer / Event / MsgQ / WQ delayed paths)
    // routinely take 5-7s. Old 5s/8s defaults caused ~33% of
    // candidate-wedge detections to be slow-but-not-stuck programs,
    // which inflated `verify_not_reproduced.completed` and burned
    // recovery cycles. Real wedges traditionally hit the verify ceiling
    // at ~8s of the old budget, so 8s for initial is a tight-but-real
    // floor; 12s verify gives 50% headroom over that.
    //
    //   wedge_initial_drain_ms — Step() waits this long before flagging
    //                            a candidate wedge.
    //   wedge_verify_drain_ms  — VerifyWedgeOnFresh() waits this long on
    //                            a freshly-recovered worker. Should be
    //                            ≥ 1.5× initial so verify is strictly
    //                            more generous than detection.
    //   wedge_health_check_enabled — if true, round-trip an EMPTY program
    //                            (call_count == 0) on the fresh channel
    //                            before re-submitting the candidate. The
    //                            empty program proves liveness without
    //                            allocating any kernel object, so it does
    //                            NOT perturb id/heap state the candidate
    //                            depends on. Failure → `health_failed`
    //                            counter, not "candidate spurious".
    //   wedge_health_check_ms  — drain window for the health-check submit.
    //
    // Tests / CI that need bounded wallclock can shorten via env vars
    // (XIUOS_WEDGE_*) read in the smoke binaries.
    std::uint32_t                  wedge_initial_drain_ms      = 8000;
    std::uint32_t                  wedge_verify_drain_ms       = 12000;
    bool                           wedge_health_check_enabled  = true;
    std::uint32_t                  wedge_health_check_ms       = 3000;
};

struct XiuosFuzzSessionStats {
    // Indexed by cc::AbnormalKind value.
    std::array<std::uint64_t, 7>   abnormal_by_kind{};

    std::uint64_t bootstrap_submits = 0;     // accepted submits during bootstrap
    std::uint64_t loop_submits = 0;          // accepted submits during scheduler loop
    std::uint64_t total_completions = 0;     // sum across bootstrap + loop
    std::uint64_t total_abnormals = 0;       // sum across all kinds
    std::uint64_t scheduler_nones = 0;       // Step() iters where NextSeedId returned nullopt

    std::size_t   corpus_after_bootstrap = 0;
    std::size_t   corpus_current = 0;
    std::size_t   bucket_count = 0;
    std::size_t   bucket_seeds = 0;
    std::size_t   unique_seed_ids_picked = 0;

    // Wedge findings: worker stopped responding to RESULT on a submitted
    // program. Detected by Step() per-submit drain deadline. Each unique
    // program payload landing in this state is persisted under
    // Config.wedge_bucket_dir; repeats are deduped by FNV-1a 64 hash.
    std::uint64_t wedge_detections = 0;     // total times wedge condition fired
    std::uint64_t wedge_persisted  = 0;     // .bin/.json files written (unique payloads)
    std::uint64_t wedge_recoveries = 0;     // successful chan rebuild after wedge
    std::uint64_t wedge_recovery_failures = 0;  // chan rebuild that failed (session dead)
    std::uint64_t findings_archived = 0;    // unique wedges newly persisted to archive
    // Verify outcomes. Sum of the 4 "not-reproduced" bins + verify_confirmed
    // equals the number of candidates Step() handed to VerifyWedgeOnFresh.
    // Don't conflate any of these with "false positive": a candidate that
    // verifies as `completed` simply means the initial wedge_initial_drain
    // was too tight. archive precision is still guaranteed because only
    // verify_confirmed payloads get bucketed.
    std::uint64_t wedge_verify_confirmed       = 0;  // re-wedged on retry → archived
    std::uint64_t wedge_verify_completed       = 0;  // got terminal Completion on retry
    std::uint64_t wedge_verify_abnormal        = 0;  // got terminal Abnormal on retry
    std::uint64_t wedge_verify_submit_failed   = 0;  // chan rejected re-submit
    std::uint64_t wedge_verify_health_failed   = 0;  // pre-submit health-check failed

    // v1 call-level oracle (RunOracleSelfTest):
    std::uint64_t oracle_cases_run = 0;         // total curated cases dispatched
    std::uint64_t oracle_failures  = 0;         // cases where vendor_aux didn't match expectation

    // [v3 per-program oracle in the campaign] worker-side invariant signals
    // surfaced on every fuzzed program (not just curated cases):
    std::uint64_t state_violations  = 0;   // STATE_VIOLATION completions (hard heap/state corruption)
    std::uint64_t state_violations_archived = 0;  // unique ones written to the archive
    std::uint64_t leak_leads         = 0;  // completions with a nonzero per-program leak delta
    std::uint64_t leak_leads_archived = 0; // unique leak-lead programs archived
};

class XiuosFuzzSession {
public:
    using Config = XiuosFuzzSessionConfig;
    using Stats  = XiuosFuzzSessionStats;

    enum class BootStatus : std::uint8_t {
        kOk = 0,
        kSkippedMissingElf,
        kSkippedMissingCorpus,
        kError,
    };

    using ProgressFn =
        std::function<void(unsigned iter, const Stats& snapshot)>;

    explicit XiuosFuzzSession(Config cfg);
    ~XiuosFuzzSession();

    XiuosFuzzSession(const XiuosFuzzSession&)            = delete;
    XiuosFuzzSession& operator=(const XiuosFuzzSession&) = delete;
    XiuosFuzzSession(XiuosFuzzSession&&)                 = delete;
    XiuosFuzzSession& operator=(XiuosFuzzSession&&)      = delete;

    // Lifecycle. Boot() returns:
    //   kSkippedMissingElf      — Config.elf_path doesn't exist on disk
    //   kSkippedMissingCorpus   — Config.corpus_root doesn't exist
    //   kError                  — Channel build/boot failed
    //   kOk                     — Channel is up; safe to Bootstrap + RunLoop
    BootStatus Boot();
    void       Close();   // idempotent; safe before Boot or after.

    // Submit N seeds from Config.corpus_root, drive their completions,
    // admit interesting ones. Returns the corpus size after bootstrap.
    // Idempotent — calling twice will submit a second batch (but the
    // already-admitted seeds get content-hash-deduped).
    std::size_t Bootstrap();

    // One iteration of the scheduler-driven loop:
    //   1) seed_id = scheduler.NextSeedId()
    //   2) Mutate(store.GetSeed(seed_id))
    //   3) Channel.Submit + drain at least one terminal event for it
    //   4) Drive feedback (admission + crash bucket)
    //   5) Tick the corpus manager
    //
    // Returns true on a normal iteration (submit accepted + event seen).
    // Returns false when:
    //   - scheduler returned nullopt (counted as scheduler_nones)
    //   - submit was rejected after retries
    //   - the GetSeed handle was null (shouldn't happen for tracked ids)
    bool Step();

    // Convenience wrapper around Step(). Calls on_progress after every
    // `progress_every` iterations (set 0 to disable). Returns the total
    // iterations attempted.
    unsigned RunLoop(unsigned iterations,
                     unsigned progress_every = 0,
                     ProgressFn on_progress  = {});

    // v1 call-level oracle. Submits a hand-curated set of test programs
    // (each with a known expected last_ret == 0 / EOK invariant), captures
    // the worker's `aux = last_ret` from Completion.vendor_aux, and reports
    // mismatches. Catches semantic kernel bugs that wedge oracle misses
    // (e.g., WorkSubmit_immediate missing `return EOK` → garbage return).
    // Findings written under <vm_workdir>/oracle/<case>.json. Returns
    // (cases_run, failures). Safe to call after Boot(), independent of
    // RunLoop / Bootstrap.
    struct OracleSummary { std::uint64_t cases_run = 0; std::uint64_t failures = 0; };
    OracleSummary RunOracleSelfTest();

    // Drain pending events without submitting anything (post-run cleanup).
    void DrainTail(std::chrono::milliseconds budget = std::chrono::milliseconds{200});

    // Snapshots / accessors. All const, safe after Boot().
    Stats Snapshot() const;
    refuzz::fuzzer::XiuosMutatorEngine::Stats MutatorStats() const;
    std::size_t CorpusSize() const;
    std::size_t BucketCount() const;
    std::size_t BucketSeeds() const;
    std::size_t UniqueSeedIdsPicked() const { return seen_seed_ids_.size(); }

    // Re-submit `payload` on a freshly-recovered channel and drain for
    // Config.wedge_verify_drain_ms. Returns true iff the resubmit also
    // fails to produce a terminal event for the same executor — i.e.,
    // reproducible wedge. False means the candidate did NOT re-wedge for
    // one of four reasons; categorized into specific stat counters
    // (verify_completed / verify_abnormal / verify_submit_failed /
    // verify_health_failed) so 56%-style headline numbers can be broken
    // down. Public so external replay tools (xiuos_archive_replay_smoke)
    // can submit archived program.bin against a fresh kernel.
    bool VerifyWedgeOnFresh(const std::vector<std::uint8_t>& payload,
                            std::uint64_t orig_seed_id);

    // Pre-replay health check used inside VerifyWedgeOnFresh. Submits an
    // empty program (call_count == 0) and waits Config.wedge_health_check_ms
    // for a terminal Completion. Public so external tools can also gate
    // their replays on host-side liveness without perturbing kernel id/heap
    // state.
    bool WedgeHealthCheck();

private:
    void DrainEventsAndFeedback(std::chrono::milliseconds budget);
    void DrainTickToFixpoint();

    // [verdict 重构] feedback.Process(ev) 后编排 admit/notify(替代旧 actions_ 闭包 +
    // CorpusAdmitDispatcher)。scheduler 自映射 disposition;manager_.OfferVerdict 据
    // 默认 kInteresting 自决建 Seed + 入 inbox_(与旧 CorpusAdmitDispatcher 等价)。
    void AdmitFromVerdict(const refuzz::core::channel_contract::ChannelEvent& ev,
                          const refuzz::fuzzer::EngineOutput& out);
    // Record a wedge: hash program_payload (FNV-1a 64-bit), if first time
    // seen write <wedge_bucket_dir>/<hash>.bin + <hash>.json. Updates
    // stats_.wedge_detections / wedge_persisted.
    void RecordWedge(std::uint64_t executor_id,
                     std::uint64_t seed_id,
                     const std::vector<std::uint8_t>& payload);
    // Shared finding/lead archiver: writes <subdir_prefix><hash>/{program.bin,
    // meta.json, repro.c} under the per-run bucket and (if enabled) the
    // persistent archive, deduped by `dedup`. `kind`/`detail_json` go into
    // meta.json. Returns true if newly archived to the persistent archive.
    void ArchiveProgram(const char* subdir_prefix, const char* kind,
                        std::uint64_t executor_id, std::uint64_t seed_id,
                        const std::vector<std::uint8_t>& payload,
                        const std::string& detail_json,
                        std::unordered_set<std::uint64_t>& dedup,
                        std::uint64_t& archived_counter);
    // Per-program oracle signals surfaced on a normal completion (see
    // XiuosResultStatus::StateViolation and the RESULT flags leak delta).
    void RecordStateViolation(std::uint64_t executor_id, std::uint64_t seed_id,
                              std::int32_t code,
                              const std::vector<std::uint8_t>& payload);
    void RecordLeakLead(std::uint64_t executor_id, std::uint64_t seed_id,
                        std::uint32_t leak_delta,
                        const std::vector<std::uint8_t>& payload);
    // Build + Boot the underlying Channel (QEMU + UART data plane). Called
    // from Boot() and RecoverFromWedge(). Returns false on failure.
    bool BuildAndBootChannel();
    // Tear down the wedged channel and stand up a fresh one with a bumped
    // serial port (avoid TIME_WAIT). Returns false if recovery itself fails
    // — in that case the session is effectively dead.
    bool RecoverFromWedge();

    Config cfg_;
    // Wedge dedup mirror; populated lazily by Boot() (scans existing dir).
    std::unordered_set<std::uint64_t> wedge_dedup_;
    // Findings archive dedup; persists across campaigns. Populated from
    // findings_archive_dir at Boot.
    std::unordered_set<std::uint64_t> archive_dedup_;
    // Per-program-oracle dedup sets (separate so a leak lead and a wedge with
    // the same payload hash are both kept).
    std::unordered_set<std::uint64_t> statev_dedup_;
    std::unordered_set<std::uint64_t> leak_dedup_;

    // Mutator + bucket — standalone, init from cfg in initializer list.
    refuzz::fuzzer::XiuosMutatorEngine mutator_;
    refuzz::fuzzer::XiuosCrashBucket   bucket_;

    // Corpus side. Declaration order matters: manager_ refers to store_,
    // sched_handle_, inbox_, so those must be declared first.
    refuzz::fuzzer::InMemoryCorpusStore                          store_;
    refuzz::fuzzer::CorpusInbox                                  inbox_;
    refuzz::fuzzer::PrioritySchedulerEngine                      scheduler_;
    refuzz::core::EngineHandle<refuzz::fuzzer::ISchedulerEngine> sched_handle_;
    refuzz::fuzzer::CorpusManager                                manager_;
    // [verdict 重构] 替代 id_alloc_:OfferVerdict 建新 seed 时 next_seed_id_++(单线程)。
    std::uint64_t                                               next_seed_id_ = 2;

    // Feedback
    refuzz::fuzzer::CompositeFeedbackEngine fb_engine_;

    // Channel — built lazily in Boot().
    std::unique_ptr<refuzz::channel::IChannel> chan_;

    // Loop state
    std::uint64_t                       next_executor_id_ = 0x60000000ull;
    std::unordered_set<std::uint64_t>   seen_seed_ids_;
    Stats                               stats_;

    // Lifecycle flags
    bool booted_ = false;
    bool closed_ = false;
};

}  // namespace refuzz::control::xiuos
